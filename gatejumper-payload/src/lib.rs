//! GateJumper Payload
//!
//! Loads plugins early, then applies the bypass profile detected for the target.

#![allow(non_snake_case)]

use std::{env, ffi::c_void, fs::OpenOptions, io::Write, path::PathBuf, sync::OnceLock};

type BOOL = i32;
type HINSTANCE = isize;

use windows::{
    core::{PCSTR, PCWSTR},
    Win32::Foundation::{SetLastError, ERROR_FILE_NOT_FOUND, HMODULE, NTSTATUS},
    Win32::System::LibraryLoader::{
        GetModuleFileNameW, GetModuleHandleA, GetProcAddress, LoadLibraryA, LoadLibraryW,
    },
    Win32::System::Environment::GetCommandLineW,
    Win32::System::Memory::{VirtualProtect, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS},
    Win32::System::Threading::{CreateThread, Sleep},
};

const DLL_PROCESS_ATTACH: u32 = 1;

#[derive(Clone, Debug)]
struct RuntimeConfig {
    driver_suppression: bool,
    strict_runtime_probe_filter: bool,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            driver_suppression: false,
            strict_runtime_probe_filter: true,
        }
    }
}

static RUNTIME_CONFIG: OnceLock<RuntimeConfig> = OnceLock::new();

fn runtime_config() -> &'static RuntimeConfig {
    RUNTIME_CONFIG.get_or_init(|| {
        let driver_suppression = env::var("GATEJUMPER_SUPPRESS_DRIVERS")
            .map(|v| v.eq_ignore_ascii_case("1") || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes"))
            .unwrap_or(false);

        let strict_runtime_probe_filter = env::var("GATEJUMPER_STRICT_PROBES")
            .map(|v| !v.eq_ignore_ascii_case("0") && !v.eq_ignore_ascii_case("false") && !v.eq_ignore_ascii_case("no"))
            .unwrap_or(true);

        RuntimeConfig { driver_suppression, strict_runtime_probe_filter }
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GameProfile {
    DirectOepUnity,
    HookedRuntimeUnity,
    PlainUnity,
}




/// True if the game's own directory uses Windows local redirection
/// (`*.exe.local` / `*.dll.local` directories, or an `apphelp.dll` shim next
/// to the game executable). These files live beside the game, never beside an
/// externally relocated gatejumper.dll.
fn detect_local_redirection() -> bool {
    let Some(dir) = game_directory() else {
        return false;
    };

    let mut saw_local_redirection = false;
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
            if name.ends_with(".exe.local") || name.ends_with(".dll.local") || name == "apphelp.dll" {
                saw_local_redirection = true;
                break;
            }
        }
    }
    saw_local_redirection
}

/// True if the current image is a packer's unpacker stub: a `.bind` section, or an
/// entry point inside a `.text` whose raw size is a tiny fraction of its virtual size.
/// This is only the packer fingerprint; whether the stub needs bypassing at all
/// depends on the client's layout (see `detect_game_profile`).
fn is_crackproof_stub_exe() -> bool {
    unsafe {
        let base = match GetModuleHandleA(None) {
            Ok(h) => h.0 as *const u8,
            Err(_) => return false,
        };

        let e_lfanew = *(base.add(0x3C) as *const u32) as usize;
        let nt_headers = base.add(e_lfanew);
        let num_sects = *(nt_headers.add(6) as *const u16) as usize;
        let opt_size = *(nt_headers.add(20) as *const u16) as usize;
        let ep_rva = *(nt_headers.add(40) as *const u32);

        // Section headers live right after the optional header; keep all reads
        // inside the always-mapped first page.
        let sect_off = e_lfanew + 24 + opt_size;
        if sect_off + num_sects * 40 > 0x1000 {
            return false;
        }

        for i in 0..num_sects {
            let off = sect_off + i * 40;
            let name = std::slice::from_raw_parts(base.add(off), 8);

            if name.starts_with(b".bind") {
                return true;
            }

            let vsize = *(base.add(off + 8) as *const u32);
            let vaddr = *(base.add(off + 12) as *const u32);
            let rawsize = *(base.add(off + 16) as *const u32);
            if name.starts_with(b".text")
                && vaddr <= ep_rva
                && ep_rva < vaddr + vsize
                && rawsize > 0
                && vsize > 0
                && (rawsize as f64 / vsize as f64) < 0.1
            {
                return true;
            }
        }

        false
    }
}

/// True if the client ships the packer's full-layout markers. The reliable
/// signal is `UnityCrashHandler64.exe` next to the game executable — part of the
/// untouched Unity build, present in every full-layout distribution (Steam and
/// launcher-managed alike). The `installer/` folder is a Steam-delivery
/// artifact only, so it counts as an additional signal but is not required.
/// Full-layout CrackProof stubs fault under Wine/Proton while unpacking and need
/// the DirectOep bypass. Light-packed clients omit the crash handler.
///
/// Markers are read from the *game's* directory (`game_directory`), not from
/// gatejumper.dll's own directory: the payload may be injected from an external
/// GateJumper folder (the DMM flow), while these files always ship next to the
/// game executable.
fn has_full_crackproof_markers() -> bool {
    let Some(dir) = game_directory() else {
        return false;
    };

    dir.join("UnityCrashHandler64.exe").is_file() || dir.join("installer").is_dir()
}

/// Map a user-supplied profile name onto a concrete profile. Matching is
/// deliberately forgiving so `plain`, `mod-loader`, `direct-oep`,
/// `hooked-runtime`, and shorthand forms all resolve; unknown names return
/// `None` and leave auto-detection untouched.
fn profile_from_name(name: &str) -> Option<GameProfile> {
    let lower = name.trim().to_ascii_lowercase();
    if lower.contains("plain") || lower.contains("loader") || lower.contains("mod") {
        return Some(GameProfile::PlainUnity);
    }
    if lower.contains("hook") || lower.contains("runtime") {
        return Some(GameProfile::HookedRuntimeUnity);
    }
    if lower.contains("direct") || lower.contains("oep") {
        return Some(GameProfile::DirectOepUnity);
    }
    None
}

/// Read a `profile = <name>` from an INI file. When `section` is `Some`, only
/// lines inside the matching `[section]` count; when `None`, the first
/// `profile` line anywhere counts. Files with no `[section]` headers at all
/// are treated as a single implicit section, so old sectionless configs keep
/// working under both modes. `#`/`;` comments and trailing comments are
/// stripped.
fn ini_profile_from_file(path: &std::path::Path, section: Option<&str>) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;
    let mut in_section = section.is_none();
    let mut saw_section_header = false;
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') {
            if let Some(rest) = line.strip_prefix('[') {
                if let Some(name) = rest.strip_suffix(']') {
                    saw_section_header = true;
                    in_section = section
                        .map(|s| name.trim().eq_ignore_ascii_case(s))
                        .unwrap_or(true);
                }
            }
            continue;
        }
        // With headers present, only the requested section counts; without any
        // headers, the whole file is the implicit section.
        if !in_section && saw_section_header {
            continue;
        }
        if let Some(rest) = line.strip_prefix("profile") {
            if let Some(val) = rest.trim().strip_prefix('=') {
                let val = val.trim().trim_matches('"');
                if !val.is_empty() {
                    return Some(val.to_string());
                }
            }
        }
    }
    None
}

/// File name of the current process's image, lowercased — the key used to look
/// up this game in the multi-profile config's `[<exe name>]` sections.
fn process_exe_name() -> Option<String> {
    let mut buf = [0u16; 512];
    let len = unsafe { GetModuleFileNameW(None, &mut buf) };
    if len == 0 {
        return None;
    }
    let path = String::from_utf16_lossy(&buf[..len as usize]);
    std::path::Path::new(&path)
        .file_name()
        .map(|s| s.to_string_lossy().to_ascii_lowercase())
}

/// Resolve the `profile = <name>` override for THIS game from config files, in
/// priority order:
///
///   1. `gatejumper.ini` inside the game's own directory — a per-game
///      individual config. Highest priority, but DMM wipes the game directory
///      on updates, so it may vanish.
///   2. The `[<game exe name>]` section of `gatejumper.ini` beside the payload
///      (the game root in standalone/Steam installs, the dedicated external
///      GateJumper folder in the DMM deployment).
///
/// Returns the first profile found; `None` leaves auto-detection untouched.
fn ini_profile_override() -> Option<String> {
    // 1. Per-game config inside the game's own directory.
    if let Some(dir) = game_directory() {
        if let Some(profile) = ini_profile_from_file(&dir.join("gatejumper.ini"), None) {
            return Some(profile);
        }
    }

    // 2. `[<exe name>]` section of the payload-adjacent global config.
    let dir = dll_directory_snapshot()?;
    let exe_name = process_exe_name()?;
    ini_profile_from_file(&dir.join("gatejumper.ini"), Some(&exe_name))
}

fn detect_game_profile() -> GameProfile {
    // Manual overrides take precedence over auto-detection, highest first:
    //   1. `--profile` on the injector's command line, which the injector
    //      forwards to this process as GATEJUMPER_PROFILE (in the DMM flow,
    //      DMM-Hook overwrites this with the per-game profile it resolved)
    //   2. GATEJUMPER_PROFILE environment variable
    //   3. `profile = <name>` resolved per game by `ini_profile_override`:
    //      a `gatejumper.ini` inside the game's directory wins, otherwise the
    //      `[<game exe name>]` section of the config beside the payload.
    // Overrides are generic and intentionally not game-specific beyond the
    // per-game sections.
    if let Ok(profile_var) = env::var("GATEJUMPER_PROFILE") {
        if let Some(profile) = profile_from_name(&profile_var) {
            log(&format!("Manual profile override via GATEJUMPER_PROFILE: {:?}.", profile));
            return profile;
        }
    }
    if let Some(ini_profile) = ini_profile_override() {
        if let Some(profile) = profile_from_name(&ini_profile) {
            log(&format!("Manual profile override via gatejumper.ini: {:?}.", profile));
            return profile;
        }
    }

    if is_crackproof_stub_exe() {
        // `.local` DLL redirection is the Cellar/DMM install method — a CrackProof
        // stub that also has DotLocal files is the DMM client. Full-layout marker
        // check still applies to distinguish the fault-prone variant.
        if detect_local_redirection() || has_full_crackproof_markers() {
            return GameProfile::DirectOepUnity;
        }
        return GameProfile::PlainUnity;
    }

    // Unpacked clients launch normally and need no bypass. GateJumper acts purely
    // as an early mod loader: plugins load from DllMain, original entry point kept.
    GameProfile::PlainUnity
}



// --- Logging ---

/// Set once in DllMain before any other threads are spawned.
static DLL_DIRECTORY: OnceLock<PathBuf> = OnceLock::new();
/// Set once in DllMain. Holds the game executable's directory.
static PROCESS_DIRECTORY: OnceLock<PathBuf> = OnceLock::new();
/// Whether the deferred bootstrap thread has been scheduled (written once in DllMain).
static mut DEFERRED_BOOTSTRAP_SCHEDULED: bool = false;

fn dll_directory_snapshot() -> Option<&'static PathBuf> {
    DLL_DIRECTORY.get()
}

fn process_directory_snapshot() -> Option<&'static PathBuf> {
    PROCESS_DIRECTORY.get()
}

/// Game directory — process image dir is authoritative; falls back to the
/// payload's own directory for standalone (non-DMM) installs.
fn game_directory() -> Option<PathBuf> {
    process_directory_snapshot()
        .or_else(|| dll_directory_snapshot())
        .map(|p| p.clone())
}

fn log(msg: &str) {
    let log_path = match DLL_DIRECTORY.get() {
        Some(dir) => dir.join("gatejumper.log"),
        None => PathBuf::from("gatejumper.log"),
    };
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(log_path) {
        let _ = writeln!(file, "[GateJumper] {}", msg);
    }
}

/// Writes to gatejumper-deferred.log — separate file, never overwritten by session start.
fn log_deferred(msg: &str) {
    let log_path = match DLL_DIRECTORY.get() {
        Some(dir) => dir.join("gatejumper-deferred.log"),
        None => PathBuf::from("gatejumper-deferred.log"),
    };
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(log_path) {
        let _ = writeln!(file, "[GateJumper-Deferred] {}", msg);
    }
}

fn log_session_start() {
    use windows::Win32::System::SystemInformation::GetSystemTime;
    use windows::Win32::Foundation::SYSTEMTIME;
    let st: SYSTEMTIME = unsafe { GetSystemTime() };
    let log_path = match DLL_DIRECTORY.get() {
        Some(dir) => dir.join("gatejumper.log"),
        None => PathBuf::from("gatejumper.log"),
    };
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(log_path) {
        let _ = writeln!(file,
            "\n{} {:04}-{:02}-{:02} {:02}:{:02}:{:02} {}",
            "─".repeat(35),
            st.wYear, st.wMonth, st.wDay,
            st.wHour, st.wMinute, st.wSecond,
            "─".repeat(35),
        );
    }
}

// --- Minimal runtime hooks used by the generic runner ---

static mut PATH_FILE_EXISTS_W_ORIG: usize = 0;
static mut LOAD_LIBRARY_A_ORIG: usize = 0;
static mut LOAD_LIBRARY_W_ORIG: usize = 0;
static mut LOAD_LIBRARY_EX_A_ORIG: usize = 0;
static mut LOAD_LIBRARY_EX_W_ORIG: usize = 0;
static mut NT_LOAD_DRIVER_ORIG: usize = 0;
static mut NT_UNLOAD_DRIVER_ORIG: usize = 0;
static mut NT_CREATE_FILE_ORIG: usize = 0;

type PathFileExistsWFn = extern "system" fn(PCWSTR) -> BOOL;
type LoadLibraryAFn = extern "system" fn(PCSTR) -> HMODULE;
type LoadLibraryWFn = extern "system" fn(PCWSTR) -> HMODULE;
type LoadLibraryExAFn = extern "system" fn(PCSTR, *mut c_void, u32) -> HMODULE;
type LoadLibraryExWFn = extern "system" fn(PCWSTR, *mut c_void, u32) -> HMODULE;
type NtLoadDriverFn = extern "system" fn(*const u16) -> NTSTATUS;
type NtUnloadDriverFn = extern "system" fn(*const u16) -> NTSTATUS;
type NtCreateFileFn = extern "system" fn(*mut *mut c_void, u32, *mut c_void, *mut c_void, *mut c_void, u32) -> NTSTATUS;

/// Returns true if `lower` (already ASCII-lowercased) matches a known anti-cheat
/// or driver probe pattern that should be suppressed.
fn is_suppressed_runtime_probe(lower: &str) -> bool {
    let suspect_driver = lower.contains("usrdrv017864") || (lower.contains("usrdrv") && lower.ends_with(".sys"));
    let strict = runtime_config().strict_runtime_probe_filter;

    if !strict {
        return suspect_driver;
    }

    lower.ends_with(".exe.local")
        || lower.ends_with(".dll.local")
        || lower.ends_with("apphelp.dll")
        || lower.contains("crackproof")
        || lower.contains("anticheat")
        || lower.contains("easyanti")
        || lower.contains("battleye")
        || lower.contains("egen")
        || suspect_driver
}

fn resolve_module_directory(module_path: &str) -> Option<PathBuf> {
    let idx = module_path.rfind('\\').or_else(|| module_path.rfind('/'))?;
    Some(PathBuf::from(&module_path[..idx]))
}

fn plugin_root_dir() -> PathBuf {
    if let Some(dir) = DLL_DIRECTORY.get() {
        return dir.join("plugins");
    }

    if let Ok(dir) = env::var("GATEJUMPER_PLUGINS_DIR") {
        return PathBuf::from(dir);
    }

    std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")).join("plugins")
}

fn plugin_loading_enabled_for_dir(dir: &std::path::Path) -> bool {
    if let Ok(value) = env::var("GATEJUMPER_LOAD_PLUGINS") {
        let lower = value.trim();
        if lower.eq_ignore_ascii_case("1")
            || lower.eq_ignore_ascii_case("true")
            || lower.eq_ignore_ascii_case("yes")
            || lower.eq_ignore_ascii_case("on")
        {
            return true;
        }
        if lower.eq_ignore_ascii_case("0")
            || lower.eq_ignore_ascii_case("false")
            || lower.eq_ignore_ascii_case("no")
            || lower.eq_ignore_ascii_case("off")
        {
            return false;
        }
    }

    dir.is_dir()
}

fn should_auto_load_plugins() -> bool {
    plugin_loading_enabled_for_dir(&plugin_root_dir())
}

fn should_suppress_driver_checks() -> bool {
    runtime_config().driver_suppression
}

fn log_bootstrap_summary() {
    let cfg = runtime_config();
    let profile = detect_game_profile();
    let gatejumper_plugin_loading = should_auto_load_plugins();
    log("=== GateJumper Payload loaded ===");
    log(&format!(
        "Runtime profile: {:?}; gatejumper_plugin_loading={}, driver_suppression={}, strict_probe_filter={}",
        profile,
        gatejumper_plugin_loading,
        cfg.driver_suppression,
        cfg.strict_runtime_probe_filter,
    ));
}

fn plugin_allowlist() -> Vec<String> {
    env::var("GATEJUMPER_PLUGIN_ALLOWLIST")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(|item| item.to_ascii_lowercase())
        .collect()
}

fn is_allowlisted_plugin(path: &std::path::Path) -> bool {
    let Some(file_name) = path.file_name().and_then(|s| s.to_str()) else {
        return false;
    };

    let lower = file_name.to_ascii_lowercase();
    let allowlist = plugin_allowlist();

    if allowlist.is_empty() {
        return true;
    }

    allowlist.iter().any(|entry| lower == *entry || lower.ends_with(entry))
}

unsafe extern "system" fn deferred_runtime_bootstrap(_param: *mut c_void) -> u32 {
    log("Deferred bootstrap thread started.");
    Sleep(250);
    log_deferred("Deferred bootstrap delay completed.");

    if runtime_config().driver_suppression {
        setup_hooks();
        log_deferred("Deferred runtime hooks enabled.");
    }

    log_deferred("Deferred bootstrap complete.");
    0
}


fn schedule_deferred_runtime_bootstrap() {
    unsafe {
        if DEFERRED_BOOTSTRAP_SCHEDULED {
            return;
        }
        DEFERRED_BOOTSTRAP_SCHEDULED = true;

        let _thread = CreateThread(
            Some(std::ptr::null()),
            0,
            Some(deferred_runtime_bootstrap),
            Some(std::ptr::null_mut()),
            windows::Win32::System::Threading::THREAD_CREATION_FLAGS(0),
            None,
        );

        if _thread.is_err() {
            log("WARN: Failed to create deferred bootstrap thread.");
        }
    }
}

fn apply_profile_bootstrap(profile: GameProfile) {
    match profile {
        GameProfile::DirectOepUnity => {
            unsafe { patch_entry_point_to_unity("Direct OEP hijack enabled."); }
        }
        GameProfile::HookedRuntimeUnity => {
            schedule_deferred_runtime_bootstrap();
            log("Hooked runtime profile: deferred bootstrap scheduled after DllMain.");
        }
        GameProfile::PlainUnity => {
            log("Plain Unity profile: no bypass applied; unpacked client launches normally and GateJumper acts as an early mod loader only.");
        }
    }
}

unsafe fn patch_entry_point_to_unity(message: &str) {
    let ep = get_game_entry_point();
    if ep.is_null() {
        log("FATAL: Entry point not found.");
        return;
    }

    let mut old_protect = PAGE_PROTECTION_FLAGS(0);
    if VirtualProtect(ep as *const c_void, 14, PAGE_EXECUTE_READWRITE, &mut old_protect).is_ok() {
        let target = launch_unity as *const () as usize;
        *ep.add(0) = 0xFF;
        *ep.add(1) = 0x25;
        *ep.add(2) = 0x00;
        *ep.add(3) = 0x00;
        *ep.add(4) = 0x00;
        *ep.add(5) = 0x00;
        let target_bytes = target.to_ne_bytes();
        std::ptr::copy_nonoverlapping(target_bytes.as_ptr(), ep.add(6), 8);
        log(message);
    } else {
        log("FATAL: Failed to make the entry point writable.");
    }
}

unsafe extern "system" fn path_file_exists_w_hook(filename: PCWSTR) -> BOOL {
    if !filename.0.is_null() && (filename.0 as usize) != usize::MAX {
        if (filename.0 as usize) < 0x00007FFFFFFFFFFF {
            if let Ok(filename_str) = filename.to_string() {
                let lower = filename_str.to_lowercase();
                if is_suppressed_runtime_probe(&lower) {
                    log(&format!("Intercepted PathFileExistsW for suppressed probe: {}", filename_str));
                    SetLastError(ERROR_FILE_NOT_FOUND);
                    return 0;
                }
            }
        }
    }

    let orig: PathFileExistsWFn = std::mem::transmute(PATH_FILE_EXISTS_W_ORIG);
    orig(filename)
}

unsafe extern "system" fn load_library_a_hook(filename: PCSTR) -> HMODULE {
    let orig: LoadLibraryAFn = std::mem::transmute(LOAD_LIBRARY_A_ORIG);
    if let Ok(name) = filename.to_string() {
        let lower = name.to_ascii_lowercase();
        if is_suppressed_runtime_probe(&lower) {
            log(&format!("Intercepted LoadLibraryA for suppressed probe: {}", name));
            return HMODULE(std::ptr::null_mut());
        }
    }
    orig(filename)
}

unsafe extern "system" fn load_library_w_hook(filename: PCWSTR) -> HMODULE {
    let orig: LoadLibraryWFn = std::mem::transmute(LOAD_LIBRARY_W_ORIG);
    if let Ok(name) = filename.to_string() {
        let lower = name.to_ascii_lowercase();
        if is_suppressed_runtime_probe(&lower) {
            log(&format!("Intercepted LoadLibraryW for suppressed probe: {}", name));
            return HMODULE(std::ptr::null_mut());
        }
    }
    orig(filename)
}

unsafe extern "system" fn load_library_ex_a_hook(filename: PCSTR, _reserved: *mut c_void, _flags: u32) -> HMODULE {
    let orig: LoadLibraryExAFn = std::mem::transmute(LOAD_LIBRARY_EX_A_ORIG);
    if let Ok(name) = filename.to_string() {
        let lower = name.to_ascii_lowercase();
        if is_suppressed_runtime_probe(&lower) {
            log(&format!("Intercepted LoadLibraryExA for suppressed probe: {}", name));
            return HMODULE(std::ptr::null_mut());
        }
    }
    orig(filename, _reserved, _flags)
}

unsafe extern "system" fn load_library_ex_w_hook(filename: PCWSTR, _reserved: *mut c_void, _flags: u32) -> HMODULE {
    let orig: LoadLibraryExWFn = std::mem::transmute(LOAD_LIBRARY_EX_W_ORIG);
    if let Ok(name) = filename.to_string() {
        let lower = name.to_ascii_lowercase();
        if is_suppressed_runtime_probe(&lower) {
            log(&format!("Intercepted LoadLibraryExW for suppressed probe: {}", name));
            return HMODULE(std::ptr::null_mut());
        }
    }
    orig(filename, _reserved, _flags)
}

unsafe extern "system" fn nt_load_driver_hook(driver_name: *const u16) -> NTSTATUS {
    if should_suppress_driver_checks() {
        if !driver_name.is_null() {
            if let Ok(name) = PCWSTR(driver_name).to_string() {
                let lower = name.to_ascii_lowercase();
                if lower.contains("usrdrv017864") || (lower.contains("usrdrv") && lower.ends_with(".sys")) {
                    log(&format!("[SUPPRESSED] NtLoadDriver: {}", name));
                    return NTSTATUS(-1);
                }
            }
        }
    }
    let orig: NtLoadDriverFn = std::mem::transmute(NT_LOAD_DRIVER_ORIG);
    orig(driver_name)
}

unsafe extern "system" fn nt_unload_driver_hook(driver_name: *const u16) -> NTSTATUS {
    if should_suppress_driver_checks() {
        if !driver_name.is_null() {
            if let Ok(name) = PCWSTR(driver_name).to_string() {
                let lower = name.to_ascii_lowercase();
                if lower.contains("usrdrv017864") || (lower.contains("usrdrv") && lower.ends_with(".sys")) {
                    log(&format!("[SUPPRESSED] NtUnloadDriver: {}", name));
                    return NTSTATUS(-1);
                }
            }
        }
    }
    let orig: NtUnloadDriverFn = std::mem::transmute(NT_UNLOAD_DRIVER_ORIG);
    orig(driver_name)
}

unsafe extern "system" fn nt_create_file_hook(handle: *mut *mut c_void, access: u32, obj_attr: *mut c_void, io_stat: *mut c_void, alloc: *mut c_void, attrs: u32) -> NTSTATUS {
    if should_suppress_driver_checks() && !obj_attr.is_null() {
        // obj_attr is OBJECT_ATTRIBUTES*. Layout (64-bit):
        //   +0x00  ULONG  Length          (4 bytes)
        //   +0x04  (pad)                  (4 bytes)
        //   +0x08  HANDLE RootDirectory   (8 bytes)
        //   +0x10  PUNICODE_STRING ObjectName  ← pointer to { USHORT Len, USHORT MaxLen, PWSTR Buffer }
        let obj_name_ptr = *(obj_attr.add(0x10) as *const *const u8);
        if !obj_name_ptr.is_null() {
            // UNICODE_STRING: USHORT Length (+0), USHORT MaxLen (+2), PWSTR Buffer (+8 on 64-bit)
            let buf_ptr = *(obj_name_ptr.add(8) as *const *const u16);
            let len_bytes = *(obj_name_ptr as *const u16) as usize;
            if !buf_ptr.is_null() && len_bytes > 0 {
                let char_count = len_bytes / 2;
                let slice = std::slice::from_raw_parts(buf_ptr, char_count);
                let path_str = String::from_utf16_lossy(slice).to_ascii_lowercase();
                if path_str.contains("usrdrv017864") || (path_str.contains("usrdrv") && path_str.ends_with(".sys")) {
                    log(&format!("[SUPPRESSED] NtCreateFile for driver: {}", path_str));
                    return NTSTATUS(-2);
                }
            }
        }
    }
    let orig: NtCreateFileFn = std::mem::transmute(NT_CREATE_FILE_ORIG);
    orig(handle, access, obj_attr, io_stat, alloc, attrs)
}

fn setup_hooks() {
    unsafe {
        if let Ok(shlwapi) = LoadLibraryA(PCSTR(b"shlwapi.dll\0".as_ptr())) {
            let p_path_file_exists =
                GetProcAddress(shlwapi, PCSTR(b"PathFileExistsW\0".as_ptr()));
            if let Some(func) = p_path_file_exists {
                match minhook::MinHook::create_hook(
                    func as *mut c_void,
                    path_file_exists_w_hook as *mut c_void,
                ) {
                    Ok(trampoline) => {
                        PATH_FILE_EXISTS_W_ORIG = trampoline as usize;
                        let _ = minhook::MinHook::enable_hook(func as *mut c_void);
                        log("PathFileExistsW hooked.");
                    }
                    Err(_) => log("WARN: Failed to hook PathFileExistsW."),
                }
            }
        }

        let k32 = GetModuleHandleA(PCSTR(b"kernel32.dll\0".as_ptr()));
        if let Ok(k32) = k32 {
            if let Some(func) = GetProcAddress(k32, PCSTR(b"LoadLibraryA\0".as_ptr())) {
                match minhook::MinHook::create_hook(func as *mut c_void, load_library_a_hook as *mut c_void) {
                    Ok(trampoline) => {
                        LOAD_LIBRARY_A_ORIG = trampoline as usize;
                        let _ = minhook::MinHook::enable_hook(func as *mut c_void);
                        log("LoadLibraryA hooked.");
                    }
                    Err(_) => log("WARN: Failed to hook LoadLibraryA."),
                }
            }

            if let Some(func) = GetProcAddress(k32, PCSTR(b"LoadLibraryW\0".as_ptr())) {
                match minhook::MinHook::create_hook(func as *mut c_void, load_library_w_hook as *mut c_void) {
                    Ok(trampoline) => {
                        LOAD_LIBRARY_W_ORIG = trampoline as usize;
                        let _ = minhook::MinHook::enable_hook(func as *mut c_void);
                        log("LoadLibraryW hooked.");
                    }
                    Err(_) => log("WARN: Failed to hook LoadLibraryW."),
                }
            }

            if let Some(func) = GetProcAddress(k32, PCSTR(b"LoadLibraryExA\0".as_ptr())) {
                match minhook::MinHook::create_hook(func as *mut c_void, load_library_ex_a_hook as *mut c_void) {
                    Ok(trampoline) => {
                        LOAD_LIBRARY_EX_A_ORIG = trampoline as usize;
                        let _ = minhook::MinHook::enable_hook(func as *mut c_void);
                        log("LoadLibraryExA hooked.");
                    }
                    Err(_) => log("WARN: Failed to hook LoadLibraryExA."),
                }
            }

            if let Some(func) = GetProcAddress(k32, PCSTR(b"LoadLibraryExW\0".as_ptr())) {
                match minhook::MinHook::create_hook(func as *mut c_void, load_library_ex_w_hook as *mut c_void) {
                    Ok(trampoline) => {
                        LOAD_LIBRARY_EX_W_ORIG = trampoline as usize;
                        let _ = minhook::MinHook::enable_hook(func as *mut c_void);
                        log("LoadLibraryExW hooked.");
                    }
                    Err(_) => log("WARN: Failed to hook LoadLibraryExW."),
                }
            }
        }

        if should_suppress_driver_checks() {
            let ntdll = GetModuleHandleA(PCSTR(b"ntdll.dll\0".as_ptr()));
            if let Ok(ntdll) = ntdll {
                for name in [
                    "NtLoadDriver",
                    "ZwLoadDriver",
                    "NtUnloadDriver",
                    "ZwUnloadDriver",
                    "NtCreateFile",
                    "ZwCreateFile",
                    "NtOpenFile",
                    "ZwOpenFile",
                ] {
                    let proc_name: Vec<u8> = format!("{}\0", name).into_bytes();
                    if let Some(func) = GetProcAddress(ntdll, PCSTR(proc_name.as_ptr())) {
                        let hook = match name {
                            "NtLoadDriver" | "ZwLoadDriver" => nt_load_driver_hook as *mut c_void,
                            "NtUnloadDriver" | "ZwUnloadDriver" => nt_unload_driver_hook as *mut c_void,
                            "NtCreateFile" | "ZwCreateFile" | "NtOpenFile" | "ZwOpenFile" => nt_create_file_hook as *mut c_void,
                            _ => continue,
                        };

                        match minhook::MinHook::create_hook(func as *mut c_void, hook) {
                            Ok(trampoline) => {
                                match name {
                                    "NtLoadDriver" | "ZwLoadDriver" => NT_LOAD_DRIVER_ORIG = trampoline as usize,
                                    "NtUnloadDriver" | "ZwUnloadDriver" => NT_UNLOAD_DRIVER_ORIG = trampoline as usize,
                                    "NtCreateFile" | "ZwCreateFile" | "NtOpenFile" | "ZwOpenFile" => NT_CREATE_FILE_ORIG = trampoline as usize,
                                    _ => (),
                                }
                                let _ = minhook::MinHook::enable_hook(func as *mut c_void);
                                log(&format!("{} hooked from ntdll.", name));
                            }
                            Err(_) => log(&format!("WARN: Failed to hook {} from ntdll.", name)),
                        }
                    }
                }
            }
        }
    }
}


// --- PE Parsing & OEP Hijack ---

fn get_game_entry_point() -> *mut u8 {
    unsafe {
        let base = match GetModuleHandleA(None) {
            Ok(h) => h.0 as *const u8,
            Err(_) => return std::ptr::null_mut(),
        };

        let dos_header = base;
        let e_lfanew = *(dos_header.add(0x3C) as *const u32);
        let nt_headers = dos_header.add(e_lfanew as usize);
        let addr_of_ep = *(nt_headers.add(40) as *const u32);

        dos_header.add(addr_of_ep as usize) as *mut u8
    }
}

unsafe fn load_plugins_from_directory() {
    let plugins_dir = plugin_root_dir();
    log(&format!("Plugin root resolved to: {}", plugins_dir.display()));

    fn scan_dir(dir: &std::path::Path, loaded: &mut usize) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.filter_map(|e| e.ok()) {
                let path = entry.path();
                if path.is_dir() {
                    scan_dir(&path, loaded);
                    continue;
                }

                if !path.is_file() || path.extension().and_then(|s| s.to_str()) != Some("dll") {
                    continue;
                }

                let file_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
                let lower = file_name.to_ascii_lowercase();
                if lower == "gatejumper.dll"
                    || lower == "unityplayer.dll"
                    || lower.ends_with(".dll.local")
                {
                    log(&format!("Skipping self/conflicting DLL: {}", path.display()));
                    continue;
                }

                if !is_allowlisted_plugin(&path) {
                    log(&format!("Skipping unapproved plugin: {}", path.display()));
                    continue;
                }

                if let Some(path_str) = path.to_str() {
                    let mut w_path: Vec<u16> = path_str.encode_utf16().collect();
                    w_path.push(0);
                    let load_result = unsafe { LoadLibraryW(PCWSTR(w_path.as_ptr())) };
                    match load_result {
                        Ok(_) => {
                            log(&format!("Successfully loaded plugin: {}", path_str));
                            *loaded += 1;
                        }
                        Err(_) => log(&format!("Failed to load plugin: {}", path_str)),
                    }
                }
            }
        }
    }

    if !plugins_dir.is_dir() {
        log("'plugins' directory not found. Skipping plugin loading.");
        return;
    }

    log("Scanning 'plugins' directory for additional mods...");
    let mut loaded = 0usize;
    scan_dir(&plugins_dir, &mut loaded);
    log(&format!("Plugin scan complete. Loaded {} external DLL(s).", loaded));
}

/// Entry point called via the OEP patch — loads and starts UnityPlayer.dll!UnityMain.
/// Address is taken directly; the `pub` and `#[allow(dead_code)]` suppress the
/// spurious "unused" warning since the compiler cannot see the OEP jump.
#[allow(dead_code)]
pub extern "system" fn launch_unity() -> i32 {
    unsafe {
        log("OEP Hijack triggered. Launching Unity Engine...");

        // Prefer to load UnityPlayer.dll from the game's own directory (the process
        // image directory) so the correct DLL is found even when gatejumper.dll was
        // injected from an external GateJumper folder (the DMM flow) and the CWD is
        // not the game directory.
        let unity_path_str = match process_directory_snapshot() {
            Some(dir) => {
                let p = dir.join("UnityPlayer.dll");
                format!("{}\0", p.display())
            }
            None => "UnityPlayer.dll\0".to_string(),
        };
        let mut unity_path_w: Vec<u16> = unity_path_str.encode_utf16().collect();
        unity_path_w.push(0);

        let h_unity = match LoadLibraryW(PCWSTR(unity_path_w.as_ptr())) {
            Ok(h) => h,
            Err(_) => {
                log("FATAL: UnityPlayer.dll not found.");
                return 1;
            }
        };

        let unity_main_ptr = GetProcAddress(h_unity, PCSTR(b"UnityMain\0".as_ptr()));
        if let Some(unity_main_fn) = unity_main_ptr {
            let unity_main: extern "system" fn(HINSTANCE, *mut c_void, *const u16, i32) -> i32 =
                std::mem::transmute(unity_main_fn);

            // Get the command line and skip argv[0] (the game exe path), passing
            // only the trailing arguments to UnityMain.
            let mut cmd_ptr = GetCommandLineW().0;
            if !cmd_ptr.is_null() {
                let mut in_quotes = false;
                let mut i = 0;
                loop {
                    let c = *cmd_ptr.add(i);
                    if c == 0 {
                        break;
                    }
                    if c == b'"' as u16 {
                        in_quotes = !in_quotes;
                    }
                    if c == b' ' as u16 && !in_quotes {
                        i += 1;
                        while *cmd_ptr.add(i) == b' ' as u16 {
                            i += 1;
                        }
                        cmd_ptr = cmd_ptr.add(i);
                        break;
                    }
                    i += 1;
                }
            }

            // hInstance = the exe's own module base (GetModuleHandle(NULL)).
            // nCmdShow  = 10 (SW_SHOWDEFAULT).
            let h_instance = GetModuleHandleA(None).map(|h| h.0 as HINSTANCE).unwrap_or(0);
            log("Handing execution to UnityPlayer.dll!UnityMain.");
            return unity_main(h_instance, std::ptr::null_mut(), cmd_ptr, 10);
        }

        log("FATAL: UnityMain export not found in UnityPlayer.dll.");
        1
    }
}

#[no_mangle]
pub extern "system" fn DllMain(
    _module: HMODULE,
    reason: u32,
    _reserved: *mut c_void,
) -> BOOL {
    if reason == DLL_PROCESS_ATTACH {
        unsafe {
            let mut path_buf = [0u16; 512];
            let len = GetModuleFileNameW(Some(_module), &mut path_buf);
            if len > 0 {
                let dll_path = String::from_utf16_lossy(&path_buf[..len as usize]);
                if let Some(dir) = resolve_module_directory(&dll_path) {
                    let _ = DLL_DIRECTORY.set(dir);
                }
            }

            // Directory of the game executable — used for packer-layout detection.
            // In the DMM flow this differs from DLL_DIRECTORY since gatejumper.dll
            // is injected from an external folder.
            let mut proc_buf = [0u16; 512];
            let proc_len = GetModuleFileNameW(None, &mut proc_buf);
            if proc_len > 0 {
                let proc_path = String::from_utf16_lossy(&proc_buf[..proc_len as usize]);
                if let Some(dir) = resolve_module_directory(&proc_path) {
                    let _ = PROCESS_DIRECTORY.set(dir);
                }
            }
        }

        log_session_start();
        let plugin_loading_enabled = should_auto_load_plugins();
        log_bootstrap_summary();

        unsafe {
            if plugin_loading_enabled {
                load_plugins_from_directory();
                log("Early GateJumper plugin scan completed before profile bootstrap.");
            }

            if runtime_config().driver_suppression {
                log("Driver suppression is enabled via GATEJUMPER_SUPPRESS_DRIVERS; runtime interception will be deferred to a post-attach thread.");
            } else {
                log("Driver suppression remains disabled by default; runtime interception hooks are opt-in only.");
            }
        }

        let profile = detect_game_profile();
        apply_profile_bootstrap(profile);
        log(&format!("Execution profile selected: {:?}.", profile));
    }
    1
}


