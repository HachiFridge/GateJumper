//! GateJumper Payload
//!
//! Proxies system DLL exports, suppresses anti-cheat checks, and performs OEP hijack.

#![windows_subsystem = "windows"]
#![allow(non_snake_case, non_upper_case_globals)]

use std::{env, ffi::c_void, fs::OpenOptions, io::Write, path::PathBuf};

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

fn runtime_config() -> RuntimeConfig {
    let driver_suppression = env::var("GATEJUMPER_SUPPRESS_DRIVERS")
        .map(|v| v.eq_ignore_ascii_case("1") || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes"))
        .unwrap_or(false);

    let strict_runtime_probe_filter = env::var("GATEJUMPER_STRICT_PROBES")
        .map(|v| !v.eq_ignore_ascii_case("0") && !v.eq_ignore_ascii_case("false") && !v.eq_ignore_ascii_case("no"))
        .unwrap_or(true);

    RuntimeConfig {
        driver_suppression,
        strict_runtime_probe_filter,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GameProfile {
    DirectOepUnity,
    HookedRuntimeUnity,
    PartialCrackproofUnity,
}

unsafe fn dll_directory_snapshot() -> Option<PathBuf> {
    let ptr = std::ptr::addr_of!(DLL_DIRECTORY);
    (*ptr).as_ref().cloned()
}

fn detect_local_redirection() -> bool {
    let Some(dir) = (unsafe { dll_directory_snapshot() }) else {
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

fn detect_partial_crackproof_layout() -> bool {
    let Some(dir) = (unsafe { dll_directory_snapshot() }) else {
        return false;
    };

    if detect_local_redirection() || dir.join("installer").is_dir() {
        return false;
    }

    let mut saw_gameassembly = false;
    let mut saw_unityplayer = false;

    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Some(ext) = path.extension().and_then(|s| s.to_str()) else {
                continue;
            };
            if !ext.eq_ignore_ascii_case("dll") {
                continue;
            }

            let lower = path.file_name().and_then(|s| s.to_str()).unwrap_or("").to_ascii_lowercase();
            if lower == "gameassembly.dll" {
                saw_gameassembly = true;
            } else if lower == "unityplayer.dll" {
                saw_unityplayer = true;
            }
        }
    }

    saw_gameassembly && saw_unityplayer
}

fn detect_full_crackproof_layout() -> bool {
    let Some(dir) = (unsafe { dll_directory_snapshot() }) else {
        return false;
    };

    if detect_local_redirection() {
        return true;
    }

    if dir.join("installer").is_dir() && dir.join("UnityCrashHandler64.exe").is_file() {
        return true;
    }

    false
}

fn detect_game_profile() -> GameProfile {
    // Explicit overrides are generic and intentionally not game-specific.
    if let Ok(profile_var) = env::var("GATEJUMPER_PROFILE") {
        let lower = profile_var.to_ascii_lowercase();
        if lower.contains("partial") || lower.contains("crackproof") {
            return GameProfile::PartialCrackproofUnity;
        }
        if lower.contains("hook") || lower.contains("runtime") {
            return GameProfile::HookedRuntimeUnity;
        }
        if lower.contains("direct") || lower.contains("oep") {
            return GameProfile::DirectOepUnity;
        }
    }

    if detect_local_redirection() {
        return GameProfile::DirectOepUnity;
    }
    if detect_full_crackproof_layout() {
        return GameProfile::DirectOepUnity;
    }
    if detect_partial_crackproof_layout() {
        return GameProfile::PartialCrackproofUnity;
    }

    GameProfile::HookedRuntimeUnity
}



// --- Logging ---

static mut DLL_DIRECTORY: Option<PathBuf> = None;
static mut DEFERRED_BOOTSTRAP_SCHEDULED: bool = false;
static mut CURRENT_PROFILE: GameProfile = GameProfile::HookedRuntimeUnity;
static mut UNITY_PROXY_MODULE: usize = 0;

// Relay LoadLibraryExW calls for cri_ware_unity to LoadLibraryW so mod hooks fire.
static mut LOAD_LIBRARY_EX_W_CRIWARE_ORIG: usize = 0;

unsafe fn log(msg: &str) {
    let log_path = if let Some(ref dir) = DLL_DIRECTORY {
        dir.join("gatejumper.log")
    } else {
        PathBuf::from("gatejumper.log")
    };
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
    {
        let _ = writeln!(file, "[GateJumper] {}", msg);
    }
}

/// Like log() but writes to gatejumper-deferred.log which is never truncated by DllMain.
unsafe fn log_deferred(msg: &str) {
    let log_path = if let Some(ref dir) = DLL_DIRECTORY {
        dir.join("gatejumper-deferred.log")
    } else {
        PathBuf::from("gatejumper-deferred.log")
    };
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
    {
        let _ = writeln!(file, "[GateJumper-Deferred] {}", msg);
    }
}

unsafe fn truncate_log() {
    let log_path = if let Some(ref dir) = DLL_DIRECTORY {
        dir.join("gatejumper.log")
    } else {
        PathBuf::from("gatejumper.log")
    };
    let _ = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(log_path);
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

fn is_suppressed_runtime_probe(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
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
    unsafe {
        if let Some(ref dir) = DLL_DIRECTORY {
            return dir.join("plugins");
        }
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

fn log_bootstrap_summary() {
    let cfg = runtime_config();
    let profile = detect_game_profile();
    let gatejumper_plugin_loading = should_auto_load_plugins();
    unsafe {
        log("=== GateJumper Payload loaded ===");
        log(&format!(
            "Runtime profile: {:?}; gatejumper_plugin_loading={}, driver_suppression={}, strict_probe_filter={}",
            profile,
            gatejumper_plugin_loading,
            cfg.driver_suppression,
            cfg.strict_runtime_probe_filter,
        ));
    }
}

unsafe extern "system" fn deferred_runtime_bootstrap(_param: *mut c_void) -> u32 {
    log("Deferred bootstrap thread started.");
    Sleep(250);
    log_deferred("Deferred bootstrap delay completed.");

    if runtime_config().driver_suppression {
        setup_hooks();
        log_deferred("Deferred runtime hooks enabled.");
    }

    if CURRENT_PROFILE == GameProfile::PartialCrackproofUnity {
        relay_criware_load_through_library_w();
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
    unsafe {
        CURRENT_PROFILE = profile;

        match profile {
            GameProfile::DirectOepUnity => {
                patch_entry_point_to_unity("Direct OEP hijack enabled.");
            }
            GameProfile::HookedRuntimeUnity => {
                schedule_deferred_runtime_bootstrap();
                log("Hooked runtime profile: deferred bootstrap scheduled after DllMain.");
            }
            GameProfile::PartialCrackproofUnity => {
                install_load_library_ex_w_criware_hook();
                schedule_deferred_runtime_bootstrap();
                log("Partial profile: original OEP preserved; LoadLibraryExW criware relay installed.");
            }
        }
    }
}

unsafe fn patch_entry_point_to_unity(message: &str) {
    // Patching a .bind OEP is correct — the JMP fires before the packer stub runs.

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
    if should_suppress_driver_checks() {
        if !obj_attr.is_null() {
            if let Ok(path_str) = PCWSTR(obj_attr as *const u16).to_string() {
                let lower = path_str.to_ascii_lowercase();
                if lower.contains("usrdrv017864") || (lower.contains("usrdrv") && lower.ends_with(".sys")) {
                    log(&format!("[SUPPRESSED] NtCreateFile for driver: {}", path_str));
                    return NTSTATUS(-2);
                }
            }
        }
    }
    let orig: NtCreateFileFn = std::mem::transmute(NT_CREATE_FILE_ORIG);
    orig(handle, access, obj_attr, io_stat, alloc, attrs)
}

/// Poll for cri_ware_unity.dll and relay its load through LoadLibraryW so any
/// hooked LoadLibraryW installed by a mod loader fires and triggers its init sequence.
unsafe fn relay_criware_load_through_library_w() {
    use windows::Win32::Foundation::HMODULE;
    use windows::Win32::System::ProcessStatus::{
        EnumProcessModulesEx, GetModuleBaseNameW, GetModuleFileNameExW, LIST_MODULES_ALL,
    };

    // Maximum wait: 400 × 50 ms = 20 seconds.
    const MAX_POLLS: u32 = 400;
    const POLL_INTERVAL_MS: u32 = 50;

    for attempt in 0..MAX_POLLS {
        Sleep(POLL_INTERVAL_MS);

        let mut modules = vec![HMODULE::default(); 2048];
        let mut cb_needed = 0u32;

        if EnumProcessModulesEx(
            windows::Win32::System::Threading::GetCurrentProcess(),
            modules.as_mut_ptr(),
            (modules.len() * std::mem::size_of::<HMODULE>()) as u32,
            &mut cb_needed,
            LIST_MODULES_ALL,
        ).is_err() {
            continue;
        }

        let count = cb_needed as usize / std::mem::size_of::<HMODULE>();
        for i in 0..count {
            let h = modules[i];
            if h.is_invalid() || h.0 as usize == 0 {
                continue;
            }

            let mut name_buf = [0u16; 64];
            let name_len = GetModuleBaseNameW(
                windows::Win32::System::Threading::GetCurrentProcess(),
                Some(h),
                &mut name_buf,
            ) as usize;
            if name_len == 0 {
                continue;
            }

            let base_name = String::from_utf16_lossy(&name_buf[..name_len]).to_ascii_lowercase();
            if !base_name.contains("cri_ware_unity") {
                continue;
            }

            // Found it — get the full path and relay through LoadLibraryW.
            let mut path_buf = [0u16; 520];
            let path_len = GetModuleFileNameExW(
                Some(windows::Win32::System::Threading::GetCurrentProcess()),
                Some(h),
                &mut path_buf,
            ) as usize;

            if path_len == 0 {
                // Fallback: use the base name only.
                let mut wide: Vec<u16> = base_name.encode_utf16().collect();
                wide.push(0);
                log_deferred(&format!(
                    "cri_ware_unity detected after ~{}ms (path unknown); relaying via LoadLibraryW.",
                    attempt * POLL_INTERVAL_MS
                ));
                let _ = LoadLibraryW(PCWSTR(wide.as_ptr()));
            } else {
                let full_path = String::from_utf16_lossy(&path_buf[..path_len]);
                log_deferred(&format!(
                    "cri_ware_unity detected after ~{}ms ({}); relaying via LoadLibraryW.",
                    attempt * POLL_INTERVAL_MS,
                    full_path
                ));
                let _ = LoadLibraryW(PCWSTR(path_buf.as_ptr()));
            }
            return;
        }
    }

    log_deferred("WARN: cri_ware_unity did not appear within 20s; mod loader relay skipped.");
}

// Hook LoadLibraryExW to relay cri_ware_unity.dll loads to LoadLibraryW.
unsafe extern "system" fn load_library_ex_w_criware_hook(
    filename: PCWSTR,
    file: *mut c_void,
    flags: u32,
) -> HMODULE {
    type Fn = extern "system" fn(PCWSTR, *mut c_void, u32) -> HMODULE;
    let orig: Fn = std::mem::transmute(LOAD_LIBRARY_EX_W_CRIWARE_ORIG);
    let handle = orig(filename, file, flags);

    if !handle.is_invalid() && handle.0 as usize != 0 && !filename.0.is_null() {
        if let Ok(name) = filename.to_string() {
            let lower = name.to_ascii_lowercase();
            let basename = lower
                .rfind('\\')
                .or_else(|| lower.rfind('/'))
                .map(|i| &lower[i + 1..])
                .unwrap_or(&lower);

            log_deferred(&format!("LoadLibraryExW: {}", basename));

            if basename.contains("cri_ware_unity") {
                log_deferred(&format!("LoadLibraryExW criware relay: {}; calling LoadLibraryW.", name));
                log(&format!("LoadLibraryExW criware relay: {}.", name));

                // Remove self — one-shot hook.
                if let Some(func) = GetProcAddress(
                    GetModuleHandleA(PCSTR(b"kernel32.dll\0".as_ptr())).unwrap(),
                    PCSTR(b"LoadLibraryExW\0".as_ptr()),
                ) {
                    let _ = minhook::MinHook::disable_hook(func as *mut c_void);
                    let _ = minhook::MinHook::remove_hook(func as *mut c_void);
                }

                // Replay through LoadLibraryW so any hooked LoadLibraryW fires.
                // filename is still valid here (caller's stack).
                let _ = LoadLibraryW(filename);
            }
        }
    }

    handle
}

fn install_load_library_ex_w_criware_hook() {
    unsafe {
        let k32 = match GetModuleHandleA(PCSTR(b"kernel32.dll\0".as_ptr())) {
            Ok(h) => h,
            Err(_) => { log("WARN: criware hook: could not get kernel32 handle."); return; }
        };
        let func = match GetProcAddress(k32, PCSTR(b"LoadLibraryExW\0".as_ptr())) {
            Some(f) => f,
            None => { log("WARN: criware hook: GetProcAddress(LoadLibraryExW) failed."); return; }
        };
        match minhook::MinHook::create_hook(
            func as *mut c_void,
            load_library_ex_w_criware_hook as *mut c_void,
        ) {
            Ok(trampoline) => {
                LOAD_LIBRARY_EX_W_CRIWARE_ORIG = trampoline as usize;
                let _ = minhook::MinHook::enable_hook(func as *mut c_void);
                log("LoadLibraryExW criware relay hook installed.");
            }
            Err(e) => log(&format!("WARN: LoadLibraryExW criware hook failed: {:?}", e)),
        }
    }
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
                    unsafe {
                        log(&format!("Skipping self/conflicting DLL: {}", path.display()));
                    }
                    continue;
                }

                if !is_allowlisted_plugin(&path) {
                    unsafe {
                        log(&format!("Skipping unapproved plugin: {}", path.display()));
                    }
                    continue;
                }

                if let Some(path_str) = path.to_str() {
                    let mut w_path: Vec<u16> = path_str.encode_utf16().collect();
                    w_path.push(0);
                    let load_result = unsafe { LoadLibraryW(PCWSTR(w_path.as_ptr())) };
                    if let Ok(h_mod) = load_result {
                        unsafe {
                            log(&format!("Successfully loaded plugin: {}", path_str));
                            if GetProcAddress(h_mod, PCSTR(b"UnityMain\0".as_ptr())).is_some() {
                                UNITY_PROXY_MODULE = h_mod.0 as usize;
                                log(&format!("Selected UnityMain provider: {}", path_str));
                            }
                        }
                        *loaded += 1;
                    } else {
                        unsafe {
                            log(&format!("Failed to load plugin: {}", path_str));
                        }
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

#[allow(dead_code)]
pub extern "system" fn launch_unity() -> i32 {
    unsafe {
        log("OEP Hijack triggered. Launching Unity Engine...");

        if UNITY_PROXY_MODULE != 0 {
            log("Note: UnityMain provider is loaded; Unity will be started via UnityPlayer.dll directly.");
        }

        let unity_path: Vec<u16> = "UnityPlayer.dll\0".encode_utf16().collect();
        let h_unity = match LoadLibraryW(PCWSTR(unity_path.as_ptr())) {
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

// --- DllMain ---

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
                    DLL_DIRECTORY = Some(dir);
                }
            }

            truncate_log();
            let cfg = runtime_config();
            let plugin_loading_enabled = should_auto_load_plugins();
            log_bootstrap_summary();

            // GateJumper plugins are an independent early-load mechanism. Load them before the
            // selected profile starts or returns to the game's original entry point.
            if plugin_loading_enabled {
                load_plugins_from_directory();
                log("Early GateJumper plugin scan completed before profile bootstrap.");
            }

            if cfg.driver_suppression {
                log("Driver suppression is enabled via GATEJUMPER_SUPPRESS_DRIVERS; runtime interception will be deferred to a post-attach thread.");
            } else {
                log("Driver suppression remains disabled by default; runtime interception hooks are opt-in only.");
            }

            let profile = detect_game_profile();
            apply_profile_bootstrap(profile);

            log(&format!("Execution profile selected: {:?}.", profile));
        }
    }
    1
}


