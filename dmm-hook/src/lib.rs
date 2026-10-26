//! DMM-Hook — injected into the DMM Game Player launcher to intercept game spawns.

#![allow(non_snake_case)]

use std::{ffi::c_void, fs::OpenOptions, io::Write, path::{Path, PathBuf}, sync::OnceLock};
use std::sync::atomic::{AtomicU32, Ordering};

type BOOL = i32;
type HINSTANCE = isize;

use windows::{
    core::{PCSTR, PCWSTR, PWSTR},
    Win32::{
        Foundation::HWND,
        System::{
            LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA},
            Threading::{PROCESS_INFORMATION, STARTUPINFOW, STARTUPINFOA, QueueUserAPC, ResumeThread},
            Diagnostics::Debug::WriteProcessMemory,
            Memory::{
                VirtualAllocEx, VirtualProtectEx,
                MEM_COMMIT, MEM_RESERVE,
                PAGE_EXECUTE_READ, PAGE_READWRITE, PAGE_PROTECTION_FLAGS,
            },
        },
        UI::Shell::SHELLEXECUTEINFOW,
    },
};

const DLL_PROCESS_ATTACH: u32 = 1;

/// Return value for ShellExecuteW/A hooks when we handled the launch ourselves.
/// Must be > 32 to indicate success per the ShellExecute API contract.
const SHELL_EXECUTE_SUCCESS: HINSTANCE = 42;

/// Set once in DllMain before any other threads are spawned.
static DLL_DIRECTORY: OnceLock<std::path::PathBuf> = OnceLock::new();

/// Lowercased file name + directory of the process this hook runs in.
static OWN_IMAGE: OnceLock<(String, PathBuf)> = OnceLock::new();

fn log(msg: &str) {
    let log_path = match DLL_DIRECTORY.get() {
        Some(dir) => dir.join("gatejumper.log"),
        None => std::path::PathBuf::from("gatejumper.log"),
    };
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(log_path) {
        let _ = writeln!(file, "[DMM-Hook] {}", msg);
    }
}

const MAX_LAUNCH_ENTRIES: usize = 5;

fn count_launch_entries(content: &str) -> usize {
    let mut seen = std::collections::HashSet::new();
    for line in content.lines() {
        if line.contains("───────────────────────────────────") {
            let trimmed = line.trim_matches(|c| c == '─' || c == ' ' || c == '\r' || c == '\n');
            if !trimmed.is_empty() {
                seen.insert(trimmed);
            }
        }
    }
    seen.len()
}

fn log_session_start() {
    use windows::Win32::System::SystemInformation::GetSystemTime;
    use windows::Win32::Foundation::SYSTEMTIME;
    let st: SYSTEMTIME = unsafe { GetSystemTime() };
    let log_path = match DLL_DIRECTORY.get() {
        Some(dir) => dir.join("gatejumper.log"),
        None => std::path::PathBuf::from("gatejumper.log"),
    };
    let deferred_path = match DLL_DIRECTORY.get() {
        Some(dir) => dir.join("gatejumper-deferred.log"),
        None => std::path::PathBuf::from("gatejumper-deferred.log"),
    };

    let time_str = format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond
    );

    if let Ok(content) = std::fs::read_to_string(&log_path) {
        if content.contains(&time_str) {
            return;
        }
        if count_launch_entries(&content) >= MAX_LAUNCH_ENTRIES {
            let _ = std::fs::remove_file(&log_path);
            let _ = std::fs::remove_file(&deferred_path);
        }
    }

    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&log_path) {
        let _ = writeln!(
            file,
            "\n{} {} {}",
            "─".repeat(35),
            time_str,
            "─".repeat(35),
        );
    }
}

// --- Configuration ---
//
// `gatejumper.ini` beside dmmhook.dll (the GateJumper folder DMM never touches)
// drives everything: `[main]` for the injector, one `[<exe>]` section per armed
// game (`dir`, `plugins`). Parsed once at DLL load. A spawn matches its own
// game-dir gatejumper.ini first, then the global section (dir, when present,
// must match), else an in-game gatejumper.dll counts as implicit; anything
// else launches untouched.

#[derive(Clone, Debug, Default)]
struct GameEntry {
    /// Directory the game is expected to live in (from `dir = <path>`).
    target_dir: Option<PathBuf>,
    /// Explicit plugin-loading override (`plugins = true/false`). `None` means
    /// inherit the default behaviour (load if `plugins/` directory exists).
    plugins: Option<bool>,
}

#[derive(Debug, Default)]
struct HookConfig {
    dmm: bool,
    main_target: Option<PathBuf>,
    /// `(exe file name lowercased, entry)` pairs, in file order.
    games: Vec<(String, GameEntry)>,
}

static HOOK_CONFIG: OnceLock<HookConfig> = OnceLock::new();

/// Strip a trailing ` # ...` / ` ; ...` comment from a value line. A comment
/// marker only counts when preceded by whitespace so paths containing `#` or
/// `;` are left intact.
fn strip_trailing_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if (b == b'#' || b == b';')
            && i > 0
            && bytes[i - 1].is_ascii_whitespace()
        {
            return line[..i].trim_end();
        }
    }
    line
}

fn exe_name_from_section(section: &str) -> String {
    Path::new(section.trim())
        .file_name()
        .map(|s| s.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_else(|| section.trim().to_ascii_lowercase())
}

/// Parse the multi-game config. Files without any `[section]` header are
/// treated as belonging to `[main]`, keeping old single-game configs valid.
fn parse_config(content: &str) -> HookConfig {
    let mut cfg = HookConfig::default();
    let mut section = String::from("main");

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        if line.starts_with('[') {
            if let Some(rest) = line.strip_prefix('[') {
                if let Some(name) = rest.strip_suffix(']') {
                    section = name.trim().to_string();
                }
            }
            continue;
        }

        let Some((key, value)) = line.split_once('=') else { continue };
        let key = key.trim().to_ascii_lowercase();
        let value = strip_trailing_comment(value.trim()).trim().trim_matches('"');
        if value.is_empty() { continue; }

        if section.eq_ignore_ascii_case("main") {
            match key.as_str() {
                "dmm" => {
                    cfg.dmm = value.eq_ignore_ascii_case("true")
                        || value.eq_ignore_ascii_case("yes")
                        || value == "1";
                }
                "target" => cfg.main_target = Some(PathBuf::from(value)),
                _ => {}
            }
            continue;
        }

        // Per-game section: keyed by the game executable's file name.
        let exe_name = exe_name_from_section(&section);
        let entry = cfg.games.iter_mut().find(|(name, _)| *name == exe_name);
        match key.as_str() {
            "dir" => {
                if let Some((_, e)) = entry {
                    e.target_dir = Some(PathBuf::from(value));
                } else {
                    let mut e = GameEntry::default();
                    e.target_dir = Some(PathBuf::from(value));
                    cfg.games.push((exe_name, e));
                }
            }
            "plugins" => {
                let enabled = value.eq_ignore_ascii_case("true")
                    || value.eq_ignore_ascii_case("yes")
                    || value == "1";
                let disabled = value.eq_ignore_ascii_case("false")
                    || value.eq_ignore_ascii_case("no")
                    || value == "0";
                if enabled || disabled {
                    if let Some((_, e)) = entry {
                        e.plugins = Some(enabled);
                    } else {
                        let mut e = GameEntry::default();
                        e.plugins = Some(enabled);
                        cfg.games.push((exe_name, e));
                    }
                }
            }
            _ => {}
        }
    }
    cfg
}

/// Normalized aliases of a path — slashes folded, lowercased — plus the
/// spellings Wine/prefix managers (Steam, Bottles, Lutris, Faugus) use for the
/// same location: `Z:` for a Unix absolute path, and `drive_<letter>` segments
/// mapped to `<letter>:\…`.
fn path_variants(path: &str) -> Vec<String> {
    let s = path.replace('/', "\\").to_ascii_lowercase();
    let t = s.trim_end_matches('\\').to_string();
    let mut out = vec![t.clone()];
    if t.starts_with('\\') {
        // Lowercase to match the lowercased base form — variants are compared
        // literally and must agree on case.
        out.push(format!("z:{}", t));
    }
    if let Some(idx) = t.find("\\drive_") {
        let rest = &t[idx + 7..]; // past "\drive_"
        let b = rest.as_bytes();
        if b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b'\\' {
            out.push(format!("{}:{}", b[0] as char, &rest[1..]));
        }
    }
    out
}

/// True when any normalized alias of `a` equals any alias of `b`.
fn dirs_equal(a: &Path, b: &Path) -> bool {
    let av = path_variants(&a.to_string_lossy());
    let bv = path_variants(&b.to_string_lossy());
    av.iter().any(|x| bv.contains(x))
}

// --- Carrier propagation (DMM Fast Launcher) ---

/// Interpreters a launcher may put between itself and the game (DMM Fast
/// Launcher: `subprocess.Popen(shell=True)` → `cmd.exe /c …`). The hook chain
/// doesn't survive into unarmed children, so the carrier must be armed.
fn is_carrier_exe(exe_name: &str) -> bool {
    matches!(exe_name, "cmd.exe" | "powershell.exe" | "pwsh.exe")
}

/// Does this lowercased command line reference an armed game? Name-based so
/// Windows and Wine/prefix spellings behave alike; the authoritative `dir`
/// match still happens on the game's own spawn.
fn config_carries_game(cfg: &HookConfig, cmd_lower: &str) -> bool {
    !cfg.games.is_empty() && cfg.games.iter().any(|(name, _)| cmd_lower.contains(name.as_str()))
}

fn command_line_carries_game(cmd_lower: &str) -> bool {
    HOOK_CONFIG.get().map(|cfg| config_carries_game(cfg, cmd_lower)).unwrap_or(false)
}

/// A same-name, same-directory spawn is the launcher's own runtime child
/// (PyInstaller one-file re-executes itself as the real process); the hook
/// chain must follow it or every launch it performs goes unseen.
fn is_own_image(exe_name: &str, exe_dir: &Path) -> bool {
    OWN_IMAGE.get()
        .map(|(n, d)| n == exe_name && dirs_equal(d, exe_dir))
        .unwrap_or(false)
}

/// Cap on carriers one hooked process may arm.
static CARRIER_ARMS: AtomicU32 = AtomicU32::new(0);
const MAX_CARRIER_ARMS: u32 = 3;

/// Result of matching a spawned game against the configuration.
struct MatchResult {
    /// Explicit plugin-loading override, or `None` to use the default
    /// (load if `plugins/` directory exists beside the payload).
    plugins: Option<bool>,
}

/// Resolve what to do with a launched game. Returns a `MatchResult` when the
/// game matches — an individual `gatejumper.ini` in the game's directory, a
/// `[<exe>]` section of the global config, or a `gatejumper.dll` sitting in
/// the game's directory — and `None` overall when it should be launched untouched.
fn resolve_match(exe_name: &str, exe_dir: &Path) -> Option<MatchResult> {
    // 1. Individual config inside the game directory — highest priority.
    let game_ini = exe_dir.join("gatejumper.ini");
    if game_ini.is_file() {
        log(&format!("Game '{}': matched via game-directory gatejumper.ini.", exe_name));
        return Some(MatchResult { plugins: None });
    }

    // 2. `[<exe name>]` section of the global config beside dmmhook.dll.
    if let Some(cfg) = HOOK_CONFIG.get() {
        if let Some((_, entry)) = cfg.games.iter().find(|(name, _)| name == exe_name) {
            if let Some(target_dir) = &entry.target_dir {
                if !dirs_equal(target_dir, exe_dir) {
                    log(&format!(
                        "Game '{}' ignored: spawned from '{}' but config dir is '{}'.",
                        exe_name, exe_dir.display(), target_dir.display(),
                    ));
                    return None;
                }
            }

            let plugins = entry.plugins;
            log(&format!("Game '{}': matched global config{}.", exe_name,
                plugins.map(|v| format!(", plugins={}", v)).unwrap_or_default()));
            return Some(MatchResult { plugins });
        }
    }

    // 3. Implicit match via standalone gatejumper.dll in the game's directory.
    if exe_dir.join("gatejumper.dll").is_file() {
        log(&format!("Game '{}': matched via gatejumper.dll in game directory.", exe_name));
        return Some(MatchResult { plugins: None });
    }

    None
}

// --- Ntdll FFI ---

#[repr(C)]
struct PROCESS_BASIC_INFORMATION {
    Reserved1:       *mut c_void,
    PebBaseAddress:  *mut c_void,
    Reserved2:       [*mut c_void; 2],
    UniqueProcessId: usize,
    Reserved3:       *mut c_void,
}

extern "system" {
    fn NtQueryInformationProcess(
        ProcessHandle:            windows::Win32::Foundation::HANDLE,
        ProcessInformationClass:  u32,
        ProcessInformation:       *mut c_void,
        ProcessInformationLength: u32,
        ReturnLength:             *mut u32,
    ) -> i32;

    fn NtReadVirtualMemory(
        ProcessHandle:       windows::Win32::Foundation::HANDLE,
        BaseAddress:         *const c_void,
        Buffer:              *mut c_void,
        NumberOfBytesToRead: usize,
        NumberOfBytesRead:   *mut usize,
    ) -> i32;
}

// --- Stealth hooks ---

static mut PATH_FILE_EXISTS_W_ORIG:    usize = 0;
static mut NT_QUERY_INFO_PROCESS_ORIG: usize = 0;

type PathFileExistsWFn    = extern "system" fn(PCWSTR) -> BOOL;
type NtQueryInfoProcessFn = extern "system" fn(
    windows::Win32::Foundation::HANDLE, u32, *mut c_void, u32, *mut u32,
) -> i32;

// Suppress .exe.local / .dll.local / apphelp.dll existence probes — no hardcoded names.
unsafe extern "system" fn path_file_exists_w_hook(filename: PCWSTR) -> BOOL {
    let orig: PathFileExistsWFn = std::mem::transmute(PATH_FILE_EXISTS_W_ORIG);
    if !filename.0.is_null() {
        if let Ok(s) = filename.to_string() {
            let lower = s.to_ascii_lowercase();
            let base = lower.rfind('\\').map(|i| &lower[i + 1..]).unwrap_or(&lower);
            if base.ends_with(".exe.local") || base.ends_with(".dll.local") || base == "apphelp.dll" {
                use windows::Win32::Foundation::{SetLastError, ERROR_FILE_NOT_FOUND};
                SetLastError(ERROR_FILE_NOT_FOUND);
                return 0;
            }
        }
    }
    orig(filename)
}

// Suppress ProcessDebugPort (7) and ProcessDebugObjectHandle (30) queries.
unsafe extern "system" fn nt_query_info_process_hook(
    h: windows::Win32::Foundation::HANDLE,
    class: u32,
    info: *mut c_void,
    len: u32,
    ret_len: *mut u32,
) -> i32 {
    let orig: NtQueryInfoProcessFn = std::mem::transmute(NT_QUERY_INFO_PROCESS_ORIG);
    if class == 7 || class == 30 {
        if !info.is_null() && len > 0 { std::ptr::write_bytes(info as *mut u8, 0, len as usize); }
        if !ret_len.is_null() { *ret_len = len; }
        return 0;
    }
    orig(h, class, info, len, ret_len)
}

fn setup_stealth_hooks() {
    unsafe {
        if let Ok(shlwapi) = LoadLibraryA(PCSTR(b"shlwapi.dll\0".as_ptr())) {
            if let Some(f) = GetProcAddress(shlwapi, PCSTR(b"PathFileExistsW\0".as_ptr())) {
                if let Ok(t) = minhook::MinHook::create_hook(f as *mut c_void, path_file_exists_w_hook as *mut c_void) {
                    PATH_FILE_EXISTS_W_ORIG = t as usize;
                    let _ = minhook::MinHook::enable_hook(f as *mut c_void);
                    log("PathFileExistsW stealth hook installed.");
                }
            }
        }
        if let Ok(ntdll) = GetModuleHandleA(PCSTR(b"ntdll.dll\0".as_ptr())) {
            if let Some(f) = GetProcAddress(ntdll, PCSTR(b"NtQueryInformationProcess\0".as_ptr())) {
                if let Ok(t) = minhook::MinHook::create_hook(f as *mut c_void, nt_query_info_process_hook as *mut c_void) {
                    NT_QUERY_INFO_PROCESS_ORIG = t as usize;
                    let _ = minhook::MinHook::enable_hook(f as *mut c_void);
                    log("NtQueryInformationProcess stealth hook installed.");
                }
            }
        }
    }
}

// --- Remote process helpers ---

unsafe fn get_process_image_base(h: windows::Win32::Foundation::HANDLE) -> Option<usize> {
    let mut pbi: PROCESS_BASIC_INFORMATION = std::mem::zeroed();
    let mut ret = 0u32;
    if NtQueryInformationProcess(h, 0, &mut pbi as *mut _ as *mut c_void,
        std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32, &mut ret) >= 0
        && !pbi.PebBaseAddress.is_null()
    {
        let mut base = 0usize;
        let mut read = 0usize;
        if NtReadVirtualMemory(h, (pbi.PebBaseAddress as usize + 0x10) as *const c_void,
            &mut base as *mut _ as *mut c_void, 8, &mut read) >= 0
        {
            return Some(base);
        }
    }
    None
}

// --- Process identity ---

// The launched process's own image path (authoritative — the exe that actually
// got loaded, wherever the launcher resolved it from). Works on the suspended
// process; the image name is fixed before the first thread runs.
fn query_process_image_name(pi: &PROCESS_INFORMATION) -> Option<String> {
    use windows::Win32::System::Threading::{QueryFullProcessImageNameW, PROCESS_NAME_FORMAT};
    let mut buf = [0u16; 1024];
    let mut size = buf.len() as u32;
    let ok = unsafe {
        QueryFullProcessImageNameW(
            pi.hProcess,
            PROCESS_NAME_FORMAT(0),
            PWSTR(buf.as_mut_ptr()),
            &mut size,
        )
    };
    if ok.is_ok() && size > 0 && size < buf.len() as u32 {
        Some(String::from_utf16_lossy(&buf[..size as usize]))
    } else {
        None
    }
}

// Extract the first executable path token from `lpApplicationName` or a
// command line like `"C:\path with spaces\game.exe" -arg` or
// `C:\path\game.exe -arg`. Used only as a fallback when the image query fails.
fn exe_path_from_create_params(lpApplicationName: PCWSTR, lpCommandLine: PWSTR) -> Option<String> {
    if !lpApplicationName.0.is_null() {
        if let Ok(s) = unsafe { lpApplicationName.to_string() } {
            if !s.is_empty() { return Some(s); }
        }
    }
    if lpCommandLine.0.is_null() { return None; }
    let cmd = unsafe { lpCommandLine.to_string() }.ok()?;
    let cmd = cmd.trim();
    if cmd.is_empty() { return None; }
    if let Some(stripped) = cmd.strip_prefix('"') {
        let end = stripped.find('"')?;
        let path = stripped[..end].trim();
        if !path.is_empty() { return Some(path.to_string()); }
        None
    } else {
        let end = cmd.find(' ').unwrap_or(cmd.len());
        let path = cmd[..end].trim();
        if !path.is_empty() { Some(path.to_string()) } else { None }
    }
}

/// Identify a spawned process as `(exe file name, exe directory)`.
fn process_identity(
    lpApplicationName: PCWSTR,
    lpCommandLine: PWSTR,
    pi: &PROCESS_INFORMATION,
) -> Option<(String, PathBuf)> {
    let exe_path = query_process_image_name(pi)
        .or_else(|| exe_path_from_create_params(lpApplicationName, lpCommandLine))?;
    let p = PathBuf::from(&exe_path);
    let name = p.file_name()?.to_string_lossy().to_ascii_lowercase();
    let dir = p.parent()?.to_path_buf();
    Some((name, dir))
}

// --- Shellcode construction ---

/// Byte offsets of the shellcode's critical instructions, for verification.
#[derive(Debug, Default)]
struct ShellcodeLayout {
    /// `lea r9, [rsp+0x20]` — old-protect slot for the first VirtualProtect.
    vp1_lea: usize,
    /// Index of the `call rax` ending the first VirtualProtect sequence.
    vp1_call: usize,
    /// `mov [rax], rcx` — first half of the OEP byte write-back (0x5D).
    oep_write: usize,
    /// `lea r9, [rsp+0x24]` — old-protect slot for the second VirtualProtect.
    vp2_lea: usize,
    /// `call SetEnvironmentVariableA` — 0 when no plugins override is set.
    setenv_call: usize,
    /// Operand slots patched with the payload path / env string addresses.
    dll_path_operand: usize,
    env_name_operand: usize,
    env_value_operand: usize,
}

/// Assemble the OEP-injection shellcode: save regs → OEP page writable →
/// restore the original 16 OEP bytes → protect again → optional
/// SetEnvironmentVariableA(GATEJUMPER_LOAD_PLUGINS) → LoadLibraryA(payload) →
/// restore regs → jump to OEP. The VirtualProtect old-protect slots live on
/// our own stack at [rsp+0x20, +0x28) — never in the RX shellcode page (that
/// out-pointer was the 0xC0000005 bug).
fn build_injection_shellcode(
    oep_addr: usize,
    virtual_protect_addr: usize,
    load_lib_addr: usize,
    setenv_addr: Option<usize>,
    orig_0_7: u64,
    orig_8_15: u64,
) -> (Vec<u8>, ShellcodeLayout) {
    let mut sc: Vec<u8> = Vec::new();
    let mut l = ShellcodeLayout::default();
    // Save all registers.
    sc.extend_from_slice(&[0x55,0x53,0x51,0x52,0x56,0x57,
        0x41,0x50,0x41,0x51,0x41,0x52,0x41,0x53,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57]);
    // mov rbp,rsp / and rsp,~0xF / sub rsp,0x40 — frame covers the old-protect slots.
    sc.extend_from_slice(&[0x48,0x89,0xE5, 0x48,0x83,0xE4,0xF0, 0x48,0x83,0xEC,0x40]);
    // VirtualProtect(oep, 16, PAGE_EXECUTE_READWRITE, &old); rcx = oep_addr.
    sc.extend_from_slice(&[0x48,0xB9]); sc.extend_from_slice(&(oep_addr as u64).to_le_bytes());
    // rdx = 16
    sc.extend_from_slice(&[0x48,0xC7,0xC2, 0x10,0x00,0x00,0x00]);
    // r8d = 0x40 (PAGE_EXECUTE_READWRITE)
    sc.extend_from_slice(&[0x41,0xB8, 0x40,0x00,0x00,0x00]);
    // lea r9, [rsp+0x20] — old-protect slot on our own stack (writable).
    l.vp1_lea = sc.len();
    sc.extend_from_slice(&[0x4C,0x8D,0x4C,0x24,0x20]);
    // call VirtualProtect
    sc.extend_from_slice(&[0x48,0xB8]); sc.extend_from_slice(&(virtual_protect_addr as u64).to_le_bytes());
    l.vp1_call = sc.len();
    sc.extend_from_slice(&[0xFF,0xD0]);
    // Restore the original 16 OEP bytes (rcx was clobbered; reload rax).
    sc.extend_from_slice(&[0x48,0xB8]); sc.extend_from_slice(&(oep_addr as u64).to_le_bytes()); // mov rax, oep_addr
    sc.extend_from_slice(&[0x48,0xB9]); sc.extend_from_slice(&orig_0_7.to_le_bytes());
    l.oep_write = sc.len();
    sc.extend_from_slice(&[0x48,0x89,0x08]);  // mov [rax], rcx
    sc.extend_from_slice(&[0x48,0xB9]); sc.extend_from_slice(&orig_8_15.to_le_bytes());
    sc.extend_from_slice(&[0x48,0x89,0x48,0x08]); // mov [rax+8], rcx
    // VirtualProtect(oep, 16, PAGE_EXECUTE_READ, &old) — restore protection.
    sc.extend_from_slice(&[0x48,0xB9]); sc.extend_from_slice(&(oep_addr as u64).to_le_bytes());
    sc.extend_from_slice(&[0x48,0xC7,0xC2, 0x10,0x00,0x00,0x00]);
    sc.extend_from_slice(&[0x41,0xB8, 0x20,0x00,0x00,0x00]); // r8d = PAGE_EXECUTE_READ
    // lea r9, [rsp+0x24] — second slot.
    l.vp2_lea = sc.len();
    sc.extend_from_slice(&[0x4C,0x8D,0x4C,0x24,0x24]);
    sc.extend_from_slice(&[0x48,0xB8]); sc.extend_from_slice(&(virtual_protect_addr as u64).to_le_bytes());
    sc.extend_from_slice(&[0xFF,0xD0]);

    // Call SetEnvironmentVariableA for GATEJUMPER_LOAD_PLUGINS when plugins is explicitly overridden.
    if let Some(sea) = setenv_addr {
        sc.extend_from_slice(&[0x48,0xB9]); // mov rcx, <name addr>
        l.env_name_operand = sc.len();
        sc.extend_from_slice(&[0u8; 8]);
        sc.extend_from_slice(&[0x48,0xBA]); // mov rdx, <value addr>
        l.env_value_operand = sc.len();
        sc.extend_from_slice(&[0u8; 8]);
        sc.extend_from_slice(&[0x48,0xB8]); sc.extend_from_slice(&(sea as u64).to_le_bytes());
        l.setenv_call = sc.len();
        sc.extend_from_slice(&[0xFF,0xD0]); // call SetEnvironmentVariableA
    }

    // LoadLibraryA(dll_path).
    sc.extend_from_slice(&[0x48,0xB9]);
    l.dll_path_operand = sc.len();
    sc.extend_from_slice(&[0u8; 8]);
    sc.extend_from_slice(&[0x48,0xB8]); sc.extend_from_slice(&(load_lib_addr as u64).to_le_bytes());
    sc.extend_from_slice(&[0xFF,0xD0]);
    // Restore stack, pop all registers.
    sc.extend_from_slice(&[0x48,0x89,0xEC]);
    sc.extend_from_slice(&[0x41,0x5F,0x41,0x5E,0x41,0x5D,0x41,0x5C,
        0x41,0x5B,0x41,0x5A,0x41,0x59,0x41,0x58,0x5F,0x5E,0x5A,0x59,0x5B,0x5D]);
    // JMP to restored OEP.
    sc.extend_from_slice(&[0x48,0xB8]); sc.extend_from_slice(&(oep_addr as u64).to_le_bytes());
    sc.extend_from_slice(&[0xFF,0xE0]);
    (sc, l)
}

/// Assert the byte-count invariants, on every injection: a drifted shellcode
/// must fail here, not as a 0xC0000005 in the game.
fn verify_injection_shellcode(sc: &[u8], l: &ShellcodeLayout) {
    // Prologue contains no addresses — exact offsets are safe; drift shifts landmarks.
    assert!(sc.len() >= 33, "injection shellcode truncated ({} bytes)", sc.len());
    assert_eq!(&sc[0..6], &[0x55,0x53,0x51,0x52,0x56,0x57], "register-push prologue changed");
    assert_eq!(&sc[6..22], &[0x41,0x50,0x41,0x51,0x41,0x52,0x41,0x53,
                             0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57], "REX push prologue changed");
    assert_eq!(&sc[22..33], &[0x48,0x89,0xE5,0x48,0x83,0xE4,0xF0,0x48,0x83,0xEC,0x40],
        "stack-frame setup changed");
    // Frame must cover the old-protect slots at [rsp+0x20, +0x28).
    let frame = sc[32] as usize;
    assert!(frame >= 0x28, "stack frame 0x{:02X} does not cover the old-protect slots", frame);

    // Byte-exact lea encodings: a wrong ModRM (r12 vs r9) is the shipped bug.
    assert_eq!(&sc[l.vp1_lea..l.vp1_lea + 5], &[0x4C,0x8D,0x4C,0x24,0x20], "first old-protect lea changed");
    assert_eq!(&sc[l.vp2_lea..l.vp2_lea + 5], &[0x4C,0x8D,0x4C,0x24,0x24], "second old-protect lea changed");
    // Each lea must feed `mov rax, imm64; call rax` directly.
    assert_eq!(&sc[l.vp1_lea + 5..l.vp1_lea + 7], &[0x48,0xB8], "first lea no longer feeds mov rax");
    assert_eq!(&sc[l.vp1_lea + 15..l.vp1_lea + 17], &[0xFF,0xD0], "first VirtualProtect call moved");
    assert_eq!(&sc[l.vp2_lea + 5..l.vp2_lea + 7], &[0x48,0xB8], "second lea no longer feeds mov rax");
    assert_eq!(&sc[l.vp2_lea + 15..l.vp2_lea + 17], &[0xFF,0xD0], "second VirtualProtect call moved");

    // Phase order: writable → write-back → protection restore.
    assert!(l.vp1_call < l.oep_write && l.oep_write < l.vp2_lea,
        "shellcode phase order changed (vp1_call={}, oep_write={}, vp2_lea={})",
        l.vp1_call, l.oep_write, l.vp2_lea);
    // The OEP write-back pair with its `mov rcx, imm64` reloads in between.
    assert_eq!(&sc[l.oep_write..l.oep_write + 3], &[0x48,0x89,0x08], "mov [rax], rcx changed");
    assert_eq!(&sc[l.oep_write + 13..l.oep_write + 17], &[0x48,0x89,0x48,0x08], "mov [rax+8], rcx changed");

    // Operand slots must sit behind their mov opcodes, inside the buffer.
    assert!(l.dll_path_operand >= 2 && l.dll_path_operand + 8 <= sc.len(), "dll-path operand out of range");
    assert_eq!(&sc[l.dll_path_operand - 2..l.dll_path_operand], &[0x48,0xB9], "dll-path operand not behind mov rcx");
    if l.setenv_call != 0 {
        assert_eq!(&sc[l.setenv_call..l.setenv_call + 2], &[0xFF,0xD0], "setenv call changed");
        assert_eq!(&sc[l.env_name_operand - 2..l.env_name_operand], &[0x48,0xB9], "env-name operand not behind mov rcx");
        assert_eq!(&sc[l.env_value_operand - 2..l.env_value_operand], &[0x48,0xBA], "env-value operand not behind mov rdx");
        assert!(l.env_value_operand + 8 <= sc.len(), "env-value operand out of range");
        assert!(l.oep_write < l.env_name_operand && l.env_name_operand < l.dll_path_operand,
            "setenv stage not between OEP restore and LoadLibrary");
    } else {
        assert_eq!(l.env_name_operand, 0, "env operand recorded without setenv_addr");
        assert_eq!(l.env_value_operand, 0, "env operand recorded without setenv_addr");
    }

    // Epilogue: mov rbp,rsp then the pops; tail ends with jmp rax.
    assert!(sc.len() >= 37 + 12, "shellcode too short for epilogue check");
    assert_eq!(&sc[sc.len() - 37..sc.len() - 34], &[0x48,0x89,0xEC], "mov rbp,rsp epilogue changed");
    assert_eq!(&sc[sc.len() - 2..], &[0xFF,0xE0], "shellcode does not end with jmp rax");
}

/// 16-byte OEP trampoline (`mov rax,imm64; call rax; nop×4`): must match the
/// 16-byte restore exactly — an 18-byte form left 2 OEP bytes as NOPs.
fn build_trampoline(shellcode_addr: usize) -> Vec<u8> {
    let mut t: Vec<u8> = Vec::new();
    t.extend_from_slice(&[0x48,0xB8]); t.extend_from_slice(&(shellcode_addr as u64).to_le_bytes());
    t.extend_from_slice(&[0xFF,0xE0,0x90,0x90,0x90,0x90]);
    assert_eq!(t.len(), 16, "OEP trampoline must be exactly 16 bytes");
    t
}

// --- OEP injection ---

unsafe fn inject_into_suspended_process(pi: &PROCESS_INFORMATION, plugins: Option<bool>) -> bool {
    let base = match get_process_image_base(pi.hProcess) {
        Some(b) => b, None => { log("Failed to get ImageBase."); return false; }
    };
    log(&format!("ImageBase: 0x{:X}", base));

    let mut hdr = vec![0u8; 4096];
    let mut read = 0usize;
    if NtReadVirtualMemory(pi.hProcess, base as *const c_void,
        hdr.as_mut_ptr() as *mut c_void, hdr.len(), &mut read) < 0 {
        log("Failed to read PE headers."); return false;
    }

    let pe = match pelite::pe64::PeView::from_bytes(&hdr) {
        Ok(p) => p, Err(_) => { log("Failed to parse PE headers."); return false; }
    };
    use pelite::pe64::Pe;
    let oep_rva  = pe.nt_headers().OptionalHeader.AddressOfEntryPoint as usize;
    let oep_addr = base + oep_rva;
    log(&format!("OEP: 0x{:X}", oep_addr));

    let mut orig = [0u8; 16];
    if NtReadVirtualMemory(pi.hProcess, oep_addr as *const c_void,
        orig.as_mut_ptr() as *mut c_void, 16, &mut read) < 0 {
        log("Failed to read OEP bytes."); return false;
    }
    let orig_0_7  = u64::from_le_bytes(orig[0..8].try_into().unwrap());
    let orig_8_15 = u64::from_le_bytes(orig[8..16].try_into().unwrap());

    // Resolve kernel32 exports via local offsets — system DLLs map at the same
    // base in every process, so no remote module enumeration is needed.
    let k32 = GetModuleHandleA(PCSTR(b"kernel32.dll\0".as_ptr())).unwrap();
    let lla = GetProcAddress(k32, PCSTR(b"LoadLibraryA\0".as_ptr())).unwrap();
    let load_lib_addr = k32.0 as usize + (lla as usize - k32.0 as usize);
    let vp = GetProcAddress(k32, PCSTR(b"VirtualProtect\0".as_ptr())).unwrap();
    let virtual_protect_addr = k32.0 as usize + (vp as usize - k32.0 as usize);

    let setenv_addr = if plugins.is_some() {
        let sea = GetProcAddress(k32, PCSTR(b"SetEnvironmentVariableA\0".as_ptr())).unwrap();
        Some(k32.0 as usize + (sea as usize - k32.0 as usize))
    } else {
        None
    };

    // Load the payload by absolute path from this DLL's own folder (DMM wipes
    // both its own and the game's directory on updates); fall back to loader
    // search (the game directory) only when it's not beside dmmhook.dll.
    let payload_path: Option<std::path::PathBuf> = DLL_DIRECTORY.get()
        .map(|dir| dir.join("gatejumper.dll"))
        .filter(|p| p.is_file());
    let dll_path: String = match payload_path {
        Some(p) => {
            log(&format!("Payload resolved beside DMM-Hook: {}", p.display()));
            format!("{}\0", p.display())
        }
        None => {
            log("gatejumper.dll not found beside dmmhook.dll; falling back to loader search (game directory).");
            "gatejumper.dll\0".to_string()
        }
    };

    let (mut sc, layout) =
        build_injection_shellcode(oep_addr, virtual_protect_addr, load_lib_addr, setenv_addr,
                                  orig_0_7, orig_8_15);
    verify_injection_shellcode(&sc, &layout);

    let dll_path_operand          = layout.dll_path_operand;
    let env_plugins_name_operand  = layout.env_name_operand;
    let env_plugins_value_operand = layout.env_value_operand;

    // Allocate RW, write shellcode, then promote to RX — never EXECUTE_READWRITE.
    let plugins_env_name  = "GATEJUMPER_LOAD_PLUGINS\0";
    let plugins_env_value: String = plugins.map(|v| if v { "1\0".to_string() } else { "0\0".to_string() }).unwrap_or_default();

    // Data (path + env strings) share the RX page; old-protect slots are on the stack.
    let path_offset           = (sc.len() + 7) & !7;
    let plugins_name_offset   = path_offset + dll_path.len();
    let plugins_value_offset  = plugins_name_offset + plugins_env_name.len();
    let alloc_size            = plugins_value_offset + plugins_env_value.len();

    let alloc = VirtualAllocEx(
        pi.hProcess, None, alloc_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE,
    );
    if alloc.is_null() { log("VirtualAllocEx failed."); return false; }

    let dll_path_addr = alloc as usize + path_offset;
    sc[dll_path_operand..dll_path_operand + 8].copy_from_slice(&(dll_path_addr as u64).to_le_bytes());

    if env_plugins_name_operand != 0 {
        let ln_addr = alloc as usize + plugins_name_offset;
        let lv_addr = alloc as usize + plugins_value_offset;
        sc[env_plugins_name_operand..env_plugins_name_operand + 8].copy_from_slice(&(ln_addr as u64).to_le_bytes());
        sc[env_plugins_value_operand..env_plugins_value_operand + 8].copy_from_slice(&(lv_addr as u64).to_le_bytes());
    }

    let mut written = 0usize;
    let _ = WriteProcessMemory(pi.hProcess, dll_path_addr as *mut c_void,
        dll_path.as_ptr() as *const c_void, dll_path.len(), Some(&mut written));
    if plugins.is_some() {
        let _ = WriteProcessMemory(pi.hProcess, (alloc as usize + plugins_name_offset) as *mut c_void,
            plugins_env_name.as_ptr() as *const c_void, plugins_env_name.len(), Some(&mut written));
        let _ = WriteProcessMemory(pi.hProcess, (alloc as usize + plugins_value_offset) as *mut c_void,
            plugins_env_value.as_ptr() as *const c_void, plugins_env_value.len(), Some(&mut written));
    }
    let _ = WriteProcessMemory(pi.hProcess, alloc, sc.as_ptr() as *const c_void, sc.len(), Some(&mut written));

    let mut old = PAGE_PROTECTION_FLAGS(0);
    let _ = VirtualProtectEx(pi.hProcess, alloc, sc.len(), PAGE_EXECUTE_READ, &mut old);

    // Patch OEP: temporarily RW, write trampoline, restore RX.
    let tramp: Vec<u8> = build_trampoline(alloc as usize);

    let _ = VirtualProtectEx(pi.hProcess, oep_addr as *mut c_void, 16, PAGE_READWRITE, &mut old);
    let _ = WriteProcessMemory(pi.hProcess, oep_addr as *mut c_void,
        tramp.as_ptr() as *const c_void, 16, Some(&mut written));
    let _ = VirtualProtectEx(pi.hProcess, oep_addr as *mut c_void, 16, PAGE_EXECUTE_READ, &mut old);

    match plugins {
        Some(l) => log(&format!("OEP hijacked (GATEJUMPER_LOAD_PLUGINS={}).", if l { "1" } else { "0" })),
        None    => log("OEP hijacked."),
    }
    true
}

// --- Carrier injection ---

/// Arm a carrier with a plain `LoadLibraryA` APC of this DLL — it fires when
/// the suspended thread resumes, before the interpreter's entry point, so its
/// CreateProcessW runs through our hooks. Carriers aren't games: no shellcode.
unsafe fn arm_carrier_via_apc(pi: &PROCESS_INFORMATION) -> bool {
    let dll_path: String = match DLL_DIRECTORY.get()
        .map(|d| d.join("dmmhook.dll"))
        .filter(|p| p.is_file())
    {
        Some(p) => format!("{}\0", p.display()),
        None => {
            log("Carrier arming: dmmhook.dll not found beside this hook; refusing.");
            return false;
        }
    };
    let bytes = dll_path.as_bytes();
    let alloc = VirtualAllocEx(pi.hProcess, None, bytes.len(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if alloc.is_null() {
        log("Carrier arming: VirtualAllocEx failed.");
        return false;
    }
    let mut written = 0usize;
    if WriteProcessMemory(pi.hProcess, alloc, bytes.as_ptr() as *const c_void, bytes.len(), Some(&mut written)).is_err()
        || written != bytes.len()
    {
        log("Carrier arming: WriteProcessMemory failed.");
        return false;
    }
    // kernel32 maps at one base per session — local export address holds.
    let k32 = GetModuleHandleA(PCSTR(b"kernel32.dll\0".as_ptr())).unwrap();
    let f = match GetProcAddress(k32, PCSTR(b"LoadLibraryA\0".as_ptr())) {
        Some(f) => f,
        None => {
            log("Carrier arming: GetProcAddress(LoadLibraryA) failed.");
            return false;
        }
    };
    let apc_fn = std::mem::transmute(f);
    if QueueUserAPC(apc_fn, pi.hThread, alloc as usize) == 0 {
        log("Carrier arming: QueueUserAPC failed.");
        return false;
    }
    true
}

// --- Process-launch hooks ---

static mut CREATE_PROCESS_W_ORIG:   usize = 0;
static mut CREATE_PROCESS_A_ORIG:   usize = 0;
static mut SHELL_EXECUTE_EX_W_ORIG: usize = 0;
static mut SHELL_EXECUTE_W_ORIG:    usize = 0;
static mut SHELL_EXECUTE_A_ORIG:    usize = 0;
static mut WIN_EXEC_ORIG:           usize = 0;

type CreateProcessWFn  = extern "system" fn(PCWSTR, PWSTR, *const c_void, *const c_void, BOOL, u32, *const c_void, PCWSTR, *const STARTUPINFOW, *mut PROCESS_INFORMATION) -> BOOL;
type ShellExecuteExWFn = extern "system" fn(*mut SHELLEXECUTEINFOW) -> BOOL;
type WinExecFn         = extern "system" fn(PCSTR, u32) -> u32;

unsafe extern "system" fn win_exec_hook(lpCmdLine: PCSTR, uCmdShow: u32) -> u32 {
    let cmd_str = if !lpCmdLine.0.is_null() { lpCmdLine.to_string().unwrap_or_default() } else { String::new() };
    log(&format!("WinExec: cmd='{}'", cmd_str));

    // Route through ShellExecuteA interception so WinExec-launched games are
    // handled the same way as any other launch path.
    if !cmd_str.is_empty() {
        // Parse out exe path (may be quoted or unquoted).
        let (exe, params) = if cmd_str.starts_with('"') {
            let end = cmd_str[1..].find('"').map(|i| i + 1).unwrap_or(cmd_str.len());
            let exe = &cmd_str[1..end];
            let rest = cmd_str[end + 1..].trim().to_string();
            (exe.to_string(), rest)
        } else {
            let end = cmd_str.find(' ').unwrap_or(cmd_str.len());
            (cmd_str[..end].to_string(), cmd_str[end..].trim().to_string())
        };

        let exe_c: Vec<u8> = format!("{}\0", exe).into_bytes();
        let params_c: Vec<u8> = format!("{}\0", params).into_bytes();
        let result = shell_execute_a_hook(
            windows::Win32::Foundation::HWND(std::ptr::null_mut()),
            PCSTR(std::ptr::null()),
            PCSTR(exe_c.as_ptr()),
            PCSTR(params_c.as_ptr()),
            PCSTR(std::ptr::null()),
            uCmdShow as i32,
        );
        if result as usize > 32 {
            return result as u32;
        }
    }

    let orig: WinExecFn = std::mem::transmute(WIN_EXEC_ORIG);
    orig(lpCmdLine, uCmdShow)
}

// Always spawn suspended so the process can be identified, then inject or
// resume. Injection is config-driven; everything unmatched launches untouched.
unsafe extern "system" fn create_process_w_hook(
    lpApplicationName: PCWSTR, lpCommandLine: PWSTR,
    lpPA: *const c_void, lpTA: *const c_void,
    bInherit: BOOL, dwFlags: u32, lpEnv: *const c_void,
    lpCurDir: PCWSTR, lpSI: *const STARTUPINFOW, lpPI: *mut PROCESS_INFORMATION,
) -> BOOL {
    let orig: CreateProcessWFn = std::mem::transmute(CREATE_PROCESS_W_ORIG);
    // Capture the command line up front — CreateProcessW may modify the buffer.
    let cmd_text: String = if !lpCommandLine.is_null() {
        lpCommandLine.to_string().unwrap_or_default()
    } else if !lpApplicationName.is_null() {
        lpApplicationName.to_string().unwrap_or_default()
    } else {
        String::new()
    };
    let caller_wanted_suspended = (dwFlags & 0x4) != 0;
    let result = orig(lpApplicationName, lpCommandLine, lpPA, lpTA,
        bInherit, dwFlags | 0x4, lpEnv, lpCurDir, lpSI, lpPI);
    if result != 0 && !lpPI.is_null() {
        let pi = &*lpPI;
        match process_identity(lpApplicationName, lpCommandLine, pi) {
            Some((exe_name, exe_dir)) => {
                match resolve_match(&exe_name, &exe_dir) {
                    Some(m) => {
                        log(&format!("Game '{}' matched configuration; injecting.", exe_name));
                        let injected = inject_into_suspended_process(pi, m.plugins);
                        if !caller_wanted_suspended {
                            ResumeThread(pi.hThread);
                            log(if injected { "Resumed with payload." } else { "Injection failed; resumed." });
                        }
                    }
                    None => {
                        // Arm the launcher's own runtime child (PyInstaller
                        // one-file) or interpreters carrying a configured
                        // game; everything else launches untouched.
                        let cmd_lower = cmd_text.to_ascii_lowercase();
                        let same_exe = is_own_image(&exe_name, &exe_dir);
                        let carrier = is_carrier_exe(&exe_name) && command_line_carries_game(&cmd_lower);
                        if same_exe || carrier {
                            let kind = if same_exe { "runtime child (same executable)" } else { "carrier" };
                            let hop = CARRIER_ARMS.fetch_add(1, Ordering::Relaxed) + 1;
                            if hop <= MAX_CARRIER_ARMS {
                                log(&format!(
                                    "{} '{}' (hop {}): command line '{}'",
                                    kind, exe_name, hop, cmd_text,
                                ));
                                let armed = arm_carrier_via_apc(pi);
                                if !caller_wanted_suspended {
                                    ResumeThread(pi.hThread);
                                }
                                log(if armed { "Armed; resuming." }
                                   else { "Arming failed; resuming unarmed." });
                            } else {
                                log(&format!(
                                    "Hop limit ({}) reached; launching '{}' unarmed.",
                                    MAX_CARRIER_ARMS, exe_name,
                                ));
                                if !caller_wanted_suspended {
                                    ResumeThread(pi.hThread);
                                }
                            }
                        } else {
                            log(&format!("Game '{}' does not match configuration; launching normally.", exe_name));
                            if !caller_wanted_suspended {
                                ResumeThread(pi.hThread);
                            }
                        }
                    }
                }
            }
            None => {
                log("Could not identify spawned process; launching normally.");
                if !caller_wanted_suspended {
                    ResumeThread(pi.hThread);
                }
            }
        }
    }
    result
}

unsafe extern "system" fn create_process_a_hook(
    lpAN: PCSTR, lpCL: windows::core::PSTR,
    lpPA: *const c_void, lpTA: *const c_void,
    bI: BOOL, dwF: u32, lpE: *const c_void,
    lpCD: PCSTR, _lpSI: *const STARTUPINFOA, _lpPI: *mut PROCESS_INFORMATION,
) -> BOOL {
    // Convert ANSI parameters to wide and route through the W hook so any game
    // DMM spawns via CreateProcessA is intercepted the same way as CreateProcessW.
    // Convert ANSI parameters to wide and route through the W hook so any game
    // DMM spawns via CreateProcessA is intercepted the same way as CreateProcessW.
    let app_w: Option<Vec<u16>> = if !lpAN.0.is_null() {
        lpAN.to_string().ok().map(|s| s.encode_utf16().chain(std::iter::once(0)).collect())
    } else { None };

    let mut cmd_w: Option<Vec<u16>> = if !lpCL.0.is_null() {
        lpCL.to_string().ok().map(|s| s.encode_utf16().chain(std::iter::once(0)).collect())
    } else { None };

    let dir_w: Option<Vec<u16>> = if !lpCD.0.is_null() {
        lpCD.to_string().ok().map(|s| s.encode_utf16().chain(std::iter::once(0)).collect())
    } else { None };

    let lp_app_w  = app_w.as_ref().map_or(PCWSTR(std::ptr::null()), |v| PCWSTR(v.as_ptr()));
    let lp_cmd_w  = cmd_w.as_mut().map_or(PWSTR(std::ptr::null_mut()), |v| PWSTR(v.as_mut_ptr()));
    let lp_dir_w  = dir_w.as_ref().map_or(PCWSTR(std::ptr::null()), |v| PCWSTR(v.as_ptr()));

    let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
    let mut si_w: STARTUPINFOW = std::mem::zeroed();
    si_w.cb = std::mem::size_of::<STARTUPINFOW>() as u32;

    create_process_w_hook(
        lp_app_w, lp_cmd_w,
        lpPA, lpTA, bI, dwF, lpE,
        lp_dir_w, &si_w, &mut pi,
    )
}

unsafe extern "system" fn shell_execute_ex_w_hook(pExecInfo: *mut SHELLEXECUTEINFOW) -> BOOL {
    let orig: ShellExecuteExWFn = std::mem::transmute(SHELL_EXECUTE_EX_W_ORIG);
    if pExecInfo.is_null() { return orig(pExecInfo); }
    let info = &*pExecInfo;
    // Non-"open" verbs (e.g. runas) get real ShellExecute: elevation happens
    // in the AppInfo service; don't force the launch unelevated.
    let verb = if !info.lpVerb.0.is_null() { info.lpVerb.to_string().unwrap_or_default() } else { String::new() };
    if !verb.is_empty() && !verb.eq_ignore_ascii_case("open") {
        log(&format!("ShellExecuteExW verb '{}' passed through.", verb));
        return orig(pExecInfo);
    }
    let file_str   = if !info.lpFile.0.is_null()       { info.lpFile.to_string().unwrap_or_default()       } else { String::new() };
    let params_str = if !info.lpParameters.0.is_null() { info.lpParameters.to_string().unwrap_or_default() } else { String::new() };
    let cmd = format!("\"{}\" {}", file_str, params_str);
    let mut cmd_w: Vec<u16> = cmd.encode_utf16().chain(std::iter::once(0)).collect();
    let mut si: STARTUPINFOW = std::mem::zeroed();
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
    let dir_w: Vec<u16>;
    let cur_dir = if !info.lpDirectory.0.is_null() { info.lpDirectory } else {
        let p = std::path::Path::new(&file_str);
        if let Some(parent) = p.parent() {
            dir_w = parent.to_string_lossy().encode_utf16().chain(std::iter::once(0)).collect();
            PCWSTR(dir_w.as_ptr())
        } else { PCWSTR(std::ptr::null()) }
    };
    let result = create_process_w_hook(
        PCWSTR(std::ptr::null()), PWSTR(cmd_w.as_mut_ptr()),
        std::ptr::null(), std::ptr::null(), 0, 0,
        std::ptr::null(), cur_dir, &si, &mut pi);
    if result != 0 {
        (*pExecInfo).hProcess = pi.hProcess;
        return result;
    }
    orig(pExecInfo)
}

unsafe extern "system" fn shell_execute_w_hook(
    hwnd: HWND, lpOp: PCWSTR, lpFile: PCWSTR,
    lpParams: PCWSTR, lpDir: PCWSTR, nShow: i32,
) -> HINSTANCE {
    let orig: extern "system" fn(HWND, PCWSTR, PCWSTR, PCWSTR, PCWSTR, i32) -> HINSTANCE =
        std::mem::transmute(SHELL_EXECUTE_W_ORIG);
    // Non-"open" verbs pass through — see the ShellExecuteExW hook.
    let verb = if !lpOp.0.is_null() { lpOp.to_string().unwrap_or_default() } else { String::new() };
    if !verb.is_empty() && !verb.eq_ignore_ascii_case("open") {
        log(&format!("ShellExecuteW verb '{}' passed through.", verb));
        return orig(hwnd, lpOp, lpFile, lpParams, lpDir, nShow);
    }
    let file_str   = if !lpFile.0.is_null()   { lpFile.to_string().unwrap_or_default()   } else { String::new() };
    let params_str = if !lpParams.0.is_null() { lpParams.to_string().unwrap_or_default() } else { String::new() };
    let cmd = format!("\"{}\" {}", file_str, params_str);
    let mut cmd_w: Vec<u16> = cmd.encode_utf16().chain(std::iter::once(0)).collect();
    let mut si: STARTUPINFOW = std::mem::zeroed();
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
    let dir_w: Vec<u16>;
    let cur_dir = if !lpDir.0.is_null() { lpDir } else {
        let p = std::path::Path::new(&file_str);
        if let Some(parent) = p.parent() {
            dir_w = parent.to_string_lossy().encode_utf16().chain(std::iter::once(0)).collect();
            PCWSTR(dir_w.as_ptr())
        } else { PCWSTR(std::ptr::null()) }
    };
    let result = create_process_w_hook(
        PCWSTR(std::ptr::null()), PWSTR(cmd_w.as_mut_ptr()),
        std::ptr::null(), std::ptr::null(), 0, 0,
        std::ptr::null(), cur_dir, &si, &mut pi);
    if result != 0 { SHELL_EXECUTE_SUCCESS } else { orig(hwnd, lpOp, lpFile, lpParams, lpDir, nShow) }
}

unsafe extern "system" fn shell_execute_a_hook(
    hwnd: HWND, lpOp: PCSTR, lpFile: PCSTR,
    lpParams: PCSTR, lpDir: PCSTR, nShow: i32,
) -> HINSTANCE {
    let orig: extern "system" fn(HWND, PCSTR, PCSTR, PCSTR, PCSTR, i32) -> HINSTANCE =
        std::mem::transmute(SHELL_EXECUTE_A_ORIG);

    // Non-"open" verbs pass through — see the ShellExecuteExW hook.
    let verb = if !lpOp.0.is_null() { lpOp.to_string().unwrap_or_default() } else { String::new() };
    if !verb.is_empty() && !verb.eq_ignore_ascii_case("open") {
        log(&format!("ShellExecuteA verb '{}' passed through.", verb));
        return orig(hwnd, lpOp, lpFile, lpParams, lpDir, nShow);
    }

    // Convert ANSI args to wide strings and route through the W interception path,
    // matching the ShellExecuteW hook so DMM games launched via ShellExecuteA are
    // intercepted the same way.
    let file_str   = if !lpFile.0.is_null()   { lpFile.to_string().unwrap_or_default()   } else { String::new() };
    let params_str = if !lpParams.0.is_null() { lpParams.to_string().unwrap_or_default() } else { String::new() };

    if file_str.is_empty() {
        return orig(hwnd, lpOp, lpFile, lpParams, lpDir, nShow);
    }

    let cmd = format!("\"{}\" {}", file_str, params_str);
    let mut cmd_w: Vec<u16> = cmd.encode_utf16().chain(std::iter::once(0)).collect();
    let mut si: STARTUPINFOW = std::mem::zeroed();
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
    let dir_w: Vec<u16>;
    let cur_dir = if !lpDir.0.is_null() {
        if let Ok(d) = lpDir.to_string() {
            dir_w = d.encode_utf16().chain(std::iter::once(0)).collect();
            PCWSTR(dir_w.as_ptr())
        } else {
            let p = std::path::Path::new(&file_str);
            if let Some(parent) = p.parent() {
                dir_w = parent.to_string_lossy().encode_utf16().chain(std::iter::once(0)).collect();
                PCWSTR(dir_w.as_ptr())
            } else { PCWSTR(std::ptr::null()) }
        }
    } else {
        let p = std::path::Path::new(&file_str);
        if let Some(parent) = p.parent() {
            dir_w = parent.to_string_lossy().encode_utf16().chain(std::iter::once(0)).collect();
            PCWSTR(dir_w.as_ptr())
        } else { PCWSTR(std::ptr::null()) }
    };

    let result = create_process_w_hook(
        PCWSTR(std::ptr::null()), PWSTR(cmd_w.as_mut_ptr()),
        std::ptr::null(), std::ptr::null(), 0, 0,
        std::ptr::null(), cur_dir, &si, &mut pi);
    if result != 0 { SHELL_EXECUTE_SUCCESS } else { orig(hwnd, lpOp, lpFile, lpParams, lpDir, nShow) }
}

fn setup_launch_hooks() {
    unsafe {
        macro_rules! hook {
            ($mod:expr, $name:literal, $fn:ident, $orig:ident) => {
                if let Some(f) = GetProcAddress($mod, PCSTR(concat!($name, "\0").as_ptr())) {
                    if let Ok(t) = minhook::MinHook::create_hook(f as *mut c_void, $fn as *mut c_void) {
                        $orig = t as usize;
                        let _ = minhook::MinHook::enable_hook(f as *mut c_void);
                        log(concat!($name, " hooked."));
                    }
                }
            };
        }
        if let Ok(k32) = LoadLibraryA(PCSTR(b"kernel32.dll\0".as_ptr())) {
            hook!(k32, "CreateProcessW", create_process_w_hook, CREATE_PROCESS_W_ORIG);
            hook!(k32, "CreateProcessA", create_process_a_hook, CREATE_PROCESS_A_ORIG);
            hook!(k32, "WinExec",        win_exec_hook,         WIN_EXEC_ORIG);
        }
        if let Ok(sh32) = LoadLibraryA(PCSTR(b"shell32.dll\0".as_ptr())) {
            hook!(sh32, "ShellExecuteExW", shell_execute_ex_w_hook, SHELL_EXECUTE_EX_W_ORIG);
            hook!(sh32, "ShellExecuteW",   shell_execute_w_hook,    SHELL_EXECUTE_W_ORIG);
            hook!(sh32, "ShellExecuteA",   shell_execute_a_hook,    SHELL_EXECUTE_A_ORIG);
        }
    }
}

// --- DllMain ---

#[no_mangle]
pub extern "system" fn DllMain(_module: HINSTANCE, reason: u32, _reserved: *mut c_void) -> BOOL {
    if reason == DLL_PROCESS_ATTACH {
        unsafe {
            let mut buf = [0u16; 512];
            let len = windows::Win32::System::LibraryLoader::GetModuleFileNameW(
                Some(windows::Win32::Foundation::HMODULE(_module as *mut c_void)), &mut buf);
            if len > 0 {
                let path = String::from_utf16_lossy(&buf[..len as usize]);
                if let Some(pos) = path.rfind('\\') {
                    let _ = DLL_DIRECTORY.set(std::path::PathBuf::from(&path[..pos]));
                }
            }
            log_session_start();
            log("=== DMM-Hook loaded ===");

            // Own image identity — used to follow PyInstaller-style runtime children.
            let mut pbuf = [0u16; 512];
            let plen = windows::Win32::System::LibraryLoader::GetModuleFileNameW(None, &mut pbuf);
            if plen > 0 {
                let p = PathBuf::from(String::from_utf16_lossy(&pbuf[..plen as usize]));
                if let (Some(n), Some(d)) = (
                    p.file_name().map(|s| s.to_string_lossy().to_ascii_lowercase()),
                    p.parent().map(|x| x.to_path_buf()),
                ) {
                    let _ = OWN_IMAGE.set((n, d));
                }
            }

            // Read the multi-game config exactly once.
            let config = DLL_DIRECTORY.get()
                .map(|d| d.join("gatejumper.ini"))
                .and_then(|p| std::fs::read_to_string(p).ok())
                .map(|content| parse_config(&content))
                .unwrap_or_default();
            log(&format!(
                "Config loaded: dmm={}, main.target={:?}, {} configured game(s): [{}].",
                config.dmm,
                config.main_target,
                config.games.len(),
                config.games.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>().join(", "),
            ));
            let _ = HOOK_CONFIG.set(config);

            setup_stealth_hooks();
            setup_launch_hooks();
        }
    }
    1
}

#[cfg(test)]
mod tests {
    use super::{
        build_injection_shellcode, build_trampoline, config_carries_game, dirs_equal,
        is_carrier_exe, parse_config, path_variants, verify_injection_shellcode,
    };
    use std::path::Path;

    // Fixture addresses — imm64 operands the verifier and tests decode again.
    const OEP: usize = 0x0000_7FF6_0000_1000;
    const VP: usize = 0x0000_7FF6_1111_0040;
    const LL: usize = 0x0000_7FF6_2222_0020;
    const SE: usize = 0x0000_7FF6_3333_00A0;
    const ORIG_0_7: u64 = 0x0123_4567_89AB_CDEF;
    const ORIG_8_15: u64 = 0xFEDC_BA98_7654_3210;

    // Hand-derived from the encodings, cross-checked against the shipped fault
    // offset (oep_write = 0x5D). A failure means the byte count changed: review
    // the change, then update these consciously.
    #[test]
    fn shellcode_layout_without_env_override() {
        let (sc, l) = build_injection_shellcode(OEP, VP, LL, None, ORIG_0_7, ORIG_8_15);
        verify_injection_shellcode(&sc, &l);
        assert_eq!(sc.len(), 209, "shellcode byte count changed");
        assert_eq!(l.vp1_lea, 56);
        assert_eq!(l.vp1_call, 71);
        assert_eq!(l.oep_write, 93);
        assert_eq!(l.vp2_lea, 133);
        assert_eq!(l.dll_path_operand, 152);
        assert_eq!(l.setenv_call, 0);
        assert_eq!(l.env_name_operand, 0);
        assert_eq!(l.env_value_operand, 0);
        // Captured OEP bytes sit where the write-back loads them.
        assert_eq!(&sc[l.oep_write - 8..l.oep_write], &ORIG_0_7.to_le_bytes());
        assert_eq!(&sc[l.oep_write + 5..l.oep_write + 13], &ORIG_8_15.to_le_bytes());
        // Both VirtualProtect calls receive the real function address.
        assert_eq!(u64::from_le_bytes(sc[l.vp1_lea + 7..l.vp1_lea + 15].try_into().unwrap()), VP as u64);
        assert_eq!(u64::from_le_bytes(sc[l.vp2_lea + 7..l.vp2_lea + 15].try_into().unwrap()), VP as u64);
    }

    #[test]
    fn shellcode_layout_with_env_override() {
        let (sc, l) = build_injection_shellcode(OEP, VP, LL, Some(SE), ORIG_0_7, ORIG_8_15);
        verify_injection_shellcode(&sc, &l);
        assert_eq!(sc.len(), 241, "shellcode byte count changed");
        assert_eq!(l.env_name_operand, 152);
        assert_eq!(l.env_value_operand, 162);
        assert_eq!(l.setenv_call, 180);
        assert_eq!(l.dll_path_operand, 184);
        // The SetEnvironmentVariableA address really landed in its operand.
        assert_eq!(u64::from_le_bytes(sc[l.setenv_call - 8..l.setenv_call].try_into().unwrap()), SE as u64);
        // Placeholder operand; LoadLibraryA sits right behind its movs.
        assert_eq!(&sc[l.dll_path_operand..l.dll_path_operand + 8], &[0u8; 8]);
        assert_eq!(u64::from_le_bytes(sc[l.dll_path_operand + 10..l.dll_path_operand + 18].try_into().unwrap()), LL as u64);
    }

    /// A corrupted old-protect ModRM (the shipped bug) must be caught.
    #[test]
    #[should_panic]
    fn verify_rejects_the_shipped_modrm_bug() {
        let (mut sc, l) = build_injection_shellcode(OEP, VP, LL, None, ORIG_0_7, ORIG_8_15);
        sc[l.vp1_lea + 2] = 0x64; // rm=100 without mod → SIB base r12, not r9
        verify_injection_shellcode(&sc, &l);
    }

    /// A shrunk frame (the other half of the shipped bug) must be caught.
    #[test]
    #[should_panic]
    fn verify_rejects_a_frame_that_cannot_hold_the_slots() {
        let (mut sc, l) = build_injection_shellcode(OEP, VP, LL, None, ORIG_0_7, ORIG_8_15);
        sc[32] = 0x20; // sub rsp, 0x20 — slots at [rsp+0x20, rsp+0x28) fall outside
        verify_injection_shellcode(&sc, &l);
    }

    #[test]
    fn trampoline_is_exactly_16_bytes() {
        let t = build_trampoline(0x0000_7FF7_0000_2000);
        assert_eq!(t.len(), 16);
        assert_eq!(&t[0..2], &[0x48, 0xB8]);
        assert_eq!(u64::from_le_bytes(t[2..10].try_into().unwrap()), 0x0000_7FF7_0000_2000);
        assert_eq!(&t[10..16], &[0xFF, 0xE0, 0x90, 0x90, 0x90, 0x90]);
    }

    // --- Path resolution across Wine/Proton/prefix-manager layouts ---

    #[test]
    fn path_variants_cover_prefix_manager_layouts() {
        // Unix absolute → also reachable through Wine's standard Z: mount of /.
        assert_eq!(
            path_variants("/media/Games/ExampleGame"),
            vec![
                "\\media\\games\\examplegame".to_string(),
                "z:\\media\\games\\examplegame".to_string(),
            ]
        );
        // Prefix drive directories → also the letter: view the process sees.
        let v = path_variants("/home/u/.steam/steam/compatdata/1/pfx/drive_c/games/game");
        assert!(v.contains(&"c:\\games\\game".to_string()), "{:?}", v);
        assert!(v.contains(&"z:\\home\\u\\.steam\\steam\\compatdata\\1\\pfx\\drive_c\\games\\game".to_string()), "{:?}", v);
        // A plain Windows path is its own single variant (trailing slash trimmed).
        assert_eq!(path_variants("C:\\Games\\Foo\\"), vec!["c:\\games\\foo".to_string()]);
    }

    #[test]
    fn dirs_equal_across_representations() {
        // Config written as a Linux path, process reports Wine's Z: spelling.
        assert!(dirs_equal(
            Path::new("/media/Games/ExampleGame"),
            Path::new("Z:\\media\\games\\ExampleGame")
        ));
        // Config written as a Linux prefix path, process reports C:\… (drive_c mapping).
        assert!(dirs_equal(
            Path::new("/home/u/bottles/bottles/Game/drive_c/Games/ExampleGame"),
            Path::new("C:\\Games\\ExampleGame")
        ));
        // Different directories still compare unequal — and a drive_c path is
        // not equal to a different drive letter.
        assert!(!dirs_equal(Path::new("/media/Games/A"), Path::new("Z:\\media\\games\\B")));
        assert!(!dirs_equal(Path::new("/x/drive_c/games/a"), Path::new("D:\\games\\a")));
    }

    // --- Carrier propagation (DMM Fast Launcher) ---

    #[test]
    fn carrier_predicate_only_matches_interpreters() {
        assert!(is_carrier_exe("cmd.exe"));
        assert!(is_carrier_exe("powershell.exe"));
        assert!(is_carrier_exe("pwsh.exe"));
        assert!(!is_carrier_exe("game.exe"));
        assert!(!is_carrier_exe("dmmgameplayer.exe"));
    }

    #[test]
    fn carrier_command_line_must_reference_a_configured_game() {
        let cfg = parse_config("[main]\ndmm = true\n[ExampleGame.exe]\ndir = C:\\Games\\ExampleGame\n");
        assert!(config_carries_game(&cfg, "\"cmd.exe\" /c \"c:\\games\\game\\examplegame.exe\" -screen"));
        assert!(config_carries_game(&cfg, "examplegame.exe"));
        assert!(!config_carries_game(&cfg, "cmd.exe /c othergame.exe"));
        assert!(!config_carries_game(&cfg, ""));
        // No armed games in the config → nothing can be a carrier payload.
        let empty = parse_config("[main]\ndmm = true\n");
        assert!(!config_carries_game(&empty, "examplegame.exe"));
    }
}
