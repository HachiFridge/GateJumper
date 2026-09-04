//! DMM-Hook — injected into the DMM Game Player launcher to intercept game spawns.

#![allow(non_snake_case)]

use std::{ffi::c_void, fs::OpenOptions, io::Write, path::{Path, PathBuf}, sync::OnceLock};

type BOOL = i32;
type HINSTANCE = isize;

use windows::{
    core::{PCSTR, PCWSTR, PWSTR},
    Win32::{
        Foundation::HWND,
        System::{
            LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA},
            Threading::{PROCESS_INFORMATION, STARTUPINFOW, STARTUPINFOA, ResumeThread},
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

fn log(msg: &str) {
    let log_path = match DLL_DIRECTORY.get() {
        Some(dir) => dir.join("gatejumper.log"),
        None => std::path::PathBuf::from("gatejumper.log"),
    };
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(log_path) {
        let _ = writeln!(file, "[DMM-Hook] {}", msg);
    }
}

fn log_session_start() {
    use windows::Win32::System::SystemInformation::GetSystemTime;
    use windows::Win32::Foundation::SYSTEMTIME;
    let st: SYSTEMTIME = unsafe { GetSystemTime() };
    let log_path = match DLL_DIRECTORY.get() {
        Some(dir) => dir.join("gatejumper.log"),
        None => std::path::PathBuf::from("gatejumper.log"),
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

// --- Configuration ---
//
// The multi-profile `gatejumper.ini` beside dmmhook.dll (the dedicated
// GateJumper folder, which DMM never touches) drives everything:
//
//   [main]
//   dmm = true
//   target = <DMM Game Player install directory>   # consumed by the injector
//
//   [ExampleGame.exe]
//   dir = <game directory>
//   profile = direct-oep
//   plugins = true            # optional; omit to load if plugins/ exists
//
//   [AnotherGame.exe]
//   dir = <game directory>
//   profile = plain
//   plugins = false           # disable plugin loading for this game
//
// The config is parsed exactly once when the DLL loads. On every process spawn
// the launched game is matched against it: a `gatejumper.ini` living inside the
// game's own directory wins outright; otherwise the `[<exe name>]` section of
// this file applies (its `dir`, when present, must match where the
// process actually launched from). A game with no config entry at all is
// launched normally — no injection, no bypass, no mod loading — unless its own
// directory contains a `gatejumper.dll` (a standalone install that DMM now
// launches), which counts as an implicit match with an auto-detected profile.

#[derive(Clone, Debug, Default)]
struct GameEntry {
    /// Directory the game is expected to live in (from `dir = <path>`).
    target_dir: Option<PathBuf>,
    /// Raw `profile = <name>` value, if any.
    profile: Option<String>,
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

/// Parse the multi-profile config. Files without any `[section]` header are
/// treated as belonging to `[main]`, keeping old single-profile configs valid.
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
            "profile" => {
                if let Some((_, e)) = entry {
                    e.profile = Some(value.to_string());
                } else {
                    let mut e = GameEntry::default();
                    e.profile = Some(value.to_string());
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

/// Map a user-supplied profile name onto its canonical GateJumper form, mirroring
/// the payload's lenient matching. Unknown values return `None` (auto-detect).
fn canonical_profile(name: &str) -> Option<&'static str> {
    let lower = name.trim().to_ascii_lowercase();
    if lower.contains("plain") || lower.contains("loader") || lower.contains("mod") {
        Some("plain")
    } else if lower.contains("hook") || lower.contains("runtime") {
        Some("hooked-runtime")
    } else if lower.contains("direct") || lower.contains("oep") {
        Some("direct-oep")
    } else {
        None
    }
}

/// Read the first `profile = <name>` from an INI file regardless of section —
/// the per-game individual config that may live inside the game's directory.
fn read_ini_profile_unscoped(ini_path: &Path) -> Option<String> {
    let content = std::fs::read_to_string(ini_path).ok()?;
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("profile") {
            if let Some(val) = rest.trim().strip_prefix('=') {
                let val = strip_trailing_comment(val.trim()).trim().trim_matches('"');
                if !val.is_empty() { return Some(val.to_string()); }
            }
        }
    }
    None
}

/// Compare two directory paths case-insensitively, normalizing slashes and
/// trailing separators. A Linux-style absolute target (`/media/…`) is mapped
/// through the prefix's `Z:` drive first, so it compares equal to the Windows
/// path (`Z:\media\…`) that Wine reports for the spawned process.
fn dirs_equal(a: &Path, b: &Path) -> bool {
    let norm = |p: &Path| -> String {
        let s = p.to_string_lossy();
        let s = if s.starts_with('/') {
            format!("Z:\\{}", s.trim_start_matches('/'))
        } else {
            s.to_string()
        };
        s.replace('/', "\\").trim_end_matches('\\').to_ascii_lowercase()
    };
    norm(a) == norm(b)
}

/// Result of matching a spawned game against the configuration.
struct MatchResult {
    /// Canonical profile to force, or `None` for auto-detection.
    profile: Option<&'static str>,
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
        let profile = read_ini_profile_unscoped(&game_ini);
        if let Some(p) = &profile {
            log(&format!("Game '{}': profile '{}' from game-directory gatejumper.ini.", exe_name, p));
        } else {
            log(&format!("Game '{}': matched via game-directory gatejumper.ini (no profile; auto-detect).", exe_name));
        }
        return Some(MatchResult { profile: profile.as_deref().and_then(canonical_profile), plugins: None });
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

            let profile = entry.profile.as_deref().and_then(canonical_profile);
            let plugins = entry.plugins;
            match profile {
                Some(p) => log(&format!("Game '{}': matched global config, profile '{}'{}.", exe_name, p,
                    plugins.map(|v| format!(", plugins={}", v)).unwrap_or_default())),
                None => log(&format!("Game '{}': matched global config (no profile; auto-detect){}.", exe_name,
                    plugins.map(|v| format!(", plugins={}", v)).unwrap_or_default())),
            }
            return Some(MatchResult { profile, plugins });
        }
    }

    // 3. Implicit match via standalone gatejumper.dll in the game's directory.
    if exe_dir.join("gatejumper.dll").is_file() {
        log(&format!("Game '{}': matched via gatejumper.dll in game directory (auto-detect).", exe_name));
        return Some(MatchResult { profile: None, plugins: None });
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

// --- OEP injection ---

unsafe fn inject_into_suspended_process(pi: &PROCESS_INFORMATION, profile: Option<&str>, plugins: Option<bool>) -> bool {
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

    // Resolve LoadLibraryA, VirtualProtect (and, for profile overrides,
    // SetEnvironmentVariableA) via local kernel32 offsets — avoids remote
    // module enumeration. System DLLs map at the same base in every process,
    // so the local base + export offset holds in the child too.
    let k32 = GetModuleHandleA(PCSTR(b"kernel32.dll\0".as_ptr())).unwrap();
    let lla = GetProcAddress(k32, PCSTR(b"LoadLibraryA\0".as_ptr())).unwrap();
    let load_lib_addr = k32.0 as usize + (lla as usize - k32.0 as usize);
    let vp = GetProcAddress(k32, PCSTR(b"VirtualProtect\0".as_ptr())).unwrap();
    let virtual_protect_addr = k32.0 as usize + (vp as usize - k32.0 as usize);
    // Only forward a profile override if one wasn't already set upstream by the
    // injector via `--profile`. The injector writes GATEJUMPER_PROFILE into
    // DMMGamePlayer's environment, which dmmhook.dll inherits; if it's present
    // here it means the user explicitly chose a profile at launch time and we
    // must not overwrite it with the per-game config value.
    let effective_profile = if std::env::var("GATEJUMPER_PROFILE").is_ok() {
        log("GATEJUMPER_PROFILE already set by injector; per-game profile override skipped.");
        None
    } else {
        profile
    };

    let setenv_addr = if effective_profile.is_some() || plugins.is_some() {
        let sea = GetProcAddress(k32, PCSTR(b"SetEnvironmentVariableA\0".as_ptr())).unwrap();
        Some(k32.0 as usize + (sea as usize - k32.0 as usize))
    } else {
        None
    };

    // The payload is loaded by absolute path from this DLL's own directory so
    // the whole GateJumper folder can live anywhere — DMM wipes both its own
    // directory and the game's directory on updates, so nothing may depend on
    // files sitting next to the launcher or next to the game. Fall back to the
    // bare filename (loader search, i.e. the game directory) only when
    // gatejumper.dll is not found beside dmmhook.dll.
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

    let mut sc: Vec<u8> = Vec::new();
    // Save all registers.
    sc.extend_from_slice(&[0x55,0x53,0x51,0x52,0x56,0x57,
        0x41,0x50,0x41,0x51,0x41,0x52,0x41,0x53,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57]);
    // Align stack and reserve shadow space before any calls.
    // mov rbp, rsp  /  and rsp, ~0xF  /  sub rsp, 0x20
    sc.extend_from_slice(&[0x48,0x89,0xE5, 0x48,0x83,0xE4,0xF0, 0x48,0x83,0xEC,0x20]);
    // VirtualProtect(oep_addr, 16, PAGE_EXECUTE_READWRITE=0x40, &old_protect).
    // rcx = oep_addr
    sc.extend_from_slice(&[0x48,0xB9]); sc.extend_from_slice(&(oep_addr as u64).to_le_bytes());
    // rdx = 16
    sc.extend_from_slice(&[0x48,0xC7,0xC2, 0x10,0x00,0x00,0x00]);
    // r8d = 0x40 (PAGE_EXECUTE_READWRITE)
    sc.extend_from_slice(&[0x41,0xB8, 0x40,0x00,0x00,0x00]);
    // r9 = &old_protect_slot (placeholder, patched after alloc)
    sc.extend_from_slice(&[0x49,0xB9]);
    let vp_old_protect_operand_1 = sc.len();
    sc.extend_from_slice(&[0u8; 8]);
    // call VirtualProtect
    sc.extend_from_slice(&[0x48,0xB8]); sc.extend_from_slice(&(virtual_protect_addr as u64).to_le_bytes());
    sc.extend_from_slice(&[0xFF,0xD0]);
    // Restore original 16 bytes at OEP (page is now writable).
    // rcx is caller-saved and clobbered by the VirtualProtect call; reload oep_addr into rax.
    sc.extend_from_slice(&[0x48,0xB8]); sc.extend_from_slice(&(oep_addr as u64).to_le_bytes()); // mov rax, oep_addr
    sc.extend_from_slice(&[0x48,0xB9]); sc.extend_from_slice(&orig_0_7.to_le_bytes());
    sc.extend_from_slice(&[0x48,0x89,0x08]);  // mov [rax], rcx
    sc.extend_from_slice(&[0x48,0xB9]); sc.extend_from_slice(&orig_8_15.to_le_bytes());
    sc.extend_from_slice(&[0x48,0x89,0x48,0x08]); // mov [rax+8], rcx
    // VirtualProtect(oep_addr, 16, PAGE_EXECUTE_READ=0x20, &old_protect) — restore protection.
    sc.extend_from_slice(&[0x48,0xB9]); sc.extend_from_slice(&(oep_addr as u64).to_le_bytes());
    sc.extend_from_slice(&[0x48,0xC7,0xC2, 0x10,0x00,0x00,0x00]);
    sc.extend_from_slice(&[0x41,0xB8, 0x20,0x00,0x00,0x00]); // r8d = PAGE_EXECUTE_READ
    sc.extend_from_slice(&[0x49,0xB9]);
    let vp_old_protect_operand_2 = sc.len();
    sc.extend_from_slice(&[0u8; 8]);
    sc.extend_from_slice(&[0x48,0xB8]); sc.extend_from_slice(&(virtual_protect_addr as u64).to_le_bytes());
    sc.extend_from_slice(&[0xFF,0xD0]);
    // Call SetEnvironmentVariableA for each forced env var — GATEJUMPER_PROFILE
    // when a profile is specified, GATEJUMPER_LOAD_PLUGINS when plugins is
    // explicitly overridden. All address operands are placeholders patched once
    // the remote allocation exists.
    let mut env_profile_name_operand  = 0usize;
    let mut env_profile_value_operand = 0usize;
    let mut env_plugins_name_operand  = 0usize;
    let mut env_plugins_value_operand = 0usize;
    if let Some(sea) = setenv_addr {
        // SetEnvironmentVariableA("GATEJUMPER_PROFILE", value)
        sc.extend_from_slice(&[0x48,0xB9]); // mov rcx, <name addr>
        env_profile_name_operand = sc.len();
        sc.extend_from_slice(&[0u8; 8]);
        sc.extend_from_slice(&[0x48,0xBA]); // mov rdx, <value addr>
        env_profile_value_operand = sc.len();
        sc.extend_from_slice(&[0u8; 8]);
        sc.extend_from_slice(&[0x48,0xB8]); sc.extend_from_slice(&(sea as u64).to_le_bytes());
        sc.extend_from_slice(&[0xFF,0xD0]); // call SetEnvironmentVariableA

        if plugins.is_some() {
            sc.extend_from_slice(&[0x48,0xB9]);
            env_plugins_name_operand = sc.len();
            sc.extend_from_slice(&[0u8; 8]);
            sc.extend_from_slice(&[0x48,0xBA]);
            env_plugins_value_operand = sc.len();
            sc.extend_from_slice(&[0u8; 8]);
            sc.extend_from_slice(&[0x48,0xB8]); sc.extend_from_slice(&(sea as u64).to_le_bytes());
            sc.extend_from_slice(&[0xFF,0xD0]);
        }
    }
    // LoadLibraryA(dll_path).
    sc.extend_from_slice(&[0x48,0xB9]);
    let dll_path_operand = sc.len();
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

    // Allocate RW, write shellcode, then promote to RX — never EXECUTE_READWRITE.
    // The remote allocation holds:
    //   [0..sc.len())                  shellcode
    //   [path_offset..)                dll path string
    //   [profile_name_offset..)        "GATEJUMPER_PROFILE\0"        (always present)
    //   [profile_value_offset..)       profile value string           (when profile forced)
    //   [plugins_name_offset..)        "GATEJUMPER_LOAD_PLUGINS\0"   (when plugins forced)
    //   [plugins_value_offset..)       "1\0" or "0\0"                (when plugins forced)
    //   [old_protect_1_offset..)       4-byte DWORD — output of first VirtualProtect call
    //   [old_protect_2_offset..)       4-byte DWORD — output of second VirtualProtect call
    // Each VirtualProtect gets its own output slot so the first call's saved
    // protection value is preserved and not overwritten by the second call.
    let profile_env_name  = "GATEJUMPER_PROFILE\0";
    let profile_env_value: String = effective_profile.map(|p| format!("{}\0", p)).unwrap_or_default();
    let plugins_env_name  = "GATEJUMPER_LOAD_PLUGINS\0";
    let plugins_env_value: String = plugins.map(|v| if v { "1\0".to_string() } else { "0\0".to_string() }).unwrap_or_default();

    let path_offset           = (sc.len() + 7) & !7;
    let profile_name_offset   = path_offset + dll_path.len();
    let profile_value_offset  = profile_name_offset + profile_env_name.len();
    let plugins_name_offset   = profile_value_offset + profile_env_value.len();
    let plugins_value_offset  = plugins_name_offset + plugins_env_name.len();
    let old_protect_1_offset  = (plugins_value_offset + plugins_env_value.len() + 7) & !7;
    let old_protect_2_offset  = old_protect_1_offset + 4;
    let alloc_size            = old_protect_2_offset + 4;

    let alloc = VirtualAllocEx(
        pi.hProcess, None, alloc_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE,
    );
    if alloc.is_null() { log("VirtualAllocEx failed."); return false; }

    // Patch VirtualProtect old_protect operands — each into its own slot.
    let old_protect_1_addr = alloc as usize + old_protect_1_offset;
    let old_protect_2_addr = alloc as usize + old_protect_2_offset;
    sc[vp_old_protect_operand_1..vp_old_protect_operand_1 + 8]
        .copy_from_slice(&(old_protect_1_addr as u64).to_le_bytes());
    sc[vp_old_protect_operand_2..vp_old_protect_operand_2 + 8]
        .copy_from_slice(&(old_protect_2_addr as u64).to_le_bytes());

    let dll_path_addr = alloc as usize + path_offset;
    sc[dll_path_operand..dll_path_operand + 8].copy_from_slice(&(dll_path_addr as u64).to_le_bytes());

    // Patch GATEJUMPER_PROFILE operands (always written even if value is empty,
    // so the name/value slot offsets are stable; the shellcode only calls
    // SetEnvironmentVariableA when setenv_addr is Some).
    if env_profile_name_operand != 0 {
        let pn_addr = alloc as usize + profile_name_offset;
        let pv_addr = alloc as usize + profile_value_offset;
        sc[env_profile_name_operand..env_profile_name_operand + 8].copy_from_slice(&(pn_addr as u64).to_le_bytes());
        sc[env_profile_value_operand..env_profile_value_operand + 8].copy_from_slice(&(pv_addr as u64).to_le_bytes());
    }
    if env_plugins_name_operand != 0 {
        let ln_addr = alloc as usize + plugins_name_offset;
        let lv_addr = alloc as usize + plugins_value_offset;
        sc[env_plugins_name_operand..env_plugins_name_operand + 8].copy_from_slice(&(ln_addr as u64).to_le_bytes());
        sc[env_plugins_value_operand..env_plugins_value_operand + 8].copy_from_slice(&(lv_addr as u64).to_le_bytes());
    }

    let mut written = 0usize;
    let _ = WriteProcessMemory(pi.hProcess, dll_path_addr as *mut c_void,
        dll_path.as_ptr() as *const c_void, dll_path.len(), Some(&mut written));
    if setenv_addr.is_some() {
        let _ = WriteProcessMemory(pi.hProcess, (alloc as usize + profile_name_offset) as *mut c_void,
            profile_env_name.as_ptr() as *const c_void, profile_env_name.len(), Some(&mut written));
        if !profile_env_value.is_empty() {
            let _ = WriteProcessMemory(pi.hProcess, (alloc as usize + profile_value_offset) as *mut c_void,
                profile_env_value.as_ptr() as *const c_void, profile_env_value.len(), Some(&mut written));
        }
        if plugins.is_some() {
            let _ = WriteProcessMemory(pi.hProcess, (alloc as usize + plugins_name_offset) as *mut c_void,
                plugins_env_name.as_ptr() as *const c_void, plugins_env_name.len(), Some(&mut written));
            let _ = WriteProcessMemory(pi.hProcess, (alloc as usize + plugins_value_offset) as *mut c_void,
                plugins_env_value.as_ptr() as *const c_void, plugins_env_value.len(), Some(&mut written));
        }
    }
    let _ = WriteProcessMemory(pi.hProcess, alloc, sc.as_ptr() as *const c_void, sc.len(), Some(&mut written));

    let mut old = PAGE_PROTECTION_FLAGS(0);
    let _ = VirtualProtectEx(pi.hProcess, alloc, sc.len(), PAGE_EXECUTE_READ, &mut old);

    // Patch OEP: temporarily RW, write trampoline, restore RX.
    let mut tramp: Vec<u8> = Vec::new();
    tramp.extend_from_slice(&[0x48,0xB8]); tramp.extend_from_slice(&(alloc as u64).to_le_bytes());
    tramp.extend_from_slice(&[0xFF,0xE0,0x90,0x90,0x90,0x90,0x90,0x90]);

    let _ = VirtualProtectEx(pi.hProcess, oep_addr as *mut c_void, 16, PAGE_READWRITE, &mut old);
    let _ = WriteProcessMemory(pi.hProcess, oep_addr as *mut c_void,
        tramp.as_ptr() as *const c_void, 16, Some(&mut written));
    let _ = VirtualProtectEx(pi.hProcess, oep_addr as *mut c_void, 16, PAGE_EXECUTE_READ, &mut old);

    match (effective_profile, plugins) {
        (Some(p), Some(l)) => log(&format!("OEP hijacked (GATEJUMPER_PROFILE={}, GATEJUMPER_LOAD_PLUGINS={}).", p, if l { "1" } else { "0" })),
        (Some(p), None)    => log(&format!("OEP hijacked (GATEJUMPER_PROFILE={}).", p)),
        (None,    Some(l)) => log(&format!("OEP hijacked (GATEJUMPER_LOAD_PLUGINS={}).", if l { "1" } else { "0" })),
        (None,    None)    => log("OEP hijacked."),
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

// Always spawn suspended so we can identify the process, then inject or resume
// cleanly. Injection is purely config-driven: only games matching the
// configuration (a gatejumper.ini inside the game's directory, or a
// `[<exe name>]` section in the global config) get the payload; everything else
// launches normally, untouched.
unsafe extern "system" fn create_process_w_hook(
    lpApplicationName: PCWSTR, lpCommandLine: PWSTR,
    lpPA: *const c_void, lpTA: *const c_void,
    bInherit: BOOL, dwFlags: u32, lpEnv: *const c_void,
    lpCurDir: PCWSTR, lpSI: *const STARTUPINFOW, lpPI: *mut PROCESS_INFORMATION,
) -> BOOL {
    let orig: CreateProcessWFn = std::mem::transmute(CREATE_PROCESS_W_ORIG);
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
                        let injected = inject_into_suspended_process(pi, m.profile, m.plugins);
                        if !caller_wanted_suspended {
                            ResumeThread(pi.hThread);
                            log(if injected { "Resumed with payload." } else { "Injection failed; resumed." });
                        }
                    }
                    None => {
                        log(&format!("Game '{}' does not match configuration; launching normally.", exe_name));
                        if !caller_wanted_suspended {
                            ResumeThread(pi.hThread);
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

            // Read the multi-profile config exactly once.
            let config = DLL_DIRECTORY.get()
                .map(|d| d.join("gatejumper.ini"))
                .and_then(|p| std::fs::read_to_string(p).ok())
                .map(|content| parse_config(&content))
                .unwrap_or_default();
            log(&format!(
                "Config loaded: dmm={}, main.target={:?}, {} game profile(s): [{}].",
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
