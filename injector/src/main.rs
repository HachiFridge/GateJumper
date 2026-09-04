//! GateJumper Injector
//!
//! Spawns the target game process suspended and injects gatejumper.dll via APC.
//!
//! Target resolution order:
//!   1. `target` / `dmm` keys in `gatejumper.ini` beside the injector
//!   2. First `.exe` argument from the command line (Steam `%command%` / launcher chain)
//!   3. Directory scan of the injector's own directory

#![windows_subsystem = "windows"]
#![allow(non_snake_case)]

use windows::core::{PCSTR, PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, GetLastError};
use windows::Win32::Storage::FileSystem::{GetFileAttributesW, INVALID_FILE_ATTRIBUTES};
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::LibraryLoader::{GetModuleFileNameW, GetModuleHandleA, GetProcAddress};
use windows::Win32::System::Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};
use windows::Win32::System::Threading::{
    CreateProcessW, QueueUserAPC, ResumeThread, TerminateProcess, CREATE_SUSPENDED,
    PROCESS_INFORMATION, STARTUPINFOW,
};

unsafe fn log(msg: &str) {
    use std::io::Write;
    println!("[Injector] {}", msg);
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(parent) = exe_path.parent() {
            let log_path = parent.join("gatejumper.log");
            if let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(log_path)
            {
                let _ = writeln!(file, "[Injector] {}", msg);
            }
        }
    }
}

/// True if the file (or directory) exists at the given Windows path.
unsafe fn path_exists_windows(path: &str) -> bool {
    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    GetFileAttributesW(PCWSTR(wide.as_ptr())) != INVALID_FILE_ATTRIBUTES
}

/// Classify a raw `target` value from the config or command line into a Windows
/// path ready for CreateProcessW. Accepted forms:
///
///   1. Windows-style: `D:\Games\ExampleGame\Game.exe`, `Z:\…`, `C:\…`, `\\server\share\…`
///        Used as-is (forward slashes normalized). The drive letter is whatever
///        the Wine/Proton prefix actually provides, including prefix-manager
///        mappings that differ from the `Z:` default.
///   2. Unix absolute: `/media/extra/Games/ExampleGame/Game.exe`
///        Translated through the `Z:` drive, Wine/Proton's standard mount of
///        `/`, and verified to exist there. A Windows process cannot discover
///        how a prefix maps partitions onto drive letters (Wine hides the Unix
///        targets of QueryDosDeviceW), so when verification fails an actionable
///        error is returned instead of guessing at other letters.
///   3. Relative: `Game.exe`, `./Game.exe`, `..\sibling\Game.exe`
///        Anchored to `base_dir` — the directory holding gatejumper.ini and
///        start.exe — which is always a working Windows path in the current
///        prefix, so no drive translation is ever needed.
fn resolve_target_value(
    raw: &str,
    base_dir: &std::path::Path,
) -> Result<std::path::PathBuf, String> {
    let text = raw.trim().trim_matches('"');
    if text.is_empty() {
        return Err("empty target value".to_string());
    }

    let bytes = text.as_bytes();
    let is_windows_absolute = text.starts_with("\\\\")
        || (bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && (bytes[2] == b'\\' || bytes[2] == b'/'));
    if is_windows_absolute {
        return Ok(std::path::PathBuf::from(text.replace('/', "\\")));
    }

    if text.starts_with('/') {
        let candidate = format!("Z:{}", text.replace('/', "\\"));
        if unsafe { path_exists_windows(&candidate) } {
            return Ok(std::path::PathBuf::from(candidate));
        }
        return Err(format!(
            "'{}' is not reachable as '{}' in this Wine/Proton prefix. Use a path relative to gatejumper.ini (e.g. 'Game.exe'), a Windows path for this prefix (e.g. from 'winepath -w'), or check the prefix's drive mappings.",
            text, candidate
        ));
    }

    // Relative: anchor to the config's own directory.
    let joined = base_dir.join(text);
    Ok(std::path::PathBuf::from(joined.to_string_lossy().replace('/', "\\")))
}

fn select_payload_for_target(target_name: &str) -> &'static str {
    let lower = target_name.to_ascii_lowercase();
    if lower.contains("dmm") || lower.contains("gameplayer") {
        "dmmhook.dll"
    } else {
        "gatejumper.dll"
    }
}

/// Strip a trailing ` # ...` / ` ; ...` comment from a value line. A comment
/// marker only counts when preceded by whitespace so paths containing `#` or
/// `;` are left intact.
fn strip_trailing_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if (b == b'#' || b == b';') && i > 0 && bytes[i - 1].is_ascii_whitespace() {
            return line[..i].trim_end();
        }
    }
    line
}

/// Read `target` / `dmm` keys from the `[main]` section of the multi-profile
/// `gatejumper.ini`. Files without `[section]` headers are treated as
/// `[main]`, keeping old single-profile configs valid; per-game sections are
/// deliberately ignored here — DMM-Hook consumes those inside the launcher.
/// Returns `(target_value, is_dmm_shorthand)`.
fn read_main_ini(ini_path: &std::path::Path) -> Option<(Option<String>, bool)> {
    let content = std::fs::read_to_string(ini_path).ok()?;
    let mut section = String::from("main");
    let mut target_val: Option<String> = None;
    let mut dmm_shorthand = false;
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') { continue; }
        if line.starts_with('[') {
            if let Some(rest) = line.strip_prefix('[') {
                if let Some(name) = rest.strip_suffix(']') {
                    section = name.trim().to_string();
                }
            }
            continue;
        }
        if !section.eq_ignore_ascii_case("main") { continue; }
        if let Some(rest) = line.strip_prefix("target") {
            if let Some(val) = rest.trim().strip_prefix('=') {
                let val = strip_trailing_comment(val.trim()).trim().trim_matches('"');
                if !val.is_empty() { target_val = Some(val.to_string()); }
            }
        }
        if let Some(rest) = line.strip_prefix("dmm") {
            if let Some(val) = rest.trim().strip_prefix('=') {
                let val = val.trim().to_ascii_lowercase();
                if val == "true" || val == "1" || val == "yes" { dmm_shorthand = true; }
            }
        }
    }
    if target_val.is_some() || dmm_shorthand {
        return Some((target_val, dmm_shorthand));
    }
    None
}

/// Scan a directory for the first plausible game executable.
fn scan_dir_for_exe(
    dir: &std::path::Path,
    our_name: &str,
) -> Option<std::path::PathBuf> {
    let entries = std::fs::read_dir(dir).ok()?;
    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()).map(|e| e.to_ascii_lowercase()).as_deref() != Some("exe") {
            continue;
        }
        let name = path.file_name()?.to_string_lossy().to_ascii_lowercase();
        if name == our_name
            || name == "unitycrashhandler64.exe"
            || name.contains("uninstall")
            || name.contains("installer")
        {
            continue;
        }
        return Some(path);
    }
    None
}

/// Map a user-supplied profile name onto its canonical form if it is a known
/// GateJumper profile; `None` otherwise. Unknown values are deliberately left
/// alone so a game-owned `--profile=...` argument passes through untouched.
fn canonical_profile_name(name: &str) -> Option<&'static str> {
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

fn main() {
    unsafe {
        let args: Vec<String> = std::env::args().collect();
        log(&format!("Starting with args: {:?}", args));

        let mut startup_info: STARTUPINFOW = std::mem::zeroed();
        startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut process_info: PROCESS_INFORMATION = std::mem::zeroed();

        // Resolve injector's own directory early — used for config lookup and
        // payload DLL path construction.
        let mut path_buf = [0u16; 512];
        let len = GetModuleFileNameW(None, &mut path_buf);
        let our_path = String::from_utf16_lossy(&path_buf[..len as usize]);
        let our_dir = if let Some(pos) = our_path.rfind('\\') {
            &our_path[..pos]
        } else {
            "."
        };
        let our_dir_path = std::path::PathBuf::from(our_dir);

        let our_name = std::env::current_exe()
            .ok()
            .and_then(|p| p.file_name().map(|s| s.to_string_lossy().to_lowercase()))
            .unwrap_or_else(|| "injector.exe".to_string());

        // --- Manual profile override (command line) ---
        // `--profile <name>` / `--profile=<name>` is accepted anywhere on the
        // command line (Steam launch options put it before or after
        // `%command%`). It is forwarded to the payload as GATEJUMPER_PROFILE so
        // the child process inherits it. Only values resolving to a known
        // profile are consumed; anything else is left untouched so a
        // game-owned `--profile=...` argument passes through to the game.
        let mut profile_override: Option<&'static str> = None;
        let mut consumed_arg_idx: Vec<usize> = Vec::new();
        {
            let mut arg_iter = args.iter().enumerate().skip(1).peekable();
            while let Some((i, arg)) = arg_iter.next() {
                let (value_idx, raw_value): (Option<usize>, Option<&str>) =
                    if let Some(v) = arg.strip_prefix("--profile=") {
                        (None, Some(v))
                    } else if arg == "--profile" {
                        match arg_iter.peek() {
                            Some((j, next)) => (Some(*j), Some(next.trim_matches('"'))),
                            None => (None, None),
                        }
                    } else {
                        (None, None)
                    };

                let Some(raw) = raw_value else { continue };
                let Some(canonical) = canonical_profile_name(raw) else {
                    continue; // not a GateJumper profile; treat as a game argument
                };

                profile_override = Some(canonical);
                consumed_arg_idx.push(i);
                if let Some(j) = value_idx {
                    consumed_arg_idx.push(j);
                    arg_iter.next(); // skip the value token
                }
                log(&format!("--profile override: {}", canonical));
            }
        }

        // --- Target resolution ---

        let mut target_exe: Option<std::path::PathBuf> = None;
        let mut cmd_line_w: Vec<u16> = Vec::new();
        let mut using_args = false;

        // 1. gatejumper.ini beside the injector — `[main]` section only
        //    (target = <DMM Game Player directory or exe> / dmm = true)
        if target_exe.is_none() {
            let ini_path = our_dir_path.join("gatejumper.ini");
            if let Some((ini_target, dmm_shorthand)) = read_main_ini(&ini_path) {
                if let Some(target) = ini_target {
                    match resolve_target_value(&target, &our_dir_path) {
                        Ok(resolved) => {
                            // `[main] target` names the DMM Game Player install:
                            // a directory (join DMMGamePlayer.exe) or an
                            // explicit launcher exe path (old-style configs).
                            let launcher = if resolved.is_dir() {
                                resolved.join("DMMGamePlayer.exe")
                            } else {
                                resolved
                            };
                            log(&format!("gatejumper.ini [main] target: {:?}", launcher));
                            target_exe = Some(launcher);
                        }
                        Err(e) => {
                            log(&format!("FATAL: gatejumper.ini [main] target: {}", e));
                            return;
                        }
                    }
                } else if dmm_shorthand {
                    // dmm = true shorthand — resolve standard DMM paths
                    let candidates = [
                        "C:\\Program Files\\DMMGamePlayer\\DMMGamePlayer.exe",
                        "C:\\Program Files (x86)\\DMMGamePlayer\\DMMGamePlayer.exe",
                        "Z:\\Program Files\\DMMGamePlayer\\DMMGamePlayer.exe",
                        "Z:\\Program Files (x86)\\DMMGamePlayer\\DMMGamePlayer.exe",
                    ];
                    for candidate in &candidates {
                        let p = std::path::PathBuf::from(candidate);
                        if p.is_file() {
                            log(&format!("gatejumper.ini [main] dmm=true: {:?}", p));
                            target_exe = Some(p);
                            break;
                        }
                    }
                    if target_exe.is_none() {
                        log("gatejumper.ini [main] dmm=true: DMMGamePlayer.exe not found at standard locations.");
                    }
                }
            }
        }

        // 2. First .exe in args (Steam %command% / launcher chain passthrough)
        if target_exe.is_none() {
            'arg_scan: for (i, arg) in args.iter().enumerate().skip(1) {
                // Skip known GateJumper flags
                if arg.starts_with("--") { continue; }
                let trimmed = arg.trim_matches('"');
                let path = std::path::PathBuf::from(trimmed);
                if path.extension().and_then(|s| s.to_str()).unwrap_or("").to_lowercase() == "exe" {
                    let normalized = match resolve_target_value(trimmed, &our_dir_path) {
                        Ok(p) => p,
                        Err(e) => {
                            log(&format!("Skipping argument '{}': {}", arg, e));
                            continue;
                        }
                    };
                    let name = normalized.file_name()
                        .map(|s| s.to_string_lossy().to_lowercase())
                        .unwrap_or_default();
                    if name != our_name && name != "start.exe" {
                        log(&format!("Found target exe in args[{}]: {:?}", i, normalized));
                        target_exe = Some(normalized);
                        using_args = true;
                        // Reconstruct command line from this arg forward, minus
                        // any GateJumper flags consumed above.
                        let cmd_parts: Vec<String> = args.iter().enumerate().skip(i)
                            .filter(|(idx, _)| !consumed_arg_idx.contains(idx))
                            .map(|(_, s)| if s.contains(' ') && !s.starts_with('"') {
                                format!("\"{}\"", s)
                            } else { s.clone() })
                            .collect();
                        let cmd_str = cmd_parts.join(" ");
                        log(&format!("Reconstructed cmd: {}", cmd_str));
                        cmd_line_w = cmd_str.encode_utf16().chain(std::iter::once(0)).collect();
                        break 'arg_scan;
                    } else {
                        log("Arg is injector itself, skipping.");
                    }
                }
            }
        }

        // 3. Directory scan of injector's own directory
        if target_exe.is_none() {
            log("No target in config or command line; scanning injector directory...");
            if let Some(found) = scan_dir_for_exe(&our_dir_path, &our_name) {
                log(&format!("Found via directory scan: {:?}", found));
                // DMM-managed games fail auth when launched directly; warn and proceed.
                let is_dmm_game = our_dir_path.join("dmmhook.dll").is_file()
                    || our_dir_path.join("installer").is_dir();
                if is_dmm_game {
                    log("WARNING: This appears to be a DMM-managed game.");
                    log("WARNING: Launching the game exe directly will fail DMM authentication.");
                    log("WARNING: Create a gatejumper.ini next to start.exe with: dmm = true");
                    log("WARNING:   or: target = C:\\...\\DMMGamePlayer.exe");
                    log("WARNING: Proceeding anyway in case you know what you're doing.");
                }
                target_exe = Some(found);
            }
        }

        let exe_path = match target_exe {
            Some(p) => { log(&format!("Selected target: {:?}", p)); p }
            None => { log("FATAL: Could not find a suitable target executable."); return; }
        };

        // Forward a manual profile override to the payload via the environment:
        // the child inherits this process's environment, so gatejumper.dll picks
        // it up from GATEJUMPER_PROFILE inside the game (and so does the game
        // when a launcher spawns it later, e.g. the DMM Game Player flow).
        if let Some(profile) = profile_override {
            std::env::set_var("GATEJUMPER_PROFILE", profile);
            log(&format!("GATEJUMPER_PROFILE={} set for child process.", profile));
        }

        let exe_name_w: Vec<u16> = exe_path
            .to_string_lossy()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let lp_command_line = if using_args {
            Some(PWSTR(cmd_line_w.as_mut_ptr()))
        } else {
            None
        };

        let success = CreateProcessW(
            PCWSTR(exe_name_w.as_ptr()),
            lp_command_line,
            None, None, false, CREATE_SUSPENDED,
            None, None, &startup_info, &mut process_info,
        );

        if success.is_err() {
            log(&format!("CreateProcessW failed: {:?}", GetLastError()));
            return;
        }

        let exe_name_lower = exe_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_ascii_lowercase();
        let hook_dll = select_payload_for_target(&exe_name_lower);
        let dll_path = format!("{}\\{}\0", our_dir, hook_dll);
        log(&format!("Injecting {} into {}", hook_dll, exe_name_lower));

        // The payload DLL must ship next to the injector. In the DMM flow this
        // is what makes the whole folder relocatable: dmmhook.dll (and, through
        // it, gatejumper.dll) is resolved from the injector's own directory,
        // never from DMM Game Player's or the game's directory — both of which
        // DMM wipes on updates. Fail loudly instead of launching a silently
        // uninjected process when a file is missing from the folder.
        if !our_dir_path.join(hook_dll).is_file() {
            log(&format!("FATAL: {} not found next to the injector; aborting without launching the target.", hook_dll));
            let _ = TerminateProcess(process_info.hProcess, 1);
            let _ = CloseHandle(process_info.hProcess);
            let _ = CloseHandle(process_info.hThread);
            return;
        }

        let dll_bytes = dll_path.as_bytes();
        let alloc_addr = VirtualAllocEx(
            process_info.hProcess, None, dll_bytes.len(),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE,
        );

        let mut injection_successful = false;

        if !alloc_addr.is_null() {
            let mut bytes_written = 0;
            let write_ok = WriteProcessMemory(
                process_info.hProcess, alloc_addr,
                dll_bytes.as_ptr() as _, dll_bytes.len(),
                Some(&mut bytes_written),
            );
            if write_ok.is_ok() && bytes_written == dll_bytes.len() {
                let k32 = GetModuleHandleA(PCSTR(b"kernel32.dll\0".as_ptr())).unwrap();
                let load_lib = GetProcAddress(k32, PCSTR(b"LoadLibraryA\0".as_ptr()));
                if let Some(f) = load_lib {
                    let apc_fn = std::mem::transmute(f);
                    if QueueUserAPC(apc_fn, process_info.hThread, alloc_addr as usize) != 0 {
                        log("APC queued.");
                        injection_successful = true;
                    } else {
                        log("QueueUserAPC failed.");
                    }
                } else {
                    log("GetProcAddress(LoadLibraryA) failed.");
                }
            } else {
                log("WriteProcessMemory failed.");
            }
        } else {
            log("VirtualAllocEx failed.");
        }

        if injection_successful {
            ResumeThread(process_info.hThread);
            log("Process resumed. Injector exiting.");
        } else {
            log("FATAL: Injection failed; terminating child process.");
            let _ = TerminateProcess(process_info.hProcess, 1);
        }

        let _ = CloseHandle(process_info.hProcess);
        let _ = CloseHandle(process_info.hThread);
    }
}
