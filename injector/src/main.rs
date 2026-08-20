//! GateJumper Injector
//!
//! Spawns the target game process suspended and injects gatejumper.dll via APC.
//! Always targets the real game executable directly — never substitutes a
//! different binary.  gatejumper.dll handles the appropriate bypass strategy
//! based on the packing layout it detects inside the target process.

#![windows_subsystem = "windows"]
#![allow(non_snake_case)]

use windows::core::{PCSTR, PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, GetLastError};
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

fn normalize_target_path(path: &std::path::Path) -> std::path::PathBuf {
    let text = path.to_string_lossy();
    if text.starts_with("/") {
        let without_prefix = text.trim_start_matches('/');
        let normalized = without_prefix.replace('/', "\\");
        let windows_path = if normalized.starts_with("\\") {
            format!("Z:{}", normalized)
        } else {
            format!("Z:\\{}", normalized)
        };
        return std::path::PathBuf::from(windows_path);
    }

    if text.contains('/') && !text.contains(':') {
        let normalized = text.replace('/', "\\");
        return std::path::PathBuf::from(normalized);
    }

    path.to_path_buf()
}

fn select_payload_for_target(target_name: &str) -> &'static str {
    let lower = target_name.to_ascii_lowercase();
    if lower.contains("dmm") || lower.contains("gameplayer") {
        "dmmhook.dll"
    } else {
        "gatejumper.dll"
    }
}

fn main() {
    unsafe {
        let args: Vec<String> = std::env::args().collect();
        log(&format!("Starting with args: {:?}", args));

        let mut startup_info: STARTUPINFOW = std::mem::zeroed();
        startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut process_info: PROCESS_INFORMATION = std::mem::zeroed();

        let mut target_exe = None;
        let mut cmd_line_w: Vec<u16> = Vec::new();
        let mut using_args = false;

        let our_name = std::env::current_exe()
            .ok()
            .and_then(|p| p.file_name().map(|s| s.to_string_lossy().to_lowercase()))
            .unwrap_or_else(|| "injector.exe".to_string());

        if args.len() > 1 {
            for (i, arg) in args.iter().enumerate().skip(1) {
                let trimmed = arg.trim_matches('"');
                log(&format!("Checking arg[{}]: {}", i, trimmed));
                let path = std::path::PathBuf::from(trimmed);

                if path
                    .extension()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_lowercase()
                    == "exe"
                {
                    let normalized = normalize_target_path(&path);
                    let name = normalized
                        .file_name()
                        .map(|s| s.to_string_lossy().to_lowercase())
                        .unwrap_or_default();
                    if name != our_name && name != "start.exe" {
                        log(&format!("Found target exe in args: {:?}", normalized));
                        target_exe = Some(normalized);
                        using_args = true;

                        let cmd_parts: Vec<String> = args[i..]
                            .iter()
                            .map(|s| {
                                if s.contains(' ') && !s.starts_with('"') {
                                    format!("\"{}\"", s)
                                } else {
                                    s.clone()
                                }
                            })
                            .collect();
                        let cmd_str = cmd_parts.join(" ");
                        log(&format!("Reconstructed cmd line: {}", cmd_str));
                        cmd_line_w = cmd_str.encode_utf16().chain(std::iter::once(0)).collect();
                        break;
                    } else {
                        log("Arg is the injector itself, skipping.");
                    }
                }
            }
        }

        if target_exe.is_none() {
            log("No target EXE in args, scanning current directory...");
            if let Ok(entries) = std::fs::read_dir(".") {
                for entry in entries.filter_map(|e| e.ok()) {
                    let path = entry.path();
                    if let Some(ext) = path.extension() {
                        if ext.to_ascii_lowercase() == "exe" {
                            let name = path
                                .file_name()
                                .unwrap()
                                .to_string_lossy()
                                .to_lowercase();
                            if name != our_name
                                && name != "unitycrashhandler64.exe"
                                && name != "start.exe"
                                && !name.contains("uninstall")
                            {
                                let normalized = normalize_target_path(&path);
                                log(&format!("Found local target: {:?}", normalized));
                                target_exe = Some(normalized);
                                break;
                            }
                        }
                    }
                }
            }
        }

        let exe_path = match target_exe {
            Some(p) => {
                let normalized = normalize_target_path(&p);
                log(&format!("Selected EXE: {:?}", normalized));
                normalized
            }
            None => {
                log("FATAL: Could not find a suitable game executable.");
                return;
            }
        };

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
            None,
            None,
            false,
            CREATE_SUSPENDED,
            None,
            None,
            &startup_info,
            &mut process_info,
        );

        if success.is_err() {
            log(&format!(
                "[GateJumper] CreateProcessW failed! Error: {:?}",
                GetLastError()
            ));
            return;
        }

        let mut path_buf = [0u16; 512];
        let len = GetModuleFileNameW(None, &mut path_buf);
        let our_path = String::from_utf16_lossy(&path_buf[..len as usize]);
        let our_dir = if let Some(pos) = our_path.rfind('\\') {
            &our_path[..pos]
        } else {
            "."
        };

        let exe_name_lower = exe_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_lowercase();
        let hook_dll = select_payload_for_target(&exe_name_lower);
        let dll_path = format!("{}\\{}\0", our_dir, hook_dll);

        log(&format!("Using payload DLL: {} for target {}", hook_dll, exe_name_lower));
        let dll_bytes = dll_path.as_bytes();
        let alloc_addr = VirtualAllocEx(
            process_info.hProcess,
            None,
            dll_bytes.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        let mut injection_successful = false;

        if !alloc_addr.is_null() {
            let mut bytes_written = 0;
            let write_success = WriteProcessMemory(
                process_info.hProcess,
                alloc_addr,
                dll_bytes.as_ptr() as _,
                dll_bytes.len(),
                Some(&mut bytes_written),
            );

            if write_success.is_ok() && bytes_written == dll_bytes.len() {
                let k32 = GetModuleHandleA(PCSTR(b"kernel32.dll\0".as_ptr())).unwrap();
                let load_lib = GetProcAddress(k32, PCSTR(b"LoadLibraryA\0".as_ptr()));

                if let Some(f) = load_lib {
                    let apc_fn = std::mem::transmute(f);
                    let apc_result = QueueUserAPC(apc_fn, process_info.hThread, alloc_addr as usize);
                    if apc_result != 0 {
                        log("[GateJumper] APC Queued.");
                        injection_successful = true;
                    } else {
                        log("QueueUserAPC failed.");
                    }
                } else {
                    log("GetProcAddress for LoadLibraryA failed.");
                }
            } else {
                log("WriteProcessMemory failed.");
            }
        } else {
            log("VirtualAllocEx failed.");
        }

        if injection_successful {
            ResumeThread(process_info.hThread);
            log("[GateJumper] Process resumed. Injector exiting.");
        } else {
            log("FATAL: Injection failed, terminating spawned process to prevent leaks.");
            let _ = TerminateProcess(process_info.hProcess, 1);
        }

        let _ = CloseHandle(process_info.hProcess);
        let _ = CloseHandle(process_info.hThread);
    }
}
