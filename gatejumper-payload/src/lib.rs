//! GateJumper Payload
//!
//! Proxies system DLL exports, suppresses anti-cheat checks, and performs OEP hijack.

#![windows_subsystem = "windows"]
#![allow(non_snake_case, non_upper_case_globals)]

use std::{ffi::c_void, fs::OpenOptions, io::Write};

type BOOL = i32;
type HINSTANCE = isize;

extern "system" {
    fn GetModuleHandleA(lpModuleName: *const u8) -> HINSTANCE;
    fn GetProcAddress(hModule: HINSTANCE, lpProcName: *const u8) -> Option<unsafe extern "system" fn()>;
    fn LoadLibraryW(lpLibFileName: *const u16) -> HINSTANCE;
    fn LoadLibraryA(lpLibFileName: *const u8) -> HINSTANCE;
    fn VirtualProtect(lpAddress: *mut c_void, dwSize: usize, flNewProtect: u32, lpflOldProtect: *mut u32) -> BOOL;
    fn GetCommandLineW() -> *const u16;
}

use windows::{
    core::PCWSTR,
    Win32::Foundation::{SetLastError, ERROR_FILE_NOT_FOUND},
};


const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const DLL_PROCESS_ATTACH: u32 = 1;

// --- Logging ---

unsafe fn log(msg: &str) {
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open("gatejumper.log") {
        let _ = writeln!(file, "[GateJumper] {}", msg);
    }
}

// --- PathFileExistsW Hook ---

static mut PATH_FILE_EXISTS_W_ORIG: usize = 0;
type PathFileExistsWFn = extern "system" fn(PCWSTR) -> BOOL;

unsafe extern "system" fn path_file_exists_w_hook(filename: PCWSTR) -> BOOL {
    if !filename.0.is_null() && (filename.0 as usize) != usize::MAX {
        if (filename.0 as usize) < 0x00007FFFFFFFFFFF {
            if let Ok(filename_str) = filename.to_string() {
                if filename_str.to_lowercase().ends_with(".exe.local") {
                    log("Intercepted PathFileExistsW for .local — suppressed.");
                    SetLastError(ERROR_FILE_NOT_FOUND);
                    return 0;
                }
            }
        }
    }
    let orig: PathFileExistsWFn = std::mem::transmute(PATH_FILE_EXISTS_W_ORIG);
    orig(filename)
}

fn setup_hooks() {
    unsafe {
        let shlwapi = LoadLibraryA(b"shlwapi.dll\0".as_ptr());
        if shlwapi != 0 {
            let p_path_file_exists = GetProcAddress(shlwapi, b"PathFileExistsW\0".as_ptr());
            if let Some(func) = p_path_file_exists {
                match minhook::MinHook::create_hook(func as *mut c_void, path_file_exists_w_hook as *mut c_void) {
                    Ok(trampoline) => {
                        PATH_FILE_EXISTS_W_ORIG = trampoline as usize;
                        let _ = minhook::MinHook::enable_hook(func as *mut c_void);
                        log("PathFileExistsW hooked.");
                    }
                    Err(_) => log("WARN: Failed to hook PathFileExistsW."),
                }
            }
        }
    }
}

// --- PE Parsing & OEP Hijack ---

fn get_game_entry_point() -> *mut u8 {
    unsafe {
        let base = GetModuleHandleA(std::ptr::null());
        if base == 0 { return std::ptr::null_mut(); }

        let dos_header = base as *const u8;
        let e_lfanew = *(dos_header.add(0x3C) as *const u32);
        let nt_headers = dos_header.add(e_lfanew as usize);
        let addr_of_ep = *(nt_headers.add(40) as *const u32);

        dos_header.add(addr_of_ep as usize) as *mut u8
    }
}

pub extern "system" fn launch_unity() -> i32 {
    unsafe {
        log("OEP Hijack triggered. Launching Unity Engine...");

        // Generic Plugin Loader
        let plugins_dir = "plugins";
        if std::path::Path::new(plugins_dir).is_dir() {
            log("Scanning 'plugins' directory for additional mods...");
            if let Ok(entries) = std::fs::read_dir(plugins_dir) {
                for entry in entries.filter_map(|e| e.ok()) {
                    let path = entry.path();
                    if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("dll") {
                        if let Some(path_str) = path.to_str() {
                            let mut w_path: Vec<u16> = path_str.encode_utf16().collect();
                            w_path.push(0);
                            let h_mod = LoadLibraryW(w_path.as_ptr());
                            if h_mod != 0 {
                                log(&format!("Successfully loaded plugin: {}", path_str));
                            } else {
                                log(&format!("Failed to load plugin: {}", path_str));
                            }
                        }
                    }
                }
            }
        } else {
            log("'plugins' directory not found. Skipping plugin loading.");
        }

        let unity_path: Vec<u16> = "UnityPlayer.dll\0".encode_utf16().collect();
        let h_unity = LoadLibraryW(unity_path.as_ptr());
        if h_unity == 0 {
            log("FATAL: UnityPlayer.dll not found.");
            return 1;
        }

        let unity_main_ptr = GetProcAddress(h_unity, b"UnityMain\0".as_ptr());
        if let Some(unity_main_fn) = unity_main_ptr {
            let unity_main: extern "system" fn(HINSTANCE, *mut c_void, *const u16, i32) -> i32 =
                std::mem::transmute(unity_main_fn);

            log("Handing execution to UnityMain.");
            let mut cmd_ptr = GetCommandLineW();
            if !cmd_ptr.is_null() {
                let mut in_quotes = false;
                let mut i = 0;
                loop {
                    let c = *cmd_ptr.add(i);
                    if c == 0 { break; }
                    if c == b'"' as u16 { in_quotes = !in_quotes; }
                    if c == b' ' as u16 && !in_quotes {
                        i += 1;
                        while *cmd_ptr.add(i) == b' ' as u16 { i += 1; }
                        cmd_ptr = cmd_ptr.add(i);
                        break;
                    }
                    i += 1;
                }
                
                let len = (0..).take_while(|&idx| *cmd_ptr.add(idx) != 0).count();
                let slice = std::slice::from_raw_parts(cmd_ptr, len);
                let cmd_str = String::from_utf16_lossy(slice);
                log(&format!("Passing lpCmdLine: {}", cmd_str));
            } else {
                log("WARNING: GetCommandLineW returned null!");
            }
            return unity_main(GetModuleHandleA(std::ptr::null()), std::ptr::null_mut(), cmd_ptr, 10);
        }

        log("FATAL: UnityMain export not found.");
        1
    }
}

// --- DllMain ---

#[no_mangle]
pub extern "system" fn DllMain(
    _module: HINSTANCE,
    reason: u32,
    _reserved: *mut c_void,
) -> BOOL {
    if reason == DLL_PROCESS_ATTACH {
        unsafe {
            log("=== GateJumper Payload loaded ===");

            setup_hooks();

            let ep = get_game_entry_point();
            if ep.is_null() {
                log("FATAL: Entry point not found.");
                return 0;
            }

            let mut old_protect = 0;
            if VirtualProtect(ep as _, 14, PAGE_EXECUTE_READWRITE, &mut old_protect) != 0 {
                let target = launch_unity as *const () as usize;

                // 64-bit absolute jump: ff 25 00 00 00 00 [8-byte addr]
                *ep.add(0) = 0xFF;
                *ep.add(1) = 0x25;
                *ep.add(2) = 0x00;
                *ep.add(3) = 0x00;
                *ep.add(4) = 0x00;
                *ep.add(5) = 0x00;

                let target_bytes = target.to_ne_bytes();
                std::ptr::copy_nonoverlapping(target_bytes.as_ptr(), ep.add(6), 8);

                log(&format!("OEP patched at {:?}. Bypass armed.", ep));
            }
        }
    }
    1
}
