//! GateJumper Injector
//!
//! Spawns process suspended and injects payload via APC.

#![windows_subsystem = "windows"]
#![allow(non_snake_case)]

use std::ptr;

type BOOL = i32;
type HANDLE = isize;
type LPWSTR = *mut u16;
type LPCWSTR = *const u16;
type LPVOID = *mut std::ffi::c_void;
type LPCVOID = *const std::ffi::c_void;
type DWORD = u32;

#[repr(C)]
pub struct STARTUPINFOW {
    pub cb: u32,
    pub lpReserved: LPWSTR,
    pub lpDesktop: LPWSTR,
    pub lpTitle: LPWSTR,
    pub dwX: u32,
    pub dwY: u32,
    pub dwXSize: u32,
    pub dwYSize: u32,
    pub dwXCountChars: u32,
    pub dwYCountChars: u32,
    pub dwFillAttribute: u32,
    pub dwFlags: u32,
    pub wShowWindow: u16,
    pub cbReserved2: u16,
    pub lpReserved2: *mut u8,
    pub hStdInput: HANDLE,
    pub hStdOutput: HANDLE,
    pub hStdError: HANDLE,
}

#[repr(C)]
pub struct PROCESS_INFORMATION {
    pub hProcess: HANDLE,
    pub hThread: HANDLE,
    pub dwProcessId: u32,
    pub dwThreadId: u32,
}

const CREATE_SUSPENDED: u32 = 0x00000004;
const MEM_COMMIT: u32 = 0x00001000;
const MEM_RESERVE: u32 = 0x00002000;
const PAGE_READWRITE: u32 = 0x04;

extern "system" {
    fn CreateProcessW(lpApplicationName: LPCWSTR, lpCommandLine: LPWSTR, lpProcessAttributes: *const c_void, lpThreadAttributes: *const c_void, bInheritHandles: BOOL, dwCreationFlags: DWORD, lpEnvironment: *const c_void, lpCurrentDirectory: LPCWSTR, lpStartupInfo: *const STARTUPINFOW, lpProcessInformation: *mut PROCESS_INFORMATION) -> BOOL;
    fn VirtualAllocEx(hProcess: HANDLE, lpAddress: LPVOID, dwSize: usize, flAllocationType: DWORD, flProtect: DWORD) -> LPVOID;
    fn WriteProcessMemory(hProcess: HANDLE, lpBaseAddress: LPVOID, lpBuffer: LPCVOID, nSize: usize, lpNumberOfBytesWritten: *mut usize) -> BOOL;
    fn GetModuleHandleA(lpModuleName: *const u8) -> HANDLE;
    fn GetProcAddress(hModule: HANDLE, lpProcName: *const u8) -> Option<unsafe extern "system" fn()>;
    fn QueueUserAPC(pfnAPC: usize, hThread: HANDLE, dwData: usize) -> u32;
    fn ResumeThread(hThread: HANDLE) -> u32;
    fn CloseHandle(hObject: HANDLE) -> BOOL;
    fn GetModuleFileNameW(hModule: HANDLE, lpFilename: *mut u16, nSize: u32) -> u32;
    fn OutputDebugStringA(lpOutputString: *const u8);
}

use std::ffi::c_void;

unsafe fn log(msg: &str) {
    use std::io::Write;
    if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open("injector.log") {
        let _ = writeln!(file, "[Injector] {}", msg);
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
                
                if path.extension().and_then(|s| s.to_str()).unwrap_or("").to_lowercase() == "exe" {
                    let name = path.file_name().map(|s| s.to_string_lossy().to_lowercase()).unwrap_or_default();
                    if name != our_name && name != "start.exe" {
                        log(&format!("Found target exe in args: {:?}", path));
                        target_exe = Some(path);
                        using_args = true;
                        
                        let cmd_parts: Vec<String> = args[i..].iter().map(|s| {
                            if s.contains(' ') && !s.starts_with('"') {
                                format!("\"{}\"", s)
                            } else {
                                s.clone()
                            }
                        }).collect();
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
                            let name = path.file_name().unwrap().to_string_lossy().to_lowercase();
                            if name != our_name && 
                               name != "unitycrashhandler64.exe" && 
                               name != "start.exe" &&
                               !name.contains("uninstall") {
                                log(&format!("Found local target: {:?}", path));
                                target_exe = Some(path);
                                break;
                            }
                        }
                    }
                }
            }
        }

        let exe_path = match target_exe {
            Some(p) => {
                log(&format!("Selected EXE: {:?}", p));
                p
            },
            None => {
                log("FATAL: Could not find a suitable game executable.");
                return;
            }
        };

        let exe_name_w: Vec<u16> = exe_path.to_string_lossy().encode_utf16().chain(std::iter::once(0)).collect();
        let lp_command_line = if using_args { cmd_line_w.as_mut_ptr() } else { ptr::null_mut() };
        
        let success = CreateProcessW(
            exe_name_w.as_ptr(),
            lp_command_line,
            ptr::null(),
            ptr::null(),
            0,
            CREATE_SUSPENDED,
            ptr::null(),
            ptr::null(),
            &startup_info,
            &mut process_info,
        );

        if success == 0 {
            log("[GateJumper] CreateProcessW failed!");
            return;
        }

        let mut path_buf = [0u16; 512];
        let len = GetModuleFileNameW(0, path_buf.as_mut_ptr(), 512);
        let our_path = String::from_utf16_lossy(&path_buf[..len as usize]);
        let our_dir = if let Some(pos) = our_path.rfind('\\') {
            &our_path[..pos]
        } else {
            "."
        };

        let exe_name_lower = exe_path.file_name().unwrap_or_default().to_string_lossy().to_lowercase();
        let hook_dll = if exe_name_lower.contains("dmmgameplayer") {
            "dmmhook.dll"
        } else {
            "gatejumper.dll"
        };

        let dll_path = format!("{}\\{}\0", our_dir, hook_dll);
        let dll_bytes = dll_path.as_bytes();
        let alloc_addr = VirtualAllocEx(
            process_info.hProcess,
            ptr::null_mut(),
            dll_bytes.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if !alloc_addr.is_null() {
            WriteProcessMemory(
                process_info.hProcess,
                alloc_addr,
                dll_bytes.as_ptr() as _,
                dll_bytes.len(),
                ptr::null_mut(),
            );

            let k32 = GetModuleHandleA(b"kernel32.dll\0".as_ptr());
            let load_lib = GetProcAddress(k32, b"LoadLibraryA\0".as_ptr());

            if let Some(f) = load_lib {
                QueueUserAPC(f as usize, process_info.hThread, alloc_addr as usize);
                log("[GateJumper] APC Queued.");
            }
        }

        ResumeThread(process_info.hThread);
        log("[GateJumper] Process resumed. Injector exiting.");

        CloseHandle(process_info.hProcess);
        CloseHandle(process_info.hThread);
    }
}
