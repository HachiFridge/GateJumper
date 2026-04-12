//! GateJumper Injector
//!
//! Launches the target crackproof-enabled executable in a SUSPENDED state, injects
//! the GateJumper gatejumper.dll (which hard-hijacks the entry point and executes UnityMain),
//! then resumes the process. This ensures our hooks are in place BEFORE CrackProof's
//! unpacker code runs, preventing the anti-cheat from terminating the game natively.
//!
//! Configure the `REAL_GAME_EXE` variable below to match your target game.

#![windows_subsystem = "windows"]
#![allow(non_snake_case, unused_variables)]

use std::ffi::c_void;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr;

type HANDLE = isize;
type BOOL = i32;
type DWORD = u32;

#[repr(C)]
struct STARTUPINFOW {
    cb: u32,
    lpReserved: *mut u16,
    lpDesktop: *mut u16,
    lpTitle: *mut u16,
    dwX: u32,
    dwY: u32,
    dwXSize: u32,
    dwYSize: u32,
    dwXCountChars: u32,
    dwYCountChars: u32,
    dwFillAttribute: u32,
    dwFlags: u32,
    wShowWindow: u16,
    cbReserved2: u16,
    lpReserved2: *mut u8,
    hStdInput: HANDLE,
    hStdOutput: HANDLE,
    hStdError: HANDLE,
}

#[repr(C)]
struct PROCESS_INFORMATION {
    hProcess: HANDLE,
    hThread: HANDLE,
    dwProcessId: u32,
    dwThreadId: u32,
}

extern "system" {
    fn CreateProcessW(
        lpApplicationName: *const u16,
        lpCommandLine: *mut u16,
        lpProcessAttributes: *const c_void,
        lpThreadAttributes: *const c_void,
        bInheritHandles: BOOL,
        dwCreationFlags: DWORD,
        lpEnvironment: *const c_void,
        lpCurrentDirectory: *const u16,
        lpStartupInfo: *const STARTUPINFOW,
        lpProcessInformation: *mut PROCESS_INFORMATION,
    ) -> BOOL;

    fn VirtualAllocEx(
        hProcess: HANDLE,
        lpAddress: *const c_void,
        dwSize: usize,
        flAllocationType: DWORD,
        flProtect: DWORD,
    ) -> *mut c_void;

    fn WriteProcessMemory(
        hProcess: HANDLE,
        lpBaseAddress: *mut c_void,
        lpBuffer: *const c_void,
        nSize: usize,
        lpNumberOfBytesWritten: *mut usize,
    ) -> BOOL;

    fn GetModuleHandleA(lpModuleName: *const u8) -> HANDLE;
    fn GetProcAddress(hModule: HANDLE, lpProcName: *const u8) -> *mut c_void;

    fn CreateRemoteThread(
        hProcess: HANDLE,
        lpThreadAttributes: *mut c_void,
        dwStackSize: usize,
        lpStartAddress: *const c_void,
        lpParameter: *mut c_void,
        dwCreationFlags: DWORD,
        lpThreadId: *mut DWORD,
    ) -> HANDLE;

    fn QueueUserAPC(
        pfnAPC: *mut c_void,
        hThread: HANDLE,
        dwData: usize,
    ) -> DWORD;


    fn WaitForSingleObject(hHandle: HANDLE, dwMilliseconds: DWORD) -> DWORD;
    fn ResumeThread(hThread: HANDLE) -> DWORD;
    fn CloseHandle(hObject: HANDLE) -> BOOL;
    fn GetModuleFileNameW(hModule: HANDLE, lpFilename: *mut u16, nSize: DWORD) -> DWORD;
    fn GetLastError() -> DWORD;
    fn OutputDebugStringA(lpOutputString: *const u8);
}

const CREATE_SUSPENDED: DWORD = 0x00000004;
const MEM_COMMIT: DWORD = 0x00001000;
const MEM_RESERVE: DWORD = 0x00002000;
const PAGE_READWRITE: DWORD = 0x04;

/// The original game exe, renamed so our injector can take its filename
const REAL_GAME_EXE: &str = "<INSERT_GAME_EXECUTABLE_HERE.exe>";
/// Our hook DLL
const HOOK_DLL: &str = "gatejumper.dll";

unsafe fn debug_log(msg: &str) {
    let mut buf = msg.as_bytes().to_vec();
    buf.push(0);
    OutputDebugStringA(buf.as_ptr());
}

fn main() {
    unsafe {
        debug_log("[GateJumper Injector] Starting...");

        // Get our own directory
        let mut path_buf = [0u16; 512];
        let len = GetModuleFileNameW(0, path_buf.as_mut_ptr(), 512);
        let our_path = String::from_utf16_lossy(&path_buf[..len as usize]);
        let our_dir = if let Some(pos) = our_path.rfind('\\') {
            &our_path[..pos]
        } else {
            "."
        };

        let args: Vec<String> = std::env::args().collect();
        let game_exe_path = if args.len() > 1 {
            args[1].clone()
        } else {
            format!("{}\\{}", our_dir, REAL_GAME_EXE)
        };
        let hook_dll_path = format!("{}\\{}", our_dir, HOOK_DLL);

        if !std::path::Path::new(&hook_dll_path).exists() {
            debug_log(&format!("[GateJumper Injector] FATAL: Could not find {} in the current directory.", HOOK_DLL));
            return;
        }

        debug_log(&format!("[GateJumper Injector] Target exe: {}", game_exe_path));
        debug_log(&format!("[GateJumper Injector] Hook DLL: {}", hook_dll_path));

        // Create the real game process in SUSPENDED state
        let exe_path_w: Vec<u16> = OsStr::new(&game_exe_path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut startup_info: STARTUPINFOW = std::mem::zeroed();
        startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as u32;

        let mut process_info: PROCESS_INFORMATION = std::mem::zeroed();

        let success = CreateProcessW(
            exe_path_w.as_ptr(),
            ptr::null_mut(),
            ptr::null(),
            ptr::null(),
            0,
            CREATE_SUSPENDED,
            ptr::null(),
            ptr::null(), // inherit current directory
            &startup_info,
            &mut process_info,
        );

        if success == 0 {
            let err = GetLastError();
            debug_log(&format!(
                "[GateJumper Injector] FATAL: CreateProcessW failed, error={}",
                err
            ));
            return;
        }

        // Allocate memory in the target process for our DLL path string
        let mut dll_path_bytes: Vec<u8> = hook_dll_path.as_bytes().to_vec();
        dll_path_bytes.push(0);

        let alloc_addr = VirtualAllocEx(
            process_info.hProcess,
            ptr::null(),
            dll_path_bytes.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if alloc_addr.is_null() {
            debug_log("[GateJumper Injector] FATAL: VirtualAllocEx failed");
            ResumeThread(process_info.hThread);
            CloseHandle(process_info.hProcess);
            CloseHandle(process_info.hThread);
            return;
        }

        let mut bytes_written = 0;
        WriteProcessMemory(
            process_info.hProcess,
            alloc_addr,
            dll_path_bytes.as_ptr() as *const c_void,
            dll_path_bytes.len(),
            &mut bytes_written,
        );

        debug_log(&format!(
            "[GateJumper Injector] Wrote {} bytes of DLL path to remote process",
            bytes_written
        ));

        // Get LoadLibraryA address from kernel32
        let kernel32 = GetModuleHandleA(b"kernel32.dll\0".as_ptr());
        let load_library_addr = GetProcAddress(kernel32, b"LoadLibraryA\0".as_ptr());

        if load_library_addr.is_null() {
            debug_log("[GateJumper Injector] FATAL: Could not find LoadLibraryA");
            ResumeThread(process_info.hThread);
            CloseHandle(process_info.hProcess);
            CloseHandle(process_info.hThread);
            return;
        }

        // Queue an APC on the main thread to call LoadLibraryA with the DLL path.
        let queue_res = QueueUserAPC(
            load_library_addr as *mut c_void,
            process_info.hThread,
            alloc_addr as usize,
        );

        if queue_res == 0 {
            debug_log("[GateJumper Injector] FATAL: QueueUserAPC failed");
            ResumeThread(process_info.hThread);
            CloseHandle(process_info.hProcess);
            CloseHandle(process_info.hThread);
            return;
        }

        debug_log("[GateJumper Injector] APC queued. Resuming main thread...");
        
        ResumeThread(process_info.hThread);
        debug_log("[GateJumper Injector] Game process resumed. Exiting injector.");

        CloseHandle(process_info.hProcess);
        CloseHandle(process_info.hThread);
    }
}
