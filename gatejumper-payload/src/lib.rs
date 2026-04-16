//! GateJumper Payload
//!
//! Forcefully hijacks the entry point of the target executable to launch 
//! UnityPlayer.dll directly, circumventing the anti-cheat packer entirely.

#![windows_subsystem = "windows"]
#![allow(non_snake_case, non_upper_case_globals)]

use std::ffi::c_void;

type BOOL = i32;
type HINSTANCE = isize;
type DWORD = u32;

extern "system" {
    fn GetModuleHandleA(lpModuleName: *const u8) -> HINSTANCE;
    fn GetProcAddress(hModule: HINSTANCE, lpProcName: *const u8) -> Option<unsafe extern "system" fn()>;
    fn LoadLibraryW(lpLibFileName: *const u16) -> HINSTANCE;
    fn VirtualProtect(lpAddress: *mut c_void, dwSize: usize, flNewProtect: u32, lpflOldProtect: *mut u32) -> BOOL;
    fn GetCommandLineW() -> *const u16;
    fn OutputDebugStringA(lpOutputString: *const u8);
}

const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const DLL_PROCESS_ATTACH: u32 = 1;

unsafe fn log(msg: &str) {
    let mut buf = String::from(msg);
    buf.push('\0');
    OutputDebugStringA(buf.as_ptr());
}

fn get_game_entry_point() -> *mut u8 {
    unsafe {
        let base = GetModuleHandleA(std::ptr::null());
        if base == 0 { return std::ptr::null_mut(); }

        let dos_header = base as *const u8;
        let e_lfanew = *(dos_header.add(0x3C) as *const u32);
        let nt_headers = dos_header.add(e_lfanew as usize);
        let addr_of_ep = *(nt_headers.add(40) as *const u32); // PE32+ AddressOfEntryPoint
        
        dos_header.add(addr_of_ep as usize) as *mut u8
    }
}

pub extern "system" fn launch_unity() -> i32 {
    unsafe {
        log("[GateJumper] OEP Hijack triggered. Initialising Unity Engine...");

        let unity_path: Vec<u16> = "UnityPlayer.dll\0".encode_utf16().collect();
        let h_unity = LoadLibraryW(unity_path.as_ptr());
        if h_unity == 0 {
            log("[GateJumper] FATAL: UnityPlayer.dll not found.");
            return 1;
        }

        let unity_main_ptr = GetProcAddress(h_unity, b"UnityMain\0".as_ptr());
        if let Some(unity_main_fn) = unity_main_ptr {
            let unity_main: extern "system" fn(HINSTANCE, *mut c_void, *const u16, i32) -> i32 = 
                std::mem::transmute(unity_main_fn);
            
            log("[GateJumper] Handing over execution to UnityMain...");
            return unity_main(GetModuleHandleA(std::ptr::null()), std::ptr::null_mut(), GetCommandLineW(), 10);
        }

        log("[GateJumper] FATAL: UnityMain export not found.");
        1
    }
}

#[no_mangle]
pub extern "system" fn DllMain(
    _module: HINSTANCE,
    reason: u32,
    _reserved: *mut c_void,
) -> BOOL {
    if reason == DLL_PROCESS_ATTACH {
        unsafe {
            log("[GateJumper] Injected. Preparing OEP Hijack...");
            
            let ep = get_game_entry_point();
            if ep.is_null() {
                log("[GateJumper] FATAL: Entry point not found.");
                return 0;
            }

            let mut old_protect = 0;
            if VirtualProtect(ep as _, 14, PAGE_EXECUTE_READWRITE, &mut old_protect) != 0 {
                let target = launch_unity as usize;
                
                // 64-bit absolute jump:
                // jmp [rip+0] / ff 25 00 00 00 00
                // 00 00 00 00 00 00 00 00 (target address)
                *ep.add(0) = 0xFF;
                *ep.add(1) = 0x25;
                *ep.add(2) = 0x00;
                *ep.add(3) = 0x00;
                *ep.add(4) = 0x00;
                *ep.add(5) = 0x00;
                
                let target_bytes: [u8; 8] = std::mem::transmute(target);
                std::ptr::copy_nonoverlapping(target_bytes.as_ptr(), ep.add(6), 8);

                log(&format!("[GateJumper] OEP patched at {:?}. Bypass ready.", ep));
            }
        }
    }
    1
}
