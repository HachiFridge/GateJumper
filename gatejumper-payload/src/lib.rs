//! GateJumper Payload
//!
//! Exposes a DllMain that strips memory locks directly from the
//! entry point of the protected game executable and forcefully hijacks
//! the thread to start the unmodified Unity Engine automatically, 
//! circumventing the CrackProof routine entirely.
#![windows_subsystem = "windows"]
#![allow(non_snake_case, unused_variables)]

use std::ffi::{c_void, CString, OsStr};
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use std::mem;

type HANDLE = isize;
type HINSTANCE = HANDLE;
type DWORD = u32;
type BOOL = i32;
type LPVOID = *mut c_void;
type LPCSTR = *const u8;
type LPCWSTR = *const u16;

const DLL_PROCESS_ATTACH: DWORD = 1;

extern "system" {
    fn DisableThreadLibraryCalls(hLibModule: HINSTANCE) -> BOOL;
    fn GetModuleHandleA(lpModuleName: LPCSTR) -> HINSTANCE;
    fn GetProcAddress(hModule: HINSTANCE, lpProcName: LPCSTR) -> *mut c_void;
    fn GetCommandLineA() -> LPCSTR;
    fn GetCommandLineW() -> LPCWSTR;
    fn LoadLibraryW(lpLibFileName: LPCWSTR) -> HINSTANCE;
    fn VirtualProtect(lpAddress: LPVOID, dwSize: usize, flNewProtect: DWORD, lpflOldProtect: *mut DWORD) -> BOOL;
    fn OutputDebugStringA(lpOutputString: LPCSTR);
}

const PAGE_EXECUTE_READWRITE: DWORD = 0x40;

unsafe fn debug_log(msg: &str) {
    let mut buf = msg.as_bytes().to_vec();
    buf.push(0);
    OutputDebugStringA(buf.as_ptr());
}

fn get_game_entry_point() -> *mut u8 {
    unsafe {
        let base = GetModuleHandleA(ptr::null());
        if base == 0 {
            return ptr::null_mut();
        }

        let dos_header = base as *const u8;
        // e_lfanew is at offset 0x3C
        let e_lfanew = *(dos_header.add(0x3C) as *const u32);
        
        let nt_headers = dos_header.add(e_lfanew as usize);
        // AddressOfEntryPoint is at offset 0x28 in OptionalHeader for PE32+ (64-bit)
        // Signature (4) + FileHeader (20) + Offset to AddressOfEntryPoint (16) = 40
        let addr_of_ep = *(nt_headers.add(40) as *const u32);
        
        dos_header.add(addr_of_ep as usize) as *mut u8
    }
}

pub extern "system" fn run_unity_main() -> i32 {
    unsafe {
        debug_log("[GateJumper] Hooked Entry Point triggered! Starting Unity...");

        let unity_path: Vec<u16> = OsStr::new("UnityPlayer.dll").encode_wide().chain(std::iter::once(0)).collect();
        let h_unity = LoadLibraryW(unity_path.as_ptr());
        if h_unity == 0 {
            debug_log("[GateJumper] FATAL: Could not load UnityPlayer.dll");
            return 1;
        }

        debug_log("[GateJumper] UnityPlayer.dll loaded.");

        let main_name = CString::new("UnityMain").unwrap();
        let unity_main_ptr = GetProcAddress(h_unity, main_name.as_ptr() as LPCSTR);
        if unity_main_ptr.is_null() {
            debug_log("[GateJumper] FATAL: Could not find UnityMain");
            return 1;
        }

        debug_log("[GateJumper] Found UnityMain. Passing execution to game engine...");

        let unity_main: extern "system" fn(HINSTANCE, *mut c_void, LPCWSTR, i32) -> i32 = mem::transmute(unity_main_ptr);
        
        let h_instance = GetModuleHandleA(ptr::null());
        let cmd_line = GetCommandLineW();
        
        unity_main(h_instance, ptr::null_mut(), cmd_line, 10)
    }
}

#[no_mangle]
pub extern "system" fn DllMain(
    dll_module: HINSTANCE,
    call_reason: DWORD,
    _reserved: LPVOID,
) -> BOOL {
    if call_reason == DLL_PROCESS_ATTACH {
        unsafe {
            DisableThreadLibraryCalls(dll_module);
            debug_log("[GateJumper] DLL injected successfully. Preparing bypass...");

            let ep = get_game_entry_point();
            if ep.is_null() {
                debug_log("[GateJumper] FATAL: Could not get executable entry point.");
                return 0; // abort loading
            }

            debug_log(&format!("[GateJumper] Game Entry Point found at {:?}", ep));

            let mut old_protect = 0;
            if VirtualProtect(ep as LPVOID, 14, PAGE_EXECUTE_READWRITE, &mut old_protect) != 0 {
                // Write absolute jump to run_unity_main
                // jmp [rip+0]
                // address (8 bytes)
                let target = run_unity_main as usize;
                
                *ep.add(0) = 0xFF; // JMP
                *ep.add(1) = 0x25; // MODRM (RIP-relative)
                *ep.add(2) = 0x00; // Offset 0
                *ep.add(3) = 0x00;
                *ep.add(4) = 0x00;
                *ep.add(5) = 0x00;
                
                let target_bytes: [u8; 8] = mem::transmute(target);
                ep.add(6).copy_from_nonoverlapping(target_bytes.as_ptr(), 8);

                VirtualProtect(ep as LPVOID, 14, old_protect, &mut old_protect);
                debug_log("[GateJumper] Successfully patched Entry Point with JMP out of CrackProof!");
            } else {
                debug_log("[GateJumper] FATAL: VirtualProtect on Entry Point failed.");
                return 0;
            }
        }
    }
    1 // TRUE
}
