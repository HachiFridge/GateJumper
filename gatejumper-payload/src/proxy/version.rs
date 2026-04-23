#![allow(non_snake_case, non_upper_case_globals)]

use std::ffi::CStr;

type HINSTANCE = isize;

extern "system" {
    fn GetSystemDirectoryW(lpBuffer: *mut u16, uSize: u32) -> u32;
    fn LoadLibraryW(lpLibFileName: *const u16) -> HINSTANCE;
    fn GetProcAddress(hModule: HINSTANCE, lpProcName: *const u8) -> Option<unsafe extern "system" fn()>;
}

proxy_proc!(GetFileVersionInfoA, GetFileVersionInfoA_orig);
proxy_proc!(GetFileVersionInfoByHandle, GetFileVersionInfoByHandle_orig);
proxy_proc!(GetFileVersionInfoExA, GetFileVersionInfoExA_orig);
proxy_proc!(GetFileVersionInfoExW, GetFileVersionInfoExW_orig);
proxy_proc!(GetFileVersionInfoSizeA, GetFileVersionInfoSizeA_orig);
proxy_proc!(GetFileVersionInfoSizeExA, GetFileVersionInfoSizeExA_orig);
proxy_proc!(GetFileVersionInfoSizeExW, GetFileVersionInfoSizeExW_orig);
proxy_proc!(GetFileVersionInfoSizeW, GetFileVersionInfoSizeW_orig);
proxy_proc!(GetFileVersionInfoW, GetFileVersionInfoW_orig);
proxy_proc!(VerFindFileA, VerFindFileA_orig);
proxy_proc!(VerFindFileW, VerFindFileW_orig);
proxy_proc!(VerInstallFileA, VerInstallFileA_orig);
proxy_proc!(VerInstallFileW, VerInstallFileW_orig);
proxy_proc!(VerLanguageNameA, VerLanguageNameA_orig);
proxy_proc!(VerLanguageNameW, VerLanguageNameW_orig);
proxy_proc!(VerQueryValueA, VerQueryValueA_orig);
proxy_proc!(VerQueryValueW, VerQueryValueW_orig);

unsafe fn get_proc(handle: HINSTANCE, name: &CStr) -> usize {
    GetProcAddress(handle, name.as_ptr() as *const u8)
        .map(|f| f as usize)
        .unwrap_or(0)
}

pub fn init() {
    unsafe {
        let mut sys_dir = [0u16; 260];
        let len = GetSystemDirectoryW(sys_dir.as_mut_ptr(), 260);
        if len == 0 { return; }

        let suffix: Vec<u16> = "\\version.dll\0".encode_utf16().collect();
        let path_len = len as usize;
        sys_dir[path_len..path_len + suffix.len()].copy_from_slice(&suffix);

        let handle = LoadLibraryW(sys_dir.as_ptr());
        if handle == 0 { return; }

        GetFileVersionInfoA_orig = get_proc(handle, c"GetFileVersionInfoA");
        GetFileVersionInfoByHandle_orig = get_proc(handle, c"GetFileVersionInfoByHandle");
        GetFileVersionInfoExA_orig = get_proc(handle, c"GetFileVersionInfoExA");
        GetFileVersionInfoExW_orig = get_proc(handle, c"GetFileVersionInfoExW");
        GetFileVersionInfoSizeA_orig = get_proc(handle, c"GetFileVersionInfoSizeA");
        GetFileVersionInfoSizeExA_orig = get_proc(handle, c"GetFileVersionInfoSizeExA");
        GetFileVersionInfoSizeExW_orig = get_proc(handle, c"GetFileVersionInfoSizeExW");
        GetFileVersionInfoSizeW_orig = get_proc(handle, c"GetFileVersionInfoSizeW");
        GetFileVersionInfoW_orig = get_proc(handle, c"GetFileVersionInfoW");
        VerFindFileA_orig = get_proc(handle, c"VerFindFileA");
        VerFindFileW_orig = get_proc(handle, c"VerFindFileW");
        VerInstallFileA_orig = get_proc(handle, c"VerInstallFileA");
        VerInstallFileW_orig = get_proc(handle, c"VerInstallFileW");
        VerLanguageNameA_orig = get_proc(handle, c"VerLanguageNameA");
        VerLanguageNameW_orig = get_proc(handle, c"VerLanguageNameW");
        VerQueryValueA_orig = get_proc(handle, c"VerQueryValueA");
        VerQueryValueW_orig = get_proc(handle, c"VerQueryValueW");
    }
}
