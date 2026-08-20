//! DMM-Hook — injected into the DMM Game Player launcher to intercept game spawns.

#![windows_subsystem = "windows"]
#![allow(non_snake_case, non_upper_case_globals)]

use std::{ffi::c_void, fs::OpenOptions, io::Write};

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

static mut DLL_DIRECTORY: Option<std::path::PathBuf> = None;

unsafe fn log(msg: &str) {
    let log_path = if let Some(ref dir) = DLL_DIRECTORY {
        dir.join("gatejumper.log")
    } else {
        std::path::PathBuf::from("gatejumper.log")
    };
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(log_path) {
        let _ = writeln!(file, "[DMM-Hook] {}", msg);
    }
}

unsafe fn truncate_log() {
    let log_path = if let Some(ref dir) = DLL_DIRECTORY {
        dir.join("gatejumper.log")
    } else {
        std::path::PathBuf::from("gatejumper.log")
    };
    let _ = OpenOptions::new().create(true).write(true).truncate(true).open(log_path);
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

// Returns true if the remote PE has a .bind section — reliable packer fingerprint.
unsafe fn remote_has_bind_section(h: windows::Win32::Foundation::HANDLE) -> bool {
    let base = match get_process_image_base(h) { Some(b) => b, None => return false };
    let mut buf = vec![0u8; 4096];
    let mut read = 0usize;
    if NtReadVirtualMemory(h, base as *const c_void, buf.as_mut_ptr() as *mut c_void, buf.len(), &mut read) < 0 {
        return false;
    }
    if buf.len() < 0x40 { return false; }
    let e_lfanew = u32::from_le_bytes(buf[0x3c..0x40].try_into().unwrap_or([0;4])) as usize;
    if e_lfanew + 22 > buf.len() { return false; }
    let num_sects = u16::from_le_bytes(buf[e_lfanew+6..e_lfanew+8].try_into().unwrap_or([0;2])) as usize;
    let opt_size  = u16::from_le_bytes(buf[e_lfanew+20..e_lfanew+22].try_into().unwrap_or([0;2])) as usize;
    let sect_off  = e_lfanew + 4 + 20 + opt_size;
    for i in 0..num_sects {
        let off = sect_off + i * 40;
        if off + 8 > buf.len() { break; }
        if buf[off..off+8].starts_with(b".bind") { return true; }
    }
    false
}

// --- OEP injection ---

unsafe fn inject_into_suspended_process(pi: &PROCESS_INFORMATION) -> bool {
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

    // Resolve LoadLibraryA via local kernel32 offset — avoids remote module enumeration.
    let k32 = GetModuleHandleA(PCSTR(b"kernel32.dll\0".as_ptr())).unwrap();
    let lla = GetProcAddress(k32, PCSTR(b"LoadLibraryA\0".as_ptr())).unwrap();
    let load_lib_addr = k32.0 as usize + (lla as usize - k32.0 as usize);

    // Allocate RW, write shellcode, then promote to RX — never EXECUTE_READWRITE.
    let alloc = VirtualAllocEx(pi.hProcess, None, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if alloc.is_null() { log("VirtualAllocEx failed."); return false; }

    let dll_path = "gatejumper.dll\0";
    let dll_path_addr = alloc as usize + 2048;
    let mut written = 0usize;
    let _ = WriteProcessMemory(pi.hProcess, dll_path_addr as *mut c_void,
        dll_path.as_ptr() as *const c_void, dll_path.len(), Some(&mut written));

    let mut sc: Vec<u8> = Vec::new();
    // Save all registers.
    sc.extend_from_slice(&[0x55,0x53,0x51,0x52,0x56,0x57,
        0x41,0x50,0x41,0x51,0x41,0x52,0x41,0x53,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57]);
    // Restore original 16 bytes at OEP.
    sc.extend_from_slice(&[0x48,0xB8]); sc.extend_from_slice(&(oep_addr as u64).to_le_bytes());
    sc.extend_from_slice(&[0x48,0xB9]); sc.extend_from_slice(&orig_0_7.to_le_bytes());
    sc.extend_from_slice(&[0x48,0x89,0x08]);
    sc.extend_from_slice(&[0x48,0xB9]); sc.extend_from_slice(&orig_8_15.to_le_bytes());
    sc.extend_from_slice(&[0x48,0x89,0x48,0x08]);
    // Align stack, call LoadLibraryA(dll_path).
    sc.extend_from_slice(&[0x48,0x89,0xE5,0x48,0x83,0xE4,0xF0,0x48,0x83,0xEC,0x20]);
    sc.extend_from_slice(&[0x48,0xB9]); sc.extend_from_slice(&(dll_path_addr as u64).to_le_bytes());
    sc.extend_from_slice(&[0x48,0xB8]); sc.extend_from_slice(&(load_lib_addr as u64).to_le_bytes());
    sc.extend_from_slice(&[0xFF,0xD0]);
    // Restore stack, pop all registers.
    sc.extend_from_slice(&[0x48,0x89,0xEC]);
    sc.extend_from_slice(&[0x41,0x5F,0x41,0x5E,0x41,0x5D,0x41,0x5C,
        0x41,0x5B,0x41,0x5A,0x41,0x59,0x41,0x58,0x5F,0x5E,0x5A,0x59,0x5B,0x5D]);
    // JMP to restored OEP.
    sc.extend_from_slice(&[0x48,0xB8]); sc.extend_from_slice(&(oep_addr as u64).to_le_bytes());
    sc.extend_from_slice(&[0xFF,0xE0]);

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

    log("OEP hijacked.");
    true
}

// --- Process-launch hooks ---

static mut CREATE_PROCESS_W_ORIG:   usize = 0;
static mut CREATE_PROCESS_A_ORIG:   usize = 0;
static mut SHELL_EXECUTE_EX_W_ORIG: usize = 0;
static mut SHELL_EXECUTE_W_ORIG:    usize = 0;
static mut SHELL_EXECUTE_A_ORIG:    usize = 0;

type CreateProcessWFn  = extern "system" fn(PCWSTR, PWSTR, *const c_void, *const c_void, BOOL, u32, *const c_void, PCWSTR, *const STARTUPINFOW, *mut PROCESS_INFORMATION) -> BOOL;
type CreateProcessAFn  = extern "system" fn(PCSTR, windows::core::PSTR, *const c_void, *const c_void, BOOL, u32, *const c_void, PCSTR, *const STARTUPINFOA, *mut PROCESS_INFORMATION) -> BOOL;
type ShellExecuteExWFn = extern "system" fn(*mut SHELLEXECUTEINFOW) -> BOOL;

// Always spawn suspended so we can inspect the PE, then inject or resume cleanly.
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
        if remote_has_bind_section(pi.hProcess) {
            let app = if !lpApplicationName.0.is_null() {
                lpApplicationName.to_string().unwrap_or_default() } else { String::new() };
            log(&format!("Packer target detected ({}); injecting.", app));
            let injected = inject_into_suspended_process(pi);
            if !caller_wanted_suspended {
                ResumeThread(pi.hThread);
                log(if injected { "Resumed with payload." } else { "Injection failed; resumed." });
            }
        } else if !caller_wanted_suspended {
            ResumeThread(pi.hThread);
        }
    }
    result
}

unsafe extern "system" fn create_process_a_hook(
    lpAN: PCSTR, lpCL: windows::core::PSTR,
    lpPA: *const c_void, lpTA: *const c_void,
    bI: BOOL, dwF: u32, lpE: *const c_void,
    lpCD: PCSTR, lpSI: *const STARTUPINFOA, lpPI: *mut PROCESS_INFORMATION,
) -> BOOL {
    let orig: CreateProcessAFn = std::mem::transmute(CREATE_PROCESS_A_ORIG);
    orig(lpAN, lpCL, lpPA, lpTA, bI, dwF, lpE, lpCD, lpSI, lpPI)
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
        (*pExecInfo).hProcess = std::mem::transmute(pi.hProcess);
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
    if result != 0 { 42 } else { orig(hwnd, lpOp, lpFile, lpParams, lpDir, nShow) }
}

unsafe extern "system" fn shell_execute_a_hook(
    hwnd: HWND, lpOp: PCSTR, lpFile: PCSTR,
    lpParams: PCSTR, lpDir: PCSTR, nShow: i32,
) -> HINSTANCE {
    let orig: extern "system" fn(HWND, PCSTR, PCSTR, PCSTR, PCSTR, i32) -> HINSTANCE =
        std::mem::transmute(SHELL_EXECUTE_A_ORIG);
    orig(hwnd, lpOp, lpFile, lpParams, lpDir, nShow)
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
                    DLL_DIRECTORY = Some(std::path::PathBuf::from(&path[..pos]));
                }
            }
            truncate_log();
            log("=== DMM-Hook loaded ===");
            setup_stealth_hooks();
            setup_launch_hooks();
        }
    }
    1
}
