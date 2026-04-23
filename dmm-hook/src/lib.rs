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
            Memory::{VirtualAllocEx, VirtualProtectEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS},
        },
        UI::Shell::SHELLEXECUTEINFOW,
    },
};

mod proxy;

const DLL_PROCESS_ATTACH: u32 = 1;

unsafe fn log(msg: &str) {
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open("dmm-hook.log") {
        let _ = writeln!(file, "[DMM-Hook] {}", msg);
    }
}

// --- Ntdll FFI ---
#[repr(C)]
struct PROCESS_BASIC_INFORMATION {
    Reserved1: *mut c_void,
    PebBaseAddress: *mut c_void,
    Reserved2: [*mut c_void; 2],
    UniqueProcessId: usize,
    Reserved3: *mut c_void,
}

extern "system" {
    fn NtQueryInformationProcess(
        ProcessHandle: windows::Win32::Foundation::HANDLE,
        ProcessInformationClass: u32,
        ProcessInformation: *mut c_void,
        ProcessInformationLength: u32,
        ReturnLength: *mut u32,
    ) -> i32;
    fn NtReadVirtualMemory(
        ProcessHandle: windows::Win32::Foundation::HANDLE,
        BaseAddress: *const c_void,
        Buffer: *mut c_void,
        NumberOfBytesToRead: usize,
        NumberOfBytesRead: *mut usize,
    ) -> i32;
}

unsafe fn get_process_image_base(h_process: windows::Win32::Foundation::HANDLE) -> Option<usize> {
    let mut pbi: PROCESS_BASIC_INFORMATION = std::mem::zeroed();
    let mut ret_len = 0;
    let status = NtQueryInformationProcess(
        h_process, 0,
        &mut pbi as *mut _ as *mut c_void,
        std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
        &mut ret_len,
    );
    if status >= 0 && !pbi.PebBaseAddress.is_null() {
        let mut image_base: usize = 0;
        let mut bytes_read = 0;
        let status = NtReadVirtualMemory(
            h_process,
            (pbi.PebBaseAddress as usize + 0x10) as *const c_void,
            &mut image_base as *mut _ as *mut c_void, 8, &mut bytes_read,
        );
        if status >= 0 { return Some(image_base); }
    }
    None
}

/// Find a remote module base address.
unsafe fn get_remote_module_base(h_process: windows::Win32::Foundation::HANDLE, module_name: &str) -> Option<usize> {
    use windows::Win32::System::ProcessStatus::{EnumProcessModulesEx, GetModuleBaseNameA, LIST_MODULES_ALL};
    use windows::Win32::Foundation::HMODULE;
    
    let mut modules = vec![HMODULE::default(); 1024];
    let mut cb_needed = 0u32;
    
    if EnumProcessModulesEx(
        h_process,
        modules.as_mut_ptr(),
        (modules.len() * std::mem::size_of::<HMODULE>()) as u32,
        &mut cb_needed,
        LIST_MODULES_ALL,
    ).is_ok() {
        let count = cb_needed as usize / std::mem::size_of::<HMODULE>();
        for i in 0..count {
            let mut name_buf = [0u8; 260];
            let len = GetModuleBaseNameA(h_process, Some(modules[i]), &mut name_buf);
            if len > 0 {
                let name = std::str::from_utf8(&name_buf[..len as usize]).unwrap_or("");
                if name.eq_ignore_ascii_case(module_name) {
                    return Some(modules[i].0 as usize);
                }
            }
        }
    }
    None
}

/// Inject payload into a suspended process via OEP hijack.
unsafe fn inject_into_suspended_process(process_info: &PROCESS_INFORMATION) -> bool {
    let image_base = match get_process_image_base(process_info.hProcess) {
        Some(base) => base,
        None => { log("Failed to get process ImageBase."); return false; }
    };
    log(&format!("ImageBase: 0x{:X}", image_base));

    let mut header_buf = vec![0u8; 4096];
    let mut bytes_read = 0;
    if NtReadVirtualMemory(process_info.hProcess, image_base as *const c_void, header_buf.as_mut_ptr() as *mut c_void, header_buf.len(), &mut bytes_read) < 0 {
        log("Failed to read PE headers."); return false;
    }

    let pe = match pelite::pe64::PeView::from_bytes(&header_buf) {
        Ok(pe) => pe, Err(_) => { log("Failed to parse PE headers."); return false; }
    };

    use pelite::pe64::Pe;
    let oep_rva = pe.nt_headers().OptionalHeader.AddressOfEntryPoint as usize;
    let oep_addr = image_base + oep_rva;
    log(&format!("OEP RVA: 0x{:X}, Absolute: 0x{:X}", oep_rva, oep_addr));

    let mut orig_bytes = [0u8; 16];
    if NtReadVirtualMemory(process_info.hProcess, oep_addr as *const c_void, orig_bytes.as_mut_ptr() as *mut c_void, 16, &mut bytes_read) < 0 {
        log("Failed to read original OEP bytes."); return false;
    }

    let orig_0_7 = u64::from_le_bytes(orig_bytes[0..8].try_into().unwrap());
    let orig_8_15 = u64::from_le_bytes(orig_bytes[8..16].try_into().unwrap());

    // Relative path; game CWD is root
    let dll_path = "gatejumper.dll\0";
    let dll_bytes = dll_path.as_bytes();

    let alloc_addr = VirtualAllocEx(process_info.hProcess, None, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if alloc_addr.is_null() { log("VirtualAllocEx failed."); return false; }

    let dll_path_addr = alloc_addr as usize + 2048;
    let mut bytes_written = 0;
    let _ = WriteProcessMemory(process_info.hProcess, dll_path_addr as *mut c_void, dll_bytes.as_ptr() as *const c_void, dll_bytes.len(), Some(&mut bytes_written));

    // Resolve remote LoadLibraryA (handling Wine ASLR).
    let local_k32 = GetModuleHandleA(PCSTR(b"kernel32.dll\0".as_ptr())).unwrap();
    let local_load_lib = GetProcAddress(local_k32, PCSTR(b"LoadLibraryA\0".as_ptr())).unwrap();
    let load_lib_offset = local_load_lib as usize - local_k32.0 as usize;
    
    let remote_k32_base = get_remote_module_base(process_info.hProcess, "kernel32.dll");
    let load_lib_addr = match remote_k32_base {
        Some(base) => {
            log(&format!("Remote kernel32 base: 0x{:X}, LoadLibraryA offset: 0x{:X}", base, load_lib_offset));
            base + load_lib_offset
        }
        None => {
            // Fallback to local address
            log("WARN: Could not find remote kernel32, using local address as fallback.");
            local_load_lib as usize
        }
    };

    let mut sc = Vec::new();
    sc.extend_from_slice(&[0x55, 0x53, 0x51, 0x52, 0x56, 0x57, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57]);
    sc.extend_from_slice(&[0x48, 0xB8]); sc.extend_from_slice(&(oep_addr as u64).to_le_bytes());
    sc.extend_from_slice(&[0x48, 0xB9]); sc.extend_from_slice(&orig_0_7.to_le_bytes());
    sc.extend_from_slice(&[0x48, 0x89, 0x08]);
    sc.extend_from_slice(&[0x48, 0xB9]); sc.extend_from_slice(&orig_8_15.to_le_bytes());
    sc.extend_from_slice(&[0x48, 0x89, 0x48, 0x08]);
    sc.extend_from_slice(&[0x48, 0x89, 0xE5]);
    sc.extend_from_slice(&[0x48, 0x83, 0xE4, 0xF0]);
    sc.extend_from_slice(&[0x48, 0x83, 0xEC, 0x20]);
    sc.extend_from_slice(&[0x48, 0xB9]); sc.extend_from_slice(&(dll_path_addr as u64).to_le_bytes());
    sc.extend_from_slice(&[0x48, 0xB8]); sc.extend_from_slice(&(load_lib_addr as u64).to_le_bytes());
    sc.extend_from_slice(&[0xFF, 0xD0]);
    sc.extend_from_slice(&[0x48, 0x89, 0xEC]);
    sc.extend_from_slice(&[0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5F, 0x5E, 0x5A, 0x59, 0x5B, 0x5D]);
    sc.extend_from_slice(&[0x48, 0xB8]); sc.extend_from_slice(&(oep_addr as u64).to_le_bytes());
    sc.extend_from_slice(&[0xFF, 0xE0]);

    let _ = WriteProcessMemory(process_info.hProcess, alloc_addr, sc.as_ptr() as *const c_void, sc.len(), Some(&mut bytes_written));
    log("Shellcode written.");

    let mut old_protect = PAGE_PROTECTION_FLAGS(0);
    let _ = VirtualProtectEx(process_info.hProcess, oep_addr as *mut c_void, 16, PAGE_EXECUTE_READWRITE, &mut old_protect);

    let mut jmp_sc = Vec::new();
    jmp_sc.extend_from_slice(&[0x48, 0xB8]); jmp_sc.extend_from_slice(&(alloc_addr as u64).to_le_bytes());
    jmp_sc.extend_from_slice(&[0xFF, 0xE0]);
    jmp_sc.extend_from_slice(&[0x90, 0x90, 0x90, 0x90, 0x90, 0x90]);

    let _ = WriteProcessMemory(process_info.hProcess, oep_addr as *mut c_void, jmp_sc.as_ptr() as *const c_void, 16, Some(&mut bytes_written));
    log("OEP Hijacked.");
    true
}

// --- Hook statics ---
static mut CREATE_PROCESS_W_ORIG: usize = 0;
type CreateProcessWFn = extern "system" fn(PCWSTR, PWSTR, *const c_void, *const c_void, BOOL, u32, *const c_void, PCWSTR, *const STARTUPINFOW, *mut PROCESS_INFORMATION) -> BOOL;

static mut CREATE_PROCESS_A_ORIG: usize = 0;
type CreateProcessAFn = extern "system" fn(PCSTR, windows::core::PSTR, *const c_void, *const c_void, BOOL, u32, *const c_void, PCSTR, *const STARTUPINFOA, *mut PROCESS_INFORMATION) -> BOOL;

static mut SHELL_EXECUTE_EX_W_ORIG: usize = 0;
type ShellExecuteExWFn = extern "system" fn(*mut SHELLEXECUTEINFOW) -> BOOL;

static mut SHELL_EXECUTE_W_ORIG: usize = 0;
static mut SHELL_EXECUTE_A_ORIG: usize = 0;

fn is_target_game(cmd_str: &str, app_str: &str) -> bool {
    let exe_path = if !app_str.is_empty() {
        app_str.to_string()
    } else {
        let mut in_quotes = false;
        let mut path_end = 0;
        for (i, c) in cmd_str.char_indices() {
            if c == '"' {
                in_quotes = !in_quotes;
            } else if c == ' ' && !in_quotes {
                path_end = i;
                break;
            }
        }
        if path_end == 0 { cmd_str.to_string() } else { cmd_str[..path_end].trim_matches('"').to_string() }
    };

    let path = std::path::Path::new(&exe_path);
    if let Some(parent) = path.parent() {
        parent.join("UnityPlayer.dll").exists() && !exe_path.to_lowercase().contains("dmmgameplayer")
    } else {
        false
    }
}

/// CreateProcessW hook: intercept target processes and inject payload.
unsafe extern "system" fn create_process_w_hook(
    lpApplicationName: PCWSTR, lpCommandLine: PWSTR, lpProcessAttributes: *const c_void, lpThreadAttributes: *const c_void, bInheritHandles: BOOL, dwCreationFlags: u32, lpEnvironment: *const c_void, lpCurrentDirectory: PCWSTR, lpStartupInfo: *const STARTUPINFOW, lpProcessInformation: *mut PROCESS_INFORMATION,
) -> BOOL {
    let orig: CreateProcessWFn = std::mem::transmute(CREATE_PROCESS_W_ORIG);
    let cmd_str = if !lpCommandLine.0.is_null() { lpCommandLine.to_string().unwrap_or_default() } else { String::new() };
    let app_str = if !lpApplicationName.0.is_null() { lpApplicationName.to_string().unwrap_or_default() } else { String::new() };

    if is_target_game(&cmd_str, &app_str) {
        log(&format!("CreateProcessW TARGET GAME: app='{}', cmd='{}'", app_str, cmd_str));
        log("Forcing CREATE_SUSPENDED for OEP injection.");

        let caller_wanted_suspended = (dwCreationFlags & 0x4) != 0;
        let new_flags = dwCreationFlags | 0x4;

        let result = orig(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, new_flags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);

        if result != 0 && !lpProcessInformation.is_null() {
            log("Process created suspended. Injecting payload...");
            let injected = inject_into_suspended_process(&*lpProcessInformation);
            
            if !caller_wanted_suspended {
                ResumeThread((*lpProcessInformation).hThread);
                if injected {
                    log("Process resumed with payload injected.");
                } else {
                    log("Injection failed, resumed anyway.");
                }
            }
        } else {
            log("CreateProcessW for target game FAILED!");
        }
        return result;
    }

    orig(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation)
}

unsafe extern "system" fn create_process_a_hook(
    lpApplicationName: PCSTR, lpCommandLine: windows::core::PSTR, lpProcessAttributes: *const c_void, lpThreadAttributes: *const c_void, bInheritHandles: BOOL, dwCreationFlags: u32, lpEnvironment: *const c_void, lpCurrentDirectory: PCSTR, lpStartupInfo: *const STARTUPINFOA, lpProcessInformation: *mut PROCESS_INFORMATION,
) -> BOOL {
    let orig: CreateProcessAFn = std::mem::transmute(CREATE_PROCESS_A_ORIG);
    orig(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation)
}

/// ShellExecuteExW hook: intercept target process launch, convert to CreateProcessW to inject payload.
unsafe extern "system" fn shell_execute_ex_w_hook(pExecInfo: *mut SHELLEXECUTEINFOW) -> BOOL {
    let orig: ShellExecuteExWFn = std::mem::transmute(SHELL_EXECUTE_EX_W_ORIG);
    if !pExecInfo.is_null() {
        let info = &*pExecInfo;
        let file_str = if !info.lpFile.0.is_null() { info.lpFile.to_string().unwrap_or_default() } else { String::new() };
        let params_str = if !info.lpParameters.0.is_null() { info.lpParameters.to_string().unwrap_or_default() } else { String::new() };
        let dir_str = if !info.lpDirectory.0.is_null() { info.lpDirectory.to_string().unwrap_or_default() } else { String::new() };
        let op_str = if !info.lpVerb.0.is_null() { info.lpVerb.to_string().unwrap_or_default() } else { String::new() };

        if is_target_game("", &file_str) {
            log(&format!("ShellExecuteExW: op='{}', file='{}', params='{}', dir='{}'", op_str, file_str, params_str, dir_str));
            log("Converting to CreateProcessW for injection.");
            
            let cmd_str = format!("\"{}\" {}", file_str, params_str);
            log(&format!("Command line: {}", cmd_str));
            let mut cmd_line_w: Vec<u16> = cmd_str.encode_utf16().chain(std::iter::once(0)).collect();

            let mut startup_info: STARTUPINFOW = std::mem::zeroed();
            startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
            let mut process_info: PROCESS_INFORMATION = std::mem::zeroed();

            let dir_w: Vec<u16>;
            let current_dir = if !info.lpDirectory.0.is_null() {
                info.lpDirectory
            } else {
                let path = std::path::Path::new(&file_str);
                if let Some(parent) = path.parent() {
                    dir_w = parent.to_string_lossy().encode_utf16().chain(std::iter::once(0)).collect();
                    PCWSTR(dir_w.as_ptr())
                } else {
                    PCWSTR(std::ptr::null())
                }
            };

            let result = create_process_w_hook(
                PCWSTR(std::ptr::null()), PWSTR(cmd_line_w.as_mut_ptr()),
                std::ptr::null(), std::ptr::null(),
                0, 0,
                std::ptr::null(), current_dir,
                &startup_info, &mut process_info,
            );

            if result != 0 {
                let info_mut = &mut *pExecInfo;
                info_mut.hProcess = std::mem::transmute(process_info.hProcess);
            }
            
            return result;
        }
    }
    orig(pExecInfo)
}

/// ShellExecuteW hook: convert to CreateProcessW to inject payload.
unsafe extern "system" fn shell_execute_w_hook(hwnd: HWND, lpOperation: PCWSTR, lpFile: PCWSTR, lpParameters: PCWSTR, lpDirectory: PCWSTR, nShowCmd: i32) -> HINSTANCE {
    let orig: extern "system" fn(HWND, PCWSTR, PCWSTR, PCWSTR, PCWSTR, i32) -> HINSTANCE = std::mem::transmute(SHELL_EXECUTE_W_ORIG);
    let file_str = if !lpFile.0.is_null() { lpFile.to_string().unwrap_or_default() } else { String::new() };
    let params_str = if !lpParameters.0.is_null() { lpParameters.to_string().unwrap_or_default() } else { String::new() };
    let dir_str = if !lpDirectory.0.is_null() { lpDirectory.to_string().unwrap_or_default() } else { String::new() };
    let op_str = if !lpOperation.0.is_null() { lpOperation.to_string().unwrap_or_default() } else { String::new() };

    if is_target_game("", &file_str) {
        log(&format!("ShellExecuteW: op='{}', file='{}', params='{}', dir='{}'", op_str, file_str, params_str, dir_str));
        log("Converting to CreateProcessW for injection.");
        
        let cmd_str = format!("\"{}\" {}", file_str, params_str);
        log(&format!("Command line: {}", cmd_str));
        let mut cmd_line_w: Vec<u16> = cmd_str.encode_utf16().chain(std::iter::once(0)).collect();

        let mut startup_info: STARTUPINFOW = std::mem::zeroed();
        startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut process_info: PROCESS_INFORMATION = std::mem::zeroed();

        let dir_w: Vec<u16>;
        let current_dir = if !lpDirectory.0.is_null() {
            lpDirectory
        } else {
            let path = std::path::Path::new(&file_str);
            if let Some(parent) = path.parent() {
                dir_w = parent.to_string_lossy().encode_utf16().chain(std::iter::once(0)).collect();
                PCWSTR(dir_w.as_ptr())
            } else {
                PCWSTR(std::ptr::null())
            }
        };

        let result = create_process_w_hook(
            PCWSTR(std::ptr::null()), PWSTR(cmd_line_w.as_mut_ptr()),
            std::ptr::null(), std::ptr::null(),
            0, 0,
            std::ptr::null(), current_dir,
            &startup_info, &mut process_info,
        );

        if result != 0 {
            return 42;
        }
        return 2;
    }
    orig(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd)
}

unsafe extern "system" fn shell_execute_a_hook(hwnd: HWND, lpOperation: PCSTR, lpFile: PCSTR, lpParameters: PCSTR, lpDirectory: PCSTR, nShowCmd: i32) -> HINSTANCE {
    let orig: extern "system" fn(HWND, PCSTR, PCSTR, PCSTR, PCSTR, i32) -> HINSTANCE = std::mem::transmute(SHELL_EXECUTE_A_ORIG);
    orig(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd)
}

fn setup_hooks() {
    unsafe {
        let k32 = LoadLibraryA(PCSTR(b"kernel32.dll\0".as_ptr()));
        if let Ok(k32_mod) = k32 {
            if let Some(func) = GetProcAddress(k32_mod, PCSTR(b"CreateProcessW\0".as_ptr())) {
                match minhook::MinHook::create_hook(func as *mut c_void, create_process_w_hook as *mut c_void) {
                    Ok(trampoline) => {
                        CREATE_PROCESS_W_ORIG = trampoline as usize;
                        let _ = minhook::MinHook::enable_hook(func as *mut c_void);
                        log("CreateProcessW hooked successfully.");
                    }
                    Err(e) => log(&format!("WARN: Failed to hook CreateProcessW: {:?}", e)),
                }
            }
            if let Some(func) = GetProcAddress(k32_mod, PCSTR(b"CreateProcessA\0".as_ptr())) {
                match minhook::MinHook::create_hook(func as *mut c_void, create_process_a_hook as *mut c_void) {
                    Ok(trampoline) => {
                        CREATE_PROCESS_A_ORIG = trampoline as usize;
                        let _ = minhook::MinHook::enable_hook(func as *mut c_void);
                        log("CreateProcessA hooked successfully.");
                    }
                    Err(e) => log(&format!("WARN: Failed to hook CreateProcessA: {:?}", e)),
                }
            }
        }
        
        let shell32 = LoadLibraryA(PCSTR(b"shell32.dll\0".as_ptr()));
        if let Ok(shell32_mod) = shell32 {
            if let Some(func) = GetProcAddress(shell32_mod, PCSTR(b"ShellExecuteExW\0".as_ptr())) {
                match minhook::MinHook::create_hook(func as *mut c_void, shell_execute_ex_w_hook as *mut c_void) {
                    Ok(trampoline) => {
                        SHELL_EXECUTE_EX_W_ORIG = trampoline as usize;
                        let _ = minhook::MinHook::enable_hook(func as *mut c_void);
                        log("ShellExecuteExW hooked successfully.");
                    }
                    Err(e) => log(&format!("WARN: Failed to hook ShellExecuteExW: {:?}", e)),
                }
            }
            if let Some(func) = GetProcAddress(shell32_mod, PCSTR(b"ShellExecuteW\0".as_ptr())) {
                match minhook::MinHook::create_hook(func as *mut c_void, shell_execute_w_hook as *mut c_void) {
                    Ok(trampoline) => {
                        SHELL_EXECUTE_W_ORIG = trampoline as usize;
                        let _ = minhook::MinHook::enable_hook(func as *mut c_void);
                        log("ShellExecuteW hooked successfully.");
                    }
                    Err(e) => log(&format!("WARN: Failed to hook ShellExecuteW: {:?}", e)),
                }
            }
            if let Some(func) = GetProcAddress(shell32_mod, PCSTR(b"ShellExecuteA\0".as_ptr())) {
                match minhook::MinHook::create_hook(func as *mut c_void, shell_execute_a_hook as *mut c_void) {
                    Ok(trampoline) => {
                        SHELL_EXECUTE_A_ORIG = trampoline as usize;
                        let _ = minhook::MinHook::enable_hook(func as *mut c_void);
                        log("ShellExecuteA hooked successfully.");
                    }
                    Err(e) => log(&format!("WARN: Failed to hook ShellExecuteA: {:?}", e)),
                }
            }
        }
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
            log("=== DMM-Hook loaded into DMM Game Player ===");
            proxy::version::init();
            setup_hooks();
        }
    }
    1
}
