fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();

    if target_os != "windows" || target_env != "msvc" || target_arch != "x86_64" {
        let host_is_windows = cfg!(target_os = "windows");
        if host_is_windows {
            panic!(
                "\n\n\x1b[31;1mError: GateJumper only supports target 'x86_64-pc-windows-msvc'.\x1b[0m\n\
                 Please configure your cargo target to 'x86_64-pc-windows-msvc'.\n\n"
            );
        } else {
            panic!(
                "\n\n\x1b[31;1mError: GateJumper only supports target 'x86_64-pc-windows-msvc'.\x1b[0m\n\
                 Since you are on a non-Windows host, please use xwin to build or check this project.\n\
                 Example: \x1b[32mcargo xbuild\x1b[0m or \x1b[32mcargo xcheck\x1b[0m\n\n"
            );
        }
    }
}
