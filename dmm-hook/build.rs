fn main() {
    let host_os = std::env::consts::OS;
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();

    if target_os.is_empty() {
        println!("cargo:warning=No target was configured; allowing host build for local validation. Use cargo xbuild/cargo xcheck for the Windows/MSVC target.");
        return;
    }

    let correct_target = target_os == "windows" && target_env == "msvc" && target_arch == "x86_64";
    if !correct_target {
        let host_prefix = match host_os {
            "windows" => "Windows host",
            "linux" => "Linux host",
            "macos" => "macOS host",
            _ => "Current host",
        };

        panic!(
            "\n\n\x1b[31;1mGateJumper requires target 'x86_64-pc-windows-msvc'.\x1b[0m\n\
             Target detected: os={target_os}, env={target_env}, arch={target_arch}\n\
             Host detected: {host_prefix}\n\
             \n\
             Usage:\n\
             - Windows: cargo build --target x86_64-pc-windows-msvc\n\
             - Linux/macOS: cargo xbuild or cargo xcheck (via xwin)\n\
             - Alias: cargo xbuild / cargo xcheck\n\n"
        );
    }
}
