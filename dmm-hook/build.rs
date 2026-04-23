fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os == "windows" {
        let def_path = std::fs::canonicalize("src/proxy/exports.def").unwrap();
        if std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default() == "msvc" {
            println!("cargo:rustc-cdylib-link-arg=/DEF:{}", def_path.display());
        } else {
            println!("cargo:rustc-cdylib-link-arg={}", def_path.display());
        }
    }
}
