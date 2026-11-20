use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=assets/app.rc");
    println!("cargo:rerun-if-changed=assets/app.manifest");
    println!("cargo:rerun-if-changed=assets/netmeter.ico");
    println!("cargo:rerun-if-changed=assets/icon_64.rgba");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();

    if target_env == "gnu" {
        let obj = out_dir.join("app_res.o");
        if let Ok(status) = Command::new("windres")
            .args([
                "-i",
                "assets/app.rc",
                "-O",
                "coff",
                "-o",
                obj.to_str().unwrap(),
            ])
            .status()
        {
            if status.success() {
                // Only link into bins (Cargo passes rustc-link-arg-bins to binaries/tests)
                println!("cargo:rustc-link-arg-bins={}", obj.display());
            }
        }
    }
}
