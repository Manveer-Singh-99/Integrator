use std::process::Command;

fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os == "macos" {
        let out_dir = std::env::var("OUT_DIR").unwrap();
        let lib_path = format!("{}/libtouchbar.a", out_dir);

        let status = Command::new("swiftc")
            .args(&[
                "-emit-library",
                "-static",
                "src/touchbar_hud.swift",
                "-o",
                &lib_path,
            ])
            .status()
            .expect("Failed to execute swiftc to build touchbar static library");

        if !status.success() {
            panic!("swiftc failed to compile touchbar_hud.swift into static library");
        }

        println!("cargo:rustc-link-search=native={}", out_dir);
        println!("cargo:rustc-link-lib=static=touchbar");
        println!("cargo:rerun-if-changed=src/touchbar_hud.swift");
    }

    tauri_build::build();
}
