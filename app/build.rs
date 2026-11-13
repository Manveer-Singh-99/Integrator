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
                "src/ambient_light.swift",
                "-o",
                &lib_path,
            ])
            .status()
            .expect("Failed to execute swiftc to build touchbar static library");

        if !status.success() {
            panic!("swiftc failed to compile swift sources into static library");
        }

        println!("cargo:rustc-link-search=native={}", out_dir);
        println!("cargo:rustc-link-lib=static=touchbar");
        println!("cargo:rerun-if-changed=src/touchbar_hud.swift");
        println!("cargo:rerun-if-changed=src/ambient_light.swift");
    }

    tauri_build::build();
}
