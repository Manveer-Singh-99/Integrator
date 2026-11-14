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

        let obj_path = format!("{}/virtual_display.o", out_dir);
        let vd_lib_path = format!("{}/libvirtualdisplay.a", out_dir);
        let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
        let clang_arch = match target_arch.as_str() {
            "aarch64" => "arm64",
            "x86_64" => "x86_64",
            _ => "",
        };

        let mut clang_cmd = Command::new("clang");
        clang_cmd.args(&["-fobjc-arc", "-c", "src/virtual_display.m", "-o", &obj_path]);
        if !clang_arch.is_empty() {
            clang_cmd.args(&["-arch", clang_arch]);
        }
        let clang_status = clang_cmd
            .status()
            .expect("Failed to execute clang to compile virtual_display.m");
        if !clang_status.success() {
            panic!("clang failed compiling src/virtual_display.m");
        }

        let ar_status = Command::new("ar")
            .args(&["rcs", &vd_lib_path, &obj_path])
            .status()
            .expect("Failed to execute ar for libvirtualdisplay.a");
        if !ar_status.success() {
            panic!("ar failed creating libvirtualdisplay.a");
        }

        println!("cargo:rustc-link-lib=static=virtualdisplay");
        println!("cargo:rustc-link-lib=framework=Foundation");
        println!("cargo:rustc-link-lib=framework=CoreGraphics");
        println!("cargo:rustc-link-lib=framework=AppKit");
        println!("cargo:rustc-link-lib=framework=IOKit");
        println!("cargo:rerun-if-changed=src/virtual_display.m");
    }

    tauri_build::build();
}
