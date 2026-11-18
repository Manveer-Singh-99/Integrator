use std::path::PathBuf;
use std::process::Command;

fn main() {
    for env_key in [
        "CARGO_CFG_TARGET_OS",
        "CARGO_CFG_TARGET_ARCH",
        "MACOSX_DEPLOYMENT_TARGET",
        "SDKROOT",
        "CC",
        "CFLAGS",
        "PROFILE",
    ] {
        println!("cargo:rerun-if-env-changed={}", env_key);
    }

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let is_release = std::env::var("PROFILE").as_deref() == Ok("release");
    if target_os == "macos" {
        let out_dir = std::env::var("OUT_DIR").unwrap();
        let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
        let deploy_target =
            std::env::var("MACOSX_DEPLOYMENT_TARGET").unwrap_or_else(|_| "12.0".to_string());

        let (swift_arch, clang_arch) = match target_arch.as_str() {
            "aarch64" => ("arm64", "arm64"),
            "x86_64" => ("x86_64", "x86_64"),
            _ => ("", ""),
        };
        let swift_target = if !swift_arch.is_empty() {
            Some(format!("{}-apple-macosx{}", swift_arch, deploy_target))
        } else {
            None
        };

        let lib_path = format!("{}/libtouchbar.a", out_dir);
        let mut swift_cmd = Command::new("swiftc");
        swift_cmd.args([
            "-emit-library",
            "-static",
            "src/touchbar_hud.swift",
            "src/ambient_light.swift",
            "src/kvm_macos.swift",
            "src/camera_macos.swift",
            "ui-macos/IntegratorApp.swift",
            "-o",
            &lib_path,
        ]);
        if is_release {
            swift_cmd.arg("-O");
        }
        if let Some(ref target) = swift_target {
            swift_cmd.args(["-target", target]);
        }

        let status = swift_cmd
            .status()
            .expect("Failed to execute swiftc to build touchbar static library");
        if !status.success() {
            panic!("swiftc failed to compile swift sources into static library");
        }

        // Also compile macos_clip_files.swift into target/<profile>/macos_clip_files (not repo root)
        let clip_helper_out = PathBuf::from(&out_dir).join("macos_clip_files");
        let mut clip_cmd = Command::new("swiftc");
        if is_release {
            clip_cmd.arg("-O");
        }
        clip_cmd.args([
            "macos_clip_files.swift",
            "-o",
            &clip_helper_out.to_string_lossy(),
        ]);
        if let Some(ref target) = swift_target {
            clip_cmd.args(["-target", target]);
        }
        if let Ok(s) = clip_cmd.status() {
            if s.success() {
                // Copy helper binary into <target>/<profile>/ regardless of Cargo's build/<pkg>/<hash>/out vs build/<pkg>-<hash>/out layout
                if let Some(profile_dir) = PathBuf::from(&out_dir)
                    .ancestors()
                    .find(|p| p.file_name().and_then(|n| n.to_str()) == Some("build"))
                    .and_then(|b| b.parent())
                {
                    let _ = std::fs::copy(&clip_helper_out, profile_dir.join("macos_clip_files"));
                }
            }
        }

        if let Ok(output) = Command::new("xcrun").args(["--find", "swiftc"]).output() {
            if output.status.success() {
                let swiftc_path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if let Some(bin_dir) = std::path::Path::new(&swiftc_path).parent() {
                    if let Some(usr_dir) = bin_dir.parent() {
                        let swift_lib = usr_dir.join("lib").join("swift").join("macosx");
                        if swift_lib.is_dir() {
                            println!("cargo:rustc-link-search=native={}", swift_lib.display());
                        }
                    }
                }
            }
        }
        println!("cargo:rustc-link-arg=-Wl,-rpath,/usr/lib/swift");
        println!("cargo:rustc-link-search=native={}", out_dir);
        println!("cargo:rustc-link-lib=static=touchbar");
        println!("cargo:rerun-if-changed=src/touchbar_hud.swift");
        println!("cargo:rerun-if-changed=src/ambient_light.swift");
        println!("cargo:rerun-if-changed=src/kvm_macos.swift");
        println!("cargo:rerun-if-changed=src/camera_macos.swift");
        println!("cargo:rerun-if-changed=ui-macos/IntegratorApp.swift");
        println!("cargo:rerun-if-changed=macos_clip_files.swift");

        let obj_path = format!("{}/virtual_display.o", out_dir);
        let vd_lib_path = format!("{}/libvirtualdisplay.a", out_dir);
        let min_ver_flag = format!("-mmacosx-version-min={}", deploy_target);

        let mut clang_cmd = Command::new("clang");
        clang_cmd.args([
            "-fobjc-arc",
            &min_ver_flag,
            "-c",
            "src/virtual_display.m",
            "-o",
            &obj_path,
        ]);
        if !clang_arch.is_empty() {
            clang_cmd.args(["-arch", clang_arch]);
        }
        let clang_status = clang_cmd
            .status()
            .expect("Failed to execute clang to compile virtual_display.m");
        if !clang_status.success() {
            panic!("clang failed compiling src/virtual_display.m");
        }

        let ar_status = Command::new("ar")
            .args(["rcs", &vd_lib_path, &obj_path])
            .status()
            .expect("Failed to execute ar for libvirtualdisplay.a");
        if !ar_status.success() {
            panic!("ar failed creating libvirtualdisplay.a");
        }

        println!("cargo:rustc-link-lib=static=virtualdisplay");
        println!("cargo:rustc-link-lib=framework=Foundation");
        println!("cargo:rustc-link-lib=framework=CoreFoundation");
        println!("cargo:rustc-link-lib=framework=Security");
        println!("cargo:rustc-link-lib=framework=CoreGraphics");
        println!("cargo:rustc-link-lib=framework=AppKit");
        println!("cargo:rustc-link-lib=framework=SwiftUI");
        println!("cargo:rustc-link-lib=framework=IOKit");
        println!("cargo:rustc-link-lib=framework=AVFoundation");
        println!("cargo:rustc-link-lib=framework=CoreMedia");
        println!("cargo:rustc-link-lib=framework=CoreVideo");
        println!("cargo:rerun-if-changed=src/virtual_display.m");
    }

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let out_dir = std::env::var("OUT_DIR").unwrap();
        cc::Build::new()
            .cpp(true)
            .file("src/kvm_windows.cpp")
            .file("src/camera_windows.cpp")
            .compile("kvm_windows");
        println!("cargo:rustc-link-lib=ole32");
        println!("cargo:rustc-link-lib=shell32");
        println!("cargo:rustc-link-lib=user32");
        println!("cargo:rustc-link-lib=gdi32");
        println!("cargo:rustc-link-lib=shlwapi");
        println!("cargo:rustc-link-lib=advapi32");
        println!("cargo:rustc-link-lib=mfplat");
        println!("cargo:rustc-link-lib=mfuuid");
        println!("cargo:rerun-if-changed=src/kvm_windows.cpp");
        println!("cargo:rerun-if-changed=src/camera_windows.cpp");
        println!("cargo:rerun-if-changed=src/vcam_windows.cpp");

        // Compile standalone FrameServer COM DLL (`integrator_vcam.dll`) with zero external runtime deps (/MT).
        let vcam_dll_out = PathBuf::from(&out_dir).join("integrator_vcam.dll");
        let vcam_obj_out = PathBuf::from(&out_dir).join("vcam_windows.obj");
        let vcam_lib_out = PathBuf::from(&out_dir).join("integrator_vcam.lib");
        let vcam_exp_out = PathBuf::from(&out_dir).join("integrator_vcam.exp");
        let compiler = cc::Build::new().cpp(true).static_crt(true).get_compiler();
        let mut vcam_cmd = compiler.to_command();
        vcam_cmd.args([
            "/nologo",
            "/O2",
            "/EHsc",
            "/DUNICODE",
            "/D_UNICODE",
            &format!("/Fo{}", vcam_obj_out.display()),
            "src/vcam_windows.cpp",
            "/LD",
            &format!("/Fe{}", vcam_dll_out.display()),
            "/link",
            &format!("/IMPLIB:{}", vcam_lib_out.display()),
            "mfplat.lib",
            "mfuuid.lib",
            "mf.lib",
            "mfsensorgroup.lib",
            "propsys.lib",
            "ole32.lib",
            "advapi32.lib",
            "/EXPORT:DllGetClassObject,PRIVATE",
            "/EXPORT:DllCanUnloadNow,PRIVATE",
        ]);
        let vcam_status = vcam_cmd
            .status()
            .expect("Failed to invoke MSVC compiler for integrator_vcam.dll");
        let _ = std::fs::remove_file(&vcam_lib_out);
        let _ = std::fs::remove_file(&vcam_exp_out);
        if !vcam_status.success() {
            panic!("MSVC failed compiling src/vcam_windows.cpp into integrator_vcam.dll");
        }
        if let Some(profile_dir) = PathBuf::from(&out_dir)
            .ancestors()
            .find(|p| p.file_name().and_then(|n| n.to_str()) == Some("build"))
            .and_then(|b| b.parent())
        {
            let _ = std::fs::copy(&vcam_dll_out, profile_dir.join("integrator_vcam.dll"));
        }
    }
}
