//! # Native Build Script (`build.rs`)
//!
//! ## 1. Module Purpose & Scope
//! Compiles and links platform-native Swift, Objective-C, C11, and C++ static libraries,
//! standalone COM DLLs, and helper binaries required by `integrator_core` on macOS and Windows 11.
//!
//! ## 2. Architectural Linkages & Dependencies
//! - **Upstream Callers**: Cargo build pipeline (`cargo build`, `cargo test`, `build-universal-app.sh`).
//! - **Downstream Callees**:
//!   - **macOS**: `swiftc`, `xcrun`, `clang`, `ar` compiling `src/*.swift`, `ui-macos/IntegratorApp.swift`,
//!     `macos_clip_files.swift`, `src/audio_macos.c` (`libaudiomacos.a`), and `src/virtual_display.m`
//!     (`libvirtualdisplay.a`).
//!   - **Windows**: MSVC / `cc` crate compiling `src/kvm_windows.cpp`, `src/camera_windows.cpp`, and
//!     `src/win_capture.cpp` into `kvm_windows`, plus standalone `src/vcam_windows.cpp` into
//!     `integrator_vcam.dll` (linked against `/MT` static CRT).
//! - **Cross-Platform / Cross-Arch Flow**: Maps Cargo's `CARGO_CFG_TARGET_ARCH` (`aarch64` / `x86_64`)
//!   and `MACOSX_DEPLOYMENT_TARGET` to explicit `-target` / `-arch` flags on macOS (supporting universal
//!   cross-compilation) and uses `cc::Build` target-triple discovery on Windows (`x86_64` / `aarch64`).
//!
//! ## 3. Threading & Concurrency Model
//! Single-threaded synchronous build script executed sequentially by Cargo prior to Rust crate compilation.
//!
//! ## 4. Security & Safety Invariants
//! All build artifacts are emitted strictly under Cargo's `OUT_DIR` or copied into the active Cargo
//! `<target>/<triple?>/<profile>/` output directory (never mutating the repository root). Swift runtime
//! rpath resolution queries `xcrun --show-sdk-path` dynamically with `/usr/lib/swift` fallback.

use std::path::PathBuf;
use std::process::Command;

/// Default minimum macOS deployment target used when `MACOSX_DEPLOYMENT_TARGET` is unset.
const DEFAULT_MACOS_DEPLOYMENT_TARGET: &str = "12.0";

/// Fallback runtime dyld rpath for macOS system Swift libraries when SDK resolution is unavailable.
const FALLBACK_MACOS_SWIFT_RPATH: &str = "/usr/lib/swift";

/// Relative path to Swift libraries inside a resolved macOS SDK bundle.
const MACOS_SDK_SWIFT_LIB_REL_PATH: &str = "usr/lib/swift";

/// Resolves the macOS SDK Swift library path dynamically via `xcrun --show-sdk-path`,
/// falling back to [`FALLBACK_MACOS_SWIFT_RPATH`] if the SDK query fails.
fn resolve_macos_swift_rpath() -> String {
    if let Ok(output) = Command::new("xcrun").args(["--show-sdk-path"]).output() {
        if output.status.success() {
            let sdk_path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !sdk_path.is_empty() {
                let sdk_swift = PathBuf::from(sdk_path).join(MACOS_SDK_SWIFT_LIB_REL_PATH);
                if sdk_swift.is_dir() {
                    return sdk_swift.to_string_lossy().into_owned();
                }
            }
        }
    }
    FALLBACK_MACOS_SWIFT_RPATH.to_string()
}

/// Resolves the Cargo `<target>/<triple?>/<profile>/` directory containing `OUT_DIR`
/// regardless of whether Cargo uses `build/<pkg>/<hash>/out` or `build/<pkg>-<hash>/out`.
fn resolve_profile_dir(out_dir: &str) -> Option<PathBuf> {
    PathBuf::from(out_dir)
        .ancestors()
        .find(|p| p.file_name().and_then(|n| n.to_str()) == Some("build"))
        .and_then(|b| b.parent())
        .map(PathBuf::from)
}

/// Cargo build script entry point: compiles platform-native Swift/C/ObjC/C++ libraries and
/// standalone helpers, emitting `cargo:rustc-link-*` and `cargo:rerun-if-*` directives.
fn main() {
    for env_key in [
        "CARGO_CFG_TARGET_OS",
        "CARGO_CFG_TARGET_ARCH",
        "TARGET",
        "MACOSX_DEPLOYMENT_TARGET",
        "SDKROOT",
        "CC",
        "CFLAGS",
        "CXX",
        "CXXFLAGS",
        "PROFILE",
    ] {
        println!("cargo:rerun-if-env-changed={}", env_key);
    }

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let is_release = std::env::var("PROFILE").as_deref() == Ok("release");
    if target_os == "macos" {
        let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set by Cargo");
        let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
        let deploy_target = std::env::var("MACOSX_DEPLOYMENT_TARGET")
            .unwrap_or_else(|_| DEFAULT_MACOS_DEPLOYMENT_TARGET.to_string());

        // Map Cargo target architecture to Apple toolchain triple / clang `-arch` names so
        // cross-arch universal builds (`arm64` <-> `x86_64`) compile the right slice.
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

        // 1. Compile Swift AppKit/Foundation/AVFoundation/IOKit integration into `libtouchbar.a`.
        let lib_path = format!("{}/libtouchbar.a", out_dir);
        let mut swift_cmd = Command::new("swiftc");
        swift_cmd.args([
            "-emit-library",
            "-static",
            "src/touchbar_hud.swift",
            "src/ambient_light.swift",
            "src/kvm_macos.swift",
            "src/camera_macos.swift",
            "src/permissions_macos.swift",
            "src/ble_macos.swift",
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

        // 2. Compile standalone `macos_clip_files` helper into `OUT_DIR`, then stage a copy into
        // `target/<triple?>/<profile>/` for runtime execution and universal `.app` bundling.
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
        let clip_status = clip_cmd
            .status()
            .expect("Failed to execute swiftc to build macos_clip_files helper");
        if !clip_status.success() {
            panic!("swiftc failed to compile macos_clip_files.swift");
        }
        if let Some(profile_dir) = resolve_profile_dir(&out_dir) {
            if let Err(e) = std::fs::copy(&clip_helper_out, profile_dir.join("macos_clip_files")) {
                println!(
                    "cargo:warning=Failed to copy macos_clip_files into {}: {}",
                    profile_dir.display(),
                    e
                );
            }
        }

        // 3. Locate toolchain Swift compatibility libraries and configure dyld rpaths.
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
        let swift_rpath = resolve_macos_swift_rpath();
        println!("cargo:rustc-link-arg=-Wl,-rpath,{}", swift_rpath);
        if swift_rpath != FALLBACK_MACOS_SWIFT_RPATH {
            println!(
                "cargo:rustc-link-arg=-Wl,-rpath,{}",
                FALLBACK_MACOS_SWIFT_RPATH
            );
        }
        println!("cargo:rustc-link-search=native={}", out_dir);
        println!("cargo:rustc-link-lib=static=touchbar");
        println!("cargo:rerun-if-changed=src/touchbar_hud.swift");
        println!("cargo:rerun-if-changed=src/ambient_light.swift");
        println!("cargo:rerun-if-changed=src/kvm_macos.swift");
        println!("cargo:rerun-if-changed=src/camera_macos.swift");
        println!("cargo:rerun-if-changed=src/permissions_macos.swift");
        println!("cargo:rerun-if-changed=src/ble_macos.swift");
        println!("cargo:rerun-if-changed=ui-macos/IntegratorApp.swift");
        println!("cargo:rerun-if-changed=macos_clip_files.swift");

        // 4. Compile pure C11 CoreAudio real-time audio driver bridge (`libaudiomacos.a`).
        let audio_obj_path = format!("{}/audio_macos.o", out_dir);
        let audio_lib_path = format!("{}/libaudiomacos.a", out_dir);
        let min_ver_flag = format!("-mmacosx-version-min={}", deploy_target);

        let mut audio_clang = Command::new("clang");
        audio_clang.args([
            "-std=c11",
            if is_release { "-O2" } else { "-O1" },
            "-Wall",
            "-Wextra",
            &min_ver_flag,
            "-c",
            "src/audio_macos.c",
            "-o",
            &audio_obj_path,
        ]);
        if !clang_arch.is_empty() {
            audio_clang.args(["-arch", clang_arch]);
        }
        let audio_clang_status = audio_clang
            .status()
            .expect("Failed to execute clang to compile audio_macos.c");
        if !audio_clang_status.success() {
            panic!("clang failed compiling src/audio_macos.c");
        }
        let audio_ar_status = Command::new("ar")
            .args(["rcs", &audio_lib_path, &audio_obj_path])
            .status()
            .expect("Failed to execute ar for libaudiomacos.a");
        if !audio_ar_status.success() {
            panic!("ar failed creating libaudiomacos.a");
        }
        println!("cargo:rustc-link-lib=static=audiomacos");
        println!("cargo:rerun-if-changed=src/audio_macos.c");

        // 5. Compile Objective-C ARC virtual display driver bridge (`libvirtualdisplay.a`).
        let obj_path = format!("{}/virtual_display.o", out_dir);
        let vd_lib_path = format!("{}/libvirtualdisplay.a", out_dir);

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
        println!("cargo:rustc-link-lib=framework=ApplicationServices");
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
        println!("cargo:rustc-link-lib=framework=CoreBluetooth");
        println!("cargo:rustc-link-lib=framework=AudioToolbox");
        println!("cargo:rustc-link-lib=framework=CoreAudio");
        println!("cargo:rerun-if-changed=src/virtual_display.m");
    } else if target_os == "windows" {
        let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set by Cargo");

        // 1. Compile Win32 C++ static library (`kvm_windows`) containing KVM hooks, camera helper,
        // and DXGI/MediaFoundation screen capture backends.
        cc::Build::new()
            .cpp(true)
            .flag_if_supported("/EHsc")
            .file("src/kvm_windows.cpp")
            .file("src/camera_windows.cpp")
            .file("src/win_capture.cpp")
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
        println!("cargo:rerun-if-changed=src/win_capture.cpp");
        println!("cargo:rerun-if-changed=src/vcam_windows.cpp");

        // 2. Compile standalone FrameServer COM DLL (`integrator_vcam.dll`) with `/MT` static CRT
        // via `cc::Build` so target-arch (`x86_64` vs `aarch64`) MSVC toolchains are selected automatically.
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
        if let Some(profile_dir) = resolve_profile_dir(&out_dir) {
            if let Err(e) = std::fs::copy(&vcam_dll_out, profile_dir.join("integrator_vcam.dll")) {
                println!(
                    "cargo:warning=Failed to copy integrator_vcam.dll into {}: {}",
                    profile_dir.display(),
                    e
                );
            }
        }
    }
}
