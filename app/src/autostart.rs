//! Cross-Platform Launch at Login Manager.
//!
//! Controls automatic login startup on macOS and Windows:
//! - macOS: Native Apple System Events Login Item (System Settings -> General -> Login Items)
//! - Windows: Standard HKCU\Software\Microsoft\Windows\CurrentVersion\Run registry key

use std::process::Command;
use anyhow::{Result, Context};

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

pub struct AutostartManager;

impl AutostartManager {
    /// Checks whether Launch at Login is currently configured for the application.
    pub fn is_enabled() -> bool {
        if cfg!(target_os = "macos") {
            let script = r#"tell application "System Events" to (exists login item "Integrator") or (exists login item "MacWindowsBridge")"#;
            if let Ok(output) = Command::new("osascript").args(&["-e", script]).output() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                return stdout.trim() == "true";
            }
            false
        } else if cfg!(target_os = "windows") {
            #[cfg(target_os = "windows")]
            {
                const CREATE_NO_WINDOW: u32 = 0x08000000;
                let mut cmd = Command::new("reg.exe");
                cmd.args(&["query", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "/v", "Integrator"]);
                cmd.creation_flags(CREATE_NO_WINDOW);
                if let Ok(out) = cmd.output() {
                    return out.status.success();
                }
            }
            false
        } else {
            false
        }
    }

    /// Sets the Launch at Login preference.
    pub fn set_enabled(enable: bool) -> Result<bool> {
        if enable {
            Self::enable()
        } else {
            Self::disable()
        }
    }

    /// Registers the application to run automatically upon user login.
    pub fn enable() -> Result<bool> {
        if cfg!(target_os = "macos") {
            let app_path = "/Applications/Integrator.app";
            let script = format!(
                r#"tell application "System Events"
                    if exists login item "MacWindowsBridge" then
                        delete login item "MacWindowsBridge"
                    end if
                    if not (exists login item "Integrator") then
                        make login item at end with properties {{path:"{}", hidden:false, name:"Integrator"}}
                    end if
                end tell"#,
                app_path
            );
            let out = Command::new("osascript")
                .args(&["-e", &script])
                .output()
                .context("Failed to execute osascript to add login item")?;

            if !out.status.success() {
                let err = String::from_utf8_lossy(&out.stderr);
                anyhow::bail!("macOS login item registration failed: {}", err.trim());
            }
            tracing::info!("🚀 Registered Integrator as macOS System Login Item");
            Ok(true)
        } else if cfg!(target_os = "windows") {
            #[cfg(target_os = "windows")]
            {
                const CREATE_NO_WINDOW: u32 = 0x08000000;
                let exe_path = std::env::current_exe()?
                    .to_string_lossy()
                    .to_string();
                let cmd_val = format!("\"{}\" --hidden", exe_path);

                let mut cmd = Command::new("reg.exe");
                cmd.args(&[
                    "add",
                    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                    "/v",
                    "Integrator",
                    "/t",
                    "REG_SZ",
                    "/d",
                    &cmd_val,
                    "/f",
                ]);
                cmd.creation_flags(CREATE_NO_WINDOW);
                let out = cmd.output().context("Failed to add Windows registry Run key")?;

                if !out.status.success() {
                    let err = String::from_utf8_lossy(&out.stderr);
                    anyhow::bail!("Windows Run key registration failed: {}", err.trim());
                }
                tracing::info!("🚀 Registered Integrator in HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run");
                Ok(true)
            }
            #[cfg(not(target_os = "windows"))]
            {
                Ok(true)
            }
        } else {
            anyhow::bail!("Unsupported OS for login item");
        }
    }

    /// Removes the application from automatic login.
    pub fn disable() -> Result<bool> {
        if cfg!(target_os = "macos") {
            let script = r#"tell application "System Events"
                if exists login item "Integrator" then
                    delete login item "Integrator"
                end if
                if exists login item "MacWindowsBridge" then
                    delete login item "MacWindowsBridge"
                end if
            end tell"#;
            let out = Command::new("osascript")
                .args(&["-e", script])
                .output()
                .context("Failed to execute osascript to delete login item")?;

            if !out.status.success() {
                let err = String::from_utf8_lossy(&out.stderr);
                anyhow::bail!("macOS login item deletion failed: {}", err.trim());
            }
            tracing::info!("🚀 Removed Integrator from macOS System Login Items");
            Ok(false)
        } else if cfg!(target_os = "windows") {
            #[cfg(target_os = "windows")]
            {
                const CREATE_NO_WINDOW: u32 = 0x08000000;
                let mut cmd = Command::new("reg.exe");
                cmd.args(&[
                    "delete",
                    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                    "/v",
                    "Integrator",
                    "/f",
                ]);
                cmd.creation_flags(CREATE_NO_WINDOW);
                let _ = cmd.output();
                tracing::info!("🚀 Removed Integrator from Windows Run registry key");
                Ok(false)
            }
            #[cfg(not(target_os = "windows"))]
            {
                Ok(false)
            }
        } else {
            anyhow::bail!("Unsupported OS for login item");
        }
    }
}
