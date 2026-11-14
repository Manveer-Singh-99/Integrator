use crate::system_info;
use anyhow::Result;
use std::path::PathBuf;
use std::process::Command;

#[cfg(target_os = "macos")]
const LAUNCH_AGENT_LABEL: &str = "com.manveersingh.integrator";

pub struct AutostartManager;

impl AutostartManager {
    pub fn is_enabled() -> bool {
        #[cfg(target_os = "macos")]
        {
            let plist_exists = mac_launch_agent_plist().is_file();
            if plist_exists {
                return true;
            }
            let script = r#"tell application "System Events" to (exists login item "Integrator") or (exists login item "MacWindowsBridge")"#;
            if let Ok(out) = Command::new("osascript").args(["-e", script]).output() {
                return String::from_utf8_lossy(&out.stdout).trim() == "true";
            }
            false
        }

        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            let mut cmd = Command::new("reg");
            cmd.creation_flags(0x08000000);
            cmd.args([
                "query",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                "/v",
                "Integrator",
            ]);
            if let Ok(out) = cmd.output() {
                return out.status.success();
            }
            false
        }

        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            false
        }
    }

    pub fn set_enabled(enable: bool) -> Result<bool> {
        if enable {
            Self::enable()
        } else {
            Self::disable()
        }
    }

    pub fn enable() -> Result<bool> {
        #[cfg(target_os = "macos")]
        {
            if let Some(app_bundle) = resolve_mac_app_bundle() {
                let app_str = app_bundle.to_string_lossy().replace('"', "\\\"");
                let script = format!(
                    r#"tell application "System Events"
                        if not (exists login item "Integrator") then
                            make login item at end with properties {{path:"{}", hidden:false, name:"Integrator"}}
                        end if
                    end tell"#,
                    app_str
                );
                let out = Command::new("osascript").args(["-e", &script]).output()?;
                if out.status.success() {
                    tracing::info!("🚀 Registered {} as macOS System Login Item", app_str);
                    return Ok(true);
                }
            }

            // Fallback: LaunchAgent pointing to current executable
            let exe = std::env::current_exe()?;
            let plist = mac_launch_agent_plist();
            if let Some(parent) = plist.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let xml = format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
"#,
                LAUNCH_AGENT_LABEL,
                exe.to_string_lossy()
            );
            std::fs::write(&plist, xml)?;
            tracing::info!("🚀 Registered LaunchAgent autostart: {}", plist.display());
            Ok(true)
        }

        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            let exe_path = std::env::current_exe()?;
            let exe_str = format!("\"{}\" --minimized", exe_path.to_string_lossy());
            let mut cmd = Command::new("reg");
            cmd.creation_flags(0x08000000);
            cmd.args([
                "add",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                "/v",
                "Integrator",
                "/t",
                "REG_SZ",
                "/d",
                &exe_str,
                "/f",
            ]);
            let out = cmd.output()?;
            if !out.status.success() {
                anyhow::bail!(
                    "Failed to register Windows Run key: {}",
                    String::from_utf8_lossy(&out.stderr)
                );
            }
            tracing::info!("🚀 Registered Integrator in HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run");
            Ok(true)
        }

        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            Ok(false)
        }
    }

    pub fn disable() -> Result<bool> {
        #[cfg(target_os = "macos")]
        {
            let plist = mac_launch_agent_plist();
            if plist.exists() {
                let _ = Command::new("launchctl")
                    .args(["unload", plist.to_string_lossy().as_ref()])
                    .output();
                let _ = std::fs::remove_file(&plist);
            }
            let script = r#"tell application "System Events"
                if exists login item "Integrator" then
                    delete login item "Integrator"
                end if
                if exists login item "MacWindowsBridge" then
                    delete login item "MacWindowsBridge"
                end if
            end tell"#;
            let out = Command::new("osascript").args(["-e", script]).output()?;
            if !out.status.success() {
                anyhow::bail!(
                    "Failed to remove login item: {}",
                    String::from_utf8_lossy(&out.stderr)
                );
            }
            tracing::info!("🚀 Removed Integrator from macOS System Login Items");
            Ok(false)
        }

        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            let mut cmd = Command::new("reg");
            cmd.creation_flags(0x08000000);
            cmd.args([
                "delete",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                "/v",
                "Integrator",
                "/f",
            ]);
            let _ = cmd.output()?;
            tracing::info!("🚀 Removed Integrator from Windows Run registry key");
            Ok(false)
        }

        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            Ok(false)
        }
    }
}

#[cfg(target_os = "macos")]
fn mac_launch_agent_plist() -> PathBuf {
    system_info::user_home_dir()
        .join("Library")
        .join("LaunchAgents")
        .join(format!("{}.plist", LAUNCH_AGENT_LABEL))
}

#[cfg(target_os = "macos")]
fn resolve_mac_app_bundle() -> Option<PathBuf> {
    if let Ok(exe) = std::env::current_exe() {
        for ancestor in exe.ancestors() {
            if ancestor
                .extension()
                .and_then(|s| s.to_str())
                .map(|ext| ext.eq_ignore_ascii_case("app"))
                .unwrap_or(false)
            {
                return Some(ancestor.to_path_buf());
            }
        }
    }

    let user_app = system_info::user_home_dir().join("Applications/Integrator.app");
    for candidate in [
        PathBuf::from("/Applications/Integrator.app"),
        user_app,
    ] {
        if candidate.is_dir() {
            return Some(candidate);
        }
    }

    if let Ok(out) = Command::new("mdfind")
        .arg("kMDItemCFBundleIdentifier == 'com.manveersingh.integrator'")
        .output()
    {
        if out.status.success() {
            if let Some(first) = String::from_utf8_lossy(&out.stdout).lines().next() {
                let p = PathBuf::from(first.trim());
                if p.is_dir() {
                    return Some(p);
                }
            }
        }
    }

    None
}
