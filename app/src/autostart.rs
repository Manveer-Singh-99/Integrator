#[cfg(target_os = "macos")]
use crate::system_info;
use anyhow::Result;
#[cfg(target_os = "macos")]
use std::path::PathBuf;
#[cfg(target_os = "windows")]
use std::process::Command;

#[cfg(target_os = "macos")]
const LAUNCH_AGENT_LABEL: &str = "com.manveersingh.integrator";

pub struct AutostartManager;

#[cfg(target_os = "macos")]
fn xml_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

impl AutostartManager {
    pub fn is_enabled() -> bool {
        #[cfg(target_os = "macos")]
        {
            // Check LaunchAgent plist directly on disk without invoking `osascript`
            // ("System Events") on every status poll, avoiding macOS TCC Automation prompts.
            mac_launch_agent_plist().is_file()
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
            let exe = if let Some(bundle_exe) = resolve_mac_app_executable() {
                bundle_exe
            } else {
                std::env::current_exe()?
            };
            let plist = mac_launch_agent_plist();
            if let Some(parent) = plist.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let escaped_exe = xml_escape(&exe.to_string_lossy());
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
        <string>--hidden</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
"#,
                LAUNCH_AGENT_LABEL, escaped_exe
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
                let _ = std::fs::remove_file(&plist);
            }
            tracing::info!("🚀 Removed Integrator LaunchAgent autostart");
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
        .join("Library/LaunchAgents")
        .join(format!("{}.plist", LAUNCH_AGENT_LABEL))
}

#[cfg(target_os = "macos")]
fn resolve_mac_app_executable() -> Option<PathBuf> {
    if let Ok(exe) = std::env::current_exe() {
        let s = exe.to_string_lossy();
        if s.contains(".app/Contents/MacOS/") {
            return Some(exe);
        }
    }
    let candidates = [
        PathBuf::from("/Applications/Integrator.app/Contents/MacOS/integrator"),
        system_info::user_home_dir().join("Applications/Integrator.app/Contents/MacOS/integrator"),
    ];
    for c in candidates {
        if c.is_file() {
            return Some(c);
        }
    }
    None
}
