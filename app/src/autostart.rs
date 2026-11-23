//! # Native Operating System Autostart & Login Persistence Manager (`autostart.rs`)
//!
//! ## 1. Module Purpose & Scope
//! `autostart.rs` manages the automatic startup configuration of Integrator across operating system
//! reboots and user login sessions on macOS and Windows 11.
//!
//! Because Integrator functions as an omnipresent workstation continuity layer (providing seamless
//! display mirroring, KVM input forwarding, audio bridging, and clipboard sync), background availability
//! from the moment the user logs into their desktop is essential.
//!
//! This module provides a unified abstraction (`AutostartManager`) that manages the divergent,
//! platform-specific mechanisms required for silent, elevated background startup:
//! - **macOS**: Manages a per-user `LaunchAgent` property list (`com.manveersingh.integrator.plist`)
//!   located in `~/Library/LaunchAgents/`, registered with macOS `launchd` via `launchctl bootstrap`
//!   and `launchctl bootout` targeting the user's active GUI domain (`gui/<UID>`).
//! - **Windows 11**: Uses Windows Task Scheduler (`schtasks.exe`) to configure a standard user scheduled task
//!   (`"IntegratorAutostart"`) with `<RunLevel>LeastPrivilege</RunLevel>`. This adheres strictly to the
//!   principle of least privilege, aligning with the `asInvoker` application manifest. It prevents high-integrity
//!   execution of the network-facing GUI, eliminates UIPI restrictions on OLE drag-and-drop with Windows Explorer,
//!   and avoids disruptive User Account Control (UAC) prompts at login. Privileged setup tasks (driver installation,
//!   firewall configuration) remain strictly isolated to explicit setup steps. It also cleans up legacy registry entries.
//!
//! ## 2. Architectural Linkages & Dependencies
//! ### Upstream Callers:
//! - `core::IntegratorCore`: Handles UI JSON-RPC requests (`"get_autostart"`, `"set_autostart"`)
//!   dispatched across the FFI boundary from settings preference panels.
//! - Native GUI View Models (Swift `SettingsView` on macOS, WinUI 3 `SettingsPage` on Windows).
//!
//! ### Downstream Callees:
//! - macOS System Binaries: `/bin/launchctl` for dynamic service lifecycle management;
//!   `/usr/bin/id -u` to determine numeric POSIX user ID.
//! - Windows System Binaries: `%SystemRoot%\System32\schtasks.exe` for task manipulation;
//!   `whoami.exe /USER` to obtain user Security Identifier (SID); `reg.exe` for legacy registry cleanup.
//! - `system_info::atomic_write_private`: Writes LaunchAgent plists and Task XMLs with restricted permissions.
//!
//! ### Cross-Platform / Cross-Device Flow:
//! Autostart operates strictly on the local machine. Once enabled, the application launches with `--hidden`
//! (macOS) or `--minimized` (Windows), initializes background UDP discovery listeners and transport servers,
//! and automatically re-establishes connections to paired peers across the network.
//!
//! ## 3. Threading & Concurrency Model
//! - Methods in `AutostartManager` execute synchronous process invocations (`std::process::Command`).
//! - When invoked from the Tokio asynchronous runtime in `core.rs`, calls are wrapped in
//!   `tokio::task::spawn_blocking` to avoid blocking executor worker threads during OS process execution.
//!
//! ## 4. Security & Safety Invariants
//! - **XML Injection Prevention**: All dynamic file paths, arguments, and user identity tokens inserted
//!   into plist and XML templates are strictly sanitized via `xml_escape` and validated to reject ASCII
//!   control characters (`\0`, `\n`, `\r`, `\t`).
//! - **Hardened Process Spawning**:
//!   - On Windows, all processes are executed with `CREATE_NO_WINDOW (0x08000000)` to prevent console flashing.
//!   - Executables are resolved using fully qualified paths (e.g. `system32_exe("schtasks.exe")`),
//!     mitigating path-hijacking attacks.
//! - **UTF-16LE Encoding with BOM**: Windows Task Scheduler XML imports require strict UTF-16LE with BOM
//!   (`0xFF 0xFE`), generated via `encode_utf16_le_with_bom`.
//! - **Private File Permissions**: Plist and temporary XML files are created with mode `0o600` on Unix.

use anyhow::{Context, Result};
use std::path::Path;
#[cfg(target_os = "macos")]
use std::path::PathBuf;
#[cfg(any(target_os = "macos", target_os = "windows"))]
use std::process::Command;

/// Canonical LaunchAgent bundle identifier for macOS launchd registration.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const MAC_LAUNCH_LABEL: &str = "com.manveersingh.integrator";

/// Standard system Applications directory on macOS.
#[cfg(target_os = "macos")]
const MAC_SYSTEM_APPLICATIONS_DIR: &str = "/Applications";

/// Relative per-user Applications subdirectory under `$HOME` on macOS.
#[cfg(target_os = "macos")]
const MAC_USER_APPLICATIONS_SUBDIR: &str = "Applications";

/// Canonical macOS `.app` bundle directory name for Integrator.
#[cfg(target_os = "macos")]
const MAC_APP_BUNDLE_NAME: &str = "Integrator.app";

/// Relative executable directory inside a standard macOS `.app` bundle.
#[cfg(target_os = "macos")]
const MAC_APP_BUNDLE_MACOS_SUBDIR: &str = "Contents/MacOS";

/// Ordered candidate executable names inside `Integrator.app/Contents/MacOS/`.
#[cfg(target_os = "macos")]
const MAC_APP_EXECUTABLE_NAMES: [&str; 2] = ["Integrator", "integrator"];

/// Task Scheduler task name for elevated startup on Windows.
#[cfg(target_os = "windows")]
const WIN_TASK_NAME: &str = "IntegratorAutostart";

/// Windows Task Scheduler `<Priority>` level (7 = below normal default for background services).
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const WIN_TASK_SCHEDULER_PRIORITY: u8 = 7;

/// Legacy registry run key path used in older versions, cleaned up upon activation.
#[cfg(target_os = "windows")]
const WIN_LEGACY_RUN_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";

/// Windows process creation flag to prevent terminal window popup.
#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Platform-agnostic manager for inspecting and toggling system login autostart.
pub struct AutostartManager;

impl AutostartManager {
    /// Queries the operating system to determine whether autostart is currently enabled.
    ///
    /// # Platform Mechanics:
    /// - **macOS**: Checks whether `~/Library/LaunchAgents/com.manveersingh.integrator.plist` exists on disk.
    /// - **Windows**: Queries `schtasks.exe /Query /TN IntegratorAutostart` and checks for exit code 0.
    /// - **Other**: Returns `false`.
    pub fn is_enabled() -> bool {
        #[cfg(target_os = "macos")]
        {
            return mac_plist_path().map(|p| p.is_file()).unwrap_or(false);
        }

        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            let schtasks = crate::system_info::system32_exe("schtasks.exe");
            return Command::new(&schtasks)
                .args(["/Query", "/TN", WIN_TASK_NAME])
                .creation_flags(CREATE_NO_WINDOW)
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
        }

        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            false
        }
    }

    /// Configures the operating system autostart state.
    ///
    /// # Arguments
    /// * `enabled` - `true` to register autostart on user login; `false` to deregister and remove configuration.
    ///
    /// # Return Value
    /// Returns `Ok(bool)` reflecting the new verified state of `is_enabled()`, or `Err` if OS commands failed.
    pub fn set_enabled(enabled: bool) -> Result<bool> {
        #[cfg(target_os = "macos")]
        {
            set_enabled_macos(enabled)?;
            return Ok(Self::is_enabled());
        }

        #[cfg(target_os = "windows")]
        {
            set_enabled_windows(enabled)?;
            return Ok(Self::is_enabled());
        }

        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            let _ = enabled;
            anyhow::bail!("Autostart is only supported on macOS and Windows")
        }
    }
}

/// Escapes reserved XML characters in a string to prevent XML injection attacks.
///
/// Converts `&`, `<`, `>`, `"`, and `'` to their corresponding XML entities (`&amp;`, `&lt;`, etc.).
pub(crate) fn xml_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            other => out.push(other),
        }
    }
    out
}

/// Validates that a filesystem path is valid UTF-8 and contains no control characters.
///
/// Rejects paths containing NUL bytes, newlines, carriage returns, or other non-printable characters.
fn validate_path_for_xml(path: &Path) -> Result<String> {
    let s = path
        .to_str()
        .context("Executable path contains invalid UTF-8")?;
    if s.is_empty() {
        anyhow::bail!("Executable path is empty");
    }
    if s.chars().any(|c| c.is_control()) {
        anyhow::bail!("Executable path contains disallowed control characters");
    }
    Ok(s.to_string())
}

/// Constructs a valid macOS `LaunchAgent` XML plist for the specified executable path.
///
/// Configures `RunAtLoad = true`, `KeepAlive = false`, and `ProcessType = Interactive`
/// passing `--hidden` to launch the application into the background status bar.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn build_macos_plist_xml(exe_path: &Path) -> Result<String> {
    let exe_str = validate_path_for_xml(exe_path)?;
    let escaped = xml_escape(&exe_str);
    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{MAC_LAUNCH_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{escaped}</string>
        <string>--hidden</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <false/>
    <key>ProcessType</key>
    <string>Interactive</string>
</dict>
</plist>
"#
    ))
}

/// Constructs a valid Windows Task Scheduler Task definition XML.
///
/// Configures `<LogonTrigger>`, `<RunLevel>LeastPrivilege</RunLevel>`,
/// and passes `--minimized` to suppress the main window on startup.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) fn build_windows_task_xml(exe_path: &Path, user_id: Option<&str>) -> Result<String> {
    let exe_str = validate_path_for_xml(exe_path)?;
    let escaped_exe = xml_escape(&exe_str);
    let user_xml = match user_id.map(str::trim).filter(|s| !s.is_empty()) {
        Some(uid) => {
            if uid.chars().any(|c| c.is_control()) {
                anyhow::bail!("User ID contains disallowed control characters");
            }
            format!("<UserId>{}</UserId>", xml_escape(uid))
        }
        None => String::new(),
    };

    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Integrator auto-start service</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      {user_xml}
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      {user_xml}
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>{WIN_TASK_SCHEDULER_PRIORITY}</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{escaped_exe}</Command>
      <Arguments>--minimized</Arguments>
    </Exec>
  </Actions>
</Task>
"#
    ))
}

/// Encodes a UTF-8 text string into UTF-16 Little-Endian bytes prefixed with a Byte Order Mark (BOM).
///
/// Windows `schtasks.exe /Create /XML` requires a UTF-16LE BOM (`0xFF 0xFE`) when parsing task XML definitions.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) fn encode_utf16_le_with_bom(text: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(2 + text.len() * 2);
    // Write UTF-16 Little-Endian Byte Order Mark (BOM)
    bytes.push(0xFF);
    bytes.push(0xFE);
    for unit in text.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes
}

/// Resolves the current user's home directory from the `HOME` environment variable on macOS.
#[cfg(target_os = "macos")]
fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// Resolves the absolute path to the user's LaunchAgent plist file.
#[cfg(target_os = "macos")]
fn mac_plist_path() -> Result<PathBuf> {
    let home = home_dir().context("Could not resolve HOME directory")?;
    Ok(home
        .join("Library")
        .join("LaunchAgents")
        .join(format!("{MAC_LAUNCH_LABEL}.plist")))
}

/// Discovers the absolute path to the executable inside the `.app` bundle on macOS.
///
/// Searches `std::env::current_exe()`, standard `/Applications/Integrator.app`,
/// and user `~/Applications/Integrator.app` locations.
#[cfg(target_os = "macos")]
fn resolve_mac_app_executable() -> Result<PathBuf> {
    let bundle_marker = format!(".app/{MAC_APP_BUNDLE_MACOS_SUBDIR}/");
    // Check if the current running executable is already inside an .app bundle
    if let Ok(exe) = std::env::current_exe() {
        let canonical = exe.canonicalize().unwrap_or(exe);
        let s = canonical.to_string_lossy();
        if s.contains(&bundle_marker) && canonical.is_file() {
            return Ok(canonical);
        }
    }

    // Inspect standard system and per-user .app bundle locations
    let mut app_roots = vec![PathBuf::from(MAC_SYSTEM_APPLICATIONS_DIR)];
    if let Some(home) = home_dir() {
        app_roots.push(home.join(MAC_USER_APPLICATIONS_SUBDIR));
    }
    for root in app_roots {
        let macos_dir = root
            .join(MAC_APP_BUNDLE_NAME)
            .join(MAC_APP_BUNDLE_MACOS_SUBDIR);
        for exe_name in MAC_APP_EXECUTABLE_NAMES {
            let cand = macos_dir.join(exe_name);
            if cand.is_file() {
                return Ok(cand);
            }
        }
    }

    // Fall back to current executable
    let exe = std::env::current_exe().context("Could not resolve current executable path")?;
    if exe.is_file() {
        return Ok(exe);
    }
    anyhow::bail!("Could not locate Integrator executable for LaunchAgent")
}

/// Retrieves the current POSIX numeric user ID by executing `/usr/bin/id -u`.
#[cfg(target_os = "macos")]
fn current_uid() -> Result<String> {
    let out = Command::new(crate::config::MACOS_ID_BIN)
        .arg("-u")
        .output()
        .context("Failed to execute /usr/bin/id")?;
    if !out.status.success() {
        anyhow::bail!("/usr/bin/id -u exited with status {}", out.status);
    }
    let uid = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if uid.is_empty() || !uid.chars().all(|c| c.is_ascii_digit()) {
        anyhow::bail!("Unexpected UID from /usr/bin/id: {:?}", uid);
    }
    Ok(uid)
}

/// Unloads any active LaunchAgent service registration via `/bin/launchctl bootout`.
#[cfg(target_os = "macos")]
fn launchctl_bootout(uid: &str) {
    let service_target = format!("gui/{uid}/{MAC_LAUNCH_LABEL}");
    let _ = Command::new(crate::config::MACOS_LAUNCHCTL_BIN)
        .args(["bootout", &service_target])
        .output();
}

/// Enables or disables macOS autostart by creating/deleting the LaunchAgent plist and bootstrapping launchd.
#[cfg(target_os = "macos")]
fn set_enabled_macos(enabled: bool) -> Result<()> {
    let plist_path = mac_plist_path()?;
    let uid = current_uid()?;

    if enabled {
        let dir = plist_path
            .parent()
            .context("LaunchAgent plist has no parent directory")?;
        std::fs::create_dir_all(dir)
            .with_context(|| format!("Failed to create LaunchAgents directory {}", dir.display()))?;

        let exe_path = resolve_mac_app_executable()?;
        let plist_xml = build_macos_plist_xml(&exe_path)?;

        // Boot out any existing registration prior to writing updated plist
        launchctl_bootout(&uid);
        crate::system_info::atomic_write_private(&plist_path, plist_xml.as_bytes())
            .with_context(|| format!("Failed to write LaunchAgent plist {}", plist_path.display()))?;

        // Register the new LaunchAgent with launchd for the user's GUI session
        let domain = format!("gui/{uid}");
        let plist_str = plist_path
            .to_str()
            .context("LaunchAgent plist path is not valid UTF-8")?;
        let out = Command::new(crate::config::MACOS_LAUNCHCTL_BIN)
            .args(["bootstrap", &domain, plist_str])
            .output()
            .context("Failed to invoke /bin/launchctl bootstrap")?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let stdout = String::from_utf8_lossy(&out.stdout);
            tracing::warn!(
                status = %out.status,
                stderr = %stderr.trim(),
                stdout = %stdout.trim(),
                "launchctl bootstrap returned non-zero (plist saved for next login)"
            );
        }
    } else {
        launchctl_bootout(&uid);
        if plist_path.symlink_metadata().is_ok() {
            std::fs::remove_file(&plist_path)
                .with_context(|| format!("Failed to remove {}", plist_path.display()))?;
        }
    }

    Ok(())
}

/// Parses the output of `whoami.exe /USER /FO CSV /NH` to extract the user's Security Identifier (SID).
#[cfg(target_os = "windows")]
fn parse_whoami_sid_csv(csv: &str) -> Option<String> {
    let line = csv.lines().next()?.trim();
    // Format: "DOMAIN\user","S-1-5-21-..."
    let mut parts = line.split("\",\"");
    let _user = parts.next()?;
    let sid_raw = parts.next()?.trim_matches('"').trim();
    if sid_raw.starts_with("S-1-") && sid_raw.len() > 4 {
        Some(sid_raw.to_string())
    } else {
        None
    }
}

/// Retrieves the current Windows user's SID or DOMAIN\Username.
#[cfg(target_os = "windows")]
fn current_windows_user_id() -> Option<String> {
    use std::os::windows::process::CommandExt;
    let whoami = crate::system_info::system32_exe("whoami.exe");
    if let Ok(out) = Command::new(&whoami)
        .args(["/USER", "/FO", "CSV", "/NH"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
    {
        if out.status.success() {
            if let Some(sid) = parse_whoami_sid_csv(&String::from_utf8_lossy(&out.stdout)) {
                return Some(sid);
            }
        }
    }

    let user = std::env::var("USERNAME").ok()?;
    let user = user.trim();
    if user.is_empty() {
        return None;
    }
    match std::env::var("USERDOMAIN") {
        Ok(dom) if !dom.trim().is_empty() => Some(format!("{}\\{user}", dom.trim())),
        _ => Some(user.to_string()),
    }
}

/// Removes legacy non-elevated Run registry values from `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.
#[cfg(target_os = "windows")]
fn cleanup_legacy_run_key() {
    use std::os::windows::process::CommandExt;
    let reg = crate::system_info::system32_exe("reg.exe");
    let _ = Command::new(&reg)
        .args(["delete", WIN_LEGACY_RUN_KEY, "/v", "Integrator", "/f"])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
}

/// Enables or disables Windows autostart via elevated Scheduled Task manipulation.
#[cfg(target_os = "windows")]
fn set_enabled_windows(enabled: bool) -> Result<()> {
    use std::os::windows::process::CommandExt;
    // Remove obsolete registry key
    cleanup_legacy_run_key();

    let schtasks = crate::system_info::system32_exe("schtasks.exe");
    if enabled {
        let exe = std::env::current_exe().context("Could not resolve current executable path")?;
        let user_id = current_windows_user_id();
        let xml = build_windows_task_xml(&exe, user_id.as_deref())?;
        let xml_bytes = encode_utf16_le_with_bom(&xml);

        let data_dir = crate::system_info::app_data_dir();
        std::fs::create_dir_all(&data_dir).with_context(|| {
            format!("Failed to create app data directory {}", data_dir.display())
        })?;
        let xml_path = data_dir.join(format!("autostart_{}.xml.tmp", std::process::id()));
        crate::system_info::atomic_write_private(&xml_path, &xml_bytes)
            .with_context(|| format!("Failed to write task XML {}", xml_path.display()))?;

        let xml_path_str = xml_path
            .to_str()
            .context("Task XML path contains invalid UTF-8")?;
        let out = Command::new(&schtasks)
            .args(["/Create", "/TN", WIN_TASK_NAME, "/XML", xml_path_str, "/F"])
            .creation_flags(CREATE_NO_WINDOW)
            .output();
        let _ = std::fs::remove_file(&xml_path);

        let out = out.context("Failed to execute schtasks.exe /Create")?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let stdout = String::from_utf8_lossy(&out.stdout);
            anyhow::bail!(
                "schtasks /Create failed ({}): {} {}",
                out.status,
                stderr.trim(),
                stdout.trim()
            );
        }
    } else {
        let out = Command::new(&schtasks)
            .args(["/Delete", "/TN", WIN_TASK_NAME, "/F"])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .context("Failed to execute schtasks.exe /Delete")?;
        if !out.status.success() && AutostartManager::is_enabled() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let stdout = String::from_utf8_lossy(&out.stdout);
            anyhow::bail!(
                "schtasks /Delete failed ({}): {} {}",
                out.status,
                stderr.trim(),
                stdout.trim()
            );
        }
    }

    Ok(())
}

/// Inspects an existing Windows scheduled task XML for `WIN_TASK_NAME`.
/// If the task exists and contains `<RunLevel>HighestAvailable</RunLevel>`,
/// automatically migrates it to `<RunLevel>LeastPrivilege</RunLevel>`.
///
/// Returns `Ok(true)` if an elevated task was migrated to standard user privileges,
/// `Ok(false)` if no migration was necessary or task does not exist.
#[cfg(target_os = "windows")]
pub fn migrate_task_to_least_privilege_windows() -> Result<bool> {
    use std::os::windows::process::CommandExt;
    let schtasks = crate::system_info::system32_exe("schtasks.exe");
    let out = match Command::new(&schtasks)
        .args(["/Query", "/TN", WIN_TASK_NAME, "/XML"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
    {
        Ok(o) => o,
        Err(_) => return Ok(false),
    };

    if !out.status.success() {
        return Ok(false);
    }

    let xml = String::from_utf8_lossy(&out.stdout);
    if task_xml_needs_least_privilege_migration(&xml) {
        tracing::warn!("⚠️ Existing Windows scheduled task '{}' is configured as HighestAvailable; migrating to LeastPrivilege...", WIN_TASK_NAME);
        set_enabled_windows(true)?;
        tracing::info!("✅ Successfully migrated scheduled task '{}' to LeastPrivilege", WIN_TASK_NAME);
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Checks whether a Windows Task Scheduler XML string contains `HighestAvailable` run level.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) fn task_xml_needs_least_privilege_migration(xml: &str) -> bool {
    xml.contains("<RunLevel>HighestAvailable</RunLevel>")
}

/// Transforms task XML content with `HighestAvailable` into `LeastPrivilege`.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) fn migrate_task_xml_content_to_least_privilege(xml: &str) -> (String, bool) {
    if xml.contains("<RunLevel>HighestAvailable</RunLevel>") {
        (
            xml.replace(
                "<RunLevel>HighestAvailable</RunLevel>",
                "<RunLevel>LeastPrivilege</RunLevel>",
            ),
            true,
        )
    } else {
        (xml.to_string(), false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xml_escape_escapes_all_reserved_characters() {
        let raw = r#"C:\A&B\<Test> "One" 'Two'"#;
        let escaped = xml_escape(raw);
        assert_eq!(
            escaped,
            "C:\\A&amp;B\\&lt;Test&gt; &quot;One&quot; &apos;Two&apos;"
        );
    }

    #[test]
    fn build_macos_plist_xml_escapes_special_chars_and_sets_keys() {
        let path = Path::new("/Applications/A&B <App>/Integrator.app/Contents/MacOS/integrator");
        let xml = build_macos_plist_xml(path).unwrap();
        assert!(xml.contains("<string>com.manveersingh.integrator</string>"));
        assert!(xml.contains(
            "<string>/Applications/A&amp;B &lt;App&gt;/Integrator.app/Contents/MacOS/integrator</string>"
        ));
        assert!(xml.contains("<string>--hidden</string>"));
        assert!(xml.contains("<key>RunAtLoad</key>"));
    }

    #[test]
    fn build_windows_task_xml_configures_least_privilege_and_battery_options() {
        let path = Path::new(r"C:\Program Files\Integrator & Co\IntegratorUI.exe");
        let xml = build_windows_task_xml(path, Some("S-1-5-21-123456-7890")).unwrap();
        assert!(xml.contains("encoding=\"UTF-16\""));
        assert!(xml.contains("<LogonType>InteractiveToken</LogonType>"));
        assert!(xml.contains("<RunLevel>LeastPrivilege</RunLevel>"));
        assert!(xml.contains("<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>"));
        assert!(xml.contains("<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>"));
        assert!(xml.contains("<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>"));
        assert!(xml.contains("<UserId>S-1-5-21-123456-7890</UserId>"));
        assert!(xml.contains(
            "<Command>C:\\Program Files\\Integrator &amp; Co\\IntegratorUI.exe</Command>"
        ));
        assert!(xml.contains("<Arguments>--minimized</Arguments>"));
    }

    #[test]
    fn reject_control_characters_in_paths_and_users() {
        assert!(build_macos_plist_xml(Path::new("/tmp/bad\npath")).is_err());
        assert!(build_windows_task_xml(Path::new("C:\\bad\0path.exe"), None).is_err());
        assert!(build_windows_task_xml(Path::new("C:\\ok.exe"), Some("bad\ruser")).is_err());
    }

    #[test]
    fn utf16_le_bom_encoding_matches_expected_bytes() {
        let bytes = encode_utf16_le_with_bom("AB");
        assert_eq!(bytes, vec![0xFF, 0xFE, b'A', 0x00, b'B', 0x00]);
    }

    #[test]
    fn test_migration_of_existing_highest_available_task() {
        let legacy_xml = r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
</Task>"#;

        assert!(task_xml_needs_least_privilege_migration(legacy_xml));
        let (migrated_xml, modified) = migrate_task_xml_content_to_least_privilege(legacy_xml);
        assert!(modified);
        assert!(migrated_xml.contains("<RunLevel>LeastPrivilege</RunLevel>"));
        assert!(!migrated_xml.contains("<RunLevel>HighestAvailable</RunLevel>"));
        assert!(!task_xml_needs_least_privilege_migration(&migrated_xml));

        // Already migrated XML should not be modified
        let (re_migrated, re_modified) = migrate_task_xml_content_to_least_privilege(&migrated_xml);
        assert!(!re_modified);
        assert_eq!(re_migrated, migrated_xml);
    }
}
