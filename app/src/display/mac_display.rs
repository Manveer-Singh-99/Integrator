//! macOS Native Display Controller.
//! Manages virtual display creation (vd165), Sunshine output configuration,
//! and Moonlight client launching.

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;
use anyhow::{Result, Context};
use tracing::info;

#[cfg(target_os = "macos")]
#[link(name = "CoreGraphics", kind = "framework")]
extern "C" {
    fn CGGetOnlineDisplayList(max_displays: u32, online_displays: *mut u32, display_count: *mut u32) -> i32;
    fn CGDisplayIsBuiltin(display_id: u32) -> i32;
}

pub struct MacDisplayManager;

impl MacDisplayManager {
    /// Returns the CoreGraphics display ID of the virtual display (non-builtin display).
    #[cfg(target_os = "macos")]
    pub fn get_active_virtual_display() -> Option<u32> {
        unsafe {
            let mut count: u32 = 0;
            if CGGetOnlineDisplayList(0, std::ptr::null_mut(), &mut count) != 0 || count == 0 {
                return None;
            }
            let mut displays = vec![0u32; count as usize];
            if CGGetOnlineDisplayList(count, displays.as_mut_ptr(), &mut count) != 0 {
                return None;
            }
            for d in displays {
                if CGDisplayIsBuiltin(d) == 0 {
                    return Some(d);
                }
            }
        }
        None
    }

    #[cfg(not(target_os = "macos"))]
    pub fn get_active_virtual_display() -> Option<u32> {
        None
    }

    /// Updates ~/.config/sunshine/sunshine.conf output_name = <display_id>.
    pub fn configure_sunshine_output(display_id: u32) -> Result<()> {
        let home = std::env::var("HOME").context("HOME not set")?;
        let conf_path = PathBuf::from(home).join(".config/sunshine/sunshine.conf");

        let content = fs::read_to_string(&conf_path).unwrap_or_default();
        let target_line = format!("output_name = {}", display_id);

        let mut replaced = false;
        let mut new_lines = Vec::new();
        for line in content.lines() {
            if line.trim().starts_with("output_name") {
                new_lines.push(target_line.clone());
                replaced = true;
            } else {
                new_lines.push(line.to_string());
            }
        }
        if !replaced {
            new_lines.push(target_line);
        }

        fs::create_dir_all(conf_path.parent().unwrap())?;
        fs::write(&conf_path, new_lines.join("\n") + "\n")?;
        info!("Configured Sunshine output_name = {}", display_id);
        Ok(())
    }

    /// Spawns the virtual display binary vd165.
    pub fn start_virtual_display(width: u32, height: u32, fps: u32) -> Result<()> {
        let vd165_path = Self::find_vd165_binary()
            .context("vd165 virtual display binary not found")?;

        let home = std::env::var("HOME").context("HOME not set")?;
        let log_file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(PathBuf::from(home).join("Library/Logs/vd165.log"))?;

        let mut cmd = Command::new(vd165_path);
        cmd.args([width.to_string(), height.to_string(), fps.to_string()]);
        cmd.stdout(log_file.try_clone()?);
        cmd.stderr(log_file);

        let child = cmd.spawn().context("Failed to spawn vd165")?;
        info!("Spawned virtual display vd165 (PID {}, {}x{} @ {}Hz)", child.id(), width, height, fps);
        Ok(())
    }

    /// Terminates vd165 virtual display.
    pub fn stop_virtual_display() -> Result<()> {
        let _ = Command::new("pkill").args(["-f", "vd165"]).status();
        info!("Terminated virtual display vd165");
        Ok(())
    }

    /// Checks if vd165 is currently running.
    pub fn is_virtual_display_active() -> bool {
        if let Ok(output) = Command::new("pgrep").args(["-f", "vd165"]).output() {
            return output.status.success() && !output.stdout.is_empty();
        }
        false
    }

    /// Launches Sunshine.app on macOS.
    pub fn start_sunshine() -> Result<()> {
        Command::new("open").args(["-a", "/Applications/Sunshine.app"]).status()?;
        info!("Launched Sunshine.app");
        Ok(())
    }

    /// Terminates Sunshine on macOS.
    pub fn stop_sunshine() -> Result<()> {
        let _ = Command::new("killall").arg("Sunshine").status();
        info!("Stopped Sunshine.app");
        Ok(())
    }

    /// Waits until Sunshine binds and listens on port 47989.
    pub async fn wait_for_sunshine_ready(timeout_dur: Duration) -> bool {
        let start = std::time::Instant::now();
        while start.elapsed() < timeout_dur {
            if tokio::net::TcpStream::connect("127.0.0.1:47989").await.is_ok() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
        false
    }

    /// Waits until remote port on peer IP is reachable.
    pub async fn wait_for_port(ip: &str, port: u16, timeout: Duration) -> bool {
        let addr = format!("{}:{}", ip, port);
        let start = std::time::Instant::now();
        while start.elapsed() < timeout {
            if tokio::net::TcpStream::connect(&addr).await.is_ok() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        false
    }

    /// Launches Moonlight on macOS connected to remote PC.
    pub fn start_moonlight_client(pc_ip: &str, port: u16, host_name: &str) -> Result<()> {
        // 1. Kill any existing instance
        let _ = Command::new("killall").arg("Moonlight").status();
        std::thread::sleep(Duration::from_millis(200));

        // 2. Set Moonlight preferences
        let _ = Command::new("defaults").args(["write", "com.moonlight-stream.Moonlight", "width", "-int", "2560"]).status();
        let _ = Command::new("defaults").args(["write", "com.moonlight-stream.Moonlight", "height", "-int", "1600"]).status();
        let _ = Command::new("defaults").args(["write", "com.moonlight-stream.Moonlight", "fps", "-int", "60"]).status();
        let _ = Command::new("defaults").args(["write", "com.moonlight-stream.Moonlight", "enableVsync", "-bool", "false"]).status();
        let _ = Command::new("defaults").args(["write", "com.moonlight-stream.Moonlight", "framePacing", "-bool", "false"]).status();

        // Host 1: HP-Omen (port 47989)
        let _ = Command::new("defaults").args(["write", "com.moonlight-stream.Moonlight", "hosts.1.localaddress", "-string", pc_ip]).status();
        let _ = Command::new("defaults").args(["write", "com.moonlight-stream.Moonlight", "hosts.1.manualaddress", "-string", pc_ip]).status();
        let _ = Command::new("defaults").args(["write", "com.moonlight-stream.Moonlight", "hosts.1.localport", "-int", "47989"]).status();
        let _ = Command::new("defaults").args(["write", "com.moonlight-stream.Moonlight", "hosts.1.manualport", "-int", "47989"]).status();

        // Host 2: HP-Omen-Mac2 (port 48989)
        let _ = Command::new("defaults").args(["write", "com.moonlight-stream.Moonlight", "hosts.2.localaddress", "-string", pc_ip]).status();
        let _ = Command::new("defaults").args(["write", "com.moonlight-stream.Moonlight", "hosts.2.manualaddress", "-string", pc_ip]).status();
        let _ = Command::new("defaults").args(["write", "com.moonlight-stream.Moonlight", "hosts.2.localport", "-int", "48989"]).status();
        let _ = Command::new("defaults").args(["write", "com.moonlight-stream.Moonlight", "hosts.2.manualport", "-int", "48989"]).status();

        // 3. Wait up to 5 seconds for remote Sunshine port to respond
        let addr = format!("{}:{}", pc_ip, port);
        let start = std::time::Instant::now();
        while start.elapsed() < Duration::from_secs(5) {
            if let Ok(target_addr) = addr.parse() {
                if std::net::TcpStream::connect_timeout(&target_addr, Duration::from_millis(250)).is_ok() {
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(200));
        }

        // 4. Launch Moonlight executable directly in background
        let moonlight_bin = "/Applications/Moonlight.app/Contents/MacOS/Moonlight";
        let mut cmd = Command::new(moonlight_bin);
        cmd.args(["stream", host_name, "Desktop", "--no-vsync", "--no-frame-pacing", "--quit-after"]);

        cmd.spawn().context("Failed to spawn Moonlight on macOS")?;
        info!("Launched Moonlight on macOS (Streaming {} from {}:{})", host_name, pc_ip, port);
        Ok(())
    }

    /// Stops Moonlight on macOS.
    pub fn stop_moonlight_client() -> Result<()> {
        let _ = Command::new("killall").arg("Moonlight").status();
        info!("Stopped Moonlight on macOS");
        Ok(())
    }

    /// Triggers native macOS user notification.
    pub fn show_notification(title: &str, message: &str) {
        let script = format!("display notification \"{}\" with title \"{}\" sound name \"Glass\"", message, title);
        let _ = Command::new("osascript").args(["-e", &script]).status();
    }

    fn find_vd165_binary() -> Option<PathBuf> {
        let home = std::env::var("HOME").unwrap_or_default();
        let candidates = [
            PathBuf::from(&home).join(".local/bin/vd165"),
            PathBuf::from("/usr/local/bin/vd165"),
            PathBuf::from("vd165"),
        ];
        for c in &candidates {
            if c.exists() {
                return Some(c.clone());
            }
        }
        None
    }
}
