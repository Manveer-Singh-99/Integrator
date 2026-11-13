#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

mod config;
mod bridge;
mod discovery;
mod clipboard;
mod display;
mod telemetry;

use std::sync::Mutex;
use anyhow::Result;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use discovery::DiscoveryManager;
use clipboard::ClipboardService;
use display::{DisplayController, DisplayServer, DisplayRpcRequest};

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    // 1. Check for CLI Subcommands (e.g. `mac_windows_bridge display toggle`)
    if args.len() > 1 && args[1] == "display" {
        let subcmd = args.get(2).map(|s| s.as_str()).unwrap_or("toggle");
        let req = match subcmd {
            "toggle" | "toggle-mac-to-pc" => DisplayRpcRequest::ToggleMacToPc,
            "toggle-pc-to-mac" => DisplayRpcRequest::TogglePcToMac,
            "stop" | "stop-all" => DisplayRpcRequest::StopAll,
            "status" => DisplayRpcRequest::GetStatus,
            _ => {
                eprintln!("Unknown display command: {}. Usage: display [toggle | toggle-pc-to-mac | stop | status]", subcmd);
                std::process::exit(1);
            }
        };

        match DisplayController::send_remote_rpc("127.0.0.1", &req).await {
            Ok(resp) => {
                println!("{}", resp.message);
                if !resp.success {
                    std::process::exit(1);
                }
                return Ok(());
            }
            Err(e) => {
                eprintln!("Bridge daemon not reachable on 127.0.0.1:58281: {}. Is mac_windows_bridge running?", e);
                std::process::exit(1);
            }
        }
    }

    // 2. Initialize Logging for Daemon
    let home = if cfg!(target_os = "windows") {
        std::env::var("USERPROFILE").unwrap_or_else(|_| ".".into())
    } else {
        std::env::var("HOME").unwrap_or_else(|_| ".".into())
    };
    let log_path = std::path::PathBuf::from(home).join(".mac_windows_bridge.log");
    let file_opt = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .ok();

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    let stdout_layer = tracing_subscriber::fmt::layer().with_writer(std::io::stdout);

    if let Some(f) = file_opt {
        let file_layer = tracing_subscriber::fmt::layer()
            .with_writer(Mutex::new(f))
            .with_ansi(false);
        tracing_subscriber::registry()
            .with(env_filter)
            .with(stdout_layer)
            .with(file_layer)
            .init();
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(stdout_layer)
            .init();
    }

    let os_name = std::env::consts::OS;
    let device_name = if cfg!(target_os = "macos") {
        "Manveer-MacBook-Pro"
    } else {
        "HP-OMEN-Laptop"
    };

    tracing::info!("🚀 mac-windows-usbc-bridge companion app v1.0.0 initializing on {} [{}]...", os_name, device_name);

    // 3. Initialize Dynamic Multi-Subnet Discovery
    let discovery = DiscoveryManager::new(device_name);
    discovery.start().await?;
    tracing::info!("🔍 Dynamic Multi-Subnet Discovery active (broadcasting & listening across USB-C, Hotspot, and Wi-Fi)");

    // 4. Initialize Universal Clipboard (Text, Images, Files) with Deskflow-inspired sequence tracking
    let clipboard = ClipboardService::new(discovery.clone())?;
    clipboard.start().await?;
    tracing::info!("📋 Universal Clipboard running (Zero-RAM file streaming, image, and text sync enabled)");

    // 5. Initialize Native Extended Desktop Controller & RPC Server
    let display_ctrl = DisplayController::new(discovery.clone());
    let display_server = DisplayServer::new(display_ctrl.clone());
    display_server.start().await?;
    tracing::info!("🖥️ Native Extended Desktop Controller active (Zero-SSH, Zero-VBScript sub-millisecond IPC enabled)");

    // Keep daemon running
    tokio::signal::ctrl_c().await?;
    tracing::info!("Shutting down companion app.");

    Ok(())
}
