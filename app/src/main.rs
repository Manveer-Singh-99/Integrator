#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

mod config;
mod bridge;
mod discovery;
mod clipboard;
mod telemetry;

use std::sync::Mutex;
use anyhow::Result;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use discovery::DiscoveryManager;
use clipboard::ClipboardService;

#[tokio::main]
async fn main() -> Result<()> {
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

    // 1. Initialize Dynamic Multi-Subnet Discovery
    let discovery = DiscoveryManager::new(device_name);
    discovery.start().await?;
    tracing::info!("🔍 Dynamic Multi-Subnet Discovery active (broadcasting & listening across USB-C, Hotspot, and Wi-Fi)");

    // 2. Initialize Universal Clipboard (Text, Images, Files) with Deskflow-inspired sequence tracking
    let clipboard = ClipboardService::new(discovery.clone())?;
    clipboard.start().await?;
    tracing::info!("📋 Universal Clipboard running (Zero-RAM file streaming, image, and text sync enabled)");

    // Keep daemon running
    tokio::signal::ctrl_c().await?;
    tracing::info!("Shutting down companion app.");

    Ok(())
}
