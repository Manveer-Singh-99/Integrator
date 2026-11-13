mod config;
mod bridge;
mod discovery;
mod clipboard;
mod telemetry;

use anyhow::Result;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use discovery::DiscoveryManager;
use clipboard::ClipboardService;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

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

    // 2. Initialize Universal Clipboard (Text, Images, Files)
    let clipboard = ClipboardService::new(discovery.clone())?;
    clipboard.start().await?;
    tracing::info!("📋 Universal Clipboard running (Zero-RAM file streaming, image, and text sync enabled)");

    // Keep daemon running
    tokio::signal::ctrl_c().await?;
    tracing::info!("Shutting down companion app.");

    Ok(())
}
