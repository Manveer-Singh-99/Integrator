mod config;
mod bridge;
mod telemetry;

use anyhow::Result;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use config::AppConfig;
use bridge::LinkMonitor;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("mac-windows-usbc-bridge companion app v1.0.0 initializing...");

    let config = AppConfig::default();
    tracing::info!("Active Peer Target: {}:{}", config.peer_ip, config.control_port);

    let monitor = LinkMonitor::new(&config.peer_ip, config.control_port)?;
    
    // Spawn link monitor in background
    let monitor_handle = tokio::spawn(async move {
        monitor.run_watchdog().await;
    });

    monitor_handle.await?;

    Ok(())
}
