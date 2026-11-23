//! # Standard Bonjour / mDNS Zero-Configuration Discovery (`bonjour_discovery.rs`)
//!
//! ## 1. Module Purpose & Scope
//! `bonjour_discovery.rs` integrates standard RFC 6762 / RFC 6763 Multicast DNS (mDNS) and
//! DNS Service Discovery (DNS-SD / Apple Bonjour) into Integrator using the cross-platform
//! `mdns-sd` crate.
//!
//! ### Strict Isolation from Apple Ecosystem Services
//! Integrator registers and browses **exclusively** under its dedicated private service type
//! [`crate::config::BONJOUR_SERVICE_TYPE`] (`"_integrator._tcp.local."`).
//! Apple TV, AirPlay (`_airplay._tcp`, `_raop._tcp`), AirDrop (`_airdrop._tcp`), HomeKit
//! (`_hap._tcp`), and system printers completely ignore `_integrator._tcp.local.`, so
//! Windows PCs running Integrator will **never** appear as AirPlay destinations or Apple devices.
//!
//! ## 2. Architectural Linkages & Dependencies
//! ### Upstream Callers:
//! - `discovery::DiscoveryManager`: Starts [`start_bonjour_discovery`] as an additive discovery
//!   transport alongside UDP `:58280` beacons and BLE magic packets.
//! - `core::run_cli_if_requested`: Invokes [`browse_once_for_bonjour_hint`] for isolated
//!   Bonjour-only authentication testing (`integrator discovery auth-via-bonjour`).
//!
//! ### Downstream Callees:
//! - `mdns_sd::ServiceDaemon`: Manages UDP multicast `224.0.0.251:5353` (`SO_REUSEPORT` /
//!   `SO_REUSEADDR` coexisting cleanly with macOS `mDNSResponder` and Windows `dnssd`).
//! - `system_info::list_local_ipv4_interfaces`: Provides filtered, non-virtual active IPv4
//!   addresses so VPN/Docker/WSL virtual interfaces are never advertised over Bonjour.
//!
//! ### Cross-Platform / Cross-Device Flow:
//! - Both macOS and Windows 11 peers register `<hostname>-<dev_prefix>._integrator._tcp.local.`
//!   on UDP multicast `224.0.0.251:5353` with TXT metadata (`v`, `id`, `os`, `ff`, `port`).
//! - When either peer resolves a remote `_integrator._tcp.local.` record, it forwards the
//!   extracted [`BonjourDiscoveryHint`] into `discovery::DiscoveryManager`, which verifies the
//!   peer via a mutual Ed25519 + X25519 + ChaCha20-Poly1305 `TransportSessionV2` handshake on
//!   TCP `:58281`.
//!
//! ## 3. Threading & Concurrency Model
//! - `mdns_sd::ServiceDaemon` runs its internal multicast socket I/O on a dedicated OS thread.
//! - A lightweight Tokio background task refreshes service IP registrations whenever the host's
//!   active IPv4 interface set changes (e.g., switching between USB-C, Hotspot, and LAN).
//! - A blocking receiver bridge forwards resolved [`BonjourDiscoveryHint`] records into a Tokio
//!   `mpsc::UnboundedSender` without blocking async executor threads.
//!
//! ## 4. Security & Safety Invariants
//! - **Untrusted Hint Only**: mDNS/Bonjour records are unauthenticated link-local discovery hints.
//!   Every resolved IP MUST complete full mutual Ed25519 + X25519 + ChaCha20-Poly1305
//!   `TransportSessionV2` authentication before trust or state updates occur.
//! - **Input Sanitization**: Instance names, hostnames, TXT fields, and ports are sanitized
//!   against control characters, Unicode BiDi overrides, and privileged ports (`< 1024`).

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::mpsc;

use crate::config::{
    BONJOUR_SERVICE_TYPE, BONJOUR_TXT_KEY_DEVICE_ID, BONJOUR_TXT_KEY_FORM_FACTOR,
    BONJOUR_TXT_KEY_OS, BONJOUR_TXT_KEY_PORT, BONJOUR_TXT_KEY_VERSION, CONTROL_PORT,
};
use crate::discovery::DISCOVERY_PROTOCOL_VERSION;
use crate::system_info;

/// Interval between checking whether active local IPv4 interfaces changed for mDNS re-registration.
const BONJOUR_IP_REFRESH_INTERVAL: Duration = Duration::from_secs(6);

/// Global flag reflecting whether Bonjour / mDNS (`_integrator._tcp.local.`) is active.
static BONJOUR_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Returns `true` if the Bonjour mDNS daemon is currently running.
pub fn is_bonjour_active() -> bool {
    BONJOUR_ACTIVE.load(Ordering::Acquire)
}

/// Decoded reachability hint extracted from a resolved `_integrator._tcp.local.` mDNS service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BonjourDiscoveryHint {
    /// Full Bonjour service instance name (e.g., `"HP-OMEN-daf2ad95._integrator._tcp.local."`).
    pub fullname: String,
    /// Advertised lowercase hex `device_id` from TXT key `"id"`, if present.
    pub device_id: Option<String>,
    /// Resolved host label (without trailing `.local.`).
    pub hostname: String,
    /// Resolved peer IPv4 address.
    pub ip: Ipv4Addr,
    /// Resolved TCP control RPC port.
    pub port: u16,
    /// Advertised OS platform from TXT key `"os"`, if present.
    pub os: Option<String>,
    /// Advertised form factor from TXT key `"ff"`, if present.
    pub form_factor: Option<String>,
}

/// Sanitizes an arbitrary hostname into a valid RFC 1035 DNS label (`[a-zA-Z0-9-]`, max 48 chars).
pub fn sanitize_dns_label(raw: &str, fallback: &str) -> String {
    let mut out = String::new();
    let mut last_dash = false;
    for c in raw.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c);
            last_dash = false;
        } else if (c == '-' || c == ' ' || c == '_' || c == '.') && !out.is_empty() && !last_dash {
            out.push('-');
            last_dash = true;
        }
        if out.len() >= 48 {
            break;
        }
    }
    let trimmed = out.trim_matches('-').to_string();
    if trimmed.is_empty() {
        fallback.to_string()
    } else {
        trimmed
    }
}

/// Collects active, non-virtual local IPv4 addresses sorted by transport priority for mDNS registration.
fn collect_bonjour_local_ipv4s() -> Vec<Ipv4Addr> {
    let mut ifaces = system_info::list_local_ipv4_interfaces();
    ifaces.sort_by(|a, b| a.transport.route_priority().cmp(&b.transport.route_priority()));
    let mut ips = Vec::new();
    for iface in ifaces {
        if let Ok(ip) = iface.ip.parse::<Ipv4Addr>() {
            if !ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast() && !ips.contains(&ip)
            {
                ips.push(ip);
            }
        }
    }
    ips
}

/// Builds an `mdns_sd::ServiceInfo` record exclusively for `_integrator._tcp.local.`.
fn build_service_info(
    device_id: &str,
    hostname_raw: &str,
    os_name: &str,
    form_factor: &str,
    ips: &[Ipv4Addr],
) -> anyhow::Result<ServiceInfo> {
    let dev_prefix: String = device_id
        .trim()
        .to_ascii_lowercase()
        .chars()
        .take(8)
        .collect();
    let host_label = sanitize_dns_label(hostname_raw, "integrator");
    let instance_name = format!("{}-{}", host_label, dev_prefix);
    let host_fqdn = format!("{}-{}.local.", host_label.to_ascii_lowercase(), dev_prefix);

    let mut props = HashMap::new();
    props.insert(
        BONJOUR_TXT_KEY_VERSION.to_string(),
        DISCOVERY_PROTOCOL_VERSION.to_string(),
    );
    props.insert(
        BONJOUR_TXT_KEY_DEVICE_ID.to_string(),
        device_id.trim().to_ascii_lowercase(),
    );
    props.insert(BONJOUR_TXT_KEY_OS.to_string(), os_name.to_string());
    props.insert(
        BONJOUR_TXT_KEY_FORM_FACTOR.to_string(),
        form_factor.to_string(),
    );
    props.insert(BONJOUR_TXT_KEY_PORT.to_string(), CONTROL_PORT.to_string());

    let ip_addrs: Vec<IpAddr> = ips.iter().copied().map(IpAddr::V4).collect();
    let info = ServiceInfo::new(
        BONJOUR_SERVICE_TYPE,
        &instance_name,
        &host_fqdn,
        ip_addrs.as_slice(),
        CONTROL_PORT,
        Some(props),
    )?;
    Ok(info)
}

/// Converts an `mdns_sd::ServiceInfo` resolution event into zero or more [`BonjourDiscoveryHint`]s.
fn extract_hints_from_resolved(
    info: &ServiceInfo,
    own_device_id: &str,
) -> Vec<BonjourDiscoveryHint> {
    let own_lower = own_device_id.trim().to_ascii_lowercase();
    let dev_id = info
        .get_property_val_str(BONJOUR_TXT_KEY_DEVICE_ID)
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty());

    // Skip our own advertisements
    if dev_id.as_deref() == Some(own_lower.as_str()) {
        return Vec::new();
    }

    let port = info.get_port();
    if port < 1024 {
        return Vec::new();
    }

    let os = info
        .get_property_val_str(BONJOUR_TXT_KEY_OS)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let form_factor = info
        .get_property_val_str(BONJOUR_TXT_KEY_FORM_FACTOR)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let hostname = info
        .get_hostname()
        .trim_end_matches('.')
        .trim_end_matches(".local")
        .to_string();
    let fullname = info.get_fullname().to_string();

    let mut hints = Vec::new();
    for addr in info.get_addresses_v4() {
        let ip = *addr;
        if ip.is_loopback() || ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast() {
            continue;
        }
        hints.push(BonjourDiscoveryHint {
            fullname: fullname.clone(),
            device_id: dev_id.clone(),
            hostname: hostname.clone(),
            ip,
            port,
            os: os.clone(),
            form_factor: form_factor.clone(),
        });
    }
    hints
}

/// Starts continuous Bonjour / mDNS registration and browsing on `_integrator._tcp.local.`.
pub fn start_bonjour_discovery(
    local_device_id: String,
    enable_browse: bool,
    enable_register: bool,
) -> Option<mpsc::UnboundedReceiver<BonjourDiscoveryHint>> {
    let daemon = match ServiceDaemon::new() {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!("Bonjour/mDNS daemon failed to initialize: {}", e);
            BONJOUR_ACTIVE.store(false, Ordering::Release);
            return None;
        }
    };

    let (tx, rx) = mpsc::unbounded_channel();

    if enable_browse {
        match daemon.browse(BONJOUR_SERVICE_TYPE) {
            Ok(receiver) => {
                let own_id = local_device_id.clone();
                let tx_clone = tx.clone();
                std::thread::Builder::new()
                    .name("bonjour-browser".into())
                    .spawn(move || {
                        while let Ok(event) = receiver.recv() {
                            if let ServiceEvent::ServiceResolved(info) = event {
                                for hint in extract_hints_from_resolved(&info, &own_id) {
                                    if tx_clone.send(hint).is_err() {
                                        return;
                                    }
                                }
                            }
                        }
                    })
                    .ok();
            }
            Err(e) => {
                tracing::warn!("Bonjour browse failed on {}: {}", BONJOUR_SERVICE_TYPE, e);
            }
        }
    }

    BONJOUR_ACTIVE.store(true, Ordering::Release);
    tracing::info!(
        "🌐 Bonjour/mDNS discovery active on {} (browse={}, register={})",
        BONJOUR_SERVICE_TYPE,
        enable_browse,
        enable_register
    );

    if enable_register {
        tokio::spawn(async move {
            // Keep `daemon` alive for the lifetime of the registration loop
            let daemon = daemon;
            let mut last_ips: Vec<Ipv4Addr> = Vec::new();
            loop {
                let dev_id = local_device_id.clone();
                let prev_ips = last_ips.clone();
                let update_res = tokio::task::spawn_blocking(move || {
                    let ips = collect_bonjour_local_ipv4s();
                    if ips.is_empty() || ips == prev_ips {
                        return (ips, None);
                    }
                    let prof = system_info::collect_local_profile();
                    let info = build_service_info(
                        &dev_id,
                        &prof.hostname,
                        &prof.os,
                        prof.form_factor.as_str(),
                        &ips,
                    )
                    .ok();
                    (ips, info)
                })
                .await;

                if let Ok((ips, Some(info))) = update_res {
                    if let Err(e) = daemon.register(info) {
                        tracing::debug!("Bonjour register warning: {}", e);
                    } else {
                        tracing::info!(
                            "🌐 Registered Bonjour service {} with IPv4(s): {:?}",
                            BONJOUR_SERVICE_TYPE,
                            ips
                        );
                        last_ips = ips;
                    }
                }
                tokio::time::sleep(BONJOUR_IP_REFRESH_INTERVAL).await;
            }
        });
    } else {
        // Keep daemon alive for browser-only mode
        std::mem::forget(daemon);
    }

    Some(rx)
}

/// Performs an isolated one-shot Bonjour `_integrator._tcp.local.` browse (zero UDP `:58280`, zero BLE)
/// waiting up to `timeout` for a non-self Integrator peer service resolution.
pub async fn browse_once_for_bonjour_hint(
    own_device_id: &str,
    timeout: Duration,
) -> anyhow::Result<BonjourDiscoveryHint> {
    let own_id = own_device_id.to_string();
    let (tx, mut rx) = mpsc::unbounded_channel();

    let daemon = ServiceDaemon::new()
        .map_err(|e| anyhow::anyhow!("Failed to initialize Bonjour mDNS daemon: {}", e))?;
    let browse_rx = daemon
        .browse(BONJOUR_SERVICE_TYPE)
        .map_err(|e| anyhow::anyhow!("Failed to browse {}: {}", BONJOUR_SERVICE_TYPE, e))?;

    std::thread::Builder::new()
        .name("bonjour-oneshot".into())
        .spawn(move || {
            while let Ok(event) = browse_rx.recv() {
                if let ServiceEvent::ServiceResolved(info) = event {
                    for hint in extract_hints_from_resolved(&info, &own_id) {
                        if tx.send(hint).is_err() {
                            return;
                        }
                    }
                }
            }
        })
        .map_err(|e| anyhow::anyhow!("Failed to spawn Bonjour browser thread: {}", e))?;

    let result = tokio::time::timeout(timeout, async {
        rx.recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("Bonjour browser channel closed"))
    })
    .await;

    let _ = daemon.shutdown();

    match result {
        Ok(inner) => inner,
        Err(_) => anyhow::bail!(
            "Timed out after {}s waiting for a Bonjour {} service announcement",
            timeout.as_secs(),
            BONJOUR_SERVICE_TYPE
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_dns_label_handles_unicode_and_spaces() {
        assert_eq!(
            sanitize_dns_label("Manveer’s M1 MacBook Pro", "integrator"),
            "Manveers-M1-MacBook-Pro"
        );
        assert_eq!(sanitize_dns_label("HP-OMEN", "integrator"), "HP-OMEN");
        assert_eq!(sanitize_dns_label("!!!", "integrator"), "integrator");
    }

    #[test]
    fn bonjour_service_info_uses_private_integrator_type_only() {
        let ips = vec![Ipv4Addr::new(172, 20, 10, 7)];
        let info = build_service_info(
            "daf2ad95d836886e00c8c541ed4df46c",
            "HP-OMEN",
            "windows",
            "laptop",
            &ips,
        )
        .expect("ServiceInfo must construct cleanly");

        assert_eq!(info.get_type(), "_integrator._tcp.local.");
        assert_eq!(info.get_port(), CONTROL_PORT);
        assert_eq!(
            info.get_property_val_str(BONJOUR_TXT_KEY_DEVICE_ID),
            Some("daf2ad95d836886e00c8c541ed4df46c")
        );
        assert_eq!(info.get_property_val_str(BONJOUR_TXT_KEY_OS), Some("windows"));
        assert_eq!(
            info.get_property_val_str(BONJOUR_TXT_KEY_FORM_FACTOR),
            Some("laptop")
        );
        // Must never publish Apple AirPlay / AirDrop service types
        assert!(!info.get_type().contains("airplay"));
        assert!(!info.get_type().contains("raop"));
    }

    #[test]
    fn transport_priority_sort_prefers_thunderbolt_over_wifi() {
        use crate::system_info::{LinkTransport, LocalInterfaceInfo};
        let make_iface = |name: &str, ip: &str, transport: LinkTransport| LocalInterfaceInfo {
            name: name.to_string(),
            friendly_name: name.to_string(),
            ip: ip.to_string(),
            netmask: "255.255.255.0".to_string(),
            broadcast: "192.168.1.255".to_string(),
            cidr_prefix: 24,
            transport,
            link_speed_mbps: None,
            description: String::new(),
        };
        let mut ifaces = vec![
            make_iface("en0", "192.168.1.50", LinkTransport::Wifi),
            make_iface("bridge0", "10.0.0.1", LinkTransport::Thunderbolt),
        ];
        ifaces.sort_by(|a, b| a.transport.route_priority().cmp(&b.transport.route_priority()));
        assert_eq!(ifaces[0].transport, LinkTransport::Thunderbolt);
        assert_eq!(ifaces[1].transport, LinkTransport::Wifi);
    }
}
