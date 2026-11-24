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

/// Returns `true` if `c` is a Unicode bidirectional formatting override character.
#[inline]
fn is_bidi_format_char(c: char) -> bool {
    matches!(
        c,
        '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
    )
}

/// Strips control characters and Unicode BiDi overrides from untrusted mDNS metadata, trims
/// outer whitespace, and caps output length to `max_chars` Unicode scalar values.
fn sanitize_bonjour_text(raw: &str, max_chars: usize) -> String {
    raw.chars()
        .filter(|&c| !c.is_control() && !is_bidi_format_char(c))
        .collect::<String>()
        .trim()
        .chars()
        .take(max_chars)
        .collect()
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
///
/// # Arguments
/// * `raw` - Unsanitized local or remote hostname string.
/// * `fallback` - Default label returned if `raw` contains no ASCII alphanumeric characters.
///
/// # Returns
/// A bounded, hyphen-trimmed ASCII DNS label safe for `<label>.local.` mDNS advertisements.
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
///
/// Filters out loopback, unspecified (`0.0.0.0`), and multicast addresses and deduplicates entries
/// while preserving `LinkTransport::route_priority()` order (Thunderbolt > USB-C > Ethernet > Wi-Fi > Hotspot).
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
///
/// # Arguments
/// * `device_id` - Full hexadecimal device identity string.
/// * `hostname_raw` - Local machine hostname (sanitized to an RFC 1035 label).
/// * `os_name` - Platform identifier (`"macos"`, `"windows"`).
/// * `form_factor` - Hardware chassis form factor (`"laptop"`, `"desktop"`, `"unknown"`).
/// * `ips` - Ordered list of local IPv4 addresses to publish in mDNS A records.
///
/// # Errors
/// Returns an error if `mdns_sd::ServiceInfo::new` rejects the constructed instance or host FQDN.
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
        .filter(|c| c.is_ascii_alphanumeric())
        .take(8)
        .collect();
    // Ensure DNS label never terminates with a stray '-' if `device_id` was unexpectedly empty.
    let label_suffix = if dev_prefix.is_empty() {
        "node"
    } else {
        dev_prefix.as_str()
    };
    let host_label = sanitize_dns_label(hostname_raw, "integrator");
    let instance_name = format!("{}-{}", host_label, label_suffix);
    let host_fqdn = format!("{}-{}.local.", host_label.to_ascii_lowercase(), label_suffix);

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

/// Converts an `mdns_sd::ServiceInfo` resolution event into zero or more sanitized [`BonjourDiscoveryHint`]s.
///
/// # Security & Sanitization
/// - Drops self-advertisements matching `own_device_id`.
/// - Rejects privileged ports (`< 1024`), malformed non-hex `device_id` TXT values, and non-unicast IPv4s
///   (loopback, unspecified, broadcast, multicast).
/// - Strips control characters and Unicode BiDi formatting markers from hostname, fullname, OS, and form factor.
fn extract_hints_from_resolved(
    info: &ServiceInfo,
    own_device_id: &str,
) -> Vec<BonjourDiscoveryHint> {
    let own_lower = own_device_id.trim().to_ascii_lowercase();
    let raw_dev_id = info
        .get_property_val_str(BONJOUR_TXT_KEY_DEVICE_ID)
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty());

    if let Some(ref id) = raw_dev_id {
        if id.len() > 128 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Vec::new();
        }
    }

    // Skip our own advertisements
    if raw_dev_id.as_deref() == Some(own_lower.as_str()) {
        return Vec::new();
    }

    let port = info.get_port();
    if port < 1024 {
        return Vec::new();
    }

    let os = info
        .get_property_val_str(BONJOUR_TXT_KEY_OS)
        .map(|s| sanitize_bonjour_text(s, 64))
        .filter(|s| !s.is_empty());
    let form_factor = info
        .get_property_val_str(BONJOUR_TXT_KEY_FORM_FACTOR)
        .map(|s| sanitize_bonjour_text(s, 32))
        .filter(|s| !s.is_empty());

    let raw_host = info.get_hostname().trim_end_matches('.');
    let stripped_host = if raw_host.len() >= 6
        && raw_host[raw_host.len() - 6..].eq_ignore_ascii_case(".local")
    {
        &raw_host[..raw_host.len() - 6]
    } else {
        raw_host
    };
    let hostname = sanitize_bonjour_text(stripped_host, 128);
    let fullname = sanitize_bonjour_text(info.get_fullname(), 256);

    let mut hints = Vec::new();
    for addr in info.get_addresses_v4() {
        let ip = *addr;
        if ip.is_loopback() || ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast() {
            continue;
        }
        hints.push(BonjourDiscoveryHint {
            fullname: fullname.clone(),
            device_id: raw_dev_id.clone(),
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
///
/// # Arguments
/// * `local_device_id` - Local Ed25519 device ID hex string included in TXT records and self-filtering.
/// * `enable_browse` - When `true`, spawns a browser thread emitting remote [`BonjourDiscoveryHint`]s.
/// * `enable_register` - When `true`, periodically refreshes `_integrator._tcp.local.` registrations
///   whenever the host's active IPv4 address set changes.
///
/// # Returns
/// Returns `Some(rx)` receiving decoded remote hints, or `None` if `mdns_sd::ServiceDaemon` failed to start.
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
            // Keep `daemon` alive for the lifetime of the registration loop and shut down cleanly if receiver closes.
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
                tokio::select! {
                    _ = tx.closed() => {
                        BONJOUR_ACTIVE.store(false, Ordering::Release);
                        let _ = daemon.shutdown();
                        return;
                    }
                    _ = tokio::time::sleep(BONJOUR_IP_REFRESH_INTERVAL) => {}
                }
            }
        });
    } else {
        // Keep daemon alive for browser-only mode without leaking via `mem::forget`; shut down if receiver drops.
        tokio::spawn(async move {
            tx.closed().await;
            BONJOUR_ACTIVE.store(false, Ordering::Release);
            let _ = daemon.shutdown();
        });
    }

    Some(rx)
}

/// Performs an isolated one-shot Bonjour `_integrator._tcp.local.` browse (zero UDP `:58280`, zero BLE)
/// waiting up to `timeout` for a non-self Integrator peer service resolution.
///
/// # Arguments
/// * `own_device_id` - Local device ID hex string filtered out so self-announcements are ignored.
/// * `timeout` - Maximum wait window before returning a timeout error.
///
/// # Errors
/// Returns an error if `ServiceDaemon` fails to initialize/browse, the browser channel closes, or `timeout` elapses.
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

        // Empty device ID must not produce trailing hyphen DNS labels
        let empty_id_info = build_service_info("", "HP-OMEN", "windows", "laptop", &ips)
            .expect("ServiceInfo with empty device_id should still construct safely");
        assert!(empty_id_info.get_fullname().contains("HP-OMEN-node._integrator._tcp.local."));
    }

    #[test]
    fn sanitize_bonjour_text_strips_control_and_bidi_chars() {
        assert_eq!(sanitize_bonjour_text("  PC\u{202E}Host\x07  ", 64), "PCHost");
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
