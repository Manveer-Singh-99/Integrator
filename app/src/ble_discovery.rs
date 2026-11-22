//! # Bluetooth Low Energy (BLE) Magic-Packet Proximity Discovery (`ble_discovery.rs`)
//!
//! ## 1. Module Purpose & Scope
//! `ble_discovery.rs` implements a lightweight, privacy-masked Bluetooth Low Energy (BLE)
//! proximity beacon ("magic packet") allowing nearby macOS and Windows 11 Integrator instances
//! to exchange their current reachable IPv4 endpoint even when Wi-Fi networks block UDP
//! broadcast (`255.255.255.255` / subnet broadcast) or mDNS multicast (`224.0.0.251:5353`).
//!
//! ### Dual Cross-Platform Wire Format
//! Because macOS `CBPeripheralManager` restricts advertising packets to `ServiceUUIDs` +
//! `LocalName` (stripping `ManufacturerData`), while Windows `BluetoothLEAdvertisementPublisher`
//! publishes `ManufacturerData` (disallowing custom `LocalName` overrides), Integrator defines
//! two mathematically equivalent compact formats that BOTH platforms parse on receive:
//! 1. **17-Byte Binary Magic Packet** (advertised via Windows `ManufacturerData`, Company ID `0xFFFF`,
//!    and mirrored in macOS read-only GATT characteristic):
//!    - `[0..3]`   : ASCII magic `b"IG2"`
//!    - `[3..7]`   : First 4 bytes (8 hex chars) of sender's `device_id`
//!    - `[7..9]`   : 16-bit rotating CSPRNG anti-tracking nonce
//!    - `[9..15]`  : `([ip0, ip1, ip2, ip3, port_hi, port_lo]) XOR keystream[0..6]`
//!    - `[15..17]` : 16-bit integrity tag (`SHA256(DOMAIN_SEP || magic || dev_prefix || nonce || masked)[0..2]`)
//! 2. **27-Char ASCII LocalName Magic Packet** (advertised via macOS `CBAdvertisementDataLocalNameKey`
//!    in Scan Response alongside private 128-bit Service UUID `7A4E9C10-5B2F-4D81-9E3A-1C6F8B2D4E90`):
//!    - `"IG2"` (3) + `dev_prefix` (8 hex) + `nonce` (4 hex) + `masked_ip` (8 hex) + `tag` (4 hex) = 27 bytes
//!    - Uses canonical [`crate::config::CONTROL_PORT`] (`58281`) and fits strictly under BLE's 29-byte
//!      Scan Response Complete Local Name payload cap.
//!
//! ## 2. Architectural Linkages & Dependencies
//! ### Upstream Callers:
//! - `discovery::DiscoveryManager`: Spawns [`start_ble_discovery`] alongside UDP and Bonjour
//!   discovery, consuming [`BleDiscoveryHint`] messages and running full `TransportSessionV2`
//!   cryptographic authentication against hinted IPv4 addresses.
//! - `core::run_cli_if_requested`: Invokes [`scan_once_for_ble_hint`] for isolated BLE-only
//!   authentication verification (`integrator discovery auth-via-ble`).
//!
//! ### Downstream Callees:
//! - macOS: `src/ble_macos.swift` (`CoreBluetooth` C FFI).
//! - Windows 11: WinRT `Windows.Devices.Bluetooth.Advertisement` via the `windows` crate.
//! - `sha2::Sha256` + `getrandom`: Keystream masking and rotating anti-tracking nonce generation.
//!
//! ### Cross-Platform / Cross-Device Flow:
//! - **macOS -> Windows 11**: macOS encodes its highest-priority local IPv4 + port into a
//!   128-bit `ADV_IND` Service UUID (`7A4E...`) and a 27-char `SCAN_RSP` `LocalName` (`IG2...`).
//!   Windows `BluetoothLEAdvertisementWatcher` (in `Active` scan mode) decodes either format and
//!   initiates an authenticated `TransportSessionV2` TCP handshake to the Mac's IPv4 address.
//! - **Windows 11 -> macOS**: Windows publishes a 17-byte `ManufacturerData` payload (`0xFFFF` +
//!   `IG2`). macOS `CBCentralManager` (`withServices: nil`) captures the packet, verifies its
//!   16-bit SHA-256 tag, unmasks the PC's IPv4 + port, and initiates an authenticated
//!   `TransportSessionV2` TCP handshake to the PC.
//!
//! ## 3. Threading & Concurrency Model
//! - Platform BLE callbacks run on OS-managed radio dispatch threads (macOS `com.integrator.ble`
//!   serial GCD queue; Windows WinRT MTA callback threadpool) and push hints locklessly into a
//!   bounded/unbounded Tokio channel (`mpsc::UnboundedSender<BleDiscoveryHint>`).
//! - A Tokio background task refreshes the rotating nonce and active best local IPv4 every
//!   [`crate::config::BLE_PAYLOAD_REFRESH_SECS`] seconds.
//!
//! ## 4. Security & Safety Invariants
//! - **Zero Trust Bypass**: BLE beacons are strictly untrusted reachability hints. Every decoded
//!   IP MUST pass full mutual Ed25519 + X25519 + ChaCha20-Poly1305 `TransportSessionV2`
//!   authentication before any peer metadata is trusted or accepted.
//! - **Zero Apple Interference**: Uses private RFC 4122 v4 Service UUID and Company ID `0xFFFF`
//!   (never Apple's `0x004C`), preventing any interaction with AirDrop, Handoff, or Apple TV.
//! - **Endpoint Sanitization**: Decoded hints rejecting loopback, unspecified (`0.0.0.0`),
//!   broadcast (`255.255.255.255`), multicast, and privileged ports (`< 1024`) are dropped at decode.

use sha2::{Digest, Sha256};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use tokio::sync::mpsc;

use crate::config::{
    BLE_LOCAL_NAME_PREFIX, BLE_MASK_DOMAIN_SEP, BLE_PACKET_MAGIC, BLE_PAYLOAD_REFRESH_SECS,
    CONTROL_PORT,
};
use crate::system_info;

/// Fixed byte length of the Integrator v2 binary BLE magic packet.
pub const BLE_BINARY_PACKET_LEN: usize = 17;

/// Fixed byte length of the Integrator v2 128-bit Service UUID BLE magic packet.
pub const BLE_UUID_PACKET_LEN: usize = 16;

/// Two-byte private UUID prefix identifying Integrator v2 BLE Service UUID magic packets (`0x7A4E`).
pub const BLE_UUID_MAGIC_PREFIX: [u8; 2] = [0x7A, 0x4E];

/// Fixed ASCII character length of the Integrator v2 LocalName BLE magic packet (`"IG2"` + 24 hex).
pub const BLE_LOCAL_NAME_LEN: usize = 27;

/// Decoded reachability hint extracted from a nearby Integrator BLE magic packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BleDiscoveryHint {
    /// First 8 lowercase hex characters (4 bytes) of the advertising device's `device_id`.
    pub device_id_prefix: String,
    /// Unmasked IPv4 address advertised by the nearby Integrator device.
    pub ip: Ipv4Addr,
    /// Control RPC TCP port advertised by the nearby Integrator device.
    pub port: u16,
    /// Observed Bluetooth LE signal strength in dBm (e.g., `-52`).
    pub rssi: i16,
    /// Wire format from which this hint was decoded (`"ble-mfg"` or `"ble-name"`).
    pub format: &'static str,
}

/// Global flag reflecting whether the BLE discovery subsystem is currently active.
static BLE_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Returns `true` if BLE advertising/scanning was successfully started on this machine.
pub fn is_ble_active() -> bool {
    BLE_ACTIVE.load(Ordering::Acquire)
}

/// Generates a fresh 2-byte CSPRNG nonce for BLE magic-packet obfuscation.
fn random_nonce_2() -> [u8; 2] {
    let mut nonce = [0u8; 2];
    let _ = getrandom::fill(&mut nonce);
    nonce
}

/// Parses the first 4 bytes (8 hex chars) of a device ID hex string.
fn parse_device_prefix_4(device_id_hex: &str) -> Option<[u8; 4]> {
    let trimmed = device_id_hex.trim();
    if trimmed.len() < 8 {
        return None;
    }
    let bytes = trimmed.as_bytes();
    let mut out = [0u8; 4];
    for i in 0..4 {
        let hi = hex_nibble(bytes[i * 2])?;
        let lo = hex_nibble(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

/// Decodes a single ASCII hex character into its 4-bit value.
#[inline]
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Encodes a byte slice as lowercase ASCII hexadecimal.
fn bytes_to_hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}

/// Decodes an exact-length ASCII hexadecimal string into bytes.
fn hex_to_bytes<const N: usize>(hex_str: &str) -> Option<[u8; N]> {
    let raw = hex_str.as_bytes();
    if raw.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for i in 0..N {
        let hi = hex_nibble(raw[i * 2])?;
        let lo = hex_nibble(raw[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

/// Derives the 6-byte XOR mask keystream for `(dev_prefix, nonce)`.
fn derive_mask_keystream(dev_prefix: &[u8; 4], nonce: &[u8; 2]) -> [u8; 6] {
    let mut hasher = Sha256::new();
    hasher.update(BLE_MASK_DOMAIN_SEP);
    hasher.update(dev_prefix);
    hasher.update(nonce);
    let digest = hasher.finalize();
    let mut ks = [0u8; 6];
    ks.copy_from_slice(&digest[..6]);
    ks
}

/// Computes the 2-byte integrity tag over `(mode_tag, dev_prefix, nonce, masked_payload)`.
fn compute_integrity_tag(
    mode_tag: u8,
    dev_prefix: &[u8; 4],
    nonce: &[u8; 2],
    masked_payload: &[u8],
) -> [u8; 2] {
    let mut hasher = Sha256::new();
    hasher.update(BLE_MASK_DOMAIN_SEP);
    hasher.update([mode_tag]);
    hasher.update(BLE_PACKET_MAGIC);
    hasher.update(dev_prefix);
    hasher.update(nonce);
    hasher.update(masked_payload);
    let digest = hasher.finalize();
    [digest[0], digest[1]]
}

/// Validates that a decoded BLE IPv4 endpoint is a plausible unicast peer address and non-privileged port.
fn is_valid_ble_endpoint(ip: Ipv4Addr, port: u16) -> bool {
    !ip.is_loopback()
        && !ip.is_unspecified()
        && !ip.is_broadcast()
        && !ip.is_multicast()
        && port >= 1024
}

/// Encodes a 17-byte binary Integrator v2 BLE magic packet (used in Windows ManufacturerData & macOS GATT).
pub fn encode_ble_binary_packet(
    device_id_hex: &str,
    ip: Ipv4Addr,
    port: u16,
    nonce: [u8; 2],
) -> Option<[u8; BLE_BINARY_PACKET_LEN]> {
    if !is_valid_ble_endpoint(ip, port) {
        return None;
    }
    let dev_prefix = parse_device_prefix_4(device_id_hex)?;
    let ks = derive_mask_keystream(&dev_prefix, &nonce);

    let octets = ip.octets();
    let port_be = port.to_be_bytes();
    let plain = [octets[0], octets[1], octets[2], octets[3], port_be[0], port_be[1]];
    let mut masked = [0u8; 6];
    for i in 0..6 {
        masked[i] = plain[i] ^ ks[i];
    }
    let tag = compute_integrity_tag(0x01, &dev_prefix, &nonce, &masked);

    let mut pkt = [0u8; BLE_BINARY_PACKET_LEN];
    pkt[0..3].copy_from_slice(&BLE_PACKET_MAGIC);
    pkt[3..7].copy_from_slice(&dev_prefix);
    pkt[7..9].copy_from_slice(&nonce);
    pkt[9..15].copy_from_slice(&masked);
    pkt[15..17].copy_from_slice(&tag);
    Some(pkt)
}

/// Decodes and validates a 17-byte binary Integrator v2 BLE magic packet.
pub fn decode_ble_binary_packet(data: &[u8], rssi: i16) -> Option<BleDiscoveryHint> {
    if data.len() < BLE_BINARY_PACKET_LEN || data[0..3] != BLE_PACKET_MAGIC {
        return None;
    }
    let mut dev_prefix = [0u8; 4];
    dev_prefix.copy_from_slice(&data[3..7]);
    let mut nonce = [0u8; 2];
    nonce.copy_from_slice(&data[7..9]);
    let masked = &data[9..15];
    let expected_tag = compute_integrity_tag(0x01, &dev_prefix, &nonce, masked);
    if data[15..17] != expected_tag {
        return None;
    }

    let ks = derive_mask_keystream(&dev_prefix, &nonce);
    let mut plain = [0u8; 6];
    for i in 0..6 {
        plain[i] = masked[i] ^ ks[i];
    }
    let ip = Ipv4Addr::new(plain[0], plain[1], plain[2], plain[3]);
    let port = u16::from_be_bytes([plain[4], plain[5]]);
    if !is_valid_ble_endpoint(ip, port) {
        return None;
    }

    Some(BleDiscoveryHint {
        device_id_prefix: bytes_to_hex_lower(&dev_prefix),
        ip,
        port,
        rssi,
        format: "ble-mfg",
    })
}

/// Encodes a 16-byte (128-bit) Service UUID Integrator v2 BLE magic packet transmitted directly
/// inside `ADV_IND` (`CBAdvertisementDataServiceUUIDsKey`), avoiding `SCAN_RSP` name truncation.
///
/// Layout (16 bytes big-endian):
/// - `[0..2]`   : `[0x7A, 0x4E]` private namespace prefix
/// - `[2..6]`   : 4-byte `device_id` prefix
/// - `[6..8]`   : 2-byte rotating CSPRNG nonce
/// - `[8..14]`  : 6-byte XOR-masked `[ip0, ip1, ip2, ip3, port_hi, port_lo]`
/// - `[14..16]` : 2-byte SHA-256 integrity tag (mode `0x03`)
pub fn encode_ble_service_uuid_bytes(
    device_id_hex: &str,
    ip: Ipv4Addr,
    port: u16,
    nonce: [u8; 2],
) -> Option<[u8; BLE_UUID_PACKET_LEN]> {
    if !is_valid_ble_endpoint(ip, port) {
        return None;
    }
    let dev_prefix = parse_device_prefix_4(device_id_hex)?;
    let ks = derive_mask_keystream(&dev_prefix, &nonce);

    let octets = ip.octets();
    let port_be = port.to_be_bytes();
    let plain = [octets[0], octets[1], octets[2], octets[3], port_be[0], port_be[1]];
    let mut masked = [0u8; 6];
    for i in 0..6 {
        masked[i] = plain[i] ^ ks[i];
    }
    let tag = compute_integrity_tag(0x03, &dev_prefix, &nonce, &masked);

    let mut out = [0u8; BLE_UUID_PACKET_LEN];
    out[0..2].copy_from_slice(&BLE_UUID_MAGIC_PREFIX);
    out[2..6].copy_from_slice(&dev_prefix);
    out[6..8].copy_from_slice(&nonce);
    out[8..14].copy_from_slice(&masked);
    out[14..16].copy_from_slice(&tag);
    Some(out)
}

/// Formats a 16-byte big-endian payload into a canonical hyphenated 128-bit UUID string.
pub fn format_uuid_128(bytes: &[u8; BLE_UUID_PACKET_LEN]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

/// Reassembles WinRT/Win32 `GUID` fields `(data1, data2, data3, data4)` into canonical 16 big-endian UUID bytes.
#[cfg(any(target_os = "windows", test))]
pub(crate) fn guid_fields_to_be_bytes(
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
) -> [u8; BLE_UUID_PACKET_LEN] {
    let mut out = [0u8; BLE_UUID_PACKET_LEN];
    out[0..4].copy_from_slice(&data1.to_be_bytes());
    out[4..6].copy_from_slice(&data2.to_be_bytes());
    out[6..8].copy_from_slice(&data3.to_be_bytes());
    out[8..16].copy_from_slice(&data4);
    out
}

/// Decodes and validates a 16-byte Integrator v2 128-bit Service UUID magic packet.
pub fn decode_ble_service_uuid_bytes(
    data: &[u8; BLE_UUID_PACKET_LEN],
    rssi: i16,
) -> Option<BleDiscoveryHint> {
    if data[0..2] != BLE_UUID_MAGIC_PREFIX {
        return None;
    }
    let mut dev_prefix = [0u8; 4];
    dev_prefix.copy_from_slice(&data[2..6]);
    let mut nonce = [0u8; 2];
    nonce.copy_from_slice(&data[6..8]);
    let masked = &data[8..14];
    let expected_tag = compute_integrity_tag(0x03, &dev_prefix, &nonce, masked);
    if data[14..16] != expected_tag {
        return None;
    }

    let ks = derive_mask_keystream(&dev_prefix, &nonce);
    let mut plain = [0u8; 6];
    for i in 0..6 {
        plain[i] = masked[i] ^ ks[i];
    }
    let ip = Ipv4Addr::new(plain[0], plain[1], plain[2], plain[3]);
    let port = u16::from_be_bytes([plain[4], plain[5]]);
    if !is_valid_ble_endpoint(ip, port) {
        return None;
    }

    Some(BleDiscoveryHint {
        device_id_prefix: bytes_to_hex_lower(&dev_prefix),
        ip,
        port,
        rssi,
        format: "ble-uuid",
    })
}

/// Decodes an Integrator v2 128-bit Service UUID string (with or without hyphens).
#[allow(dead_code)]
pub fn decode_ble_service_uuid_str(uuid_str: &str, rssi: i16) -> Option<BleDiscoveryHint> {
    let compact: String = uuid_str
        .trim()
        .chars()
        .filter(|c| *c != '-')
        .collect();
    let bytes = hex_to_bytes::<BLE_UUID_PACKET_LEN>(&compact)?;
    decode_ble_service_uuid_bytes(&bytes, rssi)
}

/// Encodes a 27-character ASCII LocalName Integrator v2 BLE magic packet (used in macOS Scan Response).
pub fn encode_ble_local_name(
    device_id_hex: &str,
    ip: Ipv4Addr,
    nonce: [u8; 2],
) -> Option<String> {
    if !is_valid_ble_endpoint(ip, CONTROL_PORT) {
        return None;
    }
    let dev_prefix = parse_device_prefix_4(device_id_hex)?;
    let ks = derive_mask_keystream(&dev_prefix, &nonce);

    let octets = ip.octets();
    let mut masked_ip = [0u8; 4];
    for i in 0..4 {
        masked_ip[i] = octets[i] ^ ks[i];
    }
    let tag = compute_integrity_tag(0x02, &dev_prefix, &nonce, &masked_ip);

    let mut raw12 = [0u8; 12];
    raw12[0..4].copy_from_slice(&dev_prefix);
    raw12[4..6].copy_from_slice(&nonce);
    raw12[6..10].copy_from_slice(&masked_ip);
    raw12[10..12].copy_from_slice(&tag);

    Some(format!(
        "{}{}",
        BLE_LOCAL_NAME_PREFIX,
        bytes_to_hex_lower(&raw12)
    ))
}

/// Decodes and validates a 27-character ASCII LocalName Integrator v2 BLE magic packet.
pub fn decode_ble_local_name(name: &str, rssi: i16) -> Option<BleDiscoveryHint> {
    let trimmed = name.trim();
    if trimmed.len() != BLE_LOCAL_NAME_LEN || !trimmed.starts_with(BLE_LOCAL_NAME_PREFIX) {
        return None;
    }
    let hex_part = &trimmed[BLE_LOCAL_NAME_PREFIX.len()..];
    let raw = hex_to_bytes::<12>(hex_part)?;

    let mut dev_prefix = [0u8; 4];
    dev_prefix.copy_from_slice(&raw[0..4]);
    let mut nonce = [0u8; 2];
    nonce.copy_from_slice(&raw[4..6]);
    let masked_ip = &raw[6..10];
    let expected_tag = compute_integrity_tag(0x02, &dev_prefix, &nonce, masked_ip);
    if raw[10..12] != expected_tag {
        return None;
    }

    let ks = derive_mask_keystream(&dev_prefix, &nonce);
    let ip = Ipv4Addr::new(
        masked_ip[0] ^ ks[0],
        masked_ip[1] ^ ks[1],
        masked_ip[2] ^ ks[2],
        masked_ip[3] ^ ks[3],
    );
    if !is_valid_ble_endpoint(ip, CONTROL_PORT) {
        return None;
    }

    Some(BleDiscoveryHint {
        device_id_prefix: bytes_to_hex_lower(&dev_prefix),
        ip,
        port: CONTROL_PORT,
        rssi,
        format: "ble-name",
    })
}

/// Selects the highest-priority active local IPv4 address suitable for BLE advertisement.
///
/// Ranks active non-virtual interfaces by [`system_info::LinkTransport::route_priority`]
/// (smaller value = higher priority: Thunderbolt > USB-C > Ethernet > Wi-Fi > Hotspot) and prefers
/// a local Mobile Hotspot gateway (`192.168.137.1`) over an upstream client Wi-Fi interface when
/// hosting a hotspot.
pub fn select_best_advertisable_ipv4() -> Option<Ipv4Addr> {
    let mut ifaces = system_info::list_local_ipv4_interfaces();
    ifaces.sort_by(|a, b| {
        let a_is_ics_host = a.ip.starts_with("192.168.137.");
        let b_is_ics_host = b.ip.starts_with("192.168.137.");
        a.transport
            .route_priority()
            .cmp(&b.transport.route_priority())
            .then_with(|| b_is_ics_host.cmp(&a_is_ics_host))
    });
    for iface in ifaces {
        if let Ok(ip) = iface.ip.parse::<Ipv4Addr>() {
            if is_valid_ble_endpoint(ip, CONTROL_PORT) {
                return Some(ip);
            }
        }
    }
    None
}

// ============================================================================
// Platform Native BLE Bridge (macOS CoreBluetooth / Windows WinRT)
// ============================================================================

/// Global sender slot receiving decoded BLE hints from OS native callbacks.
static BLE_HINT_TX: OnceLock<Mutex<Option<mpsc::UnboundedSender<BleDiscoveryHint>>>> =
    OnceLock::new();

fn ble_hint_tx_slot() -> &'static Mutex<Option<mpsc::UnboundedSender<BleDiscoveryHint>>> {
    BLE_HINT_TX.get_or_init(|| Mutex::new(None))
}

fn dispatch_ble_hint(hint: BleDiscoveryHint) {
    if let Ok(guard) = ble_hint_tx_slot().lock() {
        if let Some(ref tx) = *guard {
            let _ = tx.send(hint);
        }
    }
}

#[cfg(target_os = "macos")]
mod macos_ble {
    use super::*;
    use std::ffi::{CStr, CString};
    use std::os::raw::c_char;

    type BinaryCb = extern "C" fn(*const u8, usize, i16);
    type NameCb = extern "C" fn(*const c_char, i16);

    extern "C" {
        fn integrator_mac_ble_start(
            enable_scan: bool,
            enable_advertise: bool,
            binary_cb: Option<BinaryCb>,
            name_cb: Option<NameCb>,
        ) -> bool;
        fn integrator_mac_ble_update_advertisement(
            service_uuid_ptr: *const c_char,
            local_name_ptr: *const c_char,
            bin_ptr: *const u8,
            bin_len: usize,
        );
        fn integrator_mac_ble_stop();
        pub(crate) fn integrator_mac_ble_auth_status() -> i32;
    }

    extern "C" fn on_binary_packet(ptr: *const u8, len: usize, rssi: i16) {
        if ptr.is_null() || len < BLE_UUID_PACKET_LEN || len > 64 {
            return;
        }
        // SAFETY: Swift CoreBluetooth callback provides a valid buffer of `len` bytes for the call duration.
        let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
        if len == BLE_UUID_PACKET_LEN {
            let mut uuid_bytes = [0u8; BLE_UUID_PACKET_LEN];
            uuid_bytes.copy_from_slice(slice);
            if let Some(hint) = decode_ble_service_uuid_bytes(&uuid_bytes, rssi) {
                dispatch_ble_hint(hint);
                return;
            }
        }
        if let Some(hint) = decode_ble_binary_packet(slice, rssi) {
            dispatch_ble_hint(hint);
        }
    }

    extern "C" fn on_local_name(ptr: *const c_char, rssi: i16) {
        if ptr.is_null() {
            return;
        }
        // SAFETY: Swift `withCString` provides a valid NUL-terminated UTF-8 string for the call duration.
        if let Ok(name) = unsafe { CStr::from_ptr(ptr) }.to_str() {
            if let Some(hint) = decode_ble_local_name(name, rssi) {
                dispatch_ble_hint(hint);
            } else if let Some(hint) = decode_ble_service_uuid_str(name, rssi) {
                dispatch_ble_hint(hint);
            }
        }
    }

    pub fn start_platform(enable_scan: bool, enable_advertise: bool) -> bool {
        unsafe {
            integrator_mac_ble_start(
                enable_scan,
                enable_advertise,
                if enable_scan {
                    Some(on_binary_packet)
                } else {
                    None
                },
                if enable_scan {
                    Some(on_local_name)
                } else {
                    None
                },
            )
        }
    }

    pub fn update_platform_advertisement(
        service_uuid: &str,
        local_name: &str,
        binary_pkt: &[u8; BLE_BINARY_PACKET_LEN],
    ) {
        if let (Ok(c_uuid), Ok(c_name)) = (CString::new(service_uuid), CString::new(local_name)) {
            unsafe {
                integrator_mac_ble_update_advertisement(
                    c_uuid.as_ptr(),
                    c_name.as_ptr(),
                    binary_pkt.as_ptr(),
                    binary_pkt.len(),
                );
            }
        }
    }

    pub fn stop_platform() {
        unsafe {
            integrator_mac_ble_stop();
        }
    }
}

#[cfg(target_os = "macos")]
pub fn macos_bluetooth_auth_status() -> i32 {
    unsafe { macos_ble::integrator_mac_ble_auth_status() }
}

/// Returns `-1` on non-macOS platforms where CoreBluetooth TCC authorization is not applicable.
#[cfg(not(target_os = "macos"))]
pub fn macos_bluetooth_auth_status() -> i32 {
    -1
}

#[cfg(target_os = "windows")]
mod windows_ble {
    use super::*;
    use crate::config::BLE_MANUFACTURER_COMPANY_ID;
    use windows::Devices::Bluetooth::Advertisement::{
        BluetoothLEAdvertisementPublisher, BluetoothLEAdvertisementReceivedEventArgs,
        BluetoothLEAdvertisementWatcher, BluetoothLEManufacturerData, BluetoothLEScanningMode,
    };
    use windows::Foundation::TypedEventHandler;
    use windows::Storage::Streams::{DataReader, DataWriter};

    /// Holds live WinRT BLE publisher and watcher COM objects for the process lifetime.
    struct WinBleHandles {
        publisher: Option<BluetoothLEAdvertisementPublisher>,
        watcher: Option<BluetoothLEAdvertisementWatcher>,
    }

    // SAFETY: WinRT agile objects (`BluetoothLEAdvertisementPublisher` and `Watcher`) are marshaling-agile
    // and safe to store inside a synchronized `Mutex`.
    unsafe impl Send for WinBleHandles {}

    static WIN_BLE: OnceLock<Mutex<Option<WinBleHandles>>> = OnceLock::new();

    fn win_ble_slot() -> &'static Mutex<Option<WinBleHandles>> {
        WIN_BLE.get_or_init(|| Mutex::new(None))
    }

    pub fn start_platform(enable_scan: bool, enable_advertise: bool) -> bool {
        let mut watcher_opt = None;
        if enable_scan {
            match BluetoothLEAdvertisementWatcher::new() {
                Ok(watcher) => {
                    // Active scanning is required so Windows sends SCAN_REQ and receives macOS SCAN_RSP LocalName!
                    let _ = watcher.SetScanningMode(BluetoothLEScanningMode::Active);
                    let handler = TypedEventHandler::<
                        BluetoothLEAdvertisementWatcher,
                        BluetoothLEAdvertisementReceivedEventArgs,
                    >::new(|_sender, args_opt| {
                        if let Some(args) = args_opt {
                            let rssi = args.RawSignalStrengthInDBm().unwrap_or(-127);
                            if let Ok(adv) = args.Advertisement() {
                                // 1. Parse 128-bit Service UUIDs (`7a4e...` ADV_IND magic packet from macOS)
                                if let Ok(uuid_list) = adv.ServiceUuids() {
                                    let count = uuid_list.Size().unwrap_or(0);
                                    for i in 0..count {
                                        if let Ok(guid) = uuid_list.GetAt(i) {
                                            let be = guid_fields_to_be_bytes(
                                                guid.data1,
                                                guid.data2,
                                                guid.data3,
                                                guid.data4,
                                            );
                                            if let Some(hint) =
                                                decode_ble_service_uuid_bytes(&be, rssi)
                                            {
                                                dispatch_ble_hint(hint);
                                            }
                                        }
                                    }
                                }
                                // 2. Parse LocalName (`IG2...` Scan Response fallback from macOS)
                                if let Ok(local_name) = adv.LocalName() {
                                    let name_str = local_name.to_string_lossy();
                                    if name_str.starts_with(BLE_LOCAL_NAME_PREFIX) {
                                        if let Some(hint) = decode_ble_local_name(&name_str, rssi) {
                                            dispatch_ble_hint(hint);
                                        }
                                    }
                                }
                                // 3. Parse ManufacturerData (CompanyId 0xFFFF + 17-byte IG2 from Windows)
                                if let Ok(mfg_list) = adv.ManufacturerData() {
                                    let count = mfg_list.Size().unwrap_or(0);
                                    for i in 0..count {
                                        if let Ok(item) = mfg_list.GetAt(i) {
                                            if item.CompanyId().unwrap_or(0)
                                                == BLE_MANUFACTURER_COMPANY_ID
                                            {
                                                if let Ok(buf) = item.Data() {
                                                    let len = buf.Length().unwrap_or(0) as usize;
                                                    if (BLE_BINARY_PACKET_LEN..=64).contains(&len) {
                                                        if let Ok(reader) =
                                                            DataReader::FromBuffer(&buf)
                                                        {
                                                            let mut raw = vec![0u8; len];
                                                            if reader.ReadBytes(&mut raw).is_ok() {
                                                                if let Some(hint) =
                                                                    decode_ble_binary_packet(
                                                                        &raw, rssi,
                                                                    )
                                                                {
                                                                    dispatch_ble_hint(hint);
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Ok(())
                    });
                    if watcher.Received(&handler).is_ok() && watcher.Start().is_ok() {
                        watcher_opt = Some(watcher);
                    } else {
                        tracing::warn!("Windows BLE watcher failed to start (Bluetooth radio may be off)");
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to construct Windows BluetoothLEAdvertisementWatcher: {}", e);
                }
            }
        }

        let started_ok = watcher_opt.is_some() || enable_advertise;
        if let Ok(mut guard) = win_ble_slot().lock() {
            *guard = Some(WinBleHandles {
                publisher: None,
                watcher: watcher_opt,
            });
        }
        started_ok
    }

    pub fn update_platform_advertisement(
        _service_uuid: &str,
        _local_name: &str,
        binary_pkt: &[u8; BLE_BINARY_PACKET_LEN],
    ) {
        let Ok(mut guard) = win_ble_slot().lock() else {
            return;
        };
        let Some(ref mut handles) = *guard else {
            return;
        };

        // Stop previous publisher before publishing fresh rotating nonce / IP payload
        if let Some(prev) = handles.publisher.take() {
            let _ = prev.Stop();
        }

        let Ok(publisher) = BluetoothLEAdvertisementPublisher::new() else {
            return;
        };
        let Ok(adv) = publisher.Advertisement() else {
            return;
        };
        let Ok(mfg_list) = adv.ManufacturerData() else {
            return;
        };
        let Ok(writer) = DataWriter::new() else {
            return;
        };
        if writer.WriteBytes(binary_pkt).is_err() {
            return;
        }
        let Ok(buf) = writer.DetachBuffer() else {
            return;
        };
        let Ok(mfg) = BluetoothLEManufacturerData::Create(BLE_MANUFACTURER_COMPANY_ID, &buf) else {
            return;
        };
        if mfg_list.Append(&mfg).is_err() {
            return;
        }
        if let Err(e) = publisher.Start() {
            tracing::debug!("Windows BLE advertisement publisher start skipped: {}", e);
            return;
        }
        handles.publisher = Some(publisher);
    }

    pub fn stop_platform() {
        if let Ok(mut guard) = win_ble_slot().lock() {
            if let Some(handles) = guard.take() {
                if let Some(p) = handles.publisher {
                    let _ = p.Stop();
                }
                if let Some(w) = handles.watcher {
                    let _ = w.Stop();
                }
            }
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
mod fallback_ble {
    use super::*;
    pub fn start_platform(_enable_scan: bool, _enable_advertise: bool) -> bool {
        false
    }
    pub fn update_platform_advertisement(
        _service_uuid: &str,
        _local_name: &str,
        _binary_pkt: &[u8; BLE_BINARY_PACKET_LEN],
    ) {}
    pub fn stop_platform() {}
}

#[cfg(target_os = "macos")]
use macos_ble as platform_ble;
#[cfg(target_os = "windows")]
use windows_ble as platform_ble;
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
use fallback_ble as platform_ble;

/// Starts background BLE magic-packet advertising and scanning, returning a receiver of decoded hints.
///
/// The background refresh loop updates the advertised IPv4 and rotates the 16-bit anti-tracking
/// nonce every [`BLE_PAYLOAD_REFRESH_SECS`] seconds.
pub fn start_ble_discovery(
    local_device_id: String,
    enable_scan: bool,
    enable_advertise: bool,
) -> Option<mpsc::UnboundedReceiver<BleDiscoveryHint>> {
    let (tx, rx) = mpsc::unbounded_channel();
    if let Ok(mut slot) = ble_hint_tx_slot().lock() {
        *slot = Some(tx);
    }

    if !platform_ble::start_platform(enable_scan, enable_advertise) {
        tracing::warn!("BLE magic-packet discovery could not initialize on this host");
        BLE_ACTIVE.store(false, Ordering::Release);
        return None;
    }

    BLE_ACTIVE.store(true, Ordering::Release);
    tracing::info!(
        "📶 BLE magic-packet discovery active (scan={}, advertise={})",
        enable_scan,
        enable_advertise
    );

    if enable_advertise {
        tokio::spawn(async move {
            loop {
                let dev_id = local_device_id.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    if let Some(best_ip) = select_best_advertisable_ipv4() {
                        let nonce = random_nonce_2();
                        if let (Some(uuid_bytes), Some(local_name), Some(bin_pkt)) = (
                            encode_ble_service_uuid_bytes(&dev_id, best_ip, CONTROL_PORT, nonce),
                            encode_ble_local_name(&dev_id, best_ip, nonce),
                            encode_ble_binary_packet(&dev_id, best_ip, CONTROL_PORT, nonce),
                        ) {
                            let service_uuid = format_uuid_128(&uuid_bytes);
                            platform_ble::update_platform_advertisement(
                                &service_uuid,
                                &local_name,
                                &bin_pkt,
                            );
                        }
                    }
                })
                .await;
                tokio::time::sleep(Duration::from_secs(BLE_PAYLOAD_REFRESH_SECS)).await;
            }
        });
    }

    Some(rx)
}

/// Performs an isolated one-shot BLE scan (zero UDP, zero Bonjour) waiting up to `timeout`
/// for a nearby non-self Integrator BLE magic packet.
pub async fn scan_once_for_ble_hint(
    own_device_id: &str,
    timeout: Duration,
) -> anyhow::Result<BleDiscoveryHint> {
    let own_prefix = own_device_id
        .trim()
        .to_ascii_lowercase()
        .chars()
        .take(8)
        .collect::<String>();

    let (tx, mut rx) = mpsc::unbounded_channel();
    let prev_tx = {
        let mut slot = ble_hint_tx_slot().lock().unwrap_or_else(|e| e.into_inner());
        slot.replace(tx)
    };

    if !platform_ble::start_platform(true, false) {
        if let Ok(mut slot) = ble_hint_tx_slot().lock() {
            *slot = prev_tx;
        }
        anyhow::bail!("Bluetooth LE scanner failed to start (ensure Bluetooth is powered on and permitted)");
    }

    let res = tokio::time::timeout(timeout, async {
        while let Some(hint) = rx.recv().await {
            if hint.device_id_prefix == own_prefix {
                continue;
            }
            return Ok(hint);
        }
        Err(anyhow::anyhow!("BLE hint channel closed unexpectedly"))
    })
    .await;

    platform_ble::stop_platform();
    if let Ok(mut slot) = ble_hint_tx_slot().lock() {
        *slot = prev_tx;
    }

    match res {
        Ok(inner) => inner,
        Err(_) => anyhow::bail!(
            "Timed out after {}s waiting for a nearby Integrator BLE magic packet",
            timeout.as_secs()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ble_binary_packet_roundtrip_and_tamper_rejection() {
        let dev_id = "d1e6a343385bd648604e3e903f9e7726";
        let ip = Ipv4Addr::new(172, 20, 10, 7);
        let nonce = [0x4B, 0x91];

        let pkt = encode_ble_binary_packet(dev_id, ip, CONTROL_PORT, nonce)
            .expect("binary BLE packet should encode");
        assert_eq!(&pkt[0..3], b"IG2");

        // Ensure raw IPv4 octets are masked (not exposed verbatim at payload offset)
        assert_ne!(&pkt[9..13], &ip.octets());

        let decoded = decode_ble_binary_packet(&pkt, -54).expect("valid packet must decode");
        assert_eq!(decoded.device_id_prefix, "d1e6a343");
        assert_eq!(decoded.ip, ip);
        assert_eq!(decoded.port, CONTROL_PORT);
        assert_eq!(decoded.rssi, -54);
        assert_eq!(decoded.format, "ble-mfg");

        // Flip 1 bit in masked IP -> integrity tag must reject
        let mut tampered = pkt;
        tampered[10] ^= 0x01;
        assert!(decode_ble_binary_packet(&tampered, -54).is_none());

        // Reject loopback and privileged ports
        assert!(encode_ble_binary_packet(dev_id, Ipv4Addr::LOCALHOST, CONTROL_PORT, nonce).is_none());
        assert!(encode_ble_binary_packet(dev_id, ip, 80, nonce).is_none());
    }

    #[test]
    fn ble_local_name_roundtrip_and_length_cap() {
        let dev_id = "daf2ad95d836886e00c8c541ed4df46c";
        let ip = Ipv4Addr::new(172, 20, 10, 2);
        let nonce = [0x12, 0xEF];

        let name = encode_ble_local_name(dev_id, ip, nonce).expect("LocalName should encode");
        assert_eq!(name.len(), BLE_LOCAL_NAME_LEN);
        assert!(name.len() <= 29, "Must fit BLE Scan Response Complete Local Name cap");
        assert!(name.starts_with("IG2"));

        let decoded = decode_ble_local_name(&name, -48).expect("valid LocalName must decode");
        assert_eq!(decoded.device_id_prefix, "daf2ad95");
        assert_eq!(decoded.ip, ip);
        assert_eq!(decoded.port, CONTROL_PORT);
        assert_eq!(decoded.rssi, -48);
        assert_eq!(decoded.format, "ble-name");

        // Tampered character must fail tag check
        let mut bad = name.into_bytes();
        bad[18] = if bad[18] == b'a' { b'b' } else { b'a' };
        let bad_str = String::from_utf8(bad).unwrap();
        assert!(decode_ble_local_name(&bad_str, -48).is_none());
    }

    #[test]
    fn ble_service_uuid_magic_packet_roundtrip_and_guid_order() {
        let dev_id = "d1e6a343385bd648604e3e903f9e7726";
        let ip = Ipv4Addr::new(172, 20, 10, 2);
        let nonce = [0x9A, 0x3C];

        let raw = encode_ble_service_uuid_bytes(dev_id, ip, CONTROL_PORT, nonce)
            .expect("128-bit UUID BLE packet should encode");
        assert_eq!(&raw[0..2], &BLE_UUID_MAGIC_PREFIX);

        let uuid_str = format_uuid_128(&raw);
        assert_eq!(uuid_str.len(), 36);

        let decoded_str = decode_ble_service_uuid_str(&uuid_str, -44)
            .expect("canonical UUID string must decode");
        assert_eq!(decoded_str.device_id_prefix, "d1e6a343");
        assert_eq!(decoded_str.ip, ip);
        assert_eq!(decoded_str.port, CONTROL_PORT);
        assert_eq!(decoded_str.rssi, -44);
        assert_eq!(decoded_str.format, "ble-uuid");

        // Verify WinRT GUID field reassembly matches canonical big-endian bytes
        let d1 = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);
        let d2 = u16::from_be_bytes([raw[4], raw[5]]);
        let d3 = u16::from_be_bytes([raw[6], raw[7]]);
        let mut d4 = [0u8; 8];
        d4.copy_from_slice(&raw[8..16]);
        let reassembled = guid_fields_to_be_bytes(d1, d2, d3, d4);
        assert_eq!(reassembled, raw);
        let decoded_guid = decode_ble_service_uuid_bytes(&reassembled, -44)
            .expect("GUID-reassembled UUID bytes must decode");
        assert_eq!(decoded_guid.ip, ip);

        // Tamper 1 bit -> rejected
        let mut bad = raw;
        bad[9] ^= 0x80;
        assert!(decode_ble_service_uuid_bytes(&bad, -44).is_none());
    }
}
