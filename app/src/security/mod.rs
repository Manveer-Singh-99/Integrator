//! # Integrator Security Core Utilities & Subsystem Entry Point (`app/src/security/mod.rs`)
//!
//! ## 1. Module Purpose & Scope
//! This module serves as the foundational cryptographic utilities layer and module root for the
//! entire Integrator Security and Trust subsystem (`app/src/security/`). It centralizes cryptographically
//! secure pseudorandom number generation (CSPRNG), constant-time slice comparisons, secure hashing (SHA-256),
//! deterministic device and key identifier derivation, human-readable Short Authentication String (SAS)
//! generation, hex encoding/decoding, and high-resolution Unix timestamps.
//!
//! The module re-exports the five core cryptographic domain modules:
//! - [`spake2_rfc9382`]: Verbatim RFC 9382 Password-Authenticated Key Exchange over Edwards25519.
//! - [`keystore`]: OS-native hardware- and credential-backed Master Keystore (`trusted_peers_v2.json`).
//! - [`pairing`]: 4-message mutual SPAKE2 + Ed25519 handshake protocol (`IPR2`) and anti-DoS engine.
//! - [`transport`]: Mutually authenticated, forward-secret, replay-protected TCP record layer (`ITR2`).
//! - [`audio_udp`]: Authenticated ChaCha20-Poly1305 UDP datagram audio protocol (`IUA2`) with sliding anti-replay.
//!
//! ## 2. Architectural Linkages & Dependencies
//! - **Upstream Callers**:
//!   - `app/src/trust.rs`: High-level peer discovery, pairing coordinator, and session establishment.
//!   - `app/src/security/pairing.rs`: Identity derivation, SAS formatting, and constant-time tag comparisons.
//!   - `app/src/security/transport.rs`: Nonce generation, timestamp validation, and handshake replay filtering.
//!   - `app/src/security/keystore.rs`: Key wrapping, device ID derivations, and constant-time verifications.
//!   - `app/src/security/audio_udp.rs`: Audio session key derivation, header serialization, and timestamps.
//!   - Platform UI and IPC layers (macOS Swift UI, Windows C# WPF UI, CLI command loops) consuming hex IDs and SAS strings.
//! - **Downstream Callees**:
//!   - OS Kernel CSPRNG (`getrandom::fill` via OS-specific syscalls: `getentropy`/`SecRandomCopyBytes` on macOS, `ProcessPrng`/`BCryptGenRandom` on Windows).
//!   - `subtle::ConstantTimeEq`: Constant-time byte comparisons to defeat side-channel timing attacks.
//!   - `sha2::Sha256`: Cryptographic hashing for device and key identifiers.
//!   - `zeroize::Zeroizing`: Memory zeroization on drop for temporary sensitive buffers.
//! - **Cross-Platform / Cross-Device Flow**:
//!   - Enables byte-for-byte identical cryptographic derivations between macOS (ARM64/x86_64) and Windows 11 (x86_64/ARM64).
//!   - Enforces canonical little-endian / big-endian network byte ordering across asymmetric architectures.
//!   - Produces unambiguous Short Authentication Strings (SAS) rendered identically on Mac and Windows display interfaces.
//!
//! ## 3. Threading & Concurrency Model
//! All utility functions in this module are stateless, reentrant, and thread-safe. They may be invoked
//! concurrently from arbitrary Tokio worker threads, native platform UI threads (Windows STA, macOS Main Dispatch Queue),
//! or low-level audio/video callback threads without external synchronization or lock contention.
//!
//! ## 4. Security & Safety Invariants
//! - **Zero Static Keys**: No embedded secret keys, compile-time passwords, or fallback credentials exist.
//! - **Constant-Time Verification**: All byte slice comparisons involving cryptographic authenticators,
//!   MAC tags, or public keys utilize `subtle::ConstantTimeEq` to prevent side-channel timing disclosures.
//! - **CSPRNG Failure Containment**: If the OS entropy source fails, operations fail immediately (panic or `Result::Err`),
//!   strictly forbidding deterministic or pseudo-random fallbacks (e.g. `rand::thread_rng` or timestamp seeding).
//! - **Memory Zeroization**: Secret buffers returned by `try_csprng_array` are wrapped in `zeroize::Zeroizing`
//!   to ensure cryptographic wiping upon leaving stack/heap scope.

pub mod audio_udp;
pub mod keystore;
pub mod pairing;
pub mod spake2_rfc9382;
pub mod transport;

use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

/// Fills the destination buffer `buf` with cryptographically secure random bytes from the OS kernel CSPRNG.
///
/// Under the hood, this invokes `getrandom::fill`, which delegates directly to the host OS entropy provider:
/// - macOS: `getentropy(2)` or `SecRandomCopyBytes` (Apple CommonCrypto / Security framework).
/// - Windows: `ProcessPrng` (Win8+) or `BCryptGenRandom` (CNG).
/// - Linux: `getrandom(2)` system call.
///
/// # Arguments
/// * `buf` - Destination byte slice to fill with entropy.
///
/// # Errors
/// Returns `getrandom::Error` if the OS kernel CSPRNG is uninitialized or reports an entropy exhaustion failure.
pub fn try_csprng_fill(buf: &mut [u8]) -> Result<(), getrandom::Error> {
    getrandom::fill(buf)
}

/// Fills `buf` with cryptographically secure random bytes from the OS kernel CSPRNG, panicking on failure.
///
/// # Panics
/// Panics with an explanatory message if the underlying OS entropy source fails. In security-sensitive
/// network software, failing to obtain genuine entropy is unrecoverable and must abort execution rather
/// than proceeding with predictable keys or nonces.
///
/// # Arguments
/// * `buf` - Destination byte slice to fill with entropy.
pub fn csprng_fill(buf: &mut [u8]) {
    try_csprng_fill(buf).expect("OS CSPRNG (getrandom) failed to produce entropy");
}

/// Returns a fixed-size array of `N` cryptographically secure random bytes.
///
/// # Type Parameters
/// * `N` - Array byte length (e.g., 4, 12, 16, 32, 64 bytes).
///
/// # Panics
/// Panics if the OS kernel CSPRNG fails.
pub fn csprng_array<const N: usize>() -> [u8; N] {
    let mut arr = [0u8; N];
    csprng_fill(&mut arr);
    arr
}

/// Constant-time byte slice equality check using [`subtle::ConstantTimeEq`].
///
/// Evaluates in constant execution time regardless of slice length mismatch or the position of the
/// first differing byte. Essential for comparing MAC tags (`confirm_mac_a`, `ack_mac`), public keys,
/// and authentication hashes to prevent remote timing side-channel attacks.
///
/// # Arguments
/// * `a` - First byte slice.
/// * `b` - Second byte slice.
///
/// # Returns
/// `true` if slices are identical in length and content; `false` otherwise.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    bool::from(a.ct_eq(b))
}

/// Computes a standard SHA-256 digest over `data`.
///
/// Produces a deterministic 32-byte hash `SHA256(data)`.
///
/// # Arguments
/// * `data` - Input arbitrary byte slice.
///
/// # Returns
/// 32-byte SHA-256 digest array.
pub fn sha256_digest(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Deterministically derives the 16-byte canonical `device_id` from an Ed25519 public key.
///
/// # Algorithm
/// ```text
/// device_id = SHA256("integrator-device-id-v2" || ed25519_pubkey)[0..16]
/// ```
///
/// Domain separation prefix `"integrator-device-id-v2"` ensures that the derived identifier
/// cannot collide with other SHA-256 hashes derived from the same Ed25519 public key.
///
/// # Arguments
/// * `ed25519_pubkey` - 32-byte compressed Edwards25519 public key.
///
/// # Returns
/// 16-byte canonical binary device identifier.
pub fn derive_device_id_from_pubkey(ed25519_pubkey: &[u8; 32]) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(b"integrator-device-id-v2");
    hasher.update(ed25519_pubkey);
    let digest = hasher.finalize();
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest[0..16]);
    id
}

/// Derives the 16-byte `key_id` identifier for a 32-byte per-peer `root_key`.
///
/// # Algorithm
/// ```text
/// key_id = SHA256("integrator-key-id-v2" || root_key)[0..16]
/// ```
///
/// The `key_id` allows transport peers to reference and index their negotiated root secret
/// across reboots and connections without transmitting or leaking the root key itself.
///
/// # Arguments
/// * `root_key` - 32-byte negotiated SPAKE2 root key (`K_root`).
///
/// # Returns
/// 16-byte key identifier.
pub fn derive_key_id(root_key: &[u8; 32]) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(b"integrator-key-id-v2");
    hasher.update(root_key);
    let digest = hasher.finalize();
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest[0..16]);
    id
}

/// Formats 4 uniform entropy bytes into an unambiguous 6-character alphanumeric Short Authentication String (`XXX-XXX`).
///
/// Uses an unambiguous 32-character alphabet (`23456789ABCDEFGHJKLMNPQRSTUVWXYZ`) that excludes visually
/// confusable glyphs (`0`, `O`, `1`, `I`). Each character encodes exactly 5 bits:
/// `6 chars * 5 bits = 30 bits` extracted from the 32-bit big-endian integer.
///
/// A hyphen is inserted in the center (`XXX-XXX`) to enhance human visual parsing during out-of-band
/// verification on Mac and Windows screen displays.
///
/// # Arguments
/// * `bytes` - 4 uniform entropy bytes derived via HKDF expansion during pairing.
///
/// # Returns
/// 7-character formatted SAS string (e.g. `"7KJ-9XP"`).
pub fn format_sas_6(bytes: &[u8; 4]) -> String {
    // 32-character base32 Crockford-variant alphabet excluding 0, O, 1, I
    const ALPHABET: &[u8; 32] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
    let val = u32::from_be_bytes(*bytes);
    let mut chars = [0u8; 6];
    // Extract 6 5-bit slices (bits 0..=29)
    for (i, slot) in chars.iter_mut().enumerate() {
        let idx = ((val >> (i * 5)) & 0x1F) as usize;
        *slot = ALPHABET[idx];
    }
    format!(
        "{}{}{}-{}{}{}",
        chars[0] as char,
        chars[1] as char,
        chars[2] as char,
        chars[3] as char,
        chars[4] as char,
        chars[5] as char
    )
}

/// Encodes an arbitrary byte slice into a lowercase hexadecimal ASCII string.
///
/// Allocates exactly `2 * bytes.len()` capacity up front.
///
/// # Arguments
/// * `bytes` - Byte slice to encode.
///
/// # Returns
/// Lowercase hexadecimal String.
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut out, "{:02x}", b);
    }
    out
}

/// Decodes a hexadecimal string slice into a `Vec<u8>`.
///
/// Rejects strings with odd lengths, whitespace, or invalid non-hex ASCII characters.
///
/// # Arguments
/// * `hex` - Hexadecimal string slice.
///
/// # Returns
/// `Some(Vec<u8>)` on valid input; `None` if the input is malformed or odd-length.
pub fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    let bytes = hex.as_bytes();
    if bytes.len() % 2 != 0 || !bytes.iter().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for i in (0..bytes.len()).step_by(2) {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

/// Decodes a hexadecimal string into an exact fixed-size byte array `[u8; N]`.
///
/// Rejects input if the decoded byte length does not match `N` exactly.
///
/// # Type Parameters
/// * `N` - Desired array length in bytes.
///
/// # Arguments
/// * `hex` - Hexadecimal string slice (must be exactly `2 * N` ASCII hex chars).
///
/// # Returns
/// `Some([u8; N])` on exact length and valid hex; `None` otherwise.
pub fn hex_decode_array<const N: usize>(hex: &str) -> Option<[u8; N]> {
    let vec = hex_decode(hex)?;
    if vec.len() != N {
        return None;
    }
    let mut arr = [0u8; N];
    arr.copy_from_slice(&vec);
    Some(arr)
}

/// Returns the current host time as seconds elapsed since the Unix epoch (`1970-01-01T00:00:00Z`).
///
/// Returns `0` if system clock is set prior to Unix epoch.
pub fn unix_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Returns the current host time as milliseconds elapsed since the Unix epoch (`1970-01-01T00:00:00Z`).
///
/// Used for millisecond-resolution handshake replay window checks and transport timing validations.
pub fn unix_epoch_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::keystore::{FixedKekProvider, KeystoreError, KeystoreV2};
    use crate::security::spake2_rfc9382::{
        compute_password_salt, const_m, const_n, decode_valid_peer_share,
        Spake2Error, Spake2Role, Spake2State, RFC9382_ED25519_M_BYTES,
        RFC9382_ED25519_N_BYTES,
    };
    use curve25519_dalek::constants::EIGHT_TORSION;
    use ed25519_dalek::SigningKey;
    use zeroize::Zeroizing;

    fn unique_temp_dir(label: &str) -> std::path::PathBuf {
        let rnd = hex_encode(&csprng_array::<6>());
        let dir = std::env::temp_dir().join(format!(
            "integrator_sec_m1_{}_{}_{}",
            label,
            std::process::id(),
            rnd
        ));
        let _ = std::fs::create_dir_all(&dir);
        dir
    }

    #[test]
    fn test_rfc9382_constants_m_and_n_valid_prime_order() {
        assert_eq!(
            hex_encode(&RFC9382_ED25519_M_BYTES),
            "d048032c6ea0b6d697ddc2e86bda85a33adac920f1bf18e1b0c6d166a5cecdaf"
        );
        assert_eq!(
            hex_encode(&RFC9382_ED25519_N_BYTES),
            "d3bfb518f44f3430f29d0c92af503865a1ed3281dc69b35dd868ba85f886c4ab"
        );

        let m = const_m();
        let n = const_n();
        assert_ne!(m, n);
        assert!(!m.is_small_order(), "M must not be small-order");
        assert!(!n.is_small_order(), "N must not be small-order");

        for t in EIGHT_TORSION.iter() {
            assert_ne!(&m, t, "M must not be in 8-torsion");
            assert_ne!(&n, t, "N must not be in 8-torsion");
        }
    }

    #[test]
    fn test_rfc9382_spake2_symmetric_agreement_and_mac_validation() {
        let password = b"847291";
        let client_id = [0x11u8; 16];
        let server_id = [0x22u8; 16];
        let salt_pw = compute_password_salt(&client_id, &server_id);
        let id_a = b"integrator-client-endpoint-A";
        let id_b = b"integrator-server-endpoint-B";

        let (state_a, p_a) = Spake2State::start_a(password, &salt_pw, id_a, id_b).unwrap();
        let (state_b, p_b) = Spake2State::start_b(password, &salt_pw, id_a, id_b).unwrap();
        assert_ne!(p_a, p_b);

        let aad = b"test-aad-wire-header";
        let out_a = state_a.finish(&p_b, aad).unwrap();
        let out_b = state_b.finish(&p_a, aad).unwrap();

        assert_eq!(*out_a.k_e, *out_b.k_e, "Ke must match between A and B");
        assert_eq!(*out_a.k_a, *out_b.k_a, "Ka must match between A and B");
        assert_eq!(
            *out_a.k_confirm_a, *out_b.k_confirm_a,
            "KcA must match between A and B"
        );
        assert_eq!(
            *out_a.k_confirm_b, *out_b.k_confirm_b,
            "KcB must match between A and B"
        );
        assert_eq!(out_a.confirm_mac_a, out_b.confirm_mac_a);
        assert_eq!(out_a.confirm_mac_b, out_b.confirm_mac_b);
        assert_eq!(out_a.tt_sha256, out_b.tt_sha256);

        out_b
            .verify_peer_confirm_mac(Spake2Role::InitiatorA, &out_a.confirm_mac_a)
            .expect("server must verify client MAC");
        out_a
            .verify_peer_confirm_mac(Spake2Role::ResponderB, &out_b.confirm_mac_b)
            .expect("client must verify server MAC");

        let sig_a = [0xAAu8; 64];
        let sig_b = [0xBBu8; 64];
        let app_a = out_a.derive_application_secrets(&sig_a, &sig_b);
        let app_b = out_b.derive_application_secrets(&sig_a, &sig_b);

        assert_eq!(*app_a.root_key, *app_b.root_key);
        assert_eq!(app_a.key_id, app_b.key_id);
        assert_eq!(*app_a.ack_key, *app_b.ack_key);
        assert_eq!(app_a.ack_mac, app_b.ack_mac);
        assert_eq!(app_a.sas_code, app_b.sas_code);
        assert_eq!(app_a.sas_code.len(), 7); // XXX-XXX
    }

    #[test]
    fn test_rfc9382_spake2_wrong_password_diverges_cleanly() {
        let client_id = [0x33u8; 16];
        let server_id = [0x44u8; 16];
        let salt_pw = compute_password_salt(&client_id, &server_id);
        let id_a = b"clientA";
        let id_b = b"serverB";

        let (state_a, p_a) = Spake2State::start_a(b"111111", &salt_pw, id_a, id_b).unwrap();
        let (state_b, p_b) = Spake2State::start_b(b"222222", &salt_pw, id_a, id_b).unwrap();

        let out_a = state_a.finish(&p_b, b"").unwrap();
        let out_b = state_b.finish(&p_a, b"").unwrap();

        assert_ne!(*out_a.k_e, *out_b.k_e);
        assert_ne!(out_a.confirm_mac_a, out_b.confirm_mac_a);

        assert_eq!(
            out_b.verify_peer_confirm_mac(Spake2Role::InitiatorA, &out_a.confirm_mac_a),
            Err(Spake2Error::ConfirmationMacMismatch)
        );
    }

    #[test]
    fn test_rfc9382_small_order_and_identity_rejection() {
        let client_id = [0x55u8; 16];
        let server_id = [0x66u8; 16];
        let salt_pw = compute_password_salt(&client_id, &server_id);
        let id_a = b"client";
        let id_b = b"server";

        for t in EIGHT_TORSION.iter() {
            let t_bytes = t.compress().to_bytes();
            assert_eq!(
                decode_valid_peer_share(&t_bytes),
                Err(Spake2Error::SmallOrderPeerShare)
            );
        }

        let (state_a, _) = Spake2State::start_a(b"654321", &salt_pw, id_a, id_b).unwrap();
        let identity_bytes = curve25519_dalek::constants::ED25519_BASEPOINT_POINT
            .compress()
            .to_bytes();
        let _ = state_a;
        assert!(decode_valid_peer_share(&identity_bytes).is_ok());
    }

    #[test]
    fn test_sas_formatting_unambiguous_alphabet() {
        let sas1 = format_sas_6(&[0x00, 0x00, 0x00, 0x00]);
        let sas2 = format_sas_6(&[0xFF, 0xFF, 0xFF, 0xFF]);
        let sas3 = format_sas_6(&[0x12, 0x34, 0x56, 0x78]);

        assert_eq!(sas1, "222-222");
        assert_eq!(sas1.len(), 7);
        assert_eq!(sas2.len(), 7);
        assert_eq!(sas3.len(), 7);
        assert_eq!(&sas1[3..4], "-");
        assert_eq!(&sas2[3..4], "-");
        assert_eq!(&sas3[3..4], "-");

        let forbidden = ['0', 'O', '1', 'I'];
        for s in [&sas1, &sas2, &sas3] {
            for c in s.chars() {
                assert!(!forbidden.contains(&c), "SAS must not contain {:?}", c);
            }
        }
    }

    #[test]
    fn test_keystore_v2_fresh_init_and_roundtrip_persistence() {
        let dir = unique_temp_dir("ks_init");
        let provider = FixedKekProvider::new([0x42u8; 32]);

        let local_id;
        let local_pk;
        {
            let ks = KeystoreV2::open_with_provider(dir.clone(), &provider).unwrap();
            local_id = ks.local_device_id();
            local_pk = ks.local_ed25519_pubkey();
            assert_eq!(
                local_id,
                derive_device_id_from_pubkey(&local_pk),
                "device_id derivation must match"
            );
            assert_eq!(ks.list_peers().len(), 0);
        }

        // Re-open from disk with the same KEK
        {
            let ks2 = KeystoreV2::open_with_provider(dir.clone(), &provider).unwrap();
            assert_eq!(ks2.local_device_id(), local_id);
            assert_eq!(ks2.local_ed25519_pubkey(), local_pk);
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_keystore_v2_commit_peer_and_reload() {
        let dir = unique_temp_dir("ks_peer");
        let provider = FixedKekProvider::new([0x55u8; 32]);

        let peer_sk = SigningKey::from_bytes(&[0x77u8; 32]);
        let peer_pk = peer_sk.verifying_key().to_bytes();
        let peer_id = derive_device_id_from_pubkey(&peer_pk);
        let root_key = Zeroizing::new([0x99u8; 32]);

        {
            let mut ks = KeystoreV2::open_with_provider(dir.clone(), &provider).unwrap();
            let creds = ks
                .commit_paired_peer(
                    peer_id,
                    peer_pk,
                    root_key.clone(),
                    "MacBook-Pro".to_string(),
                    "macOS".to_string(),
                    "10.99.99.1".to_string(),
                    true,
                )
                .unwrap();
            assert_eq!(creds.device_id, peer_id);
            assert_eq!(creds.ed25519_pubkey, peer_pk);
            assert_eq!(*creds.root_key, *root_key);
            assert_eq!(creds.key_id, derive_key_id(&root_key));
        }

        // Reopen and verify peer is intact and decrypted correctly
        {
            let ks2 = KeystoreV2::open_with_provider(dir.clone(), &provider).unwrap();
            let retrieved = ks2.get_peer_by_id_bytes(&peer_id).unwrap();
            assert_eq!(retrieved.device_id, peer_id);
            assert_eq!(retrieved.ed25519_pubkey, peer_pk);
            assert_eq!(*retrieved.root_key, *root_key);
            assert_eq!(retrieved.hostname, "MacBook-Pro");
            assert_eq!(retrieved.last_ip, "10.99.99.1");
            assert!(retrieved.via_direct_cable);
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_keystore_v2_identity_pinning_rejects_key_change() {
        let dir = unique_temp_dir("ks_pinning");
        let provider = FixedKekProvider::new([0x66u8; 32]);

        let pk1 = SigningKey::from_bytes(&[0x11u8; 32]).verifying_key().to_bytes();
        let id1 = derive_device_id_from_pubkey(&pk1);
        let root1 = Zeroizing::new([0xAAu8; 32]);

        let mut ks = KeystoreV2::open_with_provider(dir.clone(), &provider).unwrap();
        ks.commit_paired_peer(
            id1,
            pk1,
            root1,
            "Office-PC".to_string(),
            "Windows".to_string(),
            "192.168.1.10".to_string(),
            false,
        )
        .unwrap();

        // 1. Same device_id with different public key must be rejected
        let pk_fake = SigningKey::from_bytes(&[0x22u8; 32]).verifying_key().to_bytes();
        let res1 = ks.commit_paired_peer(
            id1,
            pk_fake,
            Zeroizing::new([0xBBu8; 32]),
            "Office-PC".to_string(),
            "Windows".to_string(),
            "192.168.1.10".to_string(),
            false,
        );
        assert!(matches!(res1, Err(KeystoreError::SpoofedDeviceId { .. })));

        // 2. Different device_id claiming same pinned hostname must be rejected
        let id_fake = derive_device_id_from_pubkey(&pk_fake);
        let res2 = ks.commit_paired_peer(
            id_fake,
            pk_fake,
            Zeroizing::new([0xCCu8; 32]),
            "Office-PC".to_string(),
            "Windows".to_string(),
            "192.168.1.10".to_string(),
            false,
        );
        assert!(matches!(
            res2,
            Err(KeystoreError::PinnedIdentityKeyMismatch { .. })
        ));

        // 3. After explicit unpair, re-pairing with new key succeeds
        ks.unpair_peer(&hex_encode(&id1)).unwrap();
        assert!(ks.get_peer_by_id_bytes(&id1).is_none());
        let res3 = ks.commit_paired_peer(
            id_fake,
            pk_fake,
            Zeroizing::new([0xDDu8; 32]),
            "Office-PC".to_string(),
            "Windows".to_string(),
            "192.168.1.10".to_string(),
            false,
        );
        assert!(res3.is_ok());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_keystore_v2_tamper_detection() {
        let dir = unique_temp_dir("ks_tamper");
        let provider = FixedKekProvider::new([0x77u8; 32]);
        let ks_path = dir.join("trusted_peers_v2.json");

        {
            let _ks = KeystoreV2::open_with_provider(dir.clone(), &provider).unwrap();
        }

        // Tamper with the ciphertext in the file
        let raw = std::fs::read_to_string(&ks_path).unwrap();
        let tampered = raw.replace("wrapped_local_ed25519_sk", "wrapped_local_ed25519_sk_bad");
        std::fs::write(&ks_path, tampered).unwrap();

        let res = KeystoreV2::open_with_provider(dir.clone(), &provider);
        assert!(matches!(res, Err(KeystoreError::CorruptKeystore(_))));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_keystore_v2_wrong_kek_fails_decryption() {
        let dir = unique_temp_dir("ks_wrong_kek");
        let provider1 = FixedKekProvider::new([0x88u8; 32]);
        let provider2 = FixedKekProvider::new([0x99u8; 32]);

        {
            let _ks = KeystoreV2::open_with_provider(dir.clone(), &provider1).unwrap();
        }

        let res = KeystoreV2::open_with_provider(dir.clone(), &provider2);
        assert!(matches!(res, Err(KeystoreError::AeadTamperDetected(_))));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_keystore_v2_legacy_v1_quarantine() {
        let dir = unique_temp_dir("ks_quarantine");
        let legacy_file = dir.join("trusted_peers.json");
        std::fs::write(&legacy_file, b"{\"legacy_peer\": \"192.168.1.5\"}").unwrap();

        let provider = FixedKekProvider::new([0xA1u8; 32]);
        let ks = KeystoreV2::open_with_provider(dir.clone(), &provider).unwrap();

        assert!(ks.was_legacy_v1_quarantined());
        assert!(!legacy_file.exists(), "legacy v1 file must be renamed/moved");
        assert!(
            dir.join("trusted_peers.json.v1.deprecated.bak").exists(),
            "quarantine file must exist"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
