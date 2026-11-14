//! Integrator v2.0 Cryptographic Core & Cross-Platform Keystore (`app/src/security/`).
//!
//! Provides:
//! - `spake2_rfc9382`: Verbatim RFC 9382 SPAKE2 over `edwards25519` with cofactor clearing (`h = 8`),
//!   small-order torsion rejection, identity-element abort, length-prefixed `TT` transcript, and
//!   strict separation of `K`, `Ke`, `Ka`, `KcA`, `KcB`, and `K_root`.
//! - `keystore`: Cross-platform OS-backed master key management (macOS Keychain `Security.framework`,
//!   Windows Win32 DPAPI `CryptProtectData`, Linux machine-bound `0600` HKDF), `ChaCha20Poly1305`
//!   envelope encryption for Ed25519 private keys and per-peer `K_root` secrets, strict identity-key
//!   pinning, and automatic quarantine of legacy v1 `trusted_peers.json` files.

pub mod keystore;
pub mod pairing;
pub mod spake2_rfc9382;

use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

/// Fills `buf` with cryptographically secure random bytes from the OS CSPRNG (`getrandom`).
pub fn csprng_fill(buf: &mut [u8]) {
    getrandom::fill(buf).expect("OS CSPRNG (getrandom) failed to produce entropy");
}

/// Returns a fixed-size array of cryptographically secure random bytes.
pub fn csprng_array<const N: usize>() -> [u8; N] {
    let mut arr = [0u8; N];
    csprng_fill(&mut arr);
    arr
}

/// Constant-time byte slice equality check using `subtle::ConstantTimeEq`.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    bool::from(a.ct_eq(b))
}

/// Computes `SHA256(data)`.
pub fn sha256_digest(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Deterministically derives the 16-byte canonical `device_id` from an Ed25519 public key:
/// `SHA256("integrator-device-id-v2" || ed25519_pubkey)[0..16]`
pub fn derive_device_id_from_pubkey(ed25519_pubkey: &[u8; 32]) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(b"integrator-device-id-v2");
    hasher.update(ed25519_pubkey);
    let digest = hasher.finalize();
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest[0..16]);
    id
}

/// Deterministically derives the 32-character lowercase hex `device_id` from an Ed25519 public key.
pub fn derive_device_id_hex(ed25519_pubkey: &[u8; 32]) -> String {
    hex_encode(&derive_device_id_from_pubkey(ed25519_pubkey))
}

/// Derives the 16-byte `key_id` for a 32-byte per-peer `root_key`:
/// `SHA256("integrator-key-id-v2" || root_key)[0..16]`
pub fn derive_key_id(root_key: &[u8; 32]) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(b"integrator-key-id-v2");
    hasher.update(root_key);
    let digest = hasher.finalize();
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest[0..16]);
    id
}

/// Formats 4 uniform bytes into an unambiguous 6-character alphanumeric Short Authentication String (`XXX-XXX`).
pub fn format_sas_6(bytes: &[u8; 4]) -> String {
    const ALPHABET: &[u8; 32] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
    let val = u32::from_be_bytes(*bytes);
    let mut chars = [0u8; 6];
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

/// Lowercase hexadecimal encoding.
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut out, "{:02x}", b);
    }
    out
}

/// Hexadecimal decoding into `Vec<u8>`.
pub fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    let trimmed = hex.trim();
    if trimmed.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(trimmed.len() / 2);
    let bytes = trimmed.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

/// Hexadecimal decoding into a fixed-size byte array `[u8; N]`.
pub fn hex_decode_array<const N: usize>(hex: &str) -> Option<[u8; N]> {
    let vec = hex_decode(hex)?;
    if vec.len() != N {
        return None;
    }
    let mut arr = [0u8; N];
    arr.copy_from_slice(&vec);
    Some(arr)
}

pub fn unix_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn unix_epoch_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::keystore::{FixedKekProvider, KeystoreError, KeystoreV2, OsNativeKekProvider};
    use crate::security::spake2_rfc9382::{
        build_rfc9382_transcript, compute_password_salt, const_m, const_n, decode_valid_peer_share,
        derive_password_scalar, Spake2Error, Spake2Role, Spake2State, RFC9382_ED25519_M_BYTES,
        RFC9382_ED25519_N_BYTES,
    };
    use curve25519_dalek::{constants::EIGHT_TORSION, scalar::Scalar};
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
        assert!(m.is_torsion_free(), "M must be in the prime-order subgroup");
        assert!(n.is_torsion_free(), "N must be in the prime-order subgroup");
    }

    #[test]
    fn test_rfc9382_deterministic_vector_and_key_separation() {
        let pin = b"482910";
        let id_client = [0x11u8; 16];
        let id_server = [0x22u8; 16];
        let salt_pw = compute_password_salt(&id_client, &id_server);
        let id_a = b"integrator-pair-v2-A-client-context";
        let id_b = b"integrator-pair-v2-B-server-context";
        let aad = b"pair-init-and-challenge-wire-aad";

        let x = Scalar::from_bytes_mod_order([0x07u8; 32]);
        let y = Scalar::from_bytes_mod_order([0x13u8; 32]);

        let (state_a, p_a) =
            Spake2State::start_with_scalar(Spake2Role::InitiatorA, pin, &salt_pw, id_a, id_b, x)
                .expect("start_a failed");
        let (state_b, p_b) =
            Spake2State::start_with_scalar(Spake2Role::ResponderB, pin, &salt_pw, id_a, id_b, y)
                .expect("start_b failed");

        assert_ne!(p_a, p_b);

        let out_a = state_a.finish(&p_b, aad).expect("finish A failed");
        let out_b = state_b.finish(&p_a, aad).expect("finish B failed");

        // Verify both sides derive identical transcript digests and keys
        assert_eq!(*out_a.k_e, *out_b.k_e);
        assert_eq!(*out_a.k_a, *out_b.k_a);
        assert_eq!(*out_a.k_confirm_a, *out_b.k_confirm_a);
        assert_eq!(*out_a.k_confirm_b, *out_b.k_confirm_b);
        assert_eq!(out_a.confirm_mac_a, out_b.confirm_mac_a);
        assert_eq!(out_a.confirm_mac_b, out_b.confirm_mac_b);
        assert_eq!(out_a.tt_sha256, out_b.tt_sha256);

        // Verify mutual confirmation MAC checks pass
        out_b
            .verify_peer_confirm_mac(Spake2Role::InitiatorA, &out_a.confirm_mac_a)
            .expect("Server failed to verify Client F_A");
        out_a
            .verify_peer_confirm_mac(Spake2Role::ResponderB, &out_b.confirm_mac_b)
            .expect("Client failed to verify Server F_B");

        // Verify strict key separation
        assert_ne!(*out_a.k_e, *out_a.k_a, "Ke and Ka must be distinct");
        assert_ne!(
            *out_a.k_confirm_a, *out_a.k_confirm_b,
            "KcA and KcB must be distinct"
        );
        assert_ne!(
            out_a.confirm_mac_a, out_a.confirm_mac_b,
            "F_A and F_B must be distinct"
        );

        let dummy_sig_a = [0xAAu8; 64];
        let dummy_sig_b = [0xBBu8; 64];
        let app_a = out_a.derive_application_secrets(&dummy_sig_a, &dummy_sig_b);
        let app_b = out_b.derive_application_secrets(&dummy_sig_a, &dummy_sig_b);

        assert_eq!(*app_a.root_key, *app_b.root_key);
        assert_eq!(app_a.key_id, app_b.key_id);
        assert_eq!(*app_a.ack_key, *app_b.ack_key);
        assert_eq!(app_a.ack_mac, app_b.ack_mac);
        assert_eq!(app_a.sas_code, app_b.sas_code);
        assert_eq!(app_a.sas_code.len(), 7); // XXX-XXX

        // Root key must not equal Ke, Ka, KcA, KcB, or ack_key
        assert_ne!(*app_a.root_key, *out_a.k_e);
        assert_ne!(*app_a.root_key, *out_a.k_a);
        assert_ne!(*app_a.root_key, *out_a.k_confirm_a);
        assert_ne!(*app_a.root_key, *app_a.ack_key);

        // Verify RFC 9382 §3.3 8-byte little-endian length prefix structure in TT
        let k_dummy = [0x33u8; 32];
        let w_dummy = [0x44u8; 32];
        let tt = build_rfc9382_transcript(b"alice", b"bob", &p_a, &p_b, &k_dummy, &w_dummy);
        assert_eq!(&tt[0..8], &(5u64).to_le_bytes());
        assert_eq!(&tt[8..13], b"alice");
        assert_eq!(&tt[13..21], &(3u64).to_le_bytes());
        assert_eq!(&tt[21..24], b"bob");
        assert_eq!(&tt[24..32], &(32u64).to_le_bytes());
    }

    #[test]
    fn test_spake2_wrong_password_mismatch() {
        let id_client = [0x01u8; 16];
        let id_server = [0x02u8; 16];
        let salt_pw = compute_password_salt(&id_client, &id_server);
        let id_a = b"client-A";
        let id_b = b"server-B";

        let (state_a, p_a) = Spake2State::start_a(b"123456", &salt_pw, id_a, id_b).unwrap();
        let (state_b, p_b) = Spake2State::start_b(b"654321", &salt_pw, id_a, id_b).unwrap();

        let out_a = state_a.finish(&p_b, b"aad").unwrap();
        let out_b = state_b.finish(&p_a, b"aad").unwrap();

        assert_ne!(*out_a.k_e, *out_b.k_e);
        assert_eq!(
            out_b.verify_peer_confirm_mac(Spake2Role::InitiatorA, &out_a.confirm_mac_a),
            Err(Spake2Error::ConfirmationMacMismatch)
        );
        assert_eq!(
            out_a.verify_peer_confirm_mac(Spake2Role::ResponderB, &out_b.confirm_mac_b),
            Err(Spake2Error::ConfirmationMacMismatch)
        );
    }

    #[test]
    fn test_spake2_rejects_all_8_small_order_ed25519_points() {
        let salt_pw = [0x55u8; 32];
        for (idx, torsion_point) in EIGHT_TORSION.iter().enumerate() {
            let compressed = torsion_point.compress().to_bytes();
            assert_eq!(
                decode_valid_peer_share(&compressed),
                Err(Spake2Error::SmallOrderPeerShare),
                "8-torsion point {} must be rejected",
                idx
            );

            let (state_a, _) =
                Spake2State::start_a(b"999999", &salt_pw, b"idA", b"idB").unwrap();
            assert_eq!(
                state_a.finish(&compressed, b""),
                Err(Spake2Error::SmallOrderPeerShare),
                "Spake2State::finish must reject 8-torsion point {}",
                idx
            );
        }
    }

    #[test]
    fn test_spake2_rejects_identity_shared_element_k() {
        // Active small-subgroup / identity-point attack:
        // Suppose an attacker knows or guesses w (or replays w*N + T_8 where T_8 is an 8-torsion point).
        // Note that pB_malicious = w*N + T_8 is NOT a small-order point because w*N has prime order l.
        // However, when Client A unblinds pB_malicious:
        //   pB_malicious - w*N = T_8
        // Multiplying by cofactor h = 8 yields:
        //   K = 8 * x * T_8 = O (the identity point)!
        // RFC 9382 §3.2 mandates aborting when K == O.
        let pin = b"112233";
        let salt_pw = [0x77u8; 32];
        let w = derive_password_scalar(pin, &salt_pw).unwrap();

        // Construct pB_malicious = w * N + EIGHT_TORSION[4] (order-2 point + prime-order point)
        let malicious_point = (const_n() * w) + EIGHT_TORSION[4];
        assert!(
            !malicious_point.is_small_order(),
            "malicious_point itself has order 2*l, so it bypasses a naive small-order check on pB"
        );
        let malicious_bytes = malicious_point.compress().to_bytes();

        let (state_a, _) = Spake2State::start_a(pin, &salt_pw, b"idA", b"idB").unwrap();
        let res = state_a.finish(&malicious_bytes, b"aad");
        assert_eq!(
            res.err(),
            Some(Spake2Error::IdentitySharedElement),
            "Cofactor multiplication + identity check must abort when K == O"
        );
    }

    #[test]
    fn test_spake2_rejects_non_canonical_point_encoding() {
        // y = 2^255 - 1 (0x7f, 0xff, ..., 0xff) >= p = 2^255 - 19 is non-canonical.
        let mut non_canonical = [0xffu8; 32];
        non_canonical[31] = 0x7f;
        assert_eq!(
            decode_valid_peer_share(&non_canonical),
            Err(Spake2Error::NonCanonicalPeerShare)
        );
    }

    #[test]
    fn test_spake2_transcript_binding_detects_identity_or_aad_tampering() {
        let pin = b"739201";
        let salt_pw = [0x99u8; 32];
        // Client believes id_b is "server-1", Server believes id_b is "server-2" (MITM identity misbinding)
        let (state_a, p_a) =
            Spake2State::start_a(pin, &salt_pw, b"client-1", b"server-1").unwrap();
        let (state_b, p_b) =
            Spake2State::start_b(pin, &salt_pw, b"client-1", b"server-2").unwrap();

        let out_a = state_a.finish(&p_b, b"aad").unwrap();
        let out_b = state_b.finish(&p_a, b"aad").unwrap();

        assert!(out_b
            .verify_peer_confirm_mac(Spake2Role::InitiatorA, &out_a.confirm_mac_a)
            .is_err());
    }

    #[test]
    fn test_keystore_v2_roundtrip_and_aead_envelope_tamper_detection() {
        let dir = unique_temp_dir("roundtrip_tamper");
        let kek_provider = FixedKekProvider::new([0x42u8; 32]);

        let mut ks = KeystoreV2::open_with_provider(dir.clone(), &kek_provider)
            .expect("open fresh keystore");
        let local_id = ks.local_device_id();
        let local_pk = ks.local_ed25519_pubkey();
        assert_eq!(local_id, derive_device_id_from_pubkey(&local_pk));

        // Create a peer identity
        let peer_sk = SigningKey::from_bytes(&[0x5Au8; 32]);
        let peer_pk = peer_sk.verifying_key().to_bytes();
        let peer_id = derive_device_id_from_pubkey(&peer_pk);
        let peer_root = Zeroizing::new([0xC3u8; 32]);

        ks.commit_paired_peer(
            peer_id,
            peer_pk,
            peer_root.clone(),
            "HP-Omen".to_string(),
            "Windows".to_string(),
            "10.99.99.1".to_string(),
            true,
        )
        .expect("commit_paired_peer");

        // Reload from disk and verify
        let ks_reloaded = KeystoreV2::open_with_provider(dir.clone(), &kek_provider)
            .expect("reload keystore");
        assert_eq!(ks_reloaded.local_device_id(), local_id);
        assert_eq!(ks_reloaded.local_ed25519_pubkey(), local_pk);
        let loaded_peer = ks_reloaded
            .get_peer_by_id_bytes(&peer_id)
            .expect("peer must exist");
        assert_eq!(*loaded_peer.root_key, *peer_root);
        assert_eq!(loaded_peer.ed25519_pubkey, peer_pk);

        // Wrong KEK must fail AEAD unwrap
        let wrong_provider = FixedKekProvider::new([0x43u8; 32]);
        let wrong_res = KeystoreV2::open_with_provider(dir.clone(), &wrong_provider);
        assert!(matches!(
            wrong_res,
            Err(KeystoreError::AeadTamperDetected(_))
        ));

        // Tamper with the wrapped root key ciphertext in trusted_peers_v2.json
        let json_path = dir.join("trusted_peers_v2.json");
        let raw_json = std::fs::read_to_string(&json_path).unwrap();
        let mut val: serde_json::Value = serde_json::from_str(&raw_json).unwrap();
        let orig_ct = val["peers"][0]["wrapped_root_key"]["ciphertext_hex"]
            .as_str()
            .unwrap()
            .to_string();
        let mut ct_bytes = hex_decode(&orig_ct).unwrap();
        ct_bytes[0] ^= 0x01; // flip 1 bit
        val["peers"][0]["wrapped_root_key"]["ciphertext_hex"] =
            serde_json::Value::String(hex_encode(&ct_bytes));
        std::fs::write(&json_path, serde_json::to_vec_pretty(&val).unwrap()).unwrap();

        let tampered_res = KeystoreV2::open_with_provider(dir.clone(), &kek_provider);
        assert!(matches!(
            tampered_res,
            Err(KeystoreError::AeadTamperDetected(_))
        ));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_keystore_v2_identity_pinning_blocks_key_change_until_unpaired() {
        let dir = unique_temp_dir("pinning");
        let kek_provider = FixedKekProvider::new([0x71u8; 32]);
        let mut ks = KeystoreV2::open_with_provider(dir.clone(), &kek_provider).unwrap();

        let sk_1 = SigningKey::from_bytes(&[0x11u8; 32]);
        let pk_1 = sk_1.verifying_key().to_bytes();
        let id_1 = derive_device_id_from_pubkey(&pk_1);

        ks.commit_paired_peer(
            id_1,
            pk_1,
            Zeroizing::new([0xAAu8; 32]),
            "HP-Omen".to_string(),
            "Windows".to_string(),
            "10.99.99.1".to_string(),
            true,
        )
        .unwrap();

        // Attempt to pair a different Ed25519 key under the same hostname ("HP-Omen")
        let sk_2 = SigningKey::from_bytes(&[0x22u8; 32]);
        let pk_2 = sk_2.verifying_key().to_bytes();
        let id_2 = derive_device_id_from_pubkey(&pk_2);

        let conflict_res = ks.commit_paired_peer(
            id_2,
            pk_2,
            Zeroizing::new([0xBBu8; 32]),
            "HP-Omen".to_string(),
            "Windows".to_string(),
            "10.99.99.1".to_string(),
            true,
        );
        assert!(matches!(
            conflict_res,
            Err(KeystoreError::PinnedIdentityKeyMismatch { .. })
        ));

        // Attempt to claim id_1 with pk_2 (spoofed device_id)
        let spoof_res = ks.check_peer_identity_pinning(&id_1, &pk_2, "OtherHost");
        assert!(matches!(
            spoof_res,
            Err(KeystoreError::SpoofedDeviceId { .. })
        ));

        // Explicit unpair of id_1 allows pairing "HP-Omen" with pk_2
        assert!(ks.unpair_peer(&hex_encode(&id_1)).unwrap());
        ks.commit_paired_peer(
            id_2,
            pk_2,
            Zeroizing::new([0xBBu8; 32]),
            "HP-Omen".to_string(),
            "Windows".to_string(),
            "10.99.99.1".to_string(),
            true,
        )
        .expect("re-pairing after explicit unpair must succeed");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_keystore_v2_quarantines_legacy_v1_trust_file() {
        let dir = unique_temp_dir("quarantine_v1");
        let legacy_file = dir.join("trusted_peers.json");
        std::fs::write(
            &legacy_file,
            r#"{"pairing_pin":"123456","trusted_peers":[{"device_id":"old-v1","hostname":"LegacyPC","last_ip":"10.99.99.1","paired_at_epoch":1,"via_direct_cable":true,"shared_secret_hex":""}]}"#,
        )
        .unwrap();

        let kek_provider = FixedKekProvider::new([0x99u8; 32]);
        let ks = KeystoreV2::open_with_provider(dir.clone(), &kek_provider).unwrap();

        assert!(ks.was_legacy_v1_quarantined());
        assert!(!legacy_file.exists(), "legacy v1 file must be moved out of the way");
        assert!(
            dir.join("trusted_peers.json.v1.deprecated.bak").exists(),
            "quarantined backup file must exist"
        );
        assert!(
            ks.list_peers().is_empty(),
            "no legacy v1 peers may be imported as trusted"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_os_native_kek_provider_roundtrip() {
        let dir = unique_temp_dir("os_native_kek");
        let ks1 = KeystoreV2::open_with_provider(dir.clone(), &OsNativeKekProvider)
            .expect("open with OsNativeKekProvider");
        let id1 = ks1.local_device_id();
        let pk1 = ks1.local_ed25519_pubkey();

        let ks2 = KeystoreV2::open_with_provider(dir.clone(), &OsNativeKekProvider)
            .expect("reopen with OsNativeKekProvider");
        assert_eq!(ks2.local_device_id(), id1);
        assert_eq!(ks2.local_ed25519_pubkey(), pk1);

        crate::security::keystore::delete_os_kek_for_dir(&dir);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
