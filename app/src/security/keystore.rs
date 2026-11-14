//! Cross-Platform OS-Backed Keystore & Identity Pinning (`trusted_peers_v2.json`).
//!
//! Architecture:
//! 1. **Layer 1 (OS Native Secret Store)**:
//!    - **macOS**: Stores the 256-bit Master Keystore Encryption Key (`K_kek`) in the macOS login
//!      Keychain via native `Security.framework` (`SecItemCopyMatching`, `SecItemAdd`, `SecItemDelete`)
//!      under service `"com.integrator.security.keystore.v2"`, account `"master-kek-v2"`.
//!    - **Windows**: Protects `K_kek` using Win32 Data Protection API (`CryptProtectData` /
//!      `CryptUnprotectData` in `crypt32.dll`) with `CRYPTPROTECT_UI_FORBIDDEN` (bound to the
//!      current Windows user logon credentials) and application-specific secondary entropy
//!      `"INTEGRATOR-WIN32-DPAPI-ENTROPY-V2"`, stored at `%LOCALAPPDATA%\Integrator\security\master_kek_v2.dpapi`.
//!    - **Linux / Other Unix**: Derives `K_kek` via HKDF-SHA256 combining `/etc/machine-id`, UID,
//!      and a mode-`0600` random key file `~/.integrator/security/master_kek_v2.key`.
//! 2. **Layer 2 (AEAD Envelope Store)**:
//!    - All long-term secrets in `trusted_peers_v2.json` (`local_ed25519_sk` and per-peer `K_root`)
//!      are individually encrypted with `ChaCha20Poly1305` under `K_kek`.
//!    - Each record's `device_id`, `ed25519_pubkey`, and `key_id` are cryptographically bound into
//!      the `ChaCha20Poly1305` AAD, preventing offline JSON tampering or public-key substitution.
//! 3. **Strict Identity-Key Pinning & Legacy Quarantine**:
//!    - `device_id` is deterministically derived from `ed25519_pubkey`.
//!    - Once a peer is pinned, any attempt to re-register or connect with a different `ed25519_pubkey`
//!      for the same `device_id` or `hostname` is rejected with `KeystoreError::PinnedIdentityKeyMismatch`
//!      until the user explicitly unpairs/forgets the peer.
//!    - Legacy v1 `trusted_peers.json` files (which lack pinned Ed25519 public keys and PAKE root keys)
//!      are automatically quarantined to `trusted_peers.json.v1.deprecated.bak` on startup.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use subtle::ConstantTimeEq;
use tracing::{info, warn};
use zeroize::Zeroizing;

pub const KEYSTORE_SCHEMA_VERSION: u32 = 2;

const AAD_LOCAL_IDENTITY_PREFIX: &[u8] = b"integrator-keystore-v2-local-id";
const AAD_PEER_ROOT_PREFIX: &[u8] = b"integrator-keystore-v2-peer-root";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeystoreError {
    OsKeystoreFailure(String),
    IoFailure(String),
    SerializationFailure(String),
    CorruptKeystore(String),
    AeadTamperDetected(String),
    SpoofedDeviceId {
        claimed_hex: String,
        derived_hex: String,
    },
    PinnedIdentityKeyMismatch {
        peer_identifier: String,
        pinned_pubkey_hex: String,
        presented_pubkey_hex: String,
    },
    PeerNotFound(String),
    PeerBlocked(String),
}

impl std::fmt::Display for KeystoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeystoreError::OsKeystoreFailure(msg) => write!(f, "OS keystore error: {}", msg),
            KeystoreError::IoFailure(msg) => write!(f, "Keystore I/O error: {}", msg),
            KeystoreError::SerializationFailure(msg) => {
                write!(f, "Keystore serialization error: {}", msg)
            }
            KeystoreError::CorruptKeystore(msg) => write!(f, "Corrupt keystore: {}", msg),
            KeystoreError::AeadTamperDetected(msg) => {
                write!(f, "Keystore AEAD integrity check failed (tampering detected): {}", msg)
            }
            KeystoreError::SpoofedDeviceId {
                claimed_hex,
                derived_hex,
            } => write!(
                f,
                "Device ID {} does not match SHA-256 derivation {} from Ed25519 public key",
                claimed_hex, derived_hex
            ),
            KeystoreError::PinnedIdentityKeyMismatch {
                peer_identifier,
                pinned_pubkey_hex,
                presented_pubkey_hex,
            } => write!(
                f,
                "Security alert: peer '{}' presented Ed25519 key {} which conflicts with pinned key {}. Explicit unpair required before re-pairing.",
                peer_identifier, presented_pubkey_hex, pinned_pubkey_hex
            ),
            KeystoreError::PeerNotFound(id) => write!(f, "Trusted peer '{}' not found", id),
            KeystoreError::PeerBlocked(id) => write!(f, "Peer '{}' is blocked", id),
        }
    }
}

impl std::error::Error for KeystoreError {}

/// Trait abstracting the OS Master Keystore Encryption Key (`K_kek`) provider.
pub trait KekProvider: Send + Sync {
    fn load_or_create_kek(&self, storage_dir: &Path) -> Result<Zeroizing<[u8; 32]>, KeystoreError>;
}

/// Default production OS KEK provider (macOS Keychain / Windows DPAPI / Linux HKDF+0600).
pub struct OsNativeKekProvider;

impl KekProvider for OsNativeKekProvider {
    fn load_or_create_kek(&self, storage_dir: &Path) -> Result<Zeroizing<[u8; 32]>, KeystoreError> {
        #[cfg(target_os = "macos")]
        {
            macos_keychain_load_or_create_kek(storage_dir)
        }
        #[cfg(target_os = "windows")]
        {
            windows_dpapi_load_or_create_kek(storage_dir)
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            unix_fallback_load_or_create_kek(storage_dir)
        }
    }
}

/// Deterministic/custom in-memory KEK provider for isolated unit and adversarial tests.
pub struct FixedKekProvider {
    kek: Zeroizing<[u8; 32]>,
}

impl FixedKekProvider {
    pub fn new(kek_bytes: [u8; 32]) -> Self {
        Self {
            kek: Zeroizing::new(kek_bytes),
        }
    }
}

impl KekProvider for FixedKekProvider {
    fn load_or_create_kek(&self, _storage_dir: &Path) -> Result<Zeroizing<[u8; 32]>, KeystoreError> {
        Ok(self.kek.clone())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AeadWrappedSecret {
    pub nonce_hex: String,
    pub ciphertext_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedPeerRecordV2 {
    pub schema_version: u32,
    pub device_id_hex: String,
    pub ed25519_pubkey_hex: String,
    pub key_id_hex: String,
    pub hostname: String,
    pub os: String,
    pub last_ip: String,
    pub paired_at_epoch: u64,
    pub via_direct_cable: bool,
    pub wrapped_root_key: AeadWrappedSecret,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeystoreFileV2 {
    pub schema_version: u32,
    pub local_device_id_hex: String,
    pub local_ed25519_pubkey_hex: String,
    pub wrapped_local_ed25519_sk: AeadWrappedSecret,
    #[serde(default)]
    pub peers: Vec<TrustedPeerRecordV2>,
    #[serde(default)]
    pub blocked_device_ids: Vec<String>,
    #[serde(default)]
    pub blocked_ips: Vec<String>,
    #[serde(default)]
    pub legacy_v1_quarantined: bool,
}

/// Verified in-memory representation of a pinned peer with its unwrapped `K_root`.
#[derive(Clone)]
pub struct VerifiedPeerCredentials {
    pub device_id: [u8; 16],
    pub device_id_hex: String,
    pub ed25519_pubkey: [u8; 32],
    pub key_id: [u8; 16],
    pub root_key: Zeroizing<[u8; 32]>,
    pub hostname: String,
    pub os: String,
    pub last_ip: String,
    pub paired_at_epoch: u64,
    pub via_direct_cable: bool,
}

impl std::fmt::Debug for VerifiedPeerCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedPeerCredentials")
            .field("device_id_hex", &self.device_id_hex)
            .field("ed25519_pubkey", &super::hex_encode(&self.ed25519_pubkey))
            .field("key_id", &super::hex_encode(&self.key_id))
            .field("hostname", &self.hostname)
            .field("last_ip", &self.last_ip)
            .finish()
    }
}

pub struct KeystoreV2 {
    storage_dir: PathBuf,
    keystore_path: PathBuf,
    kek: Zeroizing<[u8; 32]>,
    local_signing_key: SigningKey,
    local_verifying_key: VerifyingKey,
    local_device_id: [u8; 16],
    local_device_id_hex: String,
    peers: HashMap<String, VerifiedPeerCredentials>,
    blocked_device_ids: Vec<String>,
    blocked_ips: Vec<String>,
    legacy_v1_quarantined: bool,
}

impl KeystoreV2 {
    /// Opens or initializes the production v2 keystore in the default directory (`~/.integrator/security`).
    pub fn open_default() -> Result<Self, KeystoreError> {
        let dir = default_keystore_dir();
        Self::open_with_provider(dir, &OsNativeKekProvider)
    }

    /// Opens or initializes a v2 keystore in `storage_dir` using the given `KekProvider`.
    pub fn open_with_provider(
        storage_dir: PathBuf,
        provider: &dyn KekProvider,
    ) -> Result<Self, KeystoreError> {
        ensure_secure_directory(&storage_dir)?;

        // Check and quarantine any legacy v1 trusted_peers.json files.
        let quarantined = quarantine_legacy_v1_files(&storage_dir);

        let kek = provider.load_or_create_kek(&storage_dir)?;
        let keystore_path = storage_dir.join("trusted_peers_v2.json");

        if keystore_path.exists() {
            Self::load_existing(storage_dir, keystore_path, kek, quarantined)
        } else {
            Self::initialize_fresh(storage_dir, keystore_path, kek, quarantined)
        }
    }

    fn initialize_fresh(
        storage_dir: PathBuf,
        keystore_path: PathBuf,
        kek: Zeroizing<[u8; 32]>,
        legacy_v1_quarantined: bool,
    ) -> Result<Self, KeystoreError> {
        let mut sk_seed = Zeroizing::new([0u8; 32]);
        super::csprng_fill(&mut *sk_seed);
        let signing_key = SigningKey::from_bytes(&sk_seed);
        let verifying_key = signing_key.verifying_key();
        let pubkey_bytes = verifying_key.to_bytes();
        let device_id = super::derive_device_id_from_pubkey(&pubkey_bytes);
        let device_id_hex = super::hex_encode(&device_id);

        let store = Self {
            storage_dir,
            keystore_path,
            kek,
            local_signing_key: signing_key,
            local_verifying_key: verifying_key,
            local_device_id: device_id,
            local_device_id_hex: device_id_hex,
            peers: HashMap::new(),
            blocked_device_ids: Vec::new(),
            blocked_ips: Vec::new(),
            legacy_v1_quarantined,
        };
        store.persist_to_disk()?;
        Ok(store)
    }

    fn load_existing(
        storage_dir: PathBuf,
        keystore_path: PathBuf,
        kek: Zeroizing<[u8; 32]>,
        newly_quarantined: bool,
    ) -> Result<Self, KeystoreError> {
        let raw = fs::read_to_string(&keystore_path)
            .map_err(|e| KeystoreError::IoFailure(format!("read {}: {}", keystore_path.display(), e)))?;

        let parsed: KeystoreFileV2 = serde_json::from_str(&raw).map_err(|e| {
            KeystoreError::CorruptKeystore(format!("invalid JSON in {}: {}", keystore_path.display(), e))
        })?;

        if parsed.schema_version != KEYSTORE_SCHEMA_VERSION {
            return Err(KeystoreError::CorruptKeystore(format!(
                "unsupported keystore schema_version {} (expected {})",
                parsed.schema_version, KEYSTORE_SCHEMA_VERSION
            )));
        }

        let local_pk_bytes: [u8; 32] = super::hex_decode_array(&parsed.local_ed25519_pubkey_hex)
            .ok_or_else(|| KeystoreError::CorruptKeystore("invalid local_ed25519_pubkey_hex".into()))?;
        let local_id_bytes: [u8; 16] = super::hex_decode_array(&parsed.local_device_id_hex)
            .ok_or_else(|| KeystoreError::CorruptKeystore("invalid local_device_id_hex".into()))?;

        let expected_local_id = super::derive_device_id_from_pubkey(&local_pk_bytes);
        if !bool::from(local_id_bytes.ct_eq(&expected_local_id)) {
            return Err(KeystoreError::SpoofedDeviceId {
                claimed_hex: parsed.local_device_id_hex.clone(),
                derived_hex: super::hex_encode(&expected_local_id),
            });
        }

        let local_aad = build_local_identity_aad(&local_id_bytes, &local_pk_bytes);
        let sk_seed = unwrap_secret_32(&kek, &parsed.wrapped_local_ed25519_sk, &local_aad)?;
        let signing_key = SigningKey::from_bytes(&sk_seed);
        let verifying_key = signing_key.verifying_key();

        if !bool::from(verifying_key.to_bytes().ct_eq(&local_pk_bytes)) {
            return Err(KeystoreError::AeadTamperDetected(
                "unwrapped local Ed25519 secret key does not match stored public key".into(),
            ));
        }

        let mut peers = HashMap::new();
        for rec in &parsed.peers {
            if rec.schema_version != KEYSTORE_SCHEMA_VERSION {
                return Err(KeystoreError::CorruptKeystore(format!(
                    "peer '{}' has invalid schema_version {}",
                    rec.device_id_hex, rec.schema_version
                )));
            }
            let peer_id: [u8; 16] = super::hex_decode_array(&rec.device_id_hex).ok_or_else(|| {
                KeystoreError::CorruptKeystore(format!("invalid peer device_id_hex '{}'", rec.device_id_hex))
            })?;
            let peer_pk: [u8; 32] =
                super::hex_decode_array(&rec.ed25519_pubkey_hex).ok_or_else(|| {
                    KeystoreError::CorruptKeystore(format!(
                        "invalid peer ed25519_pubkey_hex for '{}'",
                        rec.device_id_hex
                    ))
                })?;
            let key_id: [u8; 16] = super::hex_decode_array(&rec.key_id_hex).ok_or_else(|| {
                KeystoreError::CorruptKeystore(format!("invalid peer key_id_hex for '{}'", rec.device_id_hex))
            })?;

            // Verify peer_pk is a valid Ed25519 public key.
            let _ = VerifyingKey::from_bytes(&peer_pk).map_err(|_| {
                KeystoreError::CorruptKeystore(format!(
                    "peer '{}' has invalid Ed25519 public key point",
                    rec.device_id_hex
                ))
            })?;

            // Verify peer device_id matches deterministic SHA-256 derivation from peer_pk.
            let derived_peer_id = super::derive_device_id_from_pubkey(&peer_pk);
            if !bool::from(peer_id.ct_eq(&derived_peer_id)) {
                return Err(KeystoreError::SpoofedDeviceId {
                    claimed_hex: rec.device_id_hex.clone(),
                    derived_hex: super::hex_encode(&derived_peer_id),
                });
            }

            // Unwrap peer root_key with AAD binding (peer_id || peer_pk || key_id).
            let peer_aad = build_peer_root_aad(&peer_id, &peer_pk, &key_id);
            let root_key = unwrap_secret_32(&kek, &rec.wrapped_root_key, &peer_aad)?;

            // Verify key_id matches SHA256("integrator-key-id-v2" || root_key)[0..16].
            let expected_key_id = super::derive_key_id(&root_key);
            if !bool::from(key_id.ct_eq(&expected_key_id)) {
                return Err(KeystoreError::AeadTamperDetected(format!(
                    "peer '{}' key_id does not match unwrapped root_key",
                    rec.device_id_hex
                )));
            }

            let canonical_id_hex = super::hex_encode(&peer_id);
            peers.insert(
                canonical_id_hex.clone(),
                VerifiedPeerCredentials {
                    device_id: peer_id,
                    device_id_hex: canonical_id_hex,
                    ed25519_pubkey: peer_pk,
                    key_id,
                    root_key,
                    hostname: rec.hostname.clone(),
                    os: rec.os.clone(),
                    last_ip: rec.last_ip.clone(),
                    paired_at_epoch: rec.paired_at_epoch,
                    via_direct_cable: rec.via_direct_cable,
                },
            );
        }

        let store = Self {
            storage_dir,
            keystore_path,
            kek,
            local_signing_key: signing_key,
            local_verifying_key: verifying_key,
            local_device_id: local_id_bytes,
            local_device_id_hex: super::hex_encode(&local_id_bytes),
            peers,
            blocked_device_ids: parsed.blocked_device_ids,
            blocked_ips: parsed.blocked_ips,
            legacy_v1_quarantined: parsed.legacy_v1_quarantined || newly_quarantined,
        };

        if newly_quarantined && !parsed.legacy_v1_quarantined {
            let _ = store.persist_to_disk();
        }

        Ok(store)
    }

    pub fn local_device_id(&self) -> [u8; 16] {
        self.local_device_id
    }

    pub fn local_device_id_hex(&self) -> &str {
        &self.local_device_id_hex
    }

    pub fn local_ed25519_pubkey(&self) -> [u8; 32] {
        self.local_verifying_key.to_bytes()
    }

    pub fn sign_transcript(&self, message: &[u8]) -> [u8; 64] {
        self.local_signing_key.sign(message).to_bytes()
    }

    pub fn verify_signature(
        pubkey_bytes: &[u8; 32],
        message: &[u8],
        signature_bytes: &[u8; 64],
    ) -> Result<(), KeystoreError> {
        let vk = VerifyingKey::from_bytes(pubkey_bytes).map_err(|_| {
            KeystoreError::CorruptKeystore("invalid Ed25519 public key bytes".into())
        })?;
        // Use verify_strict to reject malleable or small-order Ed25519 signatures.
        let sig = Signature::from_bytes(signature_bytes);
        vk.verify_strict(message, &sig)
            .map_err(|_| KeystoreError::AeadTamperDetected("Ed25519 signature verification failed".into()))
    }

    pub fn was_legacy_v1_quarantined(&self) -> bool {
        self.legacy_v1_quarantined
    }

    /// Checks whether a candidate peer identity conflicts with any already-pinned peer.
    /// Rejects both:
    /// 1. Claimed `device_id` that does not match `SHA256("integrator-device-id-v2" || pubkey)[0..16]`.
    /// 2. A peer with the same `hostname` (non-empty) that is already pinned to a different `ed25519_pubkey`,
    ///    preventing silent key replacement without an explicit user unpair action.
    pub fn check_peer_identity_pinning(
        &self,
        peer_device_id: &[u8; 16],
        peer_ed25519_pk: &[u8; 32],
        hostname: &str,
    ) -> Result<(), KeystoreError> {
        let _ = VerifyingKey::from_bytes(peer_ed25519_pk).map_err(|_| {
            KeystoreError::CorruptKeystore("peer presented invalid Ed25519 public key".into())
        })?;

        let derived_id = super::derive_device_id_from_pubkey(peer_ed25519_pk);
        if !bool::from(peer_device_id.ct_eq(&derived_id)) {
            return Err(KeystoreError::SpoofedDeviceId {
                claimed_hex: super::hex_encode(peer_device_id),
                derived_hex: super::hex_encode(&derived_id),
            });
        }

        let id_hex = super::hex_encode(peer_device_id);
        if self.blocked_device_ids.iter().any(|b| b == &id_hex) {
            return Err(KeystoreError::PeerBlocked(id_hex));
        }

        if let Some(existing) = self.peers.get(&id_hex) {
            if !bool::from(existing.ed25519_pubkey.ct_eq(peer_ed25519_pk)) {
                return Err(KeystoreError::PinnedIdentityKeyMismatch {
                    peer_identifier: id_hex,
                    pinned_pubkey_hex: super::hex_encode(&existing.ed25519_pubkey),
                    presented_pubkey_hex: super::hex_encode(peer_ed25519_pk),
                });
            }
        }

        let trimmed_host = hostname.trim();
        if !trimmed_host.is_empty() && !trimmed_host.eq_ignore_ascii_case("unknown") {
            for existing in self.peers.values() {
                if existing.hostname.eq_ignore_ascii_case(trimmed_host)
                    && !bool::from(existing.ed25519_pubkey.ct_eq(peer_ed25519_pk))
                {
                    return Err(KeystoreError::PinnedIdentityKeyMismatch {
                        peer_identifier: trimmed_host.to_string(),
                        pinned_pubkey_hex: super::hex_encode(&existing.ed25519_pubkey),
                        presented_pubkey_hex: super::hex_encode(peer_ed25519_pk),
                    });
                }
            }
        }

        Ok(())
    }

    /// Commits a newly paired (or re-keyed same-identity) peer into the keystore and atomically persists to disk.
    pub fn commit_paired_peer(
        &mut self,
        peer_device_id: [u8; 16],
        peer_ed25519_pk: [u8; 32],
        root_key: Zeroizing<[u8; 32]>,
        hostname: String,
        os: String,
        last_ip: String,
        via_direct_cable: bool,
    ) -> Result<VerifiedPeerCredentials, KeystoreError> {
        self.check_peer_identity_pinning(&peer_device_id, &peer_ed25519_pk, &hostname)?;

        let key_id = super::derive_key_id(&root_key);
        let device_id_hex = super::hex_encode(&peer_device_id);
        let now_secs = super::unix_epoch_secs();

        let creds = VerifiedPeerCredentials {
            device_id: peer_device_id,
            device_id_hex: device_id_hex.clone(),
            ed25519_pubkey: peer_ed25519_pk,
            key_id,
            root_key,
            hostname,
            os,
            last_ip,
            paired_at_epoch: now_secs,
            via_direct_cable,
        };

        self.peers.insert(device_id_hex, creds.clone());
        self.persist_to_disk()?;
        Ok(creds)
    }

    /// Explicitly unpairs/revokes a pinned peer so a new key or fresh pairing can be established.
    pub fn unpair_peer(&mut self, device_id_hex: &str) -> Result<bool, KeystoreError> {
        let canonical = device_id_hex.trim().to_ascii_lowercase();
        let removed = self.peers.remove(&canonical).is_some();
        if removed {
            self.persist_to_disk()?;
        }
        Ok(removed)
    }

    pub fn get_peer(&self, device_id_hex: &str) -> Option<&VerifiedPeerCredentials> {
        let canonical = device_id_hex.trim().to_ascii_lowercase();
        if self.blocked_device_ids.iter().any(|b| b == &canonical) {
            return None;
        }
        self.peers.get(&canonical)
    }

    pub fn get_peer_by_id_bytes(&self, device_id: &[u8; 16]) -> Option<&VerifiedPeerCredentials> {
        let hex = super::hex_encode(device_id);
        self.get_peer(&hex)
    }

    pub fn list_peers(&self) -> Vec<VerifiedPeerCredentials> {
        let mut out: Vec<VerifiedPeerCredentials> = self.peers.values().cloned().collect();
        out.sort_by(|a, b| a.hostname.cmp(&b.hostname).then(a.device_id_hex.cmp(&b.device_id_hex)));
        out
    }

    pub fn update_peer_last_ip(
        &mut self,
        device_id_hex: &str,
        new_ip: &str,
    ) -> Result<(), KeystoreError> {
        let canonical = device_id_hex.trim().to_ascii_lowercase();
        if let Some(peer) = self.peers.get_mut(&canonical) {
            if peer.last_ip != new_ip {
                peer.last_ip = new_ip.to_string();
                self.persist_to_disk()?;
            }
            Ok(())
        } else {
            Err(KeystoreError::PeerNotFound(canonical))
        }
    }

    pub fn persist_to_disk(&self) -> Result<(), KeystoreError> {
        let local_pk_bytes = self.local_verifying_key.to_bytes();
        let local_sk_bytes = Zeroizing::new(self.local_signing_key.to_bytes());
        let local_aad = build_local_identity_aad(&self.local_device_id, &local_pk_bytes);
        let wrapped_local_sk = wrap_secret_32(&self.kek, &local_sk_bytes, &local_aad)?;

        let mut serialized_peers = Vec::with_capacity(self.peers.len());
        for peer in self.peers.values() {
            let peer_aad = build_peer_root_aad(&peer.device_id, &peer.ed25519_pubkey, &peer.key_id);
            let wrapped_root = wrap_secret_32(&self.kek, &peer.root_key, &peer_aad)?;
            serialized_peers.push(TrustedPeerRecordV2 {
                schema_version: KEYSTORE_SCHEMA_VERSION,
                device_id_hex: peer.device_id_hex.clone(),
                ed25519_pubkey_hex: super::hex_encode(&peer.ed25519_pubkey),
                key_id_hex: super::hex_encode(&peer.key_id),
                hostname: peer.hostname.clone(),
                os: peer.os.clone(),
                last_ip: peer.last_ip.clone(),
                paired_at_epoch: peer.paired_at_epoch,
                via_direct_cable: peer.via_direct_cable,
                wrapped_root_key: wrapped_root,
            });
        }
        serialized_peers.sort_by(|a, b| a.device_id_hex.cmp(&b.device_id_hex));

        let file_obj = KeystoreFileV2 {
            schema_version: KEYSTORE_SCHEMA_VERSION,
            local_device_id_hex: self.local_device_id_hex.clone(),
            local_ed25519_pubkey_hex: super::hex_encode(&local_pk_bytes),
            wrapped_local_ed25519_sk: wrapped_local_sk,
            peers: serialized_peers,
            blocked_device_ids: self.blocked_device_ids.clone(),
            blocked_ips: self.blocked_ips.clone(),
            legacy_v1_quarantined: self.legacy_v1_quarantined,
        };

        let json_bytes = serde_json::to_vec_pretty(&file_obj)
            .map_err(|e| KeystoreError::SerializationFailure(e.to_string()))?;

        atomic_write_secure_file(&self.storage_dir, &self.keystore_path, &json_bytes)
    }
}

fn build_local_identity_aad(device_id: &[u8; 16], pubkey: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_LOCAL_IDENTITY_PREFIX.len() + 16 + 32);
    aad.extend_from_slice(AAD_LOCAL_IDENTITY_PREFIX);
    aad.extend_from_slice(device_id);
    aad.extend_from_slice(pubkey);
    aad
}

fn build_peer_root_aad(device_id: &[u8; 16], pubkey: &[u8; 32], key_id: &[u8; 16]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_PEER_ROOT_PREFIX.len() + 16 + 32 + 16);
    aad.extend_from_slice(AAD_PEER_ROOT_PREFIX);
    aad.extend_from_slice(device_id);
    aad.extend_from_slice(pubkey);
    aad.extend_from_slice(key_id);
    aad
}

fn wrap_secret_32(
    kek: &[u8; 32],
    secret: &[u8; 32],
    aad: &[u8],
) -> Result<AeadWrappedSecret, KeystoreError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(kek));
    let mut nonce_bytes = [0u8; 12];
    super::csprng_fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: secret,
                aad,
            },
        )
        .map_err(|_| KeystoreError::OsKeystoreFailure("ChaCha20Poly1305 wrap failed".into()))?;

    Ok(AeadWrappedSecret {
        nonce_hex: super::hex_encode(&nonce_bytes),
        ciphertext_hex: super::hex_encode(&ciphertext),
    })
}

fn unwrap_secret_32(
    kek: &[u8; 32],
    wrapped: &AeadWrappedSecret,
    aad: &[u8],
) -> Result<Zeroizing<[u8; 32]>, KeystoreError> {
    let nonce_bytes: [u8; 12] = super::hex_decode_array(&wrapped.nonce_hex)
        .ok_or_else(|| KeystoreError::AeadTamperDetected("invalid wrapped nonce_hex".into()))?;
    let ciphertext = super::hex_decode(&wrapped.ciphertext_hex)
        .ok_or_else(|| KeystoreError::AeadTamperDetected("invalid wrapped ciphertext_hex".into()))?;

    if ciphertext.len() != 32 + 16 {
        return Err(KeystoreError::AeadTamperDetected(format!(
            "unexpected wrapped secret length {} (expected 48)",
            ciphertext.len()
        )));
    }

    let cipher = ChaCha20Poly1305::new(Key::from_slice(kek));
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: &ciphertext,
                    aad,
                },
            )
            .map_err(|_| {
                KeystoreError::AeadTamperDetected(
                    "ChaCha20Poly1305 tag verification failed on keystore record".into(),
                )
            })?,
    );

    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&plaintext);
    Ok(out)
}

pub fn default_keystore_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
            return PathBuf::from(local_app_data).join("Integrator").join("security");
        }
        if let Ok(user_profile) = std::env::var("USERPROFILE") {
            return PathBuf::from(user_profile).join(".integrator").join("security");
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(".integrator").join("security");
        }
    }
    std::env::temp_dir().join("integrator_security")
}

fn ensure_secure_directory(dir: &Path) -> Result<(), KeystoreError> {
    fs::create_dir_all(dir)
        .map_err(|e| KeystoreError::IoFailure(format!("create_dir_all {}: {}", dir.display(), e)))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

fn atomic_write_secure_file(dir: &Path, target: &Path, content: &[u8]) -> Result<(), KeystoreError> {
    ensure_secure_directory(dir)?;
    let mut rnd = [0u8; 6];
    super::csprng_fill(&mut rnd);
    let tmp_name = format!(
        ".{}.tmp.{}.{}",
        target
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("keystore"),
        std::process::id(),
        super::hex_encode(&rnd)
    );
    let tmp_path = dir.join(tmp_name);

    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
        opts.custom_flags(libc::O_NOFOLLOW);
    }

    let mut file = opts
        .open(&tmp_path)
        .map_err(|e| KeystoreError::IoFailure(format!("open temp {}: {}", tmp_path.display(), e)))?;

    if let Err(e) = file.write_all(content).and_then(|_| file.sync_all()) {
        let _ = fs::remove_file(&tmp_path);
        return Err(KeystoreError::IoFailure(format!(
            "write/sync temp {}: {}",
            tmp_path.display(),
            e
        )));
    }
    drop(file);

    if let Err(e) = fs::rename(&tmp_path, target) {
        let _ = fs::remove_file(&tmp_path);
        return Err(KeystoreError::IoFailure(format!(
            "rename {} -> {}: {}",
            tmp_path.display(),
            target.display(),
            e
        )));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(target, fs::Permissions::from_mode(0o600));
    }

    Ok(())
}

/// Quarantines any legacy v1 `trusted_peers.json` in `storage_dir`, its parent directory,
/// or `~/.usbc_clipboard_cache/trusted_peers.json` by renaming it to `.v1.deprecated.bak`.
pub fn quarantine_legacy_v1_files(storage_dir: &Path) -> bool {
    let mut candidate_paths = Vec::new();
    candidate_paths.push(storage_dir.join("trusted_peers.json"));
    if let Some(parent) = storage_dir.parent() {
        candidate_paths.push(parent.join("trusted_peers.json"));
    }

    // Only inspect global home directory paths when operating on the default keystore directory.
    if storage_dir == default_keystore_dir() {
        #[cfg(target_os = "windows")]
        if let Ok(profile) = std::env::var("USERPROFILE") {
            let p = PathBuf::from(profile);
            candidate_paths.push(p.join(".usbc_clipboard_cache").join("trusted_peers.json"));
            candidate_paths.push(p.join(".integrator").join("trusted_peers.json"));
        }
        #[cfg(not(target_os = "windows"))]
        if let Ok(home) = std::env::var("HOME") {
            let p = PathBuf::from(home);
            candidate_paths.push(p.join(".usbc_clipboard_cache").join("trusted_peers.json"));
            candidate_paths.push(p.join(".integrator").join("trusted_peers.json"));
        }
    }

    let mut quarantined_any = false;
    for legacy_path in candidate_paths {
        if legacy_path.exists() {
            let bak_path = legacy_path.with_extension("json.v1.deprecated.bak");
            match fs::rename(&legacy_path, &bak_path) {
                Ok(()) => {
                    info!(
                        "Quarantined legacy v1 trust file {} -> {}",
                        legacy_path.display(),
                        bak_path.display()
                    );
                    quarantined_any = true;
                }
                Err(e) => {
                    warn!(
                        "Failed to rename legacy v1 trust file {}: {}; removing legacy file",
                        legacy_path.display(),
                        e
                    );
                    if fs::remove_file(&legacy_path).is_ok() {
                        quarantined_any = true;
                    }
                }
            }
        }
    }
    quarantined_any
}

// ============================================================================
// Platform-Specific OS Master KEK Implementations
// ============================================================================

#[cfg(target_os = "macos")]
fn macos_keychain_load_or_create_kek(
    storage_dir: &Path,
) -> Result<Zeroizing<[u8; 32]>, KeystoreError> {
    use core_foundation::base::{CFTypeRef, TCFType};
    use core_foundation::boolean::CFBoolean;
    use core_foundation::data::CFData;
    use core_foundation::dictionary::CFMutableDictionary;
    use core_foundation::string::CFString;
    use std::os::raw::c_int;

    #[link(name = "Security", kind = "framework")]
    extern "C" {
        static kSecClass: CFTypeRef;
        static kSecClassGenericPassword: CFTypeRef;
        static kSecAttrService: CFTypeRef;
        static kSecAttrAccount: CFTypeRef;
        static kSecValueData: CFTypeRef;
        static kSecReturnData: CFTypeRef;
        static kSecMatchLimit: CFTypeRef;
        static kSecMatchLimitOne: CFTypeRef;
        static kSecAttrAccessible: CFTypeRef;
        static kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly: CFTypeRef;

        fn SecItemCopyMatching(query: CFTypeRef, result: *mut CFTypeRef) -> c_int;
        fn SecItemAdd(attributes: CFTypeRef, result: *mut CFTypeRef) -> c_int;
        fn SecItemDelete(query: CFTypeRef) -> c_int;
    }

    const ERR_SEC_SUCCESS: c_int = 0;
    const ERR_SEC_ITEM_NOT_FOUND: c_int = -25300;

    let service = CFString::new("com.integrator.security.keystore.v2");
    // Scope the account name by storage_dir hash so custom paths don't collide.
    let account_hash = super::hex_encode(&super::sha256_digest(
        storage_dir.to_string_lossy().as_bytes(),
    )[0..8]);
    let account = CFString::new(&format!("master-kek-v2-{}", account_hash));

    unsafe {
        let mut query: CFMutableDictionary<CFTypeRef, CFTypeRef> = CFMutableDictionary::new();
        query.set(kSecClass, kSecClassGenericPassword);
        query.set(kSecAttrService, service.as_CFTypeRef());
        query.set(kSecAttrAccount, account.as_CFTypeRef());
        query.set(kSecReturnData, CFBoolean::true_value().as_CFTypeRef());
        query.set(kSecMatchLimit, kSecMatchLimitOne);

        let mut result: CFTypeRef = std::ptr::null();
        let status = SecItemCopyMatching(query.as_CFTypeRef(), &mut result);
        if status == ERR_SEC_SUCCESS && !result.is_null() {
            let data: CFData = TCFType::wrap_under_create_rule(result as *const _);
            if data.len() == 32 {
                let mut kek = Zeroizing::new([0u8; 32]);
                kek.copy_from_slice(data.bytes());
                return Ok(kek);
            }
            // Invalid length in keychain; delete and recreate.
            let mut del_q: CFMutableDictionary<CFTypeRef, CFTypeRef> = CFMutableDictionary::new();
            del_q.set(kSecClass, kSecClassGenericPassword);
            del_q.set(kSecAttrService, service.as_CFTypeRef());
            del_q.set(kSecAttrAccount, account.as_CFTypeRef());
            let _ = SecItemDelete(del_q.as_CFTypeRef());
        }

        if status != ERR_SEC_SUCCESS && status != ERR_SEC_ITEM_NOT_FOUND {
            warn!(
                "macOS Keychain SecItemCopyMatching returned OSStatus {}; falling back to hardware-UUID derived envelope key",
                status
            );
            return unix_fallback_load_or_create_kek(storage_dir);
        }

        let mut new_kek = Zeroizing::new([0u8; 32]);
        super::csprng_fill(&mut *new_kek);
        let cf_data = CFData::from_buffer(&*new_kek);

        let mut add_attrs: CFMutableDictionary<CFTypeRef, CFTypeRef> = CFMutableDictionary::new();
        add_attrs.set(kSecClass, kSecClassGenericPassword);
        add_attrs.set(kSecAttrService, service.as_CFTypeRef());
        add_attrs.set(kSecAttrAccount, account.as_CFTypeRef());
        add_attrs.set(kSecValueData, cf_data.as_CFTypeRef());
        add_attrs.set(
            kSecAttrAccessible,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        );

        let add_status = SecItemAdd(add_attrs.as_CFTypeRef(), std::ptr::null_mut());
        if add_status == ERR_SEC_SUCCESS {
            Ok(new_kek)
        } else {
            warn!(
                "macOS Keychain SecItemAdd returned OSStatus {} (e.g. locked headless keychain); using machine-bound 0600 key envelope",
                add_status
            );
            unix_fallback_load_or_create_kek(storage_dir)
        }
    }
}

/// Removes the OS-stored master KEK for a specific `storage_dir` (used during test cleanup or full reset).
pub fn delete_os_kek_for_dir(storage_dir: &Path) {
    #[cfg(target_os = "macos")]
    {
        use core_foundation::base::{CFTypeRef, TCFType};
        use core_foundation::dictionary::CFMutableDictionary;
        use core_foundation::string::CFString;
        use std::os::raw::c_int;

        #[link(name = "Security", kind = "framework")]
        extern "C" {
            static kSecClass: CFTypeRef;
            static kSecClassGenericPassword: CFTypeRef;
            static kSecAttrService: CFTypeRef;
            static kSecAttrAccount: CFTypeRef;
            fn SecItemDelete(query: CFTypeRef) -> c_int;
        }

        let service = CFString::new("com.integrator.security.keystore.v2");
        let account_hash = super::hex_encode(
            &super::sha256_digest(storage_dir.to_string_lossy().as_bytes())[0..8],
        );
        let account = CFString::new(&format!("master-kek-v2-{}", account_hash));
        unsafe {
            let mut del_q: CFMutableDictionary<CFTypeRef, CFTypeRef> = CFMutableDictionary::new();
            del_q.set(kSecClass, kSecClassGenericPassword);
            del_q.set(kSecAttrService, service.as_CFTypeRef());
            del_q.set(kSecAttrAccount, account.as_CFTypeRef());
            let _ = SecItemDelete(del_q.as_CFTypeRef());
        }
    }
    let _ = fs::remove_file(storage_dir.join("master_kek_v2.dpapi"));
    let _ = fs::remove_file(storage_dir.join(".master_kek_v2.seed"));
}

#[cfg(target_os = "windows")]
fn windows_dpapi_load_or_create_kek(
    storage_dir: &Path,
) -> Result<Zeroizing<[u8; 32]>, KeystoreError> {
    use std::ffi::c_void;

    #[repr(C)]
    struct DataBlob {
        cb_data: u32,
        pb_data: *mut u8,
    }

    const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;
    const DPAPI_ENTROPY: &[u8] = b"INTEGRATOR-WIN32-DPAPI-ENTROPY-V2";

    #[link(name = "crypt32")]
    extern "system" {
        fn CryptProtectData(
            p_data_in: *const DataBlob,
            sz_data_descr: *const u16,
            p_optional_entropy: *const DataBlob,
            pv_reserved: *mut c_void,
            p_prompt_struct: *mut c_void,
            dw_flags: u32,
            p_data_out: *mut DataBlob,
        ) -> i32;

        fn CryptUnprotectData(
            p_data_in: *const DataBlob,
            ppsz_data_descr: *mut *mut u16,
            p_optional_entropy: *const DataBlob,
            pv_reserved: *mut c_void,
            p_prompt_struct: *mut c_void,
            dw_flags: u32,
            p_data_out: *mut DataBlob,
        ) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn LocalFree(h_mem: *mut c_void) -> *mut c_void;
    }

    ensure_secure_directory(storage_dir)?;
    let dpapi_path = storage_dir.join("master_kek_v2.dpapi");

    let mut entropy_vec = DPAPI_ENTROPY.to_vec();
    let entropy_blob = DataBlob {
        cb_data: entropy_vec.len() as u32,
        pb_data: entropy_vec.as_mut_ptr(),
    };

    if dpapi_path.exists() {
        let mut encrypted_bytes = fs::read(&dpapi_path).map_err(|e| {
            KeystoreError::IoFailure(format!("read DPAPI file {}: {}", dpapi_path.display(), e))
        })?;
        if encrypted_bytes.is_empty() {
            return Err(KeystoreError::CorruptKeystore("empty DPAPI file".into()));
        }

        let in_blob = DataBlob {
            cb_data: encrypted_bytes.len() as u32,
            pb_data: encrypted_bytes.as_mut_ptr(),
        };
        let mut out_blob = DataBlob {
            cb_data: 0,
            pb_data: std::ptr::null_mut(),
        };

        let ok = unsafe {
            CryptUnprotectData(
                &in_blob,
                std::ptr::null_mut(),
                &entropy_blob,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out_blob,
            )
        };

        if ok == 0 || out_blob.pb_data.is_null() {
            return Err(KeystoreError::OsKeystoreFailure(
                "Windows DPAPI CryptUnprotectData failed to unwrap master KEK".into(),
            ));
        }

        let slice =
            unsafe { std::slice::from_raw_parts(out_blob.pb_data, out_blob.cb_data as usize) };
        if slice.len() != 32 {
            unsafe {
                std::ptr::write_bytes(out_blob.pb_data, 0, out_blob.cb_data as usize);
                LocalFree(out_blob.pb_data as *mut c_void);
            }
            return Err(KeystoreError::CorruptKeystore(format!(
                "DPAPI unwrapped KEK has invalid length {}",
                slice.len()
            )));
        }

        let mut kek = Zeroizing::new([0u8; 32]);
        kek.copy_from_slice(slice);
        unsafe {
            std::ptr::write_bytes(out_blob.pb_data, 0, out_blob.cb_data as usize);
            LocalFree(out_blob.pb_data as *mut c_void);
        }
        return Ok(kek);
    }

    let mut new_kek = Zeroizing::new([0u8; 32]);
    super::csprng_fill(&mut *new_kek);

    let in_blob = DataBlob {
        cb_data: 32,
        pb_data: new_kek.as_mut_ptr(),
    };
    let mut out_blob = DataBlob {
        cb_data: 0,
        pb_data: std::ptr::null_mut(),
    };

    let ok = unsafe {
        CryptProtectData(
            &in_blob,
            std::ptr::null(),
            &entropy_blob,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        )
    };

    if ok == 0 || out_blob.pb_data.is_null() {
        return Err(KeystoreError::OsKeystoreFailure(
            "Windows DPAPI CryptProtectData failed to protect master KEK".into(),
        ));
    }

    let encrypted_slice =
        unsafe { std::slice::from_raw_parts(out_blob.pb_data, out_blob.cb_data as usize) };
    let write_res = atomic_write_secure_file(storage_dir, &dpapi_path, encrypted_slice);
    unsafe {
        LocalFree(out_blob.pb_data as *mut c_void);
    }
    write_res?;
    Ok(new_kek)
}

#[cfg(not(target_os = "windows"))]
fn unix_fallback_load_or_create_kek(
    storage_dir: &Path,
) -> Result<Zeroizing<[u8; 32]>, KeystoreError> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    ensure_secure_directory(storage_dir)?;
    let key_file = storage_dir.join(".master_kek_v2.seed");

    let raw_seed: Zeroizing<[u8; 32]> = if key_file.exists() {
        let bytes = fs::read(&key_file).map_err(|e| {
            KeystoreError::IoFailure(format!("read {}: {}", key_file.display(), e))
        })?;
        if bytes.len() != 32 {
            return Err(KeystoreError::CorruptKeystore(format!(
                "invalid seed file length {} in {}",
                bytes.len(),
                key_file.display()
            )));
        }
        let mut arr = Zeroizing::new([0u8; 32]);
        arr.copy_from_slice(&bytes);
        arr
    } else {
        let mut arr = Zeroizing::new([0u8; 32]);
        super::csprng_fill(&mut *arr);
        atomic_write_secure_file(storage_dir, &key_file, &*arr)?;
        arr
    };

    // Combine the 0600 random seed with local machine/user identity via HKDF-SHA256.
    let mut salt_data = Vec::from(&b"integrator-unix-kek-salt-v2"[..]);
    if let Ok(mid) = fs::read("/etc/machine-id") {
        salt_data.extend_from_slice(&mid);
    }
    #[cfg(unix)]
    {
        let uid = unsafe { libc::geteuid() };
        salt_data.extend_from_slice(&uid.to_le_bytes());
    }

    let hk = Hkdf::<Sha256>::new(Some(&salt_data), &*raw_seed);
    let mut derived = Zeroizing::new([0u8; 32]);
    hk.expand(b"integrator-v2-master-kek", &mut *derived)
        .expect("32-byte HKDF expand cannot fail");
    Ok(derived)
}

/// Global singleton accessor for the production v2 keystore.
static GLOBAL_KEYSTORE_V2: OnceLock<Mutex<KeystoreV2>> = OnceLock::new();

pub fn global_keystore() -> &'static Mutex<KeystoreV2> {
    GLOBAL_KEYSTORE_V2.get_or_init(|| {
        let ks = KeystoreV2::open_default().unwrap_or_else(|e| {
            panic!("Failed to initialize Integrator v2 security keystore: {}", e)
        });
        Mutex::new(ks)
    })
}
