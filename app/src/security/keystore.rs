//! # Cross-Platform OS-Backed Keystore & Identity Pinning (`app/src/security/keystore.rs`)
//!
//! ## 1. Module Purpose & Architectural Scope
//! This module owns all persistent cryptographic state for the Integrator application, governing the
//! storage, lifecycle, encryption, identity-key pinning, and access control of:
//! - The local host's master Ed25519 identity keypair (`local_ed25519_sk`, `local_ed25519_pk`).
//! - The canonical 16-byte local `device_id` derived from `local_ed25519_pk`.
//! - Per-peer pre-shared root keys ($K_{\text{root}}$) negotiated via RFC 9382 SPAKE2 pairing.
//! - Pinned remote peer metadata (device IDs, public keys, key IDs, hostnames, last-seen IPs, direct-cable flags).
//! - Active network and device blocklists (`blocked_device_ids`, `blocked_ips`).
//!
//! All long-term secrets are stored on disk in `~/.integrator/security/trusted_peers_v2.json` (or Windows
//! `%LOCALAPPDATA%\Integrator\security\trusted_peers_v2.json`) under multi-layered defense-in-depth protection.
//!
//! ## 2. Multi-Layer Security Architecture
//! 1. **Layer 1: OS-Native Root of Trust (Master Keystore Encryption Key, $K_{\text{kek}}$)**:
//!    - **macOS (`target_os = "macos"`)**:
//!      - Queries Apple Keychain Services (`Security.framework`) non-interactively using
//!        `kSecUseAuthenticationUIFail` under service `"com.integrator.security.keystore.v2"`, account
//!        `"master-kek-v2-<account_hash>"`.
//!      - Suppresses interactive macOS security dialogs (`NoUiKeychainGuard`) to prevent GUI lockups.
//!      - If no pre-existing keychain entry exists, derives $K_{\text{kek}}$ by binding an unguessable
//!        256-bit CSPRNG seed (`.master_kek_v2.seed`, mode `0600`) to machine hardware identifiers
//!        (`IOPlatformUUID`, `IOPlatformSerialNumber` via `IOKit.framework`) and the current user's UID via HKDF-SHA256.
//!    - **Windows (`target_os = "windows"`)**:
//!      - Protects $K_{\text{kek}}$ using the Win32 Data Protection API (`CryptProtectData` and
//!        `CryptUnprotectData` in `crypt32.dll`).
//!      - Passes `CRYPTPROTECT_UI_FORBIDDEN` to guarantee silent, headless operation without credential prompts.
//!      - Binds encryption to current Windows user login credentials combined with secondary application entropy
//!        `"INTEGRATOR-WIN32-DPAPI-ENTROPY-V2"`.
//!      - Securely zeroes sensitive plaintexts in volatile memory before releasing memory via `LocalFree`.
//!      - Stored at `%LOCALAPPDATA%\Integrator\security\master_kek_v2.dpapi`.
//!    - **Linux / Other Unix (`not(any(macos, windows))`**:
//!      - Derives $K_{\text{kek}}$ by combining a mode-`0600` CSPRNG seed file (`.master_kek_v2.seed`),
//!        `/etc/machine-id`, and effective user ID (EUID) via HKDF-SHA256.
//! 2. **Layer 2: AEAD Envelope Encryption**:
//!    - Plaintext private keys (`local_ed25519_sk`) and peer root keys ($K_{\text{root}}$) are NEVER written to disk in the clear.
//!    - Each secret is wrapped with `ChaCha20Poly1305` using an independent 12-byte CSPRNG nonce.
//!    - Authenticated Additional Data (`AAD`) binds the owner's `device_id`, `ed25519_pubkey`, and `key_id` directly
//!      into the Poly1305 authenticator, cryptographically preventing record-swapping or JSON key substitution.
//! 3. **Layer 3: Whole-File Metadata Integrity MAC**:
//!    - An HMAC-SHA256 integrity tag (`state_mac_hex`) authenticates the entire serialized keystore contents
//!      (schema version, local identity, all peers, blocklists, quarantine flag) under a dedicated MAC key
//!      derived from $K_{\text{kek}}$ (`KEYSTORE_META_MAC_INFO`).
//!    - Detects unauthorized offline modifications to unencrypted metadata (e.g. modifying pinned hostnames or tampering with blocklists).
//! 4. **Layer 4: Strict Identity-Key Pinning & Anti-Spoofing**:
//!    - `device_id` is deterministically derived: $\text{SHA256}(\text{"integrator-device-id-v2"} \,\|\, \text{pubkey})[0..16]$.
//!    - Any mismatch between claimed `device_id` and presented `ed25519_pubkey` is rejected with [`KeystoreError::SpoofedDeviceId`].
//!    - Once a peer is pinned, any connection or re-pairing attempt presenting a different `ed25519_pubkey` for the
//!      same `device_id` or non-empty `hostname` is rejected with [`KeystoreError::PinnedIdentityKeyMismatch`].
//!    - Pinned identities can only be updated after an explicit user unpair action (`unpair_peer`).
//! 5. **Layer 5: Legacy v1 Keystore Quarantine**:
//!    - Scans for deprecated v1 `trusted_peers.json` files lacking Ed25519 keys or PAKE roots.
//!    - Automatically renames them to `trusted_peers.json.v1.deprecated.bak` with mode `0600` to prevent insecure fallback.
//! 6. **Layer 6: Filesystem Safety & Atomic Replacement**:
//!    - Directory and file creation enforces POSIX mode `0700` / `0600`.
//!    - Disallows following symlinks or Windows reparse points (`O_NOFOLLOW`, `FILE_ATTRIBUTE_REPARSE_POINT`).
//!    - Atomic writes: writes to a hidden temporary file with PID and CSPRNG hex suffix, calls `sync_all()`, and renames over target.
//!    - Maximum file size bounded by `MAX_KEYSTORE_FILE_BYTES` (16 MiB).
//!
//! ## 3. Architectural Linkages & Callers/Callees
//! - **Upstream Callers**:
//!   - `app/src/trust.rs`: High-level peer status queries, beacon signing/verification, unpair/block operations.
//!   - `app/src/security/pairing.rs`: Identity verification, peer commitment upon successful SPAKE2 handshake.
//!   - `app/src/security/transport.rs`: Pinned peer credential lookups for `TransportSessionV2` mutual handshake.
//!   - `app/src/security/audio_udp.rs`: Looking up $K_{\text{root}}$ to derive authenticated UDP audio session keys.
//! - **Downstream Callees**:
//!   - `chacha20poly1305`: Envelope encryption and decryption.
//!   - `ed25519_dalek`: Local signing key management, signature creation and strict verification.
//!   - OS Cryptographic APIs (`crypt32.dll` on Windows, `Security.framework` on macOS).
//!
//! ## 4. Threading & Concurrency Model
//! Access to the active keystore is managed through the global thread-safe singleton [`global_keystore`],
//! which wraps a `KeystoreV2` instance inside an `std::sync::Mutex`. In async contexts, callers acquire the
//! mutex guard synchronously for brief operations and drop it before invoking `.await` points, ensuring the
//! returned futures remain `Send`.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use subtle::ConstantTimeEq;
use tracing::{info, warn};
use zeroize::Zeroizing;

/// Schema version identifier for Integrator v2 keystores (`2`).
pub const KEYSTORE_SCHEMA_VERSION: u32 = 2;

/// AAD prefix binding local identity records to prevent AEAD ciphertext swapping.
const AAD_LOCAL_IDENTITY_PREFIX: &[u8] = b"integrator-keystore-v2-local-id";

/// AAD prefix binding remote peer root keys to prevent AEAD ciphertext swapping.
const AAD_PEER_ROOT_PREFIX: &[u8] = b"integrator-keystore-v2-peer-root";

/// HKDF salt for deriving the whole-file metadata MAC key.
const KEYSTORE_META_MAC_SALT: &[u8] = b"integrator-keystore-v2-meta-salt";

/// HKDF info string for deriving the whole-file metadata MAC key.
const KEYSTORE_META_MAC_INFO: &[u8] = b"integrator-keystore-v2-meta-mac";

type HmacSha256 = Hmac<Sha256>;

/// Errors encountered during keystore initialization, cryptographic wrapping, or identity pinning checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeystoreError {
    /// OS native secret store failure (Keychain, DPAPI, or CSPRNG).
    OsKeystoreFailure(String),
    /// Filesystem input/output error (stat, open, read, write, permissions).
    IoFailure(String),
    /// JSON serialization or deserialization failure.
    SerializationFailure(String),
    /// Keystore format corruption, non-UTF8 bytes, or schema version mismatch.
    CorruptKeystore(String),
    /// ChaCha20-Poly1305 AEAD tag verification failure or metadata HMAC mismatch (tampering detected).
    AeadTamperDetected(String),
    /// Claimed device ID does not match the deterministic SHA-256 derivation from the Ed25519 public key.
    SpoofedDeviceId {
        claimed_hex: String,
        derived_hex: String,
    },
    /// Security alert: remote peer presented an Ed25519 public key conflicting with the already-pinned key.
    PinnedIdentityKeyMismatch {
        peer_identifier: String,
        pinned_pubkey_hex: String,
        presented_pubkey_hex: String,
    },
    /// Requested peer device ID was not found in the trust store.
    PeerNotFound(String),
    /// Connection rejected because the peer device ID or IP address is on the blocklist.
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

/// Trait abstracting the retrieval or generation of the 256-bit Master Keystore Encryption Key ($K_{\text{kek}}$).
pub trait KekProvider: Send + Sync {
    /// Loads the existing $K_{\text{kek}}$ from the OS secure storage or initializes a fresh one.
    ///
    /// # Arguments
    /// * `storage_dir` - Directory containing keystore configuration and platform key tokens.
    ///
    /// # Returns
    /// 32-byte master key wrapped in [`zeroize::Zeroizing`].
    fn load_or_create_kek(&self, storage_dir: &Path) -> Result<Zeroizing<[u8; 32]>, KeystoreError>;
}

/// Default production implementation of [`KekProvider`], delegating to OS native secret storage:
/// - macOS: Apple Keychain Services / Hardware-bound sealed seed.
/// - Windows: Win32 DPAPI (`CryptProtectData`).
/// - Linux: Machine-ID + EUID + mode-0600 seed file.
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

/// Deterministic in-memory [`KekProvider`] for isolated unit and adversarial integration tests.
#[cfg(test)]
pub struct FixedKekProvider {
    kek: Zeroizing<[u8; 32]>,
}

#[cfg(test)]
impl FixedKekProvider {
    /// Constructs a test KEK provider with fixed 32-byte key material.
    pub fn new(kek_bytes: [u8; 32]) -> Self {
        Self {
            kek: Zeroizing::new(kek_bytes),
        }
    }
}

#[cfg(test)]
impl KekProvider for FixedKekProvider {
    fn load_or_create_kek(&self, _storage_dir: &Path) -> Result<Zeroizing<[u8; 32]>, KeystoreError> {
        Ok(self.kek.clone())
    }
}

/// On-disk representation of an envelope-encrypted 32-byte secret (e.g., Ed25519 secret key seed or PAKE root key).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AeadWrappedSecret {
    /// 24-character hexadecimal representation of the 12-byte CSPRNG nonce.
    pub nonce_hex: String,
    /// 96-character hexadecimal representation of the 48-byte AEAD output (32-byte ciphertext + 16-byte Poly1305 tag).
    pub ciphertext_hex: String,
}

/// On-disk record for a pinned trusted peer inside `trusted_peers_v2.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedPeerRecordV2 {
    /// Record schema version (`2`).
    pub schema_version: u32,
    /// 32-character lowercase hex canonical device ID: $\text{SHA256}(\text{"integrator-device-id-v2"} \,\|\, \text{pubkey})[0..16]$.
    pub device_id_hex: String,
    /// 64-character lowercase hex compressed Edwards25519 public key.
    pub ed25519_pubkey_hex: String,
    /// 32-character lowercase hex key ID: $\text{SHA256}(\text{"integrator-key-id-v2"} \,\|\, K_{\text{root}})[0..16]$.
    pub key_id_hex: String,
    /// Verified hostname of the peer device at the time of pairing.
    pub hostname: String,
    /// Operating system string (e.g. `"macOS"`, `"Windows"`).
    pub os: String,
    /// Most recently verified IP address string (e.g. `"10.99.99.1"`).
    pub last_ip: String,
    /// Unix epoch timestamp (seconds) when mutual pairing completed.
    pub paired_at_epoch: u64,
    /// True if paired over a direct USB-C / Thunderbolt cable interface.
    pub via_direct_cable: bool,
    /// Envelope-encrypted 32-byte root key ($K_{\text{root}}$) with AAD binding.
    pub wrapped_root_key: AeadWrappedSecret,
}

/// Top-level on-disk JSON structure of `trusted_peers_v2.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeystoreFileV2 {
    /// File schema version (must equal [`KEYSTORE_SCHEMA_VERSION`] = 2).
    pub schema_version: u32,
    /// Local machine's canonical 32-character hex device ID.
    pub local_device_id_hex: String,
    /// Local machine's 64-character hex Ed25519 public key.
    pub local_ed25519_pubkey_hex: String,
    /// Envelope-encrypted local Ed25519 secret key seed (32 bytes).
    pub wrapped_local_ed25519_sk: AeadWrappedSecret,
    /// Array of pinned trusted peer records.
    #[serde(default)]
    pub peers: Vec<TrustedPeerRecordV2>,
    /// List of explicitly blocked 32-hex device IDs.
    #[serde(default)]
    pub blocked_device_ids: Vec<String>,
    /// List of explicitly blocked IP address strings.
    #[serde(default)]
    pub blocked_ips: Vec<String>,
    /// True if legacy v1 `trusted_peers.json` files were detected and quarantined.
    #[serde(default)]
    pub legacy_v1_quarantined: bool,
    /// 64-character hex HMAC-SHA256 integrity tag over all serialized metadata fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_mac_hex: Option<String>,
}

/// Verified in-memory representation of an authenticated, pinned peer with its decrypted root key.
#[derive(Clone)]
pub struct VerifiedPeerCredentials {
    /// 16-byte binary canonical device ID.
    pub device_id: [u8; 16],
    /// 32-character lowercase hex canonical device ID.
    pub device_id_hex: String,
    /// 32-byte binary compressed Edwards25519 public key.
    pub ed25519_pubkey: [u8; 32],
    /// 16-byte binary key identifier.
    pub key_id: [u8; 16],
    /// Decrypted 32-byte root secret ($K_{\text{root}}$) wrapped in [`zeroize::Zeroizing`].
    pub root_key: Zeroizing<[u8; 32]>,
    /// Verified hostname of the peer device.
    pub hostname: String,
    /// Operating system of the peer device.
    pub os: String,
    /// Most recent verified IP address string.
    pub last_ip: String,
    /// Unix epoch timestamp (seconds) when pairing completed.
    pub paired_at_epoch: u64,
    /// True if paired over a direct physical link.
    pub via_direct_cable: bool,
}

impl std::fmt::Debug for VerifiedPeerCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redacts raw root_key material from Debug output to prevent accidental log leakage
        f.debug_struct("VerifiedPeerCredentials")
            .field("device_id_hex", &self.device_id_hex)
            .field("ed25519_pubkey", &super::hex_encode(&self.ed25519_pubkey))
            .field("key_id", &super::hex_encode(&self.key_id))
            .field("hostname", &self.hostname)
            .field("last_ip", &self.last_ip)
            .finish()
    }
}

/// Active in-memory manager for local cryptographic identity and trusted peer credentials.
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
    /// Opens or initializes the production v2 keystore in the default directory.
    ///
    /// # Errors
    /// Returns [`KeystoreError`] if OS secret storage or directory operations fail.
    pub fn open_default() -> Result<Self, KeystoreError> {
        let dir = try_default_keystore_dir()?;
        Self::open_with_provider(dir, &OsNativeKekProvider)
    }

    /// Opens or initializes a v2 keystore in `storage_dir` using the specified `provider`.
    ///
    /// Performs directory validation, legacy v1 quarantine, master KEK acquisition, and loads
    /// or initializes the keystore file.
    ///
    /// # Arguments
    /// * `storage_dir` - Directory path for keystore storage.
    /// * `provider` - KEK provider implementation.
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

    /// Initializes a brand new keystore with a fresh Ed25519 signing keypair from the OS CSPRNG.
    fn initialize_fresh(
        storage_dir: PathBuf,
        keystore_path: PathBuf,
        kek: Zeroizing<[u8; 32]>,
        legacy_v1_quarantined: bool,
    ) -> Result<Self, KeystoreError> {
        let mut sk_seed = Zeroizing::new([0u8; 32]);
        super::try_csprng_fill(&mut *sk_seed)
            .map_err(|e| KeystoreError::OsKeystoreFailure(format!("CSPRNG failed: {}", e)))?;
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

    /// Loads and decrypts an existing `trusted_peers_v2.json` file.
    ///
    /// Validates whole-file metadata HMAC, unwraps local Ed25519 secret key, verifies public key
    /// correspondence, unwraps all peer root keys with AAD binding, and populates the in-memory cache.
    fn load_existing(
        storage_dir: PathBuf,
        keystore_path: PathBuf,
        kek: Zeroizing<[u8; 32]>,
        newly_quarantined: bool,
    ) -> Result<Self, KeystoreError> {
        let raw_bytes = read_secure_bytes(&keystore_path)?;
        let raw = String::from_utf8(raw_bytes).map_err(|e| {
            KeystoreError::CorruptKeystore(format!(
                "non-UTF8 bytes in {}: {}",
                keystore_path.display(),
                e
            ))
        })?;

        let parsed: KeystoreFileV2 = serde_json::from_str(&raw).map_err(|e| {
            KeystoreError::CorruptKeystore(format!("invalid JSON in {}: {}", keystore_path.display(), e))
        })?;

        if parsed.schema_version != KEYSTORE_SCHEMA_VERSION {
            return Err(KeystoreError::CorruptKeystore(format!(
                "unsupported keystore schema_version {} (expected {})",
                parsed.schema_version, KEYSTORE_SCHEMA_VERSION
            )));
        }

        // Verify metadata integrity MAC when present (upgrade older v2 stores on save below).
        let needs_mac_upgrade = match &parsed.state_mac_hex {
            Some(mac_hex) => {
                let presented_mac: [u8; 32] = super::hex_decode_array(mac_hex).ok_or_else(|| {
                    KeystoreError::AeadTamperDetected("invalid state_mac_hex encoding".into())
                })?;
                let expected_mac = compute_keystore_file_mac(&kek, &parsed)?;
                if !bool::from(presented_mac.ct_eq(&expected_mac)) {
                    return Err(KeystoreError::AeadTamperDetected(
                        "keystore metadata integrity MAC verification failed".into(),
                    ));
                }
                false
            }
            None => true,
        };

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

        let mut blocked_device_ids = Vec::new();
        for b in &parsed.blocked_device_ids {
            let norm = b.trim().to_ascii_lowercase();
            if !norm.is_empty() && !blocked_device_ids.contains(&norm) {
                blocked_device_ids.push(norm);
            }
        }
        let mut blocked_ips = Vec::new();
        for ip in &parsed.blocked_ips {
            let norm = ip.trim().to_string();
            if !norm.is_empty() && !blocked_ips.contains(&norm) {
                blocked_ips.push(norm);
            }
        }

        let mut peers = HashMap::new();
        let mut seen_hostnames: Vec<String> = Vec::new();
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
            if blocked_device_ids.iter().any(|b| b == &canonical_id_hex) {
                warn!("Skipping blocked peer '{}' during keystore load", canonical_id_hex);
                continue;
            }
            let clean_host = rec.hostname.trim().to_string();
            let host_lower = clean_host.to_ascii_lowercase();
            if !host_lower.is_empty() && host_lower != "unknown" {
                if seen_hostnames.contains(&host_lower) {
                    return Err(KeystoreError::CorruptKeystore(format!(
                        "duplicate pinned hostname '{}' in keystore",
                        clean_host
                    )));
                }
                seen_hostnames.push(host_lower);
            }

            peers.insert(
                canonical_id_hex.clone(),
                VerifiedPeerCredentials {
                    device_id: peer_id,
                    device_id_hex: canonical_id_hex,
                    ed25519_pubkey: peer_pk,
                    key_id,
                    root_key,
                    hostname: clean_host,
                    os: rec.os.trim().to_string(),
                    last_ip: rec.last_ip.trim().to_string(),
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
            blocked_device_ids,
            blocked_ips,
            legacy_v1_quarantined: parsed.legacy_v1_quarantined || newly_quarantined,
        };

        if (newly_quarantined && !parsed.legacy_v1_quarantined) || needs_mac_upgrade {
            store.persist_to_disk()?;
        }

        Ok(store)
    }

    /// Returns the local machine's 16-byte binary canonical device identifier.
    pub fn local_device_id(&self) -> [u8; 16] {
        self.local_device_id
    }

    /// Returns the local machine's 32-character lowercase hex canonical device identifier.
    pub fn local_device_id_hex(&self) -> &str {
        &self.local_device_id_hex
    }

    /// Returns the local machine's 32-byte Ed25519 public key.
    pub fn local_ed25519_pubkey(&self) -> [u8; 32] {
        self.local_verifying_key.to_bytes()
    }

    /// Signs an arbitrary message (e.g. handshake transcript digest) with the local Ed25519 signing key.
    ///
    /// # Arguments
    /// * `message` - Input message slice to sign.
    ///
    /// # Returns
    /// 64-byte Ed25519 digital signature.
    pub fn sign_transcript(&self, message: &[u8]) -> [u8; 64] {
        self.local_signing_key.sign(message).to_bytes()
    }

    /// Strictly verifies an Ed25519 signature using `VerifyingKey::verify_strict`.
    ///
    /// Rejects malleable, non-canonical, or small-order Ed25519 signatures per RFC 8032.
    ///
    /// # Arguments
    /// * `pubkey_bytes` - 32-byte Ed25519 public key.
    /// * `message` - Authenticated message slice.
    /// * `signature_bytes` - 64-byte Ed25519 signature.
    pub fn verify_signature(
        pubkey_bytes: &[u8; 32],
        message: &[u8],
        signature_bytes: &[u8; 64],
    ) -> Result<(), KeystoreError> {
        let vk = VerifyingKey::from_bytes(pubkey_bytes).map_err(|_| {
            KeystoreError::CorruptKeystore("invalid Ed25519 public key bytes".into())
        })?;
        let sig = Signature::from_bytes(signature_bytes);
        vk.verify_strict(message, &sig)
            .map_err(|_| KeystoreError::AeadTamperDetected("Ed25519 signature verification failed".into()))
    }

    /// Returns whether any legacy v1 `trusted_peers.json` files were quarantined during initialization.
    #[cfg(test)]
    pub fn was_legacy_v1_quarantined(&self) -> bool {
        self.legacy_v1_quarantined
    }

    /// Checks whether a candidate peer identity conflicts with any already-pinned peer record.
    ///
    /// Rejects:
    /// 1. Self-pairing: attempting to pair the device with its own identity.
    /// 2. Spoofed device ID: `peer_device_id != SHA256("integrator-device-id-v2" || pk)[0..16]`.
    /// 3. Blocked device ID.
    /// 4. Public key conflict: candidate has same `device_id` but different `ed25519_pk`.
    /// 5. Hostname conflict: candidate has same `hostname` (non-empty) but different `ed25519_pk`.
    ///
    /// # Arguments
    /// * `peer_device_id` - 16-byte binary device ID.
    /// * `peer_ed25519_pk` - 32-byte Ed25519 public key.
    /// * `hostname` - Declared peer hostname string.
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
        if bool::from(peer_device_id.ct_eq(&self.local_device_id)) {
            return Err(KeystoreError::CorruptKeystore(
                "Cannot pair device with its own local identity".into(),
            ));
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
                if existing.hostname.trim().eq_ignore_ascii_case(trimmed_host)
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

    /// Commits a newly paired peer into the keystore and atomically persists state to disk.
    ///
    /// # Arguments
    /// * `peer_device_id` - 16-byte binary device ID.
    /// * `peer_ed25519_pk` - 32-byte Ed25519 public key.
    /// * `root_key` - 32-byte negotiated SPAKE2 root key.
    /// * `hostname` - Remote machine hostname.
    /// * `os` - Remote machine OS.
    /// * `last_ip` - Remote machine IP address.
    /// * `via_direct_cable` - True if paired over direct physical cable.
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
        let clean_hostname = hostname.trim().to_string();
        self.check_peer_identity_pinning(&peer_device_id, &peer_ed25519_pk, &clean_hostname)?;

        let key_id = super::derive_key_id(&root_key);
        let device_id_hex = super::hex_encode(&peer_device_id);
        let now_secs = super::unix_epoch_secs();

        let creds = VerifiedPeerCredentials {
            device_id: peer_device_id,
            device_id_hex: device_id_hex.clone(),
            ed25519_pubkey: peer_ed25519_pk,
            key_id,
            root_key,
            hostname: clean_hostname,
            os: os.trim().to_string(),
            last_ip: last_ip.trim().to_string(),
            paired_at_epoch: now_secs,
            via_direct_cable,
        };

        let mut next_peers = self.peers.clone();
        next_peers.insert(device_id_hex, creds.clone());
        self.persist_state(&next_peers, &self.blocked_device_ids, &self.blocked_ips)?;
        self.peers = next_peers;
        Ok(creds)
    }

    /// Explicitly unpairs and forgets a pinned peer by its device ID hex.
    ///
    /// # Arguments
    /// * `device_id_hex` - 32-character hex device ID.
    ///
    /// # Returns
    /// `true` if the peer was found and removed; `false` if not found.
    pub fn unpair_peer(&mut self, device_id_hex: &str) -> Result<bool, KeystoreError> {
        let canonical = device_id_hex.trim().to_ascii_lowercase();
        let mut next_peers = self.peers.clone();
        let removed = next_peers.remove(&canonical).is_some();
        if removed {
            self.persist_state(&next_peers, &self.blocked_device_ids, &self.blocked_ips)?;
            self.peers = next_peers;
        }
        Ok(removed)
    }

    /// Removes a peer from trust and optionally blocks its device ID and IP address.
    pub fn untrust_or_block_peer(
        &mut self,
        device_id_hex: &str,
        block: bool,
        known_ip: Option<&str>,
    ) -> Result<(), KeystoreError> {
        let canonical = device_id_hex.trim().to_ascii_lowercase();
        let mut next_peers = self.peers.clone();
        let mut next_blocked_ids = self.blocked_device_ids.clone();
        let mut next_blocked_ips = self.blocked_ips.clone();

        let removed_peer = next_peers.remove(&canonical);
        if block {
            if !canonical.is_empty() && !next_blocked_ids.iter().any(|b| b == &canonical) {
                next_blocked_ids.push(canonical.clone());
            }
            if let Some(peer) = removed_peer {
                if !peer.last_ip.is_empty()
                    && !next_blocked_ips.iter().any(|ip| ip == &peer.last_ip)
                {
                    next_blocked_ips.push(peer.last_ip);
                }
            }
            if let Some(ip) = known_ip.map(|s| s.trim()).filter(|s| !s.is_empty()) {
                if !next_blocked_ips.iter().any(|bip| bip == ip) {
                    next_blocked_ips.push(ip.to_string());
                }
            }
        } else {
            next_blocked_ids.retain(|b| b != &canonical);
            if let Some(peer) = removed_peer {
                if !peer.last_ip.is_empty() {
                    next_blocked_ips.retain(|bip| bip != &peer.last_ip);
                }
            }
            if let Some(ip) = known_ip.map(|s| s.trim()).filter(|s| !s.is_empty()) {
                next_blocked_ips.retain(|bip| bip != ip);
            }
        }
        self.persist_state(&next_peers, &next_blocked_ids, &next_blocked_ips)?;
        self.peers = next_peers;
        self.blocked_device_ids = next_blocked_ids;
        self.blocked_ips = next_blocked_ips;
        Ok(())
    }

    /// Returns a slice of all currently blocked device ID strings.
    pub fn blocked_device_ids(&self) -> &[String] {
        &self.blocked_device_ids
    }

    /// Returns a slice of all currently blocked IP address strings.
    pub fn blocked_ips(&self) -> &[String] {
        &self.blocked_ips
    }

    /// Checks if a device ID or IP address is currently blocked.
    pub fn is_device_or_ip_blocked(&self, device_id_hex: &str, ip: &str) -> bool {
        let canonical = device_id_hex.trim().to_ascii_lowercase();
        let clean_ip = ip.trim();
        self.blocked_device_ids.iter().any(|b| b == &canonical)
            || (!clean_ip.is_empty() && self.blocked_ips.iter().any(|bip| bip == clean_ip))
    }

    /// Finds a pinned peer matching a specific IP address, excluding blocked peers.
    pub fn find_peer_by_ip(&self, ip: &str) -> Option<&VerifiedPeerCredentials> {
        let clean_ip = ip.trim();
        if clean_ip.is_empty() || self.blocked_ips.iter().any(|bip| bip == clean_ip) {
            return None;
        }
        self.peers.values().find(|p| {
            p.last_ip == clean_ip && !self.blocked_device_ids.iter().any(|b| b == &p.device_id_hex)
        })
    }

    /// Looks up a pinned peer by its 32-character hex device ID, excluding blocked peers.
    pub fn get_peer(&self, device_id_hex: &str) -> Option<&VerifiedPeerCredentials> {
        let canonical = device_id_hex.trim().to_ascii_lowercase();
        if self.blocked_device_ids.iter().any(|b| b == &canonical) {
            return None;
        }
        self.peers.get(&canonical)
    }

    /// Looks up a pinned peer by its 16-byte binary device ID.
    pub fn get_peer_by_id_bytes(&self, device_id: &[u8; 16]) -> Option<&VerifiedPeerCredentials> {
        let hex = super::hex_encode(device_id);
        self.get_peer(&hex)
    }

    /// Returns a sorted list of all active pinned peers.
    pub fn list_peers(&self) -> Vec<VerifiedPeerCredentials> {
        let mut out: Vec<VerifiedPeerCredentials> = self.peers.values().cloned().collect();
        out.sort_by(|a, b| a.hostname.cmp(&b.hostname).then(a.device_id_hex.cmp(&b.device_id_hex)));
        out
    }

    /// Updates the `last_ip` record for a pinned peer after a verified packet or handshake.
    pub fn update_peer_last_ip(
        &mut self,
        device_id_hex: &str,
        new_ip: &str,
    ) -> Result<(), KeystoreError> {
        let canonical = device_id_hex.trim().to_ascii_lowercase();
        let clean_new_ip = new_ip.trim();
        if !self.peers.contains_key(&canonical) {
            return Err(KeystoreError::PeerNotFound(canonical));
        }
        let unchanged = self
            .peers
            .get(&canonical)
            .map(|p| p.last_ip == clean_new_ip)
            .unwrap_or(false);
        if unchanged {
            return Ok(());
        }
        let mut next_peers = self.peers.clone();
        if let Some(peer) = next_peers.get_mut(&canonical) {
            peer.last_ip = clean_new_ip.to_string();
        }
        self.persist_state(&next_peers, &self.blocked_device_ids, &self.blocked_ips)?;
        self.peers = next_peers;
        Ok(())
    }

    /// Persists current in-memory state to disk atomically.
    pub fn persist_to_disk(&self) -> Result<(), KeystoreError> {
        self.persist_state(&self.peers, &self.blocked_device_ids, &self.blocked_ips)
    }

    /// Internal serialization, AEAD encryption, HMAC calculation, and atomic write.
    fn persist_state(
        &self,
        peers_map: &HashMap<String, VerifiedPeerCredentials>,
        blocked_device_ids: &[String],
        blocked_ips: &[String],
    ) -> Result<(), KeystoreError> {
        let local_pk_bytes = self.local_verifying_key.to_bytes();
        let local_sk_bytes = Zeroizing::new(self.local_signing_key.to_bytes());
        let local_aad = build_local_identity_aad(&self.local_device_id, &local_pk_bytes);
        let wrapped_local_sk = wrap_secret_32(&self.kek, &local_sk_bytes, &local_aad)?;

        let mut serialized_peers = Vec::with_capacity(peers_map.len());
        for peer in peers_map.values() {
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

        let mut sorted_blocked_ids = blocked_device_ids.to_vec();
        sorted_blocked_ids.sort();
        sorted_blocked_ids.dedup();
        let mut sorted_blocked_ips = blocked_ips.to_vec();
        sorted_blocked_ips.sort();
        sorted_blocked_ips.dedup();

        let mut file_obj = KeystoreFileV2 {
            schema_version: KEYSTORE_SCHEMA_VERSION,
            local_device_id_hex: self.local_device_id_hex.clone(),
            local_ed25519_pubkey_hex: super::hex_encode(&local_pk_bytes),
            wrapped_local_ed25519_sk: wrapped_local_sk,
            peers: serialized_peers,
            blocked_device_ids: sorted_blocked_ids,
            blocked_ips: sorted_blocked_ips,
            legacy_v1_quarantined: self.legacy_v1_quarantined,
            state_mac_hex: None,
        };
        let mac = compute_keystore_file_mac(&self.kek, &file_obj)?;
        file_obj.state_mac_hex = Some(super::hex_encode(&mac));

        let json_bytes = serde_json::to_vec_pretty(&file_obj)
            .map_err(|e| KeystoreError::SerializationFailure(e.to_string()))?;

        atomic_write_secure_file(&self.storage_dir, &self.keystore_path, &json_bytes)
    }
}

/// Computes the HMAC-SHA256 integrity tag over all serialized keystore metadata fields.
fn compute_keystore_file_mac(
    kek: &[u8; 32],
    file_obj: &KeystoreFileV2,
) -> Result<[u8; 32], KeystoreError> {
    let hk = Hkdf::<Sha256>::new(Some(KEYSTORE_META_MAC_SALT), kek);
    let mut mac_key = Zeroizing::new([0u8; 32]);
    hk.expand(KEYSTORE_META_MAC_INFO, &mut *mac_key)
        .map_err(|e| KeystoreError::OsKeystoreFailure(format!("HKDF meta MAC key failed: {}", e)))?;

    let mut mac = <HmacSha256 as Mac>::new_from_slice(&*mac_key)
        .map_err(|_| KeystoreError::OsKeystoreFailure("HMAC meta MAC init failed".into()))?;

    fn update_lp(mac: &mut HmacSha256, bytes: &[u8]) {
        mac.update(&(bytes.len() as u32).to_be_bytes());
        mac.update(bytes);
    }

    mac.update(&file_obj.schema_version.to_be_bytes());
    update_lp(&mut mac, file_obj.local_device_id_hex.as_bytes());
    update_lp(&mut mac, file_obj.local_ed25519_pubkey_hex.as_bytes());
    mac.update(&[u8::from(file_obj.legacy_v1_quarantined)]);

    let mut peers = file_obj.peers.clone();
    peers.sort_by(|a, b| a.device_id_hex.cmp(&b.device_id_hex));
    mac.update(&(peers.len() as u32).to_be_bytes());
    for p in &peers {
        mac.update(&p.schema_version.to_be_bytes());
        update_lp(&mut mac, p.device_id_hex.as_bytes());
        update_lp(&mut mac, p.ed25519_pubkey_hex.as_bytes());
        update_lp(&mut mac, p.key_id_hex.as_bytes());
        update_lp(&mut mac, p.hostname.as_bytes());
        update_lp(&mut mac, p.os.as_bytes());
        update_lp(&mut mac, p.last_ip.as_bytes());
        mac.update(&p.paired_at_epoch.to_be_bytes());
        mac.update(&[u8::from(p.via_direct_cable)]);
    }

    mac.update(&(file_obj.blocked_device_ids.len() as u32).to_be_bytes());
    for bid in &file_obj.blocked_device_ids {
        update_lp(&mut mac, bid.as_bytes());
    }
    mac.update(&(file_obj.blocked_ips.len() as u32).to_be_bytes());
    for bip in &file_obj.blocked_ips {
        update_lp(&mut mac, bip.as_bytes());
    }

    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    Ok(out)
}

/// Constructs the AAD byte slice binding local identity record:
/// `AAD_LOCAL_IDENTITY_PREFIX || device_id || pubkey`.
fn build_local_identity_aad(device_id: &[u8; 16], pubkey: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_LOCAL_IDENTITY_PREFIX.len() + 16 + 32);
    aad.extend_from_slice(AAD_LOCAL_IDENTITY_PREFIX);
    aad.extend_from_slice(device_id);
    aad.extend_from_slice(pubkey);
    aad
}

/// Constructs the AAD byte slice binding peer root key record:
/// `AAD_PEER_ROOT_PREFIX || device_id || pubkey || key_id`.
fn build_peer_root_aad(device_id: &[u8; 16], pubkey: &[u8; 32], key_id: &[u8; 16]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_PEER_ROOT_PREFIX.len() + 16 + 32 + 16);
    aad.extend_from_slice(AAD_PEER_ROOT_PREFIX);
    aad.extend_from_slice(device_id);
    aad.extend_from_slice(pubkey);
    aad.extend_from_slice(key_id);
    aad
}

/// Wraps a 32-byte secret with `ChaCha20Poly1305` using an ephemeral 12-byte CSPRNG nonce and authenticated AAD.
fn wrap_secret_32(
    kek: &[u8; 32],
    secret: &[u8; 32],
    aad: &[u8],
) -> Result<AeadWrappedSecret, KeystoreError> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(kek));
    let mut nonce_bytes = [0u8; 12];
    super::try_csprng_fill(&mut nonce_bytes)
        .map_err(|e| KeystoreError::OsKeystoreFailure(format!("CSPRNG failed: {}", e)))?;
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

/// Unwraps an envelope-encrypted 32-byte secret, verifying the Poly1305 authentication tag against `aad`.
fn unwrap_secret_32(
    kek: &[u8; 32],
    wrapped: &AeadWrappedSecret,
    aad: &[u8],
) -> Result<Zeroizing<[u8; 32]>, KeystoreError> {
    let nonce_bytes: [u8; 12] = super::hex_decode_array(&wrapped.nonce_hex)
        .ok_or_else(|| KeystoreError::AeadTamperDetected("invalid wrapped nonce_hex".into()))?;
    let ciphertext = super::hex_decode(&wrapped.ciphertext_hex)
        .ok_or_else(|| KeystoreError::AeadTamperDetected("invalid wrapped ciphertext_hex".into()))?;

    // 32 bytes plaintext + 16 bytes Poly1305 AEAD tag = 48 bytes
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

/// Maximum permitted keystore file size (16 MiB) to prevent decompression or memory exhaustion.
const MAX_KEYSTORE_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// Resolves the default security keystore directory for the current platform:
/// - Windows: `%LOCALAPPDATA%\Integrator\security` or `%USERPROFILE%\.integrator\security`.
/// - macOS/Linux: `$HOME/.integrator/security`.
pub fn try_default_keystore_dir() -> Result<PathBuf, KeystoreError> {
    #[cfg(target_os = "windows")]
    {
        if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
            let trimmed = local_app_data.trim();
            if !trimmed.is_empty() {
                return Ok(PathBuf::from(trimmed).join("Integrator").join("security"));
            }
        }
        if let Ok(user_profile) = std::env::var("USERPROFILE") {
            let trimmed = user_profile.trim();
            if !trimmed.is_empty() {
                return Ok(PathBuf::from(trimmed).join(".integrator").join("security"));
            }
        }
        Err(KeystoreError::IoFailure(
            "Neither LOCALAPPDATA nor USERPROFILE is set; refusing insecure temporary keystore fallback".into(),
        ))
    }
    #[cfg(not(target_os = "windows"))]
    {
        if let Ok(home) = std::env::var("HOME") {
            let trimmed = home.trim();
            if !trimmed.is_empty() {
                return Ok(PathBuf::from(trimmed).join(".integrator").join("security"));
            }
        }
        Err(KeystoreError::IoFailure(
            "HOME is unset or empty; refusing insecure temporary keystore fallback".into(),
        ))
    }
}

/// Convenience accessor for [`try_default_keystore_dir`], returning `None` if unresolvable.
pub fn default_keystore_dir() -> Option<PathBuf> {
    try_default_keystore_dir().ok()
}

/// Verifies that a path is a regular file and NOT a symlink or Windows reparse point.
fn verify_non_symlink_regular_file(path: &Path) -> Result<fs::Metadata, KeystoreError> {
    let meta = fs::symlink_metadata(path)
        .map_err(|e| KeystoreError::IoFailure(format!("stat {}: {}", path.display(), e)))?;
    if meta.file_type().is_symlink() {
        return Err(KeystoreError::IoFailure(format!(
            "refusing to follow symlink at {}",
            path.display()
        )));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        if (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            return Err(KeystoreError::IoFailure(format!(
                "refusing to follow reparse point at {}",
                path.display()
            )));
        }
    }
    if !meta.is_file() {
        return Err(KeystoreError::IoFailure(format!(
            "expected regular file at {}",
            path.display()
        )));
    }
    Ok(meta)
}

/// Safely reads the byte contents of a keystore file, rejecting symlinks and oversized files.
fn read_secure_bytes(path: &Path) -> Result<Vec<u8>, KeystoreError> {
    let meta = verify_non_symlink_regular_file(path)?;
    if meta.len() > MAX_KEYSTORE_FILE_BYTES {
        return Err(KeystoreError::CorruptKeystore(format!(
            "file {} exceeds maximum size ({} bytes)",
            path.display(),
            meta.len()
        )));
    }

    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }

    let file = opts
        .open(path)
        .map_err(|e| KeystoreError::IoFailure(format!("open {}: {}", path.display(), e)))?;
    let mut buf = Vec::with_capacity(meta.len().min(65536) as usize);
    let mut limited = file.take(MAX_KEYSTORE_FILE_BYTES + 1);
    limited
        .read_to_end(&mut buf)
        .map_err(|e| KeystoreError::IoFailure(format!("read {}: {}", path.display(), e)))?;
    if (buf.len() as u64) > MAX_KEYSTORE_FILE_BYTES {
        return Err(KeystoreError::CorruptKeystore(format!(
            "file {} exceeded {} bytes while reading",
            path.display(),
            MAX_KEYSTORE_FILE_BYTES
        )));
    }
    Ok(buf)
}

/// Validates or creates the keystore directory with restrictive access permissions (POSIX `0700`).
fn ensure_secure_directory(dir: &Path) -> Result<(), KeystoreError> {
    match fs::symlink_metadata(dir) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(KeystoreError::IoFailure(format!(
                    "refusing symlink keystore directory {}",
                    dir.display()
                )));
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
                if (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
                    return Err(KeystoreError::IoFailure(format!(
                        "refusing reparse-point keystore directory {}",
                        dir.display()
                    )));
                }
            }
            if !meta.is_dir() {
                return Err(KeystoreError::IoFailure(format!(
                    "keystore path {} exists and is not a directory",
                    dir.display()
                )));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(dir).map_err(|e| {
                KeystoreError::IoFailure(format!("create_dir_all {}: {}", dir.display(), e))
            })?;
            let meta = fs::symlink_metadata(dir).map_err(|e| {
                KeystoreError::IoFailure(format!("stat {}: {}", dir.display(), e))
            })?;
            if meta.file_type().is_symlink() || !meta.is_dir() {
                return Err(KeystoreError::IoFailure(format!(
                    "keystore directory {} failed post-create validation",
                    dir.display()
                )));
            }
        }
        Err(e) => {
            return Err(KeystoreError::IoFailure(format!(
                "stat {}: {}",
                dir.display(),
                e
            )));
        }
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(|e| {
            KeystoreError::IoFailure(format!("chmod 0700 {}: {}", dir.display(), e))
        })?;
    }
    Ok(())
}

/// Atomically writes `content` to `target` file by first writing to a random tempfile with mode `0600`
/// and renaming it over `target`.
fn atomic_write_secure_file(dir: &Path, target: &Path, content: &[u8]) -> Result<(), KeystoreError> {
    ensure_secure_directory(dir)?;
    let mut rnd = [0u8; 6];
    super::try_csprng_fill(&mut rnd)
        .map_err(|e| KeystoreError::OsKeystoreFailure(format!("CSPRNG failed: {}", e)))?;
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

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = file.set_permissions(fs::Permissions::from_mode(0o600)) {
            let _ = fs::remove_file(&tmp_path);
            return Err(KeystoreError::IoFailure(format!(
                "chmod 0600 temp {}: {}",
                tmp_path.display(),
                e
            )));
        }
    }

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
        fs::set_permissions(target, fs::Permissions::from_mode(0o600)).map_err(|e| {
            KeystoreError::IoFailure(format!("chmod 0600 {}: {}", target.display(), e))
        })?;
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
    if default_keystore_dir().as_deref() == Some(storage_dir) {
        #[cfg(target_os = "windows")]
        if let Ok(profile) = std::env::var("USERPROFILE") {
            let trimmed = profile.trim();
            if !trimmed.is_empty() {
                let p = PathBuf::from(trimmed);
                candidate_paths.push(p.join(".usbc_clipboard_cache").join("trusted_peers.json"));
                candidate_paths.push(p.join(".integrator").join("trusted_peers.json"));
            }
        }
        #[cfg(not(target_os = "windows"))]
        if let Ok(home) = std::env::var("HOME") {
            let trimmed = home.trim();
            if !trimmed.is_empty() {
                let p = PathBuf::from(trimmed);
                candidate_paths.push(p.join(".usbc_clipboard_cache").join("trusted_peers.json"));
                candidate_paths.push(p.join(".integrator").join("trusted_peers.json"));
            }
        }
    }

    let mut quarantined_any = false;
    for legacy_path in candidate_paths {
        let Ok(meta) = fs::symlink_metadata(&legacy_path) else {
            continue;
        };
        if meta.file_type().is_symlink() || !meta.is_file() {
            continue;
        }
        let bak_path = legacy_path.with_extension("json.v1.deprecated.bak");
        match fs::rename(&legacy_path, &bak_path) {
            Ok(()) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(&bak_path, fs::Permissions::from_mode(0o600));
                }
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
    quarantined_any
}

// ============================================================================
// Platform-Specific OS Master KEK Implementations
// ============================================================================

#[cfg(target_os = "macos")]
struct NoUiKeychainGuard {
    prev_allowed: u8,
    _lock: std::sync::MutexGuard<'static, ()>,
}

#[cfg(target_os = "macos")]
impl NoUiKeychainGuard {
    /// Acquires a global mutex and disables interactive Keychain UI dialogs via `SecKeychainSetUserInteractionAllowed(0)`.
    fn acquire() -> Self {
        use std::os::raw::c_int;
        use std::sync::OnceLock;

        #[link(name = "Security", kind = "framework")]
        extern "C" {
            fn SecKeychainGetUserInteractionAllowed(state: *mut u8) -> c_int;
            fn SecKeychainSetUserInteractionAllowed(state: u8) -> c_int;
        }

        static KC_UI_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();
        let lock = KC_UI_MUTEX
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut prev_allowed: u8 = 1;
        unsafe {
            let _ = SecKeychainGetUserInteractionAllowed(&mut prev_allowed);
            let _ = SecKeychainSetUserInteractionAllowed(0);
        }
        Self {
            prev_allowed,
            _lock: lock,
        }
    }
}

#[cfg(target_os = "macos")]
impl Drop for NoUiKeychainGuard {
    fn drop(&mut self) {
        use std::os::raw::c_int;
        #[link(name = "Security", kind = "framework")]
        extern "C" {
            fn SecKeychainSetUserInteractionAllowed(state: u8) -> c_int;
        }
        unsafe {
            let _ = SecKeychainSetUserInteractionAllowed(self.prev_allowed);
        }
    }
}

#[cfg(target_os = "macos")]
/// Queries Apple IOKit registry for immutable hardware identifiers (`IOPlatformUUID`, `IOPlatformSerialNumber`).
fn macos_read_platform_hardware_identity() -> Result<Vec<u8>, KeystoreError> {
    use core_foundation::base::{kCFAllocatorDefault, CFGetTypeID, CFTypeRef, TCFType};
    use core_foundation::string::{CFString, CFStringRef};
    use std::os::raw::c_char;

    #[link(name = "IOKit", kind = "framework")]
    extern "C" {
        fn IOServiceMatching(name: *const c_char) -> CFTypeRef;
        fn IOServiceGetMatchingService(main_port: u32, matching: CFTypeRef) -> u32;
        fn IORegistryEntryCreateCFProperty(
            entry: u32,
            key: CFTypeRef,
            allocator: CFTypeRef,
            options: u32,
        ) -> CFTypeRef;
        fn IOObjectRelease(object: u32) -> i32;
    }

    let mut binding = Vec::with_capacity(96);
    unsafe {
        let matching = IOServiceMatching(b"IOPlatformExpertDevice\0".as_ptr() as *const c_char);
        if !matching.is_null() {
            let service = IOServiceGetMatchingService(0, matching);
            if service != 0 {
                for key_name in ["IOPlatformUUID", "IOPlatformSerialNumber"] {
                    let cf_key = CFString::new(key_name);
                    let prop = IORegistryEntryCreateCFProperty(
                        service,
                        cf_key.as_CFTypeRef(),
                        kCFAllocatorDefault,
                        0,
                    );
                    if !prop.is_null() {
                        if CFGetTypeID(prop) == CFString::type_id() {
                            let val: CFString =
                                TCFType::wrap_under_create_rule(prop as CFStringRef);
                            let s = val.to_string();
                            if !s.trim().is_empty() {
                                binding.extend_from_slice(key_name.as_bytes());
                                binding.push(b'=');
                                binding.extend_from_slice(s.trim().as_bytes());
                                binding.push(b'|');
                            }
                        } else {
                            core_foundation::base::CFRelease(prop);
                        }
                    }
                }
                let _ = IOObjectRelease(service);
            }
        }
    }

    if !binding.is_empty() {
        return Ok(binding);
    }

    // CLI fallback via `/usr/sbin/ioreg` if IOKit direct symbols fail
    if let Ok(out) = std::process::Command::new("/usr/sbin/ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output()
    {
        if out.status.success() {
            let txt = String::from_utf8_lossy(&out.stdout);
            for key_name in ["IOPlatformUUID", "IOPlatformSerialNumber"] {
                for line in txt.lines() {
                    if let Some((_, rhs)) = line.split_once(key_name) {
                        if let Some((_, val_part)) = rhs.split_once('=') {
                            let val = val_part.trim().trim_matches('"').trim();
                            if !val.is_empty() {
                                binding.extend_from_slice(key_name.as_bytes());
                                binding.push(b'=');
                                binding.extend_from_slice(val.as_bytes());
                                binding.push(b'|');
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    if binding.is_empty() {
        return Err(KeystoreError::OsKeystoreFailure(
            "Unable to query macOS IOPlatformUUID/SerialNumber for hardware-bound KEK".into(),
        ));
    }
    Ok(binding)
}

#[cfg(target_os = "macos")]
/// Derives $K_{\text{kek}}$ by combining a mode-`0600` random seed file with macOS hardware identity (`IOPlatformUUID`).
fn macos_hw_bound_load_or_create_kek(
    storage_dir: &Path,
) -> Result<Zeroizing<[u8; 32]>, KeystoreError> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    extern "C" {
        fn getuid() -> u32;
    }

    ensure_secure_directory(storage_dir)?;

    let seed_path = storage_dir.join(".master_kek_v2.seed");
    let mut seed = Zeroizing::new(Vec::new());

    match fs::symlink_metadata(&seed_path) {
        Ok(_) => {
            let existing = Zeroizing::new(read_secure_bytes(&seed_path)?);
            if existing.len() != 32 {
                return Err(KeystoreError::CorruptKeystore(format!(
                    "invalid macOS sealed KEK seed length {} in {} (expected 32); refusing to overwrite existing trust state",
                    existing.len(),
                    seed_path.display()
                )));
            }
            fs::set_permissions(&seed_path, fs::Permissions::from_mode(0o600)).map_err(|e| {
                KeystoreError::IoFailure(format!("chmod 0600 {}: {}", seed_path.display(), e))
            })?;
            *seed = existing.to_vec();
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(KeystoreError::OsKeystoreFailure(format!(
                "stat macOS sealed KEK seed {}: {}",
                seed_path.display(),
                e
            )));
        }
    }

    if seed.len() != 32 {
        let mut fresh = Zeroizing::new([0u8; 32]);
        super::try_csprng_fill(&mut *fresh)
            .map_err(|e| KeystoreError::OsKeystoreFailure(format!("CSPRNG failed: {}", e)))?;
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&seed_path)
        {
            Ok(mut f) => {
                if let Err(e) = f.set_permissions(fs::Permissions::from_mode(0o600)) {
                    drop(f);
                    let _ = fs::remove_file(&seed_path);
                    return Err(KeystoreError::IoFailure(format!(
                        "chmod 0600 macOS sealed KEK seed {}: {}",
                        seed_path.display(),
                        e
                    )));
                }
                if let Err(e) = f.write_all(&*fresh).and_then(|_| f.sync_all()) {
                    drop(f);
                    let _ = fs::remove_file(&seed_path);
                    return Err(KeystoreError::OsKeystoreFailure(format!(
                        "write/sync macOS sealed KEK seed {}: {}",
                        seed_path.display(),
                        e
                    )));
                }
                *seed = fresh.to_vec();
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing = Zeroizing::new(read_secure_bytes(&seed_path)?);
                if existing.len() != 32 {
                    return Err(KeystoreError::CorruptKeystore(
                        "Invalid macOS sealed KEK seed length".into(),
                    ));
                }
                *seed = existing.to_vec();
            }
            Err(e) => {
                return Err(KeystoreError::OsKeystoreFailure(format!(
                    "create macOS sealed KEK seed {}: {}",
                    seed_path.display(),
                    e
                )));
            }
        }
    }

    let hw_id = macos_read_platform_hardware_identity()?;
    let mut ikm = Zeroizing::new(Vec::with_capacity(seed.len() + 1 + hw_id.len()));
    ikm.extend_from_slice(&seed);
    ikm.push(b'|');
    ikm.extend_from_slice(&hw_id);

    let dir_canonical = fs::canonicalize(storage_dir).unwrap_or_else(|_| storage_dir.to_path_buf());
    let mut salt = Vec::from(&b"integrator-macos-hw-kek-salt-v2|"[..]);
    salt.extend_from_slice(&super::sha256_digest(
        dir_canonical.to_string_lossy().as_bytes(),
    ));

    let uid = unsafe { getuid() };
    let info = format!("integrator-macos-hw-kek-v2:uid={}", uid);

    let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut kek = Zeroizing::new([0u8; 32]);
    hk.expand(info.as_bytes(), &mut *kek)
        .map_err(|e| KeystoreError::OsKeystoreFailure(format!("macOS HKDF-SHA256 expand failed: {}", e)))?;
    Ok(kek)
}

#[cfg(target_os = "macos")]
/// Loads existing $K_{\text{kek}}$ from macOS Keychain Services or derives a hardware-bound seed key.
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
        static kSecReturnData: CFTypeRef;
        static kSecMatchLimit: CFTypeRef;
        static kSecMatchLimitOne: CFTypeRef;
        static kSecUseAuthenticationUI: CFTypeRef;
        static kSecUseAuthenticationUIFail: CFTypeRef;

        fn SecItemCopyMatching(query: CFTypeRef, result: *mut CFTypeRef) -> c_int;
    }

    const ERR_SEC_SUCCESS: c_int = 0;
    const ERR_SEC_ITEM_NOT_FOUND: c_int = -25300;
    const ERR_SEC_AUTH_FAILED: c_int = -25293;
    const ERR_SEC_INTERACTION_NOT_ALLOWED: c_int = -25308;

    // Fast path: once a hardware+UID-bound sealed KEK seed exists, derive K_kek directly
    // without touching login.keychain-db so rebuilds/ad-hoc runs never trigger password dialogs.
    if storage_dir.join(".master_kek_v2.seed").is_file() {
        return macos_hw_bound_load_or_create_kek(storage_dir);
    }

    let service = CFString::new("com.integrator.security.keystore.v2");
    // Scope the account name by storage_dir hash so custom paths don't collide.
    let account_hash = super::hex_encode(&super::sha256_digest(
        storage_dir.to_string_lossy().as_bytes(),
    )[0..8]);
    let account = CFString::new(&format!("master-kek-v2-{}", account_hash));

    // Strictly suppress legacy SecKeychain interactive UI dialogs while checking for an
    // existing Keychain item that is already silently readable by this code signature.
    let _no_ui_guard = NoUiKeychainGuard::acquire();
    unsafe {
        let mut query: CFMutableDictionary<CFTypeRef, CFTypeRef> = CFMutableDictionary::new();
        query.set(kSecClass, kSecClassGenericPassword);
        query.set(kSecAttrService, service.as_CFTypeRef());
        query.set(kSecAttrAccount, account.as_CFTypeRef());
        query.set(kSecReturnData, CFBoolean::true_value().as_CFTypeRef());
        query.set(kSecMatchLimit, kSecMatchLimitOne);
        query.set(kSecUseAuthenticationUI, kSecUseAuthenticationUIFail);

        let mut result: CFTypeRef = std::ptr::null();
        let status = SecItemCopyMatching(query.as_CFTypeRef(), &mut result);
        if status == ERR_SEC_SUCCESS && !result.is_null() {
            let data: CFData = TCFType::wrap_under_create_rule(result as *const _);
            if data.len() == 32 {
                let mut kek = Zeroizing::new([0u8; 32]);
                kek.copy_from_slice(data.bytes());
                return Ok(kek);
            }
        }

        if status != ERR_SEC_ITEM_NOT_FOUND
            && status != ERR_SEC_AUTH_FAILED
            && status != ERR_SEC_INTERACTION_NOT_ALLOWED
        {
            warn!(
                "macOS Keychain non-interactive check returned OSStatus {}; using hardware-bound sealed KEK",
                status
            );
        }
    }
    drop(_no_ui_guard);

    // Do not create new ad-hoc CDHash-pinned items in login.keychain-db (which prompt for the
    // user's macOS password on every rebuild). Bind K_kek via IOPlatformUUID + UID + 0600 seed.
    macos_hw_bound_load_or_create_kek(storage_dir)
}

#[cfg(target_os = "windows")]
/// Protects or unprotects $K_{\text{kek}}$ using Win32 Data Protection API (`CryptProtectData` / `CryptUnprotectData`).
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
    let entropy_len = u32::try_from(entropy_vec.len())
        .map_err(|_| KeystoreError::OsKeystoreFailure("DPAPI entropy too large".into()))?;
    let entropy_blob = DataBlob {
        cb_data: entropy_len,
        pb_data: entropy_vec.as_mut_ptr(),
    };

    let dpapi_exists = match fs::symlink_metadata(&dpapi_path) {
        Ok(_) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => {
            return Err(KeystoreError::IoFailure(format!(
                "stat DPAPI file {}: {}",
                dpapi_path.display(),
                e
            )));
        }
    };

    if dpapi_exists {
        let mut encrypted_bytes = Zeroizing::new(read_secure_bytes(&dpapi_path)?);
        if encrypted_bytes.is_empty() {
            return Err(KeystoreError::CorruptKeystore("empty DPAPI file".into()));
        }
        let in_len = u32::try_from(encrypted_bytes.len())
            .map_err(|_| KeystoreError::CorruptKeystore("DPAPI file exceeds u32 size".into()))?;

        let in_blob = DataBlob {
            cb_data: in_len,
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

        let out_len = out_blob.cb_data as usize;
        if out_len != 32 {
            unsafe {
                for i in 0..out_len {
                    std::ptr::write_volatile(out_blob.pb_data.add(i), 0);
                }
                std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
                LocalFree(out_blob.pb_data as *mut c_void);
            }
            return Err(KeystoreError::CorruptKeystore(format!(
                "DPAPI unwrapped KEK has invalid length {}",
                out_len
            )));
        }

        let slice = unsafe { std::slice::from_raw_parts(out_blob.pb_data, out_len) };
        let mut kek = Zeroizing::new([0u8; 32]);
        kek.copy_from_slice(slice);
        unsafe {
            for i in 0..out_len {
                std::ptr::write_volatile(out_blob.pb_data.add(i), 0);
            }
            std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
            LocalFree(out_blob.pb_data as *mut c_void);
        }
        return Ok(kek);
    }

    let mut new_kek = Zeroizing::new([0u8; 32]);
    super::try_csprng_fill(&mut *new_kek)
        .map_err(|e| KeystoreError::OsKeystoreFailure(format!("CSPRNG failed: {}", e)))?;

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

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
/// Fallback implementation for generic Unix systems binding `/etc/machine-id` and EUID.
fn unix_fallback_load_or_create_kek(
    storage_dir: &Path,
) -> Result<Zeroizing<[u8; 32]>, KeystoreError> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    ensure_secure_directory(storage_dir)?;
    let key_file = storage_dir.join(".master_kek_v2.seed");

    let raw_seed: Zeroizing<[u8; 32]> = match fs::symlink_metadata(&key_file) {
        Ok(_) => {
            let bytes = Zeroizing::new(read_secure_bytes(&key_file)?);
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
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut arr = Zeroizing::new([0u8; 32]);
            super::try_csprng_fill(&mut *arr)
                .map_err(|e| KeystoreError::OsKeystoreFailure(format!("CSPRNG failed: {}", e)))?;
            atomic_write_secure_file(storage_dir, &key_file, &*arr)?;
            arr
        }
        Err(e) => {
            return Err(KeystoreError::IoFailure(format!(
                "stat {}: {}",
                key_file.display(),
                e
            )));
        }
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
        .map_err(|e| KeystoreError::OsKeystoreFailure(format!("HKDF expand failed: {}", e)))?;
    Ok(derived)
}

/// Global singleton accessor for the production v2 keystore wrapped in a thread-safe `Mutex`.
static GLOBAL_KEYSTORE_V2: OnceLock<Result<Mutex<KeystoreV2>, KeystoreError>> = OnceLock::new();

/// Attempts to initialize or retrieve the global singleton keystore mutex.
pub fn try_global_keystore() -> Result<&'static Mutex<KeystoreV2>, KeystoreError> {
    let init = GLOBAL_KEYSTORE_V2.get_or_init(|| {
        #[cfg(test)]
        {
            let test_dir = std::env::temp_dir().join(format!(
                "integrator_global_ks_test_{}",
                std::process::id()
            ));
            let _ = std::fs::create_dir_all(&test_dir);
            KeystoreV2::open_with_provider(test_dir, &FixedKekProvider::new([0xA5u8; 32]))
                .map(Mutex::new)
        }
        #[cfg(not(test))]
        {
            KeystoreV2::open_default().map(Mutex::new)
        }
    });
    match init {
        Ok(m) => Ok(m),
        Err(e) => Err(e.clone()),
    }
}

/// Retrieves the global singleton keystore mutex, panicking if initialization fails.
pub fn global_keystore() -> &'static Mutex<KeystoreV2> {
    try_global_keystore().unwrap_or_else(|e| {
        panic!("Failed to initialize Integrator v2 security keystore: {}", e)
    })
}
