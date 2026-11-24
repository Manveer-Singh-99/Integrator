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
//! 3. **Layer 3: Whole-File Metadata Integrity MAC & Threat Model Boundary (SEC-1D-19)**:
//!    - An HMAC-SHA256 integrity tag (`state_mac_hex`) authenticates the entire serialized keystore contents
//!      (schema version, local identity, all peers, blocklists, quarantine flag, tombstones) under a dedicated MAC key
//!      derived from $K_{\text{kek}}$ (`KEYSTORE_META_MAC_INFO`).
//!    - Detects unauthorized offline modifications to unencrypted metadata (e.g. modifying pinned hostnames,
//!      tampering with blocklists, or injecting revoked peers).
//!    - **Threat Model Boundary & Anti-Rollback Note**: Whole-file HMAC verification guarantees cryptographic integrity
//!      and authenticity against unauthorized modification or tampering of keystore records. However, local HMAC verification
//!      does NOT prevent an attacker with full local filesystem write access from substituting the entire keystore file with
//!      a previously authenticated, valid historical snapshot (rollback attack), in the absence of hardware monotonic counter
//!      anchors. Neither macOS nor Windows standard user filesystems provide a generic hardware monotonic counter API for
//!      userland configuration files. Integrator mitigates in-memory rollback via monotonically increasing per-peer trust
//!      generations across daemon lifetimes and persists tombstones, but acknowledges offline whole-file substitution
//!      as outside the userland HMAC threat model boundary.
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
//!   - `app/src/security/passkey.rs`: Deriving keystore-bound encryption keys for WebAuthn/FIDO2 passkey vault storage.
//!   - `app/src/camera/mod.rs`: Querying and persisting generation-bound camera authorization consents (`always_allow:<gen>`, `blocked`).
//!   - `app/src/clipboard/service.rs`: Verifying active peer trust generations before clipboard payload synchronization.
//!   - `app/src/core.rs` & `app/src/system_info.rs`: Local canonical `device_id` retrieval and peer revocation orchestration.
//! - **Downstream Callees**:
//!   - `chacha20poly1305`: AEAD envelope encryption and decryption of 32-byte private/root keys.
//!   - `ed25519_dalek`: Local signing key management, transcript signing, and strict RFC 8032 signature verification.
//!   - `hkdf`, `hmac`, `sha2`: HKDF-SHA256 key derivation and whole-file metadata HMAC-SHA256 authentication.
//!   - `subtle` & `zeroize`: Constant-time byte array comparisons (`ConstantTimeEq`) and RAII secret zeroization (`Zeroizing`).
//!   - `app/src/security/transport.rs`: Synchronizing in-memory peer trust generations (`register_peer_trust_generation`, `invalidate_peer_trust`).
//!   - OS Cryptographic & Hardware APIs (`crypt32.dll` / `kernel32.dll` on Windows; `Security.framework` / `IOKit.framework` on macOS).
//! - **Cross-Platform / Cross-Device Flow (Mac ↔ Windows 11)**:
//!   - During mutual RFC 9382 SPAKE2 pairing over TCP (`pairing.rs`), both the macOS host and Windows 11 PC verify each
//!     other's Ed25519 public key and deterministic 16-byte `device_id` via [`KeystoreV2::check_peer_identity_pinning`],
//!     derive a shared 256-bit root secret ($K_{\text{root}}$) and 16-byte `key_id`, and atomically commit the counterpart's
//!     [`VerifiedPeerCredentials`] via [`KeystoreV2::commit_paired_peer`] with a monotonically increasing `trust_generation`.
//!   - Subsequent control/data connections (`TransportSessionV2` over TCP and `AudioUdp` over UDP) look up the pinned
//!     peer record by `device_id` to verify `key_id` equality and Ed25519 transcript signatures without transmitting $K_{\text{root}}$.
//!   - When a user unpairs or blocks a counterpart on either Mac or Windows ([`KeystoreV2::unpair_peer_ext`],
//!     [`KeystoreV2::untrust_or_block_peer_ext`]), the keystore advances the peer's `trust_generation` tombstone on disk first
//!     and then immediately notifies `security::transport::invalidate_peer_trust` to tear down active cross-device sessions (`VULN-04`).
//!
//! ## 4. Threading & Concurrency Model
//! Access to the active keystore is managed through the global thread-safe singleton [`global_keystore`],
//! which wraps a [`KeystoreV2`] instance inside a `std::sync::Mutex`.
//! - **Async Non-Blocking Rule**: In Tokio async contexts, callers acquire the mutex guard synchronously for brief
//!   in-memory reads or atomic file persistence and drop the guard before crossing any `.await` suspension point.
//! - **Deadlock Prevention Invariant (`SEC-1D-04`)**: Higher-level subsystem locks (such as camera authorization consent
//!   managers or pending peer tables) must NEVER be acquired while holding the `global_keystore()` mutex.
//! - **Fail-Closed Persistence Ordering**: Mutating operations (`commit_paired_peer`, `unpair_peer_ext`,
//!   `untrust_or_block_peer_ext`, `update_peer_last_ip`, `set_camera_consent`) serialize and atomically commit the
//!   updated state to disk *before* updating the in-memory maps or broadcasting transport invalidations.
//!
//! ## 5. Security & Safety Invariants
//! - **Constant-Time Verification**: All secret comparisons, HMAC tags, key IDs, device IDs, and public keys are compared
//!   using `subtle::ConstantTimeEq` (`ct_eq`) to prevent timing side-channel leaks.
//! - **Secret Zeroization**: All plaintext KEKs, Ed25519 seed bytes, decrypted root keys, HKDF PRKs/OKMs, and DPAPI buffers
//!   are wrapped in `zeroize::Zeroizing` or explicitly wiped via `write_volatile` + `compiler_fence(Ordering::SeqCst)`.
//! - **FFI & `unsafe` Boundaries**: Restricted strictly to OS-native root-of-trust retrieval (`Security.framework` and
//!   `IOKit.framework` on macOS, `CryptProtectData`/`CryptUnprotectData`/`LocalFree` on Windows, `getuid`/`geteuid` on Unix)
//!   with explicit null-pointer, type-ID (`CFGetTypeID`), and buffer-length validation prior to slice construction.

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

/// Candidate Linux/Unix machine-ID file paths checked in order when deriving fallback KEK salt.
#[cfg(not(any(target_os = "windows", target_os = "macos")))]
#[cfg_attr(test, allow(dead_code))]
const LINUX_MACHINE_ID_PATHS: &[&str] = &["/etc/machine-id", "/var/lib/dbus/machine-id"];

/// macOS Keychain Services generic-password service identifier for the v2 master KEK.
#[cfg(target_os = "macos")]
#[cfg_attr(test, allow(dead_code))]
const MACOS_KEYCHAIN_SERVICE: &str = "com.integrator.security.keystore.v2";

/// Canonical filename of the encrypted v2 peer trust keystore.
const KEYSTORE_FILENAME_V2: &str = "trusted_peers_v2.json";

/// Filename of the deprecated v1 peer trust file quarantined on upgrade.
const LEGACY_KEYSTORE_V1_FILENAME: &str = "trusted_peers.json";

/// Hidden `.integrator` user configuration directory name for keystore storage and legacy quarantine.
const LEGACY_INTEGRATOR_DIR_NAME: &str = ".integrator";

/// Replacement file extension applied when quarantining deprecated v1 trust files.
const LEGACY_V1_QUARANTINE_EXT: &str = "json.v1.deprecated.bak";

/// Filename of the mode-`0600` CSPRNG seed used for hardware/UID-bound KEK derivation on Unix/macOS.
#[cfg(not(target_os = "windows"))]
#[cfg_attr(test, allow(dead_code))]
const MASTER_KEK_SEED_FILENAME: &str = ".master_kek_v2.seed";

/// Filename of the DPAPI-protected master KEK blob on Windows.
#[cfg(target_os = "windows")]
#[cfg_attr(test, allow(dead_code))]
const MASTER_KEK_DPAPI_FILENAME: &str = "master_kek_v2.dpapi";

/// Initial read buffer capacity ceiling in bytes when reading keystore files (64 KiB).
const KEYSTORE_FILE_READ_CHUNK_LIMIT: u64 = 65536;

/// Number of CSPRNG bytes appended as hex entropy to atomic temporary filenames (6 bytes).
const TEMP_FILENAME_ENTROPY_BYTES: usize = 6;

/// Lowercase sentinel hostname excluded from duplicate-hostname pinning conflict checks.
const UNKNOWN_HOSTNAME_SENTINEL: &str = "unknown";

/// HMAC-SHA256 message authentication code instance used for whole-file keystore metadata integrity verification.
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
        /// 32-character lowercase hex device ID claimed by the peer or record.
        claimed_hex: String,
        /// 32-character lowercase hex device ID deterministically derived from the Ed25519 public key.
        derived_hex: String,
    },
    /// Security alert: remote peer presented an Ed25519 public key conflicting with the already-pinned key.
    PinnedIdentityKeyMismatch {
        /// Canonical 32-character hex device ID or pinned hostname that triggered the conflict.
        peer_identifier: String,
        /// 64-character lowercase hex Ed25519 public key currently pinned in the keystore.
        pinned_pubkey_hex: String,
        /// 64-character lowercase hex Ed25519 public key presented by the peer.
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
#[allow(dead_code)]
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
    /// Fixed 32-byte Master Keystore Encryption Key ($K_{\text{kek}}$) zeroized on drop.
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

/// Default trust generation for legacy serialized peer records (1).
fn default_trust_generation() -> u64 {
    1
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
    /// Monotonically increasing trust epoch / generation for this peer pairing.
    #[serde(default = "default_trust_generation")]
    pub trust_generation: u64,
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
    /// Map of peer device ID hex to persisted trust generation tombstones for unpinned/revoked peers.
    #[serde(default)]
    pub tombstone_generations: HashMap<String, u64>,
    /// Map of peer device ID hex to persisted camera permissions ("always_allow:<gen>" or "blocked").
    #[serde(default)]
    pub persistent_camera_consents: HashMap<String, String>,
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
    /// Monotonically increasing trust epoch / generation for this peer pairing.
    pub trust_generation: u64,
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
            .field("trust_generation", &self.trust_generation)
            .finish()
    }
}

/// Active in-memory manager for local cryptographic identity and trusted peer credentials.
pub struct KeystoreV2 {
    /// Validated filesystem directory path containing `trusted_peers_v2.json` and platform KEK tokens.
    storage_dir: PathBuf,
    /// Full filesystem path to the active `trusted_peers_v2.json` file.
    keystore_path: PathBuf,
    /// 256-bit Master Keystore Encryption Key ($K_{\text{kek}}$) wrapped in [`Zeroizing`] for automatic memory wiping.
    kek: Zeroizing<[u8; 32]>,
    /// Local host's Ed25519 signing key used to authenticate pairing and transport handshakes.
    local_signing_key: SigningKey,
    /// Local host's Ed25519 verifying (public) key corresponding to `local_signing_key`.
    local_verifying_key: VerifyingKey,
    /// Canonical 16-byte binary local device ID derived via `SHA256("integrator-device-id-v2" || pubkey)[0..16]`.
    local_device_id: [u8; 16],
    /// Canonical 32-character lowercase hexadecimal representation of `local_device_id`.
    local_device_id_hex: String,
    /// Map of canonical 32-character hex peer device IDs to verified, unwrapped [`VerifiedPeerCredentials`].
    peers: HashMap<String, VerifiedPeerCredentials>,
    /// Canonical lowercase 32-character hex device IDs explicitly blocked from pairing or connecting.
    blocked_device_ids: Vec<String>,
    /// Trimmed IPv4/IPv6 address strings explicitly blocked from pairing or connecting.
    blocked_ips: Vec<String>,
    /// Sticky flag indicating whether a deprecated v1 `trusted_peers.json` file was detected and quarantined.
    legacy_v1_quarantined: bool,
    /// Monotonically increasing trust generation counter per peer device ID hex (including unpaired tombstones).
    peer_generations: HashMap<String, u64>,
    /// Map of peer device ID hex to persistent camera authorization policy (`"always_allow:<gen>"` or `"blocked"`).
    camera_consents: HashMap<String, String>,
}

impl KeystoreV2 {
    /// Opens or initializes the production v2 keystore in the default directory.
    ///
    /// # Errors
    /// Returns [`KeystoreError`] if OS secret storage or directory operations fail.
    #[allow(dead_code)]
    pub fn open_default() -> Result<Self, KeystoreError> {
        let dir = try_default_keystore_dir()?;
        Self::open_with_provider(dir, &OsNativeKekProvider)
    }

    /// Opens or initializes a v2 keystore in `storage_dir` using the specified `provider`.
    ///
    /// Performs directory validation (`0700`), stale temp-file sweep, legacy v1 quarantine,
    /// master KEK acquisition, and loads or initializes `trusted_peers_v2.json`.
    ///
    /// # Arguments
    /// * `storage_dir` - Directory path for keystore storage.
    /// * `provider` - KEK provider implementation.
    ///
    /// # Errors
    /// Returns [`KeystoreError`] if directory validation, KEK acquisition, keystore verification,
    /// or initial persistence fails.
    pub fn open_with_provider(
        storage_dir: PathBuf,
        provider: &dyn KekProvider,
    ) -> Result<Self, KeystoreError> {
        ensure_secure_directory(&storage_dir)?;

        // Safely sweep stale .tmp files from previous interrupted runs (SEC-1D-20)
        clean_stale_temp_files(&storage_dir);

        // Check and quarantine any legacy v1 trusted_peers.json files.
        let quarantined = quarantine_legacy_v1_files(&storage_dir);

        let kek = provider.load_or_create_kek(&storage_dir)?;
        let keystore_path = storage_dir.join(KEYSTORE_FILENAME_V2);

        // Inspect via symlink_metadata rather than Path::exists() so dangling symlinks are
        // detected and rejected by load_existing instead of being treated as absent.
        match fs::symlink_metadata(&keystore_path) {
            Ok(_) => Self::load_existing(storage_dir, keystore_path, kek, quarantined),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Self::initialize_fresh(storage_dir, keystore_path, kek, quarantined)
            }
            Err(e) => Err(KeystoreError::IoFailure(format!(
                "stat {}: {}",
                keystore_path.display(),
                e
            ))),
        }
    }

    /// Initializes a brand new keystore with a fresh Ed25519 signing keypair from the OS CSPRNG.
    ///
    /// # Arguments
    /// * `storage_dir` - Validated keystore directory path.
    /// * `keystore_path` - Destination path for `trusted_peers_v2.json`.
    /// * `kek` - 32-byte Master Keystore Encryption Key ($K_{\text{kek}}$).
    /// * `legacy_v1_quarantined` - Whether legacy v1 trust files were quarantined during open.
    ///
    /// # Errors
    /// Returns [`KeystoreError::OsKeystoreFailure`] if CSPRNG fails, or [`KeystoreError::IoFailure`]
    /// if initial atomic persistence fails.
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
            peer_generations: HashMap::new(),
            camera_consents: HashMap::new(),
        };
        store.persist_to_disk()?;
        crate::security::transport::register_local_device_identity(&store.local_device_id_hex);
        Ok(store)
    }

    /// Loads and decrypts an existing `trusted_peers_v2.json` file.
    ///
    /// Validates whole-file metadata HMAC (with backward-compatible upgrade from Batch 1D/legacy v2
    /// MAC layouts), unwraps the local Ed25519 secret key, verifies public key correspondence,
    /// unwraps all peer root keys with AAD binding, and synchronizes trust generations with
    /// `crate::security::transport`.
    ///
    /// # Arguments
    /// * `storage_dir` - Validated directory containing the keystore file.
    /// * `keystore_path` - Path to `trusted_peers_v2.json`.
    /// * `kek` - 32-byte Master Keystore Encryption Key ($K_{\text{kek}}$).
    /// * `newly_quarantined` - True if legacy v1 trust files were quarantined during this startup.
    ///
    /// # Errors
    /// Returns [`KeystoreError`] on I/O, UTF-8/JSON parsing, schema mismatch, HMAC/AEAD
    /// tamper detection, spoofed device ID, or duplicate peer/hostname errors.
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
        let mut needs_mac_upgrade = false;
        match &parsed.state_mac_hex {
            Some(mac_hex) => {
                let presented_mac: [u8; 32] = super::hex_decode_array(mac_hex).ok_or_else(|| {
                    KeystoreError::AeadTamperDetected("invalid state_mac_hex encoding".into())
                })?;
                let expected_mac = compute_keystore_file_mac(&kek, &parsed)?;
                if bool::from(presented_mac.ct_eq(&expected_mac)) {
                    // Valid modern Batch 1E MAC
                } else if parsed.persistent_camera_consents.is_empty() {
                    // Check if valid Batch 1D MAC with tombstones
                    let v2_mac = compute_keystore_file_mac_v2(&kek, &parsed)?;
                    if bool::from(presented_mac.ct_eq(&v2_mac)) {
                        needs_mac_upgrade = true;
                    } else if parsed.tombstone_generations.is_empty() {
                        // Check if valid legacy MAC without tombstones
                        let legacy_mac = compute_keystore_file_mac_legacy(&kek, &parsed)?;
                        if bool::from(presented_mac.ct_eq(&legacy_mac)) {
                            needs_mac_upgrade = true;
                        } else {
                            return Err(KeystoreError::AeadTamperDetected(
                                "keystore metadata integrity MAC verification failed".into(),
                            ));
                        }
                    } else {
                        return Err(KeystoreError::AeadTamperDetected(
                            "keystore metadata integrity MAC verification failed".into(),
                        ));
                    }
                } else {
                    return Err(KeystoreError::AeadTamperDetected(
                        "keystore metadata integrity MAC verification failed".into(),
                    ));
                }
            }
            None => {
                needs_mac_upgrade = true;
            }
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
        let mut peer_generations = HashMap::new();

        // 1. Populate generation tombstones for unpinned/revoked peers (preserving max on duplicate keys)
        for (raw_id, &gen) in &parsed.tombstone_generations {
            let clean_id = raw_id.trim().to_ascii_lowercase();
            if clean_id.len() == 32 && super::hex_decode_array::<16>(&clean_id).is_some() && gen >= 1 {
                let prev = peer_generations.get(&clean_id).copied().unwrap_or(0);
                peer_generations.insert(clean_id, prev.max(gen));
            } else {
                warn!("Ignoring invalid tombstone record '{}' => {}", raw_id, gen);
            }
        }

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
            if bool::from(peer_id.ct_eq(&local_id_bytes)) {
                return Err(KeystoreError::CorruptKeystore(format!(
                    "peer record '{}' matches local device identity",
                    canonical_id_hex
                )));
            }
            if peers.contains_key(&canonical_id_hex) {
                return Err(KeystoreError::CorruptKeystore(format!(
                    "duplicate peer device_id_hex '{}' in keystore",
                    canonical_id_hex
                )));
            }

            let trust_gen = rec.trust_generation.max(1);
            let current_known = peer_generations.get(&canonical_id_hex).copied().unwrap_or(0);
            peer_generations.insert(canonical_id_hex.clone(), trust_gen.max(current_known));

            if blocked_device_ids.iter().any(|b| b == &canonical_id_hex) {
                warn!("Skipping blocked peer '{}' during keystore load", canonical_id_hex);
                needs_mac_upgrade = true;
                continue;
            }
            let clean_host = rec.hostname.trim().to_string();
            let host_lower = clean_host.to_ascii_lowercase();
            if !host_lower.is_empty() && host_lower != UNKNOWN_HOSTNAME_SENTINEL {
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
                    trust_generation: trust_gen,
                },
            );
        }

        let mut camera_consents = HashMap::new();
        for (id, val) in &parsed.persistent_camera_consents {
            let clean_id = id.trim().to_ascii_lowercase();
            if clean_id.is_empty() {
                warn!("Discarding persistent camera consent with empty peer id");
                needs_mac_upgrade = true;
                continue;
            }
            if val == "blocked" {
                camera_consents.insert(clean_id, "blocked".to_string());
            } else if let Some(gen_str) = val.strip_prefix("always_allow:") {
                if let Ok(gen) = gen_str.parse::<u64>() {
                    if camera_consents.get(&clean_id).map(|v| v == "blocked").unwrap_or(false) {
                        // Fail-closed: an explicit "blocked" entry wins over any duplicate non-canonical key.
                        needs_mac_upgrade = true;
                        continue;
                    }
                    if let Some(peer) = peers.get(&clean_id) {
                        if peer.trust_generation == gen {
                            camera_consents.insert(clean_id, format!("always_allow:{}", gen));
                        } else {
                            warn!(
                                "Discarding stale persistent camera consent for {} (stored gen {} != active gen {})",
                                clean_id, gen, peer.trust_generation
                            );
                            needs_mac_upgrade = true;
                        }
                    } else {
                        warn!("Discarding orphaned persistent camera consent for unpaired peer {}", clean_id);
                        needs_mac_upgrade = true;
                    }
                } else {
                    warn!("Discarding malformed persistent camera consent generation '{}' for {}", val, clean_id);
                    needs_mac_upgrade = true;
                }
            } else {
                warn!("Discarding unrecognized persistent camera consent '{}' for {}", val, clean_id);
                needs_mac_upgrade = true;
            }
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
            peer_generations,
            camera_consents,
        };

        crate::security::transport::register_local_device_identity(&store.local_device_id_hex);
        for (id, creds) in &store.peers {
            crate::security::transport::register_peer_trust_generation(id, creds.trust_generation);
        }
        for (id, &gen) in &store.peer_generations {
            if !store.peers.contains_key(id) {
                crate::security::transport::invalidate_peer_trust(id, gen);
            }
        }

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
    /// * `pubkey_bytes` - 32-byte compressed Edwards25519 public key.
    /// * `message` - Authenticated message slice.
    /// * `signature_bytes` - 64-byte Ed25519 signature.
    ///
    /// # Errors
    /// Returns [`KeystoreError::CorruptKeystore`] if `pubkey_bytes` is not a valid curve point,
    /// or [`KeystoreError::AeadTamperDetected`] if strict signature verification fails.
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
    /// 1. Invalid Ed25519 public key bytes.
    /// 2. Spoofed device ID: `peer_device_id != SHA256("integrator-device-id-v2" || pk)[0..16]`.
    /// 3. Self-pairing: attempting to pair the device with its own local identity.
    /// 4. Blocked device ID.
    /// 5. Public key conflict: candidate has same `device_id` but different `ed25519_pk`.
    /// 6. Hostname conflict: candidate has same `hostname` (non-empty, non-`"unknown"`) but different `ed25519_pk`.
    ///
    /// # Arguments
    /// * `peer_device_id` - 16-byte binary device ID.
    /// * `peer_ed25519_pk` - 32-byte Ed25519 public key.
    /// * `hostname` - Declared peer hostname string.
    ///
    /// # Errors
    /// Returns [`KeystoreError::CorruptKeystore`], [`KeystoreError::SpoofedDeviceId`],
    /// [`KeystoreError::PeerBlocked`], or [`KeystoreError::PinnedIdentityKeyMismatch`].
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
        if !trimmed_host.is_empty() && !trimmed_host.eq_ignore_ascii_case(UNKNOWN_HOSTNAME_SENTINEL) {
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
    /// Advances the peer's monotonic `trust_generation`, clears stale persisted camera consent
    /// for the prior generation, persists to disk before mutating memory, and updates transport
    /// and clipboard revocation state.
    ///
    /// # Arguments
    /// * `peer_device_id` - 16-byte binary device ID.
    /// * `peer_ed25519_pk` - 32-byte Ed25519 public key.
    /// * `root_key` - 32-byte negotiated SPAKE2 root key.
    /// * `hostname` - Remote machine hostname.
    /// * `os` - Remote machine OS.
    /// * `last_ip` - Remote machine IP address.
    /// * `via_direct_cable` - True if paired over direct physical cable.
    ///
    /// # Returns
    /// The committed [`VerifiedPeerCredentials`] with its newly assigned `trust_generation` (>= 1).
    ///
    /// # Errors
    /// Returns [`KeystoreError`] if identity pinning checks or atomic disk persistence fail.
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

        let current_gen = self.peer_generations.get(&device_id_hex).copied().unwrap_or(0);
        let trust_generation = current_gen.saturating_add(1);

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
            trust_generation,
        };

        let mut next_peers = self.peers.clone();
        next_peers.insert(device_id_hex.clone(), creds.clone());
        let mut next_gens = self.peer_generations.clone();
        next_gens.insert(device_id_hex.clone(), trust_generation);
        let mut next_consents = self.camera_consents.clone();
        next_consents.remove(&device_id_hex);
        self.persist_state(&next_peers, &self.blocked_device_ids, &self.blocked_ips, &next_gens, &next_consents)?;
        self.peers = next_peers;
        self.peer_generations = next_gens;
        self.camera_consents = next_consents;
        crate::security::transport::register_peer_trust_generation(&creds.device_id_hex, creds.trust_generation);
        if let Some(clip) = crate::clipboard::CLIPBOARD_INSTANCE.get() {
            clip.clear_peer_revocation(&creds.device_id_hex);
        }
        // Note: Subsystem consent revocation (e.g. camera) must NEVER be invoked while holding
        // the global keystore mutex to eliminate ABBA deadlock (SEC-1D-04). Higher-level pairing
        // callers orchestrate subsystem consent resets outside the keystore lock.
        Ok(creds)
    }

    /// Explicitly unpairs and forgets a pinned peer by its device ID hex, returning
    /// whether the peer was removed and the newly established unpair trust generation (SEC-1D-14).
    ///
    /// Persists the updated keystore and generation tombstone to disk before updating in-memory
    /// state or calling `crate::security::transport::invalidate_peer_trust`.
    ///
    /// # Arguments
    /// * `device_id_hex` - 32-character hex peer device ID (trimmed and lowercased internally).
    ///
    /// # Returns
    /// `(removed, next_gen)` where `removed` is `true` if the peer existed in the active store,
    /// and `next_gen` is the monotonically incremented revocation generation.
    ///
    /// # Errors
    /// Returns [`KeystoreError`] if atomic disk persistence fails (in-memory state remains unchanged).
    pub fn unpair_peer_ext(&mut self, device_id_hex: &str) -> Result<(bool, u64), KeystoreError> {
        let canonical = device_id_hex.trim().to_ascii_lowercase();
        let current_gen = self
            .peer_generations
            .get(&canonical)
            .copied()
            .or_else(|| self.peers.get(&canonical).map(|p| p.trust_generation))
            .unwrap_or(0);
        let next_gen = current_gen.saturating_add(1);
        let mut next_peers = self.peers.clone();
        let removed = next_peers.remove(&canonical).is_some();
        let mut next_gens = self.peer_generations.clone();
        next_gens.insert(canonical.clone(), next_gen);

        let mut next_consents = self.camera_consents.clone();
        next_consents.remove(&canonical);

        // Persist state to disk before mutating in-memory state or invalidating sessions.
        // If disk persistence fails, fail closed without mutating memory or invalidating transport sessions.
        self.persist_state(&next_peers, &self.blocked_device_ids, &self.blocked_ips, &next_gens, &next_consents)?;

        self.peers = next_peers;
        self.peer_generations = next_gens;
        self.camera_consents = next_consents;
        crate::security::transport::invalidate_peer_trust(&canonical, next_gen);

        Ok((removed, next_gen))
    }

    /// Explicitly unpairs and forgets a pinned peer by its device ID hex.
    ///
    /// # Arguments
    /// * `device_id_hex` - 32-character hex device ID.
    ///
    /// # Returns
    /// `true` if the peer was found and removed; `false` if not found.
    #[cfg(test)]
    pub fn unpair_peer(&mut self, device_id_hex: &str) -> Result<bool, KeystoreError> {
        self.unpair_peer_ext(device_id_hex).map(|(removed, _)| removed)
    }

    /// Removes a peer from trust and optionally blocks its device ID and IP address, returning
    /// the newly established revocation trust generation (SEC-1D-14).
    ///
    /// Persists changes atomically before updating in-memory maps or invalidating transport sessions.
    ///
    /// # Arguments
    /// * `device_id_hex` - 32-character hex peer device ID.
    /// * `block` - `true` to add `device_id_hex`, `peer.last_ip`, and `known_ip` to blocklists
    ///   (and mark camera consent `"blocked"`); `false` to remove them from blocklists.
    /// * `known_ip` - Optional IPv4/IPv6 string associated with the peer connection.
    ///
    /// # Returns
    /// Monotonically incremented revocation trust generation.
    ///
    /// # Errors
    /// Returns [`KeystoreError`] if atomic disk persistence fails.
    pub fn untrust_or_block_peer_ext(
        &mut self,
        device_id_hex: &str,
        block: bool,
        known_ip: Option<&str>,
    ) -> Result<u64, KeystoreError> {
        let canonical = device_id_hex.trim().to_ascii_lowercase();
        let current_gen = self
            .peer_generations
            .get(&canonical)
            .copied()
            .or_else(|| self.peers.get(&canonical).map(|p| p.trust_generation))
            .unwrap_or(0);
        let next_gen = current_gen.saturating_add(1);
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

        let mut next_gens = self.peer_generations.clone();
        next_gens.insert(canonical.clone(), next_gen);

        let mut next_consents = self.camera_consents.clone();
        if block {
            next_consents.insert(canonical.clone(), "blocked".to_string());
        } else {
            next_consents.remove(&canonical);
        }

        // Persist state to disk before mutating in-memory state or invalidating sessions.
        // If disk persistence fails, fail closed without mutating memory or invalidating transport sessions.
        self.persist_state(&next_peers, &next_blocked_ids, &next_blocked_ips, &next_gens, &next_consents)?;

        self.peers = next_peers;
        self.blocked_device_ids = next_blocked_ids;
        self.blocked_ips = next_blocked_ips;
        self.peer_generations = next_gens;
        self.camera_consents = next_consents;
        crate::security::transport::invalidate_peer_trust(&canonical, next_gen);

        Ok(next_gen)
    }

    /// Removes a peer from trust and optionally blocks its device ID and IP address.
    #[cfg(test)]
    pub fn untrust_or_block_peer(
        &mut self,
        device_id_hex: &str,
        block: bool,
        known_ip: Option<&str>,
    ) -> Result<(), KeystoreError> {
        self.untrust_or_block_peer_ext(device_id_hex, block, known_ip).map(|_| ())
    }

    /// Returns a slice of all currently blocked device ID strings.
    pub fn blocked_device_ids(&self) -> &[String] {
        &self.blocked_device_ids
    }

    /// Returns a slice of all currently blocked IP address strings.
    pub fn blocked_ips(&self) -> &[String] {
        &self.blocked_ips
    }

    /// Checks if a device ID is currently blocked.
    pub fn is_device_blocked(&self, device_id_hex: &str) -> bool {
        let canonical = device_id_hex.trim().to_ascii_lowercase();
        self.blocked_device_ids.iter().any(|b| b == &canonical)
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

    /// Returns the active trust generation for the given peer device ID hex if tracked in keystore.
    ///
    /// Checks `peer_generations` first to preserve generation tracking across unpair/revoke operations,
    /// falling back to the pinned peer record's generation.
    pub fn peer_trust_generation(&self, device_id_hex: &str) -> Option<u64> {
        let canonical = device_id_hex.trim().to_ascii_lowercase();
        self.peer_generations
            .get(&canonical)
            .copied()
            .or_else(|| self.peers.get(&canonical).map(|p| p.trust_generation))
    }

    /// Registers a mock paired peer with an explicit trust generation for testing.
    #[cfg(test)]
    pub fn register_test_peer_with_generation(
        &mut self,
        device_id_hex: &str,
        generation: u64,
    ) {
        let canonical = device_id_hex.trim().to_ascii_lowercase();
        self.peer_generations.insert(canonical.clone(), generation);
        let creds = VerifiedPeerCredentials {
            device_id: [0u8; 16],
            device_id_hex: canonical.clone(),
            ed25519_pubkey: [0u8; 32],
            key_id: [1u8; 16],
            root_key: zeroize::Zeroizing::new([0u8; 32]),
            hostname: format!("test-peer-{}", &canonical[..8.min(canonical.len())]),
            os: "test".into(),
            last_ip: "127.0.0.1".into(),
            paired_at_epoch: 0,
            via_direct_cable: false,
            trust_generation: generation,
        };
        self.peers.insert(canonical.clone(), creds);
        crate::security::transport::register_peer_trust_generation(&canonical, generation);
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
    ///
    /// Performs an atomic disk write only when `new_ip` (trimmed) differs from the stored `last_ip`.
    ///
    /// # Errors
    /// Returns [`KeystoreError::PeerNotFound`] if the peer is not pinned, or [`KeystoreError::IoFailure`]
    /// if atomic disk persistence fails.
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
        self.persist_state(&next_peers, &self.blocked_device_ids, &self.blocked_ips, &self.peer_generations, &self.camera_consents)?;
        self.peers = next_peers;
        Ok(())
    }

    /// Persists current in-memory state to disk atomically.
    pub fn persist_to_disk(&self) -> Result<(), KeystoreError> {
        self.persist_state(&self.peers, &self.blocked_device_ids, &self.blocked_ips, &self.peer_generations, &self.camera_consents)
    }

    /// Returns the persistent camera consent string for `device_id_hex` if set.
    #[cfg(test)]
    pub fn get_camera_consent(&self, device_id_hex: &str) -> Option<String> {
        let clean_id = device_id_hex.trim().to_ascii_lowercase();
        self.camera_consents.get(&clean_id).cloned()
    }

    /// Sets or updates the persistent camera consent for `device_id_hex` and persists to disk.
    ///
    /// # Arguments
    /// * `device_id_hex` - 32-character hex peer device ID (trimmed and lowercased).
    /// * `consent` - Consent policy string (`"always_allow:<trust_generation>"` or `"blocked"`).
    ///
    /// # Errors
    /// Returns [`KeystoreError`] if atomic disk persistence fails (in-memory state remains unchanged).
    pub fn set_camera_consent(&mut self, device_id_hex: &str, consent: String) -> Result<(), KeystoreError> {
        let clean_id = device_id_hex.trim().to_ascii_lowercase();
        let mut next_consents = self.camera_consents.clone();
        next_consents.insert(clean_id, consent);
        self.persist_state(&self.peers, &self.blocked_device_ids, &self.blocked_ips, &self.peer_generations, &next_consents)?;
        self.camera_consents = next_consents;
        Ok(())
    }

    /// Removes persistent camera consent for `device_id_hex` and persists to disk.
    ///
    /// # Returns
    /// `true` if an existing consent entry was removed; `false` if none existed.
    ///
    /// # Errors
    /// Returns [`KeystoreError`] if atomic disk persistence fails.
    pub fn remove_camera_consent(&mut self, device_id_hex: &str) -> Result<bool, KeystoreError> {
        let clean_id = device_id_hex.trim().to_ascii_lowercase();
        let mut next_consents = self.camera_consents.clone();
        let removed = next_consents.remove(&clean_id).is_some();
        if removed {
            self.persist_state(&self.peers, &self.blocked_device_ids, &self.blocked_ips, &self.peer_generations, &next_consents)?;
            self.camera_consents = next_consents;
        }
        Ok(removed)
    }

    /// Returns a copy of all persistent camera consents.
    pub fn all_camera_consents(&self) -> HashMap<String, String> {
        self.camera_consents.clone()
    }

    /// Internal serialization, AEAD encryption, HMAC calculation, and atomic write.
    fn persist_state(
        &self,
        peers_map: &HashMap<String, VerifiedPeerCredentials>,
        blocked_device_ids: &[String],
        blocked_ips: &[String],
        peer_generations: &HashMap<String, u64>,
        camera_consents: &HashMap<String, String>,
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
                trust_generation: peer.trust_generation,
            });
        }
        serialized_peers.sort_by(|a, b| a.device_id_hex.cmp(&b.device_id_hex));

        let mut sorted_blocked_ids = blocked_device_ids.to_vec();
        sorted_blocked_ids.sort();
        sorted_blocked_ids.dedup();
        let mut sorted_blocked_ips = blocked_ips.to_vec();
        sorted_blocked_ips.sort();
        sorted_blocked_ips.dedup();

        let mut tombstones = HashMap::new();
        for (id, &gen) in peer_generations {
            if !peers_map.contains_key(id) && gen >= 1 {
                tombstones.insert(id.clone(), gen);
            }
        }

        let mut file_obj = KeystoreFileV2 {
            schema_version: KEYSTORE_SCHEMA_VERSION,
            local_device_id_hex: self.local_device_id_hex.clone(),
            local_ed25519_pubkey_hex: super::hex_encode(&local_pk_bytes),
            wrapped_local_ed25519_sk: wrapped_local_sk,
            peers: serialized_peers,
            blocked_device_ids: sorted_blocked_ids,
            blocked_ips: sorted_blocked_ips,
            legacy_v1_quarantined: self.legacy_v1_quarantined,
            tombstone_generations: tombstones,
            persistent_camera_consents: camera_consents.clone(),
            state_mac_hex: None,
        };
        let mac = compute_keystore_file_mac(&self.kek, &file_obj)?;
        file_obj.state_mac_hex = Some(super::hex_encode(&mac));

        let json_bytes = serde_json::to_vec_pretty(&file_obj)
            .map_err(|e| KeystoreError::SerializationFailure(e.to_string()))?;

        atomic_write_secure_file(&self.storage_dir, &self.keystore_path, &json_bytes)
    }
}

/// Shared HMAC-SHA256 integrity tag computation over serialized keystore metadata fields.
///
/// # Cryptographic Framing
/// Variable-length strings are length-prefixed with their big-endian `u32` byte count (`update_lp`),
/// and collections (`peers`, `tombstone_generations`, `persistent_camera_consents`) are sorted
/// lexicographically by key to ensure a canonical, unambiguous byte stream immune to field-boundary
/// concatenation collisions.
///
/// # Arguments
/// * `kek` - 32-byte Master Keystore Encryption Key ($K_{\text{kek}}$) used to derive the MAC key via HKDF-SHA256.
/// * `file_obj` - Deserialized or pending [`KeystoreFileV2`] structure to authenticate.
/// * `include_tombstones` - Whether to include `tombstone_generations` (Batch 1D+ format).
/// * `include_camera_consents` - Whether to include `persistent_camera_consents` (Batch 1E+ format).
///
/// # Errors
/// Returns [`KeystoreError::OsKeystoreFailure`] on HKDF/HMAC initialization failure or
/// [`KeystoreError::SerializationFailure`] if any field or collection length exceeds `u32::MAX`.
fn compute_keystore_file_mac_inner(
    kek: &[u8; 32],
    file_obj: &KeystoreFileV2,
    include_tombstones: bool,
    include_camera_consents: bool,
) -> Result<[u8; 32], KeystoreError> {
    let hk = Hkdf::<Sha256>::new(Some(KEYSTORE_META_MAC_SALT), kek);
    let mut mac_key = Zeroizing::new([0u8; 32]);
    hk.expand(KEYSTORE_META_MAC_INFO, &mut *mac_key)
        .map_err(|e| KeystoreError::OsKeystoreFailure(format!("HKDF meta MAC key failed: {}", e)))?;

    let mut mac = <HmacSha256 as Mac>::new_from_slice(&*mac_key)
        .map_err(|_| KeystoreError::OsKeystoreFailure("HMAC meta MAC init failed".into()))?;

    // Feed a 4-byte big-endian length prefix before each variable-length field to prevent ambiguity.
    fn update_lp(mac: &mut HmacSha256, bytes: &[u8]) -> Result<(), KeystoreError> {
        let len_u32 = u32::try_from(bytes.len()).map_err(|_| {
            KeystoreError::SerializationFailure("keystore MAC field exceeds u32 length".into())
        })?;
        mac.update(&len_u32.to_be_bytes());
        mac.update(bytes);
        Ok(())
    }

    fn update_count(mac: &mut HmacSha256, count: usize) -> Result<(), KeystoreError> {
        let count_u32 = u32::try_from(count).map_err(|_| {
            KeystoreError::SerializationFailure("keystore MAC collection exceeds u32 count".into())
        })?;
        mac.update(&count_u32.to_be_bytes());
        Ok(())
    }

    mac.update(&file_obj.schema_version.to_be_bytes());
    update_lp(&mut mac, file_obj.local_device_id_hex.as_bytes())?;
    update_lp(&mut mac, file_obj.local_ed25519_pubkey_hex.as_bytes())?;
    mac.update(&[u8::from(file_obj.legacy_v1_quarantined)]);

    let mut peers = file_obj.peers.clone();
    peers.sort_by(|a, b| a.device_id_hex.cmp(&b.device_id_hex));
    update_count(&mut mac, peers.len())?;
    for p in &peers {
        mac.update(&p.schema_version.to_be_bytes());
        update_lp(&mut mac, p.device_id_hex.as_bytes())?;
        update_lp(&mut mac, p.ed25519_pubkey_hex.as_bytes())?;
        update_lp(&mut mac, p.key_id_hex.as_bytes())?;
        update_lp(&mut mac, p.hostname.as_bytes())?;
        update_lp(&mut mac, p.os.as_bytes())?;
        update_lp(&mut mac, p.last_ip.as_bytes())?;
        mac.update(&p.paired_at_epoch.to_be_bytes());
        mac.update(&[u8::from(p.via_direct_cable)]);
    }

    update_count(&mut mac, file_obj.blocked_device_ids.len())?;
    for bid in &file_obj.blocked_device_ids {
        update_lp(&mut mac, bid.as_bytes())?;
    }
    update_count(&mut mac, file_obj.blocked_ips.len())?;
    for bip in &file_obj.blocked_ips {
        update_lp(&mut mac, bip.as_bytes())?;
    }

    if include_tombstones {
        let mut tombstones: Vec<(&String, &u64)> = file_obj.tombstone_generations.iter().collect();
        tombstones.sort_by_key(|(k, _)| *k);
        update_count(&mut mac, tombstones.len())?;
        for (tid, tgen) in tombstones {
            update_lp(&mut mac, tid.as_bytes())?;
            mac.update(&tgen.to_be_bytes());
        }
    }

    if include_camera_consents {
        let mut consents: Vec<(&String, &String)> =
            file_obj.persistent_camera_consents.iter().collect();
        consents.sort_by_key(|(k, _)| *k);
        update_count(&mut mac, consents.len())?;
        for (cid, cval) in consents {
            update_lp(&mut mac, cid.as_bytes())?;
            update_lp(&mut mac, cval.as_bytes())?;
        }
    }

    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    Ok(out)
}

/// Computes the current Batch 1E HMAC-SHA256 integrity tag over all serialized keystore metadata
/// fields including tombstones and persistent camera consents.
fn compute_keystore_file_mac(
    kek: &[u8; 32],
    file_obj: &KeystoreFileV2,
) -> Result<[u8; 32], KeystoreError> {
    compute_keystore_file_mac_inner(kek, file_obj, true, true)
}

/// Batch 1D MAC calculation for backward-compatible verification of older v2 keystore files
/// with tombstones but without persistent camera consents.
fn compute_keystore_file_mac_v2(
    kek: &[u8; 32],
    file_obj: &KeystoreFileV2,
) -> Result<[u8; 32], KeystoreError> {
    compute_keystore_file_mac_inner(kek, file_obj, true, false)
}

/// Legacy MAC calculation for backward-compatible verification of older v2 keystore files without tombstones.
fn compute_keystore_file_mac_legacy(
    kek: &[u8; 32],
    file_obj: &KeystoreFileV2,
) -> Result<[u8; 32], KeystoreError> {
    compute_keystore_file_mac_inner(kek, file_obj, false, false)
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
///
/// # Arguments
/// * `kek` - 32-byte Master Keystore Encryption Key ($K_{\text{kek}}$).
/// * `secret` - 32-byte plaintext secret (Ed25519 seed or $K_{\text{root}}$).
/// * `aad` - Authenticated Additional Data binding the secret to its owner identity.
///
/// # Errors
/// Returns [`KeystoreError::OsKeystoreFailure`] if CSPRNG generation or AEAD encryption fails.
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
///
/// # Errors
/// Returns [`KeystoreError::AeadTamperDetected`] if hex decoding fails, ciphertext length != 48 bytes
/// (32-byte payload + 16-byte Poly1305 tag), or tag verification fails.
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
///
/// # Errors
/// Returns [`KeystoreError::IoFailure`] if required home/app-data environment variables are unset or empty,
/// deliberately refusing insecure temporary directory fallbacks.
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
                return Ok(PathBuf::from(trimmed)
                    .join(LEGACY_INTEGRATOR_DIR_NAME)
                    .join("security"));
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
                return Ok(PathBuf::from(trimmed)
                    .join(LEGACY_INTEGRATOR_DIR_NAME)
                    .join("security"));
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
///
/// # Errors
/// Returns [`KeystoreError::IoFailure`] if `symlink_metadata` fails, the path is a symlink/reparse
/// point, or the path is not a regular file.
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
        // Win32 `FILE_ATTRIBUTE_REPARSE_POINT` (0x0400) covers NTFS junctions and directory/file symlinks.
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

/// Safely reads the byte contents of a keystore file, rejecting symlinks, reparse points, and
/// files exceeding [`MAX_KEYSTORE_FILE_BYTES`] (16 MiB).
///
/// Uses `O_NOFOLLOW` on Unix to prevent symlink TOCTOU races between `symlink_metadata` and `open`.
///
/// # Errors
/// Returns [`KeystoreError::IoFailure`] on stat/open/read/symlink errors, or
/// [`KeystoreError::CorruptKeystore`] if the file size exceeds 16 MiB.
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
    let mut buf = Vec::with_capacity(meta.len().min(KEYSTORE_FILE_READ_CHUNK_LIMIT) as usize);
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
///
/// Rejects symlinks and Windows reparse points on existing paths and enforces post-create validation
/// on newly created directories.
///
/// # Errors
/// Returns [`KeystoreError::IoFailure`] if directory creation, validation, or `chmod 0700` fails.
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
///
/// Uses `create_new(true)` + `O_NOFOLLOW` on Unix, calls `sync_all()` on both the temporary file
/// and (on Unix) the parent directory after `rename`, and unlinks the temporary file on error.
///
/// # Errors
/// Returns [`KeystoreError::OsKeystoreFailure`] on CSPRNG failure or [`KeystoreError::IoFailure`]
/// if directory validation, temp creation, permission enforcement, write/fsync, or rename fails.
fn atomic_write_secure_file(dir: &Path, target: &Path, content: &[u8]) -> Result<(), KeystoreError> {
    ensure_secure_directory(dir)?;
    let mut rnd = [0u8; TEMP_FILENAME_ENTROPY_BYTES];
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
        if let Err(e) = fs::set_permissions(target, fs::Permissions::from_mode(0o600)) {
            tracing::warn!("chmod 0600 on committed target {} failed: {}", target.display(), e);
        }

        // Parent directory fsync to persist directory entry rename to durable storage (SEC-1D-20)
        match fs::File::open(dir) {
            Ok(dir_file) => {
                if let Err(e) = dir_file.sync_all() {
                    // The file is already committed via rename, but directory metadata sync had an error.
                    // We report this limitation honestly without corrupting in-memory state.
                    tracing::warn!("Post-rename parent directory fsync failed on {}: {}", dir.display(), e);
                }
            }
            Err(e) => {
                tracing::warn!("Could not open parent directory for post-rename fsync {}: {}", dir.display(), e);
            }
        }
    }

    Ok(())
}

/// Safely cleans up stale temporary keystore files (`.{target}.tmp.*`) left behind by previous
/// aborted or crashed daemon runs, strictly avoiding symlink traversal (SEC-1D-20).
pub fn clean_stale_temp_files(dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else { return; };
    for entry in entries.flatten() {
        let path = entry.path();
        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();
        if name_str.starts_with('.') && name_str.contains(".tmp.") {
            // Strictly inspect symlink metadata: NEVER follow symlinks or Windows reparse points!
            if let Ok(meta) = fs::symlink_metadata(&path) {
                #[cfg(windows)]
                let is_reparse = {
                    use std::os::windows::fs::MetadataExt;
                    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
                    (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0
                };
                #[cfg(not(windows))]
                let is_reparse = false;

                if meta.file_type().is_symlink() || is_reparse {
                    tracing::warn!("Removing untrusted symlinked temporary file: {}", path.display());
                    let _ = fs::remove_file(&path);
                } else if meta.is_file() {
                    // Check age: remove if older than 300 seconds (5 minutes).
                    // If `modified_time.elapsed()` returns `Err` (mtime slightly in the future due to
                    // NTP clock adjustment), treat the file as freshly created (`false`) rather than stale.
                    let is_stale = match meta.modified() {
                        Ok(modified_time) => match modified_time.elapsed() {
                            Ok(elapsed) => elapsed.as_secs() > 300,
                            Err(_) => false,
                        },
                        Err(_) => true,
                    };
                    if is_stale {
                        tracing::debug!("Cleaning stale temporary keystore file: {}", path.display());
                        let _ = fs::remove_file(&path);
                    }
                }
            }
        }
    }
}

/// Quarantines any legacy v1 `trusted_peers.json` in `storage_dir`, its parent directory,
/// or `~/.usbc_clipboard_cache/trusted_peers.json` by renaming it to `.v1.deprecated.bak`.
pub fn quarantine_legacy_v1_files(storage_dir: &Path) -> bool {
    let mut candidate_paths = Vec::new();
    candidate_paths.push(storage_dir.join(LEGACY_KEYSTORE_V1_FILENAME));
    if let Some(parent) = storage_dir.parent() {
        candidate_paths.push(parent.join(LEGACY_KEYSTORE_V1_FILENAME));
    }

    // Only inspect global home directory paths when operating on the default keystore directory.
    if default_keystore_dir().as_deref() == Some(storage_dir) {
        #[cfg(target_os = "windows")]
        if let Ok(profile) = std::env::var("USERPROFILE") {
            let trimmed = profile.trim();
            if !trimmed.is_empty() {
                let p = PathBuf::from(trimmed);
                candidate_paths.push(
                    p.join(crate::config::APP_DATA_DIR_NAME)
                        .join(LEGACY_KEYSTORE_V1_FILENAME),
                );
                candidate_paths.push(
                    p.join(LEGACY_INTEGRATOR_DIR_NAME)
                        .join(LEGACY_KEYSTORE_V1_FILENAME),
                );
            }
        }
        #[cfg(not(target_os = "windows"))]
        if let Ok(home) = std::env::var("HOME") {
            let trimmed = home.trim();
            if !trimmed.is_empty() {
                let p = PathBuf::from(trimmed);
                candidate_paths.push(
                    p.join(crate::config::APP_DATA_DIR_NAME)
                        .join(LEGACY_KEYSTORE_V1_FILENAME),
                );
                candidate_paths.push(
                    p.join(LEGACY_INTEGRATOR_DIR_NAME)
                        .join(LEGACY_KEYSTORE_V1_FILENAME),
                );
            }
        }
    }

    let mut quarantined_any = false;
    for legacy_path in candidate_paths {
        let Ok(meta) = fs::symlink_metadata(&legacy_path) else {
            continue;
        };
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
            if (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
                continue;
            }
        }
        if meta.file_type().is_symlink() || !meta.is_file() {
            continue;
        }
        let bak_path = legacy_path.with_extension(LEGACY_V1_QUARANTINE_EXT);
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

/// RAII guard that serializes macOS Keychain access and temporarily suppresses interactive
/// Security.framework UI prompts (`SecKeychainSetUserInteractionAllowed(0)`), restoring the
/// prior interaction state when dropped.
#[cfg(target_os = "macos")]
#[allow(dead_code)]
struct NoUiKeychainGuard {
    /// Previous boolean interaction state returned by `SecKeychainGetUserInteractionAllowed` (`0` or `1`).
    prev_allowed: u8,
    /// Process-wide mutex guard serializing modifications to global `SecKeychain` interaction state.
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
#[allow(dead_code)]
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
#[allow(dead_code)]
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
        // IOServiceMatching returns a CFMutableDictionaryRef whose retain count is consumed by IOServiceGetMatchingService.
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
    if let Ok(out) = std::process::Command::new(crate::config::MACOS_IOREG_BIN)
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
#[allow(dead_code)]
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

    let seed_path = storage_dir.join(MASTER_KEK_SEED_FILENAME);
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

    let hw_id = Zeroizing::new(macos_read_platform_hardware_identity()?);
    let mut ikm = Zeroizing::new(Vec::with_capacity(seed.len() + 1 + hw_id.len()));
    ikm.extend_from_slice(&seed);
    ikm.push(b'|');
    ikm.extend_from_slice(&hw_id);

    let dir_canonical = fs::canonicalize(storage_dir).unwrap_or_else(|_| storage_dir.to_path_buf());
    let mut salt = Zeroizing::new(Vec::from(&b"integrator-macos-hw-kek-salt-v2|"[..]));
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
#[allow(dead_code)]
/// Loads existing $K_{\text{kek}}$ from macOS Keychain Services or derives a hardware-bound seed key.
fn macos_keychain_load_or_create_kek(
    storage_dir: &Path,
) -> Result<Zeroizing<[u8; 32]>, KeystoreError> {
    use core_foundation::base::{CFGetTypeID, CFRelease, CFTypeRef, TCFType};
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

    // Security.framework OSStatus result codes (<Security/SecBase.h>)
    const ERR_SEC_SUCCESS: c_int = 0;
    const ERR_SEC_ITEM_NOT_FOUND: c_int = -25300;
    const ERR_SEC_AUTH_FAILED: c_int = -25293;
    const ERR_SEC_INTERACTION_NOT_ALLOWED: c_int = -25308;

    // Fast path: once a hardware+UID-bound sealed KEK seed exists on disk (checked via
    // symlink_metadata so symlinks are routed immediately into read_secure_bytes rejection),
    // derive K_kek directly without touching login.keychain-db so rebuilds never trigger dialogs.
    if fs::symlink_metadata(storage_dir.join(MASTER_KEK_SEED_FILENAME)).is_ok() {
        return macos_hw_bound_load_or_create_kek(storage_dir);
    }

    let service = CFString::new(MACOS_KEYCHAIN_SERVICE);
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
            if CFGetTypeID(result) == CFData::type_id() {
                let data: CFData = TCFType::wrap_under_create_rule(result as *const _);
                if data.len() == 32 {
                    let mut kek = Zeroizing::new([0u8; 32]);
                    kek.copy_from_slice(data.bytes());
                    return Ok(kek);
                }
            } else {
                CFRelease(result);
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
#[cfg_attr(test, allow(dead_code))]
/// Protects or unprotects $K_{\text{kek}}$ using Win32 Data Protection API (`CryptProtectData` / `CryptUnprotectData`).
fn windows_dpapi_load_or_create_kek(
    storage_dir: &Path,
) -> Result<Zeroizing<[u8; 32]>, KeystoreError> {
    use std::ffi::c_void;

    /// FFI representation of Win32 `DATA_BLOB` (`CRYPT_INTEGER_BLOB`) from `<wincrypt.h>`.
    #[repr(C)]
    struct DataBlob {
        /// Count of bytes in the buffer pointed to by `pb_data`.
        cb_data: u32,
        /// Pointer to the raw byte buffer allocated by the caller or by `CryptProtectData`/`CryptUnprotectData` (`LocalAlloc`).
        pb_data: *mut u8,
    }

    // Disallows interactive credential UI dialogs during headless/background daemon DPAPI operations.
    const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;
    // Application-specific secondary entropy mixed with the Windows user logon credential by DPAPI.
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
    let dpapi_path = storage_dir.join(MASTER_KEK_DPAPI_FILENAME);

    let mut entropy_vec = Zeroizing::new(DPAPI_ENTROPY.to_vec());
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
            if !out_blob.pb_data.is_null() {
                unsafe {
                    LocalFree(out_blob.pb_data as *mut c_void);
                }
            }
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
        // Zeroize DPAPI-allocated plaintext heap buffer using volatile writes before releasing via LocalFree.
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

    if ok == 0 || out_blob.pb_data.is_null() || out_blob.cb_data == 0 {
        if !out_blob.pb_data.is_null() {
            unsafe {
                LocalFree(out_blob.pb_data as *mut c_void);
            }
        }
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
    let key_file = storage_dir.join(MASTER_KEK_SEED_FILENAME);

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
    let mut salt_data = Zeroizing::new(Vec::from(&b"integrator-unix-kek-salt-v2"[..]));
    for path in LINUX_MACHINE_ID_PATHS {
        if let Ok(mid) = fs::read(path) {
            if !mid.is_empty() {
                salt_data.extend_from_slice(&mid);
                break;
            }
        }
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
///
/// In production (`not(test)`), opens the default OS-backed keystore via [`KeystoreV2::open_default`].
/// In unit tests (`cfg(test)`), initializes an isolated per-PID temporary keystore backed by
/// [`FixedKekProvider`] so test suites never touch the user's real Keychain/DPAPI keystore.
///
/// # Errors
/// Returns [`KeystoreError`] if the initial keystore open failed (error is cached in `GLOBAL_KEYSTORE_V2`).
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
///
/// # Panics
/// Panics if [`try_global_keystore`] returns an error (e.g. corrupt keystore or tampered MAC).
pub fn global_keystore() -> &'static Mutex<KeystoreV2> {
    try_global_keystore().unwrap_or_else(|e| {
        panic!("Failed to initialize Integrator v2 security keystore: {}", e)
    })
}
