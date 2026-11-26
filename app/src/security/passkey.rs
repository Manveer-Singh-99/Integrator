//! # WebAuthn & FIDO2 Passkey Cryptographic Subsystem (`app/src/security/passkey.rs`)
//!
//! ## 1. Module Purpose & Scope
//! This module implements the **FIDO2 / WebAuthn Resident Passkey Authenticator** for Integrator.
//! It enables passwordless, phishing-resistant public-key authentication for websites and apps
//! running on a Windows 11 workstation, using the paired macOS device's Touch ID biometric verification
//! over mutually authenticated [`crate::security::transport::TransportSessionV2`].
//!
//! Core responsibilities include:
//! - **Passkey Keypair Generation**: Generates FIDO2-compliant ECDSA P-256 (`COSE_ALG_ES256 = -7`)
//!   resident keypairs bound to Relying Party identifiers (`rpId`).
//! - **Authenticator Data Encoding**: Serializes canonical WebAuthn `authenticatorData` buffers containing
//!   SHA-256 Relying Party hashes (`rpIdHash`), User Presence (`UP`), User Verification (`UV`), Backup
//!   Eligibility/State (`BE`/`BS`), monotonic `signCount`, and Attested Credential Data (`AT`).
//! - **COSE Public Key Formatting**: Encodes uncompressed NIST P-256 (`EC2`) public keys in canonical
//!   CBOR format according to RFC 8152 (`ciborium`).
//! - **Biometric Assertion Signing**: Cryptographically signs `authenticatorData || clientDataHash`
//!   challenges with the resident passkey private key only after physical Touch ID verification.
//! - **Atomic Persistent Store**: Persists resident passkey records in `passkeys_v1.json` via
//!   write-fsync-rename updates hardened with owner-only POSIX `0o600` file / `0o700` directory
//!   permissions and forensic backup of corrupted store files.
//! - **CTAP2 Capabilities Descriptor**: Serializes canonical CBOR `authenticatorGetInfo` bytes for the
//!   Windows 11 `IPluginAuthenticator` registration flow.
//!
//! ## 2. Architectural Linkages & Dependencies
//! - **Upstream Callers**:
//!   - `app/src/display/controller.rs`: Handles `DisplayRpcRequest::PasskeyMakeCredential` and
//!     `DisplayRpcRequest::PasskeyGetAssertion` across active `TransportSessionV2` streams.
//!   - `app/src/core.rs`: Exposes CLI subcommands `integrator passkey status|info|list|test|make-hex|assert-hex`
//!     (bridged by `app/ui-windows/PasskeyHost/Program.cs`) and IPC RPCs `passkey_list`, `passkey_get_info`,
//!     `passkey_make_credential_remote`, and `passkey_get_assertion_remote` (used by
//!     `app/ui-windows/PasskeyAuthenticatorPlugin.cs`).
//! - **Downstream Callees**:
//!   - `p256::ecdsa` & `p256::pkcs8`: NIST P-256 ECDSA key generation, PKCS#8 DER codec, and assertion signing.
//!   - `ciborium`: Canonical CBOR serialization for COSE keys, attestation objects, and `authenticatorGetInfo`.
//!   - `crate::security::sha256_digest`: Relying Party ID hashing (`rpIdHash`).
//!   - `app/src/trust.rs`: Native macOS Touch ID evaluation (`evaluate_local_touchid_and_sign`).
//!   - `app/src/security/`: Kernel CSPRNG (`csprng_array`), hex encoding/decoding (`hex_encode`, `hex_decode`, `hex_decode_array`), Unix timestamps.
//! - **Cross-Platform / Cross-Device Flow**:
//!   - **Windows 11 (Initiator)**: Browser initiates WebAuthn ceremony -> Windows routes request to
//!     Integrator's `PasskeyAuthenticatorPlugin` / `PasskeyHost` COM server -> Integrator forwards
//!     `PasskeyMakeCredentialRequest` / `PasskeyGetAssertionRequest` over `TransportSessionV2` (TCP port 58281).
//!   - **macOS (Authenticator)**: Displays Apple Touch ID sensor prompt -> User verifies fingerprint ->
//!     Private P-256 key signs `authData || clientDataHash` -> Returns CBOR/DER response to Windows.
//!
//! ## 3. Threading & Concurrency Model
//! All public functions are reentrant and thread-safe. Biometric prompts and cryptographic operations
//! execute synchronously on Tokio blocking worker threads (`tokio::task::spawn_blocking`).
//! [`GlobalPasskeyStore`] guards both in-memory credentials and disk persistence under a single
//! `std::sync::Mutex` lock acquisition (`save_locked`) with transactional rollback if persistence fails.
//!
//! ## 4. Security & Safety Invariants
//! - **Filesystem & IPC Hygiene**: `passkeys_v1.json` is written under `0o600` permissions in a `0o700`
//!   directory; `list_resident_passkeys()` zeroes and clears `private_key_pkcs8_der` on returned records so
//!   CLI/IPC inspection never discloses private key bytes; custom `Debug` redacts key material.
//! - **Biometric Gate Invariant**: Remote registration/assertion RPCs validate `rp_id`,
//!   `client_data_hash_hex`, `user_id_hex`, and credential existence *before* prompting Touch ID.
//! - **Domain Separation & Normalization**: `rp_id` is validated per RFC 1035 bounds, lowercased,
//!   and SHA-256 hashed into `rpIdHash`; signing covers strictly `authData || clientDataHash`.
//! - **Strict Zeroization**: Transient key copies are zeroized on completion/redaction via `zeroize::Zeroize`.

#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey};
use p256::elliptic_curve::rand_core::OsRng;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use zeroize::Zeroize;

// ============================================================================
// Protocol Constants & Magic Numbers (Strictly Zero Inline Literals)
// ============================================================================

/// COSE algorithm identifier for ECDSA with SHA-256 on NIST P-256 curve (ES256, RFC 8152 §8.1).
pub const COSE_ALG_ES256: i32 = -7;

/// COSE key type identifier for 2-coordinate elliptic curve keys (EC2, RFC 8152 §13).
pub const COSE_KEY_TYPE_EC2: i64 = 2;

/// COSE curve identifier for NIST P-256 (`secp256r1`, RFC 8152 §13.1).
pub const COSE_CRV_P256: i64 = 1;

/// Authenticator Data Flag: User Presence (`UP`) bit (Bit 0 = `0x01`).
pub const AUTHDATA_FLAG_USER_PRESENT: u8 = 0x01;

/// Authenticator Data Flag: User Verification (`UV`) bit (Bit 2 = `0x04` - Biometrics confirmed).
pub const AUTHDATA_FLAG_USER_VERIFIED: u8 = 0x04;

/// Authenticator Data Flag: Backup Eligibility (`BE`) bit (Bit 3 = `0x08` - Multi-device passkey).
pub const AUTHDATA_FLAG_BACKUP_ELIGIBLE: u8 = 0x08;

/// Authenticator Data Flag: Backup State (`BS`) bit (Bit 4 = `0x10` - Synced / cross-device state).
pub const AUTHDATA_FLAG_BACKUP_STATE: u8 = 0x10;

/// Authenticator Data Flag: Attested Credential Data (`AT`) present bit (Bit 6 = `0x40`).
pub const AUTHDATA_FLAG_ATTESTED_CRED_DATA: u8 = 0x40;

/// Length in bytes of a standard WebAuthn Authenticator Attestation GUID (AAGUID = 16 bytes).
pub const AAGUID_BYTE_LEN: usize = 16;

/// Standard Integrator Authenticator Attestation GUID (AAGUID).
/// `d9a4a4e1-2fbc-4b57-908d-a247e16806f4`
pub const INTEGRATOR_AAGUID: [u8; AAGUID_BYTE_LEN] = [
    0xd9, 0xa4, 0xa4, 0xe1, 0x2f, 0xbc, 0x4b, 0x57, 0x90, 0x8d, 0xa2, 0x47, 0xe1, 0x68, 0x06, 0xf4,
];

/// Length in bytes of the Relying Party identifier hash (`rpIdHash` via SHA-256 = 32 bytes).
pub const RP_ID_HASH_LEN: usize = 32;

/// Length in bytes of the WebAuthn client data digest challenge (`clientDataHash` via SHA-256 = 32 bytes).
pub const CLIENT_DATA_HASH_LEN: usize = 32;

/// Length in bytes of an uncompressed NIST P-256 public key (`0x04` prefix + 32-byte X + 32-byte Y = 65 bytes).
pub const P256_UNCOMPRESSED_KEY_LEN: usize = 65;

/// Length in bytes of a single coordinate scalar on NIST P-256 (32 bytes).
pub const P256_SCALAR_LEN: usize = 32;

/// Length in bytes of a generated credential identifier (32 bytes = 256 bits of CSPRNG entropy).
pub const CREDENTIAL_ID_LEN: usize = 32;

/// Filename under the user's application data directory for persistent passkey storage.
pub const PASSKEY_STORE_FILENAME: &str = "passkeys_v1.json";

// ============================================================================
// Passkey Data Structures & Wire Models
// ============================================================================

/// Persisted record of a resident WebAuthn passkey credential stored on the authenticator.
#[derive(Clone, Serialize, Deserialize)]
pub struct PasskeyRecord {
    /// 32-byte (64-character) unique hex credential identifier.
    pub credential_id_hex: String,
    /// Relying Party identifier (e.g. `"github.com"`, `"google.com"`).
    pub rp_id: String,
    /// Hex-encoded user identifier provided by the Relying Party during registration.
    pub user_id_hex: String,
    /// Human-readable username or email handle associated with this passkey.
    pub user_name: String,
    /// Optional human-readable display name (e.g. `"Manveer Singh"`).
    pub user_display_name: String,
    /// PKCS#8 DER-encoded private signing key.
    pub private_key_pkcs8_der: Vec<u8>,
    /// SEC1 uncompressed public key bytes (`0x04 || X || Y`).
    pub public_key_sec1: Vec<u8>,
    /// COSE algorithm identifier ([`COSE_ALG_ES256`] = -7).
    pub cose_alg: i32,
    /// Monotonically increasing signature invocation counter.
    pub sign_count: u32,
    /// Milliseconds since Unix epoch when this credential was registered.
    pub created_at_ms: u64,
}

impl std::fmt::Debug for PasskeyRecord {
    /// Formats record metadata while strictly redacting `private_key_pkcs8_der`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasskeyRecord")
            .field("credential_id_hex", &self.credential_id_hex)
            .field("rp_id", &self.rp_id)
            .field("user_name", &self.user_name)
            .field("cose_alg", &self.cose_alg)
            .field("sign_count", &self.sign_count)
            .field("private_key", &"<REDACTED_PKCS8>")
            .finish()
    }
}

/// Request parameters for creating a new passkey credential (`authenticatorMakeCredential`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PasskeyMakeCredentialRequest {
    /// 32-byte SHA-256 digest of the clientDataJSON buffer from the browser.
    pub client_data_hash_hex: String,
    /// Relying party domain identifier (e.g. `"github.com"`).
    pub rp_id: String,
    /// User identifier assigned by the relying party.
    pub user_id_hex: String,
    /// Username or account handle for the account being created.
    pub user_name: String,
    /// Display name for the account being created.
    pub user_display_name: String,
    /// Hostname of the workstation requesting credential creation.
    pub requester_hostname: String,
}

/// Output payload returned upon successful passkey credential creation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PasskeyMakeCredentialResponse {
    /// 32-byte (64-character) unique hex credential identifier.
    pub credential_id_hex: String,
    /// Canonical WebAuthn `authenticatorData` bytes.
    pub auth_data_hex: String,
    /// Attestation format name (`"none"` for self/zero-attestation).
    pub attestation_format: String,
    /// Complete canonical CBOR-encoded WebAuthn Attestation Object.
    pub attestation_object_cbor_hex: String,
}

/// Request parameters for asserting an existing passkey credential (`authenticatorGetAssertion`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PasskeyGetAssertionRequest {
    /// 32-byte SHA-256 digest of the clientDataJSON buffer from the browser.
    pub client_data_hash_hex: String,
    /// Relying party domain identifier being authenticated (e.g. `"github.com"`).
    pub rp_id: String,
    /// List of acceptable credential IDs provided by the relying party (or empty for any matching).
    pub allow_credential_ids_hex: Vec<String>,
    /// Hostname of the workstation requesting authentication.
    pub requester_hostname: String,
}

/// Output payload returned upon successful passkey assertion signing.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PasskeyGetAssertionResponse {
    /// Hex-encoded credential identifier that was asserted.
    pub credential_id_hex: String,
    /// Hex-encoded user identifier associated with the credential.
    pub user_id_hex: String,
    /// Canonical WebAuthn `authenticatorData` bytes.
    pub auth_data_hex: String,
    /// ASN.1 DER-encoded ECDSA signature bytes over `authData || clientDataHash`.
    pub signature_der_hex: String,
    /// Incremented signature invocation count.
    pub sign_count: u32,
}

// ============================================================================
// Persistent Passkey Store
// ============================================================================

/// On-disk JSON container storing resident passkey records under owner-only `0o600` permissions.
#[derive(Default, Serialize, Deserialize)]
struct PasskeyDatabase {
    /// Mapping from `credential_id_hex` to [`PasskeyRecord`].
    credentials: HashMap<String, PasskeyRecord>,
}

/// Global thread-safe passkey database manager.
struct GlobalPasskeyStore {
    /// Synchronized in-memory mapping of resident passkey credentials.
    db: Mutex<PasskeyDatabase>,
    /// Absolute filesystem path to `passkeys_v1.json`.
    path: PathBuf,
}

impl GlobalPasskeyStore {
    /// Initializes or loads the persistent passkey database from `base_dir/passkeys_v1.json`.
    ///
    /// If an existing store file is corrupted and fails JSON deserialization, preserves a forensic
    /// backup (`passkeys_v1.json.corrupt.<epoch_secs>`) and logs an error before falling back
    /// to an empty database.
    fn new(base_dir: &Path) -> Self {
        let path = base_dir.join(PASSKEY_STORE_FILENAME);
        let db = if path.exists() {
            match fs::read_to_string(&path) {
                Ok(content) => match serde_json::from_str::<PasskeyDatabase>(&content) {
                    Ok(parsed) => parsed,
                    Err(e) => {
                        let epoch = crate::security::unix_epoch_secs();
                        let backup = path.with_extension(format!("json.corrupt.{}", epoch));
                        let _ = fs::copy(&path, &backup);
                        tracing::error!(
                            "Corrupt passkey store at {} ({}); backed up to {}",
                            path.display(),
                            e,
                            backup.display()
                        );
                        PasskeyDatabase::default()
                    }
                },
                Err(e) => {
                    tracing::error!("Failed to read passkey store from {}: {}", path.display(), e);
                    PasskeyDatabase::default()
                }
            }
        } else {
            PasskeyDatabase::default()
        };
        Self {
            db: Mutex::new(db),
            path,
        }
    }

    /// Persists the provided database snapshot atomically using write-sync-rename with hardened `0o600` permissions.
    ///
    /// Called while holding the `self.db` mutex guard to prevent concurrent race windows between
    /// in-memory state updates and disk commits. Cleans up the transient temporary file on any error.
    fn save_locked(db: &PasskeyDatabase, path: &Path) -> Result<(), String> {
        let json = serde_json::to_string_pretty(db)
            .map_err(|e| format!("Serialization error: {}", e))?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("Failed to create directory: {}", e))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                // Restrict parent directory to owner access only (rwx------).
                let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
            }
        }
        let rand_suffix = crate::security::hex_encode(&crate::security::csprng_array::<8>());
        let tmp_path = path.with_extension(format!("tmp.{}.{}", std::process::id(), rand_suffix));

        let open_res = {
            let mut opts = fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                // Create temporary file with owner-only rw------- (0o600) permissions from birth
                // so PKCS#8 private key material is never exposed under a permissive default umask.
                opts.mode(0o600);
            }
            opts.open(&tmp_path)
        };

        let mut file = open_res.map_err(|e| {
            format!(
                "Failed to create temporary store {}: {}",
                tmp_path.display(),
                e
            )
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600));
        }

        if let Err(e) = file.write_all(json.as_bytes()) {
            drop(file);
            let _ = fs::remove_file(&tmp_path);
            return Err(format!("Failed to write store {}: {}", tmp_path.display(), e));
        }
        if let Err(e) = file.sync_all() {
            drop(file);
            let _ = fs::remove_file(&tmp_path);
            return Err(format!("Failed to sync store: {}", e));
        }
        // Explicitly close file handle before rename for Windows filesystem compatibility.
        drop(file);

        if let Err(e) = fs::rename(&tmp_path, path) {
            let _ = fs::remove_file(&tmp_path);
            return Err(format!("Atomic rename failed: {}", e));
        }
        Ok(())
    }

    /// Stores a newly generated passkey record atomically, rolling back in-memory state if disk persistence fails.
    fn insert(&self, record: PasskeyRecord) -> Result<(), String> {
        let mut db = self.db.lock().map_err(|e| format!("Mutex poisoned: {}", e))?;
        let key = record.credential_id_hex.clone();
        let previous = db.credentials.insert(key.clone(), record);
        if let Err(e) = Self::save_locked(&db, &self.path) {
            // Rollback authoritative in-memory state if disk persistence fails.
            match previous {
                Some(old) => {
                    db.credentials.insert(key, old);
                }
                None => {
                    db.credentials.remove(&key);
                }
            }
            return Err(e);
        }
        Ok(())
    }

    /// Looks up the highest-priority resident credential matching `rp_id` and `allow_ids` while holding `db`.
    fn find_for_rp_locked<'a>(
        db: &'a PasskeyDatabase,
        rp_id: &str,
        allow_ids: &[String],
    ) -> Option<&'a PasskeyRecord> {
        let normalized_rp = rp_id.trim().to_ascii_lowercase();

        // If an explicit allow-list was provided by the relying party, match by ID first
        if !allow_ids.is_empty() {
            for id in allow_ids {
                let clean_id = id.trim().to_ascii_lowercase();
                if let Some(rec) = db.credentials.get(&clean_id) {
                    if rec.rp_id.eq_ignore_ascii_case(&normalized_rp) {
                        return Some(rec);
                    }
                }
            }
            // Per W3C WebAuthn Level 3 (§5.1.3), if allowCredentials is non-empty and no matching
            // credential exists on this authenticator, the authenticator MUST NOT pick another credential.
            return None;
        }

        // Otherwise return the most recently created credential matching the RP ID
        let mut matches: Vec<&PasskeyRecord> = db
            .credentials
            .values()
            .filter(|rec| rec.rp_id.eq_ignore_ascii_case(&normalized_rp))
            .collect();
        matches.sort_by(|a, b| b.created_at_ms.cmp(&a.created_at_ms));
        matches.first().copied()
    }

    /// Returns whether any resident passkey exists for `rp_id` (without cloning key material).
    fn has_for_rp(&self, rp_id: &str, allow_ids: &[String]) -> Result<bool, String> {
        let db = self.db.lock().map_err(|e| format!("Mutex poisoned: {}", e))?;
        Ok(Self::find_for_rp_locked(&db, rp_id, allow_ids).is_some())
    }

    /// Retrieves an existing passkey matching `rp_id` and optional `allow_ids`.
    fn find_for_rp(
        &self,
        rp_id: &str,
        allow_ids: &[String],
    ) -> Result<Option<PasskeyRecord>, String> {
        let db = self.db.lock().map_err(|e| format!("Mutex poisoned: {}", e))?;
        Ok(Self::find_for_rp_locked(&db, rp_id, allow_ids).cloned())
    }

    /// Increments the signature invocation counter for a credential atomically, rolling back on persistence failure.
    fn increment_sign_count(&self, credential_id_hex: &str) -> Result<u32, String> {
        let mut db = self.db.lock().map_err(|e| format!("Mutex poisoned: {}", e))?;
        let prev_count = {
            let rec = db
                .credentials
                .get_mut(credential_id_hex)
                .ok_or_else(|| "Credential not found".to_string())?;
            let prev = rec.sign_count;
            rec.sign_count = rec.sign_count.saturating_add(1);
            prev
        };
        if let Err(e) = Self::save_locked(&db, &self.path) {
            if let Some(rec) = db.credentials.get_mut(credential_id_hex) {
                rec.sign_count = prev_count;
            }
            return Err(e);
        }
        Ok(prev_count.saturating_add(1))
    }

    /// Returns a list of all resident credentials with `private_key_pkcs8_der` zeroized and cleared
    /// so CLI/IPC callers cannot expose private signing keys.
    fn list_all(&self) -> Result<Vec<PasskeyRecord>, String> {
        let db = self.db.lock().map_err(|e| format!("Mutex poisoned: {}", e))?;
        Ok(db
            .credentials
            .values()
            .cloned()
            .map(|mut rec| {
                rec.private_key_pkcs8_der.zeroize();
                rec.private_key_pkcs8_der.clear();
                rec
            })
            .collect())
    }
}

/// Global singleton store instance.
static GLOBAL_PASSKEY_STORE: OnceLock<GlobalPasskeyStore> = OnceLock::new();

/// Accesses the global passkey store singleton.
///
/// In unit test builds (`#[cfg(test)]`), uses an isolated per-process temporary directory so tests
/// never mutate or pollute the user's real `passkeys_v1.json` store.
fn passkey_store() -> &'static GlobalPasskeyStore {
    GLOBAL_PASSKEY_STORE.get_or_init(|| {
        #[cfg(test)]
        let base_dir = std::env::temp_dir().join(format!(
            "integrator_test_passkeys_{}",
            std::process::id()
        ));
        #[cfg(not(test))]
        let base_dir = crate::system_info::app_data_dir();
        GlobalPasskeyStore::new(&base_dir)
    })
}

// ============================================================================
// Core WebAuthn Cryptographic Functions
// ============================================================================

/// Validates Relying Party identifier syntax according to WebAuthn / FIDO2 specifications.
///
/// Enforces:
/// - Non-empty after trimming whitespace.
/// - Length <= 253 ASCII characters (DNS hostname limit per RFC 1035).
/// - No null bytes (`\0`), path separators (`/`, `\`), or scheme/port delimiters (`:`).
pub fn validate_rp_id(rp_id: &str) -> Result<(), String> {
    let clean = rp_id.trim();
    if clean.is_empty() {
        return Err("Relying Party ID cannot be empty".into());
    }
    if clean.len() > 253 {
        return Err("Relying Party ID exceeds 253 characters".into());
    }
    if clean.contains('\0') || clean.contains('/') || clean.contains(':') || clean.contains('\\') {
        return Err("Relying Party ID must be a valid domain or host string without scheme or port".into());
    }
    Ok(())
}

/// Serializes a NIST P-256 public key into RFC 8152 COSE Key canonical CBOR bytes.
///
/// COSE Key Map structure:
/// - Key `1` (kty): `2` ([`COSE_KEY_TYPE_EC2`])
/// - Key `3` (alg): `-7` ([`COSE_ALG_ES256`])
/// - Key `-1` (crv): `1` ([`COSE_CRV_P256`])
/// - Key `-2` (x): 32 bytes X-coordinate
/// - Key `-3` (y): 32 bytes Y-coordinate
pub fn encode_cose_p256_public_key(public_key_sec1: &[u8]) -> Result<Vec<u8>, String> {
    if public_key_sec1.len() != P256_UNCOMPRESSED_KEY_LEN || public_key_sec1[0] != 0x04 {
        return Err("Invalid SEC1 uncompressed P-256 public key length".into());
    }
    let x_coord = &public_key_sec1[1..1 + P256_SCALAR_LEN];
    let y_coord = &public_key_sec1[1 + P256_SCALAR_LEN..1 + 2 * P256_SCALAR_LEN];

    // Build RFC 8152 COSE EC2 Key map: 1=kty (EC2), 3=alg (ES256), -1=crv (P-256), -2=x, -3=y.
    use ciborium::value::Value;
    let cose_map = Value::Map(vec![
        (Value::Integer(1.into()), Value::Integer(COSE_KEY_TYPE_EC2.into())),
        (Value::Integer(3.into()), Value::Integer((COSE_ALG_ES256 as i64).into())),
        (Value::Integer((-1).into()), Value::Integer(COSE_CRV_P256.into())),
        (Value::Integer((-2).into()), Value::Bytes(x_coord.to_vec())),
        (Value::Integer((-3).into()), Value::Bytes(y_coord.to_vec())),
    ]);

    let mut out = Vec::with_capacity(96);
    ciborium::into_writer(&cose_map, &mut out)
        .map_err(|e| format!("Failed to serialize COSE key CBOR: {}", e))?;
    Ok(out)
}

/// Builds the canonical WebAuthn `authenticatorData` structure for credential creation (W3C WebAuthn §6.1).
///
/// Wire layout:
/// - `rpIdHash` (32 bytes, [`RP_ID_HASH_LEN`]): `SHA256(lowercase(rp_id))`
/// - `flags` (1 byte): Bitmask of `UP | UV | BE | BS | AT`
/// - `signCount` (4 bytes, big-endian `u32`): Initial invocation count (`0`)
/// - `aaguid` (16 bytes, [`AAGUID_BYTE_LEN`]): Authenticator Attestation GUID
/// - `credentialIdLength` (2 bytes, big-endian `u16`): Byte length of `credential_id`
/// - `credentialId` (`credential_id.len()` bytes): Random credential identifier
/// - `credentialPublicKey` (`cose_public_key_cbor.len()` bytes): RFC 8152 COSE-encoded public key
pub fn build_authenticator_data_make_credential(
    rp_id: &str,
    flags: u8,
    sign_count: u32,
    aaguid: &[u8; AAGUID_BYTE_LEN],
    credential_id: &[u8],
    cose_public_key_cbor: &[u8],
) -> Result<Vec<u8>, String> {
    if credential_id.len() > u16::MAX as usize {
        return Err("Credential ID exceeds maximum length".into());
    }
    let clean_rp = rp_id.trim().to_ascii_lowercase();
    let rp_id_hash = crate::security::sha256_digest(clean_rp.as_bytes());
    let cred_len_be = (credential_id.len() as u16).to_be_bytes();

    let mut buf = Vec::with_capacity(
        RP_ID_HASH_LEN + 1 + 4 + AAGUID_BYTE_LEN + 2 + credential_id.len() + cose_public_key_cbor.len(),
    );
    buf.extend_from_slice(&rp_id_hash);
    buf.push(flags);
    buf.extend_from_slice(&sign_count.to_be_bytes());
    buf.extend_from_slice(aaguid);
    buf.extend_from_slice(&cred_len_be);
    buf.extend_from_slice(credential_id);
    buf.extend_from_slice(cose_public_key_cbor);
    Ok(buf)
}

/// Builds the canonical 37-byte WebAuthn `authenticatorData` structure for assertion signing (W3C WebAuthn §6.1).
///
/// Wire layout (37 bytes total = [`RP_ID_HASH_LEN`] + 1 + 4):
/// - `rpIdHash` (32 bytes): `SHA256(lowercase(rp_id))`
/// - `flags` (1 byte): Bitmask of `UP | UV | BE | BS`
/// - `signCount` (4 bytes, big-endian `u32`): Monotonically incremented invocation counter
pub fn build_authenticator_data_assertion(
    rp_id: &str,
    flags: u8,
    sign_count: u32,
) -> Vec<u8> {
    let clean_rp = rp_id.trim().to_ascii_lowercase();
    let rp_id_hash = crate::security::sha256_digest(clean_rp.as_bytes());
    let mut buf = Vec::with_capacity(RP_ID_HASH_LEN + 1 + 4);
    buf.extend_from_slice(&rp_id_hash);
    buf.push(flags);
    buf.extend_from_slice(&sign_count.to_be_bytes());
    buf
}

/// Builds a canonical CBOR WebAuthn Attestation Object (`fmt: "none"`).
pub fn build_attestation_object_cbor(auth_data: &[u8]) -> Result<Vec<u8>, String> {
    use ciborium::value::Value;
    let att_obj = Value::Map(vec![
        (Value::Text("fmt".into()), Value::Text("none".into())),
        (Value::Text("attStmt".into()), Value::Map(vec![])),
        (Value::Text("authData".into()), Value::Bytes(auth_data.to_vec())),
    ]);

    let mut out = Vec::with_capacity(auth_data.len() + 64);
    ciborium::into_writer(&att_obj, &mut out)
        .map_err(|e| format!("Failed to encode attestation object: {}", e))?;
    Ok(out)
}

/// Maximum sanitized display string length retained for resident passkey user labels.
const MAX_PASSKEY_USER_LABEL_CHARS: usize = 256;

/// Maximum permitted `user_id_hex` ASCII character length (128 hex chars = 64 bytes per WebAuthn §5.4.3).
const MAX_PASSKEY_USER_ID_HEX_LEN: usize = 128;

/// Strips ASCII/Unicode control characters and bounds length for user-facing passkey labels.
fn sanitize_user_label(raw: &str, max_chars: usize) -> String {
    raw.trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(max_chars)
        .collect()
}

/// Validates optional `user_id_hex` (even-length ASCII hex up to 64 bytes per W3C WebAuthn §5.4.3).
fn validate_and_normalize_user_id_hex(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    if trimmed.len() > MAX_PASSKEY_USER_ID_HEX_LEN {
        return Err("user_id_hex exceeds 64-byte (128-char) WebAuthn limit".into());
    }
    let decoded = crate::security::hex_decode(trimmed)
        .ok_or_else(|| "Invalid user_id_hex: must be even-length hexadecimal".to_string())?;
    Ok(crate::security::hex_encode(&decoded))
}

/// Generates a resident ECDSA P-256 passkey credential without biometric prompt (called post-Touch ID).
///
/// # Errors
/// Returns an explanatory error string if `rp_id`, `client_data_hash_hex`, or `user_id_hex` fail
/// validation, PKCS#8/COSE/CBOR serialization fails, or atomic disk persistence fails.
pub fn generate_passkey_credential(
    req: &PasskeyMakeCredentialRequest,
) -> Result<PasskeyMakeCredentialResponse, String> {
    // 0. Validate Relying Party ID, 32-byte clientDataHash (O(1) length check before decode), and user_id_hex
    validate_rp_id(&req.rp_id)?;
    if crate::security::hex_decode_array::<CLIENT_DATA_HASH_LEN>(req.client_data_hash_hex.trim())
        .is_none()
    {
        return Err("Invalid client_data_hash: must be exactly 32-byte (64-char) hex".into());
    }
    let clean_user_id_hex = validate_and_normalize_user_id_hex(&req.user_id_hex)?;

    // 1. Generate fresh cryptographic P-256 signing key
    let mut rng = OsRng;
    let signing_key = P256SigningKey::random(&mut rng);
    let verifying_key = P256VerifyingKey::from(&signing_key);
    let sec1_pub = verifying_key.to_encoded_point(false);
    let public_key_sec1 = sec1_pub.as_bytes().to_vec();

    // 2. Derive PKCS#8 private key DER
    let pkcs8_der = signing_key
        .to_pkcs8_der()
        .map_err(|e| format!("PKCS#8 encoding failed: {}", e))?
        .as_bytes()
        .to_vec();
    drop(signing_key);

    // 3. Generate random 32-byte credential identifier
    let cred_id_bytes = crate::security::csprng_array::<CREDENTIAL_ID_LEN>();
    let cred_id_hex = crate::security::hex_encode(&cred_id_bytes);

    // 4. Encode COSE public key
    let cose_key = encode_cose_p256_public_key(&public_key_sec1)?;

    // 5. Build authenticatorData with UP=1, UV=1, BE=1, BS=1, AT=1 (0x5D, matching Windows 11 passkey plugins)
    let flags = AUTHDATA_FLAG_USER_PRESENT
        | AUTHDATA_FLAG_USER_VERIFIED
        | AUTHDATA_FLAG_BACKUP_ELIGIBLE
        | AUTHDATA_FLAG_BACKUP_STATE
        | AUTHDATA_FLAG_ATTESTED_CRED_DATA;
    let auth_data = build_authenticator_data_make_credential(
        &req.rp_id,
        flags,
        0, // Initial signature counter
        &INTEGRATOR_AAGUID,
        &cred_id_bytes,
        &cose_key,
    )?;

    // 6. Build Attestation Object
    let att_obj_cbor = build_attestation_object_cbor(&auth_data)?;

    // 7. Sanitize user metadata and persist record atomically in passkeys_v1.json
    let record = PasskeyRecord {
        credential_id_hex: cred_id_hex.clone(),
        rp_id: req.rp_id.trim().to_ascii_lowercase(),
        user_id_hex: clean_user_id_hex,
        user_name: sanitize_user_label(&req.user_name, MAX_PASSKEY_USER_LABEL_CHARS),
        user_display_name: sanitize_user_label(&req.user_display_name, MAX_PASSKEY_USER_LABEL_CHARS),
        private_key_pkcs8_der: pkcs8_der,
        public_key_sec1,
        cose_alg: COSE_ALG_ES256,
        sign_count: 0,
        created_at_ms: crate::security::unix_epoch_millis(),
    };
    passkey_store().insert(record)?;

    Ok(PasskeyMakeCredentialResponse {
        credential_id_hex: cred_id_hex,
        auth_data_hex: crate::security::hex_encode(&auth_data),
        attestation_format: "none".into(),
        attestation_object_cbor_hex: crate::security::hex_encode(&att_obj_cbor),
    })
}

/// Asserts an existing resident passkey credential without biometric prompt (called post-Touch ID).
///
/// Zeroizes the temporary cloned PKCS#8 private key DER buffer immediately after constructing the signing key.
///
/// # Errors
/// Returns an error string if `rp_id` or `client_data_hash_hex` is malformed, no matching resident
/// passkey exists for `rp_id`, counter persistence fails, or stored private key DER decoding fails.
pub fn sign_passkey_assertion(
    req: &PasskeyGetAssertionRequest,
) -> Result<PasskeyGetAssertionResponse, String> {
    // 0. Validate Relying Party ID and 32-byte clientDataHash before touching the store
    validate_rp_id(&req.rp_id)?;
    let client_data_hash =
        crate::security::hex_decode_array::<CLIENT_DATA_HASH_LEN>(req.client_data_hash_hex.trim())
            .ok_or_else(|| "Invalid client_data_hash: must be exactly 32-byte (64-char) hex".to_string())?;

    // 1. Look up existing credential matching RP ID and optional allowCredentials allow-list
    let store = passkey_store();
    let mut record = store
        .find_for_rp(&req.rp_id, &req.allow_credential_ids_hex)?
        .ok_or_else(|| format!("No passkey found for domain '{}'", req.rp_id))?;

    // 2. Parse P-256 signing key and immediately zeroize the cloned DER buffer
    let signing_key_res = P256SigningKey::from_pkcs8_der(&record.private_key_pkcs8_der);
    record.private_key_pkcs8_der.zeroize();
    let signing_key = signing_key_res.map_err(|e| format!("Corrupt private key DER: {}", e))?;

    // 3. Atomically increment persistent signature counter after validating stored key integrity
    let new_sign_count = store.increment_sign_count(&record.credential_id_hex)?;

    // 4. Construct authenticatorData with UP=1, UV=1, BE=1, BS=1 (0x1D, matching registration BE/BS bits)
    let flags = AUTHDATA_FLAG_USER_PRESENT
        | AUTHDATA_FLAG_USER_VERIFIED
        | AUTHDATA_FLAG_BACKUP_ELIGIBLE
        | AUTHDATA_FLAG_BACKUP_STATE;
    let auth_data = build_authenticator_data_assertion(&req.rp_id, flags, new_sign_count);

    // 5. Compute ECDSA P-256 signature over `authenticatorData || clientDataHash`
    let mut data_to_sign = Vec::with_capacity(auth_data.len() + CLIENT_DATA_HASH_LEN);
    data_to_sign.extend_from_slice(&auth_data);
    data_to_sign.extend_from_slice(&client_data_hash);

    let signature: P256Signature = signing_key.sign(&data_to_sign);
    drop(signing_key);
    let signature_der = signature.to_der();

    Ok(PasskeyGetAssertionResponse {
        credential_id_hex: record.credential_id_hex,
        user_id_hex: record.user_id_hex,
        auth_data_hex: crate::security::hex_encode(&auth_data),
        signature_der_hex: crate::security::hex_encode(signature_der.as_bytes()),
        sign_count: new_sign_count,
    })
}

// ============================================================================
// macOS Native Touch ID Biometric Evaluation & Passkey Integration
// ============================================================================

/// Evaluates physical Apple Touch ID biometrics on macOS and registers a new passkey credential.
///
/// Validates `rp_id`, `client_data_hash_hex`, and `user_id_hex` and sanitizes control characters
/// from `user_name` *before* invoking the macOS `LocalAuthentication` Touch ID prompt so malformed
/// or spoofed requests fail immediately without prompting the user.
///
/// # Errors
/// Returns an error string on validation failure, non-macOS execution, canceled/failed Touch ID
/// biometric verification, or credential persistence failure.
pub fn evaluate_mac_touchid_and_make_credential(
    req: &PasskeyMakeCredentialRequest,
) -> Result<PasskeyMakeCredentialResponse, String> {
    #[cfg(target_os = "macos")]
    {
        // Pre-flight validation before triggering physical biometric prompt
        validate_rp_id(&req.rp_id)?;
        let clean_hash = req.client_data_hash_hex.trim();
        if crate::security::hex_decode_array::<CLIENT_DATA_HASH_LEN>(clean_hash).is_none() {
            return Err("Invalid client_data_hash: must be 32-byte (64-char) hex".into());
        }
        let _ = validate_and_normalize_user_id_hex(&req.user_id_hex)?;
        let sanitized_user = sanitize_user_label(&req.user_name, 128);
        let prompt_reason = format!(
            "create a passkey for {} ({})",
            req.rp_id.trim(),
            sanitized_user
        );
        let challenge_nonce = crate::security::csprng_array::<32>();
        let challenge_hex = crate::security::hex_encode(&challenge_nonce);

        // Biometric prompt via Apple LocalAuthentication
        let _assertion = crate::trust::evaluate_local_touchid_and_sign(
            &challenge_hex,
            "00000000000000000000000000000000",
            &prompt_reason,
        )?;

        // Biometrics confirmed -> generate and store credential
        generate_passkey_credential(req)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = req;
        Err("Hardware Touch ID is only supported on macOS".into())
    }
}

/// Evaluates physical Apple Touch ID biometrics on macOS and signs an existing passkey assertion.
///
/// Performs pre-flight validation of `rp_id`, `client_data_hash_hex`, and resident credential
/// existence *before* presenting the Touch ID prompt.
pub fn evaluate_mac_touchid_and_sign_assertion(
    req: &PasskeyGetAssertionRequest,
) -> Result<PasskeyGetAssertionResponse, String> {
    #[cfg(target_os = "macos")]
    {
        // Pre-flight validation: verify RP ID syntax, clientDataHash format, and matching
        // Integrator passkey existence BEFORE prompting Touch ID.
        validate_rp_id(&req.rp_id)?;
        let clean_hash = req.client_data_hash_hex.trim();
        if crate::security::hex_decode_array::<CLIENT_DATA_HASH_LEN>(clean_hash).is_none() {
            return Err("Invalid client_data_hash: must be 32-byte (64-char) hex".into());
        }
        if !passkey_store().has_for_rp(&req.rp_id, &req.allow_credential_ids_hex)? {
            return Err(format!(
                "NO_PASSKEY_FOUND: No Integrator Touch ID passkey stored for '{}'",
                req.rp_id
            ));
        }

        // macOS prefixes "Touch ID to " in its native Touch Bar & sheet UI.
        let prompt_reason = format!("sign in to {}", req.rp_id.trim());
        let challenge_nonce = crate::security::csprng_array::<32>();
        let challenge_hex = crate::security::hex_encode(&challenge_nonce);

        // Biometric prompt via Apple LocalAuthentication
        let _assertion = crate::trust::evaluate_local_touchid_and_sign(
            &challenge_hex,
            "00000000000000000000000000000000",
            &prompt_reason,
        )?;

        // Biometrics confirmed -> sign assertion
        sign_passkey_assertion(req)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = req;
        Err("Hardware Touch ID is only supported on macOS".into())
    }
}

/// Returns a sanitized list of all resident passkeys (private signing keys stripped) for CLI/IPC display.
///
/// # Errors
/// Returns an error string if the internal store mutex is poisoned.
pub fn list_resident_passkeys() -> Result<Vec<PasskeyRecord>, String> {
    passkey_store().list_all()
}

// ============================================================================
// CTAP2 CBOR Message Processing (For Windows IPluginAuthenticator)
// ============================================================================

/// Returns canonical CBOR bytes for the CTAP2 `authenticatorGetInfo` structure.
/// Matches Microsoft Windows 11 WebAuthn Plugin expectations (versions, AAGUID, options,
/// internal transport, and ES256 algorithm descriptor).
pub fn get_info_cbor_bytes() -> Vec<u8> {
    use ciborium::value::Value;
    // Map:
    // 1 (versions): ["FIDO_2_0", "FIDO_2_1"]
    // 3 (aaguid): 16-byte INTEGRATOR_AAGUID
    // 4 (options): {"rk": true, "up": true, "uv": true}
    // 9 (transports): ["internal"]
    // 10 (algorithms): [{"alg": -7, "type": "public-key"}]
    let get_info = Value::Map(vec![
        (
            Value::Integer(1.into()),
            Value::Array(vec![
                Value::Text("FIDO_2_0".into()),
                Value::Text("FIDO_2_1".into()),
            ]),
        ),
        (
            Value::Integer(3.into()),
            Value::Bytes(INTEGRATOR_AAGUID.to_vec()),
        ),
        (
            Value::Integer(4.into()),
            Value::Map(vec![
                (Value::Text("rk".into()), Value::Bool(true)),
                (Value::Text("up".into()), Value::Bool(true)),
                (Value::Text("uv".into()), Value::Bool(true)),
            ]),
        ),
        (
            Value::Integer(9.into()),
            Value::Array(vec![Value::Text("internal".into())]),
        ),
        (
            Value::Integer(10.into()),
            Value::Array(vec![Value::Map(vec![
                (Value::Text("alg".into()), Value::Integer(COSE_ALG_ES256.into())),
                (Value::Text("type".into()), Value::Text("public-key".into())),
            ])]),
        ),
    ]);

    let mut out = Vec::with_capacity(128);
    let _ = ciborium::into_writer(&get_info, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cose_key_encoding() {
        let sec1_dummy = vec![0x04; P256_UNCOMPRESSED_KEY_LEN];
        let cose = encode_cose_p256_public_key(&sec1_dummy).expect("COSE encoding failed");
        assert!(!cose.is_empty());
    }

    #[test]
    fn test_auth_data_and_attestation() {
        let auth_data = build_authenticator_data_assertion("example.com", 0x05, 1);
        assert_eq!(auth_data.len(), 37);
        let att_obj = build_attestation_object_cbor(&auth_data).expect("Attestation encoding failed");
        assert!(!att_obj.is_empty());
    }

    #[test]
    fn test_validate_rp_id() {
        assert!(validate_rp_id("github.com").is_ok());
        assert!(validate_rp_id("login.live.com").is_ok());
        assert!(validate_rp_id("").is_err());
        assert!(validate_rp_id("https://github.com").is_err());
        assert!(validate_rp_id("github.com:443").is_err());
        assert!(validate_rp_id("bad\0domain").is_err());
        let long_rp = "a".repeat(254);
        assert!(validate_rp_id(&long_rp).is_err());
    }

    #[test]
    fn test_passkey_make_and_assert_roundtrip() {
        let req = PasskeyMakeCredentialRequest {
            client_data_hash_hex: crate::security::hex_encode(&[0x42; 32]),
            rp_id: "integrator.test".into(),
            user_id_hex: crate::security::hex_encode(&[0x01; 16]),
            user_name: "testuser\x07".into(),
            user_display_name: "Test User".into(),
            requester_hostname: "MacBook-Pro".into(),
        };
        let make_res = generate_passkey_credential(&req).expect("make credential failed");
        assert_eq!(make_res.attestation_format, "none");
        assert!(!make_res.credential_id_hex.is_empty());

        let assert_req = PasskeyGetAssertionRequest {
            client_data_hash_hex: crate::security::hex_encode(&[0x99; 32]),
            rp_id: "integrator.test".into(),
            allow_credential_ids_hex: vec![make_res.credential_id_hex.clone()],
            requester_hostname: "Windows-Desktop".into(),
        };
        let assert_res = sign_passkey_assertion(&assert_req).expect("assertion failed");
        assert_eq!(assert_res.credential_id_hex, make_res.credential_id_hex);
        assert_eq!(assert_res.sign_count, 1);

        // Resident listing must strip private keys so IPC/CLI output never exposes PKCS#8 material.
        let listed = list_resident_passkeys().expect("list_resident_passkeys failed");
        let rec = listed
            .iter()
            .find(|r| r.credential_id_hex == make_res.credential_id_hex)
            .expect("created credential present in listing");
        assert!(rec.private_key_pkcs8_der.is_empty());
        assert_eq!(rec.user_name, "testuser");
    }

    #[test]
    fn test_passkey_rejects_malformed_hashes_and_user_ids() {
        let bad_hash = PasskeyMakeCredentialRequest {
            client_data_hash_hex: "not_hex".into(),
            rp_id: "example.com".into(),
            user_id_hex: "0102".into(),
            user_name: "alice".into(),
            user_display_name: "Alice".into(),
            requester_hostname: "Win11".into(),
        };
        assert!(generate_passkey_credential(&bad_hash).is_err());

        let bad_user_id = PasskeyMakeCredentialRequest {
            client_data_hash_hex: crate::security::hex_encode(&[0x11; 32]),
            rp_id: "example.com".into(),
            user_id_hex: "xyz!".into(),
            user_name: "alice".into(),
            user_display_name: "Alice".into(),
            requester_hostname: "Win11".into(),
        };
        assert!(generate_passkey_credential(&bad_user_id).is_err());
    }
}
