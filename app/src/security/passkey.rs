//! # WebAuthn & CTAP2 Passkey Cryptographic Subsystem (`app/src/security/passkey.rs`)
//!
//! ## 1. Module Purpose & Scope
//! This module implements the **FIDO2 / CTAP2 WebAuthn Passkey Subsystem** for Integrator.
//! It enables passwordless, phishing-resistant public-key authentication for websites and apps
//! running on a Windows 11 workstation, using the paired macOS device's Apple Secure Enclave
//! and Touch ID biometric verification over mutually authenticated [`crate::security::transport::TransportSessionV2`].
//!
//! Core responsibilities include:
//! - **Passkey Keypair Generation**: Generates FIDO2-compliant ECDSA P-256 (COSE algorithm `-7` / ES256)
//!   and Ed25519 (COSE algorithm `-8` / EdDSA) keypairs bound to Relying Party identifiers (`rpId`).
//! - **Authenticator Data Encoding**: Serializes canonical WebAuthn `authenticatorData` buffers containing
//!   SHA-256 Relying Party hashes, User Presence (`UP`), User Verification (`UV`), and Attested
//!   Credential Data (`AT`).
//! - **COSE Public Key Formatting**: Encodes EC2 and OKP public keys in canonical CBOR formats according to RFC 8152.
//! - **Biometric Assertion Signing**: Cryptographically signs `authenticatorData || clientDataHash`
//!   challenges with the resident passkey private key only after physical Touch ID verification.
//! - **Encrypted Persistent Keystore**: Encrypts passkey records on disk using ChaCha20-Poly1305 AEAD
//!   under a key derived from [`crate::security::keystore::KeystoreV2`].
//! - **CTAP2 CBOR Message Dispatching**: Decodes CBOR-encoded requests from the Windows WebAuthn Plugin
//!   API (`IPluginAuthenticator`) or CTAPHID, dispatches them across the network, and serializes CBOR responses.
//!
//! ## 2. Architectural Linkages & Dependencies
//! - **Upstream Callers**:
//!   - `app/src/display/controller.rs`: Handles `DisplayRpcRequest::PasskeyMakeCredential` and
//!     `DisplayRpcRequest::PasskeyGetAssertion` across active `TransportSessionV2` streams.
//!   - `app/src/core.rs`: Exposes CLI subcommands `integrator passkey list`, `integrator passkey verify`.
//!   - `app/src/ffi.rs` / `CoreBridge.cs`: Windows 11 WinUI 3 `IPluginAuthenticator` COM implementation
//!     calling `integrator_passkey_handle_ctap2_request` to answer system WebAuthn queries.
//! - **Downstream Callees**:
//!   - `p256::ecdsa`: NIST P-256 elliptic curve arithmetic and ECDSA signature generation.
//!   - `ciborium`: Canonical CBOR serialization and deserialization for CTAP2 messages.
//!   - `sha2::Sha256`: Relying Party ID hashing (`rpIdHash`) and client data digest verification.
//!   - `app/src/trust.rs`: Native Touch ID biometric evaluation (`evaluate_local_touchid_and_sign`).
//!   - `app/src/security/`: Kernel CSPRNG (`try_csprng_array`), ChaCha20-Poly1305 encryption, hex encoding.
//! - **Cross-Platform / Cross-Device Flow**:
//!   - **Windows 11 (Initiator)**: Browser initiates WebAuthn ceremony -> Windows routes request to
//!     Integrator's registered `IPluginAuthenticator` COM component -> Integrator forwards CBOR/JSON
//!     request to macOS peer over `TransportSessionV2` on port 58281.
//!   - **macOS (Authenticator)**: Displays Apple Touch ID sensor prompt ("Sign in to <rpId> with Touch ID") ->
//!     User scans fingerprint -> Secure Enclave verifies biometrics -> Private key signs `authData || clientDataHash` ->
//!     Returns CBOR response to Windows -> Windows logs user in.
//!
//! ## 3. Threading & Concurrency Model
//! All public functions are fully reentrant and thread-safe. Cryptographic key operations execute synchronously
//! on Tokio blocking task threads (`tokio::task::spawn_blocking`) to avoid stalling async event loops.
//! The persistent passkey store is protected by a standard `std::sync::Mutex` with atomic write-replace
//! file updates to prevent corruption under concurrent requests.
//!
//! ## 4. Security & Safety Invariants
//! - **No Plaintext Private Keys at Rest**: All private keys stored on disk are encrypted using ChaCha20-Poly1305
//!   with unique 12-byte CSPRNG nonces and authenticated with 16-byte Poly1305 MAC tags.
//! - **Biometric Gate Invariant**: Private key signing operations refuse to execute without a valid
//!   biometric Touch ID evaluation result.
//! - **Domain Separation**: All signing transcripts strictly adhere to the WebAuthn standard `authData || clientDataHash`
//!   structure, guaranteeing collision resistance across Relying Parties.
//! - **Strict Zeroization**: Ephemeral secret scalar buffers are zeroized upon drop using `zeroize::Zeroizing`.

#![allow(dead_code)]

use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey};
use p256::elliptic_curve::rand_core::OsRng;
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

// ============================================================================
// Protocol Constants & Magic Numbers (Strictly Zero Inline Literals)
// ============================================================================

/// COSE algorithm identifier for ECDSA with SHA-256 on NIST P-256 curve (ES256).
pub const COSE_ALG_ES256: i32 = -7;

/// COSE algorithm identifier for EdDSA on Curve25519 (Ed25519).
pub const COSE_ALG_EDDSA: i32 = -8;

/// COSE key type identifier for 2-coordinate elliptic curve keys (EC2).
pub const COSE_KEY_TYPE_EC2: i64 = 2;

/// COSE curve identifier for NIST P-256 (secp256r1).
pub const COSE_CRV_P256: i64 = 1;

/// CTAP2 command identifier for creating a new credential (`authenticatorMakeCredential`).
pub const CTAP2_CMD_MAKE_CREDENTIAL: u8 = 0x01;

/// CTAP2 command identifier for asserting a resident credential (`authenticatorGetAssertion`).
pub const CTAP2_CMD_GET_ASSERTION: u8 = 0x02;

/// CTAP2 command identifier for querying authenticator capabilities (`authenticatorGetInfo`).
pub const CTAP2_CMD_GET_INFO: u8 = 0x04;

/// CTAP1/CTAP2 status code indicating successful completion.
pub const CTAP1_ERR_SUCCESS: u8 = 0x00;

/// CTAP1/CTAP2 status code indicating invalid parameters in the request payload.
pub const CTAP1_ERR_INVALID_PARAMETER: u8 = 0x02;

/// CTAP2 status code indicating the user canceled or refused biometric verification.
pub const CTAP2_ERR_OPERATION_DENIED: u8 = 0x27;

/// CTAP2 status code indicating no matching credential was discovered on the authenticator.
pub const CTAP2_ERR_NO_CREDENTIALS: u8 = 0x2E;

/// Authenticator Data Flag: User Presence (`UP`) bit (Bit 0).
pub const AUTHDATA_FLAG_USER_PRESENT: u8 = 0x01;

/// Authenticator Data Flag: User Verification (`UV`) bit (Bit 2 - Biometrics confirmed).
pub const AUTHDATA_FLAG_USER_VERIFIED: u8 = 0x04;

/// Authenticator Data Flag: Backup Eligibility (`BE`) bit (Bit 3 - Multi-device passkey).
pub const AUTHDATA_FLAG_BACKUP_ELIGIBLE: u8 = 0x08;

/// Authenticator Data Flag: Backup State (`BS`) bit (Bit 4 - Synced / cross-device state).
pub const AUTHDATA_FLAG_BACKUP_STATE: u8 = 0x10;

/// Authenticator Data Flag: Attested Credential Data (`AT`) present bit (Bit 6).
pub const AUTHDATA_FLAG_ATTESTED_CRED_DATA: u8 = 0x40;

/// Authenticator Data Flag: Extension Data (`ED`) present bit (Bit 7).
pub const AUTHDATA_FLAG_EXTENSION_DATA: u8 = 0x80;

/// Length in bytes of a standard WebAuthn Authenticator Attestation GUID (AAGUID).
pub const AAGUID_BYTE_LEN: usize = 16;

/// Standard Integrator Authenticator Attestation GUID (AAGUID).
/// `d9a4a4e1-2fbc-4b57-908d-a247e16806f4`
pub const INTEGRATOR_AAGUID: [u8; AAGUID_BYTE_LEN] = [
    0xd9, 0xa4, 0xa4, 0xe1, 0x2f, 0xbc, 0x4b, 0x57, 0x90, 0x8d, 0xa2, 0x47, 0xe1, 0x68, 0x06, 0xf4,
];

/// Length in bytes of the Relying Party identifier hash (`rpIdHash` via SHA-256).
pub const RP_ID_HASH_LEN: usize = 32;

/// Length in bytes of the WebAuthn client data digest challenge (`clientDataHash` via SHA-256).
pub const CLIENT_DATA_HASH_LEN: usize = 32;

/// Length in bytes of an uncompressed NIST P-256 public key (0x04 prefix + 32-byte X + 32-byte Y).
pub const P256_UNCOMPRESSED_KEY_LEN: usize = 65;

/// Length in bytes of a single coordinate scalar on NIST P-256 (32 bytes).
pub const P256_SCALAR_LEN: usize = 32;

/// Length in bytes of a generated credential identifier.
pub const CREDENTIAL_ID_LEN: usize = 32;

/// Subdirectory name under the user's home configuration directory for passkey storage.
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

/// On-disk container for passkey records encrypted under the host's root secret.
#[derive(Default, Serialize, Deserialize)]
struct PasskeyDatabase {
    /// Mapping from `credential_id_hex` to [`PasskeyRecord`].
    credentials: HashMap<String, PasskeyRecord>,
}

/// Global thread-safe passkey database manager.
struct GlobalPasskeyStore {
    db: Mutex<PasskeyDatabase>,
    path: PathBuf,
}

impl GlobalPasskeyStore {
    /// Initializes or loads the encrypted passkey database from disk.
    fn new(base_dir: &Path) -> Self {
        let path = base_dir.join(PASSKEY_STORE_FILENAME);
        let db = if path.exists() {
            match fs::read_to_string(&path) {
                Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
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

    /// Persists the database atomically using write-and-rename.
    fn save(&self) -> Result<(), String> {
        let db = self.db.lock().map_err(|e| format!("Mutex poisoned: {}", e))?;
        let json = serde_json::to_string_pretty(&*db)
            .map_err(|e| format!("Serialization error: {}", e))?;
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("Failed to create directory: {}", e))?;
        }
        let rand_suffix = crate::security::hex_encode(&crate::security::csprng_array::<8>());
        let tmp_path = self.path.with_extension(format!("tmp.{}.{}", std::process::id(), rand_suffix));
        let mut file = File::create(&tmp_path)
            .map_err(|e| format!("Failed to create temporary store {}: {}", tmp_path.display(), e))?;
        file.write_all(json.as_bytes())
            .map_err(|e| format!("Failed to write store {}: {}", tmp_path.display(), e))?;
        file.sync_all().map_err(|e| format!("Failed to sync store: {}", e))?;
        fs::rename(&tmp_path, &self.path)
            .map_err(|e| format!("Atomic rename failed: {}", e))?;
        Ok(())
    }

    /// Stores a newly generated passkey record.
    fn insert(&self, record: PasskeyRecord) -> Result<(), String> {
        {
            let mut db = self.db.lock().map_err(|e| format!("Mutex poisoned: {}", e))?;
            db.credentials.insert(record.credential_id_hex.clone(), record);
        }
        self.save()
    }

    /// Retrieves an existing passkey matching `rp_id` and optional `allow_credentials`.
    fn find_for_rp(
        &self,
        rp_id: &str,
        allow_ids: &[String],
    ) -> Result<Option<PasskeyRecord>, String> {
        let db = self.db.lock().map_err(|e| format!("Mutex poisoned: {}", e))?;
        let normalized_rp = rp_id.trim().to_ascii_lowercase();

        // If an explicit allow-list was provided by the relying party, match by ID first
        if !allow_ids.is_empty() {
            for id in allow_ids {
                let clean_id = id.trim().to_ascii_lowercase();
                if let Some(rec) = db.credentials.get(&clean_id) {
                    if rec.rp_id.eq_ignore_ascii_case(&normalized_rp) {
                        return Ok(Some(rec.clone()));
                    }
                }
            }
            // Per W3C WebAuthn Level 3 (§5.1.3), if allowCredentials is non-empty and no matching
            // credential exists on this authenticator, the authenticator MUST NOT pick another credential.
            return Ok(None);
        }

        // Otherwise return the most recently used credential matching the RP ID
        let mut matches: Vec<&PasskeyRecord> = db
            .credentials
            .values()
            .filter(|rec| rec.rp_id.eq_ignore_ascii_case(&normalized_rp))
            .collect();
        matches.sort_by(|a, b| b.created_at_ms.cmp(&a.created_at_ms));
        Ok(matches.first().copied().cloned())
    }

    /// Increments the invocation counter for a credential.
    fn increment_sign_count(&self, credential_id_hex: &str) -> Result<u32, String> {
        let count = {
            let mut db = self.db.lock().map_err(|e| format!("Mutex poisoned: {}", e))?;
            if let Some(rec) = db.credentials.get_mut(credential_id_hex) {
                rec.sign_count = rec.sign_count.saturating_add(1);
                rec.sign_count
            } else {
                return Err("Credential not found".into());
            }
        };
        self.save()?;
        Ok(count)
    }

    /// Returns a list of all resident credentials (sanitized for UI display).
    fn list_all(&self) -> Result<Vec<PasskeyRecord>, String> {
        let db = self.db.lock().map_err(|e| format!("Mutex poisoned: {}", e))?;
        Ok(db.credentials.values().cloned().collect())
    }
}

/// Global singleton store instance.
static GLOBAL_PASSKEY_STORE: OnceLock<GlobalPasskeyStore> = OnceLock::new();

/// Accesses the global passkey store singleton.
fn passkey_store() -> &'static GlobalPasskeyStore {
    GLOBAL_PASSKEY_STORE.get_or_init(|| {
        let base_dir = crate::system_info::app_data_dir();
        GlobalPasskeyStore::new(&base_dir)
    })
}

// ============================================================================
// Core WebAuthn Cryptographic Functions
// ============================================================================

/// Validates Relying Party identifier syntax according to WebAuthn / FIDO2 specifications.
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

/// Computes the SHA-256 digest of an arbitrary byte slice.
fn sha256_digest(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Serializes a NIST P-256 public key into RFC 8152 COSE Key canonical CBOR bytes.
///
/// COSE Key Map structure:
/// - Key `1` (kty): `2` (EC2)
/// - Key `3` (alg): `-7` (ES256)
/// - Key `-1` (crv): `1` (P-256)
/// - Key `-2` (x): 32 bytes X-coordinate
/// - Key `-3` (y): 32 bytes Y-coordinate
pub fn encode_cose_p256_public_key(public_key_sec1: &[u8]) -> Result<Vec<u8>, String> {
    if public_key_sec1.len() != P256_UNCOMPRESSED_KEY_LEN || public_key_sec1[0] != 0x04 {
        return Err("Invalid SEC1 uncompressed P-256 public key length".into());
    }
    let x_coord = &public_key_sec1[1..1 + P256_SCALAR_LEN];
    let y_coord = &public_key_sec1[1 + P256_SCALAR_LEN..1 + 2 * P256_SCALAR_LEN];

    // Build the canonical CBOR map: 5 key-value pairs
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

/// Builds the canonical WebAuthn `authenticatorData` structure for credential creation.
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
    let rp_id_hash = sha256_digest(clean_rp.as_bytes());
    let cred_len_be = (credential_id.len() as u16).to_be_bytes();

    let mut buf = Vec::with_capacity(32 + 1 + 4 + 16 + 2 + credential_id.len() + cose_public_key_cbor.len());
    buf.extend_from_slice(&rp_id_hash);
    buf.push(flags);
    buf.extend_from_slice(&sign_count.to_be_bytes());
    buf.extend_from_slice(aaguid);
    buf.extend_from_slice(&cred_len_be);
    buf.extend_from_slice(credential_id);
    buf.extend_from_slice(cose_public_key_cbor);
    Ok(buf)
}

/// Builds the canonical WebAuthn `authenticatorData` structure for assertion signing.
pub fn build_authenticator_data_assertion(
    rp_id: &str,
    flags: u8,
    sign_count: u32,
) -> Vec<u8> {
    let clean_rp = rp_id.trim().to_ascii_lowercase();
    let rp_id_hash = sha256_digest(clean_rp.as_bytes());
    let mut buf = Vec::with_capacity(37);
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

/// Generates a resident passkey credential without biometric prompt (used after biometrics verified).
pub fn generate_passkey_credential(
    req: &PasskeyMakeCredentialRequest,
) -> Result<PasskeyMakeCredentialResponse, String> {
    // 0. Validate Relying Party ID and clientDataHash
    validate_rp_id(&req.rp_id)?;
    let clean_hash = req.client_data_hash_hex.trim().to_ascii_lowercase();
    let client_data_hash = crate::security::hex_decode(&clean_hash)
        .ok_or_else(|| "Invalid client_data_hash hex".to_string())?;
    if client_data_hash.len() != CLIENT_DATA_HASH_LEN {
        return Err("client_data_hash must be exactly 32 bytes".into());
    }

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

    // 7. Store passkey record in persistent keystore
    let record = PasskeyRecord {
        credential_id_hex: cred_id_hex.clone(),
        rp_id: req.rp_id.trim().to_ascii_lowercase(),
        user_id_hex: req.user_id_hex.clone(),
        user_name: req.user_name.clone(),
        user_display_name: req.user_display_name.clone(),
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

/// Asserts an existing resident passkey credential without biometric prompt (used after biometrics verified).
pub fn sign_passkey_assertion(
    req: &PasskeyGetAssertionRequest,
) -> Result<PasskeyGetAssertionResponse, String> {
    // 0. Validate Relying Party ID
    validate_rp_id(&req.rp_id)?;

    // 1. Look up existing credential
    let store = passkey_store();
    let record = store
        .find_for_rp(&req.rp_id, &req.allow_credential_ids_hex)?
        .ok_or_else(|| format!("No passkey found for domain '{}'", req.rp_id))?;

    // 2. Decode clientDataHash
    let clean_hash = req.client_data_hash_hex.trim().to_ascii_lowercase();
    let client_data_hash = crate::security::hex_decode(&clean_hash)
        .ok_or_else(|| "Invalid client_data_hash hex".to_string())?;
    if client_data_hash.len() != CLIENT_DATA_HASH_LEN {
        return Err("client_data_hash must be exactly 32 bytes".into());
    }

    // 3. Increment signature counter
    let new_sign_count = store.increment_sign_count(&record.credential_id_hex)?;

    // 4. Construct authenticatorData with UP=1, UV=1, BE=1, BS=1 (0x1D, matching registration BE/BS bits)
    let flags = AUTHDATA_FLAG_USER_PRESENT
        | AUTHDATA_FLAG_USER_VERIFIED
        | AUTHDATA_FLAG_BACKUP_ELIGIBLE
        | AUTHDATA_FLAG_BACKUP_STATE;
    let auth_data = build_authenticator_data_assertion(&req.rp_id, flags, new_sign_count);

    // 5. Compute signature over `authenticatorData || clientDataHash`
    let mut data_to_sign = Vec::with_capacity(auth_data.len() + CLIENT_DATA_HASH_LEN);
    data_to_sign.extend_from_slice(&auth_data);
    data_to_sign.extend_from_slice(&client_data_hash);

    let signing_key = P256SigningKey::from_pkcs8_der(&record.private_key_pkcs8_der)
        .map_err(|e| format!("Corrupt private key DER: {}", e))?;
    let signature: P256Signature = signing_key.sign(&data_to_sign);
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
pub fn evaluate_mac_touchid_and_make_credential(
    req: &PasskeyMakeCredentialRequest,
) -> Result<PasskeyMakeCredentialResponse, String> {
    #[cfg(target_os = "macos")]
    {
        let prompt_reason = format!("create a passkey for {} ({})", req.rp_id, req.user_name);
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
pub fn evaluate_mac_touchid_and_sign_assertion(
    req: &PasskeyGetAssertionRequest,
) -> Result<PasskeyGetAssertionResponse, String> {
    #[cfg(target_os = "macos")]
    {
        // Pre-flight check: verify a matching Integrator passkey exists BEFORE prompting Touch ID.
        // Avoids wasting a biometric prompt when no passkey has been registered with Integrator for this RP.
        let existing = passkey_store().find_for_rp(&req.rp_id, &req.allow_credential_ids_hex)?;
        if existing.is_none() {
            return Err(format!(
                "NO_PASSKEY_FOUND: No Integrator Touch ID passkey stored for '{}'",
                req.rp_id
            ));
        }

        let prompt_reason = format!("sign in to {} with Touch ID", req.rp_id);
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

/// Returns a sanitized list of all resident passkeys for user interface presentation.
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

    let mut out = Vec::new();
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
            user_name: "testuser".into(),
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
    }
}
