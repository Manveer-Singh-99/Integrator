//! # Strict RFC 9382 SPAKE2 Implementation (`app/src/security/spake2_rfc9382.rs`)
//!
//! ## 1. Module Purpose & Mathematical Scope
//! This module implements the verbatim RFC 9382 Password-Authenticated Key Exchange (PAKE) protocol
//! instantiated over the twisted Edwards curve `edwards25519`:
//! `SPAKE2-edwards25519-SHA512-HKDF-SHA256-HMAC-SHA256`.
//!
//! It provides high-entropy shared secret derivation from low-entropy secrets (e.g. 6-digit numeric PINs)
//! without exposing the secret to offline dictionary attacks or eavesdropping.
//!
//! ### Why this custom implementation exists instead of using external crates (e.g., `spake2 0.4.0`):
//! - `spake2 0.4.0` implements the obsolete pre-RFC `draft-ladd-spake2-01` specification (originating from `python-spake2` in 2017).
//!   It uses non-RFC `M` and `N` point constants, omits cofactor clearing (`h = 8`) when computing shared point `K`,
//!   does not check for or reject small-subgroup torsion or identity points, and uses a static 192-byte SHA-256 hash
//!   instead of RFC 9382's canonical 8-byte little-endian length-prefixed transcript `TT`.
//! - This module implements the finalized **RFC 9382 (published December 2022)** Section 3 & Section 4 standard:
//!   1. Distinguished prime-order curve points `M` and `N` from RFC 9382 Section 4.
//!   2. 512-bit HKDF-SHA256 wide modular reduction modulo the prime subgroup order $\ell$ for password scalar $w$.
//!   3. Canonical compressed Edwards Y-coordinate point decoding and rejection of all 8 small-order torsion points.
//!   4. Mandatory cofactor clearing ($h = 8$) for $K = h \cdot x \cdot (pB - w \cdot N)$ and $K = h \cdot y \cdot (pA - w \cdot M)$,
//!      combined with explicit identity-element abort (`K.is_identity()`).
//!   5. Exact canonical 8-byte little-endian length-prefixed transcript `TT`:
//!      `len(A) || A || len(B) || B || len(pA) || pA || len(pB) || pB || len(K) || K || len(w) || w`.
//!   6. Strict cryptographic separation between raw group element $K$, shared secret $K_e$, confirmation
//!      master key $K_a$, directional confirmation MAC keys $K_{cA}$ / $K_{cB}$, and long-term application root key $K_{\text{root}}$.
//!
//! ## 2. Cryptographic Security & Threat Model
//! - **Mathematical Group**: Edwards25519 curve $-x^2 + y^2 = 1 - (121665/121666)x^2 y^2$ over $\mathbb{F}_{2^{255}-19}$.
//!   - Subgroup order $\ell = 2^{252} + 27742317777372353535851937790883648493$ (a 253-bit prime).
//!   - Cofactor $h = 8$.
//!   - Base point $B = (x, 4/5)$.
//! - **Offline Dictionary Attack Mitigation**: An attacker observing the handshake over the network
//!   or actively tampering with messages cannot verify a candidate password offline. Each invalid attempt
//!   requires an interactive online handshake with the server, where it is constrained by IP rate limiting.
//! - **Small-Subgroup Confinement & Torsion Attacks**:
//!   - Any peer share lying in the 8-element torsion subgroup is rejected immediately upon decoding via
//!     `point.is_small_order()`.
//!   - Multiplying by cofactor $h = 8$ guarantees that the unblinded point is cleared of any residual low-order
//!     torsion component before scalar multiplication by $x$ or $y$.
//! - **Identity Element Attack**:
//!   - If $K = O$ (the neutral identity element), the protocol aborts immediately with [`Spake2Error::IdentitySharedElement`].
//! - **Side-Channel Timing Resistance**:
//!   - Ephemeral scalar sampling and point scalar multiplications execute via `curve25519-dalek` constant-time formulas.
//!   - All confirmation MAC and signature comparisons use constant-time comparisons via [`subtle::ConstantTimeEq`].
//! - **Memory Safety & Zeroization**:
//!   - Ephemeral scalar $x$ or $y$, password scalar $w$, and my public share are wiped on `Drop` via [`zeroize::Zeroize`].
//!   - Output keys $K_e$, $K_a$, $K_{cA}$, $K_{cB}$, $K_{\text{root}}$, and $K_{\text{ack}}$ are wrapped in [`zeroize::Zeroizing`].
//!
//! ## 3. Architectural Linkages & Dependencies
//! - **Upstream Callers**:
//!   - `app/src/security/pairing.rs`: [`PairingCoordinatorV2`], [`ClientPairingHandshakeV2`], and [`ClientAwaitingServerComplete`] invoke [`compute_password_salt`], [`Spake2State::start_a`], [`Spake2State::start_b`], [`Spake2State::finish`], [`Spake2TranscriptOutput::verify_peer_confirm_mac`], and [`Spake2TranscriptOutput::derive_application_secrets`] during the 4-message `IPR2` pairing handshake.
//!   - `app/src/security/mod.rs`: Cryptographic unit and vector test suite validating RFC 9382 point constants, torsion rejection, and symmetric key agreement.
//! - **Downstream Callees**:
//!   - `curve25519_dalek`: Constant-time `EdwardsPoint`, `CompressedEdwardsY`, and `Scalar` arithmetic over `edwards25519`.
//!   - `hkdf::Hkdf<Sha256>`, `hmac::Hmac<Sha256>`, `sha2::{Sha256, Sha512}`: RFC 5869 HKDF key expansion, RFC 2104 HMAC tag generation, and SHA-2 transcript digests.
//!   - `subtle::ConstantTimeEq`: Timing-safe comparisons for scalars, curve points, and confirmation MACs.
//!   - `zeroize::{Zeroize, Zeroizing}`: Deterministic memory wiping of sensitive scalars, transcripts, and derived keys on drop.
//!   - `super::{try_csprng_fill, derive_key_id, format_sas_6}`: OS kernel CSPRNG entropy filling, 128-bit key ID derivation, and 6-character human-readable SAS formatting.
//! - **Cross-Platform / Cross-Device Flow (Mac ↔ Windows 11)**:
//!   - Ensures byte-for-byte identical PAKE computations across macOS (ARM64/x86_64) and Windows 11 (x86_64/ARM64) endpoints over TCP port 58281 (`IPR2` framing).
//!   - All curve points are exchanged as canonical 32-byte compressed Edwards Y coordinates, and all transcript length prefixes use canonical 8-byte little-endian (`u64::to_le_bytes`) encoding to eliminate endianness or architecture divergence.
//!
//! ### Protocol State Machine
//! ```text
//!    Initiator (Client A)                                 Responder (Server B)
//!    ====================                                 ====================
//!    Start: sample x in [1, l-1]                          Start: sample y in [1, l-1]
//!           w = derive_pw_scalar(PIN, salt)                      w = derive_pw_scalar(PIN, salt)
//!           pA = x*B + w*M                                       pB = y*B + w*N
//!                 ---------- [PairInit / pA] --------->
//!                 <--------- [PairServerShare / pB] ---
//!    Finish:                                              Finish:
//!      K = 8 * x * (pB - w*N)                               K = 8 * y * (pA - w*M)
//!      abort if K == Identity                               abort if K == Identity
//!      TT = len(A)||A||...||len(w)||w                       TT = len(A)||A||...||len(w)||w
//!      H(TT) = SHA512(TT) -> Ke || Ka                       H(TT) = SHA512(TT) -> Ke || Ka
//!      KcA || KcB = HKDF(Ka, "ConfirmationKeys"||aad)       KcA || KcB = HKDF(Ka, "ConfirmationKeys"||aad)
//!      F_A = HMAC(KcA, TT)                                  F_A = HMAC(KcA, TT)
//!      F_B = HMAC(KcB, TT)                                  F_B = HMAC(KcB, TT)
//!      sig_A = Ed25519_Sign(tt_sha256 || F_A)
//!                 ---------- [PairClientConfirm / F_A, sig_A] ->
//!                                                            Verify F_A == expected
//!                                                            Verify sig_A with peer Ed25519 key
//!                                                            sig_B = Ed25519_Sign(tt_sha256 || F_B || sig_A)
//!                                                            Derive K_root, K_ack, F_ack, SAS
//!                                                            Commit Client to KeystoreV2
//!                 <--------- [PairServerComplete / F_B, sig_B, F_ack, key_id] ---
//!    Verify F_B == expected
//!    Verify sig_B with peer Ed25519 key
//!    Derive K_root, K_ack, F_ack, SAS
//!    Verify F_ack == expected, key_id == expected
//!    Commit Server to KeystoreV2
//! ```
//!
//! ## 4. Threading & Concurrency Model
//! All structures and functions in this module are purely computational, synchronous, and non-blocking.
//! They contain no mutexes, channel endpoints, or file handles, making them safe to execute within any
//! Tokio async task or worker thread.
//!
//! ## 5. Security & Safety Invariants
//! - **Zero `unsafe` Blocks**: All curve arithmetic, hashing, and memory zeroization rely strictly on safe Rust abstractions.
//! - **Input Clamping**: Transcript identity (`id_a`, `id_b`) and associated data (`aad`) inputs are bounded to [`MAX_SPAKE2_TRANSCRIPT_INPUT_BYTES`] (4,096 bytes) to prevent memory exhaustion.
//! - **Strict Key Separation**: Shared group point $K$, encryption secret $K_e$, confirmation master key $K_a$, directional MAC keys $K_{cA}/K_{cB}$, root key $K_{\text{root}}$, and acknowledgment key $K_{\text{ack}}$ are domain-separated via SHA-512 splitting and HKDF-SHA256 labels.

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::IsIdentity,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

/// Type alias for HMAC-SHA256 message authentication code instance (32-byte tag output).
type HmacSha256 = Hmac<Sha256>;

/// RFC 9382 Section 4 `edwards25519` point constant `M` (compressed Edwards Y, 32 bytes):
/// `d048032c6ea0b6d697ddc2e86bda85a33adac920f1bf18e1b0c6d166a5cecdaf`
///
/// Generated deterministically per RFC 9382 Section 4 using the `edwards25519_PointGeneration`
/// algorithm with string `"SPAKE2-edwards25519-SHA512-HKDF-SHA256-HMAC-SHA256 Point M"`.
/// Blinds the initiator's ephemeral public share: $pA = x \cdot B + w \cdot M$.
pub const RFC9382_ED25519_M_BYTES: [u8; 32] = [
    0xd0, 0x48, 0x03, 0x2c, 0x6e, 0xa0, 0xb6, 0xd6, 0x97, 0xdd, 0xc2, 0xe8, 0x6b, 0xda, 0x85, 0xa3,
    0x3a, 0xda, 0xc9, 0x20, 0xf1, 0xbf, 0x18, 0xe1, 0xb0, 0xc6, 0xd1, 0x66, 0xa5, 0xce, 0xcd, 0xaf,
];

/// RFC 9382 Section 4 `edwards25519` point constant `N` (compressed Edwards Y, 32 bytes):
/// `d3bfb518f44f3430f29d0c92af503865a1ed3281dc69b35dd868ba85f886c4ab`
///
/// Generated deterministically per RFC 9382 Section 4 using the `edwards25519_PointGeneration`
/// algorithm with string `"SPAKE2-edwards25519-SHA512-HKDF-SHA256-HMAC-SHA256 Point N"`.
/// Blinds the responder's ephemeral public share: $pB = y \cdot B + w \cdot N$.
pub const RFC9382_ED25519_N_BYTES: [u8; 32] = [
    0xd3, 0xbf, 0xb5, 0x18, 0xf4, 0x4f, 0x34, 0x30, 0xf2, 0x9d, 0x0c, 0x92, 0xaf, 0x50, 0x38, 0x65,
    0xa1, 0xed, 0x32, 0x81, 0xdc, 0x69, 0xb3, 0x5d, 0xd8, 0x68, 0xba, 0x85, 0xf8, 0x86, 0xc4, 0xab,
];

/// Maximum permitted byte length for SPAKE2 identity strings (`id_a`, `id_b`) and associated data (`aad`).
pub const MAX_SPAKE2_TRANSCRIPT_INPUT_BYTES: usize = 4096;

/// Failure scenarios encountered during RFC 9382 SPAKE2 computation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Spake2Error {
    /// Password or numeric PIN slice is empty (must have length >= 1).
    EmptyPassword,
    /// The sampled ephemeral private scalar was zero modulo $\ell$ (probability $\approx 2^{-252}$).
    ZeroEphemeralScalar,
    /// An identity string (`id_a`, `id_b`) or associated data slice exceeded the maximum permitted size (4096 bytes).
    OversizedTranscriptInput,
    /// The peer's 32-byte public share is not a canonical, on-curve compressed Edwards25519 point.
    NonCanonicalPeerShare,
    /// The peer's public share lies in the small-order torsion subgroup (order dividing 8), indicating an attack.
    SmallOrderPeerShare,
    /// The computed shared group element $K$ is the neutral curve identity element $O$.
    IdentitySharedElement,
    /// Constant-time comparison of the peer's confirmation MAC ($F_A$ or $F_B$) failed (wrong password or altered transcript).
    ConfirmationMacMismatch,
}

impl std::fmt::Display for Spake2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Spake2Error::EmptyPassword => write!(f, "SPAKE2 password/PIN must not be empty"),
            Spake2Error::ZeroEphemeralScalar => write!(f, "SPAKE2 ephemeral scalar must be non-zero"),
            Spake2Error::OversizedTranscriptInput => {
                write!(f, "SPAKE2 identity or AAD input exceeds maximum permitted size")
            }
            Spake2Error::NonCanonicalPeerShare => {
                write!(f, "SPAKE2 peer point is not a valid canonical compressed Edwards25519 point")
            }
            Spake2Error::SmallOrderPeerShare => {
                write!(f, "SPAKE2 peer point lies in a small-order torsion subgroup")
            }
            Spake2Error::IdentitySharedElement => {
                write!(f, "SPAKE2 computed shared group element K is the identity point")
            }
            Spake2Error::ConfirmationMacMismatch => {
                write!(f, "SPAKE2 key confirmation MAC verification failed")
            }
        }
    }
}

impl std::error::Error for Spake2Error {}

/// Decompresses and returns the RFC 9382 Section 4 constant point `M` on `edwards25519`.
///
/// # Panics
/// Panics only if the hardcoded constant bytes fail curve decompression (impossible for valid RFC constant).
pub fn const_m() -> EdwardsPoint {
    CompressedEdwardsY(RFC9382_ED25519_M_BYTES)
        .decompress()
        .expect("RFC 9382 edwards25519 constant M is a valid curve point")
}

/// Decompresses and returns the RFC 9382 Section 4 constant point `N` on `edwards25519`.
///
/// # Panics
/// Panics only if the hardcoded constant bytes fail curve decompression (impossible for valid RFC constant).
pub fn const_n() -> EdwardsPoint {
    CompressedEdwardsY(RFC9382_ED25519_N_BYTES)
        .decompress()
        .expect("RFC 9382 edwards25519 constant N is a valid curve point")
}

/// Derives the password scalar $w \in [1, \ell - 1]$ using 512-bit HKDF-SHA256 expansion
/// and constant-time wide modular reduction modulo subgroup order $\ell$, per RFC 9382 §3.1.
///
/// # Mathematical Details
/// 1. Extracts PRK using `salt_pw` and input password/PIN bytes.
/// 2. Expands 64 pseudorandom bytes (512 bits) with info label `"RFC9382-edwards25519-w"`.
/// 3. Reduces the 64-byte integer modulo the 253-bit prime order $\ell$ via `Scalar::from_bytes_mod_order_wide`.
/// 4. If $w \equiv 0 \pmod \ell$, clamps $w = 1$ in constant time per RFC 9382 §3.1.
///
/// # Arguments
/// * `password` - Raw password or PIN bytes (must be non-empty).
/// * `salt_pw` - Domain-separated salt computed via [`compute_password_salt`].
///
/// # Errors
/// Returns [`Spake2Error::EmptyPassword`] if `password` is empty.
pub fn derive_password_scalar(password: &[u8], salt_pw: &[u8]) -> Result<Scalar, Spake2Error> {
    if password.is_empty() {
        return Err(Spake2Error::EmptyPassword);
    }
    // HKDF-Extract using domain-separated salt_pw as salt, password as IKM
    let hk = Hkdf::<Sha256>::new(Some(salt_pw), password);
    let mut okm = Zeroizing::new([0u8; 64]);
    // Expand 64 bytes to guarantee negligible bias (< 2^-256) upon modular reduction
    hk.expand(b"RFC9382-edwards25519-w", &mut *okm)
        .expect("64-byte HKDF-SHA256 expand cannot fail");

    // Reduce wide 512-bit integer modulo prime subgroup order l
    let mut w = Scalar::from_bytes_mod_order_wide(&okm);
    // RFC 9382 §3.1: w must be non-zero mod l. Constant-time check:
    if bool::from(w.ct_eq(&Scalar::ZERO)) {
        w = Scalar::ONE;
    }
    Ok(w)
}

/// Computes the domain-separated password salt for a pairing session between `client_device_id` and `server_device_id`.
///
/// # Formula
/// ```text
/// salt_pw = SHA256("integrator-spake2-pw-v2" || client_device_id || server_device_id)
/// ```
///
/// Binds both participant identities to the salt, preventing cross-device credential replay.
///
/// # Arguments
/// * `client_device_id` - 16-byte canonical device ID of Client A.
/// * `server_device_id` - 16-byte canonical device ID of Server B.
pub fn compute_password_salt(client_device_id: &[u8; 16], server_device_id: &[u8; 16]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"integrator-spake2-pw-v2");
    hasher.update(client_device_id);
    hasher.update(server_device_id);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Validates and decompresses a 32-byte peer public share (`pA` or `pB`).
///
/// Enforces two critical cryptographic invariants:
/// 1. **Canonical Field Encoding**: Ensures that re-compressing the decoded curve point matches the
///    original 32-byte input byte-for-byte in constant time, rejecting non-canonical field elements.
/// 2. **Torsion Freedom**: Rejects all 8 small-order torsion subgroup points on Edwards25519 via
///    `point.is_small_order()`.
///
/// # Arguments
/// * `bytes` - 32-byte compressed Edwards Y-coordinate received from the peer.
///
/// # Errors
/// - [`Spake2Error::NonCanonicalPeerShare`]: Bytes do not represent a valid or canonical curve point.
/// - [`Spake2Error::SmallOrderPeerShare`]: Point lies in the small-order torsion subgroup.
pub fn decode_valid_peer_share(bytes: &[u8; 32]) -> Result<EdwardsPoint, Spake2Error> {
    let compressed = CompressedEdwardsY(*bytes);
    let point = compressed
        .decompress()
        .ok_or(Spake2Error::NonCanonicalPeerShare)?;

    // Reject non-canonical field encodings by verifying re-compression matches byte-for-byte.
    if !bool::from(point.compress().as_bytes().ct_eq(bytes)) {
        return Err(Spake2Error::NonCanonicalPeerShare);
    }

    // Reject all 8 small-order torsion points on Edwards25519.
    if point.is_small_order() {
        return Err(Spake2Error::SmallOrderPeerShare);
    }

    Ok(point)
}

/// Appends an 8-byte little-endian length prefix followed by the byte slice, per RFC 9382 §3.3.
///
/// Wire encoding: `u64_le(len) || data`.
#[inline]
fn append_rfc9382_lv(buf: &mut Vec<u8>, data: &[u8]) {
    let len_le = (data.len() as u64).to_le_bytes();
    buf.extend_from_slice(&len_le);
    buf.extend_from_slice(data);
}

/// Constructs the exact RFC 9382 §3.3 canonical transcript `TT`:
/// ```text
/// TT = len(A) || A || len(B) || B || len(pA) || pA || len(pB) || pB || len(K) || K || len(w) || w
/// ```
///
/// All length fields are 8-byte unsigned integers in little-endian byte order.
///
/// # Arguments
/// * `id_a` - Client A identity string slice.
/// * `id_b` - Server B identity string slice.
/// * `p_a` - 32-byte compressed share $pA$.
/// * `p_b` - 32-byte compressed share $pB$.
/// * `k_bytes` - 32-byte compressed shared curve point $K$.
/// * `w_bytes` - 32-byte little-endian encoded password scalar $w$.
///
/// # Returns
/// Heap-allocated transcript vector wrapped in [`zeroize::Zeroizing`] because it embeds scalar $w$.
pub fn build_rfc9382_transcript(
    id_a: &[u8],
    id_b: &[u8],
    p_a: &[u8; 32],
    p_b: &[u8; 32],
    k_bytes: &[u8; 32],
    w_bytes: &[u8; 32],
) -> Zeroizing<Vec<u8>> {
    let cap = 6 * 8 + id_a.len() + id_b.len() + 4 * 32;
    let mut tt = Vec::with_capacity(cap);
    append_rfc9382_lv(&mut tt, id_a);
    append_rfc9382_lv(&mut tt, id_b);
    append_rfc9382_lv(&mut tt, p_a);
    append_rfc9382_lv(&mut tt, p_b);
    append_rfc9382_lv(&mut tt, k_bytes);
    append_rfc9382_lv(&mut tt, w_bytes);
    Zeroizing::new(tt)
}

/// Protocol role in the SPAKE2 exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Spake2Role {
    /// Initiator (`A`), blinds with RFC constant point $M$.
    InitiatorA,
    /// Responder (`B`), blinds with RFC constant point $N$.
    ResponderB,
}

/// Single-use ephemeral state machine for an RFC 9382 SPAKE2 handshake party.
///
/// Consumed by value in [`Spake2State::finish`] to enforce single-use execution and prevent
/// ephemeral scalar reuse across multiple peer shares. Securely zeroizes internal scalars
/// $x/y$ and $w$, transcript identities, and the local blinded share upon drop.
pub struct Spake2State {
    /// Protocol role of the local party ([`Spake2Role::InitiatorA`] or [`Spake2Role::ResponderB`]).
    role: Spake2Role,
    /// Ephemeral secret scalar $x \in [1, \ell - 1]$ (for Initiator A) or $y \in [1, \ell - 1]$ (for Responder B).
    xy_scalar: Scalar,
    /// Password-derived scalar $w \in [1, \ell - 1]$ computed from the 6-digit PIN and session salt.
    w_scalar: Scalar,
    /// Canonical initiator identity byte sequence `A` bound into the RFC 9382 transcript `TT` (max 4,096 bytes).
    id_a: Vec<u8>,
    /// Canonical responder identity byte sequence `B` bound into the RFC 9382 transcript `TT` (max 4,096 bytes).
    id_b: Vec<u8>,
    /// Local party's 32-byte compressed Edwards25519 blinded public share ($pA$ for Initiator A, $pB$ for Responder B).
    my_share: [u8; 32],
}

impl Drop for Spake2State {
    /// Zeroizes all secret scalars, transcript identity buffers, and public share bytes when the state leaves scope.
    fn drop(&mut self) {
        self.xy_scalar.zeroize();
        self.w_scalar.zeroize();
        self.id_a.zeroize();
        self.id_b.zeroize();
        self.my_share.zeroize();
    }
}

/// Samples a uniform non-zero private scalar $s \in [1, \ell - 1]$ from the OS kernel CSPRNG via rejection sampling.
///
/// # Mathematical Details
/// Samples 64 random bytes (512 bits) per iteration and performs wide modular reduction modulo the 253-bit
/// prime subgroup order $\ell$ (`Scalar::from_bytes_mod_order_wide`), ensuring statistical distance from a
/// uniform distribution over $\mathbb{Z}/\ell\mathbb{Z}$ is $< 2^{-256}$ per RFC 9382 §3.2.
///
/// # Errors
/// Returns [`Spake2Error::ZeroEphemeralScalar`] if the OS kernel CSPRNG fails to provide entropy.
fn sample_nonzero_scalar() -> Result<Scalar, Spake2Error> {
    let mut scalar_wide = Zeroizing::new([0u8; 64]);
    loop {
        // Fill 512-bit buffer from OS CSPRNG; abort immediately if kernel entropy source fails.
        super::try_csprng_fill(&mut *scalar_wide).map_err(|_| Spake2Error::ZeroEphemeralScalar)?;
        let s = Scalar::from_bytes_mod_order_wide(&scalar_wide);
        // Reject zero modulo l in constant time (probability ~ 2^-252).
        if !bool::from(s.ct_eq(&Scalar::ZERO)) {
            return Ok(s);
        }
    }
}

/// Output of [`Spake2State::finish`], providing strict separation of all derived keys and MAC tags.
#[derive(Debug, PartialEq, Eq)]
pub struct Spake2TranscriptOutput {
    /// $K_e$ (32 bytes): SPAKE2 shared secret ($\text{SHA512}(TT)[0..32]$), used ONLY to derive application root keys.
    pub k_e: Zeroizing<[u8; 32]>,
    /// $K_a$ (32 bytes): Confirmation master key ($\text{SHA512}(TT)[32..64]$), used ONLY to derive $K_{cA}$ and $K_{cB}$.
    pub k_a: Zeroizing<[u8; 32]>,
    /// $K_{cA}$ (32 bytes): Client (`A`) confirmation MAC key derived from $K_a$.
    pub k_confirm_a: Zeroizing<[u8; 32]>,
    /// $K_{cB}$ (32 bytes): Server (`B`) confirmation MAC key derived from $K_a$.
    pub k_confirm_b: Zeroizing<[u8; 32]>,
    /// $F_A = \text{HMAC-SHA256}(K_{cA}, TT)$ (32 bytes): Client confirmation tag.
    pub confirm_mac_a: [u8; 32],
    /// $F_B = \text{HMAC-SHA256}(K_{cB}, TT)$ (32 bytes): Server confirmation tag.
    pub confirm_mac_b: [u8; 32],
    /// $\text{SHA256}(TT)$ (32 bytes): Digest of transcript $TT$, used to bind Ed25519 signatures without leaking $w$.
    pub tt_sha256: [u8; 32],
}

/// Final application credentials and tokens derived from $K_e$ after mutual confirmation succeeds.
#[derive(Debug, PartialEq, Eq)]
pub struct PairingApplicationSecrets {
    /// Long-term 256-bit per-peer root key ($K_{\text{root}}$) stored in KeystoreV2.
    pub root_key: Zeroizing<[u8; 32]>,
    /// 128-bit key identifier: $\text{SHA256}(\text{"integrator-key-id-v2"} \,\|\, K_{\text{root}})[0..16]$.
    pub key_id: [u8; 16],
    /// 256-bit key for authenticating the final `PairServerComplete` acknowledgment tag ($F_{\text{ack}}$).
    pub ack_key: Zeroizing<[u8; 32]>,
    /// $F_{\text{ack}} = \text{HMAC-SHA256}(K_{\text{ack}}, \text{"integrator-pair-complete-v2"} \,\|\, tt\_sha256 \,\|\, F_A \,\|\, sig_A)$.
    pub ack_mac: [u8; 32],
    /// Human-readable 6-character Short Authentication String (`XXX-XXX`) for out-of-band user visual confirmation.
    pub sas_code: String,
}

impl Spake2State {
    /// Starts SPAKE2 as Initiator (`A`) using OS CSPRNG entropy.
    ///
    /// Computes $pA = x \cdot B + w \cdot M$.
    ///
    /// # Arguments
    /// * `password` - Numeric PIN or password bytes.
    /// * `salt_pw` - Domain-separated password salt.
    /// * `id_a` - Client A identity string slice.
    /// * `id_b` - Server B identity string slice.
    ///
    /// # Returns
    /// Tuple of `(Spake2State, [u8; 32])` containing the state and Client A's public share $pA$.
    pub fn start_a(
        password: &[u8],
        salt_pw: &[u8],
        id_a: &[u8],
        id_b: &[u8],
    ) -> Result<(Self, [u8; 32]), Spake2Error> {
        let x = sample_nonzero_scalar()?;
        Self::start_with_scalar(Spake2Role::InitiatorA, password, salt_pw, id_a, id_b, x)
    }

    /// Starts SPAKE2 as Responder (`B`) using OS CSPRNG entropy.
    ///
    /// Computes $pB = y \cdot B + w \cdot N$.
    ///
    /// # Arguments
    /// * `password` - Numeric PIN or password bytes.
    /// * `salt_pw` - Domain-separated password salt.
    /// * `id_a` - Client A identity string slice.
    /// * `id_b` - Server B identity string slice.
    ///
    /// # Returns
    /// Tuple of `(Spake2State, [u8; 32])` containing the state and Server B's public share $pB$.
    pub fn start_b(
        password: &[u8],
        salt_pw: &[u8],
        id_a: &[u8],
        id_b: &[u8],
    ) -> Result<(Self, [u8; 32]), Spake2Error> {
        let y = sample_nonzero_scalar()?;
        Self::start_with_scalar(Spake2Role::ResponderB, password, salt_pw, id_a, id_b, y)
    }

    /// Deterministic constructor accepting an explicit scalar.
    ///
    /// Used for deterministic test vectors and internal initialization. Rejects zero scalars and
    /// oversized identity inputs (> 4096 bytes).
    pub fn start_with_scalar(
        role: Spake2Role,
        password: &[u8],
        salt_pw: &[u8],
        id_a: &[u8],
        id_b: &[u8],
        xy_scalar: Scalar,
    ) -> Result<(Self, [u8; 32]), Spake2Error> {
        if bool::from(xy_scalar.ct_eq(&Scalar::ZERO)) {
            return Err(Spake2Error::ZeroEphemeralScalar);
        }
        if id_a.len() > MAX_SPAKE2_TRANSCRIPT_INPUT_BYTES
            || id_b.len() > MAX_SPAKE2_TRANSCRIPT_INPUT_BYTES
        {
            return Err(Spake2Error::OversizedTranscriptInput);
        }
        let w_scalar = derive_password_scalar(password, salt_pw)?;
        let blinding_point = match role {
            Spake2Role::InitiatorA => const_m(),
            Spake2Role::ResponderB => const_n(),
        };

        // Compute blinded share: pA = x*B + w*M  or  pB = y*B + w*N
        let share_point = (ED25519_BASEPOINT_POINT * xy_scalar) + (blinding_point * w_scalar);
        let my_share = share_point.compress().to_bytes();

        Ok((
            Self {
                role,
                xy_scalar,
                w_scalar,
                id_a: id_a.to_vec(),
                id_b: id_b.to_vec(),
                my_share,
            },
            my_share,
        ))
    }

    /// Completes the SPAKE2 exchange given the peer's 32-byte public share (`pB` or `pA`) and optional AAD.
    ///
    /// # Algorithm
    /// 1. Decodes and verifies peer share: canonical encoding, on-curve, not small-order.
    /// 2. Unblinds peer share: $p_{\text{peer}} - w \cdot N$ (Initiator A) or $p_{\text{peer}} - w \cdot M$ (Responder B).
    /// 3. Computes shared point with cofactor clearing: $K = 8 \cdot \text{scalar} \cdot \text{unblinded}$.
    /// 4. Aborts if $K == O$ (identity element).
    /// 5. Assembles canonical transcript `TT`.
    /// 6. Computes $H(TT) = \text{SHA512}(TT) \implies K_e \,\|\, K_a$.
    /// 7. Derives confirmation keys $K_{cA} \,\|\, K_{cB} = \text{HKDF-SHA256}(K_a, \text{"ConfirmationKeys"} \,\|\, aad, 64)$.
    /// 8. Computes directional confirmation MACs $F_A = \text{HMAC}(K_{cA}, TT)$ and $F_B = \text{HMAC}(K_{cB}, TT)$.
    ///
    /// # Arguments
    /// * `peer_share_bytes` - 32-byte compressed Edwards share from the remote party.
    /// * `aad` - Associated data (e.g. wire header hash) bound into confirmation key derivation.
    pub fn finish(
        self,
        peer_share_bytes: &[u8; 32],
        aad: &[u8],
    ) -> Result<Spake2TranscriptOutput, Spake2Error> {
        if aad.len() > MAX_SPAKE2_TRANSCRIPT_INPUT_BYTES {
            return Err(Spake2Error::OversizedTranscriptInput);
        }
        let peer_point = decode_valid_peer_share(peer_share_bytes)?;

        let (unblind_point, p_a, p_b) = match self.role {
            Spake2Role::InitiatorA => (const_n(), self.my_share, *peer_share_bytes),
            Spake2Role::ResponderB => (const_m(), *peer_share_bytes, self.my_share),
        };

        // Unblind: (p_peer - w * N) for Initiator A, or (p_peer - w * M) for Responder B
        let unblinded = peer_point - (unblind_point * self.w_scalar);

        // RFC 9382 §3.2 & §4: Multiply by cofactor h = 8 and by ephemeral scalar x or y:
        // K = 8 * x * (pB - w*N) = 8 * y * (pA - w*M)
        let k_point = unblinded.mul_by_cofactor() * self.xy_scalar;

        // Mandatory abort if K is the neutral curve identity element O.
        if k_point.is_identity() {
            return Err(Spake2Error::IdentitySharedElement);
        }

        let k_bytes = Zeroizing::new(k_point.compress().to_bytes());
        let w_bytes = Zeroizing::new(self.w_scalar.to_bytes());

        // Construct canonical RFC 9382 length-prefixed transcript TT.
        let tt = build_rfc9382_transcript(&self.id_a, &self.id_b, &p_a, &p_b, &k_bytes, &w_bytes);

        // H(TT) = SHA512(TT) -> Ke (first 32 bytes) || Ka (second 32 bytes).
        let digest_512 = Sha512::digest(&*tt);
        let mut h_tt = Zeroizing::new([0u8; 64]);
        h_tt.copy_from_slice(&digest_512);
        let mut k_e = Zeroizing::new([0u8; 32]);
        let mut k_a = Zeroizing::new([0u8; 32]);
        k_e.copy_from_slice(&h_tt[0..32]);
        k_a.copy_from_slice(&h_tt[32..64]);

        // Derive confirmation keys KcA || KcB = HKDF-SHA256(salt="", ikm=Ka, info="ConfirmationKeys" || aad, L=64).
        let hk_confirm = Hkdf::<Sha256>::new(Some(b""), &*k_a);
        let mut info = Vec::with_capacity(b"ConfirmationKeys".len() + aad.len());
        info.extend_from_slice(b"ConfirmationKeys");
        info.extend_from_slice(aad);

        let mut kc_okm = Zeroizing::new([0u8; 64]);
        hk_confirm
            .expand(&info, &mut *kc_okm)
            .expect("64-byte HKDF expand cannot fail");

        let mut k_confirm_a = Zeroizing::new([0u8; 32]);
        let mut k_confirm_b = Zeroizing::new([0u8; 32]);
        k_confirm_a.copy_from_slice(&kc_okm[0..32]);
        k_confirm_b.copy_from_slice(&kc_okm[32..64]);

        // Compute confirmation MACs over the full transcript TT:
        // F_A = HMAC-SHA256(KcA, TT), F_B = HMAC-SHA256(KcB, TT)
        let confirm_mac_a = compute_hmac_sha256(&*k_confirm_a, &tt);
        let confirm_mac_b = compute_hmac_sha256(&*k_confirm_b, &tt);

        let tt_sha256_digest = Sha256::digest(&*tt);
        let mut tt_sha256 = [0u8; 32];
        tt_sha256.copy_from_slice(&tt_sha256_digest);

        Ok(Spake2TranscriptOutput {
            k_e,
            k_a,
            k_confirm_a,
            k_confirm_b,
            confirm_mac_a,
            confirm_mac_b,
            tt_sha256,
        })
    }
}

impl Spake2TranscriptOutput {
    /// Verifies the peer's confirmation MAC tag (`F_A` or `F_B`) in constant execution time.
    ///
    /// # Arguments
    /// * `expected_role_of_sender` - The role of the party who sent `candidate_mac`.
    /// * `candidate_mac` - 32-byte MAC tag presented by the peer.
    ///
    /// # Errors
    /// Returns [`Spake2Error::ConfirmationMacMismatch`] if the tag does not match expected.
    pub fn verify_peer_confirm_mac(
        &self,
        expected_role_of_sender: Spake2Role,
        candidate_mac: &[u8; 32],
    ) -> Result<(), Spake2Error> {
        let expected = match expected_role_of_sender {
            Spake2Role::InitiatorA => &self.confirm_mac_a,
            Spake2Role::ResponderB => &self.confirm_mac_b,
        };
        if bool::from(expected.ct_eq(candidate_mac)) {
            Ok(())
        } else {
            Err(Spake2Error::ConfirmationMacMismatch)
        }
    }

    /// Derives final application credentials ($K_{\text{root}}$, $K_{\text{ack}}$, $F_{\text{ack}}$, SAS)
    /// exclusively from $K_e$ and both parties' Ed25519 transcript signatures.
    ///
    /// # Derivation Formula
    /// ```text
    /// salt = SHA256("integrator-pair-prk-salt-v2" || tt_sha256 || sig_a || sig_b)
    /// hk = HKDF-Extract(salt, Ke)
    /// K_root = HKDF-Expand(hk, "integrator-v2-root-key", 32)
    /// K_ack  = HKDF-Expand(hk, "integrator-v2-pair-ack", 32)
    /// sas_raw = HKDF-Expand(hk, "integrator-v2-sas", 4)
    /// F_ack = HMAC-SHA256(K_ack, "integrator-pair-complete-v2" || tt_sha256 || confirm_mac_a || sig_a)
    /// ```
    ///
    /// # Arguments
    /// * `sig_a` - Client A's 64-byte Ed25519 signature over `tt_sha256 || F_A`.
    /// * `sig_b` - Server B's 64-byte Ed25519 signature over `tt_sha256 || F_B || sig_A`.
    pub fn derive_application_secrets(
        &self,
        sig_a: &[u8; 64],
        sig_b: &[u8; 64],
    ) -> PairingApplicationSecrets {
        let mut salt_hasher = Sha256::new();
        salt_hasher.update(b"integrator-pair-prk-salt-v2");
        salt_hasher.update(self.tt_sha256);
        salt_hasher.update(sig_a);
        salt_hasher.update(sig_b);
        let salt_digest = salt_hasher.finalize();
        let mut salt = Zeroizing::new([0u8; 32]);
        salt.copy_from_slice(&salt_digest);

        // HKDF-Extract with transcript-bound salt and SPAKE2 shared encryption secret Ke as IKM.
        let hk = Hkdf::<Sha256>::new(Some(&*salt), &*self.k_e);

        let mut root_key = Zeroizing::new([0u8; 32]);
        hk.expand(b"integrator-v2-root-key", &mut *root_key)
            .expect("32-byte HKDF expand cannot fail");

        let mut ack_key = Zeroizing::new([0u8; 32]);
        hk.expand(b"integrator-v2-pair-ack", &mut *ack_key)
            .expect("32-byte HKDF expand cannot fail");

        let mut sas_bytes = Zeroizing::new([0u8; 4]);
        hk.expand(b"integrator-v2-sas", &mut *sas_bytes)
            .expect("4-byte HKDF expand cannot fail");

        let key_id = super::derive_key_id(&root_key);
        let sas_code = super::format_sas_6(&sas_bytes);

        // Assemble 155-byte acknowledgment payload: 27B domain label || 32B tt_sha256 || 32B confirm_mac_a || 64B sig_a.
        let mut ack_input = Zeroizing::new(Vec::with_capacity(27 + 32 + 32 + 64));
        ack_input.extend_from_slice(b"integrator-pair-complete-v2");
        ack_input.extend_from_slice(&self.tt_sha256);
        ack_input.extend_from_slice(&self.confirm_mac_a);
        ack_input.extend_from_slice(sig_a);
        let ack_mac = compute_hmac_sha256(&*ack_key, &ack_input);

        PairingApplicationSecrets {
            root_key,
            key_id,
            ack_key,
            ack_mac,
            sas_code,
        }
    }
}

/// Computes `HMAC-SHA256(key, data)` returning a 32-byte MAC tag.
///
/// # Arguments
/// * `key` - Cryptographic key slice (any length accepted per RFC 2104).
/// * `data` - Input message slice to authenticate.
pub fn compute_hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}
