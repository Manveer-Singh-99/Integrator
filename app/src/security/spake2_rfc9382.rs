//! Strict RFC 9382 SPAKE2 Implementation (`SPAKE2-edwards25519-SHA512-HKDF-SHA256-HMAC-SHA256`).
//!
//! Why this module exists instead of using `spake2 0.4.0`:
//! - `spake2 0.4.0` implements pre-RFC `draft-ladd-spake2-01` (`python-spake2` from 2017) with
//!   non-RFC `M`/`N` constants, omits cofactor multiplication (`h = 8`) when computing `K`,
//!   does not reject small-subgroup/identity points, and uses a fixed 192-byte SHA-256 hash
//!   instead of RFC 9382's 8-byte little-endian length-prefixed transcript `TT` and `Ke || Ka`
//!   confirmation key schedule.
//! - This module implements verbatim RFC 9382 Section 3 & Section 4 over `curve25519-dalek` v4:
//!   1. Distinguished constants `M` and `N` from RFC 9382 §4 (`edwards25519`).
//!   2. Wide 512-bit HKDF-SHA256 reduction modulo the prime subgroup order `l` for password scalar `w`.
//!   3. Canonical compressed Edwards point decoding and small-order torsion rejection (`!is_small_order()`).
//!   4. Mandatory cofactor clearing (`mul_by_cofactor()`, `h = 8`) for `K = h * x * (pB - w*N)` and
//!      `K = h * y * (pA - w*M)`, plus explicit identity-element abort (`K.is_identity()`).
//!   5. Canonical 8-byte little-endian length-prefixed transcript:
//!      `TT = len(A) || A || len(B) || B || len(pA) || pA || len(pB) || pB || len(K) || K || len(w) || w`.
//!   6. Strict separation between raw group element `K`, SPAKE2 shared secret `Ke`, confirmation
//!      master key `Ka`, directional confirmation MAC keys `KcA` / `KcB`, and application root key `K_root`.

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

type HmacSha256 = Hmac<Sha256>;

/// RFC 9382 Section 4 `edwards25519` constant `M` (compressed Edwards Y, 32 bytes):
/// `d048032c6ea0b6d697ddc2e86bda85a33adac920f1bf18e1b0c6d166a5cecdaf`
pub const RFC9382_ED25519_M_BYTES: [u8; 32] = [
    0xd0, 0x48, 0x03, 0x2c, 0x6e, 0xa0, 0xb6, 0xd6, 0x97, 0xdd, 0xc2, 0xe8, 0x6b, 0xda, 0x85, 0xa3,
    0x3a, 0xda, 0xc9, 0x20, 0xf1, 0xbf, 0x18, 0xe1, 0xb0, 0xc6, 0xd1, 0x66, 0xa5, 0xce, 0xcd, 0xaf,
];

/// RFC 9382 Section 4 `edwards25519` constant `N` (compressed Edwards Y, 32 bytes):
/// `d3bfb518f44f3430f29d0c92af503865a1ed3281dc69b35dd868ba85f886c4ab`
pub const RFC9382_ED25519_N_BYTES: [u8; 32] = [
    0xd3, 0xbf, 0xb5, 0x18, 0xf4, 0x4f, 0x34, 0x30, 0xf2, 0x9d, 0x0c, 0x92, 0xaf, 0x50, 0x38, 0x65,
    0xa1, 0xed, 0x32, 0x81, 0xdc, 0x69, 0xb3, 0x5d, 0xd8, 0x68, 0xba, 0x85, 0xf8, 0x86, 0xc4, 0xab,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Spake2Error {
    EmptyPassword,
    NonCanonicalPeerShare,
    SmallOrderPeerShare,
    IdentitySharedElement,
    ConfirmationMacMismatch,
    InvalidSignature,
}

impl std::fmt::Display for Spake2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Spake2Error::EmptyPassword => write!(f, "SPAKE2 password/PIN must not be empty"),
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
            Spake2Error::InvalidSignature => {
                write!(f, "SPAKE2 peer Ed25519 identity signature verification failed")
            }
        }
    }
}

impl std::error::Error for Spake2Error {}

/// Decompresses RFC 9382 constant `M`.
pub fn const_m() -> EdwardsPoint {
    CompressedEdwardsY(RFC9382_ED25519_M_BYTES)
        .decompress()
        .expect("RFC 9382 edwards25519 constant M is a valid curve point")
}

/// Decompresses RFC 9382 constant `N`.
pub fn const_n() -> EdwardsPoint {
    CompressedEdwardsY(RFC9382_ED25519_N_BYTES)
        .decompress()
        .expect("RFC 9382 edwards25519 constant N is a valid curve point")
}

/// Derives the password scalar `w` in `[1, l - 1]` using 512-bit HKDF-SHA256 expansion
/// and constant-time wide modular reduction per RFC 9382 §3.1.
pub fn derive_password_scalar(password: &[u8], salt_pw: &[u8]) -> Result<Scalar, Spake2Error> {
    if password.is_empty() {
        return Err(Spake2Error::EmptyPassword);
    }
    let hk = Hkdf::<Sha256>::new(Some(salt_pw), password);
    let mut okm = Zeroizing::new([0u8; 64]);
    hk.expand(b"RFC9382-edwards25519-w", &mut *okm)
        .expect("64-byte HKDF-SHA256 expand cannot fail");

    let mut w = Scalar::from_bytes_mod_order_wide(&okm);
    // RFC 9382 §3.1: w must be non-zero mod l.
    if bool::from(w.ct_eq(&Scalar::ZERO)) {
        w = Scalar::ONE;
    }
    Ok(w)
}

/// Computes the domain-separated password salt for a pairing session between `client_device_id` and `server_device_id`.
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

/// Validates and decompresses a 32-byte peer share (`pA` or `pB`).
/// Rejects non-canonical encodings and small-order torsion points.
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
fn append_rfc9382_lv(buf: &mut Vec<u8>, data: &[u8]) {
    let len_le = (data.len() as u64).to_le_bytes();
    buf.extend_from_slice(&len_le);
    buf.extend_from_slice(data);
}

/// Constructs the exact RFC 9382 §3.3 canonical transcript:
/// `TT = len(A) || A || len(B) || B || len(pA) || pA || len(pB) || pB || len(K) || K || len(w) || w`
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Spake2Role {
    InitiatorA,
    ResponderB,
}

/// Ephemeral single-use SPAKE2 state for either Initiator (`A`) or Responder (`B`).
pub struct Spake2State {
    role: Spake2Role,
    xy_scalar: Scalar,
    w_scalar: Scalar,
    id_a: Vec<u8>,
    id_b: Vec<u8>,
    my_share: [u8; 32],
}

impl Drop for Spake2State {
    fn drop(&mut self) {
        self.xy_scalar.zeroize();
        self.w_scalar.zeroize();
    }
}

/// Output of `Spake2State::finish`, strictly separating `Ke`, `Ka`, `KcA`, `KcB`, and `TT_sha256`.
#[derive(Debug, PartialEq, Eq)]
pub struct Spake2TranscriptOutput {
    /// `Ke` (32 bytes): SPAKE2 shared secret (`SHA512(TT)[0..32]`), used ONLY to derive application root keys.
    pub k_e: Zeroizing<[u8; 32]>,
    /// `Ka` (32 bytes): Confirmation master key (`SHA512(TT)[32..64]`), used ONLY to derive `KcA` and `KcB`.
    pub k_a: Zeroizing<[u8; 32]>,
    /// `KcA` (32 bytes): Client (`A`) confirmation MAC key.
    pub k_confirm_a: Zeroizing<[u8; 32]>,
    /// `KcB` (32 bytes): Server (`B`) confirmation MAC key.
    pub k_confirm_b: Zeroizing<[u8; 32]>,
    /// `F_A = HMAC-SHA256(KcA, TT)` (32 bytes).
    pub confirm_mac_a: [u8; 32],
    /// `F_B = HMAC-SHA256(KcB, TT)` (32 bytes).
    pub confirm_mac_b: [u8; 32],
    /// `SHA256(TT)` (32 bytes) for binding Ed25519 identity signatures without exposing raw `w` in `TT`.
    pub tt_sha256: [u8; 32],
}

/// Final application secrets derived from `Ke` after mutual confirmation and signature checks succeed.
#[derive(Debug, PartialEq, Eq)]
pub struct PairingApplicationSecrets {
    /// Long-term 256-bit per-peer root key (`K_root`).
    pub root_key: Zeroizing<[u8; 32]>,
    /// 128-bit key identifier `SHA256("integrator-key-id-v2" || K_root)[0..16]`.
    pub key_id: [u8; 16],
    /// 256-bit key for authenticating the final `PairServerComplete` acknowledgment tag (`F_ack`).
    pub ack_key: Zeroizing<[u8; 32]>,
    /// `F_ack = HMAC-SHA256(K_ack, "integrator-pair-complete-v2" || tt_sha256 || F_A || sig_A)`.
    pub ack_mac: [u8; 32],
    /// Human-readable 6-character Short Authentication String (`XXX-XXX`).
    pub sas_code: String,
}

impl Spake2State {
    /// Starts SPAKE2 as Initiator (`A`) using OS CSPRNG entropy.
    pub fn start_a(
        password: &[u8],
        salt_pw: &[u8],
        id_a: &[u8],
        id_b: &[u8],
    ) -> Result<(Self, [u8; 32]), Spake2Error> {
        let mut scalar_wide = Zeroizing::new([0u8; 64]);
        super::csprng_fill(&mut *scalar_wide);
        let mut x = Scalar::from_bytes_mod_order_wide(&scalar_wide);
        if bool::from(x.ct_eq(&Scalar::ZERO)) {
            x = Scalar::ONE;
        }
        Self::start_with_scalar(Spake2Role::InitiatorA, password, salt_pw, id_a, id_b, x)
    }

    /// Starts SPAKE2 as Responder (`B`) using OS CSPRNG entropy.
    pub fn start_b(
        password: &[u8],
        salt_pw: &[u8],
        id_a: &[u8],
        id_b: &[u8],
    ) -> Result<(Self, [u8; 32]), Spake2Error> {
        let mut scalar_wide = Zeroizing::new([0u8; 64]);
        super::csprng_fill(&mut *scalar_wide);
        let mut y = Scalar::from_bytes_mod_order_wide(&scalar_wide);
        if bool::from(y.ct_eq(&Scalar::ZERO)) {
            y = Scalar::ONE;
        }
        Self::start_with_scalar(Spake2Role::ResponderB, password, salt_pw, id_a, id_b, y)
    }

    /// Deterministic constructor for RFC 9382 test vectors.
    pub fn start_with_scalar(
        role: Spake2Role,
        password: &[u8],
        salt_pw: &[u8],
        id_a: &[u8],
        id_b: &[u8],
        mut xy_scalar: Scalar,
    ) -> Result<(Self, [u8; 32]), Spake2Error> {
        if bool::from(xy_scalar.ct_eq(&Scalar::ZERO)) {
            xy_scalar = Scalar::ONE;
        }
        let w_scalar = derive_password_scalar(password, salt_pw)?;
        let blinding_point = match role {
            Spake2Role::InitiatorA => const_m(),
            Spake2Role::ResponderB => const_n(),
        };

        // pA = x*B + w*M  or  pB = y*B + w*N
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

    /// Completes the SPAKE2 exchange given the peer's 32-byte share (`pB` or `pA`) and optional wire header AAD.
    pub fn finish(
        self,
        peer_share_bytes: &[u8; 32],
        aad: &[u8],
    ) -> Result<Spake2TranscriptOutput, Spake2Error> {
        let peer_point = decode_valid_peer_share(peer_share_bytes)?;

        let (unblind_point, p_a, p_b) = match self.role {
            Spake2Role::InitiatorA => (const_n(), self.my_share, *peer_share_bytes),
            Spake2Role::ResponderB => (const_m(), *peer_share_bytes, self.my_share),
        };

        // Unblind: (p_peer - w * N) or (p_peer - w * M)
        let unblinded = peer_point - (unblind_point * self.w_scalar);

        // RFC 9382 §3.2 & §4: Multiply by cofactor h = 8 and by ephemeral scalar x or y:
        // K = h * x * (pB - w*N) = h * y * (pA - w*M)
        let k_point = unblinded.mul_by_cofactor() * self.xy_scalar;

        // Mandatory abort if K is the identity element O.
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
    /// Verifies the peer's confirmation MAC (`F_A` or `F_B`) in constant time.
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

    /// Derives the final application root key (`K_root`), completion ack key (`K_ack`),
    /// `F_ack`, and 6-char SAS code exclusively from `Ke` and the signed transcript context.
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
        let salt = salt_hasher.finalize();

        let hk = Hkdf::<Sha256>::new(Some(&salt), &*self.k_e);

        let mut root_key = Zeroizing::new([0u8; 32]);
        hk.expand(b"integrator-v2-root-key", &mut *root_key)
            .expect("32-byte HKDF expand cannot fail");

        let mut ack_key = Zeroizing::new([0u8; 32]);
        hk.expand(b"integrator-v2-pair-ack", &mut *ack_key)
            .expect("32-byte HKDF expand cannot fail");

        let mut sas_bytes = [0u8; 4];
        hk.expand(b"integrator-v2-sas", &mut sas_bytes)
            .expect("4-byte HKDF expand cannot fail");

        let key_id = super::derive_key_id(&root_key);
        let sas_code = super::format_sas_6(&sas_bytes);

        let mut ack_input = Vec::with_capacity(32 + 32 + 32 + 64);
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

pub fn compute_hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}
