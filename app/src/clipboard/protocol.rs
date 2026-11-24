//! # Universal Clipboard Wire Protocol & Framing Specifications
//!
//! ## 1. Module Purpose & Scope
//! This module defines the wire protocol data models, streaming frame identifiers, resource
//! consumption boundaries, and serialization formats for the Integrator Universal Clipboard.
//!
//! ### Core Subsystem Responsibilities:
//! - **Control Framing**: Serializes clipboard announcements and requests (`ClipboardMessage`)
//!   carrying SHA-256 content hashes, plain text strings, inline RGBA bitmaps, or lazy multi-file
//!   descriptors (`LazyAnnouncement`).
//! - **Zero-RAM Binary Streaming Protocol**: Defines the binary frame markers used when streaming
//!   large multi-gigabyte directory trees or uncompressed high-resolution images across
//!   `TransportSessionV2` without buffering complete files in physical memory:
//!   - `FRAME_DIR (0x01)`: Directory header (creates directory level in isolated staging area).
//!   - `FRAME_FILE (0x02)`: File metadata header (relative path, file size in bytes).
//!   - `FRAME_FILE_DATA (0x03)`: Raw file content chunk (up to 256 KiB per AEAD packet).
//!   - `FRAME_FILE_HASH (0x04)`: Per-file SHA-256 verification digest (32 bytes).
//!   - `FRAME_IMAGE_DATA (0x05)`: Raw RGBA pixel stream chunk.
//!   - `FRAME_END (0xFF)`: Terminal stream marker and session-level digest commit.
//! - **Resource Bounds Enforcement**: Hard caps on text size, image dimensions, directory depth,
//!   and cumulative transfer volume prevent memory exhaustion or disk denial-of-service attacks.
//!
//! ## 2. Architectural Linkages & Dependencies
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────────────────────────────────┐
//! │                          Clipboard Framing & Streaming Wire Flow                       │
//! └────────────────────────────────────────────────────────────────────────────────────────┘
//!
//!   Local Workstation Copy                               Remote Workstation Paste
//!  ┌───────────────────────┐                           ┌───────────────────────────┐
//!  │ User copies files     │                           │ User presses Cmd+V/Ctrl+V │
//!  └───────────┬───────────┘                           └─────────────┬─────────────┘
//!              │                                                     │
//!              ▼                                                     ▼
//!  ┌───────────────────────┐      LazyAnnouncement       ┌───────────────────────────┐
//!  │ LazyAnnouncement      ├────────────────────────────►│ Interceptor triggers     │
//!  │ - session_id (hex)    │    (Metadata announcement)  │ RequestStream(session_id) │
//!  │ - total_bytes, roots  │                             └─────────────┬─────────────┘
//!  └───────────────────────┘                                           │
//!              ▲                                                       │
//!              │           RequestStream(session_id)                   │
//!              └───────────────────────────────────────────────────────┘
//!                                      │
//!                                      ▼
//!  ┌───────────────────────────────────────────────────────────────────────────────┐
//!  │ Binary Streaming Loop over TransportSessionV2 (Port 58283, 256 KiB AEAD)      │
//!  │   [0x01] FRAME_DIR       -> "Projects/App"                                    │
//!  │   [0x02] FRAME_FILE      -> "Projects/App/main.rs" (size: 4096B)              │
//!  │   [0x03] FRAME_FILE_DATA -> Chunk 1..N (256 KiB)                              │
//!  │   [0x04] FRAME_FILE_HASH -> SHA-256 (32B)                                     │
//!  │   [0xFF] FRAME_END       -> End of stream marker                              │
//!  └───────────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ### Upstream Callers:
//! - `src/clipboard/service.rs`: Serializes control messages, decodes frame tags, and checks quotas.
//! - `src/kvm/service.rs`: Uses `LazyAnnouncement` and `StreamRequest` during cross-screen drag staging.
//!
//! ### Downstream Callees:
//! - `serde`: JSON serialization for control frames.
//! - `sha2::Sha256`: Digest verification for transferred content.
//!
//! ## 3. Threading & Concurrency Model
//! All structures are immutable data transfer objects (DTOs) implementing `Send + Sync + Clone`.
//! They can be freely transmitted across asynchronous Tokio channels and tasks.
//!
//! ## 4. Security & Safety Invariants
//! - **Image Allocation Overflow Defense**: `validate_image_bounds` performs checked multiplications
//!   (`width.checked_mul(height)?.checked_mul(4)?`) to eliminate integer overflow before buffer allocations.
//! - **Base64 Canonical Bit Validation**: Custom Base64 deserialization verifies that unused padding
//!   bits are strictly zero, preventing steganographic covert channels or non-canonical malleability.
//! - **Path Length & Depth Caps**: `MAX_DIRECTORY_DEPTH = 16` prevents stack overflow during recursion.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Frame marker byte: Directory creation notification (`0x01`).
pub const FRAME_DIR: u8 = 0x01;

/// Frame marker byte: File header containing relative path and file byte length (`0x02`).
pub const FRAME_FILE: u8 = 0x02;

/// Frame marker byte: Raw file content chunk (`0x03`).
pub const FRAME_FILE_DATA: u8 = 0x03;

/// Frame marker byte: Per-file SHA-256 digest validation frame (`0x04`).
pub const FRAME_FILE_HASH: u8 = 0x04;

/// Frame marker byte: Raw RGBA pixel stream chunk (`0x05`).
pub const FRAME_IMAGE_DATA: u8 = 0x05;

/// Frame marker byte: Terminal end-of-stream delimiter (`0xFF`).
pub const FRAME_END: u8 = 0xFF;

// Security limits against memory exhaustion, recursive tree attacks, and disk exhaustion:

/// Maximum allowed plain text string length in characters (10 MiB).
pub const MAX_TEXT_CHARS: usize = 10 * 1024 * 1024;

/// Maximum allowed uncompressed RGBA image buffer size in bytes (64 MiB).
pub const MAX_IMAGE_BYTES: usize = 64 * 1024 * 1024;

/// Maximum allowed width or height in pixels for clipboard image frames (8,192 px).
pub const MAX_IMAGE_DIMENSION: usize = 8_192;

/// Maximum allowed length in bytes for serialized control message headers (16 MiB).
pub const MAX_CLIPBOARD_HEADER_BYTES: usize = 16 * 1024 * 1024;

/// Maximum count of individual files or folders allowed in a single clipboard transfer (4,096).
pub const MAX_TRANSFER_FILES: usize = 4_096;

/// Maximum count of top-level root items allowed in a multi-file selection (1,000).
pub const MAX_ROOTS: usize = 1_000;

/// Maximum directory nesting depth allowed during recursive tree transfers (16 levels).
pub const MAX_DIRECTORY_DEPTH: usize = 16;

/// Maximum allowable size in bytes for a single file payload (16 GiB).
pub const MAX_SINGLE_FILE_BYTES: u64 = 16 * 1024 * 1024 * 1024;

/// Maximum cumulative transfer size in bytes allowed across an entire clipboard session (32 GiB).
pub const MAX_TOTAL_TRANSFER_BYTES: u64 = 32 * 1024 * 1024 * 1024;

/// Background automatic file pre-staging threshold (128 MiB). Transfers under this threshold
/// pre-stage into cache for instantaneous pasting.
pub const MAX_AUTO_STAGE_BYTES: u64 = 128 * 1024 * 1024;

/// Validates image dimensions and total byte length against strict security invariants.
///
/// Ensures:
/// 1. Dimensions are non-zero and do not exceed `MAX_IMAGE_DIMENSION` (8,192 px).
/// 2. `width * height * 4` does not overflow `usize`.
/// 3. Calculated byte length exactly equals `byte_len` and is within `MAX_IMAGE_BYTES` (64 MiB).
///
/// # Arguments
/// * `width` - Image width in pixels.
/// * `height` - Image height in pixels.
/// * `byte_len` - Declared payload byte length.
///
/// # Returns
/// `Some(expected_bytes)` on successful validation, or `None` if out of bounds.
pub(crate) fn validate_image_bounds(
    width: usize,
    height: usize,
    byte_len: usize,
) -> Option<usize> {
    // Reject zero dimensions or dimensions exceeding the 8,192 px single-axis cap.
    if width == 0
        || height == 0
        || width > MAX_IMAGE_DIMENSION
        || height > MAX_IMAGE_DIMENSION
    {
        return None;
    }
    // Checked multiplication prevents 32-bit/64-bit integer wraparound prior to allocation.
    let expected = width.checked_mul(height)?.checked_mul(4)?;
    if expected == 0 || expected > MAX_IMAGE_BYTES || expected != byte_len {
        return None;
    }
    Some(expected)
}

/// Metadata announcement for lazy file transfers.
///
/// Broadcast when files or folders are copied to the local clipboard. Carries summary
/// statistics without transmitting the actual file contents until requested.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LazyAnnouncement {
    /// 64-bit random hex session identifier generated by the source machine.
    pub session_id: String,

    /// User-visible name of the primary copied root item (e.g. `"Archive.zip"`).
    pub root_name: String,

    /// List of all top-level root item names in a multi-file selection.
    #[serde(default)]
    pub roots: Vec<String>,

    /// Total count of all files and folders included in the transfer.
    pub total_files: usize,

    /// Cumulative uncompressed payload size in bytes across all files.
    pub total_bytes: u64,
}

/// Request sent by the receiving peer to initiate binary streaming for a staged file session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StreamRequest {
    /// Session identifier of the lazy announcement to stream.
    pub session_id: String,
}

/// Enumeration of all discrete clipboard payload types exchanged over the network.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ClipboardPayload {
    /// UTF-8 plain text string payload.
    Text(String),

    /// Compact inline RGBA image with base64 encoding (used for small icons and clipboard previews).
    Image {
        /// Width in pixels.
        width: usize,
        /// Height in pixels.
        height: usize,
        /// Base64-encoded raw RGBA pixel data.
        #[serde(with = "rgba_base64")]
        rgba: Vec<u8>,
    },

    /// Header declaring an upcoming binary RGBA image stream. Raw bytes follow in `FRAME_IMAGE_DATA` chunks.
    ImageStream {
        /// Width in pixels.
        width: usize,
        /// Height in pixels.
        height: usize,
        /// Expected cumulative byte count (`width * height * 4`).
        byte_len: usize,
    },

    /// Lazy announcement advertising available files on the remote clipboard.
    LazyAnnouncement(LazyAnnouncement),

    /// Request emitted when the user presses `Cmd+V` / `Ctrl+V` to pull the announced file stream.
    RequestStream(StreamRequest),

    /// Request emitted when a cross-screen drag session is dropped onto the local workspace.
    RequestDragStream(StreamRequest),
}

/// Envelope wrapping a clipboard payload alongside its cryptographic content hash.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClipboardMessage {
    /// SHA-256 hexadecimal digest of the payload content for deduplication and integrity checking.
    pub hash: String,

    /// Typed clipboard content payload.
    pub payload: ClipboardPayload,
}

/// Custom high-performance Base64 serialization module with strict canonical padding validation.
///
/// Standard relaxed Base64 decoders often ignore non-zero trailing bits in padded quartets
/// (`==` or `=`), enabling representation malleability. This codec strictly enforces RFC 4648 §3.5
/// canonical zero-padding invariants and pre-allocation quota checks against `MAX_IMAGE_BYTES`.
mod rgba_base64 {
    use super::*;
    use serde::de::Error;

    /// Standard RFC 4648 Base64 64-character lookup table.
    const B64_ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /// Serializes raw byte slices into standard Base64 ASCII strings.
    ///
    /// Packs every 3-byte input triplet into a 24-bit integer (`triple`) and emits 4 6-bit
    /// ASCII characters, appending `=` padding characters when the final chunk has 1 or 2 bytes.
    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Pre-allocate exact output length: ceil(len / 3) * 4 characters.
        let mut out = String::with_capacity(((bytes.len() + 2) / 3) * 4);
        for chunk in bytes.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
            let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
            // Combine 3 octets into a 24-bit big-endian register for 6-bit sextet extraction.
            let triple = (b0 << 16) | (b1 << 8) | b2;
            out.push(B64_ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
            out.push(B64_ALPHABET[((triple >> 12) & 0x3F) as usize] as char);
            out.push(if chunk.len() > 1 {
                B64_ALPHABET[((triple >> 6) & 0x3F) as usize] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                B64_ALPHABET[(triple & 0x3F) as usize] as char
            } else {
                '='
            });
        }
        serializer.serialize_str(&out)
    }

    /// Decodes an individual Base64 ASCII character to its 6-bit value (`0..=63`),
    /// returning `None` for padding (`=`), whitespace, or out-of-alphabet bytes.
    fn decode_char(b: u8) -> Option<u8> {
        match b {
            b'A'..=b'Z' => Some(b - b'A'),
            b'a'..=b'z' => Some(b - b'a' + 26),
            b'0'..=b'9' => Some(b - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }

    /// Deserializes a Base64 string into raw bytes, enforcing canonical padding bit verification
    /// and pre-allocation `MAX_IMAGE_BYTES` bounds checking.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let raw = s.as_bytes();
        // Valid Base64 strings must always be a multiple of 4 ASCII characters.
        if raw.len() % 4 != 0 {
            return Err(D::Error::custom("Invalid base64 image length"));
        }
        if raw.is_empty() {
            return Ok(Vec::new());
        }
        let padding = if raw.ends_with(b"==") {
            2
        } else if raw.ends_with(b"=") {
            1
        } else {
            0
        };
        // Reject oversized payloads before allocating the output vector.
        let estimated = (raw.len() / 4) * 3 - padding;
        if estimated > MAX_IMAGE_BYTES {
            return Err(D::Error::custom("Image base64 payload exceeds MAX_IMAGE_BYTES"));
        }
        let mut out = Vec::with_capacity(estimated);
        let chunks = raw.chunks_exact(4);
        let total_chunks = chunks.len();
        for (idx, quad) in chunks.enumerate() {
            let is_last = idx + 1 == total_chunks;
            let v0 = decode_char(quad[0])
                .ok_or_else(|| D::Error::custom("Invalid base64 character"))?;
            let v1 = decode_char(quad[1])
                .ok_or_else(|| D::Error::custom("Invalid base64 character"))?;

            if quad[2] == b'=' {
                // Double padding `==` is only legal in the final quartet, requires `quad[3] == '='`,
                // and requires the low 4 bits of `v1` to be zero (RFC 4648 canonical encoding).
                if !is_last || quad[3] != b'=' || (v1 & 0x0F) != 0 {
                    return Err(D::Error::custom("Malformed base64 padding"));
                }
                out.push((v0 << 2) | (v1 >> 4));
            } else if quad[3] == b'=' {
                // Single padding `=` is only legal in the final quartet and requires the low 2 bits
                // of `v2` to be zero.
                if !is_last {
                    return Err(D::Error::custom("Malformed base64 padding"));
                }
                let v2 = decode_char(quad[2])
                    .ok_or_else(|| D::Error::custom("Invalid base64 character"))?;
                if (v2 & 0x03) != 0 {
                    return Err(D::Error::custom("Non-canonical base64 padding bits"));
                }
                out.push((v0 << 2) | (v1 >> 4));
                out.push((v1 << 4) | (v2 >> 2));
            } else {
                // Unpadded quartet: decode all 4 sextets into 3 output bytes.
                let v2 = decode_char(quad[2])
                    .ok_or_else(|| D::Error::custom("Invalid base64 character"))?;
                let v3 = decode_char(quad[3])
                    .ok_or_else(|| D::Error::custom("Invalid base64 character"))?;
                out.push((v0 << 2) | (v1 >> 4));
                out.push((v1 << 4) | (v2 >> 2));
                out.push((v2 << 6) | v3);
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lazy_announcement_deserializes_without_roots_and_with_roots() {
        let legacy_json = r#"{"session_id":"abc","root_name":"foo.txt","total_files":1,"total_bytes":42}"#;
        let parsed: LazyAnnouncement = serde_json::from_str(legacy_json).expect("legacy ann");
        assert!(parsed.roots.is_empty());

        let modern = LazyAnnouncement {
            session_id: "0123456789abcdef".to_string(),
            root_name: "a.txt".to_string(),
            roots: vec!["a.txt".to_string(), "b.txt".to_string()],
            total_files: 2,
            total_bytes: 100,
        };
        let enc = serde_json::to_string(&modern).expect("encode modern");
        let dec: LazyAnnouncement = serde_json::from_str(&enc).expect("decode modern");
        assert_eq!(dec, modern);
    }

    #[test]
    fn clipboard_message_image_base64_and_image_stream_round_trip() {
        const _: () = assert!(MAX_CLIPBOARD_HEADER_BYTES <= 16 * 1024 * 1024);

        let rgba = vec![10, 20, 30, 255, 40, 50, 60, 128];
        let msg = ClipboardMessage {
            hash: "h".to_string(),
            payload: ClipboardPayload::Image {
                width: 2,
                height: 1,
                rgba: rgba.clone(),
            },
        };
        let json = serde_json::to_string(&msg).expect("encode inline image");
        assert!(json.contains("\"rgba\":\"ChQe/ygyPIA=\""));
        let decoded: ClipboardMessage = serde_json::from_str(&json).expect("decode inline image");
        assert_eq!(decoded, msg);

        let stream_msg = ClipboardMessage {
            hash: "hs".to_string(),
            payload: ClipboardPayload::ImageStream {
                width: 1920,
                height: 1080,
                byte_len: 1920 * 1080 * 4,
            },
        };
        let sjson = serde_json::to_string(&stream_msg).expect("encode image stream");
        let sdec: ClipboardMessage = serde_json::from_str(&sjson).expect("decode image stream");
        assert_eq!(sdec, stream_msg);
    }
}
