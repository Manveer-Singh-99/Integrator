use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub const FRAME_DIR: u8 = 0x01;
pub const FRAME_FILE: u8 = 0x02;
pub const FRAME_FILE_DATA: u8 = 0x03;
pub const FRAME_FILE_HASH: u8 = 0x04;
pub const FRAME_IMAGE_DATA: u8 = 0x05;
pub const FRAME_END: u8 = 0xFF;

// Security limits against memory exhaustion & path traversal attacks
pub const MAX_TEXT_CHARS: usize = 10 * 1024 * 1024;               // 10 MiB text
pub const MAX_IMAGE_BYTES: usize = 64 * 1024 * 1024;              // 64 MiB uncompressed RGBA
pub const MAX_IMAGE_DIMENSION: usize = 8_192;                     // Max 8192x8192 px (checked pre-allocation)
pub const MAX_CLIPBOARD_HEADER_BYTES: usize = 16 * 1024 * 1024;   // Max serialized control header (16 MiB)
pub const MAX_TRANSFER_FILES: usize = 1_000;                      // Max 1,000 entries in a single copy
pub const MAX_ROOTS: usize = MAX_TRANSFER_FILES;
pub const MAX_DIRECTORY_DEPTH: usize = 16;                        // Max 16 directory depth levels
pub const MAX_SINGLE_FILE_BYTES: u64 = 16 * 1024 * 1024 * 1024;   // 16 GiB per file
pub const MAX_TOTAL_TRANSFER_BYTES: u64 = 32 * 1024 * 1024 * 1024;// 32 GiB total per copy
pub const MAX_AUTO_STAGE_BYTES: u64 = 128 * 1024 * 1024;          // 128 MiB background auto-stage cap

/// Validates image dimensions & byte length (`width * height * 4 == byte_len <= MAX_IMAGE_BYTES`).
pub(crate) fn validate_image_bounds(
    width: usize,
    height: usize,
    byte_len: usize,
) -> Option<usize> {
    if width == 0
        || height == 0
        || width > MAX_IMAGE_DIMENSION
        || height > MAX_IMAGE_DIMENSION
    {
        return None;
    }
    let expected = width.checked_mul(height)?.checked_mul(4)?;
    if expected == 0 || expected > MAX_IMAGE_BYTES || expected != byte_len {
        return None;
    }
    Some(expected)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LazyAnnouncement {
    pub session_id: String,
    pub root_name: String,
    #[serde(default)]
    pub roots: Vec<String>,
    pub total_files: usize,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StreamRequest {
    pub session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ClipboardPayload {
    Text(String),
    /// Compact inline RGBA image (base64-encoded for backwards compatibility / small icons).
    Image {
        width: usize,
        height: usize,
        #[serde(with = "rgba_base64")]
        rgba: Vec<u8>,
    },
    /// Binary-streamed RGBA image header; `byte_len` raw bytes follow in `FRAME_IMAGE_DATA` chunks.
    ImageStream {
        width: usize,
        height: usize,
        byte_len: usize,
    },
    LazyAnnouncement(LazyAnnouncement),
    // Request by receiver upon Cmd+V / Ctrl+V to open streaming pipe
    RequestStream(StreamRequest),
    // Request by receiver upon Drag-to-Drop release at edge
    RequestDragStream(StreamRequest),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClipboardMessage {
    pub hash: String,
    pub payload: ClipboardPayload,
}

mod rgba_base64 {
    use super::*;
    use serde::de::Error;

    const B64_ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut out = String::with_capacity(((bytes.len() + 2) / 3) * 4);
        for chunk in bytes.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
            let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
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

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let raw = s.as_bytes();
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
                if !is_last || quad[3] != b'=' || (v1 & 0x0F) != 0 {
                    return Err(D::Error::custom("Malformed base64 padding"));
                }
                out.push((v0 << 2) | (v1 >> 4));
            } else if quad[3] == b'=' {
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
