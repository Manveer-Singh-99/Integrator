use serde::{Deserialize, Serialize};

pub const FRAME_DIR: u8 = 0x01;
pub const FRAME_FILE: u8 = 0x02;
pub const FRAME_FILE_DATA: u8 = 0x03;
pub const FRAME_FILE_HASH: u8 = 0x04;
pub const FRAME_END: u8 = 0xFF;

// Maximum safe in-memory and transfer limits (Integrator v2.0 Security Specification Section 8)
pub const MAX_TEXT_CHARS: usize = 10 * 1024 * 1024;               // 10 MiB text
pub const MAX_IMAGE_BYTES: usize = 64 * 1024 * 1024;              // 64 MiB uncompressed RGBA
pub const MAX_IMAGE_DIMENSION: usize = 8_192;                     // Max 8192x8192 px (checked pre-allocation)
pub const MAX_CLIPBOARD_HEADER_BYTES: usize = 256 * 1024 * 1024;  // Max serialized message size
pub const MAX_TRANSFER_FILES: usize = 1_000;                      // Max 1,000 files in a single copy
pub const MAX_DIRECTORY_DEPTH: usize = 16;                        // Max 16 directory depth levels
pub const MAX_SINGLE_FILE_BYTES: u64 = 16 * 1024 * 1024 * 1024;   // 16 GiB per file
pub const MAX_TOTAL_TRANSFER_BYTES: u64 = 32 * 1024 * 1024 * 1024;// 32 GiB total per copy
pub const MAX_AUTO_STAGE_BYTES: u64 = 128 * 1024 * 1024;          // 128 MiB background auto-stage cap

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LazyAnnouncement {
    pub session_id: String,
    pub root_name: String,
    pub total_files: usize,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamRequest {
    pub session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClipboardPayload {
    Text(String),
    Image {
        width: usize,
        height: usize,
        rgba: Vec<u8>,
    },
    /// Universal Control-style Lazy Announcement sent on copy (<1ms, <1KB).
    /// Large transfers (>128 MiB) are pulled only when the user triggers paste.
    LazyAnnouncement(LazyAnnouncement),
    /// On-demand streaming request sent when user triggers paste or bounded staging.
    RequestStream(StreamRequest),
    /// On-demand streaming request for an active Cross-Screen Drag & Drop session.
    RequestDragStream(StreamRequest),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClipboardMessage {
    pub hash: String,
    pub payload: ClipboardPayload,
}
