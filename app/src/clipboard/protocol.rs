use serde::{Deserialize, Serialize};

pub const FRAME_DIR: u8 = 0x01;
pub const FRAME_FILE: u8 = 0x02;
pub const FRAME_END: u8 = 0xFF;

// Maximum safe in-memory limits for Text and Image
pub const MAX_TEXT_CHARS: usize = 50 * 1024 * 1024;        // 50 MB
pub const MAX_IMAGE_BYTES: usize = 100 * 1024 * 1024;      // 100 MB uncompressed RGBA

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
    /// No file data is transferred until requested.
    LazyAnnouncement(LazyAnnouncement),
    /// On-demand streaming request sent when user triggers paste.
    RequestStream(StreamRequest),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClipboardMessage {
    pub hash: String,
    pub payload: ClipboardPayload,
}
