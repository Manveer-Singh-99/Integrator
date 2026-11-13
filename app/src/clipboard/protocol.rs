use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    /// Relative path with forward slashes (e.g. "Photos/vacation/sunset.jpg" or "Photos" or "document.pdf")
    pub rel_path: String,
    pub size: u64,
    pub is_dir: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClipboardPayload {
    Text(String),
    Image {
        width: usize,
        height: usize,
        rgba: Vec<u8>,
    },
    Files {
        /// Names of the top-level items copied (e.g. ["Photos", "notes.txt"])
        root_names: Vec<String>,
        /// Flattened list of all directories and files to extract
        entries: Vec<FileEntry>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClipboardMessage {
    pub hash: String,
    pub payload: ClipboardPayload,
}
