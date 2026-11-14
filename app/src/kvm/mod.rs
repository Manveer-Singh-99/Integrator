pub mod layout;
#[cfg(target_os = "macos")]
pub mod macos_backend;
pub mod protocol;
pub mod service;
#[cfg(target_os = "windows")]
pub mod windows_backend;

pub use protocol::{KvmLayoutConfig, ScreenEdge};
pub use service::{KvmService, KvmStatusSnapshot};
