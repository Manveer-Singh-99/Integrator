//! # Universal Clipboard Subsystem Module
//!
//! ## 1. Module Purpose & Scope
//! The `clipboard` module implements the secure, bi-directional, cross-platform clipboard
//! synchronization subsystem for Integrator. It bridges the native clipboard environments of
//! macOS (`NSPasteboard`) and Windows 10/11 (`Win32 Clipboard` / `CF_HDROP`).
//!
//! ### Core Subsystem Responsibilities:
//! - **Rich Multi-Format Support**:
//!   - **Plain Text**: Synchronizes UTF-8 strings up to 10 MiB with fast SHA-256 deduplication.
//!   - **Bitmaps & Images**: Ingests raw RGBA uncompressed frames (inline base64 for icons,
//!     streamed binary chunks for high-resolution images up to 64 MiB / 8192x8192 px).
//!   - **Files & Directory Hierarchies**: Synchronizes file and folder trees up to 32 GiB total
//!     using a zero-RAM streaming pipe over encrypted TCP.
//! - **Lazy File Announcements & On-Demand Transfer**:
//!   - Copying 10 GB of files does *not* transmit 10 GB across the network immediately. Instead,
//!     a lightweight `LazyAnnouncement` is published. The actual file streaming commences only
//!     when the receiving user triggers Paste (`Cmd+V` / `Ctrl+V`) or drops an edge-dragged item.
//! - **Integrity & Security Invariants**:
//!   - Every transferred file is staged in an isolated, private directory (`0o700` mode on Unix)
//!     and verified against both per-file SHA-256 hashes and cumulative session digests.
//!   - Defends against path traversal attacks (blocking `..`, absolute paths, drive-letter prefixes,
//!     and symlink creation).
//!
//! ## 2. Architectural Linkages & Dependencies
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────────────────────────────────┐
//! │                             Clipboard Subsystem Architecture                           │
//! └────────────────────────────────────────────────────────────────────────────────────────┘
//!
//!              ┌─────────────────────────────────────────────────────────┐
//!              │                 Integrator Core Engine                  │
//!              │             (src/core.rs / src/main.rs)                 │
//!              └────────────────────────────┬────────────────────────────┘
//!                                           │ Instantiates & Supervises
//!                                           ▼
//!              ┌─────────────────────────────────────────────────────────┐
//!              │         ClipboardService (src/clipboard/service.rs)     │
//!              │  - Sequence Poller (os_seq.rs)                          │
//!              │  - Format Negotiator (Text, Image, LazyAnnouncement)   │
//!              │  - Chunked Staging & Atomic Commit Manager             │
//!              └───────┬─────────────────┬───────────────────┬───────────┘
//!                      │                 │                   │
//!     Native File I/O  │   Wire Protocol │                   │ Hardware HUD
//!                      ▼                 ▼                   ▼
//!       ┌─────────────────────┐   ┌─────────────────┐   ┌──────────────────────┐
//!       │   file_helper.rs    │   │  protocol.rs    │   │  touchbar_hud.swift  │
//!       │ - macOS: NSPasteboard   │ - Wire Enums    │   │ - Paste Progress Bar │
//!       │ - Win32: CF_HDROP   │   │ - Frame Framing │   │ - File Name Preview  │
//!       └─────────────────────┘   └────────┬────────┘   └──────────────────────┘
//!                                          │
//!                                          ▼
//!                         ┌─────────────────────────────────┐
//!                         │       TransportSessionV2        │
//!                         │   (ServiceId::ClipboardSync)    │
//!                         │   ChaCha20-Poly1305 over TCP    │
//!                         │   Port CLIPBOARD_PORT (58285)   │
//!                         └─────────────────────────────────┘
//! ```
//!
//! ### Upstream Callers:
//! - `src/core.rs`: Instantiates `ClipboardService::new`, stores global references in
//!   `CLIPBOARD_INSTANCE`, initializes the background sequence watcher, and triggers shutdown.
//! - C FFI / Shortcut Interceptors: `trigger_rust_remote_paste()` called from macOS Event Taps
//!   or Windows hook filters upon detecting `Cmd+V` / `Ctrl+V` while remote files are pending.
//! - KVM Engine (`src/kvm/service.rs`): Uses `ClipboardService` staging helpers to prepare files
//!   for cross-screen drag-and-drop operations.
//!
//! ### Downstream Callees:
//! - `protocol`: Wire framing definitions (`FRAME_DIR`, `FRAME_FILE`, `FRAME_FILE_DATA`, `FRAME_FILE_HASH`, `FRAME_END`).
//! - `os_seq`: Fast OS-level clipboard change sequence probe (`changeCount` on macOS, `GetClipboardSequenceNumber` on Windows).
//! - `file_helper`: Native OS clipboard file list ingestion and serialization (`NSPasteboard` / `CF_HDROP`).
//! - `arboard`: Cross-platform text and image clipboard access.
//! - `crate::security::transport::TransportSessionV2`: Encrypted bi-directional framing over port 58285.
//!
//! ## 3. Threading & Concurrency Model
//! - **Tokio Multi-Threaded Runtime**: Manages connection establishment, inbound packet deserialization,
//!   background polling loops, and async streaming tasks.
//! - **Sequence Watcher Task**: Polls the lightweight OS sequence counter every 250 milliseconds.
//!   Heavy clipboard inspection occurs only when the monotonic counter increments.
//! - **Concurrency Boundaries**: Outbound streaming tasks run with independent cancellation tokens
//!   and timeout safeguards (`FRAME_IO_TIMEOUT = 15s`).
//!
//! ## 4. Security & Safety Invariants
//! - **Strict Quotas**: Enforces hard caps: 10 MiB text, 64 MiB images, 16 GiB single-file limit,
//!   and 32 GiB cumulative transfer limit.
//! - **Zero Foreign Symlinks**: Symlinks are strictly forbidden on incoming transfers to prevent
//!   arbitrary file overwrites or sensitive credential leakage.
//! - **Isolated Staging**: Transferred files land in private temporary staging directories before
//!   atomic promotion to the local clipboard cache.

pub(crate) mod file_helper;
pub(crate) mod os_seq;
pub(crate) mod protocol;
pub(crate) mod service;

pub use service::{ClipboardService, CLIPBOARD_INSTANCE, TOKIO_HANDLE};
