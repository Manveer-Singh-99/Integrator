//! # Universal Input KVM & Drag-Drop Wire Protocol
//!
//! ## 1. Module Purpose & Scope
//! This module defines the canonical, platform-agnostic wire protocol and cross-platform input
//! event representations for the Integrator Universal Input KVM and Cross-Screen Drag-and-Drop
//! subsystem.
//!
//! Operating over a mutually authenticated `TransportSessionV2` channel (`ServiceId::InputKvm` on
//! TCP port 58286), these protocol structures encapsulate mouse pointer movement deltas, button
//! states, high-precision trackpad/scroll wheel deltas, logical key events with normalized modifier
//! states, display geometry advertisements, desk arrangement topology synchronizations, and
//! drag-and-drop session handoffs.
//!
//! ## 2. Architectural Linkages & Dependencies
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────────────────────────────────┐
//! │                          KVM Protocol Serialization & Routing                          │
//! └────────────────────────────────────────────────────────────────────────────────────────┘
//!
//!      macOS Native Backend                             Windows Native Backend
//!  (CGEventTap / IOKit HID)                         (LowLevelHooks / SendInput)
//!             │                                                  │
//!             ▼                                                  ▼
//!  macos_backend::on_cg_event                       windows_backend::on_win_event
//!             │                                                  │
//!             └────────────────────────┬─────────────────────────┘
//!                                      │ Maps native events to
//!                                      ▼
//!                         ┌───────────────────────────┐
//!                         │     KvmWireMessage        │
//!                         │  - MouseMoveDelta(dx, dy) │
//!                         │  - MouseButton(btn, down) │
//!                         │  - MouseScroll(dx, dy)    │
//!                         │  - KeyEvent(key, down, mod│
//!                         │  - EnterScreen / Leave    │
//!                         │  - DragOffer / DragResult │
//!                         └────────────┬──────────────┘
//!                                      │ Bincode / JSON Serialization
//!                                      ▼
//!                         ┌───────────────────────────┐
//!                         │    TransportSessionV2     │
//!                         │  (ServiceId::InputKvm)    │
//!                         │  ChaCha20-Poly1305 AEAD   │
//!                         └────────────┬──────────────┘
//!                                      │ TCP Port 58286
//!                                      ▼
//!                           Remote Peer Workstation
//! ```
//!
//! ### Upstream Callers:
//! - `src/kvm/service.rs`: Serializes outbound messages to `mpsc::Sender<KvmOutboundCmd>` and
//!   deserializes incoming wire frames read from `TransportReaderV2`.
//! - `src/kvm/macos_backend.rs`: Converts macOS `CGKeyCode` and Quartz flags to `LogicalKey` and `ModifierMask`.
//! - `src/kvm/windows_backend.rs`: Converts Win32 Virtual-Key codes (`VK_*`) to `LogicalKey` and `ModifierMask`.
//! - `src/kvm/layout.rs`: References `ScreenEdge` and `KvmLayoutConfig` for desk layout calculations.
//!
//! ### Downstream Callees:
//! - `serde`: High-performance JSON/binary serialization and deserialization.
//! - Network transport: Transferred through encrypted frames over `TransportWriterV2` / `TransportReaderV2`.
//!
//! ## 3. Threading & Concurrency Model
//! All structures in this module are purely functional data transfer objects (DTOs). They implement
//! `Send + Sync + Clone`, are free of internal mutable state or locks, and can be freely moved
//! across thread boundaries and asynchronous tasks.
//!
//! ## 4. Security & Safety Invariants
//! - **Bounded Message Size**: Wire messages are enforced to reside within `MAX_WIRE_MESSAGE_BYTES` (96 KiB)
//!   by the transport layer, preventing memory exhaustion attacks.
//! - **Sanitized Numerical Ranges**: Relative deltas (`dx`, `dy`) and normalized coordinates (`norm_pos`)
//!   are clamped to finite, safe ranges to eliminate `NaN` / infinite floating-point propagation.
//! - **Safe String Parsing**: String conversions (`ScreenEdge::from_str_lossy`) employ case-insensitive,
//!   trimmed matching with safe fallback defaults.

use serde::{Deserialize, Serialize};

/// Represents one of the four cardinal physical edges of a display monitor.
///
/// Used to designate the relative placement of the remote workstation relative
/// to the local display (e.g., peer is situated to the "Right" of the Mac),
/// as well as the exit and entry edges during boundary-crossing transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScreenEdge {
    /// The left boundary edge of the display screen.
    Left,
    /// The right boundary edge of the display screen.
    Right,
    /// The top boundary edge of the display screen (e.g., menu bar edge).
    Top,
    /// The bottom boundary edge of the display screen (e.g., Dock / taskbar edge).
    Bottom,
}

impl ScreenEdge {
    /// Returns the geometrically opposing screen edge.
    ///
    /// For instance, when a cursor departs via the local `Right` edge, it must enter the
    /// remote workstation's display across its `Left` edge.
    ///
    /// # Returns
    /// - `ScreenEdge::Left` ↔ `ScreenEdge::Right`
    /// - `ScreenEdge::Top` ↔ `ScreenEdge::Bottom`
    pub fn opposite(self) -> Self {
        match self {
            ScreenEdge::Left => ScreenEdge::Right,
            ScreenEdge::Right => ScreenEdge::Left,
            ScreenEdge::Top => ScreenEdge::Bottom,
            ScreenEdge::Bottom => ScreenEdge::Top,
        }
    }

    /// Returns a human-readable title-cased label for display in UI logs and settings panels.
    pub fn label(self) -> &'static str {
        match self {
            ScreenEdge::Left => "Left",
            ScreenEdge::Right => "Right",
            ScreenEdge::Top => "Top",
            ScreenEdge::Bottom => "Bottom",
        }
    }

    /// Parses a string into a `ScreenEdge` variant in a case-insensitive, whitespace-tolerant manner.
    ///
    /// Recognizes colloquial directional synonyms:
    /// - `"left"` -> `Some(ScreenEdge::Left)`
    /// - `"right"` -> `Some(ScreenEdge::Right)`
    /// - `"top"`, `"up"` -> `Some(ScreenEdge::Top)`
    /// - `"bottom"`, `"down"` -> `Some(ScreenEdge::Bottom)`
    ///
    /// # Arguments
    /// * `raw` - Raw string slice to inspect.
    ///
    /// # Returns
    /// `Some(ScreenEdge)` if matched, otherwise `None`.
    pub fn from_str_lossy(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "left" => Some(ScreenEdge::Left),
            "right" => Some(ScreenEdge::Right),
            "top" | "up" => Some(ScreenEdge::Top),
            "bottom" | "down" => Some(ScreenEdge::Bottom),
            _ => None,
        }
    }
}

/// Physical desk layout configuration and behavioral toggles for the KVM engine.
///
/// Encapsulates screen arrangement topology, edge transition sensitivities, dead-corner guards,
/// modifier key translations, and drag-and-drop preferences. Persisted atomically to disk
/// in `kvm_layout.json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct KvmLayoutConfig {
    /// Cardinal side of the local display where the paired peer workstation sits on the physical desk.
    pub peer_edge: ScreenEdge,

    /// Normalized perpendicular alignment offset along the shared edge (`-0.5..=0.5`, `0.0` centered).
    /// Used when the two physical monitors are not vertically or horizontally flush.
    pub alignment_offset: f32,

    /// Required cursor dwell / push threshold in milliseconds before the cursor hops across the boundary (`0..=250` ms).
    /// Prevents inadvertent transitions during casual mouse movement near the edge.
    pub hop_delay_ms: u32,

    /// Guard corner pixels (e.g., Apple menu bar icon, close window 'X', system tray) against accidental hops.
    pub dead_corners: bool,

    /// Automatically translate macOS `Command ⌘` ↔ Windows `Ctrl` modifier keys for seamless muscle memory.
    pub modifier_translation: bool,

    /// Forward horizontal/vertical high-precision trackpad gestures and smooth mouse wheel deltas.
    pub precision_touchpad: bool,

    /// Render a translucent floating preview badge and edge-peek indicator during active cross-screen drags.
    pub ghost_thumbnail: bool,

    /// Throttle background bulk drag data streaming when an Extended Desktop video stream is actively consuming bandwidth.
    pub qos_clamp: bool,

    /// Default fallback destination directory label (`"downloads"` | `"desktop"` | `"cache"`) for dropped items.
    pub drop_folder: String,

    /// Allows the remote peer workstation to control the local mouse and keyboard.
    /// When disabled, incoming EnterScreen requests are rejected and returned immediately.
    pub allow_remote_control: bool,

    /// Monotonic last-modified timestamp (Unix epoch milliseconds) for layout synchronization conflict resolution.
    pub updated_at_ms: u64,
}

impl Default for KvmLayoutConfig {
    /// Constructs default desk layout settings based on the hosting operating system.
    ///
    /// By default, macOS assumes the peer sits to its `Right`, while Windows assumes the peer
    /// sits to its `Left`.
    fn default() -> Self {
        Self {
            peer_edge: if cfg!(target_os = "macos") {
                ScreenEdge::Right
            } else {
                ScreenEdge::Left
            },
            alignment_offset: 0.0,
            hop_delay_ms: 40,
            dead_corners: true,
            modifier_translation: true,
            precision_touchpad: true,
            ghost_thumbnail: true,
            qos_clamp: true,
            drop_folder: "downloads".to_string(),
            allow_remote_control: true,
            updated_at_ms: 0,
        }
    }
}

/// Metadata payload offered when beginning a cross-screen drag-and-drop operation.
///
/// Transmitted across the wire inside `KvmWireMessage::EnterScreen` when the cursor crosses
/// the display edge while holding down an active file/folder drag session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DragOffer {
    /// Unique 64-bit random hex session identifier generated by the source machine.
    pub session_id: String,

    /// User-visible display name of the primary dragged root item (e.g., `"ProjectAssets.zip"`).
    pub root_name: String,

    /// Preview list containing up to the top 8 entry names for multi-item drag previews.
    pub top_entries: Vec<String>,

    /// Total count of all files and folders contained within the drag selection.
    pub total_files: usize,

    /// Cumulative uncompressed payload size in bytes across all dragged items.
    pub total_bytes: u64,

    /// True if the root dragged entity is a directory hierarchy rather than an isolated file.
    pub is_directory: bool,

    /// Optional small Base64-encoded PNG file icon thumbnail (<= 64 KiB) for cursor ghost badges.
    pub icon_png_b64: Option<String>,
}

/// Canonical cross-platform representation of physical mouse buttons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RemoteMouseButton {
    /// Primary mouse button (typically left click).
    Left,
    /// Secondary mouse button (typically right click / contextual menu).
    Right,
    /// Auxiliary mouse button (typically mouse wheel click / tertiary).
    Middle,
}

/// Platform-independent canonical keyboard modifier bitmask.
///
/// Normalizes Quartz event modifier flags (`NSEventModifierFlags` / `CGEventFlags`)
/// and Windows keystate flags (`VK_SHIFT`, `VK_CONTROL`, `VK_MENU`, `VK_LWIN`/`VK_RWIN`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModifierMask {
    /// Shift key modifier active.
    pub shift: bool,
    /// Control key modifier active.
    pub control: bool,
    /// Alt / Option key modifier active.
    pub alt: bool,
    /// Meta modifier active (`Command ⌘` on macOS, `Windows ⊞` key on Windows).
    pub meta: bool,
}

/// Platform-independent logical key codes mapped cleanly between macOS `CGKeyCode` and Windows `VK_*`.
///
/// Ensures uniform interpretation of alphanumeric keys, function keys, navigation keys,
/// and modifier keys across different physical keyboard layouts and operating systems.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LogicalKey {
    CharA, CharB, CharC, CharD, CharE, CharF, CharG, CharH, CharI, CharJ, CharK, CharL, CharM,
    CharN, CharO, CharP, CharQ, CharR, CharS, CharT, CharU, CharV, CharW, CharX, CharY, CharZ,
    Digit0, Digit1, Digit2, Digit3, Digit4, Digit5, Digit6, Digit7, Digit8, Digit9,
    Minus, Equal, LeftBracket, RightBracket, Backslash, Semicolon, Quote, Comma, Period, Slash, Grave,
    Return, Tab, Space, Backspace, Delete, Escape,
    Up, Down, Left, Right,
    Home, End, PageUp, PageDown,
    CapsLock,
    ShiftLeft, ShiftRight,
    ControlLeft, ControlRight,
    AltLeft, AltRight,
    MetaLeft, MetaRight,
    F1, F2, F3, F4, F5, F6, F7, F8, F9, F10, F11, F12,
}

/// Enumeration of all discrete wire protocol messages exchanged over the KVM transport session.
///
/// Encoded using Serde and framed over `TransportSessionV2` with ChaCha20-Poly1305 encryption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KvmWireMessage {
    /// Synchronizes desk layout placement from user configuration to peer (mirrored automatically).
    SyncLayout(KvmLayoutConfig),

    /// Advertises receiver screen dimensions for smooth pointer edge mapping and aspect ratio scaling.
    ScreenGeometry {
        /// Primary monitor width in physical or logical display pixels.
        width: u32,
        /// Primary monitor height in physical or logical display pixels.
        height: u32,
    },

    /// Transfers pointer/keyboard (and optional active drag session) onto peer's screen.
    EnterScreen {
        /// Screen edge across which the pointer is entering the peer workstation.
        entry_edge: ScreenEdge,
        /// Normalized perpendicular offset `[0.0, 1.0]` along the entry boundary.
        norm_pos: f32,
        /// Indicates if the primary mouse button was held down during the edge crossing.
        left_button_held: bool,
        /// Optional drag-and-drop metadata offer if a native drag session is in progress.
        drag_offer: Option<DragOffer>,
    },

    /// Returns pointer/keyboard control back across the shared screen border to the originating workstation.
    LeaveScreen {
        /// Screen edge across which the pointer exited the remote screen.
        exit_edge: ScreenEdge,
        /// Normalized perpendicular offset `[0.0, 1.0]` along the exit boundary.
        norm_pos: f32,
    },

    /// Sub-millisecond relative pointer movement deltas while actively controlling the remote peer.
    MouseMoveDelta {
        /// Horizontal movement delta in device-independent units.
        dx: f32,
        /// Vertical movement delta in device-independent units.
        dy: f32,
    },

    /// Mouse button press or release state transition.
    MouseButton {
        /// Mouse button being pressed or released.
        button: RemoteMouseButton,
        /// True if pressed down, false if released up.
        pressed: bool,
    },

    /// High-resolution scroll wheel or precision trackpad pan deltas.
    MouseScroll {
        /// Horizontal scroll delta.
        dx: f32,
        /// Vertical scroll delta.
        dy: f32,
    },

    /// Discrete keyboard key transition event.
    KeyEvent {
        /// Canonical logical key code.
        key: LogicalKey,
        /// True if key was pressed down, false if released up.
        pressed: bool,
        /// Canonical modifier state snapshot at the time of the event.
        modifiers: ModifierMask,
    },

    /// Cancels an active cross-screen drag session cleanly without dropping files.
    DragCancel {
        /// Unique session identifier of the cancelled drag operation.
        session_id: String,
    },

    /// Reports final drop completion status and target acceptance back to sending workstation.
    DragDropResult {
        /// Unique session identifier of the finished drag operation.
        session_id: String,
        /// True if the drop target accepted and processed the dropped payload.
        accepted: bool,
        /// Diagnostic or failure description message.
        message: String,
    },

    /// Forces immediate release of any remotely held cursor locks or pressed keys.
    /// Emitted on disconnect, network error, or feature deactivation to prevent stuck keys.
    ReleaseAll,

    /// Keep-alive ping frame to verify end-to-end transport responsiveness and detect link loss.
    Ping,
}
