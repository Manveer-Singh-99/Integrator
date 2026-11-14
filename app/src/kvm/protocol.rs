//! Wire protocol and canonical cross-platform input types for Universal Input KVM
//! and Cross-Screen Drag & Drop over `TransportSessionV2` (`ServiceId::InputKvm`).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScreenEdge {
    Left,
    Right,
    Top,
    Bottom,
}

impl ScreenEdge {
    pub fn opposite(self) -> Self {
        match self {
            ScreenEdge::Left => ScreenEdge::Right,
            ScreenEdge::Right => ScreenEdge::Left,
            ScreenEdge::Top => ScreenEdge::Bottom,
            ScreenEdge::Bottom => ScreenEdge::Top,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            ScreenEdge::Left => "Left",
            ScreenEdge::Right => "Right",
            ScreenEdge::Top => "Top",
            ScreenEdge::Bottom => "Bottom",
        }
    }

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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct KvmLayoutConfig {
    /// Side of the local display where the paired peer workstation sits on the desk.
    pub peer_edge: ScreenEdge,
    /// Normalized perpendicular alignment along the shared edge (`-0.5..=0.5`, `0.0` centered).
    pub alignment_offset: f32,
    /// Dwell / push threshold in milliseconds before cursor crosses the display edge (`0..=250`).
    pub hop_delay_ms: u32,
    /// Guard corner pixels (e.g. menu bar Apple icon / close X) against accidental transitions.
    pub dead_corners: bool,
    /// Automatically translate `Command ⌘` <-> `Ctrl` between macOS and Windows.
    pub modifier_translation: bool,
    /// Forward horizontal/vertical trackpad & precision mouse wheel events.
    pub precision_touchpad: bool,
    /// Render translucent floating preview & edge-peek indicator during drag/handoff.
    pub ghost_thumbnail: bool,
    /// Throttle background bulk drag streaming while Extended Desktop video stream is active.
    pub qos_clamp: bool,
    /// Default fallback destination label ("downloads" | "desktop" | "cache") for dashboard drops.
    pub drop_folder: String,
    /// Monotonic last-modified timestamp (Unix ms) for layout sync conflict resolution.
    pub updated_at_ms: u64,
}

impl Default for KvmLayoutConfig {
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
            updated_at_ms: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DragOffer {
    pub session_id: String,
    pub root_name: String,
    pub top_entries: Vec<String>,
    pub total_files: usize,
    pub total_bytes: u64,
    pub is_directory: bool,
    /// Optional small PNG preview thumbnail (<= 64 KiB) for cursor overlay badge.
    pub icon_png_b64: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RemoteMouseButton {
    Left,
    Right,
    Middle,
}

/// Cross-platform canonical keyboard modifier bitmask.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModifierMask {
    pub shift: bool,
    pub control: bool,
    pub alt: bool,
    pub meta: bool,
}

/// Platform-independent logical key codes mapped cleanly between macOS `CGKeyCode` and Windows `VK_*`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LogicalKey {
    CharA,
    CharB,
    CharC,
    CharD,
    CharE,
    CharF,
    CharG,
    CharH,
    CharI,
    CharJ,
    CharK,
    CharL,
    CharM,
    CharN,
    CharO,
    CharP,
    CharQ,
    CharR,
    CharS,
    CharT,
    CharU,
    CharV,
    CharW,
    CharX,
    CharY,
    CharZ,
    Digit0,
    Digit1,
    Digit2,
    Digit3,
    Digit4,
    Digit5,
    Digit6,
    Digit7,
    Digit8,
    Digit9,
    Minus,
    Equal,
    LeftBracket,
    RightBracket,
    Backslash,
    Semicolon,
    Quote,
    Comma,
    Period,
    Slash,
    Grave,
    Return,
    Tab,
    Space,
    Backspace,
    Delete,
    Escape,
    Up,
    Down,
    Left,
    Right,
    Home,
    End,
    PageUp,
    PageDown,
    CapsLock,
    ShiftLeft,
    ShiftRight,
    ControlLeft,
    ControlRight,
    AltLeft,
    AltRight,
    MetaLeft,
    MetaRight,
    F1,
    F2,
    F3,
    F4,
    F5,
    F6,
    F7,
    F8,
    F9,
    F10,
    F11,
    F12,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KvmWireMessage {
    /// Synchronizes desk layout placement from user configuration to peer (mirrored automatically).
    SyncLayout(KvmLayoutConfig),
    /// Advertises receiver screen dimensions for smooth pointer edge mapping.
    ScreenGeometry { width: u32, height: u32 },
    /// Transfers pointer/keyboard (and optional active drag session) onto peer's screen.
    EnterScreen {
        entry_edge: ScreenEdge,
        norm_pos: f32,
        left_button_held: bool,
        drag_offer: Option<DragOffer>,
    },
    /// Returns pointer/keyboard control back across the shared screen border.
    LeaveScreen {
        exit_edge: ScreenEdge,
        norm_pos: f32,
    },
    /// Sub-millisecond relative pointer movement while controlling peer.
    MouseMoveDelta { dx: f32, dy: f32 },
    /// Mouse button press/release while controlling peer.
    MouseButton {
        button: RemoteMouseButton,
        pressed: bool,
    },
    /// Scroll wheel / trackpad pan delta while controlling peer.
    MouseScroll { dx: f32, dy: f32 },
    /// Keyboard event while controlling peer.
    KeyEvent {
        key: LogicalKey,
        pressed: bool,
        modifiers: ModifierMask,
    },
    /// Cancels an active cross-screen drag session cleanly without dropping files.
    DragCancel { session_id: String },
    /// Reports final drop completion status back to sending workstation.
    DragDropResult {
        session_id: String,
        accepted: bool,
        message: String,
    },
    /// Forces release of any remotely controlled cursor/keys on disconnect or feature toggle-off.
    ReleaseAll,
    Ping,
}
