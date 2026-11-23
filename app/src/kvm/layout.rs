//! # Desk Layout, Screen Geometry & Coordinate Normalization Engine
//!
//! ## 1. Module Purpose & Scope
//! This module provides the mathematical foundations, coordinate transformation pipeline,
//! mirror symmetry algorithms, dead-corner filtering, and atomic disk persistence for the
//! Integrator Universal Input KVM system.
//!
//! When two heterogeneous workstations (e.g. a 16-inch MacBook Pro Liquid Retina XDR display
//! at 3456x2234 logical/physical scale and a Windows 11 PC driving a 3840x2160 4K monitor)
//! sit side-by-side, their coordinate systems cannot be naively mapped 1:1. This module
//! projects multi-monitor spaces into normalized unit intervals `[0.0, 1.0]` along active
//! transition edges, taking into account user-defined vertical/horizontal desk offsets,
//! monitor resolution differences, and corner exclusion zones.
//!
//! ## 2. Architectural Linkages & Dependencies
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────────────────────────────────┐
//! │                    Display Geometry & Coordinate Normalization Flow                    │
//! └────────────────────────────────────────────────────────────────────────────────────────┘
//!
//!     MacBook Screen (1440 x 900)                    Windows 11 Screen (1920 x 1080)
//!  ┌──────────────────────────────┐              ┌──────────────────────────────────────┐
//!  │                              │              │                                      │
//!  │  Cursor Exits Right Edge     │              │  Cursor Enters Left Edge             │
//!  │  Y = 450.0 px (50% height)   │              │  Y = 540.0 px (50% height)           │
//!  │                              ├─────────────►│                                      │
//!  │  compute_normalized_edge_pos │   Network    │  resolve_entry_point                 │
//!  │  norm_pos = 0.500            │  Wire Msg    │  (x = 6.0 px, y = 540.0 px)          │
//!  └──────────────────────────────┘              └──────────────────────────────────────┘
//! ```
//!
//! ### Upstream Callers:
//! - `src/kvm/service.rs`: Calls `is_in_dead_corner` and `compute_normalized_edge_pos` on pointer
//!   movement hooks when the cursor touches an outer display boundary, and calls `resolve_entry_point`
//!   upon receiving `KvmWireMessage::EnterScreen`.
//! - `src/kvm/service.rs`: Calls `load_layout_config`, `save_layout_config`, and `mirror_layout_for_peer`
//!   during startup, configuration updates, and inbound layout synchronization.
//!
//! ### Downstream Callees:
//! - `crate::system_info::app_data_dir()`: Obtains the platform-safe storage directory.
//! - `crate::system_info::atomic_write_private()`: Flushes layout state to disk atomically via temporary files
//!   and atomic renames (`rename` on Unix, `MoveFileExW(MOVEFILE_REPLACE_EXISTING)` on Windows).
//!
//! ## 3. Threading & Concurrency Model
//! - Geometric transformation functions (`compute_normalized_edge_pos`, `resolve_entry_point`,
//!   `is_in_dead_corner`) are pure, non-blocking, and re-entrant. They are invoked synchronously
//!   from OS event hook callbacks (`CGEventTap` on macOS, `WH_MOUSE_LL` on Windows) where execution
//!   latency must stay under 500 microseconds.
//! - File persistence (`save_layout_config`) is guarded by `LAYOUT_SAVE_LOCK` (`Mutex<()>`) to prevent
//!   race conditions if rapid configuration changes arrive concurrently from local UI and remote RPC.
//!
//! ## 4. Security & Safety Invariants
//! - **Sanitized Numerical Ranges**: Perpendicular alignment offset is strictly clamped to `[-0.5, 0.5]`
//!   and tested for finite validity (`is_finite()`). All `NaN` or infinite inputs collapse safely to `0.0`.
//! - **Clock Skew Bounding**: Monotonic synchronization timestamps (`updated_at_ms`) are validated
//!   against local clock time with a maximum forward skew cap (`MAX_CLOCK_SKEW_MS = 300,000` ms / 5 minutes)
//!   to thwart replay attacks or clock-tampering denial of service.
//! - **Zero-Division Avoidance**: Zero or sub-pixel screen dimensions are caught and defaulted to 0.5.

use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::warn;

use super::protocol::{KvmLayoutConfig, ScreenEdge};

/// Size of the corner exclusion zone in device pixels (36.0 px).
///
/// Prevents accidental KVM hops when interacting with edge-adjacent UI controls such as:
/// - macOS Apple menu (top-left) and Control Center (top-right)
/// - Windows Start menu (bottom-left) and Notification Center (bottom-right)
/// - Window title bar maximize/close controls
pub const DEAD_CORNER_PX: f32 = 36.0;

/// Maximum allowable forward clock skew in milliseconds (5 minutes).
const MAX_CLOCK_SKEW_MS: u64 = 300_000;

/// Maximum configurable edge hop dwell delay in milliseconds (250 ms).
const MAX_HOP_DELAY_MS: u32 = 250;

/// Maximum fraction of a display edge dimension covered by a corner exclusion guard (15%).
const MAX_DEAD_CORNER_RATIO: f32 = 0.15;

/// Minimum clamped normalized edge coordinate along a display boundary (`0.02`).
const EDGE_NORM_MIN: f32 = 0.02;

/// Maximum clamped normalized edge coordinate along a display boundary (`0.98`).
const EDGE_NORM_MAX: f32 = 0.98;

/// Minimum inward cursor entry inset in device pixels (`2.0` px) on a destination display.
const MIN_ENTRY_INSET_PX: f32 = 2.0;

/// Fallback inward cursor entry inset in device pixels (`6.0` px) when the supplied inset is non-finite.
const DEFAULT_ENTRY_INSET_PX: f32 = 6.0;

/// Global synchronization lock ensuring atomic file serialization for layout configurations.
static LAYOUT_SAVE_LOCK: Mutex<()> = Mutex::new(());

/// Axis-aligned bounding rectangle representing a physical or virtual screen surface.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ScreenRect {
    /// Horizontal origin coordinate (leftmost edge) in device-independent units.
    pub x: f32,
    /// Vertical origin coordinate (topmost edge) in device-independent units.
    pub y: f32,
    /// Physical or logical width of the screen in units.
    pub width: f32,
    /// Physical or logical height of the screen in units.
    pub height: f32,
}

impl ScreenRect {
    /// Returns the maximum horizontal coordinate (`x + width`) along the right boundary.
    #[inline]
    pub fn max_x(&self) -> f32 {
        self.x + self.width
    }

    /// Returns the maximum vertical coordinate (`y + height`) along the bottom boundary.
    #[inline]
    pub fn max_y(&self) -> f32 {
        self.y + self.height
    }
}

/// Computes the absolute filesystem path for the persisted KVM layout configuration (`kvm_layout.json`).
///
/// Located inside the application data directory (`~/Library/Application Support/Integrator` on macOS,
/// `%LOCALAPPDATA%\Integrator` on Windows).
pub fn layout_config_path() -> PathBuf {
    crate::system_info::app_data_dir().join(crate::config::KVM_LAYOUT_FILE)
}

/// Loads and validates the persisted KVM layout configuration from disk.
///
/// If the file does not exist, is unreadable, or contains invalid JSON syntax,
/// the system emits a warning and safely falls back to `KvmLayoutConfig::default()`.
///
/// # Returns
/// A validated, sanitized `KvmLayoutConfig`.
pub fn load_layout_config() -> KvmLayoutConfig {
    let path = layout_config_path();
    if let Ok(raw) = fs::read_to_string(&path) {
        match serde_json::from_str::<KvmLayoutConfig>(&raw) {
            Ok(mut cfg) => {
                sanitize_layout(&mut cfg);
                return cfg;
            }
            Err(e) => {
                warn!("Invalid kvm_layout.json ({}); resetting to defaults", e);
            }
        }
    }
    KvmLayoutConfig::default()
}

/// Persists the provided KVM layout configuration to disk atomically.
///
/// Writes through a temporary sibling file and performs an atomic rename to prevent
/// partial file corruption during sudden system reboot or power loss.
///
/// # Arguments
/// * `cfg` - Configuration reference to sanitize and persist.
///
/// # Returns
/// `Ok(())` on successful atomic write, or `std::io::Error` on filesystem failure.
pub fn save_layout_config(cfg: &KvmLayoutConfig) -> std::io::Result<()> {
    let _guard = LAYOUT_SAVE_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let mut sanitized = cfg.clone();
    sanitize_layout(&mut sanitized);
    let path = layout_config_path();
    let json = serde_json::to_string_pretty(&sanitized)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    crate::system_info::atomic_write_private(&path, json.as_bytes())
}

/// Clamps numerical ranges, normalizes strings, and bounds timestamps for `KvmLayoutConfig`.
///
/// Invariants enforced:
/// - `alignment_offset`: finite and clamped within `[-0.5, 0.5]`
/// - `hop_delay_ms`: clamped to a maximum of `250` ms
/// - `drop_folder`: normalized to `"desktop"`, `"cache"`, or `"downloads"`
/// - `updated_at_ms`: capped at `now + MAX_CLOCK_SKEW_MS`
pub fn sanitize_layout(cfg: &mut KvmLayoutConfig) {
    // 1. Sanitize perpendicular alignment offset
    if !cfg.alignment_offset.is_finite() {
        cfg.alignment_offset = 0.0;
    }
    cfg.alignment_offset = cfg.alignment_offset.clamp(-0.5, 0.5);

    // 2. Sanitize edge hop delay threshold
    cfg.hop_delay_ms = cfg.hop_delay_ms.min(MAX_HOP_DELAY_MS);

    // 3. Normalize drop destination folder
    cfg.drop_folder = match cfg.drop_folder.trim().to_ascii_lowercase().as_str() {
        "desktop" => "desktop".to_string(),
        "cache" => "cache".to_string(),
        _ => "downloads".to_string(),
    };

    // 4. Bound timestamp against unreasonable future clock skew
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let max_ts = now_ms.saturating_add(MAX_CLOCK_SKEW_MS);
    if cfg.updated_at_ms > max_ts {
        cfg.updated_at_ms = max_ts;
    }
}

/// Computes the peer-side mirrored layout when the user configures local desk arrangement.
///
/// Enforces physical mirror symmetry:
/// - If the peer is on my `Right`, the peer sees me on its `Left`.
/// - If local has a `+0.25` perpendicular offset, peer has `-0.25`.
///
/// # Arguments
/// * `local` - Local layout configuration.
///
/// # Returns
/// The geometrically inverted `KvmLayoutConfig` for the peer workstation.
pub fn mirror_layout_for_peer(local: &KvmLayoutConfig) -> KvmLayoutConfig {
    KvmLayoutConfig {
        peer_edge: local.peer_edge.opposite(),
        alignment_offset: (-local.alignment_offset).clamp(-0.5, 0.5),
        hop_delay_ms: local.hop_delay_ms.min(MAX_HOP_DELAY_MS),
        dead_corners: local.dead_corners,
        modifier_translation: local.modifier_translation,
        precision_touchpad: local.precision_touchpad,
        ghost_thumbnail: local.ghost_thumbnail,
        qos_clamp: local.qos_clamp,
        drop_folder: local.drop_folder.clone(),
        allow_remote_control: true,
        updated_at_ms: local.updated_at_ms,
    }
}

/// Checks whether coordinates `(x, y)` lie inside a corner dead-zone along `edge`.
///
/// Protects against accidental transitions when the user moves the cursor to access
/// OS-level UI elements (e.g. menu bar corners, Apple logo, Window close button).
/// Dead-zone depth is dynamically bounded to at most 15% of the edge dimension.
///
/// # Arguments
/// * `rect` - Primary screen bounding box.
/// * `edge` - Active boundary edge being approached.
/// * `x` - Pointer X coordinate.
/// * `y` - Pointer Y coordinate.
///
/// # Returns
/// `true` if within a dead corner, suppressing KVM hopping.
pub fn is_in_dead_corner(rect: ScreenRect, edge: ScreenEdge, x: f32, y: f32) -> bool {
    let guard_y = DEAD_CORNER_PX.min(rect.height * MAX_DEAD_CORNER_RATIO);
    let guard_x = DEAD_CORNER_PX.min(rect.width * MAX_DEAD_CORNER_RATIO);
    match edge {
        ScreenEdge::Left | ScreenEdge::Right => {
            y < rect.y + guard_y || y > rect.max_y() - guard_y
        }
        ScreenEdge::Top | ScreenEdge::Bottom => {
            x < rect.x + guard_x || x > rect.max_x() - guard_x
        }
    }
}

/// Converts a local coordinate `(x, y)` exiting `exit_edge` into a normalized `[0.0, 1.0]`
/// coordinate along that edge, accounting for perpendicular desk `alignment_offset`.
///
/// Clamps output within `[0.02, 0.98]` to guarantee the cursor lands cleanly on the active
/// display area and avoids boundary singularity artifacts.
///
/// # Arguments
/// * `rect` - Originating screen bounding box.
/// * `exit_edge` - Cardinal boundary edge being crossed.
/// * `x` - Current pointer X coordinate.
/// * `y` - Current pointer Y coordinate.
/// * `alignment_offset` - User-configured perpendicular offset `[-0.5, 0.5]`.
///
/// # Returns
/// A normalized fractional position `[0.02, 0.98]`.
pub fn compute_normalized_edge_pos(
    rect: ScreenRect,
    exit_edge: ScreenEdge,
    x: f32,
    y: f32,
    alignment_offset: f32,
) -> f32 {
    let raw = match exit_edge {
        ScreenEdge::Left | ScreenEdge::Right => {
            if rect.height <= 1.0 {
                0.5
            } else {
                (y - rect.y) / rect.height
            }
        }
        ScreenEdge::Top | ScreenEdge::Bottom => {
            if rect.width <= 1.0 {
                0.5
            } else {
                (x - rect.x) / rect.width
            }
        }
    };
    let offset = if alignment_offset.is_finite() {
        alignment_offset.clamp(-0.5, 0.5)
    } else {
        0.0
    };
    if !raw.is_finite() {
        return 0.5;
    }
    (raw - offset).clamp(EDGE_NORM_MIN, EDGE_NORM_MAX)
}

/// Resolves an entry point `(px, py)` just inside `entry_edge` on the destination display.
///
/// Maps the incoming normalized position `norm_pos` to the target screen's dimensions,
/// applying an inward inset (typically 6.0 px) so the cursor is immediately recognized
/// as inside the target workstation's display bounds.
///
/// # Arguments
/// * `target_rect` - Destination screen bounding box.
/// * `entry_edge` - Cardinal boundary edge where cursor is entering.
/// * `norm_pos` - Normalized position along the edge `[0.0, 1.0]`.
/// * `inset_px` - Inset distance from the boundary in device pixels.
///
/// # Returns
/// Target coordinates `(px, py)` in the destination display coordinate system.
pub fn resolve_entry_point(
    target_rect: ScreenRect,
    entry_edge: ScreenEdge,
    norm_pos: f32,
    inset_px: f32,
) -> (f32, f32) {
    let n = if norm_pos.is_finite() {
        norm_pos.clamp(EDGE_NORM_MIN, EDGE_NORM_MAX)
    } else {
        0.5
    };
    let inset = if inset_px.is_finite() {
        inset_px.max(MIN_ENTRY_INSET_PX)
    } else {
        DEFAULT_ENTRY_INSET_PX
    };
    match entry_edge {
        ScreenEdge::Left => (
            target_rect.x + inset,
            target_rect.y + n * target_rect.height,
        ),
        ScreenEdge::Right => (
            target_rect.max_x() - inset,
            target_rect.y + n * target_rect.height,
        ),
        ScreenEdge::Top => (
            target_rect.x + n * target_rect.width,
            target_rect.y + inset,
        ),
        ScreenEdge::Bottom => (
            target_rect.x + n * target_rect.width,
            target_rect.max_y() - inset,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_layout_mirror_and_entry_point_mapping() {
        let mut local = KvmLayoutConfig {
            peer_edge: ScreenEdge::Right,
            alignment_offset: 0.25,
            hop_delay_ms: 40,
            dead_corners: true,
            modifier_translation: true,
            precision_touchpad: true,
            ghost_thumbnail: true,
            qos_clamp: true,
            drop_folder: "downloads".to_string(),
            allow_remote_control: true,
            updated_at_ms: 12345,
        };
        sanitize_layout(&mut local);

        let peer = mirror_layout_for_peer(&local);
        assert_eq!(peer.peer_edge, ScreenEdge::Left);
        assert!((peer.alignment_offset + 0.25).abs() < 1e-5);

        let mac_rect = ScreenRect {
            x: 0.0,
            y: 0.0,
            width: 1440.0,
            height: 900.0,
        };
        let win_rect = ScreenRect {
            x: 0.0,
            y: 0.0,
            width: 1920.0,
            height: 1200.0,
        };

        assert!(is_in_dead_corner(mac_rect, ScreenEdge::Right, 1440.0, 10.0));
        assert!(!is_in_dead_corner(mac_rect, ScreenEdge::Right, 1440.0, 450.0));

        // Exit Mac middle-right with alignment offset 0.0 -> enter Windows Left edge at middle
        let norm = compute_normalized_edge_pos(mac_rect, ScreenEdge::Right, 1440.0, 450.0, 0.0);
        assert!((norm - 0.5).abs() < 1e-5);
        let (wx, wy) = resolve_entry_point(win_rect, ScreenEdge::Left, norm, 6.0);
        assert!((wx - 6.0).abs() < 1e-4);
        assert!((wy - 600.0).abs() < 1e-4);
    }

    #[test]
    fn test_multi_monitor_negative_origin_edge_crossing_and_clamping() {
        // Multi-monitor desktop where a secondary 1920x1080 monitor sits to the left and slightly above
        // the primary 2560x1440 display -> virtual screen origin at (-1920, -320), total 4480x1760.
        let multi_desk_rect = ScreenRect {
            x: -1920.0,
            y: -320.0,
            width: 4480.0,
            height: 1760.0,
        };
        assert!((multi_desk_rect.max_x() - 2560.0).abs() < 1e-4);
        assert!((multi_desk_rect.max_y() - 1440.0).abs() < 1e-4);

        // Top-left and bottom-left corners at x = -1920 must trigger dead-corner guard
        assert!(is_in_dead_corner(
            multi_desk_rect,
            ScreenEdge::Left,
            -1920.0,
            -310.0
        ));
        assert!(is_in_dead_corner(
            multi_desk_rect,
            ScreenEdge::Left,
            -1920.0,
            1430.0
        ));
        // Midpoint of left edge (y = -320 + 880 = 560) is not in a dead corner
        assert!(!is_in_dead_corner(
            multi_desk_rect,
            ScreenEdge::Left,
            -1920.0,
            560.0
        ));

        // Normalized edge position at midpoint (x = 320, y = 560) should be 0.5
        let norm_left = compute_normalized_edge_pos(
            multi_desk_rect,
            ScreenEdge::Left,
            -1920.0,
            560.0,
            0.0,
        );
        assert!((norm_left - 0.5).abs() < 1e-5);

        let norm_top = compute_normalized_edge_pos(
            multi_desk_rect,
            ScreenEdge::Top,
            320.0,
            -320.0,
            0.0,
        );
        assert!((norm_top - 0.5).abs() < 1e-5);

        // Entry points on a negative-origin multi-monitor destination must land inside [x..max_x, y..max_y]
        let (enter_lx, enter_ly) =
            resolve_entry_point(multi_desk_rect, ScreenEdge::Left, 0.5, 6.0);
        assert!((enter_lx - (-1914.0)).abs() < 1e-4);
        assert!((enter_ly - 560.0).abs() < 1e-4);

        let (enter_rx, enter_ry) =
            resolve_entry_point(multi_desk_rect, ScreenEdge::Right, 0.5, 6.0);
        assert!((enter_rx - 2554.0).abs() < 1e-4);
        assert!((enter_ry - 560.0).abs() < 1e-4);
    }
}
