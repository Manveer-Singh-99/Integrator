//! Desk Layout configuration, mirror symmetry, normalized screen-edge geometry,
//! dead-corner protection, and atomic persistence (`kvm_layout.json`).

use std::fs;
use std::path::PathBuf;
use tracing::warn;

use super::protocol::{KvmLayoutConfig, ScreenEdge};

pub const DEAD_CORNER_PX: f32 = 36.0;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ScreenRect {
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
}

impl ScreenRect {
    pub fn max_x(&self) -> f32 {
        self.x + self.width
    }

    pub fn max_y(&self) -> f32 {
        self.y + self.height
    }
}

pub fn layout_config_path() -> PathBuf {
    crate::system_info::app_data_dir().join("kvm_layout.json")
}

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

pub fn save_layout_config(cfg: &KvmLayoutConfig) -> std::io::Result<()> {
    let mut sanitized = cfg.clone();
    sanitize_layout(&mut sanitized);
    let path = layout_config_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    let json = serde_json::to_string_pretty(&sanitized)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    fs::write(&tmp, json)?;
    fs::rename(&tmp, &path)?;
    Ok(())
}

pub fn sanitize_layout(cfg: &mut KvmLayoutConfig) {
    if !cfg.alignment_offset.is_finite() {
        cfg.alignment_offset = 0.0;
    }
    cfg.alignment_offset = cfg.alignment_offset.clamp(-0.5, 0.5);
    cfg.hop_delay_ms = cfg.hop_delay_ms.min(250);
    cfg.drop_folder = match cfg.drop_folder.trim().to_ascii_lowercase().as_str() {
        "desktop" => "desktop".to_string(),
        "cache" => "cache".to_string(),
        _ => "downloads".to_string(),
    };
}

/// Computes the peer-side mirrored layout when the user sets local arrangement
/// (e.g., if peer is on my `Right` with `+0.15` offset, peer sees me on its `Left` with `-0.15`).
pub fn mirror_layout_for_peer(local: &KvmLayoutConfig) -> KvmLayoutConfig {
    KvmLayoutConfig {
        peer_edge: local.peer_edge.opposite(),
        alignment_offset: (-local.alignment_offset).clamp(-0.5, 0.5),
        hop_delay_ms: local.hop_delay_ms.min(250),
        dead_corners: local.dead_corners,
        modifier_translation: local.modifier_translation,
        precision_touchpad: local.precision_touchpad,
        ghost_thumbnail: local.ghost_thumbnail,
        qos_clamp: local.qos_clamp,
        drop_folder: local.drop_folder.clone(),
        updated_at_ms: local.updated_at_ms,
    }
}

/// Checks whether `(x, y)` lies inside a corner dead-zone along `edge`.
pub fn is_in_dead_corner(rect: ScreenRect, edge: ScreenEdge, x: f32, y: f32) -> bool {
    let guard_y = DEAD_CORNER_PX.min(rect.height * 0.15);
    let guard_x = DEAD_CORNER_PX.min(rect.width * 0.15);
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
    (raw - alignment_offset.clamp(-0.5, 0.5)).clamp(0.02, 0.98)
}

/// Resolves an entry point `(px, py)` just inside `entry_edge` on the destination display.
pub fn resolve_entry_point(
    target_rect: ScreenRect,
    entry_edge: ScreenEdge,
    norm_pos: f32,
    inset_px: f32,
) -> (f32, f32) {
    let n = norm_pos.clamp(0.02, 0.98);
    let inset = inset_px.max(2.0);
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
}
