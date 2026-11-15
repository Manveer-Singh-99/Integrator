use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use crate::kvm::layout::ScreenRect;
use crate::kvm::protocol::{LogicalKey, ModifierMask, RemoteMouseButton, ScreenEdge};
use crate::kvm::service::{HookDecision, KvmService};

static KVM_SERVICE_REF: OnceLock<Arc<KvmService>> = OnceLock::new();
static HOOK_ACTIVE: AtomicBool = AtomicBool::new(false);
static START_HOOK_LOCK: Mutex<()> = Mutex::new(());

type KvmWinEventCallback = extern "C" fn(i32, f64, f64, f64, f64, u64) -> i32;
type KvmWinDragEndedCallback = extern "C" fn(bool, *const c_char);

extern "C" {
    fn integrator_kvm_win_start_hooks(
        cb: Option<KvmWinEventCallback>,
        drag_ended_cb: Option<KvmWinDragEndedCallback>,
    ) -> bool;
    fn integrator_kvm_win_stop_hooks();
    fn integrator_kvm_win_is_hook_active() -> bool;
    fn integrator_kvm_win_screen_rect(
        out_x: *mut f64,
        out_y: *mut f64,
        out_w: *mut f64,
        out_h: *mut f64,
    );
    fn integrator_kvm_win_set_edge_probe(enabled: bool, edge_mode: i32);
    fn integrator_kvm_win_set_controlling(
        controlling: bool,
        park_x: i32,
        park_y: i32,
        restore_x: i32,
        restore_y: i32,
    );
    fn integrator_kvm_win_set_controlled(controlled: bool, entry_x: i32, entry_y: i32);
    fn integrator_kvm_win_take_drag_paths() -> *mut c_char;
    fn integrator_kvm_win_free_str(ptr: *mut c_char);
    fn integrator_kvm_win_cancel_local_drag();
    fn integrator_kvm_win_inject_mouse_move(abs_x: i32, abs_y: i32);
    fn integrator_kvm_win_inject_mouse_button(button: i32, pressed: bool);
    fn integrator_kvm_win_inject_scroll(dx: f64, dy: f64);
    fn integrator_kvm_win_inject_key(vk: u16, pressed: bool, extended: bool);
    fn integrator_kvm_win_show_drag_ghost(
        x: i32,
        y: i32,
        title: *const c_char,
        subtitle: *const c_char,
    );
    fn integrator_kvm_win_move_drag_ghost(x: i32, y: i32);
    fn integrator_kvm_win_hide_drag_ghost();
    fn integrator_kvm_win_begin_native_drag(
        paths_utf8: *const *const c_char,
        count: i32,
        session_id: *const c_char,
        remote_left_still_held: bool,
    );
    fn integrator_kvm_win_cancel_remote_drag();
}

pub fn start(service: Arc<KvmService>) {
    let _ = KVM_SERVICE_REF.set(service);
    let _guard = START_HOOK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let ok = unsafe { integrator_kvm_win_start_hooks(Some(on_win_event), Some(on_drag_ended)) };
    HOOK_ACTIVE.store(ok, Ordering::Release);
    if ok {
        tracing::info!("🖱️ Windows LL mouse/keyboard hooks & OLE IDropTarget/DoDragDrop active");
    } else {
        tracing::warn!("⚠️ Failed to install Windows low-level KVM input hooks; will retry");
        std::thread::Builder::new()
            .name("kvm-win-hook-retry".into())
            .spawn(|| {
                for _ in 0..10 {
                    std::thread::sleep(std::time::Duration::from_secs(2));
                    let _g = START_HOOK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
                    let activated = unsafe {
                        integrator_kvm_win_start_hooks(Some(on_win_event), Some(on_drag_ended))
                    };
                    if activated {
                        HOOK_ACTIVE.store(true, Ordering::Release);
                        tracing::info!("🖱️ Windows low-level KVM input hooks activated on retry");
                        break;
                    }
                }
            })
            .ok();
    }
}

pub fn stop() {
    let _guard = START_HOOK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    HOOK_ACTIVE.store(false, Ordering::Release);
    unsafe {
        integrator_kvm_win_stop_hooks();
    }
}

pub fn is_hook_active() -> bool {
    let active = unsafe { integrator_kvm_win_is_hook_active() };
    HOOK_ACTIVE.store(active, Ordering::Release);
    active
}

pub fn sync_edge_probe(enabled: bool, peer_edge: ScreenEdge) {
    let mode = match peer_edge {
        ScreenEdge::Left => 0,
        ScreenEdge::Right => 1,
        ScreenEdge::Top => 2,
        ScreenEdge::Bottom => 3,
    };
    unsafe {
        integrator_kvm_win_set_edge_probe(enabled, mode);
    }
}

pub fn get_primary_screen_rect() -> ScreenRect {
    let mut x = 0.0;
    let mut y = 0.0;
    let mut w = 1920.0;
    let mut h = 1080.0;
    unsafe {
        integrator_kvm_win_screen_rect(&mut x, &mut y, &mut w, &mut h);
    }
    ScreenRect {
        x: x as f32,
        y: y as f32,
        width: (w as f32).max(320.0),
        height: (h as f32).max(200.0),
    }
}

pub fn set_controlling_mode(
    controlling: bool,
    park_x: f32,
    park_y: f32,
    restore_x: f32,
    restore_y: f32,
) {
    unsafe {
        integrator_kvm_win_set_controlling(
            controlling,
            park_x.round() as i32,
            park_y.round() as i32,
            restore_x.round() as i32,
            restore_y.round() as i32,
        );
    }
}

pub fn set_controlled_mode(controlled: bool, entry_x: f32, entry_y: f32) {
    unsafe {
        integrator_kvm_win_set_controlled(
            controlled,
            entry_x.round() as i32,
            entry_y.round() as i32,
        );
    }
}

pub fn probe_active_drag_paths() -> Vec<PathBuf> {
    let ptr = unsafe { integrator_kvm_win_take_drag_paths() };
    if ptr.is_null() {
        return Vec::new();
    }
    let json = unsafe {
        let s = CStr::from_ptr(ptr).to_string_lossy().into_owned();
        integrator_kvm_win_free_str(ptr);
        s
    };
    serde_json::from_str::<Vec<String>>(&json)
        .unwrap_or_default()
        .into_iter()
        .map(PathBuf::from)
        .filter(|p| p.exists())
        .collect()
}

pub fn cancel_local_drag_after_handoff() {
    unsafe {
        integrator_kvm_win_cancel_local_drag();
    }
}

pub fn cancel_remote_drag() {
    unsafe {
        integrator_kvm_win_cancel_remote_drag();
    }
}

pub fn inject_mouse_move(x: f32, y: f32, _left_held: bool) {
    unsafe {
        integrator_kvm_win_inject_mouse_move(x.round() as i32, y.round() as i32);
    }
}

pub fn inject_mouse_button(button: RemoteMouseButton, pressed: bool, _x: f32, _y: f32) {
    let btn = match button {
        RemoteMouseButton::Left => 0,
        RemoteMouseButton::Right => 1,
        RemoteMouseButton::Middle => 2,
    };
    unsafe {
        integrator_kvm_win_inject_mouse_button(btn, pressed);
    }
}

pub fn inject_scroll(dx: f32, dy: f32) {
    let safe_dx = if dx.is_finite() { dx.clamp(-5000.0, 5000.0) } else { 0.0 };
    let safe_dy = if dy.is_finite() { dy.clamp(-5000.0, 5000.0) } else { 0.0 };
    unsafe {
        integrator_kvm_win_inject_scroll(safe_dx as f64, safe_dy as f64);
    }
}

pub fn inject_key(key: LogicalKey, pressed: bool, _mods: ModifierMask) {
    if let Some((vk, ext)) = logical_to_win_vk(key) {
        unsafe {
            integrator_kvm_win_inject_key(vk, pressed, ext);
        }
    }
}

pub fn show_drag_ghost(x: f32, y: f32, title: &str, subtitle: &str, _icon_b64: Option<&str>) {
    let Ok(c_title) = CString::new(title) else { return };
    let Ok(c_sub) = CString::new(subtitle) else { return };
    unsafe {
        integrator_kvm_win_show_drag_ghost(
            x.round() as i32,
            y.round() as i32,
            c_title.as_ptr(),
            c_sub.as_ptr(),
        );
    }
}

pub fn move_drag_ghost(x: f32, y: f32) {
    unsafe {
        integrator_kvm_win_move_drag_ghost(x.round() as i32, y.round() as i32);
    }
}

pub fn hide_drag_ghost() {
    unsafe {
        integrator_kvm_win_hide_drag_ghost();
    }
}

pub fn begin_native_drop_drag(
    paths: &[PathBuf],
    session_id: &str,
    remote_left_still_held: bool,
) {
    let c_strings: Vec<CString> = paths
        .iter()
        .filter_map(|p| p.to_str())
        .filter_map(|s| CString::new(s).ok())
        .collect();
    if c_strings.is_empty() {
        return;
    }
    let ptrs: Vec<*const c_char> = c_strings.iter().map(|c| c.as_ptr()).collect();
    let Ok(c_sid) = CString::new(session_id) else { return };
    unsafe {
        integrator_kvm_win_begin_native_drag(
            ptrs.as_ptr(),
            ptrs.len() as i32,
            c_sid.as_ptr(),
            remote_left_still_held,
        );
    }
}

extern "C" fn on_drag_ended(accepted: bool, session_id_ptr: *const c_char) {
    let Some(svc) = KVM_SERVICE_REF.get() else { return };
    let sid = if session_id_ptr.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(session_id_ptr).to_string_lossy().into_owned() }
    };
    svc.on_native_drag_ended(&sid, accepted);
}

extern "C" fn on_win_event(kind: i32, a: f64, b: f64, c: f64, d: f64, extra: u64) -> i32 {
    let Some(svc) = KVM_SERVICE_REF.get() else {
        return 0;
    };
    let decision = match kind {
        1 => svc.on_local_mouse_move(a as f32, b as f32, c as f32, d as f32, extra != 0),
        2 => {
            let btn = match a as i32 {
                0 => RemoteMouseButton::Left,
                1 => RemoteMouseButton::Right,
                _ => RemoteMouseButton::Middle,
            };
            svc.on_local_mouse_button(btn, b > 0.5, c as f32, d as f32)
        }
        3 => svc.on_local_mouse_scroll(a as f32, b as f32),
        4 => {
            let vk = a as u16;
            if let Some(key) = win_vk_to_logical(vk) {
                svc.on_local_key_event(key, b > 0.5, win_flags_to_modifiers(extra))
            } else if svc.is_controlling_peer_fast() {
                HookDecision::Swallow
            } else {
                HookDecision::PassThrough
            }
        }
        _ => HookDecision::PassThrough,
    };

    match decision {
        HookDecision::PassThrough => 0,
        HookDecision::Swallow => 1,
        HookDecision::SwallowAndParkCenter => 2,
    }
}

fn win_flags_to_modifiers(raw: u64) -> ModifierMask {
    ModifierMask {
        shift: (raw & 1) != 0,
        control: (raw & 2) != 0,
        alt: (raw & 4) != 0,
        meta: (raw & 8) != 0,
    }
}

pub fn win_vk_to_logical(vk: u16) -> Option<LogicalKey> {
    use LogicalKey::*;
    Some(match vk {
        0x41 => CharA,
        0x42 => CharB,
        0x43 => CharC,
        0x44 => CharD,
        0x45 => CharE,
        0x46 => CharF,
        0x47 => CharG,
        0x48 => CharH,
        0x49 => CharI,
        0x4A => CharJ,
        0x4B => CharK,
        0x4C => CharL,
        0x4D => CharM,
        0x4E => CharN,
        0x4F => CharO,
        0x50 => CharP,
        0x51 => CharQ,
        0x52 => CharR,
        0x53 => CharS,
        0x54 => CharT,
        0x55 => CharU,
        0x56 => CharV,
        0x57 => CharW,
        0x58 => CharX,
        0x59 => CharY,
        0x5A => CharZ,
        0x30 => Digit0,
        0x31 => Digit1,
        0x32 => Digit2,
        0x33 => Digit3,
        0x34 => Digit4,
        0x35 => Digit5,
        0x36 => Digit6,
        0x37 => Digit7,
        0x38 => Digit8,
        0x39 => Digit9,
        0xBD => Minus,
        0xBB => Equal,
        0xDB => LeftBracket,
        0xDD => RightBracket,
        0xDC => Backslash,
        0xBA => Semicolon,
        0xDE => Quote,
        0xBC => Comma,
        0xBE => Period,
        0xBF => Slash,
        0xC0 => Grave,
        0x0D => Return,
        0x09 => Tab,
        0x20 => Space,
        0x08 => Backspace,
        0x2E => Delete,
        0x1B => Escape,
        0x26 => Up,
        0x28 => Down,
        0x25 => Left,
        0x27 => Right,
        0x24 => Home,
        0x23 => End,
        0x21 => PageUp,
        0x22 => PageDown,
        0x14 => CapsLock,
        0xA0 | 0x10 => ShiftLeft,
        0xA1 => ShiftRight,
        0xA2 | 0x11 => ControlLeft,
        0xA3 => ControlRight,
        0xA4 | 0x12 => AltLeft,
        0xA5 => AltRight,
        0x5B => MetaLeft,
        0x5C => MetaRight,
        0x70 => F1,
        0x71 => F2,
        0x72 => F3,
        0x73 => F4,
        0x74 => F5,
        0x75 => F6,
        0x76 => F7,
        0x77 => F8,
        0x78 => F9,
        0x79 => F10,
        0x7A => F11,
        0x7B => F12,
        _ => return None,
    })
}

pub fn logical_to_win_vk(key: LogicalKey) -> Option<(u16, bool)> {
    use LogicalKey::*;
    Some(match key {
        CharA => (0x41, false),
        CharB => (0x42, false),
        CharC => (0x43, false),
        CharD => (0x44, false),
        CharE => (0x45, false),
        CharF => (0x46, false),
        CharG => (0x47, false),
        CharH => (0x48, false),
        CharI => (0x49, false),
        CharJ => (0x4A, false),
        CharK => (0x4B, false),
        CharL => (0x4C, false),
        CharM => (0x4D, false),
        CharN => (0x4E, false),
        CharO => (0x4F, false),
        CharP => (0x50, false),
        CharQ => (0x51, false),
        CharR => (0x52, false),
        CharS => (0x53, false),
        CharT => (0x54, false),
        CharU => (0x55, false),
        CharV => (0x56, false),
        CharW => (0x57, false),
        CharX => (0x58, false),
        CharY => (0x59, false),
        CharZ => (0x5A, false),
        Digit0 => (0x30, false),
        Digit1 => (0x31, false),
        Digit2 => (0x32, false),
        Digit3 => (0x33, false),
        Digit4 => (0x34, false),
        Digit5 => (0x35, false),
        Digit6 => (0x36, false),
        Digit7 => (0x37, false),
        Digit8 => (0x38, false),
        Digit9 => (0x39, false),
        Minus => (0xBD, false),
        Equal => (0xBB, false),
        LeftBracket => (0xDB, false),
        RightBracket => (0xDD, false),
        Backslash => (0xDC, false),
        Semicolon => (0xBA, false),
        Quote => (0xDE, false),
        Comma => (0xBC, false),
        Period => (0xBE, false),
        Slash => (0xBF, false),
        Grave => (0xC0, false),
        Return => (0x0D, false),
        Tab => (0x09, false),
        Space => (0x20, false),
        Backspace => (0x08, false),
        Delete => (0x2E, true),
        Escape => (0x1B, false),
        Up => (0x26, true),
        Down => (0x28, true),
        Left => (0x25, true),
        Right => (0x27, true),
        Home => (0x24, true),
        End => (0x23, true),
        PageUp => (0x21, true),
        PageDown => (0x22, true),
        CapsLock => (0x14, false),
        ShiftLeft => (0xA0, false),
        ShiftRight => (0xA1, false),
        ControlLeft => (0xA2, false),
        ControlRight => (0xA3, true),
        AltLeft => (0xA4, false),
        AltRight => (0xA5, true),
        MetaLeft => (0x5B, true),
        MetaRight => (0x5C, true),
        F1 => (0x70, false),
        F2 => (0x71, false),
        F3 => (0x72, false),
        F4 => (0x73, false),
        F5 => (0x74, false),
        F6 => (0x75, false),
        F7 => (0x76, false),
        F8 => (0x77, false),
        F9 => (0x78, false),
        F10 => (0x79, false),
        F11 => (0x7A, false),
        F12 => (0x7B, false),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn right_shift_is_not_extended_while_right_ctrl_and_alt_are() {
        assert_eq!(logical_to_win_vk(LogicalKey::ShiftLeft), Some((0xA0, false)));
        assert_eq!(logical_to_win_vk(LogicalKey::ShiftRight), Some((0xA1, false)));
        assert_eq!(logical_to_win_vk(LogicalKey::ControlRight), Some((0xA3, true)));
        assert_eq!(logical_to_win_vk(LogicalKey::AltRight), Some((0xA5, true)));
        assert_eq!(logical_to_win_vk(LogicalKey::MetaLeft), Some((0x5B, true)));
    }

    #[test]
    fn win_flags_to_modifiers_decodes_all_bits() {
        let mask = win_flags_to_modifiers(0b1111);
        assert!(mask.shift && mask.control && mask.alt && mask.meta);
        assert_eq!(win_flags_to_modifiers(0), ModifierMask::default());
    }
}
