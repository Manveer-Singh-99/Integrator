//! # macOS Quartz & IOKit KVM Input Backend
//!
//! ## 1. Module Purpose & Scope
//! This module provides the macOS-specific hardware input capture, cursor warping, synthetic
//! event injection, and native drag-and-drop integration for the Integrator Universal Input KVM.
//!
//! ### Core Subsystem Responsibilities:
//! - **Low-Level Event Interception**: Establishes a passive/active Quartz event tap (`CGEventTap`)
//!   via Mach port callbacks in `kvm_macos.swift` to intercept raw mouse moves, clicks, scroll wheel
//!   deltas, and keyboard transitions before they reach AppKit or windowed applications.
//! - **Event Swallowing & Cursor Parking**: When the cursor hops past a configured display edge into
//!   the `ControllingPeer` state, local input events are swallowed (`kCGEventNull`) and the local cursor
//!   is parked or warped to prevent it from wandering off-screen or interacting with local windows.
//! - **Synthetic Quartz Injection**: Replays remote mouse and keyboard events originating from the
//!   paired Windows workstation using `CGEventCreateMouseEvent`, `CGEventCreateKeyboardEvent`,
//!   `CGEventCreateScrollWheelEvent2`, and `CGEventPost(kCGHIDEventTap, ...)`.
//! - **Active Drag Session Bridging**: Detects when a boundary crossing occurs while holding a file
//!   selection, extracting file paths from the active `NSPasteboard` drag pasteboard and displaying
//!   translucent floating ghost HUDs.
//!
//! ## 2. Architectural Linkages & Dependencies
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────────────────────────────────┐
//! │                           macOS KVM Backend Architecture                               │
//! └────────────────────────────────────────────────────────────────────────────────────────┘
//!
//!                     ┌────────────────────────────────────────┐
//!                     │         KvmService (service.rs)        │
//!                     └───────────────▲────────┬───────────────┘
//!                                     │        │
//!      on_cg_event / on_drag_ended    │        │ inject_mouse_move / inject_key
//!                                     │        │
//!                     ┌───────────────┴────────▼───────────────┐
//!                     │      macos_backend.rs (Rust FFI)       │
//!                     └───────────────▲────────┬───────────────┘
//!                                     │        │
//!         C FFI Event Callbacks       │        │ C FFI Injection Calls
//!                                     │        │
//!                     ┌───────────────┴────────▼───────────────┐
//!                     │       kvm_macos.swift (Swift/ObjC)     │
//!                     │  - CGEventTap on Mach Port RunLoop     │
//!                     │  - CGSSetConnectionProperty (Bg Cursor)│
//!                     │  - IOKit HID (Caps Lock State Sync)    │
//!                     │  - NSDraggingSession & Drag Ghost HUD  │
//!                     └────────────────────────────────────────┘
//! ```
//!
//! ### Upstream Callers:
//! - `src/kvm/service.rs`: Invokes `start`, `stop`, `set_controlling_mode`, `set_controlled_mode`,
//!   `inject_mouse_move`, `inject_mouse_button`, `inject_scroll`, `inject_key`, and drag ghost controls.
//!
//! ### Downstream Callees:
//! - `src/kvm_macos.swift`: Interacts directly with macOS system APIs via C-ABI functions:
//!   - `integrator_kvm_macos_start_tap` / `integrator_kvm_macos_stop_tap`: Manages `CFMachPort` lifecycle.
//!   - `integrator_kvm_macos_inject_*`: Synthesizes Quartz input events tagged with `0x494E5447` ("INTG").
//!   - `integrator_kvm_macos_show_drag_ghost` / `integrator_kvm_macos_hide_drag_ghost`: Controls AppKit HUD.
//!
//! ## 3. Threading & Concurrency Model
//! - The macOS `CGEventTap` runs inside a dedicated OS thread hosting a `CFRunLoop`.
//! - Input events invoke the `on_cg_event` C callback synchronously on the run-loop thread.
//! - `TAP_ACTIVE` is an `AtomicBool` providing instantaneous status queries without locking.
//! - `START_TAP_LOCK` ensures serial execution during tap setup, teardown, and retry attempts.
//!
//! ## 4. Security & Safety Invariants
//! - **Accessibility Privileges**: Requires Accessibility permissions (`AXIsProcessTrusted`). If permissions
//!   are missing, a non-blocking retry thread is spawned and prompts the user without crashing.
//! - **Anti-Feedback Tagging**: All synthetic events are tagged with `kIntegratorEventTag = 0x494E5447`.
//!   The event tap ignores tagged events to prevent infinite feedback loops.
//! - **Null-Pointer & Memory Safety**: All C strings returned from Swift are freed using
//!   `integrator_kvm_macos_free_str`, preventing heap leaks across the FFI boundary.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use crate::kvm::layout::ScreenRect;
use crate::kvm::protocol::{LogicalKey, ModifierMask, RemoteMouseButton};
use crate::kvm::service::{HookDecision, KvmService};

/// Polling interval between background `CGEventTap` retries while awaiting Accessibility permission (2 seconds).
const ACCESSIBILITY_RETRY_INTERVAL: Duration = Duration::from_secs(2);

/// Maximum absolute scroll wheel delta clamped per axis to prevent Quartz driver overflow (`5000.0`).
const MAX_SCROLL_DELTA: f32 = 5000.0;

/// Global handle to the active `KvmService` instance for event routing.
static KVM_SERVICE_REF: OnceLock<Arc<KvmService>> = OnceLock::new();

/// Atomic indicator showing whether the macOS `CGEventTap` is currently installed and healthy.
static TAP_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Atomic shutdown latch preventing the background Accessibility retry loop from re-installing
/// the event tap after `stop()` has been requested.
static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Mutual exclusion lock guarding event tap initialization and teardown routines.
static START_TAP_LOCK: Mutex<()> = Mutex::new(());

/// C-compatible function pointer for raw event ingestion from Swift.
type KvmEventCallback = extern "C" fn(i32, f64, f64, f64, f64, u64) -> i32;

/// C-compatible function pointer for drag-and-drop termination callbacks from Swift.
type KvmDragEndedCallback = extern "C" fn(bool, *const c_char);

// C-ABI entry points exported by `src/kvm_macos.swift` (`libtouchbar.a`).
extern "C" {
    fn integrator_kvm_macos_start_tap(
        cb: Option<KvmEventCallback>,
        drag_ended_cb: Option<KvmDragEndedCallback>,
    ) -> bool;
    fn integrator_kvm_macos_stop_tap();
    fn integrator_kvm_macos_is_tap_active() -> bool;
    fn integrator_kvm_macos_request_accessibility() -> bool;
    fn integrator_kvm_macos_screen_rect(
        out_x: *mut f64,
        out_y: *mut f64,
        out_w: *mut f64,
        out_h: *mut f64,
    );
    fn integrator_kvm_macos_set_controlling(
        controlling: bool,
        park_x: f64,
        park_y: f64,
        restore_x: f64,
        restore_y: f64,
    );
    fn integrator_kvm_macos_set_controlled(controlled: bool, entry_x: f64, entry_y: f64);
    fn integrator_kvm_macos_probe_drag_paths() -> *mut c_char;
    fn integrator_kvm_macos_cancel_local_drag();
    fn integrator_kvm_macos_icon_png_b64(path: *const c_char) -> *mut c_char;
    fn integrator_kvm_macos_free_str(ptr: *mut c_char);
    fn integrator_kvm_macos_inject_mouse_move(x: f64, y: f64, left_held: bool);
    fn integrator_kvm_macos_inject_mouse_button(button: i32, pressed: bool, x: f64, y: f64);
    fn integrator_kvm_macos_inject_scroll(dx: f64, dy: f64);
    fn integrator_kvm_macos_inject_key(
        key_code: u16,
        pressed: bool,
        shift: bool,
        ctrl: bool,
        alt: bool,
        meta: bool,
    );
    fn integrator_kvm_macos_show_drag_ghost(
        cg_x: f64,
        cg_y: f64,
        title: *const c_char,
        subtitle: *const c_char,
        icon_b64: *const c_char,
    );
    fn integrator_kvm_macos_move_drag_ghost(cg_x: f64, cg_y: f64);
    fn integrator_kvm_macos_hide_drag_ghost();
    fn integrator_kvm_macos_begin_native_drag(
        paths_json: *const c_char,
        session_id: *const c_char,
        cg_x: f64,
        cg_y: f64,
    );
}

/// Initializes the macOS KVM input backend, registering callbacks and installing the `CGEventTap`.
///
/// If Accessibility permissions have not yet been granted by macOS System Settings,
/// a background retry daemon is spawned to automatically attach the tap as soon as
/// the user enables the permission, requiring no application restart.
///
/// # Arguments
/// * `service` - Reference to the core `KvmService` coordinator.
pub fn start(service: Arc<KvmService>) {
    let _ = KVM_SERVICE_REF.set(service);
    let _guard = START_TAP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    STOP_REQUESTED.store(false, Ordering::Release);
    let ok = unsafe {
        integrator_kvm_macos_start_tap(Some(on_cg_event), Some(on_drag_ended))
    };
    TAP_ACTIVE.store(ok, Ordering::Release);
    if ok {
        tracing::info!("🖱️ macOS CGEventTap & Native Sequoia NSDraggingSession KVM hook active");
    } else {
        tracing::warn!(
            "⚠️ Failed to initialize macOS CGEventTap (grant Accessibility permission to Integrator in System Settings -> Privacy & Security)"
        );
        // Auto-retry until Accessibility permission is granted (or stop() is called) so KVM activates without restart.
        std::thread::Builder::new()
            .name("kvm-macos-tap-retry".into())
            .spawn(|| {
                loop {
                    std::thread::sleep(ACCESSIBILITY_RETRY_INTERVAL);
                    if STOP_REQUESTED.load(Ordering::Acquire) {
                        break;
                    }
                    let active_now = unsafe { integrator_kvm_macos_is_tap_active() };
                    if active_now {
                        TAP_ACTIVE.store(true, Ordering::Release);
                        break;
                    }
                    let _g = START_TAP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
                    if STOP_REQUESTED.load(Ordering::Acquire) {
                        break;
                    }
                    let activated = unsafe {
                        integrator_kvm_macos_start_tap(Some(on_cg_event), Some(on_drag_ended))
                    };
                    if activated {
                        TAP_ACTIVE.store(true, Ordering::Release);
                        tracing::info!("🖱️ macOS CGEventTap activated after Accessibility grant");
                        break;
                    }
                }
            })
            .ok();
    }
}

/// Disables and removes the macOS `CGEventTap`, restoring standard OS input dispatch.
pub fn stop() {
    let _guard = START_TAP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    STOP_REQUESTED.store(true, Ordering::Release);
    TAP_ACTIVE.store(false, Ordering::Release);
    unsafe {
        integrator_kvm_macos_stop_tap();
    }
}

/// Returns whether the macOS `CGEventTap` is currently installed and actively capturing events.
pub fn is_hook_active() -> bool {
    let active = unsafe { integrator_kvm_macos_is_tap_active() };
    TAP_ACTIVE.store(active, Ordering::Release);
    active
}

/// Triggers macOS system prompt requesting Accessibility permissions for Integrator.
///
/// # Returns
/// `true` if permissions are already trusted, `false` if prompted or denied.
pub fn request_accessibility() -> bool {
    let trusted = unsafe { integrator_kvm_macos_request_accessibility() };
    if trusted {
        let _guard = START_TAP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let activated = unsafe {
            integrator_kvm_macos_start_tap(Some(on_cg_event), Some(on_drag_ended))
        };
        TAP_ACTIVE.store(activated, Ordering::Release);
        if activated {
            tracing::info!("🖱️ macOS CGEventTap activated after Accessibility prompt");
        }
    }
    trusted
}

/// Queries the union virtual-desktop bounding box across all active macOS displays in Quartz
/// global coordinates (logical points/DIPs, supporting negative-origin secondary monitors).
///
/// # Returns
/// A `ScreenRect` representing the active display bounds, falling back to safe defaults if
/// Quartz returns non-finite or sub-minimum dimensions.
pub fn get_primary_screen_rect() -> ScreenRect {
    let mut x = 0.0;
    let mut y = 0.0;
    let mut w = crate::config::DEFAULT_MACOS_DISPLAY_WIDTH;
    let mut h = crate::config::DEFAULT_MACOS_DISPLAY_HEIGHT;
    unsafe {
        integrator_kvm_macos_screen_rect(&mut x, &mut y, &mut w, &mut h);
    }
    ScreenRect {
        x: if x.is_finite() { x as f32 } else { 0.0 },
        y: if y.is_finite() { y as f32 } else { 0.0 },
        width: (w as f32).max(crate::config::MIN_KVM_DISPLAY_WIDTH),
        height: (h as f32).max(crate::config::MIN_KVM_DISPLAY_HEIGHT),
    }
}

/// Configures the hook state when the local Mac is actively controlling the remote peer.
///
/// In controlling mode, the local mouse cursor is hidden and parked at `(park_x, park_y)`
/// to prevent it from wandering across local windows or triggering native gestures.
pub fn set_controlling_mode(
    controlling: bool,
    park_x: f32,
    park_y: f32,
    restore_x: f32,
    restore_y: f32,
) {
    if !park_x.is_finite() || !park_y.is_finite() || !restore_x.is_finite() || !restore_y.is_finite() {
        return;
    }
    unsafe {
        integrator_kvm_macos_set_controlling(
            controlling,
            park_x as f64,
            park_y as f64,
            restore_x as f64,
            restore_y as f64,
        );
    }
}

/// Configures the hook state when the local Mac is controlled by the remote peer.
///
/// Warps the cursor to the entry coordinate `(entry_x, entry_y)` and ensures the cursor is visible.
pub fn set_controlled_mode(controlled: bool, entry_x: f32, entry_y: f32) {
    if !entry_x.is_finite() || !entry_y.is_finite() {
        return;
    }
    unsafe {
        integrator_kvm_macos_set_controlled(controlled, entry_x as f64, entry_y as f64);
    }
}

/// Inspects the active `NSDraggingSession` or pasteboard to retrieve files currently being dragged.
///
/// # Returns
/// A list of filesystem paths being dragged, or an empty vector if no drag is active.
pub fn probe_active_drag_paths() -> Vec<PathBuf> {
    let ptr = unsafe { integrator_kvm_macos_probe_drag_paths() };
    if ptr.is_null() {
        return Vec::new();
    }
    let json = unsafe {
        let s = CStr::from_ptr(ptr).to_string_lossy().into_owned();
        integrator_kvm_macos_free_str(ptr);
        s
    };
    serde_json::from_str::<Vec<String>>(&json)
        .unwrap_or_default()
        .into_iter()
        .map(PathBuf::from)
        .filter(|p| p.exists())
        .collect()
}

/// Cancels the local AppKit drag session after responsibility has been handed off to the peer.
pub fn cancel_local_drag_after_handoff() {
    unsafe {
        integrator_kvm_macos_cancel_local_drag();
    }
}

/// Extracts a high-resolution icon thumbnail from a local file, encoded as Base64 PNG.
///
/// # Arguments
/// * `path` - Path to the file or directory.
///
/// # Returns
/// `Some(base64_string)` if an icon was generated, otherwise `None`.
pub fn extract_file_icon_png_b64(path: &std::path::Path) -> Option<String> {
    let c_path = CString::new(path.to_string_lossy().as_bytes()).ok()?;
    let ptr = unsafe { integrator_kvm_macos_icon_png_b64(c_path.as_ptr()) };
    if ptr.is_null() {
        return None;
    }
    let b64 = unsafe {
        let s = CStr::from_ptr(ptr).to_string_lossy().into_owned();
        integrator_kvm_macos_free_str(ptr);
        s
    };
    if b64.is_empty() { None } else { Some(b64) }
}

/// Injects synthetic pointer movement into Quartz at absolute coordinates `(x, y)`.
///
/// If `left_held` is true, posts a `kCGEventLeftMouseDragged` event; otherwise `kCGEventMouseMoved`.
pub fn inject_mouse_move(x: f32, y: f32, left_held: bool) {
    if !x.is_finite() || !y.is_finite() {
        return;
    }
    unsafe {
        integrator_kvm_macos_inject_mouse_move(x as f64, y as f64, left_held);
    }
}

/// Injects synthetic mouse button transitions into Quartz.
///
/// # Arguments
/// * `button` - Target mouse button (Left, Right, Middle).
/// * `pressed` - True for mouse down, false for mouse up.
/// * `x` - Current pointer X position.
/// * `y` - Current pointer Y position.
pub fn inject_mouse_button(button: RemoteMouseButton, pressed: bool, x: f32, y: f32) {
    if !x.is_finite() || !y.is_finite() {
        return;
    }
    let btn = match button {
        RemoteMouseButton::Left => 0,
        RemoteMouseButton::Right => 1,
        RemoteMouseButton::Middle => 2,
    };
    unsafe {
        integrator_kvm_macos_inject_mouse_button(btn, pressed, x as f64, y as f64);
    }
}

/// Injects synthetic high-resolution scroll wheel deltas into Quartz.
///
/// Values are clamped within `[-5000.0, 5000.0]` to prevent driver-level overflow.
pub fn inject_scroll(dx: f32, dy: f32) {
    let safe_dx = if dx.is_finite() { dx.clamp(-MAX_SCROLL_DELTA, MAX_SCROLL_DELTA) } else { 0.0 };
    let safe_dy = if dy.is_finite() { dy.clamp(-MAX_SCROLL_DELTA, MAX_SCROLL_DELTA) } else { 0.0 };
    unsafe {
        integrator_kvm_macos_inject_scroll(safe_dx as f64, safe_dy as f64);
    }
}

/// Injects a synthetic keyboard key transition into Quartz Event Services.
///
/// Translates the canonical `LogicalKey` to the corresponding macOS virtual `CGKeyCode`,
/// sets modifier flags, and posts to `kCGHIDEventTap`.
pub fn inject_key(key: LogicalKey, pressed: bool, mods: ModifierMask) {
    if let Some(kc) = logical_to_macos_keycode(key) {
        unsafe {
            integrator_kvm_macos_inject_key(
                kc,
                pressed,
                mods.shift,
                mods.control,
                mods.alt,
                mods.meta,
            );
        }
    }
}

/// Displays the floating translucent drag ghost HUD at `(x, y)`.
pub fn show_drag_ghost(x: f32, y: f32, title: &str, subtitle: &str, icon_b64: Option<&str>) {
    if !x.is_finite() || !y.is_finite() {
        return;
    }
    let Ok(c_title) = CString::new(title) else { return };
    let Ok(c_sub) = CString::new(subtitle) else { return };
    let c_icon = icon_b64.and_then(|s| CString::new(s).ok());
    unsafe {
        integrator_kvm_macos_show_drag_ghost(
            x as f64,
            y as f64,
            c_title.as_ptr(),
            c_sub.as_ptr(),
            c_icon.as_ref().map(|c| c.as_ptr()).unwrap_or(std::ptr::null()),
        );
    }
}

/// Moves the active drag ghost HUD to new pointer coordinates `(x, y)`.
pub fn move_drag_ghost(x: f32, y: f32) {
    if !x.is_finite() || !y.is_finite() {
        return;
    }
    unsafe {
        integrator_kvm_macos_move_drag_ghost(x as f64, y as f64);
    }
}

/// Hides and dismisses the drag ghost HUD window.
pub fn hide_drag_ghost() {
    unsafe {
        integrator_kvm_macos_hide_drag_ghost();
    }
}

/// Initiates an AppKit native `NSDraggingSession` on the receiving Mac using staged payload files.
///
/// # Arguments
/// * `paths` - Filesystem paths to the staged files on local disk.
/// * `session_id` - Drag session identifier for completion tracking.
/// * `x` - Initial cursor X position in Quartz coordinates.
/// * `y` - Initial cursor Y position in Quartz coordinates.
///
/// # Returns
/// `true` if the drag request was dispatched to Swift AppKit, or `false` if coordinates,
/// paths, or C-string conversion failed.
pub fn begin_native_drop_drag(paths: &[PathBuf], session_id: &str, x: f32, y: f32) -> bool {
    if !x.is_finite() || !y.is_finite() {
        return false;
    }
    let str_paths: Vec<String> = paths
        .iter()
        .filter_map(|p| p.to_str().map(|s| s.to_string()))
        .collect();
    if str_paths.is_empty() {
        return false;
    }
    let Ok(json) = serde_json::to_string(&str_paths) else { return false };
    let Ok(c_paths) = CString::new(json) else { return false };
    let Ok(c_sid) = CString::new(session_id) else { return false };
    unsafe {
        integrator_kvm_macos_begin_native_drag(
            c_paths.as_ptr(),
            c_sid.as_ptr(),
            x as f64,
            y as f64,
        );
    }
    true
}

/// Callback triggered by Swift when an active AppKit dragging session finishes or is cancelled.
extern "C" fn on_drag_ended(accepted: bool, session_id_ptr: *const c_char) {
    let Some(svc) = KVM_SERVICE_REF.get() else { return };
    let sid = if session_id_ptr.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(session_id_ptr).to_string_lossy().into_owned() }
    };
    svc.on_native_drag_ended(&sid, accepted);
}

/// Core C-ABI callback receiving intercepted raw Quartz events from `kvm_macos.swift`.
///
/// Event kinds:
/// - `1`: Mouse movement (absolute X/Y, relative dX/dY, button bitmask)
/// - `2`: Mouse button transition (button index, pressed boolean, X, Y)
/// - `3`: Mouse scroll deltas (dX, dY)
/// - `4`: Key down / up (virtual keycode, pressed boolean, modifier flags)
/// - `5`: Modifier flags changed (e.g. Shift, Control, Alt, Command, CapsLock)
///
/// Returns:
/// - `0`: Pass event through natively to macOS applications
/// - `1`: Swallow event (`kCGEventNull`)
/// - `2`: Swallow event and warp cursor to center park position
extern "C" fn on_cg_event(kind: i32, a: f64, b: f64, c: f64, d: f64, extra: u64) -> i32 {
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
            // Bounds-check keycode before truncating to u16 so malformed FFI floats cannot alias.
            if a.is_finite() && a >= 0.0 && a <= u16::MAX as f64 {
                let kc = a as u16;
                if let Some(key) = macos_keycode_to_logical(kc) {
                    svc.on_local_key_event(key, b > 0.5, cg_flags_to_modifiers(extra))
                } else if svc.is_controlling_peer_fast() {
                    HookDecision::Swallow
                } else {
                    HookDecision::PassThrough
                }
            } else if svc.is_controlling_peer_fast() {
                HookDecision::Swallow
            } else {
                HookDecision::PassThrough
            }
        }
        5 => {
            if a.is_finite() && a >= 0.0 && a <= u16::MAX as f64 {
                let kc = a as u16;
                let mods = cg_flags_to_modifiers(extra);
                if kc == 57 {
                    // CapsLock flagsChanged fires once per lock toggle; emit a tap so peers toggle in sync.
                    let decision = svc.on_local_key_event(LogicalKey::CapsLock, true, mods);
                    let _ = svc.on_local_key_event(LogicalKey::CapsLock, false, mods);
                    decision
                } else if let Some((key, pressed)) = macos_flags_changed_key(kc, extra, mods) {
                    svc.on_local_key_event(key, pressed, mods)
                } else if svc.is_controlling_peer_fast() {
                    HookDecision::Swallow
                } else {
                    HookDecision::PassThrough
                }
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

/// Converts raw 64-bit CoreGraphics event flags into canonical `ModifierMask`.
///
/// Uses standard `CGEventFlags` bit positions:
/// - `0x0002_0000`: `kCGEventFlagMaskShift`
/// - `0x0004_0000`: `kCGEventFlagMaskControl`
/// - `0x0008_0000`: `kCGEventFlagMaskAlternate`
/// - `0x0010_0000`: `kCGEventFlagMaskCommand`
fn cg_flags_to_modifiers(raw: u64) -> ModifierMask {
    ModifierMask {
        shift: (raw & 0x0002_0000) != 0,
        control: (raw & 0x0004_0000) != 0,
        alt: (raw & 0x0008_0000) != 0,
        meta: (raw & 0x0010_0000) != 0,
    }
}

/// Resolves which modifier key changed state using NX device-dependent left/right bits when
/// present (so releasing one side while the other is held still reports `pressed = false`),
/// falling back to the generic modifier flag otherwise.
fn macos_flags_changed_key(kc: u16, raw_flags: u64, mods: ModifierMask) -> Option<(LogicalKey, bool)> {
    let side_pressed = |this_mask: u64, pair_mask: u64, generic: bool| -> bool {
        if (raw_flags & pair_mask) != 0 {
            (raw_flags & this_mask) != 0
        } else {
            generic
        }
    };
    const L_SHIFT: u64 = 0x0000_0002;
    const R_SHIFT: u64 = 0x0000_0004;
    const L_CTRL: u64 = 0x0000_0001;
    const R_CTRL: u64 = 0x0000_2000;
    const L_ALT: u64 = 0x0000_0020;
    const R_ALT: u64 = 0x0000_0040;
    const L_CMD: u64 = 0x0000_0008;
    const R_CMD: u64 = 0x0000_0010;
    match kc {
        56 => Some((LogicalKey::ShiftLeft, side_pressed(L_SHIFT, L_SHIFT | R_SHIFT, mods.shift))),
        60 => Some((LogicalKey::ShiftRight, side_pressed(R_SHIFT, L_SHIFT | R_SHIFT, mods.shift))),
        59 => Some((LogicalKey::ControlLeft, side_pressed(L_CTRL, L_CTRL | R_CTRL, mods.control))),
        62 => Some((LogicalKey::ControlRight, side_pressed(R_CTRL, L_CTRL | R_CTRL, mods.control))),
        58 => Some((LogicalKey::AltLeft, side_pressed(L_ALT, L_ALT | R_ALT, mods.alt))),
        61 => Some((LogicalKey::AltRight, side_pressed(R_ALT, L_ALT | R_ALT, mods.alt))),
        55 => Some((LogicalKey::MetaLeft, side_pressed(L_CMD, L_CMD | R_CMD, mods.meta))),
        54 => Some((LogicalKey::MetaRight, side_pressed(R_CMD, L_CMD | R_CMD, mods.meta))),
        _ => None,
    }
}

/// Translates a macOS physical/virtual `CGKeyCode` into a canonical `LogicalKey`.
pub fn macos_keycode_to_logical(kc: u16) -> Option<LogicalKey> {
    use LogicalKey::*;
    Some(match kc {
        0 => CharA,
        11 => CharB,
        8 => CharC,
        2 => CharD,
        14 => CharE,
        3 => CharF,
        5 => CharG,
        4 => CharH,
        34 => CharI,
        38 => CharJ,
        40 => CharK,
        37 => CharL,
        46 => CharM,
        45 => CharN,
        31 => CharO,
        35 => CharP,
        12 => CharQ,
        15 => CharR,
        1 => CharS,
        17 => CharT,
        32 => CharU,
        9 => CharV,
        13 => CharW,
        7 => CharX,
        16 => CharY,
        6 => CharZ,
        29 => Digit0,
        18 => Digit1,
        19 => Digit2,
        20 => Digit3,
        21 => Digit4,
        23 => Digit5,
        22 => Digit6,
        26 => Digit7,
        28 => Digit8,
        25 => Digit9,
        27 => Minus,
        24 => Equal,
        33 => LeftBracket,
        30 => RightBracket,
        42 => Backslash,
        41 => Semicolon,
        39 => Quote,
        43 => Comma,
        47 => Period,
        44 => Slash,
        50 => Grave,
        36 | 76 => Return,
        48 => Tab,
        49 => Space,
        51 => Backspace,
        117 => Delete,
        53 => Escape,
        126 => Up,
        125 => Down,
        123 => Left,
        124 => Right,
        115 => Home,
        119 => End,
        116 => PageUp,
        121 => PageDown,
        57 => CapsLock,
        56 => ShiftLeft,
        60 => ShiftRight,
        59 => ControlLeft,
        62 => ControlRight,
        58 => AltLeft,
        61 => AltRight,
        55 => MetaLeft,
        54 => MetaRight,
        122 => F1,
        120 => F2,
        99 => F3,
        118 => F4,
        96 => F5,
        97 => F6,
        98 => F7,
        100 => F8,
        101 => F9,
        109 => F10,
        103 => F11,
        111 => F12,
        _ => return None,
    })
}

/// Translates a canonical `LogicalKey` into a macOS `CGKeyCode`.
pub fn logical_to_macos_keycode(key: LogicalKey) -> Option<u16> {
    use LogicalKey::*;
    Some(match key {
        CharA => 0,
        CharB => 11,
        CharC => 8,
        CharD => 2,
        CharE => 14,
        CharF => 3,
        CharG => 5,
        CharH => 4,
        CharI => 34,
        CharJ => 38,
        CharK => 40,
        CharL => 37,
        CharM => 46,
        CharN => 45,
        CharO => 31,
        CharP => 35,
        CharQ => 12,
        CharR => 15,
        CharS => 1,
        CharT => 17,
        CharU => 32,
        CharV => 9,
        CharW => 13,
        CharX => 7,
        CharY => 16,
        CharZ => 6,
        Digit0 => 29,
        Digit1 => 18,
        Digit2 => 19,
        Digit3 => 20,
        Digit4 => 21,
        Digit5 => 23,
        Digit6 => 22,
        Digit7 => 26,
        Digit8 => 28,
        Digit9 => 25,
        Minus => 27,
        Equal => 24,
        LeftBracket => 33,
        RightBracket => 30,
        Backslash => 42,
        Semicolon => 41,
        Quote => 39,
        Comma => 43,
        Period => 47,
        Slash => 44,
        Grave => 50,
        Return => 36,
        Tab => 48,
        Space => 49,
        Backspace => 51,
        Delete => 117,
        Escape => 53,
        Up => 126,
        Down => 125,
        Left => 123,
        Right => 124,
        Home => 115,
        End => 119,
        PageUp => 116,
        PageDown => 121,
        CapsLock => 57,
        ShiftLeft => 56,
        ShiftRight => 60,
        ControlLeft => 59,
        ControlRight => 62,
        AltLeft => 58,
        AltRight => 61,
        MetaLeft => 55,
        MetaRight => 54,
        F1 => 122,
        F2 => 120,
        F3 => 99,
        F4 => 118,
        F5 => 96,
        F6 => 97,
        F7 => 98,
        F8 => 100,
        F9 => 101,
        F10 => 109,
        F11 => 103,
        F12 => 111,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macos_flags_changed_key_tracks_simultaneous_left_and_right_modifiers() {
        // Holding Right Shift (`0x4`) while releasing Left Shift still has generic shift (`0x2_0000`).
        let flags = 0x0002_0000 | 0x0000_0004;
        let mods = cg_flags_to_modifiers(flags);
        assert!(mods.shift);
        assert_eq!(
            macos_flags_changed_key(56, flags, mods),
            Some((LogicalKey::ShiftLeft, false))
        );
        assert_eq!(
            macos_flags_changed_key(60, flags, mods),
            Some((LogicalKey::ShiftRight, true))
        );
    }

    #[test]
    fn macos_flags_changed_key_falls_back_to_generic_mask_without_device_bits() {
        let flags = 0x0008_0000 | 0x0010_0000;
        let mods = cg_flags_to_modifiers(flags);
        assert_eq!(
            macos_flags_changed_key(58, flags, mods),
            Some((LogicalKey::AltLeft, true))
        );
        assert_eq!(
            macos_flags_changed_key(54, flags, mods),
            Some((LogicalKey::MetaRight, true))
        );
        assert_eq!(macos_flags_changed_key(57, flags, mods), None);
    }
}
