//
//  kvm_windows.cpp
//  Integrator Universal Input KVM - Windows Win32 Low-Level Driver & OLE D&D Bridge
//
//  ========================================================================================
//  1. MODULE PURPOSE & ARCHITECTURAL SCOPE
//  ========================================================================================
//  This file implements the native Win32/C++ backend for the Integrator Universal Input KVM
//  subsystem on Windows 10 and Windows 11. It owns the low-level hardware input interception
//  hooks, invisible edge/guard overlay windows, synthetic `SendInput` event injection pipeline,
//  translucent GDI drag-ghost HUD window, and COM/OLE drag-and-drop (`IDropTarget` / `IDropSource`)
//  state machine.
//
//  Key Subsystem Capabilities & State Lifecycle:
//  - Low-Level OS Input Interception: Installs `WH_MOUSE_LL` and `WH_KEYBOARD_LL` hooks via
//    `SetWindowsHookExW` on a dedicated high-priority message-pump thread (`g_hook_thread`) to
//    capture raw physical mouse movements, button transitions, wheel deltas, and keyboard events
//    before desktop windows receive them.
//  - Edge Probe & Full-Screen Guard Windows: Creates 1-alpha layered, topmost, capture-excluded
//    popup windows (`WS_EX_LAYERED | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE`) positioned along
//    active virtual-desktop boundaries to catch outgoing Windows Explorer OLE drags (`EdgeDropTarget`)
//    and a full-screen blank-cursor guard window (`guard_wnd_proc`) that hides and parks the
//    local cursor while controlling the remote peer.
//  - Synthetic Input Injection: Synthesizes remote pointer movement, clicks, smooth two-axis
//    scrolling, and keyboard keystrokes using Win32 `SendInput` with virtual-key codes (`VK_*`),
//    hardware scancodes (`MapVirtualKeyW`), and `KEYEVENTF_EXTENDEDKEY` flags.
//  - Fluent Drag Ghost HUD: Renders a translucent layered GDI popup window (`WS_EX_LAYERED |
//    WS_EX_TRANSPARENT`) displaying live file drag titles and transfer status badges beneath the
//    cursor while remote drag payloads stream across the network.
//  - OLE COM Drag-and-Drop Bridging: Implements `IDropTarget` (`EdgeDropTarget`) to intercept
//    outgoing Windows Explorer `CF_HDROP` drags at the screen edge, and `IDropSource`
//    (`RemoteDropSource`) paired with `SHCreateDataObject` to execute native `DoDragDrop`
//    loops onto arbitrary Windows target applications.
//
//  ========================================================================================
//  2. ARCHITECTURAL LINKAGES & DEPENDENCIES
//  ========================================================================================
//  Upstream Callers:
//  - `src/kvm/windows_backend.rs`: Rust FFI bridge that invokes `extern "C"` functions:
//    - `integrator_kvm_win_start_hooks` / `integrator_kvm_win_stop_hooks`: Manages hook & OLE threads.
//    - `integrator_kvm_win_is_hook_active`: Queries whether both mouse and keyboard hooks are installed.
//    - `integrator_kvm_win_screen_rect`: Queries virtual-desktop or primary monitor geometry in pixels.
//    - `integrator_kvm_win_set_edge_probe`: Configures and hides/shows the screen-edge OLE catcher.
//    - `integrator_kvm_win_set_controlling`: Hides, parks, or restores the local Windows cursor.
//    - `integrator_kvm_win_set_controlled`: Warps cursor upon remote pointer entry and resets drag flags.
//    - `integrator_kvm_win_take_drag_paths` / `integrator_kvm_win_free_str`: Drains captured `CF_HDROP` JSON.
//    - `integrator_kvm_win_cancel_local_drag` / `integrator_kvm_win_cancel_remote_drag`: Aborts OLE drags.
//    - `integrator_kvm_win_inject_*`: Synthesizes mouse move, button, scroll, and keyboard events.
//    - `integrator_kvm_win_show_drag_ghost` / `move_drag_ghost` / `hide_drag_ghost`: Drives GDI HUD.
//    - `integrator_kvm_win_begin_native_drag`: Initiates asynchronous `DoDragDrop` on the OLE thread.
//  - `src/clipboard/service.rs`: Rust clipboard service that invokes `set_has_pending_remote_file`
//    when a large (>128 MB) remote macOS file announcement is waiting for an on-demand `Ctrl+V` pull.
//
//  Downstream Callees:
//  - Win32 User32 (`SetWindowsHookExW`, `UnhookWindowsHookEx`, `CallNextHookEx`, `SendInput`,
//    `CreateWindowExW`, `SetLayeredWindowAttributes`, `SetWindowDisplayAffinity`, `SetCursorPos`,
//    `GetSystemMetrics`, `GetAsyncKeyState`, `MapVirtualKeyW`, `PostMessageW`, `PostThreadMessageW`).
//  - Win32 GDI32 (`CreateSolidBrush`, `CreateFontW`, `FillRect`, `FrameRect`, `DrawTextW`, `DeleteObject`).
//  - Win32 OLE32 / Shell32 (`OleInitialize`, `OleUninitialize`, `RegisterDragDrop`, `RevokeDragDrop`,
//    `DoDragDrop`, `SHCreateDataObject`, `DragQueryFileW`, `ILCreateFromPathW`, `ILCloneFull`, `ILFree`).
//  - Rust C FFI Callbacks:
//    - `KvmWinEventCallback` (`on_win_event` in `windows_backend.rs`): Evaluates hook interception decisions.
//    - `KvmWinDragEndedCallback` (`on_drag_ended` in `windows_backend.rs`): Reports `DoDragDrop` outcome.
//    - `trigger_rust_remote_paste` (in `clipboard/service.rs`): Triggers on-demand remote file streaming.
//
//  Cross-Platform / Cross-Device Flow (Windows 11 <-> macOS):
//  - Outgoing Control (Windows -> Mac): Physical mouse/keyboard events intercepted by `low_level_mouse_proc`
//    and `low_level_kbd_proc` are forwarded via `g_kvm_cb` to `KvmService`, which normalizes coordinates
//    across asymmetric monitor layouts and transmits encrypted KVM packets over TCP/UDP to the Mac peer
//    (where `kvm_macos.swift` injects them via `CGEventPost`). When controlling the Mac, `guard_wnd_proc`
//    blank-masks the Windows cursor and pins it to `(g_park_x, g_park_y)` so relative deltas `(dx, dy)`
//    never collide with local monitor edges.
//  - Incoming Control (Mac -> Windows): Remote input packets received from macOS are decoded by
//    `KvmService` and passed through `windows_backend.rs` to `integrator_kvm_win_inject_*`, which
//    maps coordinates to `[0, 65535]` virtual-desktop space and injects `SendInput` events tagged with
//    `kIntegratorEventTag` (`0x494E5447`).
//  - Cross-Device Drag-and-Drop: Outgoing Explorer drags hit `EdgeDropTarget::DragEnter` on `g_edge_hwnd`,
//    caching local file paths; when the pointer crosses the screen boundary, `integrator_kvm_win_cancel_local_drag`
//    injects `VK_ESCAPE` to release Explorer's modal capture while `KvmService` streams a `DragOffer` to macOS.
//    Conversely, incoming Mac drags display `g_ghost_hwnd` while files stage to disk, then post
//    `WM_APP_START_OLE_DRAG` to `g_ole_hwnd` to run `DoDragDrop` via `RemoteDropSource` until the Mac
//    releases the left mouse button (`g_remote_drag_left_down == false`).
//
//  ========================================================================================
//  3. THREADING & CONCURRENCY MODEL
//  ========================================================================================
//  - Input Hook Thread (`g_hook_thread` / `hook_thread_main`): Dedicated Win32 thread running at
//    `THREAD_PRIORITY_HIGHEST` with a `GetMessageW` pump. Owns `WH_MOUSE_LL` (`g_mouse_hook`),
//    `WH_KEYBOARD_LL` (`g_kbd_hook`), `g_guard_hwnd`, `g_edge_hwnd`, `g_ghost_hwnd`, and cached GDI
//    brushes/fonts. All window state mutations from FFI threads are marshaled via `PostMessageW`
//    (`WM_APP_*`) to prevent cross-thread Win32 HWND deadlocks.
//  - OLE STA Worker Thread (`g_ole_thread` / `ole_drag_thread_main`): Dedicated Single-Threaded
//    Apartment (`OleInitialize`) thread hosting the `HWND_MESSAGE` window `g_ole_hwnd`. Executes
//    blocking modal `DoDragDrop` loops without starving the latency-critical `WH_MOUSE_LL` hook pump
//    (which Windows silently unhooks if a callback stalls beyond `LowLevelHooksTimeout`).
//  - Lifecycle & Shared State Synchronization:
//    - `g_lifecycle_mutex` serializes `integrator_kvm_win_start_hooks` and `integrator_kvm_win_stop_hooks`.
//    - `g_captured_mutex` protects `g_captured_paths` between `EdgeDropTarget` and FFI callers.
//    - `g_ghost_mutex` protects `g_ghost_title` and `g_ghost_subtitle` strings between FFI and `WM_PAINT`.
//    - Lock-free `std::atomic` primitives (`g_controlling_peer`, `g_physical_left_down`,
//      `g_remote_drag_left_down`, `g_swallowed_mod_keys`, etc.) provide wait-free state reads on the
//      hot hook path.
//
//  ========================================================================================
//  4. SECURITY & SAFETY INVARIANTS
//  ========================================================================================
//  - Anti-Feedback Loop Tagging (`kIntegratorEventTag = 0x494E5447ULL`): Every synthetic event
//    emitted via `SendInput` stamps `dwExtraInfo = 0x494E5447ULL` ("INTG"). Hook procedures inspect
//    both `LLMHF_INJECTED` / `LLKHF_INJECTED` and `dwExtraInfo == kIntegratorEventTag`, immediately
//    passing synthetic events to `CallNextHookEx` to prevent self-amplifying feedback loops.
//  - Hook Reentrancy Protection: Thread-local guards (`tls_in_mouse_hook`, `tls_in_kbd_hook`) ensure
//    that synchronous Win32 API calls inside hook callbacks (such as `SetCursorPos`) cannot trigger
//    unbounded recursive hook invocations.
//  - UNC Path Traversal & NTLM Coercion Mitigation: `is_valid_local_drag_path` enforces strict
//    drive-letter prefix validation (`[A-Za-z]:\` or `\\?\[A-Za-z]:\`), rejecting all standard UNC
//    paths (`\\server\share`), forward-slash UNC paths (`//server/share`), extended UNC paths
//    (`\\?\UNC\server\share`), Win32 device namespaces (`\\.\`), embedded nulls, and `FILE_ATTRIBUTE_DEVICE`
//    handles before invoking shell/filesystem operations.
//  - Exception & Memory Boundaries: No C++ exceptions cross `extern "C"` boundaries. Heap payloads
//    posted via `PostMessageW` are wrapped in `std::unique_ptr` on receipt, checked for queue-full
//    failure on post, and explicitly drained via `PeekMessageW(..., PM_REMOVE)` on thread teardown.
//

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <ole2.h>
#include <shlobj.h>
#include <shellapi.h>
#include <shlwapi.h>

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

/// Magic 32-bit ASCII signature (`"INTG"` = `0x494E5447`) stamped into `INPUT::dwExtraInfo`
/// on all synthetic `SendInput` events so `WH_MOUSE_LL` and `WH_KEYBOARD_LL` hooks can
/// distinguish Integrator-injected events from physical hardware inputs.
static const ULONG_PTR kIntegratorEventTag = 0x494E5447ULL; // "INTG"

/// External Rust FFI entrypoint defined in `src/clipboard/service.rs` that initiates an
/// asynchronous on-demand transfer and `CF_HDROP` staging of a large (>128 MB) remote Mac file
/// when the user presses local `Ctrl+V` on Windows.
extern "C" void trigger_rust_remote_paste();

/// Atomic flag indicating whether a large (>128 MB) remote Mac file or directory announcement
/// is currently pending an on-demand pull on local `Ctrl+V`.
static std::atomic<bool> g_has_pending_remote_file{false};

/// Default fallback X coordinate in virtual-desktop pixels used when parking the hidden cursor.
static constexpr int32_t kDefaultParkX = 400;

/// Default fallback Y coordinate in virtual-desktop pixels used when parking the hidden cursor.
static constexpr int32_t kDefaultParkY = 300;

/// Sentinel coordinate value (in virtual-desktop pixels) indicating that no synthetic cursor
/// warp is currently pending in `g_expected_warp_x` / `g_expected_warp_y`. Uses `INT32_MIN`
/// rather than `-1` because `-1` is a valid pixel coordinate on multi-monitor layouts where a
/// secondary display sits left of or above the primary monitor origin `(0, 0)`.
static constexpr int32_t kNoExpectedWarpCoord = std::numeric_limits<int32_t>::min();

/// Maximum radial excursion distance in virtual-desktop pixels from `(g_park_x, g_park_y)`
/// allowed before `low_level_mouse_proc` warps the hidden local cursor back to the park point.
static constexpr int64_t kParkRecenterThresholdPx = 20;

/// Corner exclusion margin in pixels keeping the invisible edge probe clear of screen corners.
static constexpr int kCornerGuardMarginPx = 36;

/// Thickness in pixels of the invisible topmost screen-edge OLE drag probe window.
static constexpr int kEdgeWindowWidthPx = 4;

/// Width in pixels of the translucent GDI drag ghost HUD window.
static constexpr int kGhostWindowWidthPx = 272;

/// Height in pixels of the translucent GDI drag ghost HUD window.
static constexpr int kGhostWindowHeightPx = 56;

/// Horizontal and vertical cursor offset in pixels applied when positioning the drag ghost HUD.
static constexpr int32_t kGhostCursorOffsetPx = 18;

/// Maximum number of file paths processed in a single OLE drag-and-drop batch to bound memory
/// allocation and PIDL creation latency.
static constexpr int32_t kMaxDragFileCount = 4096;

/// Maximum length in wide characters (`wchar_t`) permitted for a local extended Win32 file path.
static constexpr size_t kMaxWin32PathCch = 32760;

/// Standard Win32 `WHEEL_DELTA` units per physical mouse wheel notch.
static constexpr double kWheelDeltaDivisor = 120.0;

/// Normalized scroll lines emitted per Win32 mouse wheel detent.
static constexpr double kWheelLinesPerNotch = 3.0;

/// Scaling factor converting normalized KVM scroll units into Win32 `SendInput` wheel delta units.
static constexpr double kInjectScrollScale = 40.0;

/// Maximum absolute Win32 scroll delta permitted per injected scroll event.
static constexpr double kMaxScrollDelta = 60000.0;

/// Maximum normalized coordinate value expected by `SendInput` with `MOUSEEVENTF_ABSOLUTE`.
static constexpr double kWin32AbsoluteCoordMax = 65535.0;

/// Timeout in milliseconds waiting for hook and OLE STA worker threads to complete startup.
static constexpr DWORD kThreadStartTimeoutMs = 2000;

/// Timeout in milliseconds waiting for hook and OLE STA worker threads to exit on teardown.
static constexpr DWORD kThreadShutdownTimeoutMs = 1500;

/// C-ABI callback signature invoked by low-level hooks to report intercepted physical input
/// events to `on_win_event` in `src/kvm/windows_backend.rs`.
///
/// Parameters:
/// - `kind`: Event discriminator (`1` = mouse move, `2` = mouse button, `3` = scroll, `4` = key).
/// - `a`, `b`, `c`, `d`: Event-specific coordinates, deltas, button indices, or virtual-key codes.
/// - `extra`: Bitmask of held mouse buttons (for `kind == 1`) or active keyboard modifiers.
///
/// Return value:
/// - `0`: Pass the event through to Windows via `CallNextHookEx`.
/// - `1`: Swallow the event (return non-zero from hook procedure).
/// - `2`: Swallow the event and warp the local cursor to `(g_park_x, g_park_y)`.
typedef int32_t (*KvmWinEventCallback)(
    int32_t kind,
    double a,
    double b,
    double c,
    double d,
    uint64_t extra
);

/// C-ABI callback signature invoked on the OLE STA thread when a native `DoDragDrop` session
/// initiated for an incoming remote drag finishes or is cancelled.
///
/// Parameters:
/// - `accepted`: `true` if the target application accepted the drop (`DRAGDROP_S_DROP` with
///   non-zero drop effect), `false` if cancelled or rejected.
/// - `session_id`: Null-terminated UTF-8 drag session identifier string.
typedef void (*KvmWinDragEndedCallback)(bool accepted, const char* session_id);

/// Mutex serializing hook/OLE worker thread startup (`integrator_kvm_win_start_hooks`) and
/// teardown (`integrator_kvm_win_stop_hooks`).
static std::mutex g_lifecycle_mutex;

/// Registered Rust C-ABI callback pointer for intercepted physical mouse and keyboard events.
static std::atomic<KvmWinEventCallback> g_kvm_cb{nullptr};

/// Registered Rust C-ABI callback pointer notified when a native OLE `DoDragDrop` completes.
static std::atomic<KvmWinDragEndedCallback> g_drag_ended_cb{nullptr};

/// Atomic flag set to `true` while this Windows workstation is actively sending its local
/// physical mouse and keyboard input to control the remote macOS peer.
static std::atomic<bool> g_controlling_peer{false};

/// Atomic flag set to `true` when the invisible screen-edge OLE drag probe window is enabled.
static std::atomic<bool> g_drag_probe_enabled{false};

/// Atomic flag tracking whether the local physical left mouse button is currently held down.
static std::atomic<bool> g_physical_left_down{false};

/// Atomic flag tracking whether the remote peer's left mouse button remains held during an
/// active incoming native OLE `DoDragDrop` session (`RemoteDropSource::QueryContinueDrag`).
static std::atomic<bool> g_remote_drag_left_down{false};

/// Atomic flag set to `true` while the OLE STA worker thread is inside a modal `DoDragDrop` call.
static std::atomic<bool> g_ole_drag_active{false};

/// Atomic flag set to `true` to request immediate cancellation (`DRAGDROP_S_CANCEL`) of an
/// active incoming OLE `DoDragDrop` session.
static std::atomic<bool> g_drag_cancelled{false};

/// Bitmask of `SwallowedModBit` flags tracking modifier keys whose key-down events were
/// swallowed by `low_level_kbd_proc` while controlling the remote peer. Because swallowed
/// key-downs never update Windows kernel key state (`GetAsyncKeyState`), this bitmask is
/// OR-ed with `GetAsyncKeyState` so subsequent remote key events carry accurate modifier flags.
static std::atomic<uint32_t> g_swallowed_mod_keys{0};

/// Bit positions in `g_swallowed_mod_keys` representing individual left/right modifier keys
/// whose key-down transitions were swallowed while controlling the remote peer.
enum SwallowedModBit : uint32_t {
    /// Left Shift (`VK_LSHIFT` / `VK_SHIFT`) bit flag (`0x01`).
    kModLShift = 1u << 0,
    /// Right Shift (`VK_RSHIFT`) bit flag (`0x02`).
    kModRShift = 1u << 1,
    /// Left Control (`VK_LCONTROL` / `VK_CONTROL`) bit flag (`0x04`).
    kModLCtrl  = 1u << 2,
    /// Right Control (`VK_RCONTROL`) bit flag (`0x08`).
    kModRCtrl  = 1u << 3,
    /// Left Alt / Menu (`VK_LMENU` / `VK_MENU`) bit flag (`0x10`).
    kModLAlt   = 1u << 4,
    /// Right Alt / AltGr (`VK_RMENU`) bit flag (`0x20`).
    kModRAlt   = 1u << 5,
    /// Left Windows / Meta (`VK_LWIN`) bit flag (`0x40`).
    kModLWin   = 1u << 6,
    /// Right Windows / Meta (`VK_RWIN`) bit flag (`0x80`).
    kModRWin   = 1u << 7,
};

/// Maps a Win32 Virtual-Key code (`VK_*`) to its corresponding `SwallowedModBit` bitflag.
///
/// Parameters:
/// - `vk`: Win32 virtual-key code from `KBDLLHOOKSTRUCT::vkCode`.
///
/// Returns:
/// - The matching `SwallowedModBit` value if `vk` is a Shift, Control, Alt, or Win modifier key,
///   or `0` for all non-modifier keys.
static uint32_t swallowed_mod_bit_for_vk(DWORD vk) {
    switch (vk) {
        case VK_LSHIFT:   case VK_SHIFT:   return kModLShift;
        case VK_RSHIFT:                    return kModRShift;
        case VK_LCONTROL: case VK_CONTROL: return kModLCtrl;
        case VK_RCONTROL:                  return kModRCtrl;
        case VK_LMENU:    case VK_MENU:    return kModLAlt;
        case VK_RMENU:                     return kModRAlt;
        case VK_LWIN:                      return kModLWin;
        case VK_RWIN:                      return kModRWin;
        default:                           return 0;
    }
}

/// Target X coordinate in virtual-desktop pixels where the hidden local cursor is parked while
/// controlling the remote peer.
static std::atomic<int32_t> g_park_x{kDefaultParkX};

/// Target Y coordinate in virtual-desktop pixels where the hidden local cursor is parked while
/// controlling the remote peer.
static std::atomic<int32_t> g_park_y{kDefaultParkY};

/// Active cardinal screen boundary index for the invisible OLE drag probe window
/// (`0` = Left, `1` = Right, `2` = Top, `3` = Bottom).
static std::atomic<int32_t> g_edge_mode{0};

/// Most recent physical mouse X coordinate in virtual-desktop pixels observed by `low_level_mouse_proc`,
/// used to compute relative `(dx, dy)` movement deltas while controlling the remote peer.
static std::atomic<int32_t> g_last_mouse_x{0};

/// Most recent physical mouse Y coordinate in virtual-desktop pixels observed by `low_level_mouse_proc`,
/// used to compute relative `(dx, dy)` movement deltas while controlling the remote peer.
static std::atomic<int32_t> g_last_mouse_y{0};

/// Atomic flag indicating whether `g_last_mouse_x` and `g_last_mouse_y` hold valid baseline
/// coordinates for relative delta calculation during the current remote-control session.
static std::atomic<bool> g_has_last_mouse{false};

/// Expected X coordinate in virtual-desktop pixels of an in-flight `SetCursorPos` recenter warp
/// (or `kNoExpectedWarpCoord` when no warp is pending), used to suppress synthetic warp feedback.
static std::atomic<int32_t> g_expected_warp_x{kNoExpectedWarpCoord};

/// Expected Y coordinate in virtual-desktop pixels of an in-flight `SetCursorPos` recenter warp
/// (or `kNoExpectedWarpCoord` when no warp is pending), used to suppress synthetic warp feedback.
static std::atomic<int32_t> g_expected_warp_y{kNoExpectedWarpCoord};

/// Target X cursor anchor coordinate in virtual-desktop pixels for positioning the drag ghost HUD.
static std::atomic<int32_t> g_ghost_x{0};

/// Target Y cursor anchor coordinate in virtual-desktop pixels for positioning the drag ghost HUD.
static std::atomic<int32_t> g_ghost_y{0};

/// Win32 thread identifier (`DWORD`) of the dedicated low-level input hook message-pump thread,
/// or `0` when the thread is not running.
static std::atomic<DWORD> g_hook_thread_id{0};

/// Win32 thread identifier (`DWORD`) of the dedicated OLE STA worker thread, or `0` when stopped.
static std::atomic<DWORD> g_ole_thread_id{0};

/// Win32 thread handle (`HANDLE`) for `hook_thread_main`, guarded by `g_lifecycle_mutex`.
static HANDLE g_hook_thread = nullptr;

/// Win32 thread handle (`HANDLE`) for `ole_drag_thread_main`, guarded by `g_lifecycle_mutex`.
static HANDLE g_ole_thread = nullptr;

/// Window handle (`HWND`) of the full-screen transparent cursor-hiding guard overlay window.
static std::atomic<HWND> g_guard_hwnd{nullptr};

/// Window handle (`HWND`) of the 4-pixel screen-edge OLE `IDropTarget` catcher window.
static std::atomic<HWND> g_edge_hwnd{nullptr};

/// Window handle (`HWND`) of the translucent GDI drag ghost HUD popup window.
static std::atomic<HWND> g_ghost_hwnd{nullptr};

/// Window handle (`HWND`) of the `HWND_MESSAGE` window on the OLE STA thread that receives
/// `WM_APP_START_OLE_DRAG` requests.
static std::atomic<HWND> g_ole_hwnd{nullptr};

/// Installed `WH_MOUSE_LL` hook handle (`HHOOK`), or `nullptr` when unhooked.
static std::atomic<HHOOK> g_mouse_hook{nullptr};

/// Installed `WH_KEYBOARD_LL` hook handle (`HHOOK`), or `nullptr` when unhooked.
static std::atomic<HHOOK> g_kbd_hook{nullptr};

/// Transparent 1-bit monochrome `HCURSOR` assigned to `g_guard_hwnd` to hide the local Windows
/// cursor while controlling the remote peer.
static std::atomic<HCURSOR> g_blank_cursor{nullptr};

/// Mutex protecting `g_captured_paths` across the hook thread (`EdgeDropTarget`) and FFI callers.
static std::mutex g_captured_mutex;

/// Vector of validated UTF-8 local filesystem paths captured from an active Explorer `CF_HDROP`
/// drag over `g_edge_hwnd`, guarded by `g_captured_mutex`.
static std::vector<std::string> g_captured_paths;

/// Mutex protecting `g_ghost_title` and `g_ghost_subtitle` strings between FFI updates and
/// `ghost_wnd_proc` `WM_PAINT` rendering.
static std::mutex g_ghost_mutex;

/// Primary UTF-16 title string displayed in the drag ghost HUD window, guarded by `g_ghost_mutex`.
static std::wstring g_ghost_title;

/// Secondary UTF-16 subtitle string displayed in the drag ghost HUD window, guarded by `g_ghost_mutex`.
static std::wstring g_ghost_subtitle;

/// Cached GDI dark slate background brush (`RGB(28, 32, 42)`) owned exclusively by `ghost_wnd_proc`.
static HBRUSH g_ghost_bg_brush = nullptr;

/// Cached GDI border frame brush (`RGB(86, 156, 255)`) owned exclusively by `ghost_wnd_proc`.
static HBRUSH g_ghost_border_brush = nullptr;

/// Cached GDI left accent bar brush (`RGB(56, 189, 248)`) owned exclusively by `ghost_wnd_proc`.
static HBRUSH g_ghost_accent_brush = nullptr;

/// Cached GDI 18px semibold Segoe UI font for the ghost HUD title, owned by `ghost_wnd_proc`.
static HFONT g_ghost_title_font = nullptr;

/// Cached GDI 14px regular Segoe UI font for the ghost HUD subtitle, owned by `ghost_wnd_proc`.
static HFONT g_ghost_sub_font = nullptr;

/// Custom application window messages (`WM_APP + N`) used to marshal cross-thread commands
/// from Rust FFI entrypoints onto the owning Win32 hook or OLE STA threads via `PostMessageW`.
enum CustomMsgs : UINT {
    /// Posted to `g_guard_hwnd` to show/hide the full-screen cursor guard window and warp
    /// the cursor (`wParam`: `1` = show & park, `0` = hide & restore to `POINT*` in `lParam`).
    WM_APP_SYNC_GUARD = WM_APP + 101,
    /// Posted to `g_edge_hwnd` to show or hide the screen-edge OLE drop catcher window
    /// (`wParam`: `1` = position & show, `0` = hide).
    WM_APP_SYNC_EDGE = WM_APP + 102,
    /// Posted to `g_ghost_hwnd` to position, show, and repaint the translucent drag ghost HUD.
    WM_APP_SHOW_GHOST = WM_APP + 103,
    /// Posted to `g_ghost_hwnd` to reposition the visible drag ghost HUD to `(g_ghost_x, g_ghost_y)`.
    WM_APP_MOVE_GHOST = WM_APP + 104,
    /// Posted to `g_ghost_hwnd` to hide the drag ghost HUD window.
    WM_APP_HIDE_GHOST = WM_APP + 105,
    /// Posted to `g_guard_hwnd` to warp the cursor on the hook thread to the heap-allocated
    /// `POINT*` passed in `lParam`.
    WM_APP_WARP_CURSOR = WM_APP + 106,
    /// Posted to `g_ole_hwnd` on the OLE STA thread to initiate a modal `DoDragDrop` loop
    /// using the heap-allocated `OleDragPayload*` passed in `lParam`.
    WM_APP_START_OLE_DRAG = WM_APP + 107,
};

/// Heap-allocated message payload transferred via `WM_APP_START_OLE_DRAG` from
/// `integrator_kvm_win_begin_native_drag` to `ole_wnd_proc` on the OLE STA worker thread.
struct OleDragPayload {
    /// Validated local Windows UTF-16 file or directory paths to package into a Shell `IDataObject`.
    std::vector<std::wstring> paths;
    /// Unique UTF-8 drag session identifier echoed back to Rust via `KvmWinDragEndedCallback`.
    std::string session_id;
};

/// Reference-counted thread startup handshake object shared between `integrator_kvm_win_start_hooks`
/// and a newly spawned worker thread (`hook_thread_main` or `ole_drag_thread_main`).
///
/// Using atomic reference counting (`refs` initialized to `2`) ensures that if the caller times
/// out in `WaitForSingleObject` before the worker thread signals `ev`, neither side accesses a
/// dangling pointer or closes `ev` prematurely.
struct StartHandshake {
    /// Manual-reset Win32 event handle signaled by the worker thread once its message queue and
    /// windows/hooks are initialized.
    HANDLE ev = nullptr;
    /// Atomic reference count tracking ownership across the spawner thread and the worker thread.
    std::atomic<int> refs{2};

    /// Decrements the reference count with acquire-release ordering and closes `ev` / deletes
    /// `this` when the final owner releases its reference.
    void release() {
        if (refs.fetch_sub(1, std::memory_order_acq_rel) == 1) {
            if (ev) CloseHandle(ev);
            delete this;
        }
    }
};

/// Converts a null-terminated UTF-8 C string into a UTF-16 `std::wstring` using Win32
/// `MultiByteToWideChar(CP_UTF8, ...)`.
///
/// Parameters:
/// - `s`: Null-terminated UTF-8 string pointer (may be `nullptr` or empty).
///
/// Returns:
/// - Decoded UTF-16 `std::wstring`, or an empty string on null/empty input or conversion failure.
static std::wstring utf8_to_wide(const char* s) {
    if (!s || !*s) return L"";
    int len = MultiByteToWideChar(CP_UTF8, 0, s, -1, nullptr, 0);
    // `len` includes the trailing null terminator; `len <= 1` means empty or error.
    if (len <= 1) return L"";
    std::wstring out(static_cast<size_t>(len - 1), L'\0');
    int written = MultiByteToWideChar(CP_UTF8, 0, s, -1, &out[0], len);
    if (written <= 1) return L"";
    return out;
}

/// Converts a null-terminated UTF-16 wide C string into a UTF-8 `std::string` using Win32
/// `WideCharToMultiByte(CP_UTF8, ...)`.
///
/// Parameters:
/// - `ws`: Null-terminated UTF-16 string pointer (may be `nullptr` or empty).
///
/// Returns:
/// - Encoded UTF-8 `std::string`, or an empty string on null/empty input or conversion failure.
static std::string wide_to_utf8(const wchar_t* ws) {
    if (!ws || !*ws) return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, ws, -1, nullptr, 0, nullptr, nullptr);
    // `len` includes the trailing null terminator; `len <= 1` means empty or error.
    if (len <= 1) return "";
    std::string out(static_cast<size_t>(len - 1), '\0');
    int written = WideCharToMultiByte(CP_UTF8, 0, ws, -1, &out[0], len, nullptr, nullptr);
    if (written <= 1) return "";
    return out;
}

/// Serializes a UTF-8 string into a double-quoted RFC 8259 JSON string literal, escaping
/// quotation marks, backslashes, and control characters (`0x00`..`0x1F`).
///
/// Parameters:
/// - `src`: Raw UTF-8 string to escape.
///
/// Returns:
/// - Quoted and escaped JSON string literal (e.g., `"\"C:\\\\Users\\\\file.txt\""`).
static std::string json_escape(const std::string& src) {
    std::string out;
    out.reserve(src.size() + 4);
    out.push_back('"');
    for (unsigned char ch : src) {
        switch (ch) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b"; break;
        case '\f': out += "\\f"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (ch < 0x20) {
                char buf[8];
                snprintf(buf, sizeof(buf), "\\u%04x", ch);
                out += buf;
            } else {
                out.push_back(static_cast<char>(ch));
            }
            break;
        }
    }
    out.push_back('"');
    return out;
}

/// Checks whether a wide character slice begins with a standard local drive-letter prefix
/// (`[A-Za-z]:\` or `[A-Za-z]:/`).
///
/// Parameters:
/// - `p`: Pointer to the start of the wide character buffer.
/// - `len`: Number of wide characters in `p`.
///
/// Returns:
/// - `true` if `p` starts with an ASCII drive letter followed by `:` and a path separator.
static bool has_local_drive_prefix(const wchar_t* p, size_t len) {
    if (!p || len < 3) return false;
    wchar_t drive = p[0];
    bool is_alpha = (drive >= L'A' && drive <= L'Z') || (drive >= L'a' && drive <= L'z');
    bool is_sep = (p[2] == L'\\' || p[2] == L'/');
    return is_alpha && p[1] == L':' && is_sep;
}

/// Validates that a candidate drag-and-drop path refers to an existing, local filesystem object
/// and cannot trigger off-box SMB/NTLM coercion or Win32 device namespace side effects.
///
/// Security checks performed before calling `GetFileAttributesW`:
/// 1. Bounds length to `[1, kMaxWin32PathCch]` (`32760` characters) and rejects embedded nulls.
/// 2. Requires an explicit local drive-letter root (`[A-Za-z]:\` or extended `\\?\[A-Za-z]:\`),
///    which rejects all UNC network paths (`\\server\share`), forward-slash UNC paths
///    (`//server/share`), extended UNC paths (`\\?\UNC\server\share`), and device paths (`\\.\`).
/// 3. Verifies the target exists on disk and does not have `FILE_ATTRIBUTE_DEVICE`.
///
/// Parameters:
/// - `path`: Candidate UTF-16 filesystem path.
///
/// Returns:
/// - `true` if `path` is a safe, existing local file or folder; `false` otherwise.
static bool is_valid_local_drag_path(const std::wstring& path) {
    if (path.empty() || path.size() > kMaxWin32PathCch) return false;
    if (path.find(L'\0') != std::wstring::npos) return false;

    // Require an explicit local drive-letter prefix (either `X:\...` or extended `\\?\X:\...`)
    // so that `\\server\share`, `//server/share`, `\\?\UNC\server\share`, and `\\.\device`
    // are unconditionally rejected before touching the Win32 filesystem API.
    if (path.rfind(L"\\\\?\\", 0) == 0) {
        if (!has_local_drive_prefix(path.c_str() + 4, path.size() - 4)) {
            return false;
        }
    } else if (!has_local_drive_prefix(path.c_str(), path.size())) {
        return false;
    }

    DWORD attrs = GetFileAttributesW(path.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) return false;
    if ((attrs & FILE_ATTRIBUTE_DEVICE) != 0) return false;
    return true;
}

/// Computes the canonical 4-bit KVM modifier mask combining live Win32 `GetAsyncKeyState` key
/// states with any modifier keys whose key-down events were swallowed by `low_level_kbd_proc`.
///
/// Bit encoding matches `win_flags_to_modifiers` in `src/kvm/windows_backend.rs`:
/// - Bit 0 (`1`): Shift (`VK_SHIFT` or swallowed `kModLShift | kModRShift`)
/// - Bit 1 (`2`): Control (`VK_CONTROL` or swallowed `kModLCtrl | kModRCtrl`)
/// - Bit 2 (`4`): Alt (`VK_MENU` or swallowed `kModLAlt | kModRAlt`)
/// - Bit 3 (`8`): Meta / Windows (`VK_LWIN` / `VK_RWIN` or swallowed `kModLWin | kModRWin`)
///
/// Parameters:
/// - `sw`: Bitmask of `SwallowedModBit` flags currently active.
///
/// Returns:
/// - 64-bit modifier bitmask in the range `[0, 15]`.
static uint64_t read_current_modifiers_with_swallowed(uint32_t sw) {
    uint64_t m = 0;
    if ((GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0 || (sw & (kModLShift | kModRShift)) != 0) m |= 1ULL;
    if ((GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0 || (sw & (kModLCtrl | kModRCtrl)) != 0) m |= 2ULL;
    if ((GetAsyncKeyState(VK_MENU) & 0x8000) != 0 || (sw & (kModLAlt | kModRAlt)) != 0) m |= 4ULL;
    if (((GetAsyncKeyState(VK_LWIN) & 0x8000) != 0) ||
        ((GetAsyncKeyState(VK_RWIN) & 0x8000) != 0) ||
        (sw & (kModLWin | kModRWin)) != 0) m |= 8ULL;
    return m;
}

/// Reads the current 4-bit KVM modifier mask using the global `g_swallowed_mod_keys` state.
///
/// Returns:
/// - 64-bit modifier bitmask in the range `[0, 15]`.
static uint64_t read_current_modifiers() {
    return read_current_modifiers_with_swallowed(g_swallowed_mod_keys.load());
}

/// Positions and resizes the invisible screen-edge OLE drop catcher window (`g_edge_hwnd`)
/// along the configured virtual-desktop boundary (`g_edge_mode`), inset by `kCornerGuardMarginPx`
/// (`36` pixels) at both ends so screen corners remain clear for window resize handles and hot-corners.
///
/// Parameters:
/// - `hwnd`: Handle to the edge probe window on `g_hook_thread`.
static void position_edge_window(HWND hwnd) {
    if (!hwnd) return;
    int vx = GetSystemMetrics(SM_XVIRTUALSCREEN);
    int vy = GetSystemMetrics(SM_YVIRTUALSCREEN);
    int vw = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    int vh = GetSystemMetrics(SM_CYVIRTUALSCREEN);
    if (vw <= 0 || vh <= 0) {
        vx = 0;
        vy = 0;
        vw = GetSystemMetrics(SM_CXSCREEN);
        vh = GetSystemMetrics(SM_CYSCREEN);
    }
    int guard = kCornerGuardMarginPx;
    int edge = g_edge_mode.load();
    int x = vx, y = vy, w = kEdgeWindowWidthPx, h = vh;
    switch (edge) {
    case 0: // Left screen boundary
        x = vx;
        y = vy + guard;
        w = kEdgeWindowWidthPx;
        h = (vh > guard * 2) ? (vh - guard * 2) : vh;
        break;
    case 1: // Right screen boundary
        x = vx + vw - kEdgeWindowWidthPx;
        y = vy + guard;
        w = kEdgeWindowWidthPx;
        h = (vh > guard * 2) ? (vh - guard * 2) : vh;
        break;
    case 2: // Top screen boundary
        x = vx + guard;
        y = vy;
        w = (vw > guard * 2) ? (vw - guard * 2) : vw;
        h = kEdgeWindowWidthPx;
        break;
    case 3: // Bottom screen boundary
        x = vx + guard;
        y = vy + vh - kEdgeWindowWidthPx;
        w = (vw > guard * 2) ? (vw - guard * 2) : vw;
        h = kEdgeWindowWidthPx;
        break;
    default:
        break;
    }
    SetWindowPos(hwnd, HWND_TOPMOST, x, y, w, h, SWP_NOACTIVATE | SWP_NOOWNERZORDER);
}

// MARK: - OLE IDropTarget for Edge Catcher (captures active Explorer CF_HDROP drag at screen border)

/// OLE `IDropTarget` implementation registered on the invisible screen-edge probe window (`g_edge_hwnd`).
///
/// When the user drags files in Windows Explorer while `g_physical_left_down` is true, `g_edge_hwnd`
/// is shown along the peer-facing monitor border. As the cursor enters the 4-pixel edge strip,
/// Explorer invokes `EdgeDropTarget::DragEnter` with its `IDataObject`. `DragEnter` extracts all
/// local paths from the `CF_HDROP` storage medium, filters them through `is_valid_local_drag_path`,
/// and stores them in `g_captured_paths`. If the pointer subsequently crosses onto the remote Mac,
/// `KvmService` retrieves these paths via `integrator_kvm_win_take_drag_paths` and cancels the local
/// Explorer drag loop via `integrator_kvm_win_cancel_local_drag`.
class EdgeDropTarget final : public IDropTarget {
public:
    /// Constructs an `EdgeDropTarget` with an initial COM reference count of `1`.
    EdgeDropTarget() : ref_count_(1) {}

    /// Standard COM `IUnknown::QueryInterface` supporting `IID_IUnknown` and `IID_IDropTarget`.
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IDropTarget) {
            *ppv = static_cast<IDropTarget*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    /// Atomically increments the COM reference count.
    ULONG STDMETHODCALLTYPE AddRef() override {
        return static_cast<ULONG>(InterlockedIncrement(&ref_count_));
    }

    /// Atomically decrements the COM reference count and destroys the instance at zero.
    ULONG STDMETHODCALLTYPE Release() override {
        ULONG c = static_cast<ULONG>(InterlockedDecrement(&ref_count_));
        if (c == 0) delete this;
        return c;
    }

    /// Invoked by OLE when an active drag cursor enters `g_edge_hwnd`. Extracts up to
    /// `kMaxDragFileCount` (`4096`) local file paths from the `CF_HDROP` global memory block.
    HRESULT STDMETHODCALLTYPE DragEnter(
        IDataObject* pDataObj,
        DWORD /*grfKeyState*/,
        POINTL /*pt*/,
        DWORD* pdwEffect
    ) override {
        std::vector<std::string> found;
        if (pDataObj) {
            FORMATETC fmt = { CF_HDROP, nullptr, DVASPECT_CONTENT, -1, TYMED_HGLOBAL };
            STGMEDIUM stg = {};
            if (SUCCEEDED(pDataObj->GetData(&fmt, &stg))) {
                if (stg.tymed == TYMED_HGLOBAL && stg.hGlobal != nullptr) {
                    // Lock the global HGLOBAL handle to read the DROPFILES structure via DragQueryFileW.
                    HDROP hdrop = static_cast<HDROP>(GlobalLock(stg.hGlobal));
                    if (hdrop) {
                        UINT count = DragQueryFileW(hdrop, 0xFFFFFFFF, nullptr, 0);
                        for (UINT i = 0; i < count && i < static_cast<UINT>(kMaxDragFileCount); ++i) {
                            UINT len = DragQueryFileW(hdrop, i, nullptr, 0);
                            if (len > 0 && len < static_cast<UINT>(kMaxWin32PathCch)) {
                                std::wstring wpath(static_cast<size_t>(len) + 1, L'\0');
                                UINT copied = DragQueryFileW(hdrop, i, &wpath[0], len + 1);
                                if (copied > 0 && copied <= len) {
                                    wpath.resize(copied);
                                    if (is_valid_local_drag_path(wpath)) {
                                        std::string u8 = wide_to_utf8(wpath.c_str());
                                        if (!u8.empty()) found.push_back(std::move(u8));
                                    }
                                }
                            }
                        }
                        GlobalUnlock(stg.hGlobal);
                    }
                }
                // Always release the STGMEDIUM returned by IDataObject::GetData to avoid HGLOBAL leaks.
                ReleaseStgMedium(&stg);
            }
        }
        bool has_items = false;
        {
            std::lock_guard<std::mutex> lk(g_captured_mutex);
            g_captured_paths = std::move(found);
            has_items = !g_captured_paths.empty();
        }
        if (pdwEffect) {
            // Report DROPEFFECT_COPY so Explorer maintains an active drag cursor at the screen edge.
            *pdwEffect = has_items ? DROPEFFECT_COPY : DROPEFFECT_NONE;
        }
        return S_OK;
    }

    /// Invoked by OLE as the drag cursor moves within `g_edge_hwnd`. Preserves `DROPEFFECT_COPY`
    /// while captured paths remain cached.
    HRESULT STDMETHODCALLTYPE DragOver(DWORD, POINTL, DWORD* pdwEffect) override {
        if (pdwEffect) {
            std::lock_guard<std::mutex> lk(g_captured_mutex);
            *pdwEffect = g_captured_paths.empty() ? DROPEFFECT_NONE : DROPEFFECT_COPY;
        }
        return S_OK;
    }

    /// Invoked by OLE if the user pulls the drag cursor back away from the screen edge into
    /// the local Windows desktop; clears `g_captured_paths` so stale paths are not handed off.
    HRESULT STDMETHODCALLTYPE DragLeave() override {
        std::lock_guard<std::mutex> lk(g_captured_mutex);
        g_captured_paths.clear();
        return S_OK;
    }

    /// Invoked if the user releases the mouse button directly over the 4-pixel edge probe window
    /// before crossing to the remote peer. Rejects the drop (`DROPEFFECT_NONE`) so files are
    /// never consumed by the invisible overlay.
    HRESULT STDMETHODCALLTYPE Drop(
        IDataObject* /*pDataObj*/,
        DWORD /*grfKeyState*/,
        POINTL /*pt*/,
        DWORD* pdwEffect
    ) override {
        if (pdwEffect) *pdwEffect = DROPEFFECT_NONE;
        return S_OK;
    }

private:
    /// Atomic COM reference counter manipulated via `InterlockedIncrement` / `InterlockedDecrement`.
    volatile LONG ref_count_;
};

// MARK: - OLE IDropSource for Remote -> Windows `DoDragDrop`

/// OLE `IDropSource` implementation driving synthetic file drag sessions on Windows.
///
/// When a file drag initiated on macOS enters the Windows desktop, the payload files are
/// staged to disk, and `DoDragDrop` is executed on the dedicated OLE STA thread using this source.
/// Because the physical mouse button is held on the remote Mac rather than on a local Windows HID
/// device, `QueryContinueDrag` ignores the local `grfKeyState` mouse button bits and instead polls
/// the atomic `g_remote_drag_left_down` and `g_drag_cancelled` flags updated by incoming network
/// packets. When the user releases the physical mouse button on the Mac, `g_remote_drag_left_down`
/// becomes `false`, prompting `QueryContinueDrag` to return `DRAGDROP_S_DROP` and completing the
/// native drop into whichever Windows application is beneath the cursor.
class RemoteDropSource final : public IDropSource {
public:
    /// Constructs a `RemoteDropSource` with an initial COM reference count of `1`.
    RemoteDropSource() : ref_count_(1) {}

    /// Standard COM `IUnknown::QueryInterface` supporting `IID_IUnknown` and `IID_IDropSource`.
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IDropSource) {
            *ppv = static_cast<IDropSource*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    /// Atomically increments the COM reference count.
    ULONG STDMETHODCALLTYPE AddRef() override {
        return static_cast<ULONG>(InterlockedIncrement(&ref_count_));
    }

    /// Atomically decrements the COM reference count and destroys the instance at zero.
    ULONG STDMETHODCALLTYPE Release() override {
        ULONG c = static_cast<ULONG>(InterlockedDecrement(&ref_count_));
        if (c == 0) delete this;
        return c;
    }

    /// Polled by OLE's modal `DoDragDrop` loop on every mouse or keyboard message to decide
    /// whether to continue dragging (`S_OK`), commit the drop (`DRAGDROP_S_DROP`), or abort
    /// (`DRAGDROP_S_CANCEL`).
    HRESULT STDMETHODCALLTYPE QueryContinueDrag(BOOL fEscapePressed, DWORD /*grfKeyState*/) override {
        if (fEscapePressed || g_drag_cancelled.load()) {
            return DRAGDROP_S_CANCEL;
        }
        if (!g_remote_drag_left_down.load()) {
            return DRAGDROP_S_DROP;
        }
        return S_OK;
    }

    /// Instructs OLE to render standard system drag-and-drop cursors (`DRAGDROP_S_USEDEFAULTCURSORS`).
    HRESULT STDMETHODCALLTYPE GiveFeedback(DWORD /*dwEffect*/) override {
        return DRAGDROP_S_USEDEFAULTCURSORS;
    }

private:
    /// Atomic COM reference counter manipulated via `InterlockedIncrement` / `InterlockedDecrement`.
    volatile LONG ref_count_;
};

// MARK: - Low-Level Mouse & Keyboard Hooks

/// Simple RAII scope guard that sets a thread-local boolean flag to `true` on construction
/// and resets it to `false` on scope exit, preventing synchronous hook reentrancy.
struct ScopedReentrancyGuard {
    /// Reference to the thread-local reentrancy flag managed by this guard.
    bool& flag;
    /// Sets `flag = true` on entry.
    explicit ScopedReentrancyGuard(bool& f) : flag(f) { flag = true; }
    /// Resets `flag = false` on exit.
    ~ScopedReentrancyGuard() { flag = false; }
};

/// Win32 `WH_MOUSE_LL` hook procedure installed on `g_hook_thread`.
///
/// Algorithm & Invariants:
/// 1. Ignores injected events (`LLMHF_INJECTED` or `dwExtraInfo == kIntegratorEventTag`) so
///    synthetic `SendInput` events never re-enter `KvmService`.
/// 2. Guards against synchronous same-thread hook reentrancy (`tls_in_mouse_hook`), which can
///    occur if `SetCursorPos` dispatches a nested hook notification before returning.
/// 3. Shows or hides `g_edge_hwnd` asynchronously via `PostMessageW(WM_APP_SYNC_EDGE)` when
///    the physical left mouse button is pressed or released locally, enabling zero-overhead
///    OLE `IDropTarget` capture at the screen edge only during potential drag gestures.
/// 4. While `g_controlling_peer` is `true`, computes relative movement deltas `(dx, dy)` from
///    `(g_last_mouse_x, g_last_mouse_y)`, recenters the physical cursor to `(g_park_x, g_park_y)`
///    via `SetCursorPos` whenever it drifts beyond `kParkRecenterThresholdPx` (`20` pixels), and
///    immediately updates `g_last_mouse_x/y` to `(px, py)` so coalesced OS mouse moves never
///    produce a backward delta recoil.
/// 5. Invokes `g_kvm_cb` and swallows the event (returning `1`) if the Rust coordinator returns
///    `HookDecision::Swallow` (`1`) or `HookDecision::SwallowAndParkCenter` (`2`).
static LRESULT CALLBACK low_level_mouse_proc(int nCode, WPARAM wParam, LPARAM lParam) {
    static thread_local bool tls_in_mouse_hook = false;

    if (nCode == HC_ACTION && lParam) {
        const MSLLHOOKSTRUCT* ms = reinterpret_cast<const MSLLHOOKSTRUCT*>(lParam);
        // Fast-path filter: pass through any synthetic event generated by SendInput.
        if ((ms->flags & LLMHF_INJECTED) != 0 || ms->dwExtraInfo == kIntegratorEventTag) {
            return CallNextHookEx(nullptr, nCode, wParam, lParam);
        }

        // Prevent synchronous reentrancy if SetCursorPos or a callback triggers a nested hook call.
        if (tls_in_mouse_hook) {
            if (wParam == WM_MOUSEMOVE && g_controlling_peer.load()) {
                int32_t exp_x = g_expected_warp_x.load();
                int32_t exp_y = g_expected_warp_y.load();
                if (exp_x != kNoExpectedWarpCoord && ms->pt.x == exp_x && ms->pt.y == exp_y) {
                    g_expected_warp_x.store(kNoExpectedWarpCoord);
                    g_expected_warp_y.store(kNoExpectedWarpCoord);
                    g_last_mouse_x.store(exp_x);
                    g_last_mouse_y.store(exp_y);
                    g_has_last_mouse.store(true);
                    return 1;
                }
            }
            return CallNextHookEx(nullptr, nCode, wParam, lParam);
        }
        ScopedReentrancyGuard reentrancy_guard(tls_in_mouse_hook);

        HWND edge_hwnd = g_edge_hwnd.load();
        if (wParam == WM_LBUTTONDOWN) {
            g_physical_left_down.store(true);
            // Reveal the 4px screen-edge OLE IDropTarget window when a local drag may be starting.
            if (edge_hwnd && g_drag_probe_enabled.load() && !g_controlling_peer.load()) {
                PostMessageW(edge_hwnd, WM_APP_SYNC_EDGE, 1, 0);
            }
        } else if (wParam == WM_LBUTTONUP) {
            g_physical_left_down.store(false);
            if (edge_hwnd) {
                PostMessageW(edge_hwnd, WM_APP_SYNC_EDGE, 0, 0);
            }
            if (!g_controlling_peer.load()) {
                std::lock_guard<std::mutex> lk(g_captured_mutex);
                g_captured_paths.clear();
            }
        }

        KvmWinEventCallback cb = g_kvm_cb.load();
        if (cb) {
            int32_t decision = 0;
            switch (wParam) {
            case WM_MOUSEMOVE: {
                int32_t px = g_park_x.load();
                int32_t py = g_park_y.load();
                int32_t cur_x = ms->pt.x;
                int32_t cur_y = ms->pt.y;

                if (g_controlling_peer.load()) {
                    int32_t exp_x = g_expected_warp_x.load();
                    int32_t exp_y = g_expected_warp_y.load();
                    // If this WM_MOUSEMOVE is the exact synthetic warp generated by our own
                    // SetCursorPos(px, py), consume it silently and anchor the delta baseline.
                    if (exp_x != kNoExpectedWarpCoord && cur_x == exp_x && cur_y == exp_y) {
                        g_expected_warp_x.store(kNoExpectedWarpCoord);
                        g_expected_warp_y.store(kNoExpectedWarpCoord);
                        g_last_mouse_x.store(cur_x);
                        g_last_mouse_y.store(cur_y);
                        g_has_last_mouse.store(true);
                        return 1;
                    }
                    // Clear any stale expected-warp coordinates if Windows coalesced the warp
                    // with a subsequent physical hardware mouse move.
                    g_expected_warp_x.store(kNoExpectedWarpCoord);
                    g_expected_warp_y.store(kNoExpectedWarpCoord);

                    if (!g_has_last_mouse.load()) {
                        g_last_mouse_x.store(cur_x);
                        g_last_mouse_y.store(cur_y);
                        g_has_last_mouse.store(true);
                        if (std::abs(static_cast<int64_t>(cur_x) - static_cast<int64_t>(px)) > kParkRecenterThresholdPx ||
                            std::abs(static_cast<int64_t>(cur_y) - static_cast<int64_t>(py)) > kParkRecenterThresholdPx) {
                            g_expected_warp_x.store(px);
                            g_expected_warp_y.store(py);
                            g_last_mouse_x.store(px);
                            g_last_mouse_y.store(py);
                            if (!SetCursorPos(px, py)) {
                                g_expected_warp_x.store(kNoExpectedWarpCoord);
                                g_expected_warp_y.store(kNoExpectedWarpCoord);
                                g_last_mouse_x.store(cur_x);
                                g_last_mouse_y.store(cur_y);
                            }
                        }
                        return 1;
                    }

                    int32_t last_x = g_last_mouse_x.load();
                    int32_t last_y = g_last_mouse_y.load();
                    double dx = static_cast<double>(cur_x) - static_cast<double>(last_x);
                    double dy = static_cast<double>(cur_y) - static_cast<double>(last_y);
                    g_last_mouse_x.store(cur_x);
                    g_last_mouse_y.store(cur_y);

                    // If the hidden cursor has drifted more than 20px from the park anchor,
                    // warp it back to (px, py) and immediately reset g_last_mouse_x/y to (px, py)
                    // so a coalesced next move is measured relative to the new parked position.
                    if (std::abs(static_cast<int64_t>(cur_x) - static_cast<int64_t>(px)) > kParkRecenterThresholdPx ||
                        std::abs(static_cast<int64_t>(cur_y) - static_cast<int64_t>(py)) > kParkRecenterThresholdPx) {
                        g_expected_warp_x.store(px);
                        g_expected_warp_y.store(py);
                        g_last_mouse_x.store(px);
                        g_last_mouse_y.store(py);
                        if (!SetCursorPos(px, py)) {
                            g_expected_warp_x.store(kNoExpectedWarpCoord);
                            g_expected_warp_y.store(kNoExpectedWarpCoord);
                            g_last_mouse_x.store(cur_x);
                            g_last_mouse_y.store(cur_y);
                        }
                    }

                    if (dx == 0.0 && dy == 0.0) {
                        return 1;
                    }

                    uint64_t lbtn = g_physical_left_down.load() ? 1ULL : 0ULL;
                    decision = cb(1, static_cast<double>(cur_x), static_cast<double>(cur_y), dx, dy, lbtn);
                    break;
                }

                double dx = 0.0;
                double dy = 0.0;
                uint64_t lbtn = g_physical_left_down.load() ? 1ULL : 0ULL;
                decision = cb(1, static_cast<double>(cur_x), static_cast<double>(cur_y), dx, dy, lbtn);
                break;
            }
            case WM_LBUTTONDOWN:
                decision = cb(2, 0.0, 1.0, static_cast<double>(ms->pt.x), static_cast<double>(ms->pt.y), read_current_modifiers());
                break;
            case WM_LBUTTONUP:
                decision = cb(2, 0.0, 0.0, static_cast<double>(ms->pt.x), static_cast<double>(ms->pt.y), read_current_modifiers());
                break;
            case WM_RBUTTONDOWN:
                decision = cb(2, 1.0, 1.0, static_cast<double>(ms->pt.x), static_cast<double>(ms->pt.y), read_current_modifiers());
                break;
            case WM_RBUTTONUP:
                decision = cb(2, 1.0, 0.0, static_cast<double>(ms->pt.x), static_cast<double>(ms->pt.y), read_current_modifiers());
                break;
            case WM_MBUTTONDOWN:
                decision = cb(2, 2.0, 1.0, static_cast<double>(ms->pt.x), static_cast<double>(ms->pt.y), read_current_modifiers());
                break;
            case WM_MBUTTONUP:
                decision = cb(2, 2.0, 0.0, static_cast<double>(ms->pt.x), static_cast<double>(ms->pt.y), read_current_modifiers());
                break;
            case WM_MOUSEWHEEL: {
                SHORT delta = static_cast<SHORT>(HIWORD(ms->mouseData));
                double dy = static_cast<double>(delta) / kWheelDeltaDivisor * kWheelLinesPerNotch;
                decision = cb(3, 0.0, dy, 0.0, 0.0, read_current_modifiers());
                break;
            }
            case WM_MOUSEHWHEEL: {
                SHORT delta = static_cast<SHORT>(HIWORD(ms->mouseData));
                double dx = static_cast<double>(delta) / kWheelDeltaDivisor * kWheelLinesPerNotch;
                decision = cb(3, dx, 0.0, 0.0, 0.0, read_current_modifiers());
                break;
            }
            default:
                break;
            }

            if (decision == 2) {
                int32_t px = g_park_x.load();
                int32_t py = g_park_y.load();
                g_expected_warp_x.store(px);
                g_expected_warp_y.store(py);
                g_last_mouse_x.store(px);
                g_last_mouse_y.store(py);
                g_has_last_mouse.store(true);
                SetCursorPos(px, py);
                return 1;
            } else if (decision == 1) {
                return 1;
            }
        }
    }
    return CallNextHookEx(nullptr, nCode, wParam, lParam);
}

/// Win32 `WH_KEYBOARD_LL` hook procedure installed on `g_hook_thread`.
///
/// Algorithm & Invariants:
/// 1. Filters out synthetic keyboard events (`LLKHF_INJECTED` or `dwExtraInfo == kIntegratorEventTag`).
/// 2. Guards against synchronous same-thread hook reentrancy (`tls_in_kbd_hook`).
/// 3. Intercepts local `Ctrl+V` when `g_has_pending_remote_file` is `true` and this machine is
///    not controlling the remote peer, invoking `trigger_rust_remote_paste()` and swallowing
///    the keystroke so the clipboard service can stream and stage the remote file on demand.
/// 4. Tracks swallowed modifier keys (`g_swallowed_mod_keys`) so that when Windows kernel key
///    state (`GetAsyncKeyState`) is not updated for swallowed modifier key-downs, subsequent
///    remote key events still observe the true held modifier mask.
static LRESULT CALLBACK low_level_kbd_proc(int nCode, WPARAM wParam, LPARAM lParam) {
    static thread_local bool tls_in_kbd_hook = false;

    if (nCode == HC_ACTION && lParam) {
        const KBDLLHOOKSTRUCT* ks = reinterpret_cast<const KBDLLHOOKSTRUCT*>(lParam);
        // Fast-path filter: ignore synthetic events emitted by SendInput.
        if ((ks->flags & LLKHF_INJECTED) != 0 || ks->dwExtraInfo == kIntegratorEventTag) {
            return CallNextHookEx(nullptr, nCode, wParam, lParam);
        }
        if (tls_in_kbd_hook) {
            return CallNextHookEx(nullptr, nCode, wParam, lParam);
        }
        ScopedReentrancyGuard reentrancy_guard(tls_in_kbd_hook);

        bool pressed = (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN);
        // Intercept local Ctrl+V when a large (>128 MB) remote Mac file/folder is pending
        // on-demand pull so pressing Ctrl+V on the Windows Desktop streams and stages CF_HDROP.
        if (pressed && !g_controlling_peer.load() && ks->vkCode == 'V' && g_has_pending_remote_file.load()) {
            bool ctrl_down = (GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0;
            bool alt_down = (GetAsyncKeyState(VK_MENU) & 0x8000) != 0;
            bool win_down = ((GetAsyncKeyState(VK_LWIN) & 0x8000) != 0) ||
                            ((GetAsyncKeyState(VK_RWIN) & 0x8000) != 0);
            if (ctrl_down && !alt_down && !win_down) {
                trigger_rust_remote_paste();
                return 1;
            }
        }
        uint32_t sw_bit = swallowed_mod_bit_for_vk(ks->vkCode);
        uint32_t preview_sw = g_swallowed_mod_keys.load();
        if (sw_bit != 0 && g_controlling_peer.load()) {
            preview_sw = pressed ? (preview_sw | sw_bit) : (preview_sw & ~sw_bit);
        }
        KvmWinEventCallback cb = g_kvm_cb.load();
        if (cb) {
            int32_t decision = cb(
                4,
                static_cast<double>(ks->vkCode),
                pressed ? 1.0 : 0.0,
                0.0,
                0.0,
                read_current_modifiers_with_swallowed(preview_sw)
            );
            if (decision != 0) {
                if (sw_bit != 0) {
                    if (pressed) {
                        g_swallowed_mod_keys.fetch_or(sw_bit);
                    } else {
                        g_swallowed_mod_keys.fetch_and(~sw_bit);
                    }
                }
                return 1;
            } else if (!pressed && sw_bit != 0) {
                g_swallowed_mod_keys.fetch_and(~sw_bit);
            }
        }
    }
    return CallNextHookEx(nullptr, nCode, wParam, lParam);
}

// MARK: - Window Procedures (Guard / Edge / Fluent Drag Ghost / OLE Message Window)

/// Window procedure for `g_guard_hwnd` (`IntegratorKvmGuardWnd`), the full-screen transparent
/// topmost overlay that hides the local Windows cursor (`g_blank_cursor`) and parks it at
/// `(g_park_x, g_park_y)` while the user controls the remote peer.
static LRESULT CALLBACK guard_wnd_proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    HCURSOR blank = g_blank_cursor.load();
    if (msg == WM_SETCURSOR && g_controlling_peer.load() && blank) {
        SetCursor(blank);
        return TRUE;
    }
    if (msg == WM_DISPLAYCHANGE && g_controlling_peer.load() && IsWindowVisible(hwnd)) {
        int vx = GetSystemMetrics(SM_XVIRTUALSCREEN);
        int vy = GetSystemMetrics(SM_YVIRTUALSCREEN);
        int vw = GetSystemMetrics(SM_CXVIRTUALSCREEN);
        int vh = GetSystemMetrics(SM_CYVIRTUALSCREEN);
        if (vw <= 0 || vh <= 0) {
            vx = 0; vy = 0;
            vw = GetSystemMetrics(SM_CXSCREEN);
            vh = GetSystemMetrics(SM_CYSCREEN);
        }
        SetWindowPos(hwnd, HWND_TOPMOST, vx, vy, vw, vh, SWP_SHOWWINDOW | SWP_NOACTIVATE);
        return 0;
    }
    if (msg == WM_APP_SYNC_GUARD) {
        std::unique_ptr<POINT> pt(reinterpret_cast<POINT*>(lParam));
        if (wParam != 0 && g_controlling_peer.load()) {
            int vx = GetSystemMetrics(SM_XVIRTUALSCREEN);
            int vy = GetSystemMetrics(SM_YVIRTUALSCREEN);
            int vw = GetSystemMetrics(SM_CXVIRTUALSCREEN);
            int vh = GetSystemMetrics(SM_CYVIRTUALSCREEN);
            if (vw <= 0 || vh <= 0) {
                vx = 0; vy = 0;
                vw = GetSystemMetrics(SM_CXSCREEN);
                vh = GetSystemMetrics(SM_CYSCREEN);
            }
            SetWindowPos(hwnd, HWND_TOPMOST, vx, vy, vw, vh, SWP_SHOWWINDOW | SWP_NOACTIVATE);
            int32_t px = g_park_x.load();
            int32_t py = g_park_y.load();
            g_expected_warp_x.store(px);
            g_expected_warp_y.store(py);
            g_last_mouse_x.store(px);
            g_last_mouse_y.store(py);
            g_has_last_mouse.store(true);
            SetCursorPos(px, py);
        } else {
            ShowWindow(hwnd, SW_HIDE);
            if (pt) {
                SetCursorPos(pt->x, pt->y);
            }
        }
        return 0;
    }
    if (msg == WM_APP_WARP_CURSOR) {
        std::unique_ptr<POINT> pt(reinterpret_cast<POINT*>(lParam));
        if (pt) {
            SetCursorPos(pt->x, pt->y);
        }
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

/// Window procedure for `g_edge_hwnd` (`IntegratorKvmEdgeWnd`), the 4-pixel topmost screen-edge
/// probe window registered with OLE `RegisterDragDrop` (`EdgeDropTarget`) to intercept outgoing
/// Windows Explorer file drags before the cursor crosses to the remote monitor.
static LRESULT CALLBACK edge_wnd_proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_DISPLAYCHANGE && IsWindowVisible(hwnd)) {
        position_edge_window(hwnd);
        return 0;
    }
    if (msg == WM_APP_SYNC_EDGE) {
        if (wParam != 0 && g_drag_probe_enabled.load() && !g_controlling_peer.load()) {
            position_edge_window(hwnd);
            ShowWindow(hwnd, SW_SHOWNA);
        } else {
            ShowWindow(hwnd, SW_HIDE);
        }
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

/// Window procedure for `g_ghost_hwnd` (`IntegratorKvmGhostWnd`), the translucent GDI drag ghost
/// HUD window (`272x56` pixels, alpha `238/255`) that follows the cursor while remote drag files
/// are streaming from macOS prior to native `DoDragDrop` handoff.
static LRESULT CALLBACK ghost_wnd_proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_CREATE) {
        // Pre-allocate GDI brushes and ClearType Segoe UI fonts once on window creation
        // to avoid per-frame GDI handle churn during 120Hz cursor movement repaints.
        g_ghost_bg_brush = CreateSolidBrush(RGB(28, 32, 42));
        g_ghost_border_brush = CreateSolidBrush(RGB(86, 156, 255));
        g_ghost_accent_brush = CreateSolidBrush(RGB(56, 189, 248));
        g_ghost_title_font = CreateFontW(18, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_OUTLINE_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            VARIABLE_PITCH, L"Segoe UI");
        g_ghost_sub_font = CreateFontW(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_OUTLINE_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            VARIABLE_PITCH, L"Segoe UI");
        return 0;
    }
    if (msg == WM_DESTROY) {
        if (g_ghost_bg_brush) { DeleteObject(g_ghost_bg_brush); g_ghost_bg_brush = nullptr; }
        if (g_ghost_border_brush) { DeleteObject(g_ghost_border_brush); g_ghost_border_brush = nullptr; }
        if (g_ghost_accent_brush) { DeleteObject(g_ghost_accent_brush); g_ghost_accent_brush = nullptr; }
        if (g_ghost_title_font) { DeleteObject(g_ghost_title_font); g_ghost_title_font = nullptr; }
        if (g_ghost_sub_font) { DeleteObject(g_ghost_sub_font); g_ghost_sub_font = nullptr; }
        return 0;
    }
    if (msg == WM_PAINT) {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        RECT rc;
        GetClientRect(hwnd, &rc);

        if (g_ghost_bg_brush) FillRect(hdc, &rc, g_ghost_bg_brush);
        if (g_ghost_border_brush) FrameRect(hdc, &rc, g_ghost_border_brush);

        RECT accent = { 0, 0, 5, rc.bottom };
        if (g_ghost_accent_brush) FillRect(hdc, &accent, g_ghost_accent_brush);

        SetBkMode(hdc, TRANSPARENT);
        std::wstring title, sub;
        {
            std::lock_guard<std::mutex> lk(g_ghost_mutex);
            title = g_ghost_title;
            sub = g_ghost_subtitle;
        }

        HGDIOBJ oldFont = g_ghost_title_font ? SelectObject(hdc, g_ghost_title_font) : nullptr;
        SetTextColor(hdc, RGB(244, 247, 252));
        RECT tr = { 16, 8, rc.right - 12, 30 };
        DrawTextW(hdc, title.c_str(), -1, &tr, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);

        if (g_ghost_sub_font) SelectObject(hdc, g_ghost_sub_font);
        SetTextColor(hdc, RGB(165, 180, 200));
        RECT sr = { 16, 30, rc.right - 12, 50 };
        DrawTextW(hdc, sub.c_str(), -1, &sr, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);

        if (oldFont) SelectObject(hdc, oldFont);
        EndPaint(hwnd, &ps);
        return 0;
    }
    if (msg == WM_APP_SHOW_GHOST) {
        int64_t raw_x = static_cast<int64_t>(g_ghost_x.load()) + kGhostCursorOffsetPx;
        int64_t raw_y = static_cast<int64_t>(g_ghost_y.load()) + kGhostCursorOffsetPx;
        int x = static_cast<int>(std::max<int64_t>(std::numeric_limits<int>::min(), std::min<int64_t>(std::numeric_limits<int>::max(), raw_x)));
        int y = static_cast<int>(std::max<int64_t>(std::numeric_limits<int>::min(), std::min<int64_t>(std::numeric_limits<int>::max(), raw_y)));
        SetWindowPos(hwnd, HWND_TOPMOST, x, y, kGhostWindowWidthPx, kGhostWindowHeightPx, SWP_SHOWWINDOW | SWP_NOACTIVATE);
        InvalidateRect(hwnd, nullptr, TRUE);
        return 0;
    }
    if (msg == WM_APP_MOVE_GHOST) {
        if (IsWindowVisible(hwnd)) {
            int64_t raw_x = static_cast<int64_t>(g_ghost_x.load()) + kGhostCursorOffsetPx;
            int64_t raw_y = static_cast<int64_t>(g_ghost_y.load()) + kGhostCursorOffsetPx;
            int x = static_cast<int>(std::max<int64_t>(std::numeric_limits<int>::min(), std::min<int64_t>(std::numeric_limits<int>::max(), raw_x)));
            int y = static_cast<int>(std::max<int64_t>(std::numeric_limits<int>::min(), std::min<int64_t>(std::numeric_limits<int>::max(), raw_y)));
            SetWindowPos(hwnd, HWND_TOPMOST, x, y, 0, 0, SWP_NOSIZE | SWP_NOACTIVATE | SWP_NOOWNERZORDER);
        }
        return 0;
    }
    if (msg == WM_APP_HIDE_GHOST) {
        ShowWindow(hwnd, SW_HIDE);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

/// Window procedure for `g_ole_hwnd` (`IntegratorKvmOleMsgWnd`), the message-only (`HWND_MESSAGE`)
/// window hosted on the dedicated OLE STA worker thread (`g_ole_thread`).
///
/// Handles `WM_APP_START_OLE_DRAG` by converting staged local file paths into Shell ITEMIDLISTs
/// (`PIDLIST_ABSOLUTE`), constructing a native Shell `IDataObject` via `SHCreateDataObject`,
/// hiding the temporary GDI ghost HUD, and entering the modal `DoDragDrop` loop with
/// `RemoteDropSource`. When `DoDragDrop` returns, releases all COM objects and PIDLs and invokes
/// `g_drag_ended_cb` so `KvmService` can clean up or finalize the drag session.
static LRESULT CALLBACK ole_wnd_proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_APP_START_OLE_DRAG && lParam) {
        std::unique_ptr<OleDragPayload> payload(reinterpret_cast<OleDragPayload*>(lParam));
        std::vector<PIDLIST_ABSOLUTE> owned_pidls;
        std::vector<LPCITEMIDLIST> full_pidls;
        std::vector<LPCITEMIDLIST> child_pidls;
        PIDLIST_ABSOLUTE parent_pidl = nullptr;
        bool same_parent = true;
        std::wstring first_dir;

        for (const auto& wp : payload->paths) {
            if (!is_valid_local_drag_path(wp)) continue;
            PIDLIST_ABSOLUTE pidl = ILCreateFromPathW(wp.c_str());
            if (!pidl) continue;

            size_t slash = wp.find_last_of(L"\\/");
            std::wstring dir = (slash == std::wstring::npos) ? L"" : wp.substr(0, slash);
            if (owned_pidls.empty()) {
                first_dir = dir;
            } else if (_wcsicmp(dir.c_str(), first_dir.c_str()) != 0) {
                same_parent = false;
            }

            owned_pidls.push_back(pidl);
            full_pidls.push_back(pidl);
            PCUIDLIST_RELATIVE child = ILFindLastID(pidl);
            if (child) child_pidls.push_back(child);
        }
        bool accepted = false;
        if (!owned_pidls.empty()) {
            IDataObject* pDataObj = nullptr;
            HRESULT hr = E_FAIL;
            // Preferred path: when all staged files share a common parent folder (the standard
            // staging directory case), pass the parent folder PIDL and relative child PIDLs to
            // SHCreateDataObject so Explorer and third-party targets receive full Shell metadata.
            if (same_parent && child_pidls.size() == owned_pidls.size()) {
                parent_pidl = ILCloneFull(owned_pidls[0]);
                if (parent_pidl && ILRemoveLastID(parent_pidl)) {
                    hr = SHCreateDataObject(
                        parent_pidl,
                        static_cast<UINT>(child_pidls.size()),
                        child_pidls.data(),
                        nullptr,
                        IID_IDataObject,
                        reinterpret_cast<void**>(&pDataObj)
                    );
                }
            }
            // Fallback path for multi-directory drags: root at the Desktop empty ITEMIDLIST first,
            // then nullptr if needed.
            if (FAILED(hr) || !pDataObj) {
                static const ITEMIDLIST kDesktopRootPidl = {};
                hr = SHCreateDataObject(
                    &kDesktopRootPidl,
                    static_cast<UINT>(full_pidls.size()),
                    full_pidls.data(),
                    nullptr,
                    IID_IDataObject,
                    reinterpret_cast<void**>(&pDataObj)
                );
            }
            if (FAILED(hr) || !pDataObj) {
                hr = SHCreateDataObject(
                    nullptr,
                    static_cast<UINT>(full_pidls.size()),
                    full_pidls.data(),
                    nullptr,
                    IID_IDataObject,
                    reinterpret_cast<void**>(&pDataObj)
                );
            }
            if (SUCCEEDED(hr) && pDataObj) {
                RemoteDropSource* src = new RemoteDropSource();
                DWORD effect = DROPEFFECT_NONE;
                HWND ghost = g_ghost_hwnd.load();
                if (ghost) {
                    PostMessageW(ghost, WM_APP_HIDE_GHOST, 0, 0);
                }
                if (!g_drag_cancelled.load()) {
                    g_ole_drag_active.store(true);
                    HRESULT dhr = DoDragDrop(pDataObj, src, DROPEFFECT_COPY, &effect);
                    g_ole_drag_active.store(false);
                    accepted = (dhr == DRAGDROP_S_DROP && effect != DROPEFFECT_NONE);
                }
                src->Release();
                pDataObj->Release();
            }
            if (parent_pidl) ILFree(parent_pidl);
            for (PIDLIST_ABSOLUTE p : owned_pidls) {
                ILFree(p);
            }
        }
        HWND ghost = g_ghost_hwnd.load();
        if (ghost) {
            PostMessageW(ghost, WM_APP_HIDE_GHOST, 0, 0);
        }
        KvmWinDragEndedCallback cb = g_drag_ended_cb.load();
        if (cb) {
            cb(accepted, payload->session_id.c_str());
        }
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

/// Thread entrypoint for `g_hook_thread`, responsible for low-level mouse/keyboard hook
/// installation and the message pump driving `g_guard_hwnd`, `g_edge_hwnd`, and `g_ghost_hwnd`.
///
/// Startup & Teardown Lifecycle:
/// 1. Elevates thread priority to `THREAD_PRIORITY_HIGHEST` to minimize hook dispatch latency
///    and avoid Windows `LowLevelHooksTimeout` eviction.
/// 2. Enables `DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2` dynamically so `GetSystemMetrics` and
///    `MSLLHOOKSTRUCT::pt` report unscaled 1:1 physical virtual-desktop pixels.
/// 3. Initializes COM STA via `OleInitialize(nullptr)` for `RegisterDragDrop` on `g_edge_hwnd`.
/// 4. Creates the blank cursor, registers window classes, creates the guard/edge/ghost windows
///    excluded from screen capture (`WDA_EXCLUDEFROMCAPTURE`), and installs `WH_MOUSE_LL` and
///    `WH_KEYBOARD_LL` hooks.
/// 5. Signals `StartHandshake::ev` and runs `GetMessageW` until `WM_QUIT` is posted (or exits
///    immediately if either hook failed to install so background retries can spawn a clean thread).
/// 6. On exit, unhooks both hooks, drains any queued heap `POINT*` messages on `g_guard_hwnd`,
///    revokes drag-drop, destroys all windows/cursors, unregisters classes, and balances `OleUninitialize`.
static DWORD WINAPI hook_thread_main(LPVOID param) {
    StartHandshake* hs = static_cast<StartHandshake*>(param);
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);

    // Enable Per-Monitor DPI awareness V2 so display bounds and mouse coordinates match 1:1.
    HMODULE user32 = GetModuleHandleW(L"user32.dll");
    if (user32) {
        typedef BOOL(WINAPI* SetProcessDpiAwarenessContextFn)(HANDLE);
        SetProcessDpiAwarenessContextFn set_dpi_fn =
            reinterpret_cast<SetProcessDpiAwarenessContextFn>(GetProcAddress(user32, "SetProcessDpiAwarenessContext"));
        if (set_dpi_fn) {
            set_dpi_fn(reinterpret_cast<HANDLE>(-4)); // DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2
        }
    }

    HRESULT ole_hr = OleInitialize(nullptr);

    int cx = std::max(16, std::min(256, GetSystemMetrics(SM_CXCURSOR)));
    int cy = std::max(16, std::min(256, GetSystemMetrics(SM_CYCURSOR)));
    size_t row_bytes = static_cast<size_t>(((cx + 15) / 16) * 2);
    size_t total_bytes = row_bytes * static_cast<size_t>(cy);
    std::vector<BYTE> and_mask(total_bytes, 0xFF);
    std::vector<BYTE> xor_mask(total_bytes, 0x00);

    HINSTANCE hinst = GetModuleHandleW(nullptr);
    HCURSOR blank = CreateCursor(hinst, 0, 0, cx, cy, and_mask.data(), xor_mask.data());
    g_blank_cursor.store(blank);

    WNDCLASSW gwc = {};
    gwc.lpfnWndProc = guard_wnd_proc;
    gwc.hInstance = hinst;
    gwc.hCursor = blank;
    gwc.lpszClassName = L"IntegratorKvmGuardWnd";
    RegisterClassW(&gwc);

    WNDCLASSW ewc = {};
    ewc.lpfnWndProc = edge_wnd_proc;
    ewc.hInstance = hinst;
    ewc.lpszClassName = L"IntegratorKvmEdgeWnd";
    RegisterClassW(&ewc);

    WNDCLASSW fwc = {};
    fwc.lpfnWndProc = ghost_wnd_proc;
    fwc.hInstance = hinst;
    fwc.lpszClassName = L"IntegratorKvmGhostWnd";
    RegisterClassW(&fwc);

#ifndef WDA_EXCLUDEFROMCAPTURE
#define WDA_EXCLUDEFROMCAPTURE 0x00000011
#endif

    HWND guard_hw = CreateWindowExW(
        WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE | WS_EX_LAYERED,
        gwc.lpszClassName, L"", WS_POPUP,
        0, 0, 1, 1, nullptr, nullptr, hinst, nullptr
    );
    if (guard_hw) {
        // Alpha = 1 (out of 255) makes the guard window imperceptible to the user while still
        // hit-testable by the Win32 window manager so WM_SETCURSOR hides the cursor.
        SetLayeredWindowAttributes(guard_hw, 0, 1, LWA_ALPHA);
        SetWindowDisplayAffinity(guard_hw, WDA_EXCLUDEFROMCAPTURE);
    }
    g_guard_hwnd.store(guard_hw);

    HWND edge_hw = CreateWindowExW(
        WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE | WS_EX_LAYERED,
        ewc.lpszClassName, L"", WS_POPUP,
        0, 0, kEdgeWindowWidthPx, 100, nullptr, nullptr, hinst, nullptr
    );
    EdgeDropTarget* drop_target = nullptr;
    if (edge_hw) {
        SetLayeredWindowAttributes(edge_hw, 0, 1, LWA_ALPHA);
        SetWindowDisplayAffinity(edge_hw, WDA_EXCLUDEFROMCAPTURE);
        drop_target = new EdgeDropTarget();
        RegisterDragDrop(edge_hw, drop_target);
    }
    g_edge_hwnd.store(edge_hw);

    HWND ghost_hw = CreateWindowExW(
        WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE | WS_EX_TRANSPARENT | WS_EX_LAYERED,
        fwc.lpszClassName, L"", WS_POPUP,
        0, 0, kGhostWindowWidthPx, kGhostWindowHeightPx, nullptr, nullptr, hinst, nullptr
    );
    if (ghost_hw) {
        SetLayeredWindowAttributes(ghost_hw, 0, 238, LWA_ALPHA);
        SetWindowDisplayAffinity(ghost_hw, WDA_EXCLUDEFROMCAPTURE);
    }
    g_ghost_hwnd.store(ghost_hw);

    // Force creation of the thread message queue before signaling the startup handshake.
    MSG init_msg;
    PeekMessageW(&init_msg, nullptr, WM_USER, WM_USER, PM_NOREMOVE);

    HHOOK mh = SetWindowsHookExW(WH_MOUSE_LL, low_level_mouse_proc, hinst, 0);
    HHOOK kh = SetWindowsHookExW(WH_KEYBOARD_LL, low_level_kbd_proc, hinst, 0);
    bool hooks_ok = (mh != nullptr && kh != nullptr);
    if (hooks_ok) {
        g_mouse_hook.store(mh);
        g_kbd_hook.store(kh);
    } else {
        if (mh) UnhookWindowsHookEx(mh);
        if (kh) UnhookWindowsHookEx(kh);
    }

    if (hs) {
        if (hs->ev) SetEvent(hs->ev);
        hs->release();
    }

    if (hooks_ok) {
        MSG msg;
        while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    HHOOK mh_cur = g_mouse_hook.exchange(nullptr);
    HHOOK kh_cur = g_kbd_hook.exchange(nullptr);
    if (mh_cur) UnhookWindowsHookEx(mh_cur);
    if (kh_cur) UnhookWindowsHookEx(kh_cur);

    HWND guard_cur = g_guard_hwnd.exchange(nullptr);
    HWND edge_cur = g_edge_hwnd.exchange(nullptr);
    HWND ghost_cur = g_ghost_hwnd.exchange(nullptr);
    if (edge_cur) {
        RevokeDragDrop(edge_cur);
        DestroyWindow(edge_cur);
    }
    if (guard_cur) {
        // Drain any unprocessed WM_APP_SYNC_GUARD or WM_APP_WARP_CURSOR messages to free their
        // heap-allocated POINT* payloads before destroying the guard window.
        MSG pending;
        while (PeekMessageW(&pending, guard_cur, WM_APP_SYNC_GUARD, WM_APP_SYNC_GUARD, PM_REMOVE)) {
            delete reinterpret_cast<POINT*>(pending.lParam);
        }
        while (PeekMessageW(&pending, guard_cur, WM_APP_WARP_CURSOR, WM_APP_WARP_CURSOR, PM_REMOVE)) {
            delete reinterpret_cast<POINT*>(pending.lParam);
        }
        DestroyWindow(guard_cur);
    }
    if (ghost_cur) DestroyWindow(ghost_cur);
    if (drop_target) drop_target->Release();

    HCURSOR blank_cur = g_blank_cursor.exchange(nullptr);
    if (blank_cur) DestroyCursor(blank_cur);

    UnregisterClassW(gwc.lpszClassName, hinst);
    UnregisterClassW(ewc.lpszClassName, hinst);
    UnregisterClassW(fwc.lpszClassName, hinst);
    g_hook_thread_id.store(0);
    if (SUCCEEDED(ole_hr)) {
        OleUninitialize();
    }
    return 0;
}

/// Thread entrypoint for `g_ole_thread`, the dedicated COM STA worker thread that hosts
/// `g_ole_hwnd` (`HWND_MESSAGE`) and executes blocking `DoDragDrop` modal loops on behalf of
/// incoming remote drag-and-drop sessions without stalling `hook_thread_main`.
static DWORD WINAPI ole_drag_thread_main(LPVOID param) {
    StartHandshake* hs = static_cast<StartHandshake*>(param);
    HRESULT ole_hr = OleInitialize(nullptr);

    HINSTANCE hinst = GetModuleHandleW(nullptr);
    WNDCLASSW owc = {};
    owc.lpfnWndProc = ole_wnd_proc;
    owc.hInstance = hinst;
    owc.lpszClassName = L"IntegratorKvmOleMsgWnd";
    RegisterClassW(&owc);

    HWND ole_hw = CreateWindowExW(
        0, owc.lpszClassName, L"", 0, 0, 0, 0, 0, HWND_MESSAGE, nullptr, hinst, nullptr
    );
    g_ole_hwnd.store(ole_hw);

    MSG msg;
    PeekMessageW(&msg, nullptr, WM_USER, WM_USER, PM_NOREMOVE);
    if (hs) {
        if (hs->ev) SetEvent(hs->ev);
        hs->release();
    }

    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    HWND ole_cur = g_ole_hwnd.exchange(nullptr);
    if (ole_cur) {
        MSG pending;
        while (PeekMessageW(&pending, ole_cur, WM_APP_START_OLE_DRAG, WM_APP_START_OLE_DRAG, PM_REMOVE)) {
            delete reinterpret_cast<OleDragPayload*>(pending.lParam);
        }
        DestroyWindow(ole_cur);
    }
    UnregisterClassW(owc.lpszClassName, hinst);
    g_ole_thread_id.store(0);
    if (SUCCEEDED(ole_hr)) {
        OleUninitialize();
    }
    return 0;
}

extern "C" {

/// Queries whether both the low-level mouse hook (`WH_MOUSE_LL`) and low-level keyboard hook
/// (`WH_KEYBOARD_LL`) are currently installed and operational.
///
/// Returns:
/// - `true` if both `g_mouse_hook` and `g_kbd_hook` are non-null; `false` otherwise.
bool integrator_kvm_win_is_hook_active() {
    return g_mouse_hook.load() != nullptr && g_kbd_hook.load() != nullptr;
}

/// Spawns the dedicated input hook message-pump thread (`g_hook_thread`) and the OLE STA
/// drag-and-drop worker thread (`g_ole_thread`), waiting up to `kThreadStartTimeoutMs` (`2000` ms)
/// per thread for initialization to complete.
///
/// Thread-safe & Idempotent:
/// - Serialized by `g_lifecycle_mutex`.
/// - If a previous hook thread attempt failed to install its hooks and exited (`g_hook_thread_id == 0`),
///   any stale thread `HANDLE` is closed before spawning a new thread so background retry loops
///   in `windows_backend.rs` do not leak kernel thread handles.
///
/// Parameters:
/// - `cb`: Function pointer invoked on intercepted physical mouse/keyboard events.
/// - `drag_ended_cb`: Function pointer invoked when a native OLE `DoDragDrop` session terminates.
///
/// Returns:
/// - `true` if both `WH_MOUSE_LL` and `WH_KEYBOARD_LL` hooks are active after startup.
bool integrator_kvm_win_start_hooks(
    KvmWinEventCallback cb,
    KvmWinDragEndedCallback drag_ended_cb
) {
    std::lock_guard<std::mutex> lk(g_lifecycle_mutex);
    g_kvm_cb.store(cb);
    g_drag_ended_cb.store(drag_ended_cb);

    if (g_hook_thread_id.load() == 0) {
        if (g_hook_thread) {
            WaitForSingleObject(g_hook_thread, kThreadShutdownTimeoutMs);
            CloseHandle(g_hook_thread);
            g_hook_thread = nullptr;
        }
        StartHandshake* hs = new StartHandshake();
        hs->ev = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        DWORD tid = 0;
        HANDLE th = CreateThread(nullptr, 0, hook_thread_main, hs, 0, &tid);
        if (th) {
            g_hook_thread_id.store(tid);
            g_hook_thread = th;
            if (hs->ev) WaitForSingleObject(hs->ev, kThreadStartTimeoutMs);
            hs->release();
        } else {
            hs->release();
            hs->release();
        }
    }
    if (g_ole_thread_id.load() == 0) {
        if (g_ole_thread) {
            WaitForSingleObject(g_ole_thread, kThreadShutdownTimeoutMs);
            CloseHandle(g_ole_thread);
            g_ole_thread = nullptr;
        }
        StartHandshake* hs2 = new StartHandshake();
        hs2->ev = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        DWORD tid2 = 0;
        HANDLE th2 = CreateThread(nullptr, 0, ole_drag_thread_main, hs2, 0, &tid2);
        if (th2) {
            g_ole_thread_id.store(tid2);
            g_ole_thread = th2;
            if (hs2->ev) WaitForSingleObject(hs2->ev, kThreadStartTimeoutMs);
            hs2->release();
        } else {
            hs2->release();
            hs2->release();
        }
    }
    return integrator_kvm_win_is_hook_active();
}

/// Uninstalls the Win32 low-level input hooks, cancels any in-flight OLE drag session, and
/// cleanly terminates both `g_hook_thread` and `g_ole_thread` by posting `WM_QUIT` and waiting
/// up to `kThreadShutdownTimeoutMs` (`1500` ms) before closing thread handles.
void integrator_kvm_win_stop_hooks() {
    std::lock_guard<std::mutex> lk(g_lifecycle_mutex);
    g_controlling_peer.store(false);
    g_drag_cancelled.store(true);
    g_kvm_cb.store(nullptr);
    g_drag_ended_cb.store(nullptr);

    DWORD htid = g_hook_thread_id.load();
    if (htid != 0) {
        PostThreadMessageW(htid, WM_QUIT, 0, 0);
    }
    if (g_hook_thread) {
        WaitForSingleObject(g_hook_thread, kThreadShutdownTimeoutMs);
        CloseHandle(g_hook_thread);
        g_hook_thread = nullptr;
    }

    DWORD otid = g_ole_thread_id.load();
    if (otid != 0) {
        PostThreadMessageW(otid, WM_QUIT, 0, 0);
    }
    if (g_ole_thread) {
        WaitForSingleObject(g_ole_thread, kThreadShutdownTimeoutMs);
        CloseHandle(g_ole_thread);
        g_ole_thread = nullptr;
    }
}

/// Queries the bounding rectangle of the Windows virtual desktop (or primary monitor fallback)
/// in physical virtual-desktop pixels via `GetSystemMetrics`.
///
/// Parameters:
/// - `out_x`: Optional pointer receiving the left origin (`SM_XVIRTUALSCREEN`) in pixels.
/// - `out_y`: Optional pointer receiving the top origin (`SM_YVIRTUALSCREEN`) in pixels.
/// - `out_w`: Optional pointer receiving the total width (`SM_CXVIRTUALSCREEN`) in pixels.
/// - `out_h`: Optional pointer receiving the total height (`SM_CYVIRTUALSCREEN`) in pixels.
void integrator_kvm_win_screen_rect(
    double* out_x,
    double* out_y,
    double* out_w,
    double* out_h
) {
    int x = GetSystemMetrics(SM_XVIRTUALSCREEN);
    int y = GetSystemMetrics(SM_YVIRTUALSCREEN);
    int w = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    int h = GetSystemMetrics(SM_CYVIRTUALSCREEN);
    if (w <= 0 || h <= 0) {
        x = 0; y = 0;
        w = GetSystemMetrics(SM_CXSCREEN);
        h = GetSystemMetrics(SM_CYSCREEN);
    }
    if (out_x) *out_x = static_cast<double>(x);
    if (out_y) *out_y = static_cast<double>(y);
    if (out_w) *out_w = static_cast<double>(w);
    if (out_h) *out_h = static_cast<double>(h);
}

/// Configures whether the invisible 4-pixel screen-edge OLE drag probe window (`g_edge_hwnd`)
/// is enabled and which cardinal monitor edge (`0` = Left, `1` = Right, `2` = Top, `3` = Bottom)
/// faces the remote peer.
///
/// Parameters:
/// - `enabled`: `true` to allow `g_edge_hwnd` to appear during local left-button drags; `false` to hide it.
/// - `edge_mode`: Cardinal boundary index (`0`..`3`).
void integrator_kvm_win_set_edge_probe(bool enabled, int32_t edge_mode) {
    g_drag_probe_enabled.store(enabled);
    g_edge_mode.store(edge_mode);
    HWND edge_hw = g_edge_hwnd.load();
    if (!enabled && edge_hw) {
        PostMessageW(edge_hw, WM_APP_SYNC_EDGE, 0, 0);
    }
}

/// Transitions the local Windows workstation into or out of remote-controlling mode.
///
/// When `controlling` is `true`, resets swallowed modifier tracking, records `(park_x, park_y)`
/// as the cursor anchor, hides `g_edge_hwnd`, and posts `WM_APP_SYNC_GUARD` to `g_guard_hwnd`
/// so the full-screen blank-cursor guard overlay is shown and the cursor is parked.
/// When `controlling` is `false`, hides `g_guard_hwnd` and restores the cursor to `(restore_x, restore_y)`.
///
/// Parameters:
/// - `controlling`: `true` when taking control of the remote peer; `false` when returning locally.
/// - `park_x`: Virtual-desktop X coordinate in pixels where the hidden local cursor is pinned.
/// - `park_y`: Virtual-desktop Y coordinate in pixels where the hidden local cursor is pinned.
/// - `restore_x`: Virtual-desktop X coordinate in pixels where the cursor is restored on exit.
/// - `restore_y`: Virtual-desktop Y coordinate in pixels where the cursor is restored on exit.
void integrator_kvm_win_set_controlling(
    bool controlling,
    int32_t park_x,
    int32_t park_y,
    int32_t restore_x,
    int32_t restore_y
) {
    g_swallowed_mod_keys.store(0);
    g_park_x.store(park_x);
    g_park_y.store(park_y);
    g_has_last_mouse.store(false);
    g_expected_warp_x.store(kNoExpectedWarpCoord);
    g_expected_warp_y.store(kNoExpectedWarpCoord);
    g_controlling_peer.store(controlling);
    HWND edge_hw = g_edge_hwnd.load();
    if (edge_hw) {
        PostMessageW(edge_hw, WM_APP_SYNC_EDGE, 0, 0);
    }
    HWND guard_hw = g_guard_hwnd.load();
    if (guard_hw) {
        POINT* pt = new POINT{ restore_x, restore_y };
        if (!PostMessageW(guard_hw, WM_APP_SYNC_GUARD, controlling ? 1 : 0, reinterpret_cast<LPARAM>(pt))) {
            delete pt;
            if (!controlling) {
                SetCursorPos(restore_x, restore_y);
            }
        }
    } else if (!controlling) {
        SetCursorPos(restore_x, restore_y);
    }
}

/// Transitions the local Windows workstation into or out of being controlled by the remote peer.
///
/// When `controlled` is `true`, clears `g_drag_cancelled` and warps the local Windows cursor
/// to `(entry_x, entry_y)` via `WM_APP_WARP_CURSOR` on the hook thread.
/// When `controlled` is `false`, clears `g_remote_drag_left_down`, cancels any active incoming
/// drag, and hides `g_ghost_hwnd`.
///
/// Parameters:
/// - `controlled`: `true` when the remote peer's pointer enters this Windows desktop.
/// - `entry_x`: Entry X coordinate in virtual-desktop pixels.
/// - `entry_y`: Entry Y coordinate in virtual-desktop pixels.
void integrator_kvm_win_set_controlled(bool controlled, int32_t entry_x, int32_t entry_y) {
    if (!controlled) {
        g_remote_drag_left_down.store(false);
        g_drag_cancelled.store(true);
        HWND ghost_hw = g_ghost_hwnd.load();
        if (ghost_hw) {
            PostMessageW(ghost_hw, WM_APP_HIDE_GHOST, 0, 0);
        }
    } else {
        g_drag_cancelled.store(false);
        HWND guard_hw = g_guard_hwnd.load();
        if (guard_hw) {
            POINT* pt = new POINT{ entry_x, entry_y };
            if (!PostMessageW(guard_hw, WM_APP_WARP_CURSOR, 0, reinterpret_cast<LPARAM>(pt))) {
                delete pt;
                SetCursorPos(entry_x, entry_y);
            }
        } else {
            SetCursorPos(entry_x, entry_y);
        }
    }
}

/// Atomically takes ownership of any file paths captured by `EdgeDropTarget::DragEnter` on
/// `g_edge_hwnd` and serializes them as a heap-allocated, null-terminated UTF-8 JSON array string.
///
/// Returns:
/// - Heap-allocated `char*` buffer allocated via `std::malloc` (caller must release with
///   `integrator_kvm_win_free_str`), or `nullptr` if no drag paths are currently captured.
char* integrator_kvm_win_take_drag_paths() {
    std::vector<std::string> copy;
    {
        std::lock_guard<std::mutex> lk(g_captured_mutex);
        if (g_captured_paths.empty()) return nullptr;
        copy.swap(g_captured_paths);
    }
    std::string json = "[";
    for (size_t i = 0; i < copy.size(); ++i) {
        if (i > 0) json.push_back(',');
        json += json_escape(copy[i]);
    }
    json.push_back(']');
    char* out = static_cast<char*>(std::malloc(json.size() + 1));
    if (out) {
        std::memcpy(out, json.c_str(), json.size() + 1);
    }
    return out;
}

/// Releases a heap-allocated C string previously returned by `integrator_kvm_win_take_drag_paths`.
///
/// Parameters:
/// - `ptr`: Pointer returned by `integrator_kvm_win_take_drag_paths` (may be `nullptr`).
void integrator_kvm_win_free_str(char* ptr) {
    if (ptr) std::free(ptr);
}

/// Synthesizes a tagged `VK_ESCAPE` key-down and key-up pair via `SendInput` to cleanly abort
/// an active local Windows Explorer OLE drag loop after the drag session has been handed off
/// across the network to the remote macOS peer.
void integrator_kvm_win_cancel_local_drag() {
    INPUT inputs[2] = {};
    inputs[0].type = INPUT_KEYBOARD;
    inputs[0].ki.wVk = VK_ESCAPE;
    inputs[0].ki.dwExtraInfo = kIntegratorEventTag;
    inputs[1].type = INPUT_KEYBOARD;
    inputs[1].ki.wVk = VK_ESCAPE;
    inputs[1].ki.dwFlags = KEYEVENTF_KEYUP;
    inputs[1].ki.dwExtraInfo = kIntegratorEventTag;
    SendInput(2, inputs, sizeof(INPUT));
}

/// Synthesizes an absolute pointer move across the entire Windows virtual desktop using
/// `SendInput` with `MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK`.
///
/// Coordinate Normalization:
/// Clamps `(abs_x, abs_y)` to `[vx, vx + vw - 1]` x `[vy, vy + vh - 1]` and maps linearly onto
/// the Win32 normalized `[0, 65535]` virtual-desktop coordinate grid using nearest-integer
/// rounding (`std::lround`) to prevent truncation drift.
///
/// Parameters:
/// - `abs_x`: Target X coordinate in virtual-desktop pixels.
/// - `abs_y`: Target Y coordinate in virtual-desktop pixels.
void integrator_kvm_win_inject_mouse_move(int32_t abs_x, int32_t abs_y) {
    int vx = GetSystemMetrics(SM_XVIRTUALSCREEN);
    int vy = GetSystemMetrics(SM_YVIRTUALSCREEN);
    int vw = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    int vh = GetSystemMetrics(SM_CYVIRTUALSCREEN);
    if (vw <= 0 || vh <= 0) {
        vx = 0;
        vy = 0;
        vw = GetSystemMetrics(SM_CXSCREEN);
        vh = GetSystemMetrics(SM_CYSCREEN);
    }
    if (vw <= 1 || vh <= 1) return;

    int64_t min_x = static_cast<int64_t>(vx);
    int64_t max_x = min_x + static_cast<int64_t>(vw) - 1;
    int64_t min_y = static_cast<int64_t>(vy);
    int64_t max_y = min_y + static_cast<int64_t>(vh) - 1;

    int64_t cx = std::max(min_x, std::min(max_x, static_cast<int64_t>(abs_x)));
    int64_t cy = std::max(min_y, std::min(max_y, static_cast<int64_t>(abs_y)));
    LONG norm_x = static_cast<LONG>(std::lround((static_cast<double>(cx - min_x) * kWin32AbsoluteCoordMax) / static_cast<double>(vw - 1)));
    LONG norm_y = static_cast<LONG>(std::lround((static_cast<double>(cy - min_y) * kWin32AbsoluteCoordMax) / static_cast<double>(vh - 1)));

    INPUT inp = {};
    inp.type = INPUT_MOUSE;
    inp.mi.dx = norm_x;
    inp.mi.dy = norm_y;
    inp.mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK;
    inp.mi.dwExtraInfo = kIntegratorEventTag;
    SendInput(1, &inp, sizeof(INPUT));
}

/// Synthesizes a mouse button press or release transition via `SendInput`.
///
/// Special OLE Drag Handling:
/// When `button == 0` (Left mouse button), updates `g_remote_drag_left_down`. If a modal
/// `DoDragDrop` loop is currently active on `g_ole_thread` (`g_ole_drag_active == true`) and
/// the remote left button is released (`pressed == false`), posts `WM_NULL` to `g_ole_thread`
/// and injects a 0-delta `MOUSEEVENTF_MOVE` nudge so OLE immediately wakes up and calls
/// `RemoteDropSource::QueryContinueDrag` (which returns `DRAGDROP_S_DROP`), rather than
/// injecting a raw `MOUSEEVENTF_LEFTUP` that could race with OLE's internal capture loop.
///
/// Parameters:
/// - `button`: Button index (`0` = Left, `1` = Right, `2` = Middle).
/// - `pressed`: `true` for button-down, `false` for button-up.
void integrator_kvm_win_inject_mouse_button(int32_t button, bool pressed) {
    if (button == 0) {
        g_remote_drag_left_down.store(pressed);
        DWORD otid = g_ole_thread_id.load();
        if (!pressed && g_ole_drag_active.load() && otid != 0) {
            // Nudge OLE DoDragDrop modal loop cleanly so QueryContinueDrag drops immediately.
            PostThreadMessageW(otid, WM_NULL, 0, 0);
            INPUT nudge = {};
            nudge.type = INPUT_MOUSE;
            nudge.mi.dwFlags = MOUSEEVENTF_MOVE;
            nudge.mi.dwExtraInfo = kIntegratorEventTag;
            SendInput(1, &nudge, sizeof(INPUT));
            return;
        }
    }

    DWORD flag = 0;
    switch (button) {
    case 0: flag = pressed ? MOUSEEVENTF_LEFTDOWN : MOUSEEVENTF_LEFTUP; break;
    case 1: flag = pressed ? MOUSEEVENTF_RIGHTDOWN : MOUSEEVENTF_RIGHTUP; break;
    default: flag = pressed ? MOUSEEVENTF_MIDDLEDOWN : MOUSEEVENTF_MIDDLEUP; break;
    }

    INPUT inp = {};
    inp.type = INPUT_MOUSE;
    inp.mi.dwFlags = flag;
    inp.mi.dwExtraInfo = kIntegratorEventTag;
    SendInput(1, &inp, sizeof(INPUT));
}

/// Synthesizes vertical (`MOUSEEVENTF_WHEEL`) and/or horizontal (`MOUSEEVENTF_HWHEEL`) scroll
/// wheel deltas via `SendInput`.
///
/// Scales normalized KVM scroll units by `kInjectScrollScale` (`40.0` units per line, i.e.,
/// `120.0 / 3.0`) and clamps each axis to `[-kMaxScrollDelta, +kMaxScrollDelta]` (`+-60000.0`).
///
/// Parameters:
/// - `dx`: Horizontal scroll delta in normalized scroll lines (positive = right).
/// - `dy`: Vertical scroll delta in normalized scroll lines (positive = up/away).
void integrator_kvm_win_inject_scroll(double dx, double dy) {
    if (std::isfinite(dy) && dy != 0.0) {
        double scaled = std::max(-kMaxScrollDelta, std::min(kMaxScrollDelta, dy * kInjectScrollScale));
        int32_t delta = static_cast<int32_t>(std::lround(scaled));
        if (delta != 0) {
            INPUT inp = {};
            inp.type = INPUT_MOUSE;
            inp.mi.dwFlags = MOUSEEVENTF_WHEEL;
            inp.mi.mouseData = static_cast<DWORD>(delta);
            inp.mi.dwExtraInfo = kIntegratorEventTag;
            SendInput(1, &inp, sizeof(INPUT));
        }
    }
    if (std::isfinite(dx) && dx != 0.0) {
        double scaled = std::max(-kMaxScrollDelta, std::min(kMaxScrollDelta, dx * kInjectScrollScale));
        int32_t delta = static_cast<int32_t>(std::lround(scaled));
        if (delta != 0) {
            INPUT inp = {};
            inp.type = INPUT_MOUSE;
            inp.mi.dwFlags = MOUSEEVENTF_HWHEEL;
            inp.mi.mouseData = static_cast<DWORD>(delta);
            inp.mi.dwExtraInfo = kIntegratorEventTag;
            SendInput(1, &inp, sizeof(INPUT));
        }
    }
}

/// Synthesizes a keyboard key-down or key-up transition via `SendInput`, populating both the
/// virtual-key code (`wVk`) and hardware Set-1 scancode (`wScan` via `MapVirtualKeyW`) along
/// with `KEYEVENTF_EXTENDEDKEY` for navigation/right-side modifier keys.
///
/// Parameters:
/// - `vk`: Win32 Virtual-Key code (`VK_*`).
/// - `pressed`: `true` for key-down, `false` for key-up (`KEYEVENTF_KEYUP`).
/// - `extended`: `true` if the key requires the `0xE0` extended scancode prefix (`KEYEVENTF_EXTENDEDKEY`).
void integrator_kvm_win_inject_key(uint16_t vk, bool pressed, bool extended) {
    INPUT inp = {};
    inp.type = INPUT_KEYBOARD;
    inp.ki.wVk = vk;
    inp.ki.wScan = static_cast<WORD>(MapVirtualKeyW(vk, MAPVK_VK_TO_VSC));
    inp.ki.dwFlags = (pressed ? 0 : KEYEVENTF_KEYUP) | (extended ? KEYEVENTF_EXTENDEDKEY : 0);
    inp.ki.dwExtraInfo = kIntegratorEventTag;
    SendInput(1, &inp, sizeof(INPUT));
}

/// Updates the drag ghost HUD title/subtitle strings and asynchronously shows `g_ghost_hwnd`
/// offset from cursor coordinates `(x, y)` in virtual-desktop pixels.
///
/// Parameters:
/// - `x`: Cursor X coordinate in virtual-desktop pixels.
/// - `y`: Cursor Y coordinate in virtual-desktop pixels.
/// - `title`: Null-terminated UTF-8 primary title string (defaults to `"Universal Drag"` if null).
/// - `subtitle`: Null-terminated UTF-8 secondary status string (defaults to `"Streaming securely..."` if null).
void integrator_kvm_win_show_drag_ghost(
    int32_t x,
    int32_t y,
    const char* title,
    const char* subtitle
) {
    {
        std::lock_guard<std::mutex> lk(g_ghost_mutex);
        g_ghost_title = utf8_to_wide(title ? title : "Universal Drag");
        g_ghost_subtitle = utf8_to_wide(subtitle ? subtitle : "Streaming securely...");
    }
    g_ghost_x.store(x);
    g_ghost_y.store(y);
    HWND ghost_hw = g_ghost_hwnd.load();
    if (ghost_hw) {
        PostMessageW(ghost_hw, WM_APP_SHOW_GHOST, 0, 0);
    }
}

/// Asynchronously repositions the translucent drag ghost HUD window to follow updated cursor
/// coordinates `(x, y)` in virtual-desktop pixels.
///
/// Parameters:
/// - `x`: Cursor X coordinate in virtual-desktop pixels.
/// - `y`: Cursor Y coordinate in virtual-desktop pixels.
void integrator_kvm_win_move_drag_ghost(int32_t x, int32_t y) {
    g_ghost_x.store(x);
    g_ghost_y.store(y);
    HWND ghost_hw = g_ghost_hwnd.load();
    if (ghost_hw) {
        PostMessageW(ghost_hw, WM_APP_MOVE_GHOST, 0, 0);
    }
}

/// Asynchronously hides the translucent drag ghost HUD window (`g_ghost_hwnd`).
void integrator_kvm_win_hide_drag_ghost() {
    HWND ghost_hw = g_ghost_hwnd.load();
    if (ghost_hw) {
        PostMessageW(ghost_hw, WM_APP_HIDE_GHOST, 0, 0);
    }
}

/// Initiates an asynchronous native OLE `DoDragDrop` session on `g_ole_thread` using locally
/// staged file paths received from the remote macOS peer.
///
/// Validates all input pointers, clamps `count` to `kMaxDragFileCount` (`4096`), filters every
/// path through `is_valid_local_drag_path`, and posts an `OleDragPayload` via
/// `WM_APP_START_OLE_DRAG` to `g_ole_hwnd`.
///
/// Parameters:
/// - `paths_utf8`: Array of `count` null-terminated UTF-8 local filesystem path pointers.
/// - `count`: Number of elements in `paths_utf8`.
/// - `session_id`: Null-terminated UTF-8 drag session identifier string.
/// - `remote_left_still_held`: Initial state of `g_remote_drag_left_down` (if `false`,
///   `RemoteDropSource::QueryContinueDrag` immediately commits the drop on the first poll).
void integrator_kvm_win_begin_native_drag(
    const char* const* paths_utf8,
    int32_t count,
    const char* session_id,
    bool remote_left_still_held
) {
    HWND ole_hw = g_ole_hwnd.load();
    if (!paths_utf8 || count <= 0 || !ole_hw) return;
    g_drag_cancelled.store(false);
    g_remote_drag_left_down.store(remote_left_still_held);

    const int32_t max_items = std::min<int32_t>(count, kMaxDragFileCount);
    auto* payload = new OleDragPayload();
    payload->session_id = session_id ? session_id : "";
    for (int32_t i = 0; i < max_items; ++i) {
        if (!paths_utf8[i]) continue;
        std::wstring wp = utf8_to_wide(paths_utf8[i]);
        if (is_valid_local_drag_path(wp)) payload->paths.push_back(std::move(wp));
    }
    if (payload->paths.empty()) {
        delete payload;
        return;
    }
    if (!PostMessageW(ole_hw, WM_APP_START_OLE_DRAG, 0, reinterpret_cast<LPARAM>(payload))) {
        delete payload;
    }
}

/// Cancels any in-flight incoming remote OLE `DoDragDrop` session by setting `g_drag_cancelled`,
/// nudging `g_ole_thread`'s message loop with `WM_NULL`, and hiding `g_ghost_hwnd`.
void integrator_kvm_win_cancel_remote_drag() {
    g_drag_cancelled.store(true);
    DWORD otid = g_ole_thread_id.load();
    if (otid != 0) {
        PostThreadMessageW(otid, WM_NULL, 0, 0);
    }
    HWND ghost_hw = g_ghost_hwnd.load();
    if (ghost_hw) {
        PostMessageW(ghost_hw, WM_APP_HIDE_GHOST, 0, 0);
    }
}

/// Updates the atomic flag indicating whether a large (>128 MB) remote Mac file or folder
/// announcement is pending an on-demand pull when the user presses local `Ctrl+V` on Windows.
///
/// Parameters:
/// - `pending`: `true` if a remote file announcement is awaiting `Ctrl+V` pull; `false` otherwise.
void set_has_pending_remote_file(bool pending) {
    g_has_pending_remote_file.store(pending);
}

} // extern "C"

#endif // _WIN32
