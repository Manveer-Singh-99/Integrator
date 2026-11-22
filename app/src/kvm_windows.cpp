//
//  kvm_windows.cpp
//  Integrator Universal Input KVM - Windows Win32 Low-Level Driver & OLE D&D Bridge
//
//  ========================================================================================
//  1. MODULE PURPOSE & ARCHITECTURAL SCOPE
//  ========================================================================================
//  This file implements the native Win32/C++ backend for the Integrator Universal Input KVM
//  subsystem on Windows 10 and Windows 11.
//
//  Key Subsystem Capabilities:
//  - Low-Level OS Input Interception: Installs `WH_MOUSE_LL` and `WH_KEYBOARD_LL` hooks via
//    `SetWindowsHookExW` on a dedicated message-pump thread to capture raw mouse movements,
//    clicks, wheel deltas, and keyboard transitions before desktop windows receive them.
//  - Edge Probe & Corner Guard Windows: Creates 1-pixel layered, transparent, topmost windows
//    (`WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOOLWINDOW`) positioned along active display
//    boundaries to monitor edge dwell, corner exclusion zones, and incoming OLE drag sessions.
//  - Synthetic Input Injection: Synthesizes remote pointer movement, clicks, smooth scrolling,
//    and keyboard keystrokes using Win32 `SendInput` with virtual-key codes (`VK_*`), hardware
//    scancodes, and `KEYEVENTF_EXTENDEDKEY` flags.
//  - Fluent Drag Ghost HUD: Renders a translucent layered GDI window (`WS_EX_LAYERED`) displaying
//    live file drag badges and titles under the cursor during active cross-screen transfers.
//  - OLE COM Drag-and-Drop Bridging: Implements `IDropTarget` (`EdgeDropTarget`) to catch outgoing
//    Windows Explorer file drags at the screen boundary, and `IDropSource` / `IDataObject`
//    (`RemoteDropSource`) to execute native `DoDragDrop` calls onto Windows target applications.
//
//  ========================================================================================
//  2. ARCHITECTURAL LINKAGES & CALL FLOW
//  ========================================================================================
//  Upstream Callers:
//  - `src/kvm/windows_backend.rs`: Rust FFI bridge that invokes `extern "C"` functions:
//    - `integrator_kvm_win_start_hooks`: Starts hook and OLE worker threads.
//    - `integrator_kvm_win_stop_hooks`: Unhooks and terminates worker threads.
//    - `integrator_kvm_win_set_controlling`: Hides and parks the local Windows cursor.
//    - `integrator_kvm_win_set_controlled`: Warps and reveals cursor upon remote entry.
//    - `integrator_kvm_win_inject_*`: Synthesizes inputs into the Windows input queue.
//    - `integrator_kvm_win_show_drag_ghost` / `hide_drag_ghost`: Controls GDI HUD.
//    - `integrator_kvm_win_begin_native_drag`: Initiates `DoDragDrop` on OLE worker thread.
//
//  Downstream Callees:
//  - Win32 User32 (`SetWindowsHookExW`, `SendInput`, `CreateWindowExW`, `SetCursorPos`).
//  - Win32 GDI32 (`CreateSolidBrush`, `CreateFontW`, `FillRect`, `DrawTextW`).
//  - Win32 OLE32 / Shell32 (`OleInitialize`, `RegisterDragDrop`, `DoDragDrop`, `SHCreateDataObject`).
//  - Rust C FFI Callbacks: `KvmWinEventCallback` (`on_win_event`) and `KvmWinDragEndedCallback`.
//
//  ========================================================================================
//  3. THREADING & CONCURRENCY MODEL
//  ========================================================================================
//  - Input Hook Thread (`g_hook_thread`): Dedicated Win32 thread running a standard `GetMessage`
//    pump. Hosts `WH_MOUSE_LL` / `WH_KEYBOARD_LL` hooks, guard window, edge probe window, and
//    the GDI ghost HUD window.
//  - OLE STA Worker Thread (`g_ole_thread`): Dedicated COM STA thread hosting the message-only
//    window for executing blocking `DoDragDrop` loops without impeding the input hook pump.
//  - Fast-Path Lock-Free Synchronization: Atomic flags (`g_controlling_peer`, `g_physical_left_down`,
//    `g_swallowed_mod_keys`) provide sub-microsecond state checks inside the hook procedures.
//
//  ========================================================================================
//  4. SECURITY & SAFETY INVARIANTS
//  ========================================================================================
//  - Anti-Feedback Loop Tagging (`kIntegratorEventTag = 0x494E5447`): Synthetic events generated
//    by `SendInput` set `dwExtraInfo = 0x494E5447`. Hook procedures verify this tag and immediately
//    forward the event via `CallNextHookEx`, preventing infinite self-reinforcing input loops.
//  - UNC Path Traversal & Coercion Mitigation: `is_valid_local_drag_path` rejects remote UNC
//    network paths (`\\server\share`) to protect against NTLM reflection/relay exploits during
//    drag-and-drop operations.
//  - Exception Boundaries: No C++ exceptions cross the `extern "C"` ABI boundary into Rust.
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
#include <memory>
#include <mutex>
#include <string>
#include <vector>

static const ULONG_PTR kIntegratorEventTag = 0x494E5447ULL; // "INTG"

extern "C" void trigger_rust_remote_paste();
static std::atomic<bool> g_has_pending_remote_file{false};

/// Default fallback X coordinate in virtual-desktop pixels used when parking the hidden cursor.
static constexpr int32_t kDefaultParkX = 400;

/// Default fallback Y coordinate in virtual-desktop pixels used when parking the hidden cursor.
static constexpr int32_t kDefaultParkY = 300;

/// Corner exclusion margin in pixels keeping the invisible edge probe clear of screen corners.
static constexpr int kCornerGuardMarginPx = 36;

/// Thickness in pixels of the invisible topmost screen-edge OLE drag probe window.
static constexpr int kEdgeWindowWidthPx = 4;

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

typedef int32_t (*KvmWinEventCallback)(
    int32_t kind,
    double a,
    double b,
    double c,
    double d,
    uint64_t extra
);
typedef void (*KvmWinDragEndedCallback)(bool accepted, const char* session_id);

static std::mutex g_lifecycle_mutex;
static std::atomic<KvmWinEventCallback> g_kvm_cb{nullptr};
static std::atomic<KvmWinDragEndedCallback> g_drag_ended_cb{nullptr};

static std::atomic<bool> g_controlling_peer{false};
static std::atomic<bool> g_controlled_by_peer{false};
static std::atomic<bool> g_drag_probe_enabled{false};
static std::atomic<bool> g_physical_left_down{false};
static std::atomic<bool> g_remote_drag_left_down{false};
static std::atomic<bool> g_ole_drag_active{false};
static std::atomic<bool> g_drag_cancelled{false};
static std::atomic<uint32_t> g_swallowed_mod_keys{0};

enum SwallowedModBit : uint32_t {
    kModLShift = 1u << 0,
    kModRShift = 1u << 1,
    kModLCtrl  = 1u << 2,
    kModRCtrl  = 1u << 3,
    kModLAlt   = 1u << 4,
    kModRAlt   = 1u << 5,
    kModLWin   = 1u << 6,
    kModRWin   = 1u << 7,
};

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

static std::atomic<int32_t> g_park_x{kDefaultParkX};
static std::atomic<int32_t> g_park_y{kDefaultParkY};
static std::atomic<bool> g_park_pending{false};
static std::atomic<int32_t> g_edge_mode{0}; // 0=Left, 1=Right, 2=Top, 3=Bottom

static std::atomic<int32_t> g_ghost_x{0};
static std::atomic<int32_t> g_ghost_y{0};

static std::atomic<DWORD> g_hook_thread_id{0};
static std::atomic<DWORD> g_ole_thread_id{0};
static HANDLE g_hook_thread = nullptr;
static HANDLE g_ole_thread = nullptr;
static std::atomic<HWND> g_guard_hwnd{nullptr};
static std::atomic<HWND> g_edge_hwnd{nullptr};
static std::atomic<HWND> g_ghost_hwnd{nullptr};
static std::atomic<HWND> g_ole_hwnd{nullptr};
static std::atomic<HHOOK> g_mouse_hook{nullptr};
static std::atomic<HHOOK> g_kbd_hook{nullptr};
static std::atomic<HCURSOR> g_blank_cursor{nullptr};

static std::mutex g_captured_mutex;
static std::vector<std::string> g_captured_paths;

static std::mutex g_ghost_mutex;
static std::wstring g_ghost_title;
static std::wstring g_ghost_subtitle;

// Cached GDI resources created/destroyed on the ghost window thread
static HBRUSH g_ghost_bg_brush = nullptr;
static HBRUSH g_ghost_border_brush = nullptr;
static HBRUSH g_ghost_accent_brush = nullptr;
static HFONT g_ghost_title_font = nullptr;
static HFONT g_ghost_sub_font = nullptr;

enum CustomMsgs : UINT {
    WM_APP_SYNC_GUARD = WM_APP + 101,
    WM_APP_SYNC_EDGE = WM_APP + 102,
    WM_APP_SHOW_GHOST = WM_APP + 103,
    WM_APP_MOVE_GHOST = WM_APP + 104,
    WM_APP_HIDE_GHOST = WM_APP + 105,
    WM_APP_WARP_CURSOR = WM_APP + 106,
    WM_APP_START_OLE_DRAG = WM_APP + 107,
};

struct OleDragPayload {
    std::vector<std::wstring> paths;
    std::string session_id;
};

struct StartHandshake {
    HANDLE ev = nullptr;
    std::atomic<int> refs{2};

    void release() {
        if (refs.fetch_sub(1, std::memory_order_acq_rel) == 1) {
            if (ev) CloseHandle(ev);
            delete this;
        }
    }
};

static std::wstring utf8_to_wide(const char* s) {
    if (!s || !*s) return L"";
    int len = MultiByteToWideChar(CP_UTF8, 0, s, -1, nullptr, 0);
    if (len <= 0) return L"";
    std::wstring out(len - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s, -1, &out[0], len);
    return out;
}

static std::string wide_to_utf8(const wchar_t* ws) {
    if (!ws || !*ws) return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, ws, -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return "";
    std::string out(len - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, ws, -1, &out[0], len, nullptr, nullptr);
    return out;
}

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

static bool is_valid_local_drag_path(const std::wstring& path) {
    if (path.empty() || path.size() > 32760) return false;
    // Reject UNC network paths to avoid off-box NTLM coercion during OLE shell drag
    if (path.rfind(L"\\\\", 0) == 0 && path.rfind(L"\\\\?\\", 0) != 0) {
        return false;
    }
    DWORD attrs = GetFileAttributesW(path.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES;
}

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

static uint64_t read_current_modifiers() {
    return read_current_modifiers_with_swallowed(g_swallowed_mod_keys.load());
}

static void position_edge_window(HWND hwnd) {
    if (!hwnd) return;
    int vx = GetSystemMetrics(SM_XVIRTUALSCREEN);
    int vy = GetSystemMetrics(SM_YVIRTUALSCREEN);
    int vw = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    int vh = GetSystemMetrics(SM_CYVIRTUALSCREEN);
    if (vw <= 0 || vh <= 0) {
        vw = GetSystemMetrics(SM_CXSCREEN);
        vh = GetSystemMetrics(SM_CYSCREEN);
    }
    int guard = kCornerGuardMarginPx;
    int edge = g_edge_mode.load();
    int x = vx, y = vy, w = kEdgeWindowWidthPx, h = vh;
    switch (edge) {
    case 0: // Left
        x = vx;
        y = vy + guard;
        w = kEdgeWindowWidthPx;
        h = (vh > guard * 2) ? (vh - guard * 2) : vh;
        break;
    case 1: // Right
        x = vx + vw - kEdgeWindowWidthPx;
        y = vy + guard;
        w = kEdgeWindowWidthPx;
        h = (vh > guard * 2) ? (vh - guard * 2) : vh;
        break;
    case 2: // Top
        x = vx + guard;
        y = vy;
        w = (vw > guard * 2) ? (vw - guard * 2) : vw;
        h = kEdgeWindowWidthPx;
        break;
    case 3: // Bottom
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

/// OLE IDropTarget implementation attached to the invisible screen boundary edge window.
///
/// When the user drags files from Windows Explorer toward the configured screen boundary,
/// this target receives `DragEnter`, extracts the list of dragged files via the `CF_HDROP`
/// clipboard format, validates the paths against network UNC exploits, and caches them in
/// `g_captured_paths`. When the mouse subsequent crosses the screen border, `KvmService`
/// packages these paths into a `DragOffer` and hands off the drag session to the remote Mac.
class EdgeDropTarget final : public IDropTarget {
public:
    EdgeDropTarget() : ref_count_(1) {}

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

    ULONG STDMETHODCALLTYPE AddRef() override {
        return static_cast<ULONG>(InterlockedIncrement(&ref_count_));
    }

    ULONG STDMETHODCALLTYPE Release() override {
        ULONG c = static_cast<ULONG>(InterlockedDecrement(&ref_count_));
        if (c == 0) delete this;
        return c;
    }

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
                    HDROP hdrop = static_cast<HDROP>(GlobalLock(stg.hGlobal));
                    if (hdrop) {
                        UINT count = DragQueryFileW(hdrop, 0xFFFFFFFF, nullptr, 0);
                        for (UINT i = 0; i < count && i < 4096; ++i) {
                            UINT len = DragQueryFileW(hdrop, i, nullptr, 0);
                            if (len > 0 && len < 32760) {
                                std::wstring wpath(len + 1, L'\0');
                                if (DragQueryFileW(hdrop, i, &wpath[0], len + 1) > 0) {
                                    wpath.resize(len);
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
            *pdwEffect = has_items ? DROPEFFECT_COPY : DROPEFFECT_NONE;
        }
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE DragOver(DWORD, POINTL, DWORD* pdwEffect) override {
        if (pdwEffect) {
            std::lock_guard<std::mutex> lk(g_captured_mutex);
            *pdwEffect = g_captured_paths.empty() ? DROPEFFECT_NONE : DROPEFFECT_COPY;
        }
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE DragLeave() override {
        std::lock_guard<std::mutex> lk(g_captured_mutex);
        g_captured_paths.clear();
        return S_OK;
    }

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
    volatile LONG ref_count_;
};

// MARK: - OLE IDropSource for Remote -> Windows `DoDragDrop`

/// OLE IDropSource implementation driving synthetic file drag sessions on Windows.
///
/// When a file drag initiated on macOS enters the Windows desktop, the payload files are
/// staged to disk, and `DoDragDrop` is executed on the dedicated OLE STA thread using this source.
/// `QueryContinueDrag` continuously monitors `g_remote_drag_left_down` (updated by incoming
/// network mouse button messages from the Mac). When the user releases the physical mouse button
/// on the Mac, `g_remote_drag_left_down` becomes false, prompting `QueryContinueDrag` to return
/// `DRAGDROP_S_DROP` and completing the native drop into whatever Windows application is under the cursor.
class RemoteDropSource final : public IDropSource {
public:
    RemoteDropSource() : ref_count_(1) {}

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

    ULONG STDMETHODCALLTYPE AddRef() override {
        return static_cast<ULONG>(InterlockedIncrement(&ref_count_));
    }

    ULONG STDMETHODCALLTYPE Release() override {
        ULONG c = static_cast<ULONG>(InterlockedDecrement(&ref_count_));
        if (c == 0) delete this;
        return c;
    }

    HRESULT STDMETHODCALLTYPE QueryContinueDrag(BOOL fEscapePressed, DWORD /*grfKeyState*/) override {
        if (fEscapePressed || g_drag_cancelled.load()) {
            return DRAGDROP_S_CANCEL;
        }
        if (!g_remote_drag_left_down.load()) {
            return DRAGDROP_S_DROP;
        }
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE GiveFeedback(DWORD /*dwEffect*/) override {
        return DRAGDROP_S_USEDEFAULTCURSORS;
    }

private:
    volatile LONG ref_count_;
};

// MARK: - Low-Level Mouse & Keyboard Hooks

static LRESULT CALLBACK low_level_mouse_proc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION && lParam) {
        const MSLLHOOKSTRUCT* ms = reinterpret_cast<const MSLLHOOKSTRUCT*>(lParam);
        if ((ms->flags & LLMHF_INJECTED) != 0 || ms->dwExtraInfo == kIntegratorEventTag) {
            return CallNextHookEx(nullptr, nCode, wParam, lParam);
        }

        HWND edge_hwnd = g_edge_hwnd.load();
        if (wParam == WM_LBUTTONDOWN) {
            g_physical_left_down.store(true);
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
                if (g_controlling_peer.load() && g_park_pending.load()) {
                    if (std::abs(ms->pt.x - px) > 120 || std::abs(ms->pt.y - py) > 120) {
                        SetCursorPos(px, py);
                        return 1;
                    }
                    g_park_pending.store(false);
                }
                double dx = static_cast<double>(ms->pt.x - px);
                double dy = static_cast<double>(ms->pt.y - py);
                uint64_t lbtn = g_physical_left_down.load() ? 1ULL : 0ULL;
                decision = cb(1, static_cast<double>(ms->pt.x), static_cast<double>(ms->pt.y), dx, dy, lbtn);
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
                SetCursorPos(g_park_x.load(), g_park_y.load());
                return 1;
            } else if (decision == 1) {
                return 1;
            }
        }
    }
    return CallNextHookEx(nullptr, nCode, wParam, lParam);
}

static LRESULT CALLBACK low_level_kbd_proc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION && lParam) {
        const KBDLLHOOKSTRUCT* ks = reinterpret_cast<const KBDLLHOOKSTRUCT*>(lParam);
        if ((ks->flags & LLKHF_INJECTED) != 0 || ks->dwExtraInfo == kIntegratorEventTag) {
            return CallNextHookEx(nullptr, nCode, wParam, lParam);
        }
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

// MARK: - Window Procedures (Guard / Edge / Fluent Drag Ghost)

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
            SetWindowPos(hwnd, HWND_TOPMOST, vx, vy, vw, vh, SWP_SHOWWINDOW | SWP_NOACTIVATE);
            SetCursorPos(g_park_x.load(), g_park_y.load());
            g_park_pending.store(false);
        } else {
            g_park_pending.store(false);
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

static LRESULT CALLBACK ghost_wnd_proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_CREATE) {
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
        int x = g_ghost_x.load() + 18;
        int y = g_ghost_y.load() + 18;
        SetWindowPos(hwnd, HWND_TOPMOST, x, y, 272, 56, SWP_SHOWWINDOW | SWP_NOACTIVATE);
        InvalidateRect(hwnd, nullptr, TRUE);
        return 0;
    }
    if (msg == WM_APP_MOVE_GHOST) {
        if (IsWindowVisible(hwnd)) {
            int x = g_ghost_x.load() + 18;
            int y = g_ghost_y.load() + 18;
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
            size_t slash = wp.find_last_of(L"\\/");
            std::wstring dir = (slash == std::wstring::npos) ? L"" : wp.substr(0, slash);
            if (owned_pidls.empty()) {
                first_dir = dir;
            } else if (_wcsicmp(dir.c_str(), first_dir.c_str()) != 0) {
                same_parent = false;
            }

            PIDLIST_ABSOLUTE pidl = ILCreateFromPathW(wp.c_str());
            if (pidl) {
                owned_pidls.push_back(pidl);
                full_pidls.push_back(pidl);
                PCUIDLIST_RELATIVE child = ILFindLastID(pidl);
                if (child) child_pidls.push_back(child);
            }
        }
        bool accepted = false;
        if (!owned_pidls.empty()) {
            IDataObject* pDataObj = nullptr;
            HRESULT hr = E_FAIL;
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
                g_ole_drag_active.store(true);
                HRESULT dhr = DoDragDrop(pDataObj, src, DROPEFFECT_COPY, &effect);
                g_ole_drag_active.store(false);
                accepted = (dhr == DRAGDROP_S_DROP && effect != DROPEFFECT_NONE);
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

static DWORD WINAPI hook_thread_main(LPVOID param) {
    StartHandshake* hs = static_cast<StartHandshake*>(param);
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
    OleInitialize(nullptr);

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

    HWND guard_hw = CreateWindowExW(
        WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE | WS_EX_LAYERED,
        gwc.lpszClassName, L"", WS_POPUP,
        0, 0, 1, 1, nullptr, nullptr, hinst, nullptr
    );
    if (guard_hw) {
        SetLayeredWindowAttributes(guard_hw, 0, 1, LWA_ALPHA);
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
        drop_target = new EdgeDropTarget();
        RegisterDragDrop(edge_hw, drop_target);
    }
    g_edge_hwnd.store(edge_hw);

    HWND ghost_hw = CreateWindowExW(
        WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE | WS_EX_TRANSPARENT | WS_EX_LAYERED,
        fwc.lpszClassName, L"", WS_POPUP,
        0, 0, 272, 56, nullptr, nullptr, hinst, nullptr
    );
    if (ghost_hw) {
        SetLayeredWindowAttributes(ghost_hw, 0, 238, LWA_ALPHA);
    }
    g_ghost_hwnd.store(ghost_hw);

    MSG init_msg;
    PeekMessageW(&init_msg, nullptr, WM_USER, WM_USER, PM_NOREMOVE);

    HHOOK mh = SetWindowsHookExW(WH_MOUSE_LL, low_level_mouse_proc, hinst, 0);
    HHOOK kh = SetWindowsHookExW(WH_KEYBOARD_LL, low_level_kbd_proc, hinst, 0);
    g_mouse_hook.store(mh);
    g_kbd_hook.store(kh);

    if (hs) {
        if (hs->ev) SetEvent(hs->ev);
        hs->release();
    }

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
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
    if (guard_cur) DestroyWindow(guard_cur);
    if (ghost_cur) DestroyWindow(ghost_cur);
    if (drop_target) drop_target->Release();

    HCURSOR blank_cur = g_blank_cursor.exchange(nullptr);
    if (blank_cur) DestroyCursor(blank_cur);

    UnregisterClassW(gwc.lpszClassName, hinst);
    UnregisterClassW(ewc.lpszClassName, hinst);
    UnregisterClassW(fwc.lpszClassName, hinst);
    g_hook_thread_id.store(0);
    OleUninitialize();
    return 0;
}

static DWORD WINAPI ole_drag_thread_main(LPVOID param) {
    StartHandshake* hs = static_cast<StartHandshake*>(param);
    OleInitialize(nullptr);

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
    OleUninitialize();
    return 0;
}

extern "C" {

bool integrator_kvm_win_is_hook_active() {
    return g_mouse_hook.load() != nullptr && g_kbd_hook.load() != nullptr;
}

bool integrator_kvm_win_start_hooks(
    KvmWinEventCallback cb,
    KvmWinDragEndedCallback drag_ended_cb
) {
    std::lock_guard<std::mutex> lk(g_lifecycle_mutex);
    g_kvm_cb.store(cb);
    g_drag_ended_cb.store(drag_ended_cb);

    if (g_hook_thread_id.load() == 0) {
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

void integrator_kvm_win_stop_hooks() {
    std::lock_guard<std::mutex> lk(g_lifecycle_mutex);
    g_controlling_peer.store(false);
    g_controlled_by_peer.store(false);
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

void integrator_kvm_win_set_edge_probe(bool enabled, int32_t edge_mode) {
    g_drag_probe_enabled.store(enabled);
    g_edge_mode.store(edge_mode);
    HWND edge_hw = g_edge_hwnd.load();
    if (!enabled && edge_hw) {
        PostMessageW(edge_hw, WM_APP_SYNC_EDGE, 0, 0);
    }
}

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
    g_park_pending.store(controlling);
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

void integrator_kvm_win_set_controlled(bool controlled, int32_t entry_x, int32_t entry_y) {
    g_controlled_by_peer.store(controlled);
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

void integrator_kvm_win_free_str(char* ptr) {
    if (ptr) std::free(ptr);
}

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

void integrator_kvm_win_inject_mouse_move(int32_t abs_x, int32_t abs_y) {
    int vx = GetSystemMetrics(SM_XVIRTUALSCREEN);
    int vy = GetSystemMetrics(SM_YVIRTUALSCREEN);
    int vw = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    int vh = GetSystemMetrics(SM_CYVIRTUALSCREEN);
    if (vw <= 1 || vh <= 1) return;

    int32_t cx = std::max(vx, std::min(vx + vw - 1, abs_x));
    int32_t cy = std::max(vy, std::min(vy + vh - 1, abs_y));
    LONG norm_x = static_cast<LONG>(((static_cast<double>(cx - vx) * kWin32AbsoluteCoordMax) / static_cast<double>(vw - 1)));
    LONG norm_y = static_cast<LONG>(((static_cast<double>(cy - vy) * kWin32AbsoluteCoordMax) / static_cast<double>(vh - 1)));

    INPUT inp = {};
    inp.type = INPUT_MOUSE;
    inp.mi.dx = norm_x;
    inp.mi.dy = norm_y;
    inp.mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK;
    inp.mi.dwExtraInfo = kIntegratorEventTag;
    SendInput(1, &inp, sizeof(INPUT));
}

void integrator_kvm_win_inject_mouse_button(int32_t button, bool pressed) {
    if (button == 0) {
        g_remote_drag_left_down.store(pressed);
        DWORD otid = g_ole_thread_id.load();
        if (!pressed && g_ole_drag_active.load() && otid != 0) {
            // Nudge OLE DoDragDrop modal loop cleanly so QueryContinueDrag drops immediately
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

void integrator_kvm_win_inject_key(uint16_t vk, bool pressed, bool extended) {
    INPUT inp = {};
    inp.type = INPUT_KEYBOARD;
    inp.ki.wVk = vk;
    inp.ki.wScan = static_cast<WORD>(MapVirtualKeyW(vk, MAPVK_VK_TO_VSC));
    inp.ki.dwFlags = (pressed ? 0 : KEYEVENTF_KEYUP) | (extended ? KEYEVENTF_EXTENDEDKEY : 0);
    inp.ki.dwExtraInfo = kIntegratorEventTag;
    SendInput(1, &inp, sizeof(INPUT));
}

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

void integrator_kvm_win_move_drag_ghost(int32_t x, int32_t y) {
    g_ghost_x.store(x);
    g_ghost_y.store(y);
    HWND ghost_hw = g_ghost_hwnd.load();
    if (ghost_hw) {
        PostMessageW(ghost_hw, WM_APP_MOVE_GHOST, 0, 0);
    }
}

void integrator_kvm_win_hide_drag_ghost() {
    HWND ghost_hw = g_ghost_hwnd.load();
    if (ghost_hw) {
        PostMessageW(ghost_hw, WM_APP_HIDE_GHOST, 0, 0);
    }
}

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

    auto* payload = new OleDragPayload();
    payload->session_id = session_id ? session_id : "";
    for (int32_t i = 0; i < count; ++i) {
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
void set_has_pending_remote_file(bool pending) {
    g_has_pending_remote_file.store(pending);
}

} // extern "C"

#endif // _WIN32
