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

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

static const ULONG_PTR kIntegratorEventTag = 0x494E5447ULL; // "INTG"

typedef int32_t (*KvmWinEventCallback)(
    int32_t kind,
    double a,
    double b,
    double c,
    double d,
    uint64_t extra
);
typedef void (*KvmWinDragEndedCallback)(bool accepted, const char* session_id);

static KvmWinEventCallback g_kvm_cb = nullptr;
static KvmWinDragEndedCallback g_drag_ended_cb = nullptr;

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

static std::atomic<int32_t> g_park_x{400};
static std::atomic<int32_t> g_park_y{300};
static std::atomic<bool> g_park_pending{false};
static std::atomic<int32_t> g_edge_mode{0}; // 0=Left, 1=Right, 2=Top, 3=Bottom

static DWORD g_hook_thread_id = 0;
static DWORD g_ole_thread_id = 0;
static HWND g_guard_hwnd = nullptr;
static HWND g_edge_hwnd = nullptr;
static HWND g_ghost_hwnd = nullptr;
static HHOOK g_mouse_hook = nullptr;
static HHOOK g_kbd_hook = nullptr;
static HCURSOR g_blank_cursor = nullptr;

static std::mutex g_captured_mutex;
static std::vector<std::string> g_captured_paths;

static std::mutex g_ghost_mutex;
static std::wstring g_ghost_title;
static std::wstring g_ghost_subtitle;

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
    int guard = 36;
    int edge = g_edge_mode.load();
    int x = vx, y = vy, w = 4, h = vh;
    switch (edge) {
    case 0: // Left
        x = vx;
        y = vy + guard;
        w = 4;
        h = (vh > guard * 2) ? (vh - guard * 2) : vh;
        break;
    case 1: // Right
        x = vx + vw - 4;
        y = vy + guard;
        w = 4;
        h = (vh > guard * 2) ? (vh - guard * 2) : vh;
        break;
    case 2: // Top
        x = vx + guard;
        y = vy;
        w = (vw > guard * 2) ? (vw - guard * 2) : vw;
        h = 4;
        break;
    case 3: // Bottom
        x = vx + guard;
        y = vy + vh - 4;
        w = (vw > guard * 2) ? (vw - guard * 2) : vw;
        h = 4;
        break;
    default:
        break;
    }
    SetWindowPos(hwnd, HWND_TOPMOST, x, y, w, h, SWP_NOACTIVATE | SWP_NOOWNERZORDER);
}

// MARK: - OLE IDropTarget for Edge Catcher (captures active Explorer CF_HDROP drag at screen border)

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
                HDROP hdrop = static_cast<HDROP>(GlobalLock(stg.hGlobal));
                if (hdrop) {
                    UINT count = DragQueryFileW(hdrop, 0xFFFFFFFF, nullptr, 0);
                    for (UINT i = 0; i < count && i < 1000; ++i) {
                        UINT len = DragQueryFileW(hdrop, i, nullptr, 0);
                        if (len > 0) {
                            std::wstring wpath(len + 1, L'\0');
                            if (DragQueryFileW(hdrop, i, &wpath[0], len + 1) > 0) {
                                wpath.resize(len);
                                std::string u8 = wide_to_utf8(wpath.c_str());
                                if (!u8.empty()) found.push_back(std::move(u8));
                            }
                        }
                    }
                    GlobalUnlock(stg.hGlobal);
                }
                ReleaseStgMedium(&stg);
            }
        }
        {
            std::lock_guard<std::mutex> lk(g_captured_mutex);
            g_captured_paths = std::move(found);
        }
        if (pdwEffect) {
            *pdwEffect = g_captured_paths.empty() ? DROPEFFECT_NONE : DROPEFFECT_COPY;
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

        if (wParam == WM_LBUTTONDOWN) {
            g_physical_left_down.store(true);
            if (g_edge_hwnd && g_drag_probe_enabled.load() && !g_controlling_peer.load()) {
                PostMessageW(g_edge_hwnd, WM_APP_SYNC_EDGE, 1, 0);
            }
        } else if (wParam == WM_LBUTTONUP) {
            g_physical_left_down.store(false);
            if (g_edge_hwnd) {
                PostMessageW(g_edge_hwnd, WM_APP_SYNC_EDGE, 0, 0);
            }
        }

        if (g_kvm_cb) {
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
                decision = g_kvm_cb(1, static_cast<double>(ms->pt.x), static_cast<double>(ms->pt.y), dx, dy, lbtn);
                break;
            }
            case WM_LBUTTONDOWN:
                decision = g_kvm_cb(2, 0.0, 1.0, static_cast<double>(ms->pt.x), static_cast<double>(ms->pt.y), read_current_modifiers());
                break;
            case WM_LBUTTONUP:
                decision = g_kvm_cb(2, 0.0, 0.0, static_cast<double>(ms->pt.x), static_cast<double>(ms->pt.y), read_current_modifiers());
                break;
            case WM_RBUTTONDOWN:
                decision = g_kvm_cb(2, 1.0, 1.0, static_cast<double>(ms->pt.x), static_cast<double>(ms->pt.y), read_current_modifiers());
                break;
            case WM_RBUTTONUP:
                decision = g_kvm_cb(2, 1.0, 0.0, static_cast<double>(ms->pt.x), static_cast<double>(ms->pt.y), read_current_modifiers());
                break;
            case WM_MBUTTONDOWN:
                decision = g_kvm_cb(2, 2.0, 1.0, static_cast<double>(ms->pt.x), static_cast<double>(ms->pt.y), read_current_modifiers());
                break;
            case WM_MBUTTONUP:
                decision = g_kvm_cb(2, 2.0, 0.0, static_cast<double>(ms->pt.x), static_cast<double>(ms->pt.y), read_current_modifiers());
                break;
            case WM_MOUSEWHEEL: {
                SHORT delta = static_cast<SHORT>(HIWORD(ms->mouseData));
                double dy = static_cast<double>(delta) / 120.0 * 3.0;
                decision = g_kvm_cb(3, 0.0, dy, 0.0, 0.0, read_current_modifiers());
                break;
            }
            case WM_MOUSEHWHEEL: {
                SHORT delta = static_cast<SHORT>(HIWORD(ms->mouseData));
                double dx = static_cast<double>(delta) / 120.0 * 3.0;
                decision = g_kvm_cb(3, dx, 0.0, 0.0, 0.0, read_current_modifiers());
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
        uint32_t sw_bit = swallowed_mod_bit_for_vk(ks->vkCode);
        uint32_t preview_sw = g_swallowed_mod_keys.load();
        if (sw_bit != 0 && g_controlling_peer.load()) {
            preview_sw = pressed ? (preview_sw | sw_bit) : (preview_sw & ~sw_bit);
        }
        if (g_kvm_cb) {
            int32_t decision = g_kvm_cb(
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
    if (msg == WM_SETCURSOR && g_controlling_peer.load() && g_blank_cursor) {
        SetCursor(g_blank_cursor);
        return TRUE;
    }
    if (msg == WM_APP_SYNC_GUARD) {
        if (wParam != 0) {
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
            int rx = static_cast<int>(static_cast<int16_t>(LOWORD(lParam)));
            int ry = static_cast<int>(static_cast<int16_t>(HIWORD(lParam)));
            SetCursorPos(rx, ry);
        }
        return 0;
    }
    if (msg == WM_APP_WARP_CURSOR) {
        int x = static_cast<int>(static_cast<int16_t>(LOWORD(lParam)));
        int y = static_cast<int>(static_cast<int16_t>(HIWORD(lParam)));
        SetCursorPos(x, y);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static LRESULT CALLBACK edge_wnd_proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
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
    if (msg == WM_PAINT) {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        RECT rc;
        GetClientRect(hwnd, &rc);

        HBRUSH bg = CreateSolidBrush(RGB(28, 32, 42));
        HBRUSH border = CreateSolidBrush(RGB(86, 156, 255));
        FillRect(hdc, &rc, bg);
        FrameRect(hdc, &rc, border);
        DeleteObject(bg);
        DeleteObject(border);

        RECT accent = { 0, 0, 5, rc.bottom };
        HBRUSH acc = CreateSolidBrush(RGB(56, 189, 248));
        FillRect(hdc, &accent, acc);
        DeleteObject(acc);

        SetBkMode(hdc, TRANSPARENT);
        HFONT titleFont = CreateFontW(18, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_OUTLINE_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            VARIABLE_PITCH, L"Segoe UI");
        HFONT subFont = CreateFontW(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_OUTLINE_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            VARIABLE_PITCH, L"Segoe UI");

        std::wstring title, sub;
        {
            std::lock_guard<std::mutex> lk(g_ghost_mutex);
            title = g_ghost_title;
            sub = g_ghost_subtitle;
        }

        HGDIOBJ oldFont = SelectObject(hdc, titleFont);
        SetTextColor(hdc, RGB(244, 247, 252));
        RECT tr = { 16, 8, rc.right - 12, 30 };
        DrawTextW(hdc, title.c_str(), -1, &tr, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);

        SelectObject(hdc, subFont);
        SetTextColor(hdc, RGB(165, 180, 200));
        RECT sr = { 16, 30, rc.right - 12, 50 };
        DrawTextW(hdc, sub.c_str(), -1, &sr, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);

        SelectObject(hdc, oldFont);
        DeleteObject(titleFont);
        DeleteObject(subFont);
        EndPaint(hwnd, &ps);
        return 0;
    }
    if (msg == WM_APP_SHOW_GHOST) {
        int x = static_cast<int>(static_cast<int16_t>(LOWORD(lParam))) + 18;
        int y = static_cast<int>(static_cast<int16_t>(HIWORD(lParam))) + 18;
        SetWindowPos(hwnd, HWND_TOPMOST, x, y, 272, 56, SWP_SHOWWINDOW | SWP_NOACTIVATE);
        InvalidateRect(hwnd, nullptr, TRUE);
        return 0;
    }
    if (msg == WM_APP_MOVE_GHOST) {
        if (IsWindowVisible(hwnd)) {
            int x = static_cast<int>(static_cast<int16_t>(LOWORD(lParam))) + 18;
            int y = static_cast<int>(static_cast<int16_t>(HIWORD(lParam))) + 18;
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

static DWORD WINAPI hook_thread_main(LPVOID param) {
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
    OleInitialize(nullptr);

    BYTE and_mask = 0xFF;
    BYTE xor_mask = 0x00;
    g_blank_cursor = CreateCursor(GetModuleHandleW(nullptr), 0, 0, 1, 1, &and_mask, &xor_mask);

    HINSTANCE hinst = GetModuleHandleW(nullptr);

    WNDCLASSW gwc = {};
    gwc.lpfnWndProc = guard_wnd_proc;
    gwc.hInstance = hinst;
    gwc.hCursor = g_blank_cursor;
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

    g_guard_hwnd = CreateWindowExW(
        WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE | WS_EX_LAYERED,
        gwc.lpszClassName, L"", WS_POPUP,
        0, 0, 1, 1, nullptr, nullptr, hinst, nullptr
    );
    if (g_guard_hwnd) {
        SetLayeredWindowAttributes(g_guard_hwnd, 0, 1, LWA_ALPHA);
    }

    g_edge_hwnd = CreateWindowExW(
        WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE | WS_EX_LAYERED,
        ewc.lpszClassName, L"", WS_POPUP,
        0, 0, 4, 100, nullptr, nullptr, hinst, nullptr
    );
    EdgeDropTarget* drop_target = nullptr;
    if (g_edge_hwnd) {
        SetLayeredWindowAttributes(g_edge_hwnd, 0, 1, LWA_ALPHA);
        drop_target = new EdgeDropTarget();
        RegisterDragDrop(g_edge_hwnd, drop_target);
    }

    g_ghost_hwnd = CreateWindowExW(
        WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE | WS_EX_TRANSPARENT | WS_EX_LAYERED,
        fwc.lpszClassName, L"", WS_POPUP,
        0, 0, 272, 56, nullptr, nullptr, hinst, nullptr
    );
    if (g_ghost_hwnd) {
        SetLayeredWindowAttributes(g_ghost_hwnd, 0, 238, LWA_ALPHA);
    }

    g_mouse_hook = SetWindowsHookExW(WH_MOUSE_LL, low_level_mouse_proc, hinst, 0);
    g_kbd_hook = SetWindowsHookExW(WH_KEYBOARD_LL, low_level_kbd_proc, hinst, 0);

    HANDLE ready_ev = static_cast<HANDLE>(param);
    if (ready_ev) SetEvent(ready_ev);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    if (g_mouse_hook) UnhookWindowsHookEx(g_mouse_hook);
    if (g_kbd_hook) UnhookWindowsHookEx(g_kbd_hook);
    if (g_edge_hwnd) RevokeDragDrop(g_edge_hwnd);
    if (drop_target) drop_target->Release();
    OleUninitialize();
    return 0;
}

static DWORD WINAPI ole_drag_thread_main(LPVOID param) {
    OleInitialize(nullptr);
    HANDLE ready_ev = static_cast<HANDLE>(param);
    MSG msg;
    PeekMessageW(&msg, nullptr, WM_USER, WM_USER, PM_NOREMOVE);
    if (ready_ev) SetEvent(ready_ev);

    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        if (msg.message == WM_APP_START_OLE_DRAG && msg.lParam) {
            std::unique_ptr<OleDragPayload> payload(reinterpret_cast<OleDragPayload*>(msg.lParam));
            std::vector<PIDLIST_ABSOLUTE> owned_pidls;
            std::vector<LPCITEMIDLIST> full_pidls;
            std::vector<LPCITEMIDLIST> child_pidls;
            PIDLIST_ABSOLUTE parent_pidl = nullptr;
            bool same_parent = true;
            std::wstring first_dir;

            for (const auto& wp : payload->paths) {
                size_t slash = wp.find_last_of(L"\\/");
                std::wstring dir = (slash == std::wstring::npos) ? L"" : wp.substr(0, slash);
                if (owned_pidls.empty()) {
                    first_dir = dir;
                } else if (dir != first_dir) {
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
                    if (g_ghost_hwnd) {
                        PostMessageW(g_ghost_hwnd, WM_APP_HIDE_GHOST, 0, 0);
                    }
                    g_ole_drag_active.store(true);
                    HRESULT dhr = DoDragDrop(pDataObj, src, DROPEFFECT_COPY | DROPEFFECT_LINK, &effect);
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
            if (g_ghost_hwnd) {
                PostMessageW(g_ghost_hwnd, WM_APP_HIDE_GHOST, 0, 0);
            }
            if (g_drag_ended_cb) {
                g_drag_ended_cb(accepted, payload->session_id.c_str());
            }
        } else {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    OleUninitialize();
    return 0;
}

extern "C" {

bool integrator_kvm_win_start_hooks(
    KvmWinEventCallback cb,
    KvmWinDragEndedCallback drag_ended_cb
) {
    g_kvm_cb = cb;
    g_drag_ended_cb = drag_ended_cb;

    if (!g_hook_thread_id) {
        HANDLE ev = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        HANDLE th = CreateThread(nullptr, 0, hook_thread_main, ev, 0, &g_hook_thread_id);
        if (ev) {
            WaitForSingleObject(ev, 2000);
            CloseHandle(ev);
        }
        if (th) CloseHandle(th);
    }
    if (!g_ole_thread_id) {
        HANDLE ev2 = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        HANDLE th2 = CreateThread(nullptr, 0, ole_drag_thread_main, ev2, 0, &g_ole_thread_id);
        if (ev2) {
            WaitForSingleObject(ev2, 2000);
            CloseHandle(ev2);
        }
        if (th2) CloseHandle(th2);
    }
    return g_mouse_hook != nullptr && g_kbd_hook != nullptr;
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
    *out_x = static_cast<double>(x);
    *out_y = static_cast<double>(y);
    *out_w = static_cast<double>(w);
    *out_h = static_cast<double>(h);
}

void integrator_kvm_win_set_edge_probe(bool enabled, int32_t edge_mode) {
    g_drag_probe_enabled.store(enabled);
    g_edge_mode.store(edge_mode);
    if (!enabled && g_edge_hwnd) {
        PostMessageW(g_edge_hwnd, WM_APP_SYNC_EDGE, 0, 0);
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
    if (g_edge_hwnd) {
        PostMessageW(g_edge_hwnd, WM_APP_SYNC_EDGE, 0, 0);
    }
    if (g_guard_hwnd) {
        LPARAM lp = MAKELPARAM(static_cast<uint16_t>(restore_x), static_cast<uint16_t>(restore_y));
        PostMessageW(g_guard_hwnd, WM_APP_SYNC_GUARD, controlling ? 1 : 0, lp);
    }
}

void integrator_kvm_win_set_controlled(bool controlled, int32_t entry_x, int32_t entry_y) {
    g_controlled_by_peer.store(controlled);
    if (!controlled) {
        g_remote_drag_left_down.store(false);
        g_drag_cancelled.store(true);
        if (g_ghost_hwnd) {
            PostMessageW(g_ghost_hwnd, WM_APP_HIDE_GHOST, 0, 0);
        }
    } else {
        g_drag_cancelled.store(false);
        if (g_guard_hwnd) {
            PostMessageW(
                g_guard_hwnd,
                WM_APP_WARP_CURSOR,
                0,
                MAKELPARAM(static_cast<uint16_t>(entry_x), static_cast<uint16_t>(entry_y))
            );
        } else {
            SetCursorPos(entry_x, entry_y);
        }
    }
}

void integrator_kvm_win_warp_cursor(int32_t x, int32_t y) {
    SetCursorPos(x, y);
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

    LONG norm_x = static_cast<LONG>(((static_cast<double>(abs_x - vx) * 65535.0) / static_cast<double>(vw - 1)));
    LONG norm_y = static_cast<LONG>(((static_cast<double>(abs_y - vy) * 65535.0) / static_cast<double>(vh - 1)));

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
        if (!pressed && g_ole_drag_active.load() && g_ole_thread_id) {
            // Nudge OLE DoDragDrop modal loop cleanly so QueryContinueDrag drops immediately
            PostThreadMessageW(g_ole_thread_id, WM_NULL, 0, 0);
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
    if (dy != 0.0) {
        INPUT inp = {};
        inp.type = INPUT_MOUSE;
        inp.mi.dwFlags = MOUSEEVENTF_WHEEL;
        inp.mi.mouseData = static_cast<DWORD>(static_cast<int32_t>(dy * 40.0));
        inp.mi.dwExtraInfo = kIntegratorEventTag;
        SendInput(1, &inp, sizeof(INPUT));
    }
    if (dx != 0.0) {
        INPUT inp = {};
        inp.type = INPUT_MOUSE;
        inp.mi.dwFlags = MOUSEEVENTF_HWHEEL;
        inp.mi.mouseData = static_cast<DWORD>(static_cast<int32_t>(dx * 40.0));
        inp.mi.dwExtraInfo = kIntegratorEventTag;
        SendInput(1, &inp, sizeof(INPUT));
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
    if (g_ghost_hwnd) {
        PostMessageW(g_ghost_hwnd, WM_APP_SHOW_GHOST, 0,
            MAKELPARAM(static_cast<uint16_t>(x), static_cast<uint16_t>(y)));
    }
}

void integrator_kvm_win_move_drag_ghost(int32_t x, int32_t y) {
    if (g_ghost_hwnd) {
        PostMessageW(g_ghost_hwnd, WM_APP_MOVE_GHOST, 0,
            MAKELPARAM(static_cast<uint16_t>(x), static_cast<uint16_t>(y)));
    }
}

void integrator_kvm_win_hide_drag_ghost() {
    if (g_ghost_hwnd) {
        PostMessageW(g_ghost_hwnd, WM_APP_HIDE_GHOST, 0, 0);
    }
}

void integrator_kvm_win_begin_native_drag(
    const char* const* paths_utf8,
    int32_t count,
    const char* session_id,
    bool remote_left_still_held
) {
    if (!paths_utf8 || count <= 0 || !g_ole_thread_id) return;
    g_drag_cancelled.store(false);
    g_remote_drag_left_down.store(remote_left_still_held);

    auto* payload = new OleDragPayload();
    payload->session_id = session_id ? session_id : "";
    for (int32_t i = 0; i < count; ++i) {
        std::wstring wp = utf8_to_wide(paths_utf8[i]);
        if (!wp.empty()) payload->paths.push_back(std::move(wp));
    }
    if (payload->paths.empty()) {
        delete payload;
        return;
    }
    if (!PostThreadMessageW(g_ole_thread_id, WM_APP_START_OLE_DRAG, 0, reinterpret_cast<LPARAM>(payload))) {
        delete payload;
    }
}

void integrator_kvm_win_cancel_remote_drag() {
    g_drag_cancelled.store(true);
    if (g_ole_thread_id) {
        PostThreadMessageW(g_ole_thread_id, WM_NULL, 0, 0);
    }
    if (g_ghost_hwnd) {
        PostMessageW(g_ghost_hwnd, WM_APP_HIDE_GHOST, 0, 0);
    }
}

} // extern "C"

#endif // _WIN32
