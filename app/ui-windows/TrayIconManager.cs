// ==============================================================================================
// Integrator Windows Native System Tray Manager (`ui-windows/TrayIconManager.cs`)
//
// 1. Module Purpose & System Scope:
//    - Manages the native Win32 notification icon in the Windows taskbar system tray (Notification Area)
//      via `Shell_NotifyIconW` and `NOTIFYICON_VERSION_4`.
//    - Implemented with zero dependencies on System.Windows.Forms or legacy WebView components to maintain
//      minimal memory footprint and clean unmanaged resource management.
//    - Replicates the exact functional menu layout of the macOS `NSStatusItem` menu for cross-platform parity:
//      Show Dashboard, Paste Remote Item, Toggle Extended Screen, Open Clipboard Cache, and Quit Integrator.
//
// 2. Architectural Linkages & Native Core Bridge:
//    - Upstream Caller: `IntegratorUI.App` instantiates `TrayIconManager` during `OnLaunched` and disposes it on exit.
//    - Downstream APIs:
//        * Shell32: `Shell_NotifyIconW` (NIM_ADD, NIM_DELETE, NIM_SETVERSION).
//        * User32: Window registration (`RegisterClassExW`), message pump window (`CreateWindowExW`),
//          context menu generation (`CreatePopupMenu`, `AppendMenuW`, `TrackPopupMenuEx`), cursor tracking (`GetCursorPos`).
//        * CoreBridge: Asynchronous invocation of `CoreBridge.TrayAction` on the CLR thread pool.
//
// 3. Threading & Concurrency Model:
//    - Dedicated Message Window: Creates a zero-size, top-level unmanaged window on the STA UI thread to
//      receive `WM_TRAYICON` notification callbacks from the Windows shell.
//    - Non-Blocking Menu Handlers: Context menu actions (such as `paste_remote` or `toggle_display`) are
//      dispatched onto background `ThreadPool` threads via `ThreadPool.QueueUserWorkItem` to prevent
//      blocking the Win32 message loop or causing UI stalls.
//
// 4. Security & Safety Invariants:
//    - Shell Crash Resilience: Registers for the `"TaskbarCreated"` broadcast message via `RegisterWindowMessageW`.
//      If `explorer.exe` crashes or restarts, the tray icon is automatically re-created without user intervention.
//    - Exception Boundary Protection: The unmanaged `WndProc` trampoline wraps all managed code in a catch-all block,
//      preventing CLR exceptions from unwinding across unmanaged Win32 callback boundaries.
//    - Resource Hygiene: Complete `IDisposable` implementation explicitly frees `_hIcon`, destroys `_hwnd`,
//      deletes the notification icon via `NIM_DELETE`, and unregisters the window class with `UnregisterClassW`.
// ==============================================================================================

using System;
using System.IO;
using System.Runtime.InteropServices;

namespace IntegratorUI
{
    /// <summary>
    /// Native Win32 Shell_NotifyIconW tray icon manager (zero WinForms / WebView dependencies).
    /// Mirrors the macOS NSStatusItem menu identically.
    /// </summary>
    internal sealed class TrayIconManager : IDisposable
    {
        private const int WM_USER = 0x0400;
        private const int WM_TRAYICON = WM_USER + 42;
        private const int NIN_SELECT = 0x0400;
        private const int NIN_KEYSELECT = 0x0401;
        private const int WM_LBUTTONUP = 0x0202;
        private const int WM_LBUTTONDBLCLK = 0x0203;
        private const int WM_RBUTTONUP = 0x0205;
        private const int WM_CONTEXTMENU = 0x007B;

        private const int SM_CXSMICON = 49;
        private const int SM_CYSMICON = 50;

        private const uint NIF_MESSAGE = 0x00000001;
        private const uint NIF_ICON = 0x00000002;
        private const uint NIF_TIP = 0x00000004;
        private const uint NIF_SHOWTIP = 0x00000080;

        private const uint NIM_ADD = 0x00000000;
        private const uint NIM_DELETE = 0x00000002;
        private const uint NIM_SETVERSION = 0x00000004;
        private const uint NOTIFYICON_VERSION_4 = 4;

        private const uint IMAGE_ICON = 1;
        private const uint LR_LOADFROMFILE = 0x00000010;
        private const uint LR_DEFAULTSIZE = 0x00000040;
        private const uint LR_SHARED = 0x00008000;
        private const uint MF_STRING = 0x00000000;
        private const uint MF_SEPARATOR = 0x00000800;
        private const uint TPM_RIGHTBUTTON = 0x0002;
        private const uint TPM_NONOTIFY = 0x0080;
        private const uint TPM_RETURNCMD = 0x0100;

        private const int ID_SHOW = 1001;
        private const int ID_PASTE = 1002;
        private const int ID_DISPLAY = 1003;
        private const int ID_CACHE = 1004;
        private const int ID_QUIT = 1005;

        private readonly Action _onShowWindow;
        private readonly Action _onQuit;
        private IntPtr _hInst;
        private IntPtr _hwnd;
        private IntPtr _hIcon;
        private bool _ownsIcon;
        private string? _className;
        private uint _taskbarCreatedMsg;
        private WndProcDelegate? _wndProcDelegate;
        private bool _added;
        private bool _disposed;

        /// <summary>
        /// Native window procedure delegate matching Win32 WNDPROC signature.
        /// </summary>
        private delegate IntPtr WndProcDelegate(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

        /// <summary>
        /// Win32 WNDCLASSEXW structure for registering the hidden tray message window class.
        /// </summary>
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WNDCLASSEXW
        {
            public uint cbSize;
            public uint style;
            public IntPtr lpfnWndProc;
            public int cbClsExtra;
            public int cbWndExtra;
            public IntPtr hInstance;
            public IntPtr hIcon;
            public IntPtr hCursor;
            public IntPtr hbrBackground;
            public string? lpszMenuName;
            public string lpszClassName;
            public IntPtr hIconSm;
        }

        /// <summary>
        /// Win32 NOTIFYICONDATAW structure for communicating with Shell_NotifyIconW.
        /// </summary>
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct NOTIFYICONDATAW
        {
            public uint cbSize;
            public IntPtr hWnd;
            public uint uID;
            public uint uFlags;
            public uint uCallbackMessage;
            public IntPtr hIcon;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
            public string szTip;
            public uint dwState;
            public uint dwStateMask;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string szInfo;
            public uint uTimeoutOrVersion;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
            public string szInfoTitle;
            public uint dwInfoFlags;
            public Guid guidItem;
            public IntPtr hBalloonIcon;
        }

        /// <summary>
        /// Win32 POINT structure for cursor coordinate capture.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        private struct POINT
        {
            public int X;
            public int Y;
        }

        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern ushort RegisterClassExW(ref WNDCLASSEXW lpwcx);

        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool UnregisterClassW(string lpClassName, IntPtr hInstance);

        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint RegisterWindowMessageW(string lpString);

        [DllImport("user32.dll")]
        private static extern int GetSystemMetrics(int nIndex);

        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateWindowExW(
            uint dwExStyle, string lpClassName, string lpWindowName, uint dwStyle,
            int x, int y, int nWidth, int nHeight, IntPtr hWndParent, IntPtr hMenu,
            IntPtr hInstance, IntPtr lpParam);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool DestroyWindow(IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern IntPtr DefWindowProcW(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        private static extern IntPtr GetModuleHandleW(string? lpModuleName);

        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr LoadImageW(
            IntPtr hInst, string lpszName, uint uType, int cxDesired, int cyDesired, uint fuLoad);

        [DllImport("user32.dll")]
        private static extern bool DestroyIcon(IntPtr hIcon);

        [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
        private static extern bool Shell_NotifyIconW(uint dwMessage, ref NOTIFYICONDATAW lpData);

        [DllImport("user32.dll")]
        private static extern IntPtr CreatePopupMenu();

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern bool AppendMenuW(IntPtr hMenu, uint uFlags, UIntPtr uIDNewItem, string? lpNewItem);

        [DllImport("user32.dll")]
        private static extern bool DestroyMenu(IntPtr hMenu);

        [DllImport("user32.dll")]
        private static extern uint TrackPopupMenuEx(
            IntPtr hMenu, uint uFlags, int x, int y, IntPtr hwnd, IntPtr lptpm);

        [DllImport("user32.dll")]
        private static extern bool GetCursorPos(out POINT lpPoint);

        [DllImport("user32.dll")]
        private static extern bool SetForegroundWindow(IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern bool PostMessageW(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);

        /// <summary>
        /// Initializes the system tray notification icon and its underlying Win32 message window.
        /// </summary>
        /// <param name="onShowWindow">Callback action invoked to restore and activate the dashboard window.</param>
        /// <param name="onQuit">Callback action invoked when the user selects Quit from the context menu.</param>
        public TrayIconManager(Action onShowWindow, Action onQuit)
        {
            _onShowWindow = onShowWindow;
            _onQuit = onQuit;
            InitTray();
        }

        /// <summary>
        /// Registers the window class, creates the hidden helper window, loads the icon, and adds the tray item.
        /// </summary>
        private void InitTray()
        {
            _wndProcDelegate = WndProc;
            _hInst = GetModuleHandleW(null);
            _className = "IntegratorTrayMsgWindow_" + Environment.ProcessId + "_" + Guid.NewGuid().ToString("N");
            _taskbarCreatedMsg = RegisterWindowMessageW("TaskbarCreated");

            var wc = new WNDCLASSEXW
            {
                cbSize = (uint)Marshal.SizeOf<WNDCLASSEXW>(),
                lpfnWndProc = Marshal.GetFunctionPointerForDelegate(_wndProcDelegate),
                hInstance = _hInst,
                lpszClassName = _className
            };
            RegisterClassExW(ref wc);

            // Top-level zero-size helper window (supports TrackPopupMenu + NOTIFYICON_VERSION_4 cleanly).
            _hwnd = CreateWindowExW(0, _className, "Integrator Tray", 0, 0, 0, 0, 0, IntPtr.Zero, IntPtr.Zero, _hInst, IntPtr.Zero);

            int cx = GetSystemMetrics(SM_CXSMICON);
            int cy = GetSystemMetrics(SM_CYSMICON);
            if (cx <= 0) cx = 16;
            if (cy <= 0) cy = 16;

            string iconPath = Path.Combine(AppContext.BaseDirectory, "icon.ico");
            if (File.Exists(iconPath))
            {
                _hIcon = LoadImageW(IntPtr.Zero, iconPath, IMAGE_ICON, cx, cy, LR_LOADFROMFILE);
                _ownsIcon = _hIcon != IntPtr.Zero;
            }
            if (_hIcon == IntPtr.Zero)
            {
                // Standard application icon fallback (IDI_APPLICATION requires hInst = IntPtr.Zero + LR_SHARED).
                _hIcon = LoadImageW(IntPtr.Zero, "#32512", IMAGE_ICON, cx, cy, LR_DEFAULTSIZE | LR_SHARED);
                _ownsIcon = false;
            }

            AddTrayIcon();
        }

        /// <summary>
        /// Calls Shell_NotifyIconW to add the icon and configure NOTIFYICON_VERSION_4 behavior.
        /// </summary>
        private void AddTrayIcon()
        {
            if (_disposed || _hwnd == IntPtr.Zero) return;

            var nid = new NOTIFYICONDATAW
            {
                cbSize = (uint)Marshal.SizeOf<NOTIFYICONDATAW>(),
                hWnd = _hwnd,
                uID = 1,
                uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_SHOWTIP,
                uCallbackMessage = WM_TRAYICON,
                hIcon = _hIcon,
                szTip = "Integrator v1.0 — Cross-Device Bridge",
                szInfo = string.Empty,
                szInfoTitle = string.Empty,
                uTimeoutOrVersion = NOTIFYICON_VERSION_4
            };

            _added = Shell_NotifyIconW(NIM_ADD, ref nid);
            if (_added)
            {
                Shell_NotifyIconW(NIM_SETVERSION, ref nid);
            }
        }

        /// <summary>
        /// Unmanaged window procedure dispatching tray interactions, double clicks, and shell messages.
        /// </summary>
        private IntPtr WndProc(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam)
        {
            try
            {
                // Automatically re-register tray icon if explorer.exe crashed and restarted
                if (_taskbarCreatedMsg != 0 && msg == _taskbarCreatedMsg)
                {
                    AddTrayIcon();
                    return IntPtr.Zero;
                }
                if (msg == WM_TRAYICON)
                {
                    int ev = unchecked((int)(lParam.ToInt64() & 0xFFFF));
                    if (ev == WM_LBUTTONUP || ev == WM_LBUTTONDBLCLK || ev == NIN_SELECT || ev == NIN_KEYSELECT)
                    {
                        _onShowWindow();
                    }
                    else if (ev == WM_RBUTTONUP || ev == WM_CONTEXTMENU)
                    {
                        ShowContextMenu();
                    }
                    return IntPtr.Zero;
                }
            }
            catch
            {
                // Never allow managed exceptions to unwind across native Win32 WndProc boundaries.
            }
            return DefWindowProcW(hWnd, msg, wParam, lParam);
        }

        /// <summary>
        /// Displays the native Win32 context popup menu matching the macOS NSStatusItem menu items.
        /// </summary>
        private void ShowContextMenu()
        {
            IntPtr menu = CreatePopupMenu();
            if (menu == IntPtr.Zero) return;
            uint cmd = 0;
            try
            {
                AppendMenuW(menu, MF_STRING, (UIntPtr)ID_SHOW, "Show Dashboard");
                AppendMenuW(menu, MF_SEPARATOR, UIntPtr.Zero, null);
                AppendMenuW(menu, MF_STRING, (UIntPtr)ID_PASTE, "Paste Remote Item");
                AppendMenuW(menu, MF_STRING, (UIntPtr)ID_DISPLAY, "Toggle Extended Screen");
                AppendMenuW(menu, MF_STRING, (UIntPtr)ID_CACHE, "Open Clipboard Cache");
                AppendMenuW(menu, MF_SEPARATOR, UIntPtr.Zero, null);
                AppendMenuW(menu, MF_STRING, (UIntPtr)ID_QUIT, "Quit Integrator");

                GetCursorPos(out POINT pt);
                // Required by Win32 to ensure popup menu dismisses properly when clicking outside
                SetForegroundWindow(_hwnd);
                cmd = TrackPopupMenuEx(menu, TPM_RIGHTBUTTON | TPM_NONOTIFY | TPM_RETURNCMD, pt.X, pt.Y, _hwnd, IntPtr.Zero);
                PostMessageW(_hwnd, 0, IntPtr.Zero, IntPtr.Zero);
            }
            finally
            {
                DestroyMenu(menu);
            }

            // Execute context menu commands without blocking the message loop
            switch ((int)cmd)
            {
                case ID_SHOW:
                    _onShowWindow();
                    break;
                case ID_PASTE:
                    System.Threading.ThreadPool.QueueUserWorkItem(_ => { try { CoreBridge.TrayAction("paste_remote"); } catch { } });
                    break;
                case ID_DISPLAY:
                    System.Threading.ThreadPool.QueueUserWorkItem(_ => { try { CoreBridge.TrayAction("toggle_display"); } catch { } });
                    break;
                case ID_CACHE:
                    System.Threading.ThreadPool.QueueUserWorkItem(_ => { try { CoreBridge.TrayAction("open_cache"); } catch { } });
                    break;
                case ID_QUIT:
                    _onQuit();
                    break;
            }
        }

        /// <summary>
        /// Explicit cleanup of unmanaged Win32 window, icon, and shell notification resources.
        /// </summary>
        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            if (_added && _hwnd != IntPtr.Zero)
            {
                var nid = new NOTIFYICONDATAW
                {
                    cbSize = (uint)Marshal.SizeOf<NOTIFYICONDATAW>(),
                    hWnd = _hwnd,
                    uID = 1,
                    szTip = string.Empty,
                    szInfo = string.Empty,
                    szInfoTitle = string.Empty
                };
                Shell_NotifyIconW(NIM_DELETE, ref nid);
                _added = false;
            }
            if (_ownsIcon && _hIcon != IntPtr.Zero)
            {
                DestroyIcon(_hIcon);
            }
            _hIcon = IntPtr.Zero;
            _ownsIcon = false;
            if (_hwnd != IntPtr.Zero)
            {
                DestroyWindow(_hwnd);
                _hwnd = IntPtr.Zero;
            }
            if (!string.IsNullOrEmpty(_className))
            {
                UnregisterClassW(_className, _hInst);
                _className = null;
            }
            _wndProcDelegate = null;
        }
    }
}
