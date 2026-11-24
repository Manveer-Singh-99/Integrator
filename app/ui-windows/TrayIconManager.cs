// ==============================================================================================
// Integrator Windows Native System Tray Manager (`ui-windows/TrayIconManager.cs`)
//
// 1. Module Purpose & System Scope:
//    - Manages the native Win32 notification icon in the Windows taskbar system tray (Notification Area)
//      via `Shell_NotifyIconW` and `NOTIFYICON_VERSION_4`.
//    - Implemented with zero dependencies on `System.Windows.Forms` or legacy WebView components to maintain
//      a minimal memory footprint and deterministic unmanaged resource management.
//    - Replicates the exact functional menu layout of the macOS `NSStatusItem` menu for cross-platform parity:
//      Show Dashboard, Paste Remote Item, Toggle Extended Screen, Open Clipboard Cache, and Quit Integrator.
//
// 2. Architectural Linkages & Dependencies:
//    - Upstream Caller: `IntegratorUI.App` instantiates `TrayIconManager` during `OnLaunched` on the STA
//      UI thread and disposes it via `DisposeTrayIcon()` on application exit.
//    - Downstream Callees:
//        * Win32 `shell32.dll`: `Shell_NotifyIconW` (`NIM_ADD`, `NIM_DELETE`, `NIM_SETVERSION`).
//        * Win32 `user32.dll`: Window class registration (`RegisterClassExW`, `UnregisterClassW`), hidden top-level
//          message window (`CreateWindowExW`, `DestroyWindow`, `DefWindowProcW`), icon loading (`LoadImageW`,
//          `DestroyIcon`), popup menu generation (`CreatePopupMenu`, `AppendMenuW`, `TrackPopupMenuEx`,
//          `DestroyMenu`), focus/message control (`SetForegroundWindow`, `PostMessageW`), and metrics/cursor
//          queries (`GetSystemMetrics`, `GetCursorPos`, `RegisterWindowMessageW`).
//        * Win32 `kernel32.dll`: `GetModuleHandleW`.
//        * `CoreBridge`: Asynchronous invocation of `CoreBridge.TrayAction` (`paste_remote`, `toggle_display`,
//          `open_cache`) dispatched onto the CLR `ThreadPool`.
//    - Cross-Platform / Cross-Device Flow:
//        * Selecting "Paste Remote Item" triggers `CoreBridge.TrayAction("paste_remote")`, which pulls the
//          latest encrypted clipboard item from the paired macOS workstation over TCP :58283 (`TransportSessionV2`).
//        * Selecting "Toggle Extended Screen" triggers `CoreBridge.TrayAction("toggle_display")`, coordinating
//          IddCx virtual display / Moonlight streaming with the paired Mac over TCP :58281.
//
// 3. Threading & Concurrency Model:
//    - Dedicated STA Message Window: Creates a zero-size, top-level unmanaged window on the WinUI 3 STA UI thread
//      to receive `WM_TRAYICON` notification callbacks and `"TaskbarCreated"` broadcasts from the Windows shell.
//      (Note: `HWND_MESSAGE` message-only windows are intentionally rejected because `TrackPopupMenuEx` and
//      shell broadcast messages like `"TaskbarCreated"` require a top-level window to function reliably.)
//    - Non-Blocking Menu Handlers: Context menu actions (`paste_remote`, `toggle_display`, `open_cache`) are
//      dispatched onto background `ThreadPool` worker threads via `ThreadPool.QueueUserWorkItem` to prevent
//      blocking the Win32 message loop during network I/O.
//
// 4. Security & Safety Invariants:
//    - Shell Crash Resilience: Registers for the `"TaskbarCreated"` broadcast message via `RegisterWindowMessageW`.
//      If `explorer.exe` crashes or restarts, the tray icon is automatically re-created without user intervention.
//    - Exception Boundary Protection: The unmanaged `WndProc` trampoline wraps all managed execution in a
//      catch-all block, preventing CLR exceptions from unwinding across unmanaged Win32 callback boundaries.
//    - Re-Entrancy & Disposal Guards: `_disposed` and `_isShowingMenu` prevent nested modal `TrackPopupMenuEx`
//      loops or late `WndProc` actions after teardown begins.
//    - DLL Search-Order Hardening: All Win32 P/Invoke declarations specify
//      `[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]`.
//    - Resource Hygiene: Complete `IDisposable` implementation explicitly removes the tray icon (`NIM_DELETE`),
//      destroys owned `_hIcon` handles (`DestroyIcon`), destroys `_hwnd` (`DestroyWindow`), and unregisters
//      the window class (`UnregisterClassW`) only when registration succeeded.
// ==============================================================================================

using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;

namespace IntegratorUI
{
    /// <summary>
    /// Native Win32 <c>Shell_NotifyIconW</c> tray icon manager (zero WinForms / WebView dependencies).
    /// Mirrors the macOS <c>NSStatusItem</c> menu identically and manages all unmanaged Win32 handles safely.
    /// </summary>
    internal sealed class TrayIconManager : IDisposable
    {
        /// <summary>Win32 <c>WM_NULL</c> (<c>0x0000</c>) no-op message posted after <c>TrackPopupMenuEx</c> to force menu dismissal cleanup.</summary>
        private const uint WM_NULL = 0x0000u;

        /// <summary>Win32 <c>WM_USER</c> (<c>0x0400</c>) base offset for application-private window messages (<c>winuser.h</c>).</summary>
        private const int WM_USER = 0x0400;

        /// <summary>Custom callback window message (<c>WM_USER + 42 = 0x042A</c>) delivered by <c>Shell_NotifyIconW</c> on tray mouse/keyboard events.</summary>
        private const int WM_TRAYICON = WM_USER + 42;

        /// <summary>Win32 <c>NIN_SELECT</c> (<c>WM_USER + 0 = 0x0400</c>) notification code sent under <c>NOTIFYICON_VERSION_4</c> on mouse activation.</summary>
        private const int NIN_SELECT = 0x0400;

        /// <summary>Win32 <c>NIN_KEYSELECT</c> (<c>WM_USER + 1 = 0x0401</c>) notification code sent under <c>NOTIFYICON_VERSION_4</c> on Space/Enter key activation.</summary>
        private const int NIN_KEYSELECT = 0x0401;

        /// <summary>Win32 <c>WM_LBUTTONUP</c> (<c>0x0202</c>) left mouse button release notification code.</summary>
        private const int WM_LBUTTONUP = 0x0202;

        /// <summary>Win32 <c>WM_LBUTTONDBLCLK</c> (<c>0x0203</c>) left mouse button double-click notification code.</summary>
        private const int WM_LBUTTONDBLCLK = 0x0203;

        /// <summary>Win32 <c>WM_RBUTTONUP</c> (<c>0x0205</c>) right mouse button release notification code.</summary>
        private const int WM_RBUTTONUP = 0x0205;

        /// <summary>Win32 <c>WM_CONTEXTMENU</c> (<c>0x007B</c>) context menu request notification code (right-click or Shift+F10 / Apps key).</summary>
        private const int WM_CONTEXTMENU = 0x007B;

        /// <summary>Win32 <c>GetSystemMetrics</c> index <c>SM_CXSMICON</c> (49): recommended width of a small icon in physical pixels.</summary>
        private const int SM_CXSMICON = 49;

        /// <summary>Win32 <c>GetSystemMetrics</c> index <c>SM_CYSMICON</c> (50): recommended height of a small icon in physical pixels.</summary>
        private const int SM_CYSMICON = 50;

        /// <summary><c>NOTIFYICONDATAW.uFlags</c> bit (<c>0x00000001</c>): <c>uCallbackMessage</c> field is valid.</summary>
        private const uint NIF_MESSAGE = 0x00000001u;

        /// <summary><c>NOTIFYICONDATAW.uFlags</c> bit (<c>0x00000002</c>): <c>hIcon</c> field is valid.</summary>
        private const uint NIF_ICON = 0x00000002u;

        /// <summary><c>NOTIFYICONDATAW.uFlags</c> bit (<c>0x00000004</c>): <c>szTip</c> tooltip string field is valid.</summary>
        private const uint NIF_TIP = 0x00000004u;

        /// <summary><c>NOTIFYICONDATAW.uFlags</c> bit (<c>0x00000080</c>): required under <c>NOTIFYICON_VERSION_4</c> so standard tooltip is displayed.</summary>
        private const uint NIF_SHOWTIP = 0x00000080u;

        /// <summary><c>Shell_NotifyIconW</c> command (<c>0x00000000</c>): adds an icon to the taskbar status area.</summary>
        private const uint NIM_ADD = 0x00000000u;

        /// <summary><c>Shell_NotifyIconW</c> command (<c>0x00000002</c>): deletes an icon from the taskbar status area.</summary>
        private const uint NIM_DELETE = 0x00000002u;

        /// <summary><c>Shell_NotifyIconW</c> command (<c>0x00000004</c>): instructs the shell to behave according to <c>uTimeoutOrVersion</c>.</summary>
        private const uint NIM_SETVERSION = 0x00000004u;

        /// <summary>Vista+ notification icon behavior version (4), delivering <c>NIN_SELECT</c>/<c>WM_CONTEXTMENU</c> semantics.</summary>
        private const uint NOTIFYICON_VERSION_4 = 4u;

        /// <summary><c>LoadImageW</c> image type (<c>1</c>): loads an icon (<c>HICON</c>) resource.</summary>
        private const uint IMAGE_ICON = 1u;

        /// <summary><c>LoadImageW</c> flag (<c>0x00000010</c>): loads the image from the filesystem path in <c>lpszName</c>.</summary>
        private const uint LR_LOADFROMFILE = 0x00000010u;

        /// <summary><c>LoadImageW</c> flag (<c>0x00000040</c>): uses system metric default icon dimensions if <c>cxDesired</c>/<c>cyDesired</c> are zero.</summary>
        private const uint LR_DEFAULTSIZE = 0x00000040u;

        /// <summary><c>LoadImageW</c> flag (<c>0x00008000</c>): shares the system icon handle across callers; caller must not call <c>DestroyIcon</c>.</summary>
        private const uint LR_SHARED = 0x00008000u;

        /// <summary><c>AppendMenuW</c> flag (<c>0x00000000</c>): menu item content is a null-terminated UTF-16 text string.</summary>
        private const uint MF_STRING = 0x00000000u;

        /// <summary><c>AppendMenuW</c> flag (<c>0x00000800</c>): draws a horizontal dividing line in the popup menu.</summary>
        private const uint MF_SEPARATOR = 0x00000800u;

        /// <summary><c>TrackPopupMenuEx</c> flag (<c>0x0002</c>): allows user to select menu items with either left or right mouse button.</summary>
        private const uint TPM_RIGHTBUTTON = 0x0002u;

        /// <summary><c>TrackPopupMenuEx</c> flag (<c>0x0080</c>): suppresses <c>WM_COMMAND</c> notifications and returns selection directly via <c>TPM_RETURNCMD</c>.</summary>
        private const uint TPM_NONOTIFY = 0x0080u;

        /// <summary><c>TrackPopupMenuEx</c> flag (<c>0x0100</c>): returns the selected menu item identifier as the function return value.</summary>
        private const uint TPM_RETURNCMD = 0x0100u;

        /// <summary>Context menu command ID (1001): "Show Dashboard".</summary>
        private const int ID_SHOW = 1001;

        /// <summary>Context menu command ID (1002): "Paste Remote Item".</summary>
        private const int ID_PASTE = 1002;

        /// <summary>Context menu command ID (1003): "Toggle Extended Screen".</summary>
        private const int ID_DISPLAY = 1003;

        /// <summary>Context menu command ID (1004): "Open Clipboard Cache".</summary>
        private const int ID_CACHE = 1004;

        /// <summary>Context menu command ID (1005): "Quit Integrator".</summary>
        private const int ID_QUIT = 1005;

        /// <summary>Fallback small tray icon width and height in pixels (16 px) when <c>GetSystemMetrics</c> returns &lt;= 0.</summary>
        private const int DEFAULT_ICON_DIMENSION = 16;

        /// <summary>
        /// Win32 <c>MAKEINTRESOURCEW(32512)</c> integer resource identifier for the standard <c>IDI_APPLICATION</c> OEM icon.
        /// Passed as <c>(IntPtr)32512</c> to <c>LoadImageW</c> so Win32 <c>IS_INTRESOURCE</c> (<c>&lt; 0x10000</c>) succeeds.
        /// </summary>
        private const int IDI_APPLICATION_RES_ID = 32512;

        /// <summary>Application-defined notification icon identifier (1) scoped to <see cref="_hwnd"/> in <c>Shell_NotifyIconW</c>.</summary>
        private const uint TRAY_ICON_UID = 1u;

        /// <summary>Callback invoked when the user clicks the tray icon or selects "Show Dashboard".</summary>
        private readonly Action _onShowWindow;

        /// <summary>Callback invoked when the user selects "Quit Integrator" from the tray context menu.</summary>
        private readonly Action _onQuit;

        /// <summary>Win32 module instance handle (<c>HINSTANCE</c>) of the current executable.</summary>
        private IntPtr _hInst;

        /// <summary>Win32 window handle (<c>HWND</c>) of the hidden top-level helper message window.</summary>
        private IntPtr _hwnd;

        /// <summary>Win32 icon handle (<c>HICON</c>) displayed in the taskbar notification area.</summary>
        private IntPtr _hIcon;

        /// <summary>True if <see cref="_hIcon"/> was loaded from disk without <see cref="LR_SHARED"/> and must be freed via <see cref="DestroyIcon"/>.</summary>
        private bool _ownsIcon;

        /// <summary>Unique Win32 window class name registered for <see cref="_hwnd"/>.</summary>
        private string? _className;

        /// <summary>True if <see cref="RegisterClassExW"/> succeeded and <see cref="UnregisterClassW"/> must be called on disposal.</summary>
        private bool _classRegistered;

        /// <summary>Dynamically registered window message ID for the shell's <c>"TaskbarCreated"</c> broadcast (0 if registration failed).</summary>
        private uint _taskbarCreatedMsg;

        /// <summary>Pinned managed delegate reference for <see cref="WndProc"/>, preventing GC collection while registered with Win32.</summary>
        private WndProcDelegate? _wndProcDelegate;

        /// <summary>True if the tray icon is currently registered with the Windows shell via <see cref="NIM_ADD"/>.</summary>
        private bool _added;

        /// <summary>Re-entrancy guard preventing nested modal <see cref="TrackPopupMenuEx"/> context menu invocations.</summary>
        private bool _isShowingMenu;

        /// <summary>Idempotent disposal flag ensuring unmanaged resources are released at most once.</summary>
        private bool _disposed;

        /// <summary>
        /// Native window procedure delegate matching the Win32 <c>WNDPROC</c> calling convention and signature.
        /// </summary>
        /// <param name="hWnd">Handle to the window receiving the message.</param>
        /// <param name="msg">Win32 window message identifier.</param>
        /// <param name="wParam">Additional message-specific word parameter.</param>
        /// <param name="lParam">Additional message-specific long parameter.</param>
        /// <returns>Result of message processing depending on the message sent.</returns>
        private delegate IntPtr WndProcDelegate(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

        /// <summary>
        /// Win32 <c>WNDCLASSEXW</c> structure (<c>winuser.h</c>) used to register the hidden tray message window class.
        /// </summary>
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WNDCLASSEXW
        {
            /// <summary>Size of this structure in bytes (<c>Marshal.SizeOf&lt;WNDCLASSEXW&gt;()</c>).</summary>
            public uint cbSize;
            /// <summary>Class style bitmask (<c>CS_*</c>, 0 for hidden message window).</summary>
            public uint style;
            /// <summary>Unmanaged function pointer to the window procedure (<see cref="WndProcDelegate"/>).</summary>
            public IntPtr lpfnWndProc;
            /// <summary>Number of extra bytes to allocate following the window-class structure (0).</summary>
            public int cbClsExtra;
            /// <summary>Number of extra bytes to allocate following the window instance (0).</summary>
            public int cbWndExtra;
            /// <summary>Handle to the module instance containing the window procedure.</summary>
            public IntPtr hInstance;
            /// <summary>Handle to the class icon (<see cref="IntPtr.Zero"/>).</summary>
            public IntPtr hIcon;
            /// <summary>Handle to the class cursor (<see cref="IntPtr.Zero"/>).</summary>
            public IntPtr hCursor;
            /// <summary>Handle to the class background brush (<see cref="IntPtr.Zero"/>).</summary>
            public IntPtr hbrBackground;
            /// <summary>Resource name of the class menu (<c>null</c>).</summary>
            public string? lpszMenuName;
            /// <summary>Null-terminated UTF-16 window class name.</summary>
            public string lpszClassName;
            /// <summary>Handle to a small icon associated with the window class (<see cref="IntPtr.Zero"/>).</summary>
            public IntPtr hIconSm;
        }

        /// <summary>
        /// Win32 <c>NOTIFYICONDATAW</c> structure (<c>shellapi.h</c>) for communicating with <see cref="Shell_NotifyIconW"/>.
        /// </summary>
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct NOTIFYICONDATAW
        {
            /// <summary>Size of this structure in bytes (<c>Marshal.SizeOf&lt;NOTIFYICONDATAW&gt;()</c>).</summary>
            public uint cbSize;
            /// <summary>Handle to the window that receives notification messages associated with the icon.</summary>
            public IntPtr hWnd;
            /// <summary>Application-defined identifier of the taskbar icon (<see cref="TRAY_ICON_UID"/>).</summary>
            public uint uID;
            /// <summary>Bitmask of <c>NIF_*</c> flags indicating which structure members contain valid data.</summary>
            public uint uFlags;
            /// <summary>Application-defined message identifier (<see cref="WM_TRAYICON"/>) sent to <see cref="hWnd"/>.</summary>
            public uint uCallbackMessage;
            /// <summary>Handle to the icon (<c>HICON</c>) to be added, modified, or deleted.</summary>
            public IntPtr hIcon;
            /// <summary>Null-terminated UTF-16 standard tooltip text (maximum 128 characters including null terminator).</summary>
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
            public string szTip;
            /// <summary>State of the icon (<c>NIS_HIDDEN</c>, <c>NIS_SHAREDICON</c>).</summary>
            public uint dwState;
            /// <summary>Bitmask specifying which bits of <see cref="dwState"/> are retrieved or modified.</summary>
            public uint dwStateMask;
            /// <summary>Null-terminated UTF-16 balloon notification body text (maximum 256 characters).</summary>
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string szInfo;
            /// <summary>Union holding balloon timeout in milliseconds or version number (<see cref="NOTIFYICON_VERSION_4"/>).</summary>
            public uint uTimeoutOrVersion;
            /// <summary>Null-terminated UTF-16 balloon notification title text (maximum 64 characters).</summary>
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
            public string szInfoTitle;
            /// <summary>Flags configuring balloon notification icon and behavior (<c>NIIF_*</c>).</summary>
            public uint dwInfoFlags;
            /// <summary>Optional registered GUID identifying the icon.</summary>
            public Guid guidItem;
            /// <summary>Handle to a custom balloon notification icon (<c>HICON</c>).</summary>
            public IntPtr hBalloonIcon;
        }

        /// <summary>
        /// Win32 <c>POINT</c> structure (<c>windef.h</c>) capturing screen coordinates in physical pixels.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        private struct POINT
        {
            /// <summary>Horizontal screen coordinate in physical pixels.</summary>
            public int X;
            /// <summary>Vertical screen coordinate in physical pixels.</summary>
            public int Y;
        }

        /// <summary>Registers a window class for subsequent use in calls to <see cref="CreateWindowExW"/>.</summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern ushort RegisterClassExW(ref WNDCLASSEXW lpwcx);

        /// <summary>Unregisters a window class, freeing the memory required for the class.</summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool UnregisterClassW(string lpClassName, IntPtr hInstance);

        /// <summary>Defines a new window message that is guaranteed to be unique throughout the system.</summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint RegisterWindowMessageW(string lpString);

        /// <summary>Retrieves the specified system metric or system configuration setting in physical pixels.</summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("user32.dll")]
        private static extern int GetSystemMetrics(int nIndex);

        /// <summary>Creates an overlapped, pop-up, or child window with an extended window style.</summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateWindowExW(
            uint dwExStyle, string lpClassName, string lpWindowName, uint dwStyle,
            int x, int y, int nWidth, int nHeight, IntPtr hWndParent, IntPtr hMenu,
            IntPtr hInstance, IntPtr lpParam);

        /// <summary>Destroys the specified window on the creating thread.</summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool DestroyWindow(IntPtr hWnd);

        /// <summary>Calls the default window procedure to provide default processing for unhandled window messages.</summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("user32.dll")]
        private static extern IntPtr DefWindowProcW(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

        /// <summary>Retrieves a module handle for the specified module (or current executable when <c>null</c>).</summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        private static extern IntPtr GetModuleHandleW(string? lpModuleName);

        /// <summary>Loads an icon, cursor, or bitmap from a file path (<see cref="LR_LOADFROMFILE"/>).</summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr LoadImageW(
            IntPtr hInst, string lpszName, uint uType, int cxDesired, int cyDesired, uint fuLoad);

        /// <summary>Loads a predefined OEM icon, cursor, or bitmap by integer resource ID (<c>MAKEINTRESOURCEW</c>).</summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("user32.dll", EntryPoint = "LoadImageW", SetLastError = true)]
        private static extern IntPtr LoadImageByIntResourceW(
            IntPtr hInst, IntPtr lpszName, uint uType, int cxDesired, int cyDesired, uint fuLoad);

        /// <summary>Destroys an icon and frees any memory the icon occupied (must not be called on <see cref="LR_SHARED"/> icons).</summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("user32.dll")]
        private static extern bool DestroyIcon(IntPtr hIcon);

        /// <summary>Sends a message to the taskbar's status area to add, modify, or delete a notification icon.</summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
        private static extern bool Shell_NotifyIconW(uint dwMessage, ref NOTIFYICONDATAW lpData);

        /// <summary>Creates a drop-down menu, submenu, or shortcut popup menu.</summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("user32.dll")]
        private static extern IntPtr CreatePopupMenu();

        /// <summary>Appends a new item to the end of the specified menu bar, drop-down menu, submenu, or shortcut menu.</summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern bool AppendMenuW(IntPtr hMenu, uint uFlags, UIntPtr uIDNewItem, string? lpNewItem);

        /// <summary>Destroys the specified menu and frees any memory that the menu occupied.</summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("user32.dll")]
        private static extern bool DestroyMenu(IntPtr hMenu);

        /// <summary>Displays a shortcut menu at the specified location and tracks the selection of items on the shortcut menu.</summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("user32.dll")]
        private static extern uint TrackPopupMenuEx(
            IntPtr hMenu, uint uFlags, int x, int y, IntPtr hwnd, IntPtr lptpm);

        /// <summary>Retrieves the position of the mouse cursor, in physical screen coordinates.</summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("user32.dll")]
        private static extern bool GetCursorPos(out POINT lpPoint);

        /// <summary>Brings the thread that created the specified window into the foreground and activates the window.</summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("user32.dll")]
        private static extern bool SetForegroundWindow(IntPtr hWnd);

        /// <summary>Places (posts) a message in the message queue associated with the thread that created the specified window.</summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("user32.dll")]
        private static extern bool PostMessageW(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);

        /// <summary>
        /// Initializes the system tray notification icon and its underlying Win32 message window on the calling STA thread.
        /// </summary>
        /// <param name="onShowWindow">Non-null callback action invoked to restore and activate the dashboard window.</param>
        /// <param name="onQuit">Non-null callback action invoked when the user selects Quit from the context menu.</param>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="onShowWindow"/> or <paramref name="onQuit"/> is null.</exception>
        public TrayIconManager(Action onShowWindow, Action onQuit)
        {
            ArgumentNullException.ThrowIfNull(onShowWindow);
            ArgumentNullException.ThrowIfNull(onQuit);
            _onShowWindow = onShowWindow;
            _onQuit = onQuit;
            InitTray();
        }

        /// <summary>
        /// Registers the unique Win32 window class, creates the zero-size top-level message window,
        /// resolves the application or fallback OEM icon at current DPI small-icon metrics, and adds the tray item.
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
            _classRegistered = RegisterClassExW(ref wc) != 0;
            if (!_classRegistered)
            {
                return;
            }

            // Top-level zero-size helper window (supports TrackPopupMenuEx + NOTIFYICON_VERSION_4 + TaskbarCreated broadcasts cleanly;
            // HWND_MESSAGE is avoided because message-only windows do not receive broadcast messages such as TaskbarCreated).
            _hwnd = CreateWindowExW(0, _className, "Integrator Tray", 0, 0, 0, 0, 0, IntPtr.Zero, IntPtr.Zero, _hInst, IntPtr.Zero);
            if (_hwnd == IntPtr.Zero)
            {
                return;
            }

            int cx = GetSystemMetrics(SM_CXSMICON);
            int cy = GetSystemMetrics(SM_CYSMICON);
            if (cx <= 0) cx = DEFAULT_ICON_DIMENSION;
            if (cy <= 0) cy = DEFAULT_ICON_DIMENSION;

            string iconPath = Path.Combine(AppContext.BaseDirectory, "icon.ico");
            if (File.Exists(iconPath))
            {
                _hIcon = LoadImageW(IntPtr.Zero, iconPath, IMAGE_ICON, cx, cy, LR_LOADFROMFILE);
                _ownsIcon = _hIcon != IntPtr.Zero;
            }
            if (_hIcon == IntPtr.Zero)
            {
                // Standard application icon fallback: IDI_APPLICATION (32512) requires MAKEINTRESOURCEW ((IntPtr)32512),
                // hInst = IntPtr.Zero, and LR_SHARED so Windows returns the shared OEM icon handle.
                _hIcon = LoadImageByIntResourceW(
                    IntPtr.Zero,
                    (IntPtr)IDI_APPLICATION_RES_ID,
                    IMAGE_ICON,
                    cx,
                    cy,
                    LR_DEFAULTSIZE | LR_SHARED);
                _ownsIcon = false;
            }

            AddTrayIcon();
        }

        /// <summary>
        /// Calls <see cref="Shell_NotifyIconW"/> with <see cref="NIM_ADD"/> and <see cref="NIM_SETVERSION"/>
        /// to publish the icon and enable <see cref="NOTIFYICON_VERSION_4"/> event delivery.
        /// </summary>
        private void AddTrayIcon()
        {
            if (_disposed || _hwnd == IntPtr.Zero) return;

            var nid = new NOTIFYICONDATAW
            {
                cbSize = (uint)Marshal.SizeOf<NOTIFYICONDATAW>(),
                hWnd = _hwnd,
                uID = TRAY_ICON_UID,
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
        /// Unmanaged window procedure callback dispatching tray mouse/keyboard interactions and shell restart broadcasts.
        /// Wrapped in a catch-all exception handler so managed exceptions never cross the native Win32 ABI boundary.
        /// </summary>
        /// <param name="hWnd">Target window handle.</param>
        /// <param name="msg">Win32 message identifier.</param>
        /// <param name="wParam">Message wParam payload.</param>
        /// <param name="lParam">Message lParam payload (low 16 bits contain notification event code under <see cref="NOTIFYICON_VERSION_4"/>).</param>
        /// <returns><see cref="IntPtr.Zero"/> when handled; otherwise result of <see cref="DefWindowProcW"/>.</returns>
        private IntPtr WndProc(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam)
        {
            try
            {
                if (_disposed)
                {
                    return DefWindowProcW(hWnd, msg, wParam, lParam);
                }

                // Automatically re-register tray icon if explorer.exe crashed and restarted
                if (_taskbarCreatedMsg != 0 && msg == _taskbarCreatedMsg)
                {
                    AddTrayIcon();
                    return IntPtr.Zero;
                }

                if (msg == WM_TRAYICON)
                {
                    // Under NOTIFYICON_VERSION_4, LOWORD(lParam) carries the mouse/keyboard notification message.
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
        /// Constructs, displays, and dispatches the native Win32 context popup menu matching the macOS <c>NSStatusItem</c> menu items.
        /// Guarded against re-entrancy when both <see cref="WM_RBUTTONUP"/> and <see cref="WM_CONTEXTMENU"/> fire sequentially.
        /// </summary>
        private void ShowContextMenu()
        {
            if (_disposed || _isShowingMenu || _hwnd == IntPtr.Zero) return;

            IntPtr menu = CreatePopupMenu();
            if (menu == IntPtr.Zero) return;

            _isShowingMenu = true;
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
                // Required by Win32 Shell guidelines to ensure popup menu dismisses properly when clicking outside
                SetForegroundWindow(_hwnd);
                cmd = TrackPopupMenuEx(menu, TPM_RIGHTBUTTON | TPM_NONOTIFY | TPM_RETURNCMD, pt.X, pt.Y, _hwnd, IntPtr.Zero);
                // Post benign WM_NULL per Microsoft KB135788 to force a task switch after TrackPopupMenuEx exits
                PostMessageW(_hwnd, WM_NULL, IntPtr.Zero, IntPtr.Zero);
            }
            finally
            {
                DestroyMenu(menu);
                _isShowingMenu = false;
            }

            if (_disposed) return;

            // Execute context menu commands without blocking the Win32 message loop
            switch ((int)cmd)
            {
                case ID_SHOW:
                    _onShowWindow();
                    break;
                case ID_PASTE:
                    ThreadPool.QueueUserWorkItem(_ => { try { CoreBridge.TrayAction("paste_remote"); } catch { } });
                    break;
                case ID_DISPLAY:
                    ThreadPool.QueueUserWorkItem(_ => { try { CoreBridge.TrayAction("toggle_display"); } catch { } });
                    break;
                case ID_CACHE:
                    ThreadPool.QueueUserWorkItem(_ => { try { CoreBridge.TrayAction("open_cache"); } catch { } });
                    break;
                case ID_QUIT:
                    _onQuit();
                    break;
            }
        }

        /// <summary>
        /// Explicit, idempotent cleanup of the shell notification icon, unmanaged <c>HICON</c>,
        /// hidden Win32 helper window (<c>HWND</c>), and registered window class.
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
                    uID = TRAY_ICON_UID,
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

            if (_classRegistered && !string.IsNullOrEmpty(_className))
            {
                UnregisterClassW(_className, _hInst);
            }
            _classRegistered = false;
            _className = null;
            _wndProcDelegate = null;
        }
    }
}
