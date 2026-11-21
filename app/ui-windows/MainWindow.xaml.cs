// ==============================================================================================
// Integrator Windows Native Client & WinUI 3 Dashboard Shell (`ui-windows/MainWindow.xaml.cs`)
//
// 1. Module Purpose & System Scope:
//    - Serves as the primary user-facing desktop interface for Integrator on Windows 11 and Windows 10.
//    - Hosts the thirteen subsystem cards in an adaptive, responsive two-column grid matching the macOS
//      SwiftUI client layout and design hierarchy.
//    - Provides zero-latency hardware telemetry, 2D interactive desk monitor arrangement, SPAKE2 pairing
//      and trust verification, discrete GPU selection, SMB storage mounting, live logs, and audio/video streaming.
//
// 2. Architectural Linkages & Native Core Bridge:
//    - Upstream Caller: `IntegratorUI.App` instantiates and activates `MainWindow` during `OnLaunched`.
//    - Downstream Core: Invokes RPC endpoints on `integrator_core.dll` via `CoreBridge.Invoke<T>`
//      wrapped in background `Task.Run` operations to prevent blocking the Windows STA UI thread.
//    - Downstream APIs & Windows App SDK:
//        * Windows App SDK: `AppWindow`, `AppWindowTitleBar`, `DisplayArea`, `OverlappedPresenter`.
//        * Composition & Backdrops: `MicaController` on Windows 11; automatic runtime fallback to
//          `DesktopAcrylicController` / `DesktopAcrylicBackdrop` on Windows 10 where Mica is unsupported.
//        * Win32 User32: `GetDpiForWindow` for high-DPI monitor coordinate and dimension scaling.
//
// 3. Card Subsystems & Visual Architecture:
//    - Card 1: Extended Screen & GPU Acceleration (NVENC / DirectX / Moonlight vs VideoToolbox routing).
//    - Card 2: Universal Input KVM & Desk Layout (2D desk monitor schematic, edge hop delays, modifier translation).
//    - Card 3: Cross-Screen Drag & Drop (Zero-RAM file streaming, ghost thumbnail badge, QoS clamp, drop directory).
//    - Card 4: Universal Clipboard (ChaCha20 encrypted sync, SHA-256 verification, atomic staging cache).
//    - Card 5: Peer Discovery & v1.0 Trust (mDNS / UDP beacon discovery, SPAKE2 6-digit PIN pairing, manual IP targets).
//    - Card 6: Route Telemetry & Link Speed (Active network interface discovery, RTT ping, live speed test).
//    - Card 7: Auto-Mounted Shared Storage (Automated SMB volume negotiation, preferred share mount overrides).
//    - Card 8: True Tone & Chromatic Sync (Ambient light sensor readings, manual CCT/gamma calibration).
//    - Card 9: Touch Bar Hardware HUD (Touch Bar telemetry strip status and toggle invocation).
//    - Card 10: Dynamic Audio Routing (ChaCha20-Poly1305 encrypted spatial UDP sink, test chime invocation).
//    - Card 10B: Mac -> PC Shared Camera (Windows Virtual Camera driver receiving 720p30 video over TCP :58287).
//    - Card 11: System & Autostart (Windows Task Scheduler logon autostart, dynamic glass intensity slider).
//    - Card 12: Live Telemetry & Security Logs (Monospaced tailing log console with ANSI/log-level visual highlighting).
//
// 4. Mica & Windows 10 Desktop Acrylic Fallback + Dynamic Glass Intensity:
//    - Detects backdrop support dynamically at startup: if `MicaController.IsSupported()` is false, falls back
//      seamlessly to `DesktopAcrylicBackdrop` on Windows 10 build 19041+.
//    - The dynamic glass intensity slider modulates card background alpha and border stroke opacities
//      in real-time across all 13 card borders without requiring a window restart.
//
// 5. Threading & Concurrency Model:
//    - All UI elements execute on the Windows Single-Threaded Apartment (STA) UI thread.
//    - Asynchronous RPC dispatches: All `CoreBridge.Invoke<T>` calls are executed inside `Task.Run(() => ...)`
//      workers and resumed on the UI thread via `await` or `DispatcherQueue.TryEnqueue`.
//    - Polling: Repeating 2.0-second `DispatcherTimer` queries `get_bridge_status` on schedule. Polling is
//      automatically suspended when the window is minimized or hidden to the taskbar system tray.
//
// 6. Security & Safety Invariants:
//    - Form State Preservation: Dirty flags (`_kvmLayoutDirty`, `_encodeGpuDirty`, `_decodeGpuDirty`, `_preferredShareDirty`)
//      prevent periodic status polling updates from overwriting user inputs in-flight.
//    - Input Validation: IP address inputs are strictly validated with `IPAddress.TryParse` prior to dispatch.
//    - Failure Containment: Network and RPC failures are surfaced via non-blocking toast banners.
// ==============================================================================================

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.UI;
using Microsoft.UI.Text;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;
using Windows.Graphics;
using Windows.UI;
using WinRT.Interop;

namespace IntegratorUI
{
    /// <summary>
    /// Primary application window for Integrator on Windows, hosting the thirteen subsystem cards,
    /// navigation sidebar, top status bar, ephemeral toast notifications, and backdrop rendering.
    /// </summary>
    public sealed partial class MainWindow : Window
    {
        /// <summary>Fallback primary display work area width in physical pixels when DisplayArea is unavailable.</summary>
        private const int FallbackWorkAreaWidthPx = 1920;
        /// <summary>Fallback primary display work area height in physical pixels when DisplayArea is unavailable.</summary>
        private const int FallbackWorkAreaHeightPx = 1080;
        /// <summary>Default target window width in DIPs at 100% DPI scaling.</summary>
        private const int DefaultWindowWidthDip = 1240;
        /// <summary>Default target window height in DIPs at 100% DPI scaling.</summary>
        private const int DefaultWindowHeightDip = 820;
        /// <summary>Minimum allowed dashboard window width in physical pixels.</summary>
        private const int MinWindowWidthPx = 800;
        /// <summary>Minimum allowed dashboard window height in physical pixels.</summary>
        private const int MinWindowHeightPx = 600;
        /// <summary>Desktop work-area inset margin in physical pixels reserved around the initial window.</summary>
        private const int WorkAreaMarginPx = 48;
        /// <summary>Cards grid width threshold in DIPs at which the layout switches from 1 to 2 columns.</summary>
        private const double TwoColumnBreakpointDip = 740.0;
        /// <summary>Auto-dismiss duration in seconds for ephemeral toast notifications.</summary>
        private const int ToastDismissSeconds = 4;
        /// <summary>Periodic interval in seconds for polling get_bridge_status from the native core.</summary>
        private const int StatusPollIntervalSeconds = 2;
        /// <summary>Fallback local workstation label shown in the desk schematic when hostname is unavailable.</summary>
        private const string DefaultLocalHostname = "This PC";
        /// <summary>Fallback remote peer label shown in the desk schematic when peer hostname is unavailable.</summary>
        private const string DefaultPeerHostname = "Peer Mac";
        /// <summary>Maximum visible character prefix length for truncated device identifiers.</summary>
        private const int DeviceIdPreviewLength = 14;
        /// <summary>Maximum number of local network interfaces summarized in the Route Telemetry card.</summary>
        private const int MaxDisplayedInterfaces = 3;
        /// <summary>CIE D65 neutral fallback Correlated Color Temperature in Kelvin.</summary>
        private const uint DefaultAmbientCctKelvin = 6500;
        /// <summary>Maximum input length permitted in the per-peer pairing PIN input field.</summary>
        private const int PairingPinMaxInputLength = 12;
        /// <summary>Maximum number of trailing log entries rendered in the live logs panel.</summary>
        private const int MaxRenderedLogLines = 60;

        /// <summary>Reference to the parent WinUI application instance.</summary>
        private readonly App _app;
        /// <summary>Repeating status polling timer querying the Rust core bridge status.</summary>
        private readonly DispatcherTimer _pollTimer;
        /// <summary>Timer for auto-dismissing ephemeral toast notifications.</summary>
        private readonly DispatcherTimer _toastTimer;
        /// <summary>Array of all thirteen card container borders for responsive layout and styling.</summary>
        private readonly Border[] _allCards;
        /// <summary>Array of category navigation buttons.</summary>
        private readonly Button[] _navButtons;
        /// <summary>Dictionary caching in-progress pairing PIN inputs keyed by peer IP address.</summary>
        private readonly Dictionary<string, string> _pinInputs = new();

        /// <summary>Currently selected card navigation filter category ("all", "display", "input", "network", "system").</summary>
        private string _selectedCategory = "all";
        /// <summary>Latest bridge status snapshot returned by the core backend.</summary>
        private BridgeStatusModel? _status;
        /// <summary>Live draft of KVM monitor layout configuration.</summary>
        private KvmLayoutConfigModel _kvmLayout = new();
        /// <summary>True if user has modified KVM layout controls without saving to the core.</summary>
        private bool _kvmLayoutDirty;
        /// <summary>True if user has modified the encode GPU selection dropdown.</summary>
        private bool _encodeGpuDirty;
        /// <summary>True if user has modified the decode GPU selection dropdown.</summary>
        private bool _decodeGpuDirty;
        /// <summary>True if user has modified the preferred share name input field.</summary>
        private bool _preferredShareDirty;
        /// <summary>Reentrancy guard preventing overlapping asynchronous status refresh calls.</summary>
        private bool _refreshInFlight;
        /// <summary>True while a live speed benchmark is executing.</summary>
        private bool _speedTestRunning;
        /// <summary>True if the window is currently hidden to the system tray.</summary>
        private bool _isHiddenToTray;
        /// <summary>True if application exit sequence has commenced.</summary>
        private bool _disposedForExit;
        /// <summary>Guard flag preventing UI change event handlers from triggering during programmatic status binding.</summary>
        private bool _applyingStatus;
        /// <summary>Cached column count of the responsive cards grid to prevent redundant relayouts.</summary>
        private int _currentGridColumns = -1;
        /// <summary>Cached composite key of the discovered peers list to skip redundant DOM rebuilds.</summary>
        private string? _lastPeerKey;
        /// <summary>Cached composite key of manual peer IPs to skip redundant DOM rebuilds.</summary>
        private string? _lastManualIpKey;
        /// <summary>Cached composite key of GPU adapters to skip redundant ComboBox rebuilds.</summary>
        private string? _lastGpuListKey;
        /// <summary>Cached composite key of recent logs to skip redundant TextBlock allocations.</summary>
        private string? _lastRenderedLogsKey;
        /// <summary>Cached theme mode to detect dark/light theme transitions for log text brushes.</summary>
        private ElementTheme _lastRenderedTheme = ElementTheme.Default;

        /// <summary>
        /// Resolves the platform default public shared directory label dynamically from OS environment
        /// and Windows Known Folder APIs without hardcoding a drive letter.
        /// </summary>
        private static string GetDefaultSharedFolderLabel()
        {
            string? publicDir = Environment.GetEnvironmentVariable("PUBLIC");
            if (string.IsNullOrWhiteSpace(publicDir))
            {
                publicDir = Environment.GetFolderPath(Environment.SpecialFolder.CommonDocuments);
            }
            return string.IsNullOrWhiteSpace(publicDir)
                ? "Default (Public)"
                : $"Default ({publicDir})";
        }

        /// <summary>
        /// Initializes the main dashboard window, configures high-DPI sizing and titlebar chrome,
        /// registers system backdrop (Mica or Windows 10 Acrylic fallback), and starts the status polling timer.
        /// </summary>
        /// <param name="app">Reference to the parent application instance.</param>
        /// <param name="startHidden">True to initialize the window in hidden state (minimized to system tray).</param>
        public MainWindow(App app, bool startHidden = false)
        {
            _app = app;
            _isHiddenToTray = startHidden;
            InitializeComponent();

            AudioPillText.Text = string.Format(
                CultureInfo.InvariantCulture,
                "UDP :{0}",
                AudioRoutingStatusModel.DefaultAudioPort);
            CameraSummaryText.Text = string.Format(
                CultureInfo.InvariantCulture,
                "Exposes '{0}' ({1}p{2}) via encrypted TCP :{3} when enabled on Mac and PC.",
                CameraStatusModel.DefaultCameraDeviceName,
                CameraStatusModel.DefaultCameraHeight,
                CameraStatusModel.DefaultCameraFps,
                CameraStatusModel.DefaultCameraPort);

            _allCards = new[]
            {
                CardDisplay, CardKvm, CardDragDrop, CardClipboard,
                CardDiscovery, CardSpeed, CardStorage, CardTrueTone,
                CardTouchBar, CardAudio, CardCamera, CardSystem, CardLogs
            };
            _navButtons = new[]
            {
                NavAllBtn, NavDisplayBtn, NavInputBtn, NavNetworkBtn, NavSystemBtn
            };

            ConfigureWindowChrome();
            UpdateNavStyles();
            RebuildCardsGrid(force: true);

            RootGrid.ActualThemeChanged += (_, _) =>
            {
                if (_status != null)
                {
                    RebuildLogsPanel(_status.RecentLogs);
                }
            };

            _toastTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(ToastDismissSeconds) };
            _toastTimer.Tick += (_, _) =>
            {
                _toastTimer.Stop();
                ToastBanner.Visibility = Visibility.Collapsed;
            };

            _pollTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(StatusPollIntervalSeconds) };
            _pollTimer.Tick += (_, _) => _ = RefreshStatusAsync();
            if (!startHidden)
            {
                _pollTimer.Start();
                _ = RefreshStatusAsync();
            }
        }

        /// <summary>
        /// Win32 User32 function querying the dots per inch (DPI) of the specified window.
        /// </summary>
        /// <param name="hwnd">Window handle.</param>
        /// <returns>DPI value (e.g., 96 for 100%, 144 for 150%).</returns>
        [DllImport("user32.dll")]
        private static extern uint GetDpiForWindow(IntPtr hwnd);

        /// <summary>
        /// Configures custom XAML title bar extension, high-DPI responsive window sizing,
        /// taskbar icon, Mica or Desktop Acrylic system backdrops, and close-to-tray window behaviors.
        /// </summary>
        private void ConfigureWindowChrome()
        {
            ExtendsContentIntoTitleBar = true;
            SetTitleBar(AppTitleBar);

            IntPtr hwnd = WindowNative.GetWindowHandle(this);
            uint dpi = GetDpiForWindow(hwnd);
            double scale = dpi > 0 ? dpi / 96.0 : 1.0;

            var area = DisplayArea.GetFromWindowId(AppWindow.Id, DisplayAreaFallback.Primary)?.WorkArea
                ?? new RectInt32(0, 0, FallbackWorkAreaWidthPx, FallbackWorkAreaHeightPx);
            int targetW = Math.Min((int)(DefaultWindowWidthDip * scale), Math.Max(MinWindowWidthPx, area.Width - WorkAreaMarginPx));
            int targetH = Math.Min((int)(DefaultWindowHeightDip * scale), Math.Max(MinWindowHeightPx, area.Height - WorkAreaMarginPx));
            AppWindow.Resize(new SizeInt32(targetW, targetH));
            try
            {
                string ico = System.IO.Path.Combine(AppContext.BaseDirectory, "icon.ico");
                if (System.IO.File.Exists(ico))
                {
                    AppWindow.SetIcon(ico);
                }
            }
            catch { }

            if (AppWindow.TitleBar is AppWindowTitleBar tb)
            {
                tb.ButtonBackgroundColor = Colors.Transparent;
                tb.ButtonInactiveBackgroundColor = Colors.Transparent;
            }

            // Windows 10 frosted glass fallback if Mica is unsupported
            if (!Microsoft.UI.Composition.SystemBackdrops.MicaController.IsSupported() &&
                Microsoft.UI.Composition.SystemBackdrops.DesktopAcrylicController.IsSupported())
            {
                this.SystemBackdrop = new DesktopAcrylicBackdrop();
            }

            // Hide to system tray instead of killing background KVM/clipboard/display daemons.
            AppWindow.Closing += (_, args) =>
            {
                args.Cancel = true;
                HideToTray();
            };

            AppWindow.Changed += (_, args) =>
            {
                if (args.DidVisibilityChange || args.DidPresenterChange)
                {
                    UpdatePollingState();
                }
            };
        }

        /// <summary>
        /// Evaluates window visibility and minimize states to start or stop the periodic 2-second status polling timer.
        /// Conserves CPU cycles and network polling when the window is hidden to tray or minimized.
        /// </summary>
        private void UpdatePollingState()
        {
            if (_disposedForExit) return;
            bool minimized = AppWindow.Presenter is OverlappedPresenter op &&
                             op.State == OverlappedPresenterState.Minimized;
            bool shouldPoll = !_isHiddenToTray && AppWindow.IsVisible && !minimized;
            if (shouldPoll)
            {
                if (!_pollTimer.IsEnabled)
                {
                    _pollTimer.Start();
                    _ = RefreshStatusAsync();
                }
            }
            else if (_pollTimer.IsEnabled)
            {
                _pollTimer.Stop();
            }
        }

        /// <summary>
        /// Restores the window from minimized or hidden tray state, brings it to the foreground, and resumes polling.
        /// </summary>
        public void RestoreAndActivate()
        {
            try
            {
                _isHiddenToTray = false;
                if (AppWindow.Presenter is OverlappedPresenter p)
                {
                    p.Restore();
                }
                AppWindow.Show();
                Activate();
                UpdatePollingState();
            }
            catch { }
        }

        /// <summary>
        /// Hides the window to the taskbar system tray and pauses periodic status polling.
        /// </summary>
        public void HideToTray()
        {
            try
            {
                _isHiddenToTray = true;
                AppWindow.Hide();
                UpdatePollingState();
            }
            catch { }
        }

        /// <summary>
        /// Stops timers and marks the window as disposed during application shutdown.
        /// </summary>
        internal void CleanupForExit()
        {
            _disposedForExit = true;
            _pollTimer.Stop();
            _toastTimer.Stop();
        }

        /// <summary>
        /// Processes reverse asynchronous notifications dispatched from integrator_core.dll.
        /// </summary>
        /// <param name="evt">Event identifier string.</param>
        /// <param name="payload">JSON event payload string.</param>
        public void HandleCoreEvent(string evt, string payload)
        {
            if (evt == "toast" || evt == "ui-toast")
            {
                try
                {
                    var t = JsonSerializer.Deserialize<UiToastPayload>(payload);
                    if (!string.IsNullOrWhiteSpace(t?.Message))
                    {
                        ShowToast(t.Message!, t.Kind ?? "info");
                    }
                }
                catch { }
            }
            else if (evt == "status-changed" || evt == "kvm-changed")
            {
                _ = RefreshStatusAsync();
            }
        }

        /// <summary>
        /// Asynchronously queries get_bridge_status from integrator_core.dll on a background worker thread
        /// and applies the snapshot to the UI controls on the STA thread.
        /// </summary>
        /// <returns>Task tracking asynchronous execution.</returns>
        private async Task RefreshStatusAsync()
        {
            if (_refreshInFlight || _disposedForExit) return;
            _refreshInFlight = true;
            try
            {
                var res = await Task.Run(() => CoreBridge.Invoke<BridgeStatusModel>("get_bridge_status"));
                if (_disposedForExit || !res.Ok || res.Data == null) return;

                BridgeStatusModel s = res.Data;
                _status = s;

                if (!_kvmLayoutDirty)
                {
                    _kvmLayout = s.Kvm.Layout;
                }

                ApplyStatusToUi(s);
            }
            finally
            {
                _refreshInFlight = false;
            }
        }

        /// <summary>
        /// Programmatically updates all UI controls, status pills, and toggle switches from the bridge status snapshot.
        /// Sets _applyingStatus to true during update to prevent UI feedback loops.
        /// </summary>
        /// <param name="s">Latest bridge status snapshot from the core.</param>
        private void ApplyStatusToUi(BridgeStatusModel s)
        {
            _applyingStatus = true;
            try
            {
                // Top Bar
                TopHostnameText.Text = string.IsNullOrWhiteSpace(s.Hostname) ? "Workstation" : s.Hostname;
                string safeDevId = s.DeviceId ?? string.Empty;
                string safeHw = string.IsNullOrWhiteSpace(s.HardwareModel) ? "Windows PC" : s.HardwareModel;
                TopSubtitleText.Text = string.Format(
                    CultureInfo.InvariantCulture,
                    "{0} • {1}x{2} • {3}",
                    safeHw,
                    s.PrimaryDisplay.Width,
                    s.PrimaryDisplay.Height,
                    safeDevId.Length > DeviceIdPreviewLength ? safeDevId[..DeviceIdPreviewLength] : safeDevId);

                if (s.PeerConnected)
                {
                    SetPillStyle(TopPeerPill, TopPeerDot, Color.FromArgb(255, 32, 184, 90));
                    TopPeerLabel.Text = "Peer Linked";
                }
                else
                {
                    SetPillStyle(TopPeerPill, TopPeerDot, Color.FromArgb(255, 232, 158, 27));
                    TopPeerLabel.Text = "Searching";
                }

                // Sidebar Peer Card
                SidebarPeerName.Text = s.PeerName ?? "Searching for peer…";
                SidebarLinkDesc.Text = s.LinkDescription;
                SidebarSpeedText.Text = string.IsNullOrWhiteSpace(s.LinkSpeed) ? "--" : s.LinkSpeed;
                SidebarTrustText.Text = s.PeerTrusted ? "Verified v1.0" : "Pair Required";
                SidebarPeerDot.Fill = new SolidColorBrush(s.PeerConnected
                    ? Color.FromArgb(255, 32, 184, 90)
                    : Color.FromArgb(255, 232, 158, 27));

                var f = s.FeatureFlags;

                // Card 1: Display & GPU
                SwitchDisplay.IsOn = f.Display;
                DisplayPillText.Text = s.DisplayActive ? (s.ActiveMode ?? "Active") : "Standby";
                SetPillStyle(DisplayPill, DisplayPillDot, s.DisplayActive
                    ? Color.FromArgb(255, 32, 184, 90)
                    : Color.FromArgb(255, 136, 136, 136));
                PopulateGpuCombos(s);

                if (s.DisplayActive && !s.IsWindowsMaster)
                    BtnExtendMacToPc.Style = (Style)Application.Current.Resources["AccentButtonStyle"];
                else
                    BtnExtendMacToPc.ClearValue(FrameworkElement.StyleProperty);

                if (s.DisplayActive && s.IsWindowsMaster)
                    BtnExtendPcToMac.Style = (Style)Application.Current.Resources["AccentButtonStyle"];
                else
                    BtnExtendPcToMac.ClearValue(FrameworkElement.StyleProperty);
                EncodeGpuCombo.IsEnabled = f.Display;
                DecodeGpuCombo.IsEnabled = f.Display;
                BtnApplyGpu.IsEnabled = f.Display;
                BtnExtendMacToPc.IsEnabled = f.Display;
                BtnExtendPcToMac.IsEnabled = f.Display;
                string? displayTip = f.Display ? null : "Extended Screen is disabled in feature flags.";
                ToolTipService.SetToolTip(EncodeGpuCombo, displayTip);
                ToolTipService.SetToolTip(DecodeGpuCombo, displayTip);
                ToolTipService.SetToolTip(BtnApplyGpu, displayTip);
                ToolTipService.SetToolTip(BtnExtendMacToPc, displayTip);
                ToolTipService.SetToolTip(BtnExtendPcToMac, displayTip);

                // Card 2: KVM & Desk Layout
                SwitchKvm.IsOn = f.InputKvm;
                bool kvmHookOk = s.Kvm.HookActive ?? true;
                string kvmRole = !f.InputKvm
                    ? "Disabled"
                    : (!kvmHookOk
                        ? "Hook Off"
                        : s.Kvm.Role switch
                        {
                            "controlling" => "Controlling",
                            "controlled" => "Receiving",
                            "idle" => s.PeerConnected ? "Armed" : "Standby",
                            _ => "Armed"
                        });
                KvmPillText.Text = kvmRole;
                SetPillStyle(KvmPill, KvmPillDot, !f.InputKvm
                    ? Color.FromArgb(255, 136, 136, 136)
                    : (!kvmHookOk
                        ? Color.FromArgb(255, 232, 158, 27)
                        : (s.Kvm.ConnectedPeerIp != null
                            ? Color.FromArgb(255, 32, 184, 90)
                            : Color.FromArgb(255, 232, 158, 27))));
                ApplyKvmLayoutControls(s);

                // Card 3: Cross-Screen Drag & Drop (depends strictly on input_kvm)
                SwitchDragDrop.IsOn = f.Dragdrop && f.InputKvm;
                SwitchDragDrop.IsEnabled = f.InputKvm;
                ToolTipService.SetToolTip(SwitchDragDrop, f.InputKvm ? null : "Enable Universal Input KVM to unlock Cross-Screen Drag & Drop.");
                DragDropKvmWarn.Visibility = f.InputKvm ? Visibility.Collapsed : Visibility.Visible;
                bool ddControlsEnabled = f.InputKvm && f.Dragdrop;
                string? ddTip = !f.InputKvm
                    ? "Enable Universal Input KVM to use Cross-Screen Drag & Drop."
                    : (!f.Dragdrop ? "Turn on Cross-Screen Drag & Drop to adjust drop preferences." : null);
                ChkGhostThumb.IsEnabled = ddControlsEnabled;
                ChkQosClamp.IsEnabled = ddControlsEnabled;
                DropFolderCombo.IsEnabled = ddControlsEnabled;
                BtnSaveDropPrefs.IsEnabled = ddControlsEnabled;
                ToolTipService.SetToolTip(ChkGhostThumb, ddTip);
                ToolTipService.SetToolTip(ChkQosClamp, ddTip);
                ToolTipService.SetToolTip(DropFolderCombo, ddTip);
                ToolTipService.SetToolTip(BtnSaveDropPrefs, ddTip);

                string ddStatus = !f.InputKvm
                    ? "Requires KVM"
                    : (!string.IsNullOrEmpty(s.Kvm.ActiveDragLabel) ? "Transferring" : (f.Dragdrop ? "Ready" : "Off"));
                DragDropPillText.Text = ddStatus;
                SetPillStyle(DragDropPill, DragDropPillDot, !f.InputKvm
                    ? Color.FromArgb(255, 232, 158, 27)
                    : (f.Dragdrop ? Color.FromArgb(255, 32, 184, 90) : Color.FromArgb(255, 136, 136, 136)));

                if (!string.IsNullOrEmpty(s.Kvm.ActiveDragLabel))
                {
                    ActiveDragLabel.Text = "Active: " + s.Kvm.ActiveDragLabel;
                    ActiveDragLabel.Visibility = Visibility.Visible;
                }
                else
                {
                    ActiveDragLabel.Visibility = Visibility.Collapsed;
                }

                // Card 4: Universal Clipboard (depends strictly on input_kvm)
                SwitchClipboard.IsOn = f.Clipboard && f.InputKvm;
                SwitchClipboard.IsEnabled = f.InputKvm;
                ToolTipService.SetToolTip(SwitchClipboard, f.InputKvm ? null : "Enable Universal Input KVM to unlock Universal Clipboard.");
                ClipboardKvmWarn.Visibility = f.InputKvm ? Visibility.Collapsed : Visibility.Visible;
                BtnPasteRemote.IsEnabled = f.Clipboard && f.InputKvm;
                ToolTipService.SetToolTip(BtnPasteRemote, !f.InputKvm
                    ? "Enable Universal Input KVM to unlock Universal Clipboard."
                    : (!f.Clipboard ? "Enable Universal Clipboard to paste remote items." : null));
                ClipboardPillText.Text = !f.InputKvm ? "Requires KVM" : (f.Clipboard ? "Active" : "Off");
                SetPillStyle(ClipboardPill, ClipboardPillDot, !f.InputKvm
                    ? Color.FromArgb(255, 232, 158, 27)
                    : (f.Clipboard ? Color.FromArgb(255, 32, 184, 90) : Color.FromArgb(255, 136, 136, 136)));

                // Card 5: Discovery & Trust
                string curPin = string.IsNullOrWhiteSpace(s.Trust.PairingPin) ? "------" : s.Trust.PairingPin;
                DiscoveryPillText.Text = "PIN: " + curPin;
                SetPillStyle(DiscoveryPill, DiscoveryPillDot, Color.FromArgb(255, 24, 180, 212));
                PairingPinText.Text = curPin;
                RebuildManualIpsPanel(s);
                RebuildPeersList(s);

                // Card 6: Route Telemetry & Speed
                SpeedPillText.Text = string.IsNullOrWhiteSpace(s.LinkSpeed) ? "--" : s.LinkSpeed;
                SetPillStyle(SpeedPill, SpeedPillDot, s.PeerConnected
                    ? Color.FromArgb(255, 24, 180, 212)
                    : Color.FromArgb(255, 136, 136, 136));
                RouteTransportText.Text = string.IsNullOrWhiteSpace(s.TransportLabel) ? "Scanning" : s.TransportLabel;
                RouteSpeedText.Text = string.IsNullOrWhiteSpace(s.LinkSpeed) ? "--" : s.LinkSpeed;
                RouteRttText.Text = s.RttMs.HasValue
                    ? string.Format(CultureInfo.InvariantCulture, "{0:0.0} ms", s.RttMs.Value)
                    : "--";
                InterfacesText.Text = s.LocalInterfaces.Count > 0
                    ? "Interfaces: " + string.Join(", ", s.LocalInterfaces.Take(MaxDisplayedInterfaces).Select(i => i.Name + " (" + i.Ip + ")"))
                    : "Interfaces: scanning...";
                BtnSpeedTest.IsEnabled = f.Benchmark && !_speedTestRunning;
                ToolTipService.SetToolTip(BtnSpeedTest, f.Benchmark ? null : "Live speed benchmark is disabled in feature flags.");

                // Card 7: Shared Storage
                SwitchStorage.IsOn = f.Storage;
                StoragePillText.Text = s.StorageMounted ? "Mounted" : "Unmounted";
                SetPillStyle(StoragePill, StoragePillDot, s.StorageMounted
                    ? Color.FromArgb(255, 32, 184, 90)
                    : Color.FromArgb(255, 136, 136, 136));
                if (!string.IsNullOrWhiteSpace(s.StorageStatus.MountPath))
                    StorageSummaryText.Text = s.StorageStatus.MountPath;
                else if (!string.IsNullOrWhiteSpace(s.StorageStatus.Message))
                    StorageSummaryText.Text = s.StorageStatus.Message;
                else
                    StorageSummaryText.Text = "SMB volume ready on trusted peer";

                LocalSharedFolderInput.Text = !string.IsNullOrWhiteSpace(s.LocalSharedFolder)
                    ? s.LocalSharedFolder
                    : GetDefaultSharedFolderLabel();
                BtnOpenInExplorer.Visibility = s.StorageMounted ? Visibility.Visible : Visibility.Collapsed;

                if (!_preferredShareDirty && PreferredShareInput.FocusState == FocusState.Unfocused)
                {
                    string desiredShare = s.PreferredPeerShare ?? string.Empty;
                    if (PreferredShareInput.Text != desiredShare)
                    {
                        PreferredShareInput.Text = desiredShare;
                    }
                }
                BtnToggleMount.Content = s.StorageMounted ? "Unmount Storage" : "Mount Shared Storage";
                BtnToggleMount.IsEnabled = f.Storage;
                ToolTipService.SetToolTip(BtnToggleMount, f.Storage ? null : "Shared Storage is disabled in feature flags.");

                // Card 8: True Tone
                SwitchTrueTone.IsOn = f.Truetone;
                TrueTonePillText.Text = s.AmbientSupported
                    ? string.Format(CultureInfo.InvariantCulture, "{0:0} lux • {1}K", s.AmbientLux ?? 0f, s.AmbientCct ?? DefaultAmbientCctKelvin)
                    : "Manual";
                SetPillStyle(TrueTonePill, TrueTonePillDot, f.Truetone
                    ? Color.FromArgb(255, 232, 192, 27)
                    : Color.FromArgb(255, 136, 136, 136));
                BtnSyncCalibration.IsEnabled = f.Truetone;

                // Card 9: Touch Bar Hardware HUD
                SwitchTouchBar.IsOn = f.Touchbar;
                TouchBarPillText.Text = s.TouchbarActive ? "Active" : (s.HasTouchBar ? "Ready" : "Unavailable");
                SetPillStyle(TouchBarPill, TouchBarPillDot, s.TouchbarActive
                    ? Color.FromArgb(255, 32, 184, 90)
                    : Color.FromArgb(255, 136, 136, 136));
                TouchBarDescText.Text = s.HasTouchBar
                    ? "Touch Bar hardware GPU telemetry strip & quick controls."
                    : "No Apple Touch Bar hardware detected on this workstation.";
                BtnToggleTouchBar.IsEnabled = f.Touchbar && s.HasTouchBar;

                // Card 10: Audio
                SwitchAudio.IsOn = f.Audio;
                ushort audioPort = s.AudioStatus.Port > 0 ? s.AudioStatus.Port : AudioRoutingStatusModel.DefaultAudioPort;
                AudioPillText.Text = string.Format(CultureInfo.InvariantCulture, "UDP :{0}", audioPort);
                AudioTopologyText.Text = string.IsNullOrWhiteSpace(s.AudioStatus.Topology)
                    ? "Authenticated ChaCha20-Poly1305 spatial UDP audio sink ready."
                    : s.AudioStatus.Topology;
                BtnPlayChime.IsEnabled = f.Audio;

                // Card 10B: Mac -> PC Shared Camera
                SwitchCamera.IsOn = f.Camera;
                var cam = s.CameraStatus;
                uint camWidth = cam.Width > 0 ? cam.Width : CameraStatusModel.DefaultCameraWidth;
                uint camHeight = cam.Height > 0 ? cam.Height : CameraStatusModel.DefaultCameraHeight;
                uint camFps = cam.Fps > 0 ? cam.Fps : CameraStatusModel.DefaultCameraFps;
                ushort camPort = cam.Port > 0 ? cam.Port : CameraStatusModel.DefaultCameraPort;
                string camDeviceName = string.IsNullOrWhiteSpace(cam.DeviceName)
                    ? CameraStatusModel.DefaultCameraDeviceName
                    : cam.DeviceName;
                CameraPillText.Text = string.IsNullOrWhiteSpace(cam.State) ? (cam.Active ? "Active" : "Disabled") : cam.State;
                SetPillStyle(CameraPill, CameraPillDot, cam.Active
                    ? Color.FromArgb(255, 32, 184, 90)
                    : (f.Camera ? Color.FromArgb(255, 24, 180, 212) : Color.FromArgb(255, 136, 136, 136)));
                if (!string.IsNullOrWhiteSpace(cam.LastError))
                {
                    CameraSummaryText.Text = cam.LastError;
                }
                else if (cam.Active)
                {
                    CameraSummaryText.Text = string.Format(
                        CultureInfo.InvariantCulture,
                        "{0} • {1}x{2}@{3}fps • {4} frames received (TCP :{5})",
                        cam.Role, camWidth, camHeight, camFps, cam.FramesTransferred, camPort);
                }
                else
                {
                    CameraSummaryText.Text = string.Format(
                        CultureInfo.InvariantCulture,
                        "Exposes '{0}' ({1}p{2}) via encrypted TCP :{3} when enabled on Mac and PC.",
                        camDeviceName, camHeight, camFps, camPort);
                }
                BtnToggleCamera.Content = cam.Active ? "Stop Virtual Camera" : "Enable Virtual Camera";

                // Card 11: Autostart
                SwitchAutostart.IsOn = s.AutostartEnabled;
                AutostartPillText.Text = s.AutostartEnabled ? "Launch at Login" : "Manual Launch";
                SetPillStyle(AutostartPill, AutostartPillDot, s.AutostartEnabled
                    ? Color.FromArgb(255, 32, 184, 90)
                    : Color.FromArgb(255, 136, 136, 136));

                // Card 12: Logs
                RebuildLogsPanel(s.RecentLogs);
            }
            finally
            {
                _applyingStatus = false;
            }
        }

        /// <summary>
        /// Maps GPU name and vendor strings into canonical lowercase tags ("nvidia", "amd", "intel", "discrete").
        /// </summary>
        /// <param name="g">GPU metadata model.</param>
        /// <returns>Canonical vendor tag.</returns>
        private static string GpuVendorTag(GpuDeviceInfo g)
        {
            string combined = (g.Vendor + " " + g.Name).ToLowerInvariant();
            if (combined.Contains("nvidia") || combined.Contains("geforce") || combined.Contains("quadro") || combined.Contains("rtx"))
                return "nvidia";
            if (combined.Contains("amd") || combined.Contains("radeon"))
                return "amd";
            if (combined.Contains("intel") || combined.Contains("uhd") || combined.Contains("iris") || combined.Contains("arc"))
                return "intel";
            return g.IsDiscrete ? "discrete" : "integrated";
        }

        /// <summary>
        /// Populates encode and decode GPU ComboBox dropdowns from detected local graphics adapters.
        /// Preserves user selections if dirty flags are set.
        /// </summary>
        /// <param name="s">Bridge status model containing detected GPUs.</param>
        private void PopulateGpuCombos(BridgeStatusModel s)
        {
            string gpuKey = string.Join("|", s.LocalGpus.Select(g => $"{g.Index}:{g.Name}:{g.Vendor}:{g.IsDiscrete}"));
            if (_lastGpuListKey != gpuKey)
            {
                _lastGpuListKey = gpuKey;
                EncodeGpuCombo.Items.Clear();
                DecodeGpuCombo.Items.Clear();
                EncodeGpuCombo.Items.Add(new ComboBoxItem { Content = "Auto (Recommended)", Tag = "auto" });
                DecodeGpuCombo.Items.Add(new ComboBoxItem { Content = "Auto (Recommended)", Tag = "auto" });

                foreach (var g in s.LocalGpus)
                {
                    string vendorTag = GpuVendorTag(g);
                    EncodeGpuCombo.Items.Add(new ComboBoxItem { Content = g.Name, Tag = vendorTag });
                    DecodeGpuCombo.Items.Add(new ComboBoxItem { Content = g.Name, Tag = vendorTag });
                }
            }

            if (!_encodeGpuDirty)
            {
                SelectGpuComboByPreference(
                    EncodeGpuCombo,
                    string.IsNullOrWhiteSpace(s.EncodeGpu) ? "auto" : s.EncodeGpu,
                    s.LocalGpus);
            }
            if (!_decodeGpuDirty)
            {
                SelectGpuComboByPreference(
                    DecodeGpuCombo,
                    string.IsNullOrWhiteSpace(s.DecodeGpu) ? "auto" : s.DecodeGpu,
                    s.LocalGpus);
            }
        }

        /// <summary>
        /// Selects the ComboBox item matching the specified GPU preference tag or vendor name.
        /// </summary>
        /// <param name="combo">Target ComboBox control.</param>
        /// <param name="preference">Desired preference string.</param>
        /// <param name="gpus">List of detected GPUs.</param>
        private static void SelectGpuComboByPreference(ComboBox combo, string preference, List<GpuDeviceInfo> gpus)
        {
            string pref = preference.Trim();
            for (int i = 0; i < combo.Items.Count; i++)
            {
                if (combo.Items[i] is ComboBoxItem item &&
                    string.Equals(item.Tag as string, pref, StringComparison.OrdinalIgnoreCase))
                {
                    combo.SelectedIndex = i;
                    return;
                }
            }

            if (string.Equals(pref, "discrete", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(pref, "integrated", StringComparison.OrdinalIgnoreCase))
            {
                bool wantDiscrete = string.Equals(pref, "discrete", StringComparison.OrdinalIgnoreCase);
                var matchGpu = gpus.FirstOrDefault(g => g.IsDiscrete == wantDiscrete);
                if (matchGpu != null)
                {
                    for (int i = 0; i < combo.Items.Count; i++)
                    {
                        if (combo.Items[i] is ComboBoxItem item &&
                            string.Equals(item.Content as string, matchGpu.Name, StringComparison.OrdinalIgnoreCase))
                        {
                            combo.SelectedIndex = i;
                            return;
                        }
                    }
                }
            }

            for (int i = 0; i < combo.Items.Count; i++)
            {
                if (combo.Items[i] is ComboBoxItem item &&
                    item.Content is string name &&
                    name.Contains(pref, StringComparison.OrdinalIgnoreCase))
                {
                    combo.SelectedIndex = i;
                    return;
                }
            }

            if (combo.Items.Count > 0) combo.SelectedIndex = 0;
        }

        /// <summary>
        /// Helper selecting a ComboBoxItem whose Tag matches the specified string.
        /// </summary>
        private static void SelectComboByTag(ComboBox combo, string tag)
        {
            for (int i = 0; i < combo.Items.Count; i++)
            {
                if (combo.Items[i] is ComboBoxItem item && string.Equals(item.Tag as string, tag, StringComparison.OrdinalIgnoreCase))
                {
                    combo.SelectedIndex = i;
                    return;
                }
            }
            if (combo.Items.Count > 0) combo.SelectedIndex = 0;
        }

        /// <summary>
        /// Binds KVM layout controls (alignment slider, hop delay, checkboxes) and updates schematic tiles.
        /// </summary>
        private void ApplyKvmLayoutControls(BridgeStatusModel s)
        {
            AlignmentSlider.Value = Math.Clamp(_kvmLayout.AlignmentOffset, -0.5f, 0.5f);
            AlignmentValueText.Text = string.Format(CultureInfo.InvariantCulture, "{0:0}%", AlignmentSlider.Value * 100.0);
            uint clampedDelay = Math.Min(_kvmLayout.HopDelayMs, 250u);
            HopDelaySlider.Value = clampedDelay;
            HopDelayValueText.Text = clampedDelay + " ms";

            ChkDeadCorners.IsChecked = _kvmLayout.DeadCorners;
            ChkModifierTrans.IsChecked = _kvmLayout.ModifierTranslation;
            ChkTrackpad.IsChecked = _kvmLayout.PrecisionTouchpad;
            ChkGhostThumb.IsChecked = _kvmLayout.GhostThumbnail;
            ChkQosClamp.IsChecked = _kvmLayout.QosClamp;
            SelectComboByTag(DropFolderCombo, _kvmLayout.DropFolder);

            bool kvmEnabled = s.FeatureFlags.InputKvm;
            string? kvmTip = kvmEnabled ? null : "Enable Universal Input KVM to use this control.";
            Control[] kvmControls =
            {
                EdgeTopBtn, EdgeLeftBtn, EdgeRightBtn, EdgeBottomBtn,
                AlignmentSlider, HopDelaySlider,
                ChkDeadCorners, ChkModifierTrans, ChkTrackpad,
                BtnSaveKvm, BtnReleaseKvm
            };
            foreach (Control ctrl in kvmControls)
            {
                ctrl.IsEnabled = kvmEnabled;
                ToolTipService.SetToolTip(ctrl, kvmTip);
            }

            ApplyEdgeStylesAndSchematic(s);
        }

        /// <summary>
        /// Highlights the active peer edge transition button and rebuilds the 2D desk layout schematic.
        /// </summary>
        private void ApplyEdgeStylesAndSchematic(BridgeStatusModel s)
        {
            var accent = (Style)Application.Current.Resources["AccentButtonStyle"];
            void ApplyEdgeStyle(Button btn, string edge)
            {
                if (_kvmLayout.PeerEdge == edge) btn.Style = accent;
                else btn.ClearValue(FrameworkElement.StyleProperty);
            }
            ApplyEdgeStyle(EdgeTopBtn, "top");
            ApplyEdgeStyle(EdgeLeftBtn, "left");
            ApplyEdgeStyle(EdgeRightBtn, "right");
            ApplyEdgeStyle(EdgeBottomBtn, "bottom");

            RebuildDeskSchematic(s);
        }

        /// <summary>
        /// Rebuilds the visual 2D desk monitor placement schematic representing local and peer displays.
        /// </summary>
        private void RebuildDeskSchematic(BridgeStatusModel s)
        {
            DeskSchematicHost.Children.Clear();
            string localName = string.IsNullOrWhiteSpace(s.Hostname) ? DefaultLocalHostname : s.Hostname;
            string peerName = s.PeerName ?? DefaultPeerHostname;

            Border localTile = CreateMonitorTile(localName, accent: true);
            Border peerTile = CreateMonitorTile(peerName, accent: false);

            var panel = new StackPanel
            {
                Spacing = 6,
                Orientation = (_kvmLayout.PeerEdge is "top" or "bottom") ? Orientation.Vertical : Orientation.Horizontal
            };

            if (_kvmLayout.PeerEdge is "left" or "top")
            {
                panel.Children.Add(peerTile);
                panel.Children.Add(localTile);
            }
            else
            {
                panel.Children.Add(localTile);
                panel.Children.Add(peerTile);
            }

            DeskSchematicHost.Children.Add(panel);
        }

        /// <summary>
        /// Creates a styled monitor tile Border for the desk placement schematic.
        /// </summary>
        private Border CreateMonitorTile(string label, bool accent)
        {
            return new Border
            {
                MinWidth = 90,
                VerticalAlignment = VerticalAlignment.Center,
                Padding = new Thickness(12, 10, 12, 10),
                CornerRadius = new CornerRadius(8),
                Background = accent
                    ? (Brush)Application.Current.Resources["AccentFillColorDefaultBrush"]
                    : (Brush)Application.Current.Resources["CardBackgroundFillColorDefaultBrush"],
                BorderBrush = accent
                    ? (Brush)Application.Current.Resources["AccentFillColorDefaultBrush"]
                    : (Brush)Application.Current.Resources["CardStrokeColorDefaultBrush"],
                BorderThickness = new Thickness(1),
                Child = new TextBlock
                {
                    Text = label,
                    FontSize = 11,
                    FontWeight = FontWeights.SemiBold,
                    Foreground = accent
                        ? (Application.Current.Resources.TryGetValue("TextOnAccentFillColorPrimaryBrush", out var onAccentObj) && onAccentObj is Brush onAccentBrush
                            ? onAccentBrush
                            : new SolidColorBrush(Colors.White))
                        : (Brush)Application.Current.Resources["TextFillColorPrimaryBrush"],
                    HorizontalAlignment = HorizontalAlignment.Center,
                    TextTrimming = TextTrimming.CharacterEllipsis
                }
            };
        }

        /// <summary>
        /// Rebuilds the manual peer IP badges panel, displaying remove buttons for user-added IP targets.
        /// </summary>
        private void RebuildManualIpsPanel(BridgeStatusModel s)
        {
            var ips = s.ManualPeerIps ?? new List<string>();
            string key = string.Join("|", ips);
            if (_lastManualIpKey == key) return;
            _lastManualIpKey = key;

            ManualIpsPanel.Children.Clear();
            foreach (string rawIp in ips)
            {
                string ip = rawIp;
                var row = new Grid { ColumnSpacing = 8 };
                row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

                var lbl = new TextBlock
                {
                    Text = $"Manual target: {ip}",
                    FontSize = 11,
                    Foreground = (Brush)Application.Current.Resources["TextFillColorSecondaryBrush"],
                    VerticalAlignment = VerticalAlignment.Center,
                    TextTrimming = TextTrimming.CharacterEllipsis
                };
                Grid.SetColumn(lbl, 0);
                row.Children.Add(lbl);

                var removeBtn = new Button
                {
                    Content = "Remove",
                    Padding = new Thickness(10, 3, 10, 3),
                    FontSize = 11
                };
                AutomationProperties.SetName(removeBtn, $"Remove manual peer IP {ip}");
                removeBtn.Click += (_, _) => RunInvoke("remove_manual_peer_ip", new { ip });
                Grid.SetColumn(removeBtn, 1);
                row.Children.Add(removeBtn);

                ManualIpsPanel.Children.Add(row);
            }
        }

        /// <summary>
        /// Rebuilds the discovered and trusted peers list, presenting pairing PIN input fields, trust badges,
        /// and block/unblock action buttons while preserving user input text during refresh cycles.
        /// </summary>
        private void RebuildPeersList(BridgeStatusModel s)
        {
            // Preserve user's in-progress PIN text while updating peer statuses cleanly.
            var staleTrusted = s.Trust.TrustedPeers
                .Where(tp => !s.DiscoveredPeers.Any(d => d.DeviceId == tp.DeviceId && d.Trusted))
                .ToList();
            var blockedNotVisible = s.Trust.BlockedDeviceIds
                .Where(bid => !s.DiscoveredPeers.Any(d => d.DeviceId == bid))
                .ToList();
            string peerKey = string.Join("|", s.DiscoveredPeers.Select(p => $"{p.DeviceId}:{p.Hostname}:{p.Ip}:{p.Trusted}:{p.Blocked}"))
                + "##" + string.Join("|", staleTrusted.Select(tp => $"{tp.DeviceId}:{tp.LastIp}"))
                + "##" + string.Join("|", s.Trust.BlockedDeviceIds);
            if (_lastPeerKey == peerKey) return;
            _lastPeerKey = peerKey;

            PeersListPanel.Children.Clear();
            foreach (var tp in staleTrusted)
            {
                var row = new Grid { ColumnSpacing = 8 };
                row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
                var nameBlock = new TextBlock
                {
                    Text = $"{tp.Hostname} (Pinned Key • {tp.LastIp})",
                    FontSize = 12,
                    Foreground = new SolidColorBrush(Color.FromArgb(255, 232, 158, 27)),
                    VerticalAlignment = VerticalAlignment.Center,
                    TextTrimming = TextTrimming.CharacterEllipsis
                };
                Grid.SetColumn(nameBlock, 0);
                row.Children.Add(nameBlock);

                var actions = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 6 };
                string devId = tp.DeviceId;
                var untrustBtn = new Button { Content = "Untrust", Padding = new Thickness(10, 4, 10, 4), FontSize = 11 };
                untrustBtn.Click += (_, _) => RunInvoke("untrust_or_block_peer", new { deviceId = devId, block = false });
                actions.Children.Add(untrustBtn);
                var blockBtn = new Button { Content = "Block", Padding = new Thickness(10, 4, 10, 4), FontSize = 11 };
                blockBtn.Click += (_, _) => RunInvoke("untrust_or_block_peer", new { deviceId = devId, block = true });
                actions.Children.Add(blockBtn);

                Grid.SetColumn(actions, 1);
                row.Children.Add(actions);
                PeersListPanel.Children.Add(row);
            }
            foreach (var peer in s.DiscoveredPeers)
            {
                var row = new Grid { ColumnSpacing = 8 };
                row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
                row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

                var nameBlock = new TextBlock
                {
                    Text = $"{peer.Hostname} ({peer.Ip})",
                    FontSize = 12,
                    VerticalAlignment = VerticalAlignment.Center,
                    TextTrimming = TextTrimming.CharacterEllipsis
                };
                Grid.SetColumn(nameBlock, 0);
                row.Children.Add(nameBlock);

                string devId = peer.DeviceId;
                if (peer.Blocked)
                {
                    var badge = new TextBlock
                    {
                        Text = "Blocked",
                        FontSize = 11,
                        FontWeight = FontWeights.SemiBold,
                        Foreground = new SolidColorBrush(Color.FromArgb(255, 220, 53, 69)),
                        VerticalAlignment = VerticalAlignment.Center
                    };
                    Grid.SetColumn(badge, 1);
                    row.Children.Add(badge);

                    var unblockBtn = new Button { Content = "Unblock", Padding = new Thickness(10, 4, 10, 4), FontSize = 11 };
                    unblockBtn.Click += (_, _) => RunInvoke("untrust_or_block_peer", new { deviceId = devId, block = false });
                    Grid.SetColumn(unblockBtn, 2);
                    row.Children.Add(unblockBtn);
                }
                else if (peer.Trusted)
                {
                    var badge = new TextBlock
                    {
                        Text = "Trusted v1.0",
                        FontSize = 11,
                        FontWeight = FontWeights.SemiBold,
                        Foreground = new SolidColorBrush(Color.FromArgb(255, 32, 184, 90)),
                        VerticalAlignment = VerticalAlignment.Center
                    };
                    Grid.SetColumn(badge, 1);
                    row.Children.Add(badge);

                    var actions = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 6 };
                    var untrustBtn = new Button { Content = "Untrust", Padding = new Thickness(10, 4, 10, 4), FontSize = 11 };
                    untrustBtn.Click += (_, _) => RunInvoke("untrust_or_block_peer", new { deviceId = devId, block = false });
                    actions.Children.Add(untrustBtn);
                    var blockBtn = new Button { Content = "Block", Padding = new Thickness(10, 4, 10, 4), FontSize = 11 };
                    blockBtn.Click += (_, _) => RunInvoke("untrust_or_block_peer", new { deviceId = devId, block = true });
                    actions.Children.Add(blockBtn);

                    Grid.SetColumn(actions, 2);
                    row.Children.Add(actions);
                }
                else
                {
                    string ip = peer.Ip;
                    var pinBox = new TextBox
                    {
                        Width = 86,
                        MaxLength = PairingPinMaxInputLength,
                        PlaceholderText = "6-digit PIN",
                        Text = _pinInputs.TryGetValue(ip, out string? existing) ? existing : ""
                    };
                    AutomationProperties.SetName(pinBox, $"Pairing PIN for {peer.Hostname}");
                    pinBox.TextChanged += (_, _) => _pinInputs[ip] = pinBox.Text;
                    Grid.SetColumn(pinBox, 1);
                    row.Children.Add(pinBox);

                    var actions = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 6 };
                    var pairBtn = new Button
                    {
                        Content = "Pair v1.0",
                        Style = (Style)Application.Current.Resources["AccentButtonStyle"],
                        Padding = new Thickness(10, 4, 10, 4),
                        FontSize = 11
                    };
                    pairBtn.Click += (_, _) =>
                    {
                        string entered = _pinInputs.TryGetValue(ip, out string? val) ? val.Trim() : "";
                        _pinInputs.Remove(ip);
                        pinBox.Text = string.Empty;
                        RunInvoke("pair_with_peer", new { ip, pin = entered }, onCompleted: ok =>
                        {
                            if (ok) _lastPeerKey = null;
                        });
                    };
                    actions.Children.Add(pairBtn);

                    var blockBtn = new Button { Content = "Block", Padding = new Thickness(10, 4, 10, 4), FontSize = 11 };
                    blockBtn.Click += (_, _) => RunInvoke("untrust_or_block_peer", new { deviceId = devId, block = true });
                    actions.Children.Add(blockBtn);

                    Grid.SetColumn(actions, 2);
                    row.Children.Add(actions);
                }

                PeersListPanel.Children.Add(row);
            }
            foreach (string blockedId in blockedNotVisible)
            {
                string devId = blockedId;
                var row = new Grid { ColumnSpacing = 8 };
                row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

                var lbl = new TextBlock
                {
                    Text = $"Blocked Peer ({(devId.Length > DeviceIdPreviewLength ? devId[..DeviceIdPreviewLength] : devId)})",
                    FontSize = 11,
                    Foreground = new SolidColorBrush(Color.FromArgb(255, 220, 53, 69)),
                    VerticalAlignment = VerticalAlignment.Center,
                    TextTrimming = TextTrimming.CharacterEllipsis
                };
                Grid.SetColumn(lbl, 0);
                row.Children.Add(lbl);

                var unblockBtn = new Button { Content = "Unblock", Padding = new Thickness(10, 4, 10, 4), FontSize = 11 };
                unblockBtn.Click += (_, _) => RunInvoke("untrust_or_block_peer", new { deviceId = devId, block = false });
                Grid.SetColumn(unblockBtn, 1);
                row.Children.Add(unblockBtn);

                PeersListPanel.Children.Add(row);
            }
        }

        /// <summary>
        /// Populates the live log console panel with recent log records from the Rust core.
        /// Preserves scroll position and autoscrolls to the latest entry when pinned to bottom.
        /// </summary>
        private void RebuildLogsPanel(List<LogEntryModel> logs)
        {
            var safeLogs = logs ?? new List<LogEntryModel>();
            var tail = safeLogs.Count > MaxRenderedLogLines ? safeLogs.Skip(safeLogs.Count - MaxRenderedLogLines).ToList() : safeLogs;
            LogsCountText.Text = tail.Count + " lines";

            string logsKey = string.Join("\n", tail.Select(e => $"{e.TsMs}:{e.Level}:{e.Message}"));
            ElementTheme curTheme = RootGrid.ActualTheme;
            if (_lastRenderedLogsKey == logsKey && _lastRenderedTheme == curTheme)
            {
                return;
            }
            _lastRenderedLogsKey = logsKey;
            _lastRenderedTheme = curTheme;

            bool wasAtBottom = LogsScrollViewer.ScrollableHeight <= 1.0 ||
                               LogsScrollViewer.VerticalOffset >= LogsScrollViewer.ScrollableHeight - 24.0;

            Brush primaryBrush = (Brush)Application.Current.Resources["TextFillColorPrimaryBrush"];
            Brush errorBrush = Application.Current.Resources.TryGetValue("SystemFillColorCriticalBrush", out var critObj) && critObj is Brush cb
                ? cb
                : new SolidColorBrush(Color.FromArgb(255, 220, 53, 69));
            Brush warnBrush = Application.Current.Resources.TryGetValue("SystemFillColorCautionBrush", out var warnObj) && warnObj is Brush wb
                ? wb
                : new SolidColorBrush(Color.FromArgb(255, 214, 134, 0));

            LogsListPanel.Children.Clear();
            foreach (var entry in tail)
            {
                Brush fg = entry.Level switch
                {
                    "ERROR" => errorBrush,
                    "WARN" => warnBrush,
                    _ => primaryBrush
                };
                LogsListPanel.Children.Add(new TextBlock
                {
                    Text = $"[{entry.Level}] {entry.Message}",
                    FontFamily = new FontFamily("Consolas"),
                    FontSize = 11,
                    Foreground = fg,
                    TextWrapping = TextWrapping.Wrap,
                    IsTextSelectionEnabled = true
                });
            }

            if (wasAtBottom)
            {
                DispatcherQueue.TryEnqueue(() =>
                {
                    if (!_disposedForExit)
                    {
                        LogsScrollViewer.ChangeView(null, LogsScrollViewer.ScrollableHeight, null, disableAnimation: true);
                    }
                });
            }
        }

        /// <summary>
        /// Applies consistent colored indicator dot and semi-transparent background fill to a status pill.
        /// </summary>
        private static void SetPillStyle(Border pill, Ellipse dot, Color color)
        {
            dot.Fill = new SolidColorBrush(color);
            pill.Background = new SolidColorBrush(Color.FromArgb(34, color.R, color.G, color.B));
            pill.BorderBrush = new SolidColorBrush(Color.FromArgb(90, color.R, color.G, color.B));
        }

        // MARK: - Responsive Grid & Navigation

        /// <summary>
        /// Handles category navigation button clicks, filtering the visible cards on the dashboard.
        /// </summary>
        private void NavButton_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is string cat)
            {
                _selectedCategory = cat;
                UpdateNavStyles();
                RebuildCardsGrid(force: true);
            }
        }

        /// <summary>
        /// Updates the accent highlight styling of the category navigation buttons.
        /// </summary>
        private void UpdateNavStyles()
        {
            var accentBrush = (Brush)Application.Current.Resources["AccentFillColorDefaultBrush"];
            var transparent = new SolidColorBrush(Colors.Transparent);
            var white = new SolidColorBrush(Colors.White);
            var primary = (Brush)Application.Current.Resources["TextFillColorPrimaryBrush"];

            foreach (var btn in _navButtons)
            {
                bool active = string.Equals(btn.Tag as string, _selectedCategory, StringComparison.Ordinal);
                btn.Background = active ? accentBrush : transparent;
                btn.BorderBrush = transparent;
                btn.Foreground = active ? white : primary;
            }
        }

        /// <summary>
        /// Responds to window resize events, adjusting the cards grid layout between 1 and 2 columns.
        /// </summary>
        private void CardsGrid_SizeChanged(object sender, SizeChangedEventArgs e)
        {
            RebuildCardsGrid(force: false);
        }

        /// <summary>
        /// Reconfigures grid column and row definitions and redistributes visible cards dynamically.
        /// </summary>
        private void RebuildCardsGrid(bool force)
        {
            int cols = CardsGrid.ActualWidth >= TwoColumnBreakpointDip ? 2 : 1;
            if (!force && cols == _currentGridColumns) return;
            _currentGridColumns = cols;

            CardsGrid.ColumnDefinitions.Clear();
            for (int c = 0; c < cols; c++)
            {
                CardsGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            }

            CardsGrid.RowDefinitions.Clear();
            int visibleIdx = 0;
            foreach (var card in _allCards)
            {
                string tag = card.Tag as string ?? "system";
                bool visible = _selectedCategory == "all" || tag == _selectedCategory;
                card.Visibility = visible ? Visibility.Visible : Visibility.Collapsed;
                if (visible)
                {
                    int row = visibleIdx / cols;
                    int col = visibleIdx % cols;
                    while (CardsGrid.RowDefinitions.Count <= row)
                    {
                        CardsGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
                    }
                    Grid.SetRow(card, row);
                    Grid.SetColumn(card, col);
                    visibleIdx++;
                }
            }
        }

        // MARK: - RPC Actions & UI Event Handlers

        /// <summary>
        /// Dispatches an asynchronous JSON-RPC call to integrator_core.dll on a background worker thread,
        /// presents toast feedback, and triggers a UI status refresh.
        /// </summary>
        private async void RunInvoke(
            string method,
            object? parameters = null,
            bool refreshAfter = true,
            bool preserveNulls = false,
            Action<bool>? onCompleted = null)
        {
            var res = await Task.Run(() => CoreBridge.Invoke<JsonElement>(method, parameters, preserveNulls));
            if (_disposedForExit) return;

            if (!res.Ok)
            {
                ShowToast(string.IsNullOrWhiteSpace(res.Error) ? $"{method} failed" : res.Error!, "error");
            }
            else if (method == "regenerate_pairing_pin")
            {
                ShowToast("New pairing PIN generated", "success");
            }
            else if (res.Data.ValueKind == JsonValueKind.String)
            {
                string? msg = res.Data.GetString();
                if (!string.IsNullOrWhiteSpace(msg))
                {
                    ShowToast(msg!, "success");
                }
            }
            else if (res.Data.ValueKind == JsonValueKind.Object &&
                     res.Data.TryGetProperty("message", out JsonElement msgElem) &&
                     msgElem.ValueKind == JsonValueKind.String)
            {
                string? msg = msgElem.GetString();
                if (!string.IsNullOrWhiteSpace(msg))
                {
                    ShowToast(msg!, "success");
                }
            }

            onCompleted?.Invoke(res.Ok);

            if (refreshAfter)
            {
                await RefreshStatusAsync();
            }
        }

        /// <summary>
        /// Handles click on the Refresh button in the top bar to query latest bridge status.
        /// </summary>
        private void RefreshBtn_Click(object sender, RoutedEventArgs e) => _ = RefreshStatusAsync();
        /// <summary>
        /// Opens the local clipboard file staging and cache folder in Windows File Explorer.
        /// </summary>
        private void OpenCacheBtn_Click(object sender, RoutedEventArgs e) => RunInvoke("open_cache_folder", refreshAfter: false);
        /// <summary>
        /// Hides the main dashboard window to the Windows notification tray.
        /// </summary>
        private void HideWindowBtn_Click(object sender, RoutedEventArgs e) => HideToTray();

        /// <summary>
        /// Handles toggle switches for subsystem feature flags and dispatches set_feature_flag RPCs.
        /// </summary>
        private void FeatureSwitch_Toggled(object sender, RoutedEventArgs e)
        {
            if (_applyingStatus || _status == null) return;
            if (sender is ToggleSwitch ts && ts.Tag is string feature)
            {
                bool enabled = ts.IsOn;
                var f = _status.FeatureFlags;
                bool current = feature switch
                {
                    "display" => f.Display,
                    "input_kvm" => f.InputKvm,
                    "clipboard" => f.Clipboard && f.InputKvm,
                    "dragdrop" => f.Dragdrop && f.InputKvm,
                    "truetone" => f.Truetone,
                    "touchbar" => f.Touchbar,
                    "storage" => f.Storage,
                    "audio" => f.Audio,
                    "benchmark" => f.Benchmark,
                    "camera" => f.Camera,
                    _ => enabled
                };
                if (current == enabled) return;
                RunInvoke("set_feature_flag", new { feature, enabled });
            }
        }

        /// <summary>
        /// Initiates or toggles extended screen display streaming from Mac to Windows PC.
        /// </summary>
        private void ExtendMacToPc_Click(object sender, RoutedEventArgs e)
        {
            if (BtnExtendMacToPc != null) BtnExtendMacToPc.IsEnabled = false;
            RunInvoke("toggle_mac_to_pc", onCompleted: _ =>
            {
                if (BtnExtendMacToPc != null) BtnExtendMacToPc.IsEnabled = true;
            });
        }

        /// <summary>
        /// Initiates or toggles extended screen display streaming from Windows PC to Mac.
        /// </summary>
        private void ExtendPcToMac_Click(object sender, RoutedEventArgs e)
        {
            if (BtnExtendPcToMac != null) BtnExtendPcToMac.IsEnabled = false;
            RunInvoke("toggle_pc_to_mac", onCompleted: _ =>
            {
                if (BtnExtendPcToMac != null) BtnExtendPcToMac.IsEnabled = true;
            });
        }

        /// <summary>
        /// Marks encode or decode GPU selection as dirty when changed by the user in the dropdowns.
        /// </summary>
        private void GpuCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (_applyingStatus || _status == null) return;
            if (ReferenceEquals(sender, EncodeGpuCombo)) _encodeGpuDirty = true;
            else if (ReferenceEquals(sender, DecodeGpuCombo)) _decodeGpuDirty = true;
        }

        /// <summary>
        /// Dispatches user-selected video encode and decode GPU preferences to the native core.
        /// </summary>
        private void ApplyGpu_Click(object sender, RoutedEventArgs e)
        {
            string enc = (EncodeGpuCombo.SelectedItem as ComboBoxItem)?.Tag as string ?? "auto";
            string dec = (DecodeGpuCombo.SelectedItem as ComboBoxItem)?.Tag as string ?? "auto";
            RunInvoke("set_gpu_preferences", new { encodeGpu = enc, decodeGpu = dec }, onCompleted: ok =>
            {
                if (ok)
                {
                    _encodeGpuDirty = false;
                    _decodeGpuDirty = false;
                }
            });
        }

        /// <summary>
        /// Queries real-time discrete GPU metrics (temperature, VRAM, clock, load) from the peer.
        /// </summary>
        private async void QueryGpu_Click(object sender, RoutedEventArgs e)
        {
            var res = await Task.Run(() => CoreBridge.Invoke<GpuTelemetryModel>("get_gpu_telemetry"));
            if (_disposedForExit) return;
            if (res.Ok && res.Data != null)
            {
                var t = res.Data;
                GpuTelemetryText.Text = string.Format(
                    CultureInfo.InvariantCulture,
                    "{0}  •  {1}°C  •  GPU {2}%  •  VRAM {3}/{4} MB",
                    t.GpuName, t.TemperatureC, t.GpuUtilizationPercent, t.MemoryUsedMb, t.MemoryTotalMb);
                GpuTelemetryBox.Visibility = Visibility.Visible;
            }
            else
            {
                ShowToast(res.Error ?? "GPU telemetry unavailable", "error");
            }
        }

        /// <summary>
        /// Updates the peer edge placement ("left", "right", "top", "bottom") in the KVM layout draft.
        /// </summary>
        private void EdgeBtn_Click(object sender, RoutedEventArgs e)
        {
            if (_applyingStatus || _status == null) return;
            if (sender is Button btn && btn.Tag is string edge)
            {
                _kvmLayout.PeerEdge = edge;
                _kvmLayoutDirty = true;
                ApplyEdgeStylesAndSchematic(_status);
                SaveKvmLayoutInternal();
            }
        }

        /// <summary>
        /// Handles changes to KVM alignment offset and edge hop delay sliders, updating layout draft and text labels.
        /// </summary>
        private void KvmSlider_ValueChanged(object sender, Microsoft.UI.Xaml.Controls.Primitives.RangeBaseValueChangedEventArgs e)
        {
            if (_applyingStatus || _status == null || AlignmentValueText == null || HopDelayValueText == null) return;
            _kvmLayout.AlignmentOffset = (float)Math.Clamp(AlignmentSlider.Value, -0.5, 0.5);
            _kvmLayout.HopDelayMs = (uint)Math.Clamp(HopDelaySlider.Value, 0.0, 250.0);
            _kvmLayoutDirty = true;
            AlignmentValueText.Text = string.Format(CultureInfo.InvariantCulture, "{0:0}%", _kvmLayout.AlignmentOffset * 100f);
            HopDelayValueText.Text = _kvmLayout.HopDelayMs + " ms";
        }

        /// <summary>
        /// Updates boolean KVM preferences (dead corners, modifier translation, trackpad, ghost thumbnails, QoS clamping).
        /// </summary>
        private void KvmCheck_Changed(object sender, RoutedEventArgs e)
        {
            if (_applyingStatus || _status == null) return;
            _kvmLayout.DeadCorners = ChkDeadCorners.IsChecked == true;
            _kvmLayout.ModifierTranslation = ChkModifierTrans.IsChecked == true;
            _kvmLayout.PrecisionTouchpad = ChkTrackpad.IsChecked == true;
            _kvmLayout.GhostThumbnail = ChkGhostThumb.IsChecked == true;
            _kvmLayout.QosClamp = ChkQosClamp.IsChecked == true;
            _kvmLayoutDirty = true;
        }

        /// <summary>
        /// Handles selection of the fallback target folder for dropped files ("downloads", "desktop", "cache").
        /// </summary>
        private void DropFolderCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (_applyingStatus || _status == null) return;
            if (DropFolderCombo.SelectedItem is ComboBoxItem item && item.Tag is string folder)
            {
                _kvmLayout.DropFolder = folder;
                _kvmLayoutDirty = true;
            }
        }

        /// <summary>
        /// Handles click on the Save & Sync Layout button.
        /// </summary>
        private void SaveKvmLayout_Click(object sender, RoutedEventArgs e) => SaveKvmLayoutInternal();

        /// <summary>
        /// Synchronizes the locally modified KVM desk layout configuration with the native core.
        /// </summary>
        private void SaveKvmLayoutInternal()
        {
            _kvmLayout.UpdatedAtMs = (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            RunInvoke("set_kvm_layout", new { layout = _kvmLayout }, onCompleted: ok =>
            {
                if (ok)
                {
                    _kvmLayoutDirty = false;
                    ShowToast("KVM layout & drop preferences synced", "success");
                }
            });
        }

        /// <summary>
        /// Releases any active input capture locks held by the local or peer machine.
        /// </summary>
        private void ReleaseKvm_Click(object sender, RoutedEventArgs e) => RunInvoke("release_kvm_control");

        /// <summary>
        /// Requests remote clipboard item to be staged and pasted onto the local workstation.
        /// </summary>
        private void PasteRemote_Click(object sender, RoutedEventArgs e) => RunInvoke("paste_remote");

        /// <summary>
        /// Regenerates and rotates the local workstation's 6-digit SPAKE2 pairing PIN code.
        /// </summary>
        private void RegenPin_Click(object sender, RoutedEventArgs e) => RunInvoke("regenerate_pairing_pin");

        /// <summary>
        /// Validates and adds a manual peer IP address target for unadvertised or direct-cable peer connections.
        /// </summary>
        private void AddManualIp_Click(object sender, RoutedEventArgs e)
        {
            string ip = ManualIpInput.Text.Trim();
            if (string.IsNullOrEmpty(ip) || !IPAddress.TryParse(ip, out _))
            {
                ShowToast("Enter a valid IPv4 or IPv6 address", "warn");
                return;
            }
            RunInvoke("add_manual_peer_ip", new { ip }, onCompleted: ok =>
            {
                if (ok) ManualIpInput.Text = string.Empty;
            });
        }

        /// <summary>
        /// Triggers an active live throughput benchmark against the connected peer.
        /// </summary>
        private async void RunSpeedTest_Click(object sender, RoutedEventArgs e)
        {
            if (_status != null && !_status.FeatureFlags.Benchmark)
            {
                ShowToast("Live speed benchmark is disabled in feature flags", "warn");
                return;
            }
            _speedTestRunning = true;
            BtnSpeedTest.IsEnabled = false;
            BtnSpeedTest.Content = "Benchmarking...";
            try
            {
                var res = await Task.Run(() => CoreBridge.Invoke<SpeedTestResultModel>("run_speed_test"));
                if (_disposedForExit) return;
                if (res.Ok && res.Data != null)
                {
                    SpeedBenchmarkText.Text = string.Format(
                        CultureInfo.InvariantCulture,
                        "{0}  (Peak {1:0.00} Gbps, RTT {2:0.0} ms)",
                        res.Data.Summary, res.Data.MaxGbps, res.Data.LatencyMs);
                    SpeedBenchmarkText.Visibility = Visibility.Visible;
                    ShowToast("Live speed test finished", "success");
                    await RefreshStatusAsync();
                }
                else
                {
                    ShowToast(res.Error ?? "Speed test failed", "error");
                }
            }
            finally
            {
                _speedTestRunning = false;
                if (!_disposedForExit)
                {
                    BtnSpeedTest.Content = "Run Live Speed Test";
                    BtnSpeedTest.IsEnabled = _status?.FeatureFlags.Benchmark ?? true;
                }
            }
        }

        /// <summary>
        /// Flags the preferred storage share name input field as dirty when edited by the user.
        /// </summary>
        private void PreferredShareInput_TextChanged(object sender, TextChangedEventArgs e)
        {
            if (_applyingStatus || _status == null) return;
            _preferredShareDirty = true;
        }

        /// <summary>
        /// Dispatches the user-specified preferred remote SMB share name override to the native core.
        /// </summary>
        private void SetShare_Click(object sender, RoutedEventArgs e)
        {
            string trimmed = PreferredShareInput.Text.Trim();
            string? share = string.IsNullOrEmpty(trimmed) ? null : trimmed;
            RunInvoke("set_preferred_peer_share", new { share }, preserveNulls: true, onCompleted: ok =>
            {
                if (ok)
                {
                    _preferredShareDirty = false;
                }
            });
        }

        /// <summary>
        /// Prompts the user to select a local directory to share over SMB via native WinUI 3 FolderPicker.
        /// </summary>
        private async void ChooseFolder_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var picker = new Windows.Storage.Pickers.FolderPicker();
                picker.SuggestedStartLocation = Windows.Storage.Pickers.PickerLocationId.ComputerFolder;
                picker.FileTypeFilter.Add("*");
                IntPtr hwnd = WindowNative.GetWindowHandle(this);
                WinRT.Interop.InitializeWithWindow.Initialize(picker, hwnd);
                var folder = await picker.PickSingleFolderAsync();
                if (folder != null && !string.IsNullOrWhiteSpace(folder.Path))
                {
                    RunInvoke("set_local_shared_folder", new { folder = folder.Path });
                }
            }
            catch
            {
            }
        }

        /// <summary>
        /// Resets the user's custom shared folder preference back to default (Public directory).
        /// </summary>
        private void ResetFolder_Click(object sender, RoutedEventArgs e)
        {
            RunInvoke("set_local_shared_folder", new { folder = (string?)null }, preserveNulls: true);
        }

        /// <summary>
        /// Opens the currently mounted remote SMB storage directory in Windows File Explorer.
        /// </summary>
        private void OpenInExplorer_Click(object sender, RoutedEventArgs e)
        {
            RunInvoke("open_shared_storage");
        }

        /// <summary>
        /// Toggles mounting or unmounting of the peer's shared storage volume.
        /// </summary>
        private void ToggleMount_Click(object sender, RoutedEventArgs e)
        {
            bool mounted = _status?.StorageMounted == true;
            RunInvoke(mounted ? "unmount_shared_storage" : "mount_shared_storage");
        }

        /// <summary>
        /// Updates preview labels for True Tone CCT (Kelvin) and gamma compensation factor sliders.
        /// </summary>
        private void TrueToneSlider_ValueChanged(object sender, Microsoft.UI.Xaml.Controls.Primitives.RangeBaseValueChangedEventArgs e)
        {
            if (CctValueText == null || GammaValueText == null) return;
            CctValueText.Text = $"{(int)CctSlider.Value}K";
            GammaValueText.Text = string.Format(CultureInfo.InvariantCulture, "{0:0.00}x", GammaSlider.Value);
        }

        /// <summary>
        /// Dispatches True Tone manual calibration values (CCT and gamma) to the core.
        /// </summary>
        private void SyncCalibration_Click(object sender, RoutedEventArgs e)
        {
            RunInvoke("apply_truetone_calibration", new
            {
                cct = (int)CctSlider.Value,
                compFactor = (float)GammaSlider.Value
            });
        }

        /// <summary>
        /// Toggles the Apple Touch Bar telemetry HUD strip.
        /// </summary>
        private void ToggleTouchBar_Click(object sender, RoutedEventArgs e) => RunInvoke("toggle_touchbar_hud");

        /// <summary>
        /// Plays an authenticated spatial test chime over the low-latency UDP audio channel.
        /// </summary>
        private void PlayChime_Click(object sender, RoutedEventArgs e) => RunInvoke("play_spatial_chime");

        /// <summary>
        /// Toggles the Mac -> PC shared virtual camera streaming session.
        /// </summary>
        private void ToggleCamera_Click(object sender, RoutedEventArgs e) => RunInvoke("toggle_camera");

        /// <summary>
        /// Configures Integrator to launch automatically at Windows user logon via Task Scheduler.
        /// </summary>
        private void AutostartSwitch_Toggled(object sender, RoutedEventArgs e)
        {
            if (_applyingStatus || _status == null) return;
            if (_status.AutostartEnabled == SwitchAutostart.IsOn) return;
            RunInvoke("set_autostart", new { enabled = SwitchAutostart.IsOn });
        }

        /// <summary>
        /// Displays an ephemeral toast banner notification with colored indicator dot for 4 seconds.
        /// </summary>
        /// <param name="message">Notification body text.</param>
        /// <param name="level">Notification level ("info", "success", "warn", "error").</param>
        private void ShowToast(string message, string level)
        {
            ToastMessage.Text = message;
            Color dotColor = (level ?? "info").ToLowerInvariant() switch
            {
                "error" or "err" or "danger" => Color.FromArgb(255, 220, 53, 69),
                "warn" or "warning" => Color.FromArgb(255, 232, 158, 27),
                "success" or "ok" => Color.FromArgb(255, 32, 184, 90),
                _ => Color.FromArgb(255, 24, 180, 212)
            };
            ToastDot.Fill = new SolidColorBrush(dotColor);
            ToastBanner.Visibility = Visibility.Visible;

            _toastTimer.Stop();
            _toastTimer.Start();
        }

        /// <summary>
        /// Handles changes to the dynamic glass intensity slider, updating percentage text and card alphas.
        /// </summary>
        private void SliderGlassIntensity_ValueChanged(object sender, Microsoft.UI.Xaml.Controls.Primitives.RangeBaseValueChangedEventArgs e)
        {
            if (GlassIntensityLabel != null)
            {
                GlassIntensityLabel.Text = $"{(int)e.NewValue}%";
            }
            ApplyGlassIntensity(e.NewValue / 100.0);
        }

        /// <summary>
        /// Modulates the alpha channel of background fills and border strokes across all 13 card containers.
        /// </summary>
        /// <param name="intensity">Fractional intensity value (0.10 to 1.00).</param>
        private void ApplyGlassIntensity(double intensity)
        {
            byte alpha = (byte)Math.Clamp((int)(intensity * 255 * 0.12), 8, 70);
            byte borderAlpha = (byte)Math.Clamp((int)(intensity * 255 * 0.22), 15, 90);
            var cardBg = new SolidColorBrush(Windows.UI.Color.FromArgb(alpha, 128, 128, 128));
            var cardBorder = new SolidColorBrush(Windows.UI.Color.FromArgb(borderAlpha, 160, 160, 160));
            if (_allCards != null)
            {
                foreach (var card in _allCards)
                {
                    card.Background = cardBg;
                    card.BorderBrush = cardBorder;
                }
            }
        }
    }
}
