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
//    - Card 10B: Mac -> PC Shared Camera & Mic (Windows Virtual Camera driver + shared Mac microphone routing over TCP :58287).
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
//    - Form State Preservation: Dirty flags (`_kvmLayoutDirty`, `_encodeGpuDirty`, `_decodeGpuDirty`, `_preferredShareDirty`,
//      `_micGainDirty`) prevent periodic status polling updates from overwriting user inputs in-flight.
//    - Mutual Exclusion Guard: Extended Screen (Moonlight/Sunshine desktop streaming) and Universal Input KVM
//      (low-level input hooks + screen-edge cursor hopping) are guarded by an explicit confirmation dialog and
//      atomic backend flag switch so they never conflict over cursor capture or modifier key states.
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
        /// <summary>Debounce interval in milliseconds before dispatching microphone gain slider updates.</summary>
        private const int MicGainDebounceMs = 300;
        /// <summary>Minimum interval in seconds between background camera/microphone device enumeration queries.</summary>
        private const double DeviceListRefreshCooldownSeconds = 10.0;
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
        /// <summary>Debounce timer dispatching microphone gain updates after slider adjustments settle.</summary>
        private readonly DispatcherTimer _micGainDebounceTimer;
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
        /// <summary>Guard flag ensuring the automatic launch setup prompt is evaluated at most once per app launch.</summary>
        private bool _didShowLaunchSetupPrompt;
        /// <summary>Reentrancy guard preventing overlapping Setup Assistant ContentDialog instances.</summary>
        private bool _isSetupDialogOpen;
        /// <summary>Reentrancy guard preventing overlapping KVM/Extended Screen mutual-exclusion ContentDialog instances.</summary>
        private bool _isMutualExclusionDialogOpen;
        /// <summary>Reentrancy guard preventing overlapping quit confirmation or shutdown progress flows.</summary>
        private bool _isQuitFlowRunning;
        /// <summary>Guard suppressing SwitchConfirmQuit.Toggled during programmatic state initialization.</summary>
        private bool _syncingConfirmQuitSwitch;
        /// <summary>Guard flag preventing camera selection event during programmatic ComboBox population.</summary>
        private bool _populatingCameras;
        /// <summary>Atomic guard preventing overlapping background camera enumeration calls.</summary>
        private int _cameraRefreshInFlight;
        /// <summary>Timestamp of last camera enumeration query to throttle polling.</summary>
        private DateTime _lastCameraRefresh = DateTime.MinValue;
        /// <summary>Guard flag preventing microphone selection event during programmatic ComboBox population.</summary>
        private bool _populatingMics;
        /// <summary>Atomic guard preventing overlapping background microphone enumeration calls.</summary>
        private int _micRefreshInFlight;
        /// <summary>Timestamp of last microphone enumeration query to throttle polling.</summary>
        private DateTime _lastMicRefresh = DateTime.MinValue;
        /// <summary>Cached composite key of camera devices to avoid disrupting open ComboBox dropdowns.</summary>
        private string? _lastCameraListKey;
        /// <summary>Cached composite key of microphone devices to avoid disrupting open ComboBox dropdowns.</summary>
        private string? _lastMicListKey;
        /// <summary>True if user has modified the microphone gain slider without applying to the core.</summary>
        private bool _micGainDirty;

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
                CardDisplay, CardKvm, CardClipboard,
                CardDiscovery, CardSpeed, CardStorage, CardTrueTone,
                CardAudio, CardCamera, CardSystem, CardLogs
            };
            _navButtons = new[]
            {
                NavAllBtn, NavDisplayBtn, NavInputBtn, NavNetworkBtn, NavSystemBtn
            };

            ConfigureWindowChrome();
            UpdateNavStyles();
            RebuildCardsGrid(force: true);
            SyncConfirmQuitSwitch();

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

            _micGainDebounceTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(MicGainDebounceMs) };
            _micGainDebounceTimer.Tick += (_, _) =>
            {
                _micGainDebounceTimer.Stop();
                if (!_disposedForExit && _micGainDirty)
                {
                    DispatchMicGainSettings();
                }
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
        /// Restricted to <see cref="DllImportSearchPath.System32"/> to prevent DLL pre-loading attacks.
        /// </summary>
        /// <param name="hwnd">Window handle.</param>
        /// <returns>DPI value (e.g., 96 for 100%, 144 for 150%).</returns>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
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
                if (_isQuitFlowRunning || _disposedForExit) return;
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
            _micGainDebounceTimer.Stop();
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
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[Integrator] RefreshStatusAsync error: {ex.Message}");
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
                string fallbackHw = string.Equals(s.FormFactor, "laptop", StringComparison.OrdinalIgnoreCase)
                    ? "Windows Laptop"
                    : "Windows PC";
                string safeHw = string.IsNullOrWhiteSpace(s.HardwareModel) ? fallbackHw : s.HardwareModel;
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

                string mode = s.ActiveMode ?? "";
                bool isMacToPcActive = s.DisplayActive && mode.IndexOf("Mac -> PC", StringComparison.OrdinalIgnoreCase) >= 0;
                bool isPcToMacActive = s.DisplayActive && mode.IndexOf("PC -> Mac", StringComparison.OrdinalIgnoreCase) >= 0;

                BtnExtendMacToPc.Content = isMacToPcActive ? "Stop Extending" : "Extend Mac -> PC";
                if (isMacToPcActive)
                    BtnExtendMacToPc.Style = (Style)Application.Current.Resources["AccentButtonStyle"];
                else
                    BtnExtendMacToPc.ClearValue(FrameworkElement.StyleProperty);

                BtnExtendPcToMac.Content = isPcToMacActive ? "Stop Extending" : "Extend PC -> Mac";
                if (isPcToMacActive)
                    BtnExtendPcToMac.Style = (Style)Application.Current.Resources["AccentButtonStyle"];
                else
                    BtnExtendPcToMac.ClearValue(FrameworkElement.StyleProperty);
                EncodeGpuCombo.IsEnabled = f.Display;
                DecodeGpuCombo.IsEnabled = f.Display;
                BtnApplyGpu.IsEnabled = f.Display;
                BtnExtendMacToPc.IsEnabled = f.Display || f.InputKvm;
                BtnExtendPcToMac.IsEnabled = f.Display || f.InputKvm;
                string? gpuTip = f.Display ? null : "Extended Screen is disabled in feature flags.";
                string? displayTip = f.Display
                    ? null
                    : (f.InputKvm
                        ? "Universal Input KVM is active. Click to switch to Extended Screen."
                        : "Extended Screen is disabled in feature flags.");
                ToolTipService.SetToolTip(EncodeGpuCombo, gpuTip);
                ToolTipService.SetToolTip(DecodeGpuCombo, gpuTip);
                ToolTipService.SetToolTip(BtnApplyGpu, gpuTip);
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
                CheckAutoMountStorage.IsChecked = s.AutoMountStorage;
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

                // Card 8: True Tone (exact macOS status pill parity: never "Manual" when toggled ON)
                SwitchTrueTone.IsOn = f.Truetone;
                if (!f.Truetone)
                {
                    TrueTonePillText.Text = "Paused";
                    SetPillStyle(TrueTonePill, TrueTonePillDot, Color.FromArgb(255, 136, 136, 136));
                }
                else
                {
                    if (s.AmbientSupported && s.AmbientCct.HasValue && s.AmbientCct.Value >= 2500 && s.AmbientCct.Value <= 9000)
                    {
                        TrueTonePillText.Text = $"Auto • {s.AmbientLux ?? 0f:0} lux • {s.AmbientCct.Value}K";
                        if (CctSlider != null && CctValueText != null)
                        {
                            double targetVal = Math.Clamp((double)s.AmbientCct.Value, CctSlider.Minimum, CctSlider.Maximum);
                            if (Math.Abs(CctSlider.Value - targetVal) >= 50)
                            {
                                CctSlider.Value = targetVal;
                                CctValueText.Text = $"{(int)targetVal}K";
                            }
                        }
                    }
                    else
                    {
                        TrueTonePillText.Text = $"Active • {(int)(CctSlider?.Value ?? DefaultAmbientCctKelvin)}K";
                    }
                    SetPillStyle(TrueTonePill, TrueTonePillDot, Color.FromArgb(255, 232, 192, 27));
                }
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

                // Card 10B: Mac -> PC Shared Camera & Mic
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

                // Shared Microphone controls within Card 10B (parity with macOS SwiftUI: Share Mac Microphone
                // toggle remains usable whenever peer is linked; mute & gain controls follow MicEnabled state).
                if (SwitchCameraMic != null)
                {
                    SwitchCameraMic.IsOn = cam.MicEnabled;
                    SwitchCameraMic.IsEnabled = s.PeerConnected || cam.MicEnabled || f.Camera;
                }
                if (BtnToggleMicMute != null)
                {
                    BtnToggleMicMute.Content = cam.MicMuted ? "Mic Muted" : "Mute Mic";
                    BtnToggleMicMute.IsEnabled = cam.MicEnabled;
                    if (cam.MicEnabled && cam.MicMuted)
                    {
                        BtnToggleMicMute.Style = (Style)Application.Current.Resources["AccentButtonStyle"];
                    }
                    else
                    {
                        BtnToggleMicMute.ClearValue(FrameworkElement.StyleProperty);
                    }
                }
                if (MicSummaryText != null)
                {
                    if (!cam.MicPermissionGranted)
                    {
                        MicSummaryText.Text = "Microphone permission required on Mac.";
                    }
                    else if (!cam.MicEnabled)
                    {
                        MicSummaryText.Text = "Mac microphone sharing is paused.";
                    }
                    else
                    {
                        string micName = string.IsNullOrWhiteSpace(cam.MicDeviceName) ? "Mac Microphone" : cam.MicDeviceName;
                        string muteState = cam.MicMuted ? "Muted" : "Live";
                        int gainPct = (int)Math.Round(Math.Clamp(cam.MicGain, 0f, 2f) * 100f);
                        MicSummaryText.Text = string.Format(
                            CultureInfo.InvariantCulture,
                            "{0} • {1} • Gain {2}%",
                            micName, muteState, gainPct);
                    }
                }
                if (MicGainSlider != null && MicGainText != null)
                {
                    if (!_micGainDirty)
                    {
                        double clampedGainPct = Math.Clamp(
                            Math.Round(cam.MicGain * 100.0 / 5.0) * 5.0,
                            MicGainSlider.Minimum,
                            MicGainSlider.Maximum);
                        MicGainSlider.Value = clampedGainPct;
                        MicGainText.Text = $"{(int)clampedGainPct}%";
                    }
                    MicGainSlider.IsEnabled = cam.MicEnabled;
                }
                if (BtnApplyMicGain != null)
                {
                    BtnApplyMicGain.IsEnabled = cam.MicEnabled;
                }

                if (f.Camera)
                {
                    _ = RefreshCameraDevicesAsync();
                }
                else
                {
                    CameraSelectionPanel.Visibility = Visibility.Collapsed;
                }

                if (s.PeerConnected)
                {
                    _ = RefreshMicDevicesAsync();
                }
                else if (MicSelectionPanel != null)
                {
                    MicSelectionPanel.Visibility = Visibility.Collapsed;
                }

                // Card 11: Autostart
                SwitchAutostart.IsOn = s.AutostartEnabled;
                AutostartPillText.Text = s.AutostartEnabled ? "Launch at Login" : "Manual Launch";
                SetPillStyle(AutostartPill, AutostartPillDot, s.AutostartEnabled
                    ? Color.FromArgb(255, 32, 184, 90)
                    : Color.FromArgb(255, 136, 136, 136));

                // Setup & Permissions Header Badge + One-Time Launch Prompt
                bool setupNeedsAttention = s.SetupStatus?.NeedsAttention == true;
                if (SetupBtnDot != null)
                {
                    SetupBtnDot.Fill = new SolidColorBrush(setupNeedsAttention
                        ? Color.FromArgb(255, 232, 158, 27)
                        : Color.FromArgb(255, 32, 184, 90));
                }
                if (SetupBtnText != null)
                {
                    int missingCount = (s.SetupStatus?.MissingRequiredPermissions ?? 0)
                                     + (s.SetupStatus?.MissingRequiredDependencies ?? 0);
                    SetupBtnText.Text = setupNeedsAttention && missingCount > 0
                        ? $"Setup & Permissions ({missingCount})"
                        : "Setup & Permissions";
                }
                if (!_didShowLaunchSetupPrompt)
                {
                    _didShowLaunchSetupPrompt = true;
                    if (!UiPreferences.HasCompletedInitialSetup)
                    {
                        bool allAlreadyConfigured = UpdateSetupAssistantCardStatuses();
                        if (allAlreadyConfigured)
                        {
                            // All setup components are already installed (e.g. user updating the app)
                            UiPreferences.HasCompletedInitialSetup = true;
                        }
                        else if (!_isHiddenToTray)
                        {
                            SetupAssistantOverlay.Visibility = Visibility.Visible;
                        }
                    }
                }

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
            if (combined.Contains("amd") || combined.Contains("radeon") || combined.Contains("firepro"))
                return "amd";
            if (combined.Contains("intel") || combined.Contains("uhd") || combined.Contains("iris") || combined.Contains("arc"))
                return "intel";
            if (combined.Contains("qualcomm") || combined.Contains("adreno") || combined.Contains("snapdragon"))
                return "qualcomm";
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
            try
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
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[Integrator] RunInvoke('{method}') error: {ex.Message}");
            }
        }

        /// <summary>
        /// Handles click on the Refresh button in the top bar to query latest bridge status.
        /// </summary>
        private void RefreshBtn_Click(object sender, RoutedEventArgs e) => _ = RefreshStatusAsync();
        /// <summary>
        /// Opens the Setup, Drivers &amp; Permissions Assistant dialog when clicked from the top toolbar.
        /// </summary>
        private void SetupBtn_Click(object sender, RoutedEventArgs e) => _ = ShowSetupAssistantDialogAsync();
        /// <summary>
        /// Opens the local clipboard file staging and cache folder in Windows File Explorer.
        /// </summary>
        private void OpenCacheBtn_Click(object sender, RoutedEventArgs e) => RunInvoke("open_cache_folder", refreshAfter: false);
        /// <summary>
        /// Hides the main dashboard window to the Windows notification tray.
        /// </summary>
        private void HideWindowBtn_Click(object sender, RoutedEventArgs e) => HideToTray();

        /// <summary>
        /// Triggers the quit confirmation dialog and visual shutdown sequence from the top toolbar.
        /// </summary>
        private void QuitBtn_Click(object sender, RoutedEventArgs e) => _ = RequestQuitAsync();

        /// <summary>
        /// Handles Ctrl+Q keyboard shortcut to initiate the quit confirmation and shutdown flow.
        /// </summary>
        private void QuitAccelerator_Invoked(
            Microsoft.UI.Xaml.Input.KeyboardAccelerator sender,
            Microsoft.UI.Xaml.Input.KeyboardAcceleratorInvokedEventArgs args)
        {
            args.Handled = true;
            _ = RequestQuitAsync();
        }

        /// <summary>
        /// Persists user preference for showing the quit confirmation dialog before exiting.
        /// </summary>
        private void ConfirmQuitSwitch_Toggled(object sender, RoutedEventArgs e)
        {
            if (_syncingConfirmQuitSwitch) return;
            UiPreferences.SkipQuitConfirmation = !SwitchConfirmQuit.IsOn;
        }

        /// <summary>
        /// Synchronizes the "Ask for Confirmation Before Quitting" switch with persisted UI preferences.
        /// </summary>
        private void SyncConfirmQuitSwitch()
        {
            _syncingConfirmQuitSwitch = true;
            try
            {
                SwitchConfirmQuit.IsOn = !UiPreferences.SkipQuitConfirmation;
            }
            finally
            {
                _syncingConfirmQuitSwitch = false;
            }
        }

        /// <summary>
        /// Handles toggle switches for subsystem feature flags and dispatches set_feature_flag RPCs.
        /// Enforces mutual exclusion between Extended Screen ("display") and Universal Input KVM ("input_kvm")
        /// by presenting an explanatory confirmation dialog before switching active subsystems.
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

                // Mutual exclusion check: Extended Screen ("display") vs Universal Input KVM ("input_kvm").
                if (enabled && feature == "display" && f.InputKvm)
                {
                    _applyingStatus = true;
                    try
                    {
                        ts.IsOn = false;
                    }
                    finally
                    {
                        _applyingStatus = false;
                    }
                    _ = ShowDisplayKvmMutualExclusionDialogAsync(targetFeature: "display", postSwitchAction: null);
                    return;
                }
                if (enabled && feature == "input_kvm" && (f.Display || _status.DisplayActive))
                {
                    _applyingStatus = true;
                    try
                    {
                        ts.IsOn = false;
                    }
                    finally
                    {
                        _applyingStatus = false;
                    }
                    _ = ShowDisplayKvmMutualExclusionDialogAsync(targetFeature: "input_kvm", postSwitchAction: null);
                    return;
                }

                RunInvoke("set_feature_flag", new { feature, enabled });
            }
        }

        /// <summary>
        /// Presents a modal WinUI 3 ContentDialog explaining why Extended Screen and Universal Input KVM
        /// cannot run simultaneously, and upon confirmation switches atomically to the requested feature.
        /// </summary>
        /// <param name="targetFeature">Target feature flag to enable ("display" or "input_kvm").</param>
        /// <param name="postSwitchAction">Optional RPC method (e.g., "toggle_mac_to_pc") to invoke after switching.</param>
        private async Task ShowDisplayKvmMutualExclusionDialogAsync(string targetFeature, string? postSwitchAction)
        {
            if (_isMutualExclusionDialogOpen || _isSetupDialogOpen || _isQuitFlowRunning || _disposedForExit || RootGrid?.XamlRoot == null)
            {
                return;
            }
            _isMutualExclusionDialogOpen = true;
            try
            {
                bool switchingToDisplay = string.Equals(targetFeature, "display", StringComparison.OrdinalIgnoreCase);
                string primaryLabel = switchingToDisplay
                    ? "Switch to Extended Screen"
                    : "Switch to Universal Input KVM";
                string consequenceLine = switchingToDisplay
                    ? "Switching to Extended Screen will automatically disable Universal Input KVM and release its input hooks."
                    : "Switching to Universal Input KVM will automatically disable Extended Screen and stop any active display stream.";

                var dlg = new ContentDialog
                {
                    Title = "Extended Screen & Universal Input KVM Cannot Run Together",
                    Content = new TextBlock
                    {
                        Text = "Extended Screen streams your desktop over Moonlight/Sunshine, which captures mouse and keyboard input directly inside the stream window. " +
                               "Running Universal Input KVM's low-level input hooks and screen-edge cursor hopping at the same time causes cursor capture conflicts, stuck modifier keys, or phantom screen hops.\n\n" +
                               "Only one of these features can be active at a time. " + consequenceLine,
                        FontSize = 13,
                        TextWrapping = TextWrapping.Wrap,
                        MaxWidth = 440
                    },
                    PrimaryButtonText = primaryLabel,
                    CloseButtonText = "Cancel",
                    DefaultButton = ContentDialogButton.Primary,
                    XamlRoot = RootGrid.XamlRoot
                };

                ContentDialogResult result = await dlg.ShowAsync();
                if (result == ContentDialogResult.Primary && !_disposedForExit)
                {
                    RunInvoke(
                        "set_feature_flag",
                        new { feature = targetFeature, enabled = true },
                        refreshAfter: string.IsNullOrEmpty(postSwitchAction),
                        onCompleted: ok =>
                        {
                            if (ok && !string.IsNullOrEmpty(postSwitchAction))
                            {
                                RunInvoke(postSwitchAction!);
                            }
                            else if (!ok && !string.IsNullOrEmpty(postSwitchAction))
                            {
                                _ = RefreshStatusAsync();
                            }
                        });
                }
            }
            catch
            {
                // Suppress dialog presentation race if another modal is opening concurrently.
            }
            finally
            {
                _isMutualExclusionDialogOpen = false;
            }
        }

        /// <summary>
        /// Initiates or toggles extended screen display streaming from Mac to Windows PC.
        /// Prompts for mutual-exclusion confirmation if Universal Input KVM is currently active.
        /// </summary>
        private void ExtendMacToPc_Click(object sender, RoutedEventArgs e)
        {
            bool isMacToPcActive = _status != null && _status.DisplayActive &&
                (_status.ActiveMode?.IndexOf("Mac -> PC", StringComparison.OrdinalIgnoreCase) >= 0);
            if (!isMacToPcActive && _status?.FeatureFlags.InputKvm == true)
            {
                _ = ShowDisplayKvmMutualExclusionDialogAsync(targetFeature: "display", postSwitchAction: "toggle_mac_to_pc");
                return;
            }

            if (BtnExtendMacToPc != null) BtnExtendMacToPc.IsEnabled = false;
            RunInvoke("toggle_mac_to_pc", onCompleted: _ =>
            {
                if (BtnExtendMacToPc != null) BtnExtendMacToPc.IsEnabled = true;
            });
        }

        /// <summary>
        /// Initiates or toggles extended screen display streaming from Windows PC to Mac.
        /// Prompts for mutual-exclusion confirmation if Universal Input KVM is currently active.
        /// </summary>
        private void ExtendPcToMac_Click(object sender, RoutedEventArgs e)
        {
            bool isPcToMacActive = _status != null && _status.DisplayActive &&
                (_status.ActiveMode?.IndexOf("PC -> Mac", StringComparison.OrdinalIgnoreCase) >= 0);
            if (!isPcToMacActive && _status?.FeatureFlags.InputKvm == true)
            {
                _ = ShowDisplayKvmMutualExclusionDialogAsync(targetFeature: "display", postSwitchAction: "toggle_pc_to_mac");
                return;
            }

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
        /// Queries real-time discrete GPU metrics (temperature, VRAM, clock, load) from the peer
        /// and enumerates all physical GPUs installed in the local system.
        /// </summary>
        private async void QueryGpu_Click(object sender, RoutedEventArgs e)
        {
            var res = await Task.Run(() => CoreBridge.Invoke<GpuTelemetryModel>("get_gpu_telemetry"));
            if (_disposedForExit) return;

            var gpus = _status?.LocalGpus ?? new List<GpuDeviceInfo>();
            var lines = new List<string>();

            if (res.Ok && res.Data != null)
            {
                var t = res.Data;
                lines.Add(string.Format(
                    CultureInfo.InvariantCulture,
                    "Active Telemetry: {0} • {1}°C • GPU {2}% • VRAM {3}/{4} MB",
                    t.GpuName, t.TemperatureC, t.GpuUtilizationPercent, t.MemoryUsedMb, t.MemoryTotalMb));

                var allGpus = t.AllGpus != null && t.AllGpus.Count > 0
                    ? t.AllGpus
                    : gpus.Select(g => g.Name).Distinct().ToList();
                if (allGpus.Count > 0)
                {
                    lines.Add("Detected GPUs: " + string.Join(" | ", allGpus));
                }
            }
            else if (gpus.Count > 0)
            {
                var names = gpus.Select(g => g.Name).Distinct();
                lines.Add("Detected GPUs: " + string.Join(" | ", names));
            }
            else if (!res.Ok || res.Data == null)
            {
                lines.Add("No discrete GPU telemetry available");
            }

            GpuTelemetryText.Text = string.Join("\n", lines);
            GpuTelemetryBox.Visibility = Visibility.Visible;
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

        /// <summary>Maximum character capacity for a standard Win32 MAX_PATH buffer.</summary>
        private const int MaxPathChars = 260;

        /// <summary>Byte capacity for a UTF-16 Wide MAX_PATH display buffer (260 * 2 bytes).</summary>
        private const int MaxPathWideBytes = MaxPathChars * 2;

        /// <summary>SHBrowseForFolderW flag restricting selection to file system directories (`BIF_RETURNONLYFSDIRS`).</summary>
        private const uint BifReturnOnlyFsDirs = 0x00000001;

        /// <summary>SHBrowseForFolderW flag enabling the resizable modern folder dialog (`BIF_NEWDIALOGSTYLE`).</summary>
        private const uint BifNewDialogStyle = 0x00000040;

        /// <summary>
        /// Win32 `BROWSEINFOW` structure configuring the `SHBrowseForFolderW` shell folder picker dialog.
        /// Works reliably under both standard user tokens and elevated Administrator (`RunLevel Highest`) sessions.
        /// </summary>
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct BROWSEINFOW
        {
            /// <summary>Handle to the owner window for the modal browse dialog (`HWND`).</summary>
            public IntPtr hwndOwner;
            /// <summary>Root `ITEMIDLIST` pointer (`IntPtr.Zero` starts at the Desktop root namespace).</summary>
            public IntPtr pidlRoot;
            /// <summary>Unmanaged buffer (`MAX_PATH` UTF-16 chars) receiving the display name of the selected folder.</summary>
            public IntPtr pszDisplayName;
            /// <summary>Instructional title string displayed above the folder tree view.</summary>
            [MarshalAs(UnmanagedType.LPWStr)]
            public string lpszTitle;
            /// <summary>Bitmask of `BIF_*` option flags controlling folder filtering and dialog layout.</summary>
            public uint ulFlags;
            /// <summary>Optional browse callback procedure pointer (`IntPtr.Zero` when unused).</summary>
            public IntPtr lpfn;
            /// <summary>Application-defined parameter passed to `lpfn` (`IntPtr.Zero` when unused).</summary>
            public IntPtr lParam;
            /// <summary>Output system image list index associated with the selected folder.</summary>
            public int iImage;
        }

        /// <summary>
        /// Displays a modal Win32 Shell folder browser dialog and returns an `ITEMIDLIST` pointer (`PIDL`).
        /// </summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("shell32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern IntPtr SHBrowseForFolderW(ref BROWSEINFOW lpbi);

        /// <summary>
        /// Converts a Shell `ITEMIDLIST` pointer (`PIDL`) into a canonical UTF-16 file system path.
        /// </summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("shell32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SHGetPathFromIDListW(IntPtr pidl, [Out] char[] pszPath);

        /// <summary>
        /// Frees a block of COM task memory allocated by Shell APIs such as `SHBrowseForFolderW`.
        /// </summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("ole32.dll", ExactSpelling = true)]
        private static extern void CoTaskMemFree(IntPtr pv);

        /// <summary>
        /// Prompts the user to select a local directory to share over SMB.
        /// Uses Win32 SHBrowseForFolderW (BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE) first because
        /// WinRT FolderPicker fails with E_ACCESSDENIED when running elevated as Administrator.
        /// </summary>
        private async void ChooseFolder_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                IntPtr hwnd = WindowNative.GetWindowHandle(this);
                IntPtr displayBuf = Marshal.AllocHGlobal(MaxPathWideBytes);
                IntPtr pidl = IntPtr.Zero;
                try
                {
                    var bi = new BROWSEINFOW
                    {
                        hwndOwner = hwnd,
                        pidlRoot = IntPtr.Zero,
                        pszDisplayName = displayBuf,
                        lpszTitle = "Select a local folder to share with your paired Mac over SMB:",
                        ulFlags = BifReturnOnlyFsDirs | BifNewDialogStyle,
                        lpfn = IntPtr.Zero,
                        lParam = IntPtr.Zero,
                        iImage = 0
                    };
                    pidl = SHBrowseForFolderW(ref bi);
                    if (pidl != IntPtr.Zero)
                    {
                        char[] pathChars = new char[MaxPathChars];
                        if (SHGetPathFromIDListW(pidl, pathChars))
                        {
                            string selectedPath = new string(pathChars).TrimEnd('\0').Trim();
                            if (!string.IsNullOrWhiteSpace(selectedPath))
                            {
                                LocalSharedFolderInput.Text = selectedPath;
                                RunInvoke("set_local_shared_folder", new { folder = selectedPath });
                                return;
                            }
                        }
                    }
                    else
                    {
                        return;
                    }
                }
                finally
                {
                    if (pidl != IntPtr.Zero) CoTaskMemFree(pidl);
                    if (displayBuf != IntPtr.Zero) Marshal.FreeHGlobal(displayBuf);
                }

                // Fallback to WinRT FolderPicker if non-elevated and Win32 dialog returned empty
                var picker = new Windows.Storage.Pickers.FolderPicker();
                picker.SuggestedStartLocation = Windows.Storage.Pickers.PickerLocationId.ComputerFolder;
                picker.FileTypeFilter.Add("*");
                WinRT.Interop.InitializeWithWindow.Initialize(picker, hwnd);
                var folder = await picker.PickSingleFolderAsync();
                if (folder != null && !string.IsNullOrWhiteSpace(folder.Path))
                {
                    LocalSharedFolderInput.Text = folder.Path;
                    RunInvoke("set_local_shared_folder", new { folder = folder.Path });
                }
            }
            catch (Exception ex)
            {
                ShowToast("Folder selection failed: " + ex.Message, "error");
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
        /// Updates the auto-mount preference for shared storage when peer is detected.
        /// </summary>
        private void CheckAutoMountStorage_Click(object sender, RoutedEventArgs e)
        {
            bool enabled = CheckAutoMountStorage.IsChecked ?? false;
            RunInvoke("set_auto_mount_storage", new { enabled });
        }

        /// <summary>
        /// Updates preview labels for True Tone CCT (Kelvin) and gamma compensation factor sliders,
        /// and refreshes the active True Tone status pill when operating in manual CCT mode.
        /// </summary>
        private void TrueToneSlider_ValueChanged(object sender, Microsoft.UI.Xaml.Controls.Primitives.RangeBaseValueChangedEventArgs e)
        {
            if (CctValueText == null || GammaValueText == null) return;
            int cctK = (int)CctSlider.Value;
            CctValueText.Text = $"{cctK}K";
            GammaValueText.Text = string.Format(CultureInfo.InvariantCulture, "{0:0.00}x", GammaSlider.Value);
            if (_status?.FeatureFlags.Truetone == true &&
                !(_status.AmbientSupported && _status.AmbientCct.HasValue && _status.AmbientCct.Value >= 2500 && _status.AmbientCct.Value <= 9000) &&
                TrueTonePillText != null)
            {
                TrueTonePillText.Text = $"Active • {cctK}K";
            }
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
        private void ToggleCamera_Click(object sender, RoutedEventArgs e)
        {
            RunInvoke("toggle_camera", null, true, false, ok =>
            {
                _ = RefreshCameraDevicesAsync(true);
                _ = RefreshMicDevicesAsync(true);
            });
        }

        /// <summary>
        /// Queries the paired Mac for connected camera devices.
        /// Shows the camera selection dropdown strictly when 2 or more cameras are connected.
        /// Caches device lists via <see cref="_lastCameraListKey"/> to avoid dismissing an open dropdown.
        /// </summary>
        private async Task RefreshCameraDevicesAsync(bool force = false)
        {
            if (!force && (DateTime.UtcNow - _lastCameraRefresh).TotalSeconds < DeviceListRefreshCooldownSeconds)
            {
                return;
            }
            if (System.Threading.Interlocked.CompareExchange(ref _cameraRefreshInFlight, 1, 0) != 0)
            {
                return;
            }

            try
            {
                _lastCameraRefresh = DateTime.UtcNow;
                var res = await Task.Run(() => CoreBridge.Invoke<List<CameraDeviceModel>>("list_cameras"));
                if (_disposedForExit) return;

                var cameras = res.Data;
                if (!res.Ok || cameras == null || cameras.Count < 2)
                {
                    _lastCameraListKey = null;
                    DispatcherQueue.TryEnqueue(() =>
                    {
                        if (CameraSelectionPanel != null)
                        {
                            CameraSelectionPanel.Visibility = Visibility.Collapsed;
                        }
                    });
                    return;
                }

                string listKey = string.Join("|", cameras.Select(c => $"{c.Id}:{c.Name}:{c.IsActive}"));
                DispatcherQueue.TryEnqueue(() =>
                {
                    if (_disposedForExit || CameraSelectionCombo == null || CameraSelectionPanel == null) return;
                    if (_lastCameraListKey == listKey && CameraSelectionPanel.Visibility == Visibility.Visible)
                    {
                        return;
                    }
                    _lastCameraListKey = listKey;
                    _populatingCameras = true;
                    try
                    {
                        CameraSelectionCombo.Items.Clear();
                        int selectedIndex = 0;
                        for (int i = 0; i < cameras.Count; i++)
                        {
                            var item = new ComboBoxItem
                            {
                                Content = cameras[i].Name,
                                Tag = cameras[i].Id
                            };
                            CameraSelectionCombo.Items.Add(item);
                            if (cameras[i].IsActive)
                            {
                                selectedIndex = i;
                            }
                        }
                        CameraSelectionCombo.SelectedIndex = selectedIndex;
                        CameraSelectionPanel.Visibility = Visibility.Visible;
                    }
                    finally
                    {
                        _populatingCameras = false;
                    }
                });
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[Integrator] Failed to refresh cameras: {ex.Message}");
            }
            finally
            {
                System.Threading.Interlocked.Exchange(ref _cameraRefreshInFlight, 0);
            }
        }

        /// <summary>
        /// Handles camera selection change from the dropdown, dispatching RPC to the paired Mac.
        /// </summary>
        private void CameraSelectionCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (_populatingCameras || _applyingStatus) return;
            if (CameraSelectionCombo?.SelectedItem is ComboBoxItem item && item.Tag is string devId)
            {
                RunInvoke("select_camera", new { device_id = devId });
            }
        }

        /// <summary>
        /// Queries the paired Mac for available microphone audio input devices via the "list_mics" RPC endpoint.
        /// Populates the microphone source selection dropdown safely under the _populatingMics reentrancy guard,
        /// caching the list key to avoid disrupting open dropdown menus on 10-second background refreshes.
        /// </summary>
        /// <param name="force">True to bypass the 10-second polling throttle window.</param>
        private async Task RefreshMicDevicesAsync(bool force = false)
        {
            if (!force && (DateTime.UtcNow - _lastMicRefresh).TotalSeconds < DeviceListRefreshCooldownSeconds)
            {
                return;
            }
            if (System.Threading.Interlocked.CompareExchange(ref _micRefreshInFlight, 1, 0) != 0)
            {
                return;
            }

            try
            {
                _lastMicRefresh = DateTime.UtcNow;
                var res = await Task.Run(() => CoreBridge.Invoke<List<MicDeviceModel>>("list_mics"));
                if (_disposedForExit) return;

                var mics = res.Data;
                if (!res.Ok || mics == null || mics.Count == 0)
                {
                    _lastMicListKey = null;
                    DispatcherQueue.TryEnqueue(() =>
                    {
                        if (MicSelectionPanel != null)
                        {
                            MicSelectionPanel.Visibility = Visibility.Collapsed;
                        }
                    });
                    return;
                }

                string activeMicName = _status?.CameraStatus.MicDeviceName ?? string.Empty;
                string listKey = string.Join("|", mics.Select(m => $"{m.Id}:{m.Name}:{m.IsDefault}")) + "##" + activeMicName;
                DispatcherQueue.TryEnqueue(() =>
                {
                    if (_disposedForExit || MicSelectionCombo == null || MicSelectionPanel == null) return;
                    if (_lastMicListKey == listKey && MicSelectionPanel.Visibility == Visibility.Visible)
                    {
                        return;
                    }
                    _lastMicListKey = listKey;
                    _populatingMics = true;
                    try
                    {
                        MicSelectionCombo.Items.Clear();
                        int selectedIndex = 0;
                        bool matchedByName = false;
                        for (int i = 0; i < mics.Count; i++)
                        {
                            var item = new ComboBoxItem
                            {
                                Content = mics[i].Name,
                                Tag = mics[i].Id
                            };
                            MicSelectionCombo.Items.Add(item);
                            if (!string.IsNullOrWhiteSpace(activeMicName) &&
                                string.Equals(mics[i].Name, activeMicName, StringComparison.OrdinalIgnoreCase))
                            {
                                selectedIndex = i;
                                matchedByName = true;
                            }
                            else if (!matchedByName && mics[i].IsDefault)
                            {
                                selectedIndex = i;
                            }
                        }
                        MicSelectionCombo.SelectedIndex = selectedIndex;
                        MicSelectionPanel.Visibility = Visibility.Visible;
                    }
                    finally
                    {
                        _populatingMics = false;
                    }
                });
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[Integrator] Failed to refresh microphones: {ex.Message}");
            }
            finally
            {
                System.Threading.Interlocked.Exchange(ref _micRefreshInFlight, 0);
            }
        }

        /// <summary>
        /// Handles microphone input device selection changes from the dropdown, dispatching "select_mic" to the core.
        /// </summary>
        private void MicSelectionCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (_populatingMics || _applyingStatus) return;
            if (MicSelectionCombo?.SelectedItem is ComboBoxItem item && item.Tag is string deviceId)
            {
                RunInvoke("select_mic", new { deviceId });
            }
        }

        /// <summary>
        /// Handles toggling of the "Share Mac Microphone" switch inside the Shared Camera &amp; Mic card.
        /// Dispatches updated microphone settings (enabled, muted, gain) via "set_mic_settings".
        /// </summary>
        private void CameraMicSwitch_Toggled(object sender, RoutedEventArgs e)
        {
            if (_applyingStatus || _status == null) return;
            bool enabled = SwitchCameraMic.IsOn;
            if (_status.CameraStatus.MicEnabled == enabled) return;
            _micGainDebounceTimer.Stop();
            bool muted = _status.CameraStatus.MicMuted;
            float gain = (float)Math.Clamp((MicGainSlider?.Value ?? 100.0) / 100.0, 0.0, 2.0);
            RunInvoke("set_mic_settings", new { enabled, muted, gain }, onCompleted: ok =>
            {
                if (ok)
                {
                    _micGainDirty = false;
                    _ = RefreshMicDevicesAsync(true);
                }
            });
        }

        /// <summary>
        /// Toggles the mute state of the shared Mac microphone stream via "set_mic_settings".
        /// </summary>
        private void ToggleMicMute_Click(object sender, RoutedEventArgs e)
        {
            if (_applyingStatus || _status == null) return;
            _micGainDebounceTimer.Stop();
            bool enabled = SwitchCameraMic?.IsOn ?? _status.CameraStatus.MicEnabled;
            bool muted = !_status.CameraStatus.MicMuted;
            float gain = (float)Math.Clamp((MicGainSlider?.Value ?? 100.0) / 100.0, 0.0, 2.0);
            RunInvoke("set_mic_settings", new { enabled, muted, gain }, onCompleted: ok =>
            {
                if (ok) _micGainDirty = false;
            });
        }

        /// <summary>
        /// Updates the microphone gain percentage preview label, marks the gain slider dirty while adjusted
        /// by the user, and arms the 300ms debounce timer to synchronize gain changes smoothly.
        /// </summary>
        private void MicGainSlider_ValueChanged(object sender, Microsoft.UI.Xaml.Controls.Primitives.RangeBaseValueChangedEventArgs e)
        {
            if (MicGainText == null) return;
            MicGainText.Text = $"{(int)Math.Round(MicGainSlider.Value)}%";
            if (_applyingStatus || _status == null) return;
            _micGainDirty = true;
            _micGainDebounceTimer.Stop();
            _micGainDebounceTimer.Start();
        }

        /// <summary>
        /// Immediately dispatches the user-configured microphone gain percentage (cancelling any pending debounce).
        /// </summary>
        private void ApplyMicGain_Click(object sender, RoutedEventArgs e)
        {
            _micGainDebounceTimer.Stop();
            DispatchMicGainSettings();
        }

        /// <summary>
        /// Serializes and sends the current microphone enabled, muted, and linear gain multiplier
        /// (<c>0.0</c> to <c>2.0</c>) settings to the core via <c>"set_mic_settings"</c>.
        /// </summary>
        private void DispatchMicGainSettings()
        {
            if (_status == null) return;
            bool enabled = SwitchCameraMic?.IsOn ?? _status.CameraStatus.MicEnabled;
            bool muted = _status.CameraStatus.MicMuted;
            float gain = (float)Math.Clamp((MicGainSlider?.Value ?? 100.0) / 100.0, 0.0, 2.0);
            RunInvoke("set_mic_settings", new { enabled, muted, gain }, onCompleted: ok =>
            {
                if (ok) _micGainDirty = false;
            });
        }

        /// <summary>
        /// Initiates a live Touch ID Secure Enclave biometric challenge to the paired Mac over TransportSessionV2.
        /// </summary>
        private void VerifyTouchId_Click(object sender, RoutedEventArgs e)
        {
            ShowToast("Touch ID prompt sent to your paired Mac — place your finger on the Mac Touch ID sensor...", "info");
            RunInvoke("verify_touchid");
        }

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

        // MARK: - Setup Assistant First-Launch Wizard Event Handlers

        /// <summary>
        /// Opens the full-window Setup Assistant wizard overlay from the left navigation sidebar
        /// and refreshes live component installation statuses.
        /// </summary>
        private void NavSetupBtn_Click(object sender, RoutedEventArgs e)
        {
            SetupAssistantOverlay.Visibility = Visibility.Visible;
            UpdateSetupAssistantCardStatuses();
        }

        /// <summary>
        /// Dismisses the Setup Assistant wizard overlay without modifying persisted completion preferences.
        /// </summary>
        private void SetupAssistantClose_Click(object sender, RoutedEventArgs e)
        {
            SetupAssistantOverlay.Visibility = Visibility.Collapsed;
        }

        /// <summary>
        /// Completes the Setup Assistant wizard flow, persists the "Don't show automatically on launch" preference
        /// if checked, and reveals the primary dashboard workspace.
        /// </summary>
        private void SetupAssistantDone_Click(object sender, RoutedEventArgs e)
        {
            if (SetupDontShowAgainCheck.IsChecked == true)
            {
                UiPreferences.HasCompletedInitialSetup = true;
            }
            SetupAssistantOverlay.Visibility = Visibility.Collapsed;
            ShowToast("Setup Assistant completed! Welcome to Integrator.", "success");
        }

        /// <summary>
        /// Triggers 1-click background installation of Sunshine and Moonlight streaming dependencies via WinGet.
        /// </summary>
        private async void SetupInstallStreamingBtn_Click(object sender, RoutedEventArgs e)
        {
            SetupInstallStreamingBtn.IsEnabled = false;
            SetupDisplayStatusText.Text = "Status: Installing Sunshine & Moonlight via WinGet…";
            var r1 = await Task.Run(() => CoreBridge.Invoke<string>("install_dependency", new { id = "sunshine" }));
            var r2 = await Task.Run(() => CoreBridge.Invoke<string>("install_dependency", new { id = "moonlight" }));
            if (_disposedForExit) return;
            if (!r1.Ok && !r2.Ok)
            {
                SetupDisplayStatusText.Text = $"Status: WinGet launch failed ({r1.Error ?? r2.Error ?? "unknown error"}).";
                ShowToast(r1.Error ?? r2.Error ?? "Failed to launch streaming tools installer.", "error");
            }
            else
            {
                SetupDisplayStatusText.Text = "Status: WinGet installer launched in background. Approve prompts if shown.";
                ShowToast("Started Sunshine & Moonlight automated installation.", "info");
            }
            SetupInstallStreamingBtn.IsEnabled = true;
        }

        /// <summary>
        /// Registers Integrator's COM out-of-process WebAuthn Passkey Authenticator plugin with Windows 11
        /// so websites can authenticate passkeys using the paired Mac's Touch ID sensor.
        /// </summary>
        private async void SetupEnablePasskeyBtn_Click(object sender, RoutedEventArgs e)
        {
            SetupEnablePasskeyBtn.IsEnabled = false;
            SetupPasskeyStatusText.Text = "Status: Registering Integrator Touch ID Passkey Host…";
            bool ok = false;
            await Task.Run(() =>
            {
                try
                {
                    PasskeyAuthenticatorPlugin.Initialize();
                    ok = true;
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"[SetupPasskey] Failed: {ex}");
                }
            });
            if (_disposedForExit) return;
            if (ok)
            {
                SetupPasskeyStatusText.Text = "Status: Active! Ready to authenticate in Chrome & Edge.";
                ShowToast("Passkeys ready: choose 'Integrator (Mac Touch ID)' on websites.", "success");
            }
            else
            {
                SetupPasskeyStatusText.Text = "Status: Registration failed. Check system logs.";
                ShowToast("Failed to register Passkey host.", "error");
            }
            SetupEnablePasskeyBtn.IsEnabled = true;
        }

        /// <summary>
        /// Triggers 1-click guided configuration of the Apple USB-C NCM direct link driver and Windows SMB file server.
        /// </summary>
        private async void SetupEnableUsbNcmBtn_Click(object sender, RoutedEventArgs e)
        {
            SetupEnableUsbNcmBtn.IsEnabled = false;
            SetupUsbNcmStatusText.Text = "Status: Setting up USB-C NCM & SMB server…";
            var r1 = await Task.Run(() => CoreBridge.Invoke<string>("install_dependency", new { id = "usb_ncm" }));
            var r2 = await Task.Run(() => CoreBridge.Invoke<string>("request_permission", new { id = "smb_server" }));
            if (_disposedForExit) return;
            if (!r1.Ok && !r2.Ok)
            {
                SetupUsbNcmStatusText.Text = $"Status: Setup failed ({r1.Error ?? r2.Error ?? "unknown error"}).";
                ShowToast(r1.Error ?? r2.Error ?? "Failed to configure USB-C NCM & SMB.", "error");
            }
            else
            {
                SetupUsbNcmStatusText.Text = "Status: USB-C NCM bridge configured. SMB server ready.";
                ShowToast("USB-C NCM & SMB sharing configured.", "success");
            }
            SetupEnableUsbNcmBtn.IsEnabled = true;
        }

        /// <summary>
        /// Evaluates current setup health and Passkey registration status to update the visual indicators
        /// and action buttons on all Setup Assistant wizard cards.
        /// </summary>
        /// <returns>True if all setup dependencies, passkey plugin, and permissions are already configured.</returns>
        private bool UpdateSetupAssistantCardStatuses()
        {
            bool allConfigured = true;

            if (_status?.SetupStatus != null)
            {
                var s = _status.SetupStatus;

                // 1. Display Extension (Sunshine & Moonlight)
                var sun = s.Dependencies.FirstOrDefault(d => d.Id == "sunshine");
                var moon = s.Dependencies.FirstOrDefault(d => d.Id == "moonlight");
                bool sunOk = sun?.Installed == true;
                bool moonOk = moon?.Installed == true;

                if (sunOk && moonOk)
                {
                    SetupDisplayStatusText.Text = "Status: Installed and configured (Ready)";
                    SetupDisplayStatusText.Foreground = new SolidColorBrush(Windows.UI.Color.FromArgb(255, 32, 184, 90));
                    SetupInstallStreamingBtn.Content = "Configured ✓";
                    SetupInstallStreamingBtn.IsEnabled = false;
                }
                else
                {
                    allConfigured = false;
                    string missing = (!sunOk && !moonOk) ? "Sunshine & Moonlight missing" : (!sunOk ? "Sunshine missing" : "Moonlight missing");
                    SetupDisplayStatusText.Text = $"Status: {missing}. 1-click install via WinGet.";
                    SetupDisplayStatusText.Foreground = new SolidColorBrush(Windows.UI.Color.FromArgb(255, 232, 158, 27));
                    SetupInstallStreamingBtn.Content = "Install Display Tools";
                    SetupInstallStreamingBtn.IsEnabled = true;
                }

                // 2. Passkey Touch ID
                bool passkeyOk = PasskeyAuthenticatorPlugin.IsRegistered || PasskeyAuthenticatorPlugin.IsActive;
                if (passkeyOk)
                {
                    SetupPasskeyStatusText.Text = "Status: Registered with Windows 11 WebAuthn (Active)";
                    SetupPasskeyStatusText.Foreground = new SolidColorBrush(Windows.UI.Color.FromArgb(255, 32, 184, 90));
                    SetupEnablePasskeyBtn.Content = "Registered ✓";
                    SetupEnablePasskeyBtn.IsEnabled = false;
                }
                else
                {
                    allConfigured = false;
                    SetupPasskeyStatusText.Text = "Status: Not registered yet. 1-click registration.";
                    SetupPasskeyStatusText.Foreground = new SolidColorBrush(Windows.UI.Color.FromArgb(255, 232, 158, 27));
                    SetupEnablePasskeyBtn.Content = "Enable Touch ID";
                    SetupEnablePasskeyBtn.IsEnabled = true;
                }

                // 3. USB-C NCM & SMB Sharing
                var ncm = s.Dependencies.FirstOrDefault(d => d.Id == "usb_ncm" || d.Id == "usbncm");
                var smb = s.Permissions.FirstOrDefault(p => p.Id == "smb_server");
                bool ncmOk = ncm?.Installed == true;
                bool smbOk = smb?.Granted == true;

                if (ncmOk && smbOk)
                {
                    SetupUsbNcmStatusText.Text = "Status: USB-C link & SMB sharing configured (Ready)";
                    SetupUsbNcmStatusText.Foreground = new SolidColorBrush(Windows.UI.Color.FromArgb(255, 32, 184, 90));
                    SetupEnableUsbNcmBtn.Content = "Configured ✓";
                    SetupEnableUsbNcmBtn.IsEnabled = false;
                }
                else
                {
                    allConfigured = false;
                    string missing = (!ncmOk && !smbOk) ? "USB-C driver & SMB share not ready" : (!ncmOk ? "USB-C driver not ready" : "SMB share not started");
                    SetupUsbNcmStatusText.Text = $"Status: {missing}. 1-click setup.";
                    SetupUsbNcmStatusText.Foreground = new SolidColorBrush(Windows.UI.Color.FromArgb(255, 232, 158, 27));
                    SetupEnableUsbNcmBtn.Content = "Setup USB-C & SMB";
                    SetupEnableUsbNcmBtn.IsEnabled = true;
                }
            }

            if (allConfigured)
            {
                SetupHeaderSubtitleText.Text = "All features are already installed and configured. Your workstation continuity is fully ready!";
                SetupHeaderSubtitleText.Foreground = new SolidColorBrush(Windows.UI.Color.FromArgb(255, 32, 184, 90));
            }
            else
            {
                SetupHeaderSubtitleText.Text = "Set up seamless cross-device features between your Windows PC and Mac in one click. No terminal scripts required.";
                SetupHeaderSubtitleText.Foreground = (Brush)Application.Current.Resources["TextFillColorSecondaryBrush"];
            }

            return allConfigured;
        }

        // MARK: - Permissions & Setup Assistant Dialog

        /// <summary>
        /// Presents the WinUI 3 ContentDialog for the Permissions &amp; Setup Assistant, allowing 1-click
        /// remediation of Windows Defender Firewall rules, Network Profile category, Camera Privacy, SMB Server,
        /// and guided installation for Sunshine, Moonlight, Virtual Display Driver, USB-C NCM Bridge, and Virtual Camera.
        /// </summary>
        private async Task ShowSetupAssistantDialogAsync()
        {
            if (_isSetupDialogOpen || _disposedForExit || RootGrid?.XamlRoot == null) return;
            _isSetupDialogOpen = true;
            try
            {
                var freshRes = await Task.Run(() => CoreBridge.Invoke<SetupHealthSnapshotModel>("get_setup_status"));
                SetupHealthSnapshotModel snap = (freshRes.Ok && freshRes.Data != null)
                    ? freshRes.Data
                    : (_status?.SetupStatus ?? new SetupHealthSnapshotModel());
                if (_status != null)
                {
                    _status.SetupStatus = snap;
                }

                var hostContainer = new StackPanel { Spacing = 12, MinWidth = 540, MaxWidth = 640 };

                void RebuildDialogContent(SetupHealthSnapshotModel current)
                {
                    hostContainer.Children.Clear();

                    // Summary Banner + Action Bar
                    var topRow = new Grid { ColumnSpacing = 8 };
                    topRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                    topRow.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
                    topRow.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

                    string summaryMsg = current.NeedsAttention
                        ? $"{current.MissingRequiredPermissions} required permission(s) and {current.MissingRequiredDependencies} required tool(s) need attention."
                        : "All required Windows permissions and streaming tools are ready.";
                    var summaryText = new TextBlock
                    {
                        Text = summaryMsg,
                        FontSize = 12,
                        FontWeight = FontWeights.SemiBold,
                        Foreground = new SolidColorBrush(current.NeedsAttention
                            ? Color.FromArgb(255, 232, 158, 27)
                            : Color.FromArgb(255, 32, 184, 90)),
                        VerticalAlignment = VerticalAlignment.Center,
                        TextWrapping = TextWrapping.Wrap
                    };
                    Grid.SetColumn(summaryText, 0);
                    topRow.Children.Add(summaryText);

                    var fixAllBtn = new Button
                    {
                        Content = "Fix All Missing",
                        Padding = new Thickness(10, 4, 10, 4),
                        FontSize = 11,
                        IsEnabled = current.MissingRequiredPermissions > 0
                    };
                    fixAllBtn.Click += async (_, _) =>
                    {
                        fixAllBtn.IsEnabled = false;
                        var r = await Task.Run(() => CoreBridge.Invoke<string>("request_all_missing_permissions"));
                        if (_disposedForExit) return;
                        if (!string.IsNullOrWhiteSpace(r.Data)) ShowToast(r.Data!, r.Ok ? "success" : "warn");
                        else if (!r.Ok && !string.IsNullOrWhiteSpace(r.Error)) ShowToast(r.Error!, "error");
                        var refreshed = await Task.Run(() => CoreBridge.Invoke<SetupHealthSnapshotModel>("get_setup_status"));
                        if (_disposedForExit) return;
                        if (refreshed.Ok && refreshed.Data != null)
                        {
                            RebuildDialogContent(refreshed.Data);
                            await RefreshStatusAsync();
                        }
                        else
                        {
                            fixAllBtn.IsEnabled = true;
                        }
                    };
                    Grid.SetColumn(fixAllBtn, 1);
                    topRow.Children.Add(fixAllBtn);

                    var refreshBtn = new Button
                    {
                        Content = "Refresh",
                        Padding = new Thickness(10, 4, 10, 4),
                        FontSize = 11
                    };
                    refreshBtn.Click += async (_, _) =>
                    {
                        refreshBtn.IsEnabled = false;
                        var refreshed = await Task.Run(() => CoreBridge.Invoke<SetupHealthSnapshotModel>("get_setup_status"));
                        if (_disposedForExit) return;
                        if (refreshed.Ok && refreshed.Data != null)
                        {
                            RebuildDialogContent(refreshed.Data);
                            await RefreshStatusAsync();
                        }
                        else
                        {
                            refreshBtn.IsEnabled = true;
                        }
                    };
                    Grid.SetColumn(refreshBtn, 2);
                    topRow.Children.Add(refreshBtn);
                    hostContainer.Children.Add(topRow);

                    // Section 1: Windows Permissions
                    hostContainer.Children.Add(new TextBlock
                    {
                        Text = "Windows Security & Privacy Permissions",
                        FontSize = 13,
                        FontWeight = FontWeights.SemiBold,
                        Margin = new Thickness(0, 4, 0, 0)
                    });

                    foreach (var perm in current.Permissions)
                    {
                        string permId = perm.Id;
                        var card = new Border
                        {
                            Padding = new Thickness(10, 8, 10, 8),
                            CornerRadius = new CornerRadius(8),
                            Background = (Brush)Application.Current.Resources["CardBackgroundFillColorSecondaryBrush"],
                            BorderBrush = (Brush)Application.Current.Resources["CardStrokeColorDefaultBrush"],
                            BorderThickness = new Thickness(1)
                        };
                        var rowGrid = new Grid { ColumnSpacing = 10 };
                        rowGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                        rowGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

                        var infoStack = new StackPanel { Spacing = 2 };
                        string badgeLabel = perm.Granted ? "[OK]" : (perm.Required ? "[REQUIRED • MISSING]" : "[ADVISORY]");
                        var titleBlock = new TextBlock
                        {
                            Text = $"{badgeLabel}  {perm.Title}",
                            FontSize = 12,
                            FontWeight = FontWeights.SemiBold,
                            Foreground = new SolidColorBrush(perm.Granted
                                ? Color.FromArgb(255, 32, 184, 90)
                                : (perm.Required ? Color.FromArgb(255, 232, 158, 27) : Color.FromArgb(255, 24, 180, 212))),
                            TextWrapping = TextWrapping.Wrap
                        };
                        infoStack.Children.Add(titleBlock);
                        infoStack.Children.Add(new TextBlock
                        {
                            Text = perm.Description,
                            FontSize = 11,
                            Foreground = (Brush)Application.Current.Resources["TextFillColorSecondaryBrush"],
                            TextWrapping = TextWrapping.Wrap
                        });
                        infoStack.Children.Add(new TextBlock
                        {
                            Text = perm.Detail,
                            FontSize = 11,
                            Foreground = (Brush)Application.Current.Resources["TextFillColorTertiaryBrush"],
                            TextWrapping = TextWrapping.Wrap
                        });
                        Grid.SetColumn(infoStack, 0);
                        rowGrid.Children.Add(infoStack);

                        var btnPanel = new StackPanel
                        {
                            Orientation = Orientation.Horizontal,
                            Spacing = 6,
                            VerticalAlignment = VerticalAlignment.Center
                        };
                        if (perm.CanRequestDirectly && !perm.Granted)
                        {
                            var fixBtn = new Button
                            {
                                Content = "Fix / Request",
                                Padding = new Thickness(10, 4, 10, 4),
                                FontSize = 11
                            };
                            fixBtn.Click += async (_, _) =>
                            {
                                fixBtn.IsEnabled = false;
                                var r = await Task.Run(() => CoreBridge.Invoke<string>("request_permission", new { id = permId }));
                                if (_disposedForExit) return;
                                if (!string.IsNullOrWhiteSpace(r.Data)) ShowToast(r.Data!, r.Ok ? "success" : "warn");
                                else if (!r.Ok && !string.IsNullOrWhiteSpace(r.Error)) ShowToast(r.Error!, "error");
                                var refreshed = await Task.Run(() => CoreBridge.Invoke<SetupHealthSnapshotModel>("get_setup_status"));
                                if (_disposedForExit) return;
                                if (refreshed.Ok && refreshed.Data != null)
                                {
                                    RebuildDialogContent(refreshed.Data);
                                    await RefreshStatusAsync();
                                }
                                else
                                {
                                    fixBtn.IsEnabled = true;
                                }
                            };
                            btnPanel.Children.Add(fixBtn);
                        }
                        if (!string.IsNullOrWhiteSpace(perm.SettingsUrl))
                        {
                            var settingsBtn = new Button
                            {
                                Content = "Open Settings",
                                Padding = new Thickness(10, 4, 10, 4),
                                FontSize = 11
                            };
                            settingsBtn.Click += async (_, _) =>
                            {
                                var r = await Task.Run(() => CoreBridge.Invoke<string>("open_permission_settings", new { id = permId }));
                                if (!r.Ok && !string.IsNullOrWhiteSpace(r.Error)) ShowToast(r.Error!, "error");
                            };
                            btnPanel.Children.Add(settingsBtn);
                        }
                        Grid.SetColumn(btnPanel, 1);
                        rowGrid.Children.Add(btnPanel);
                        card.Child = rowGrid;
                        hostContainer.Children.Add(card);
                    }

                    // Section 2: Companion Drivers & Streaming Tools
                    hostContainer.Children.Add(new TextBlock
                    {
                        Text = "Drivers & Companion Streaming Tools",
                        FontSize = 13,
                        FontWeight = FontWeights.SemiBold,
                        Margin = new Thickness(0, 6, 0, 0)
                    });

                    foreach (var dep in current.Dependencies)
                    {
                        string depId = dep.Id;
                        var card = new Border
                        {
                            Padding = new Thickness(10, 8, 10, 8),
                            CornerRadius = new CornerRadius(8),
                            Background = (Brush)Application.Current.Resources["CardBackgroundFillColorSecondaryBrush"],
                            BorderBrush = (Brush)Application.Current.Resources["CardStrokeColorDefaultBrush"],
                            BorderThickness = new Thickness(1)
                        };
                        var rowGrid = new Grid { ColumnSpacing = 10 };
                        rowGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                        rowGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

                        var infoStack = new StackPanel { Spacing = 2 };
                        string badgeLabel = dep.Installed
                            ? (dep.Running == true ? "[INSTALLED • RUNNING]" : "[INSTALLED]")
                            : (dep.Required ? "[REQUIRED • MISSING]" : "[OPTIONAL]");
                        infoStack.Children.Add(new TextBlock
                        {
                            Text = $"{badgeLabel}  {dep.Name}",
                            FontSize = 12,
                            FontWeight = FontWeights.SemiBold,
                            Foreground = new SolidColorBrush(dep.Installed
                                ? Color.FromArgb(255, 32, 184, 90)
                                : (dep.Required ? Color.FromArgb(255, 232, 158, 27) : Color.FromArgb(255, 136, 136, 136))),
                            TextWrapping = TextWrapping.Wrap
                        });
                        infoStack.Children.Add(new TextBlock
                        {
                            Text = dep.Description,
                            FontSize = 11,
                            Foreground = (Brush)Application.Current.Resources["TextFillColorSecondaryBrush"],
                            TextWrapping = TextWrapping.Wrap
                        });
                        if (!string.IsNullOrWhiteSpace(dep.DetectedPath))
                        {
                            infoStack.Children.Add(new TextBlock
                            {
                                Text = $"Detected: {dep.DetectedPath}",
                                FontSize = 10,
                                FontFamily = new FontFamily("Consolas"),
                                Foreground = (Brush)Application.Current.Resources["TextFillColorTertiaryBrush"],
                                TextTrimming = TextTrimming.CharacterEllipsis
                            });
                        }
                        if (!string.IsNullOrWhiteSpace(dep.InstallCommand))
                        {
                            infoStack.Children.Add(new TextBlock
                            {
                                Text = $"{dep.InstallMethod}: {dep.InstallCommand}",
                                FontSize = 10,
                                FontFamily = new FontFamily("Consolas"),
                                Foreground = (Brush)Application.Current.Resources["TextFillColorTertiaryBrush"],
                                IsTextSelectionEnabled = true,
                                TextWrapping = TextWrapping.Wrap
                            });
                        }
                        Grid.SetColumn(infoStack, 0);
                        rowGrid.Children.Add(infoStack);

                        var installBtn = new Button
                        {
                            Content = dep.Installed ? "Reinstall / Guide" : "Install / Download",
                            Padding = new Thickness(10, 4, 10, 4),
                            FontSize = 11,
                            VerticalAlignment = VerticalAlignment.Center
                        };
                        installBtn.Click += async (_, _) =>
                        {
                            installBtn.IsEnabled = false;
                            var r = await Task.Run(() => CoreBridge.Invoke<string>("install_dependency", new { id = depId }));
                            if (_disposedForExit) return;
                            if (!string.IsNullOrWhiteSpace(r.Data)) ShowToast(r.Data!, r.Ok ? "success" : "warn");
                            else if (!r.Ok && !string.IsNullOrWhiteSpace(r.Error)) ShowToast(r.Error!, "error");
                            var refreshed = await Task.Run(() => CoreBridge.Invoke<SetupHealthSnapshotModel>("get_setup_status"));
                            if (_disposedForExit) return;
                            if (refreshed.Ok && refreshed.Data != null)
                            {
                                RebuildDialogContent(refreshed.Data);
                                await RefreshStatusAsync();
                            }
                            else
                            {
                                installBtn.IsEnabled = true;
                            }
                        };
                        Grid.SetColumn(installBtn, 1);
                        rowGrid.Children.Add(installBtn);

                        card.Child = rowGrid;
                        hostContainer.Children.Add(card);
                    }

                    // Suppress on Launch CheckBox
                    var suppressChk = new CheckBox
                    {
                        Content = "Don't prompt automatically on launch",
                        IsChecked = current.SuppressLaunchPrompt,
                        FontSize = 12,
                        Margin = new Thickness(0, 6, 0, 0)
                    };
                    suppressChk.Click += async (_, _) =>
                    {
                        bool suppress = suppressChk.IsChecked == true;
                        await Task.Run(() => CoreBridge.Invoke<bool>("set_suppress_launch_setup_prompt", new { suppress }));
                        await RefreshStatusAsync();
                    };
                    hostContainer.Children.Add(suppressChk);
                }

                RebuildDialogContent(snap);

                var scrollViewer = new ScrollViewer
                {
                    MaxHeight = 520,
                    VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                    HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
                    Content = hostContainer
                };

                var dlg = new ContentDialog
                {
                    Title = "Permissions & Setup Assistant",
                    Content = scrollViewer,
                    CloseButtonText = "Done",
                    DefaultButton = ContentDialogButton.Close,
                    XamlRoot = RootGrid.XamlRoot
                };

                await dlg.ShowAsync();
            }
            catch
            {
            }
            finally
            {
                _isSetupDialogOpen = false;
            }
        }

        // MARK: - Quit Confirmation & Live Process Shutdown Progress

        /// <summary>
        /// Displays a quit confirmation dialog (with "Don't ask again") warning that all Integrator
        /// features and background processes will stop working, then runs the visible step-by-step
        /// process shutdown dialog before terminating the application.
        /// </summary>
        internal async Task RequestQuitAsync()
        {
            if (_isQuitFlowRunning || _disposedForExit) return;
            _isQuitFlowRunning = true;
            bool wasHidden = _isHiddenToTray || !AppWindow.IsVisible;

            try
            {
                // Bring the window visible so WinUI 3 ContentDialog has a valid XamlRoot and is front-and-center.
                if (wasHidden)
                {
                    RestoreAndActivate();
                }
                else
                {
                    Activate();
                }

                // Wait briefly for initial XamlRoot layout if launched directly via --minimized.
                for (int i = 0; i < 20 && RootGrid?.XamlRoot == null; i++)
                {
                    await Task.Delay(50);
                }

                if (RootGrid?.XamlRoot == null)
                {
                    _app.ExitApplication();
                    return;
                }

                if (!UiPreferences.SkipQuitConfirmation)
                {
                    var warnHeader = new StackPanel
                    {
                        Orientation = Orientation.Horizontal,
                        Spacing = 10
                    };
                    warnHeader.Children.Add(new FontIcon
                    {
                        Glyph = "\uE7BA",
                        FontSize = 20,
                        Foreground = new SolidColorBrush(Windows.UI.Color.FromArgb(255, 232, 163, 23)),
                        VerticalAlignment = VerticalAlignment.Center
                    });
                    warnHeader.Children.Add(new TextBlock
                    {
                        Text = "All Integrator features will stop working.",
                        FontSize = 14,
                        FontWeight = FontWeights.SemiBold,
                        VerticalAlignment = VerticalAlignment.Center,
                        TextWrapping = TextWrapping.Wrap
                    });

                    var bodyText = new TextBlock
                    {
                        Text = "Are you sure you want to quit Integrator?\n\n" +
                               "Quitting will shut down all Integrator background processes — including KVM mouse & keyboard sharing, Universal Clipboard & Drag-and-Drop, Extended Screen, Shared Camera, Dynamic Audio Routing, Shared Storage, and Passkey bridging.",
                        FontSize = 13,
                        TextWrapping = TextWrapping.Wrap,
                        Opacity = 0.88
                    };

                    var dontAskCheck = new CheckBox
                    {
                        Content = "Don't ask again",
                        FontSize = 12,
                        Margin = new Thickness(0, 6, 0, 0)
                    };

                    var confirmStack = new StackPanel { Spacing = 10, MaxWidth = 420 };
                    confirmStack.Children.Add(warnHeader);
                    confirmStack.Children.Add(bodyText);
                    confirmStack.Children.Add(dontAskCheck);

                    var confirmDlg = new ContentDialog
                    {
                        Title = "Quit Integrator?",
                        Content = confirmStack,
                        PrimaryButtonText = "Quit Integrator",
                        CloseButtonText = "Cancel",
                        DefaultButton = ContentDialogButton.Close,
                        XamlRoot = RootGrid.XamlRoot
                    };

                    var result = await confirmDlg.ShowAsync();
                    if (result != ContentDialogResult.Primary)
                    {
                        if (wasHidden)
                        {
                            HideToTray();
                        }
                        return;
                    }

                    if (dontAskCheck.IsChecked == true)
                    {
                        UiPreferences.SkipQuitConfirmation = true;
                        SyncConfirmQuitSwitch();
                    }
                }

                await RunVisualShutdownAndExitAsync();
            }
            catch
            {
                _app.ExitApplication();
            }
            finally
            {
                _isQuitFlowRunning = false;
            }
        }

        /// <summary>
        /// Displays a non-dismissible shutdown progress dialog while stopping every Integrator
        /// subsystem and background process sequentially, then terminates the app cleanly.
        /// </summary>
        private async Task RunVisualShutdownAndExitAsync()
        {
            CleanupForExit();

            var steps = new (string Id, string Title, string Detail)[]
            {
                ("audio",   "Dynamic Audio Routing",            "Stopping WASAPI capture & UDP sink…"),
                ("camera",  "Shared Camera",                    "Stopping virtual camera streams…"),
                ("display", "Extended Display & GPU",           "Stopping Moonlight, virtual display & gamma…"),
                ("storage", "Clipboard, Storage & Passkey Host","Clearing cache, unmounting & stopping PasskeyHost…"),
                ("kvm",     "KVM Hooks & Core Services",        "Releasing input hooks & closing sockets…")
            };

            var headerRing = new ProgressRing { Width = 22, Height = 22, IsActive = true };
            var headerCheck = new FontIcon
            {
                Glyph = "\uE73E",
                FontSize = 18,
                Foreground = new SolidColorBrush(Windows.UI.Color.FromArgb(255, 32, 184, 90)),
                Visibility = Visibility.Collapsed
            };
            var headerText = new TextBlock
            {
                Text = "Stopping all Integrator processes and background services…",
                FontSize = 13,
                TextWrapping = TextWrapping.Wrap,
                VerticalAlignment = VerticalAlignment.Center
            };

            var headerRow = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 10 };
            headerRow.Children.Add(headerRing);
            headerRow.Children.Add(headerCheck);
            headerRow.Children.Add(headerText);

            var rowsPanel = new StackPanel { Spacing = 8, Margin = new Thickness(0, 6, 0, 0) };
            var rowWidgets = new Dictionary<string, (FontIcon Pending, ProgressRing Spinner, FontIcon Done, TextBlock Status)>();

            foreach (var step in steps)
            {
                var row = new Grid { ColumnSpacing = 10 };
                row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(20) });
                row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

                var pending = new FontIcon
                {
                    Glyph = "\uEA3A",
                    FontSize = 12,
                    Opacity = 0.45,
                    HorizontalAlignment = HorizontalAlignment.Center,
                    VerticalAlignment = VerticalAlignment.Center
                };
                var spinner = new ProgressRing
                {
                    Width = 14,
                    Height = 14,
                    IsActive = false,
                    Visibility = Visibility.Collapsed
                };
                var done = new FontIcon
                {
                    Glyph = "\uE73E",
                    FontSize = 13,
                    Foreground = new SolidColorBrush(Windows.UI.Color.FromArgb(255, 32, 184, 90)),
                    Visibility = Visibility.Collapsed,
                    HorizontalAlignment = HorizontalAlignment.Center,
                    VerticalAlignment = VerticalAlignment.Center
                };

                var iconHost = new Grid { Width = 20, Height = 20 };
                iconHost.Children.Add(pending);
                iconHost.Children.Add(spinner);
                iconHost.Children.Add(done);
                Grid.SetColumn(iconHost, 0);

                var labelStack = new StackPanel { Spacing = 1 };
                labelStack.Children.Add(new TextBlock
                {
                    Text = step.Title,
                    FontSize = 13,
                    FontWeight = FontWeights.SemiBold
                });
                var statusLbl = new TextBlock
                {
                    Text = "Waiting…",
                    FontSize = 11,
                    Opacity = 0.7
                };
                labelStack.Children.Add(statusLbl);
                Grid.SetColumn(labelStack, 1);

                row.Children.Add(iconHost);
                row.Children.Add(labelStack);
                rowsPanel.Children.Add(row);

                rowWidgets[step.Id] = (pending, spinner, done, statusLbl);
            }

            var contentStack = new StackPanel { Spacing = 10, MinWidth = 380 };
            contentStack.Children.Add(headerRow);
            contentStack.Children.Add(new Border
            {
                Height = 1,
                Background = new SolidColorBrush(Windows.UI.Color.FromArgb(40, 128, 128, 128))
            });
            contentStack.Children.Add(rowsPanel);

            bool allowClose = false;
            var shutdownDlg = new ContentDialog
            {
                Title = "Shutting Down Integrator…",
                Content = contentStack,
                XamlRoot = RootGrid.XamlRoot
            };
            shutdownDlg.Closing += (_, e) =>
            {
                if (!allowClose) e.Cancel = true;
            };

            // Show dialog asynchronously so we can drive live step transitions while it stays open.
            var showTask = shutdownDlg.ShowAsync().AsTask();

            foreach (var step in steps)
            {
                var w = rowWidgets[step.Id];
                w.Pending.Visibility = Visibility.Collapsed;
                w.Spinner.Visibility = Visibility.Visible;
                w.Spinner.IsActive = true;
                w.Status.Text = step.Detail;

                await Task.Run(() =>
                {
                    try
                    {
                        CoreBridge.Invoke<string>("shutdown_subsystem", new { step = step.Id });
                    }
                    catch { }

                    if (step.Id == "storage")
                    {
                        try
                        {
                            PasskeyAuthenticatorPlugin.Shutdown();
                            App.TerminateSessionPasskeyHosts();
                        }
                        catch { }
                    }
                    else if (step.Id == "kvm")
                    {
                        try
                        {
                            CoreBridge.Shutdown();
                        }
                        catch { }
                    }
                });

                await Task.Delay(140);

                w.Spinner.IsActive = false;
                w.Spinner.Visibility = Visibility.Collapsed;
                w.Done.Visibility = Visibility.Visible;
                w.Status.Text = "Stopped";
                w.Status.Foreground = new SolidColorBrush(Windows.UI.Color.FromArgb(255, 32, 184, 90));
                w.Status.Opacity = 1.0;
            }

            _app.DisposeTrayIcon();
            headerRing.IsActive = false;
            headerRing.Visibility = Visibility.Collapsed;
            headerCheck.Visibility = Visibility.Visible;
            headerText.Text = "All Integrator processes stopped. Quitting…";
            shutdownDlg.Title = "Integrator Stopped";

            await Task.Delay(450);

            allowClose = true;
            shutdownDlg.Hide();
            try { await showTask; } catch { }

            _app.FinishExitAfterVisualShutdown();
        }
    }

    /// <summary>
    /// Persists lightweight Windows UI preferences (such as "Don't ask again" on quit,
    /// and initial setup completion state) under %LOCALAPPDATA%\Integrator\ui_prefs.json.
    /// </summary>
    internal static class UiPreferences
    {
        /// <summary>
        /// On-disk JSON serialization model for local Windows UI preferences.
        /// </summary>
        private sealed class PrefsModel
        {
            /// <summary>True if the user opted out of the quit confirmation dialog.</summary>
            [System.Text.Json.Serialization.JsonPropertyName("skip_quit_confirmation")]
            public bool SkipQuitConfirmation { get; set; }

            /// <summary>True if the user has completed or dismissed the first-launch Setup Assistant wizard.</summary>
            [System.Text.Json.Serialization.JsonPropertyName("has_completed_initial_setup")]
            public bool HasCompletedInitialSetup { get; set; }
        }

        /// <summary>
        /// Resolves the canonical file path for ui_prefs.json under %LOCALAPPDATA%\Integrator.
        /// </summary>
        private static string PrefsPath => System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Integrator",
            "ui_prefs.json");

        /// <summary>
        /// Reads and deserializes the UI preferences JSON file from disk, returning default settings on missing or corrupt files.
        /// </summary>
        private static PrefsModel LoadModel()
        {
            try
            {
                if (System.IO.File.Exists(PrefsPath))
                {
                    string json = System.IO.File.ReadAllText(PrefsPath);
                    return JsonSerializer.Deserialize<PrefsModel>(json) ?? new PrefsModel();
                }
            }
            catch { }
            return new PrefsModel();
        }

        /// <summary>
        /// Serializes and writes the UI preferences model to %LOCALAPPDATA%\Integrator\ui_prefs.json.
        /// </summary>
        private static void SaveModel(PrefsModel model)
        {
            try
            {
                string? dir = System.IO.Path.GetDirectoryName(PrefsPath);
                if (!string.IsNullOrEmpty(dir))
                {
                    System.IO.Directory.CreateDirectory(dir);
                }
                string json = JsonSerializer.Serialize(model);
                System.IO.File.WriteAllText(PrefsPath, json);
            }
            catch { }
        }

        /// <summary>
        /// Gets or sets whether the quit confirmation dialog should be skipped when exiting Integrator.
        /// </summary>
        public static bool SkipQuitConfirmation
        {
            get => LoadModel().SkipQuitConfirmation;
            set
            {
                var m = LoadModel();
                m.SkipQuitConfirmation = value;
                SaveModel(m);
            }
        }

        /// <summary>
        /// Gets or sets whether the first-launch Setup Assistant wizard has been completed.
        /// </summary>
        public static bool HasCompletedInitialSetup
        {
            get => LoadModel().HasCompletedInitialSetup;
            set
            {
                var m = LoadModel();
                m.HasCompletedInitialSetup = value;
                SaveModel(m);
            }
        }
    }
}
