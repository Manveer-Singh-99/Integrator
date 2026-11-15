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
    public sealed partial class MainWindow : Window
    {
        private readonly App _app;
        private readonly DispatcherTimer _pollTimer;
        private readonly DispatcherTimer _toastTimer;
        private readonly Border[] _allCards;
        private readonly Button[] _navButtons;
        private readonly Dictionary<string, string> _pinInputs = new();

        private string _selectedCategory = "all";
        private BridgeStatusModel? _status;
        private KvmLayoutConfigModel _kvmLayout = new();
        private bool _kvmLayoutDirty;
        private bool _encodeGpuDirty;
        private bool _decodeGpuDirty;
        private bool _preferredShareDirty;
        private bool _refreshInFlight;
        private bool _speedTestRunning;
        private bool _isHiddenToTray;
        private bool _disposedForExit;
        private bool _applyingStatus;
        private int _currentGridColumns = -1;
        private string? _lastPeerKey;
        private string? _lastManualIpKey;
        private string? _lastGpuListKey;
        private string? _lastRenderedLogsKey;
        private ElementTheme _lastRenderedTheme = ElementTheme.Default;

        public MainWindow(App app, bool startHidden = false)
        {
            _app = app;
            _isHiddenToTray = startHidden;
            InitializeComponent();

            _allCards = new[]
            {
                CardDisplay, CardKvm, CardDragDrop, CardClipboard,
                CardDiscovery, CardSpeed, CardStorage, CardTrueTone,
                CardTouchBar, CardAudio, CardSystem, CardLogs
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

            _toastTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(4) };
            _toastTimer.Tick += (_, _) =>
            {
                _toastTimer.Stop();
                ToastBanner.Visibility = Visibility.Collapsed;
            };

            _pollTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
            _pollTimer.Tick += (_, _) => _ = RefreshStatusAsync();
            if (!startHidden)
            {
                _pollTimer.Start();
                _ = RefreshStatusAsync();
            }
        }

        [DllImport("user32.dll")]
        private static extern uint GetDpiForWindow(IntPtr hwnd);

        private void ConfigureWindowChrome()
        {
            ExtendsContentIntoTitleBar = true;
            SetTitleBar(AppTitleBar);

            IntPtr hwnd = WindowNative.GetWindowHandle(this);
            uint dpi = GetDpiForWindow(hwnd);
            double scale = dpi > 0 ? dpi / 96.0 : 1.0;

            var area = DisplayArea.GetFromWindowId(AppWindow.Id, DisplayAreaFallback.Primary)?.WorkArea
                ?? new RectInt32(0, 0, 1920, 1080);
            int targetW = Math.Min((int)(1240 * scale), Math.Max(800, area.Width - 48));
            int targetH = Math.Min((int)(820 * scale), Math.Max(600, area.Height - 48));
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

        internal void CleanupForExit()
        {
            _disposedForExit = true;
            _pollTimer.Stop();
            _toastTimer.Stop();
        }

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
                    safeDevId.Length > 14 ? safeDevId[..14] : safeDevId);

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
                SidebarTrustText.Text = s.PeerTrusted ? "Verified v2.0" : "Pair Required";
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
                    ? "Interfaces: " + string.Join(", ", s.LocalInterfaces.Take(3).Select(i => i.Name + " (" + i.Ip + ")"))
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
                    ? string.Format(CultureInfo.InvariantCulture, "{0:0} lux • {1}K", s.AmbientLux ?? 0f, s.AmbientCct ?? 6500)
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
                AudioTopologyText.Text = string.IsNullOrWhiteSpace(s.AudioStatus.Topology)
                    ? "Authenticated ChaCha20-Poly1305 spatial UDP audio sink ready."
                    : s.AudioStatus.Topology;
                BtnPlayChime.IsEnabled = f.Audio;

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

        private void RebuildDeskSchematic(BridgeStatusModel s)
        {
            DeskSchematicHost.Children.Clear();
            string localName = string.IsNullOrWhiteSpace(s.Hostname) ? "This PC" : s.Hostname;
            string peerName = s.PeerName ?? "Peer Mac";

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
                        Text = "Trusted v2.0",
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
                        MaxLength = 12,
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
                        Content = "Pair v2.0",
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
                    Text = $"Blocked Peer ({(devId.Length > 14 ? devId[..14] : devId)})",
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

        private void RebuildLogsPanel(List<LogEntryModel> logs)
        {
            var safeLogs = logs ?? new List<LogEntryModel>();
            var tail = safeLogs.Count > 60 ? safeLogs.Skip(safeLogs.Count - 60).ToList() : safeLogs;
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

        private static void SetPillStyle(Border pill, Ellipse dot, Color color)
        {
            dot.Fill = new SolidColorBrush(color);
            pill.Background = new SolidColorBrush(Color.FromArgb(34, color.R, color.G, color.B));
            pill.BorderBrush = new SolidColorBrush(Color.FromArgb(90, color.R, color.G, color.B));
        }

        // MARK: - Responsive Grid & Navigation

        private void NavButton_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is string cat)
            {
                _selectedCategory = cat;
                UpdateNavStyles();
                RebuildCardsGrid(force: true);
            }
        }

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

        private void CardsGrid_SizeChanged(object sender, SizeChangedEventArgs e)
        {
            RebuildCardsGrid(force: false);
        }

        private void RebuildCardsGrid(bool force)
        {
            int cols = CardsGrid.ActualWidth >= 740 ? 2 : 1;
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

        private void RefreshBtn_Click(object sender, RoutedEventArgs e) => _ = RefreshStatusAsync();
        private void OpenCacheBtn_Click(object sender, RoutedEventArgs e) => RunInvoke("open_cache_folder", refreshAfter: false);
        private void HideWindowBtn_Click(object sender, RoutedEventArgs e) => HideToTray();

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
                    _ => enabled
                };
                if (current == enabled) return;
                RunInvoke("set_feature_flag", new { feature, enabled });
            }
        }

        private void ExtendMacToPc_Click(object sender, RoutedEventArgs e) => RunInvoke("toggle_mac_to_pc");
        private void ExtendPcToMac_Click(object sender, RoutedEventArgs e) => RunInvoke("toggle_pc_to_mac");

        private void GpuCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (_applyingStatus || _status == null) return;
            if (ReferenceEquals(sender, EncodeGpuCombo)) _encodeGpuDirty = true;
            else if (ReferenceEquals(sender, DecodeGpuCombo)) _decodeGpuDirty = true;
        }

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

        private void KvmSlider_ValueChanged(object sender, Microsoft.UI.Xaml.Controls.Primitives.RangeBaseValueChangedEventArgs e)
        {
            if (_applyingStatus || _status == null || AlignmentValueText == null || HopDelayValueText == null) return;
            _kvmLayout.AlignmentOffset = (float)Math.Clamp(AlignmentSlider.Value, -0.5, 0.5);
            _kvmLayout.HopDelayMs = (uint)Math.Clamp(HopDelaySlider.Value, 0.0, 250.0);
            _kvmLayoutDirty = true;
            AlignmentValueText.Text = string.Format(CultureInfo.InvariantCulture, "{0:0}%", _kvmLayout.AlignmentOffset * 100f);
            HopDelayValueText.Text = _kvmLayout.HopDelayMs + " ms";
        }

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

        private void DropFolderCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (_applyingStatus || _status == null) return;
            if (DropFolderCombo.SelectedItem is ComboBoxItem item && item.Tag is string folder)
            {
                _kvmLayout.DropFolder = folder;
                _kvmLayoutDirty = true;
            }
        }

        private void SaveKvmLayout_Click(object sender, RoutedEventArgs e) => SaveKvmLayoutInternal();

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

        private void ReleaseKvm_Click(object sender, RoutedEventArgs e) => RunInvoke("release_kvm_control");
        private void PasteRemote_Click(object sender, RoutedEventArgs e) => RunInvoke("paste_remote");
        private void RegenPin_Click(object sender, RoutedEventArgs e) => RunInvoke("regenerate_pairing_pin");

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

        private void PreferredShareInput_TextChanged(object sender, TextChangedEventArgs e)
        {
            if (_applyingStatus || _status == null) return;
            _preferredShareDirty = true;
        }

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

        private void ToggleMount_Click(object sender, RoutedEventArgs e)
        {
            bool mounted = _status?.StorageMounted == true;
            RunInvoke(mounted ? "unmount_shared_storage" : "mount_shared_storage");
        }

        private void TrueToneSlider_ValueChanged(object sender, Microsoft.UI.Xaml.Controls.Primitives.RangeBaseValueChangedEventArgs e)
        {
            if (CctValueText == null || GammaValueText == null) return;
            CctValueText.Text = $"{(int)CctSlider.Value}K";
            GammaValueText.Text = string.Format(CultureInfo.InvariantCulture, "{0:0.00}x", GammaSlider.Value);
        }

        private void SyncCalibration_Click(object sender, RoutedEventArgs e)
        {
            RunInvoke("apply_truetone_calibration", new
            {
                cct = (int)CctSlider.Value,
                compFactor = (float)GammaSlider.Value
            });
        }

        private void ToggleTouchBar_Click(object sender, RoutedEventArgs e) => RunInvoke("toggle_touchbar_hud");
        private void PlayChime_Click(object sender, RoutedEventArgs e) => RunInvoke("play_spatial_chime");

        private void AutostartSwitch_Toggled(object sender, RoutedEventArgs e)
        {
            if (_applyingStatus || _status == null) return;
            if (_status.AutostartEnabled == SwitchAutostart.IsOn) return;
            RunInvoke("set_autostart", new { enabled = SwitchAutostart.IsOn });
        }

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
    }
}
