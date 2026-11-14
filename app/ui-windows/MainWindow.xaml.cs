using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.UI;
using Microsoft.UI.Text;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
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
        private DispatcherTimer? _toastTimer;
        private readonly Border[] _allCards;
        private readonly Button[] _navButtons;
        private readonly Dictionary<string, string> _pinInputs = new();

        private string _selectedCategory = "all";
        private BridgeStatusModel? _status;
        private KvmLayoutConfigModel _kvmLayout = new();
        private bool _kvmLayoutDirty;
        private bool _applyingStatus;
        private int _currentGridColumns = -1;
        private string? _lastPeerKey;

        public MainWindow(App app)
        {
            _app = app;
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

            _pollTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
            _pollTimer.Tick += (_, _) => _ = RefreshStatusAsync();
            _pollTimer.Start();

            _ = RefreshStatusAsync();
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
                AppWindow.Hide();
            };
        }

        public void RestoreAndActivate()
        {
            try
            {
                if (AppWindow.Presenter is OverlappedPresenter p)
                {
                    p.Restore();
                }
                AppWindow.Show();
                Activate();
            }
            catch { }
        }

        public void HideToTray()
        {
            try { AppWindow.Hide(); } catch { }
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
            var res = await Task.Run(() => CoreBridge.Invoke<BridgeStatusModel>("get_bridge_status"));
            if (!res.Ok || res.Data == null) return;

            BridgeStatusModel s = res.Data;
            _status = s;

            if (!_kvmLayoutDirty || s.Kvm.Layout.UpdatedAtMs > _kvmLayout.UpdatedAtMs)
            {
                _kvmLayout = s.Kvm.Layout;
                _kvmLayoutDirty = false;
            }

            ApplyStatusToUi(s);
        }

        private void ApplyStatusToUi(BridgeStatusModel s)
        {
            _applyingStatus = true;
            try
            {
                // Top Bar
                TopHostnameText.Text = string.IsNullOrWhiteSpace(s.Hostname) ? "Workstation" : s.Hostname;
                TopSubtitleText.Text = string.Format(
                    CultureInfo.InvariantCulture,
                    "{0} • {1}x{2} • {3}",
                    s.HardwareModel,
                    s.PrimaryDisplay.Width,
                    s.PrimaryDisplay.Height,
                    s.DeviceId.Length > 14 ? s.DeviceId[..14] : s.DeviceId);

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
                BtnExtendMacToPc.IsEnabled = f.Display;
                BtnExtendPcToMac.IsEnabled = f.Display;

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
                DragDropKvmWarn.Visibility = f.InputKvm ? Visibility.Collapsed : Visibility.Visible;
                BtnSaveDropPrefs.IsEnabled = f.InputKvm;

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
                ClipboardKvmWarn.Visibility = f.InputKvm ? Visibility.Collapsed : Visibility.Visible;
                BtnPasteRemote.IsEnabled = f.Clipboard && f.InputKvm;
                ClipboardPillText.Text = !f.InputKvm ? "Requires KVM" : (f.Clipboard ? "Active" : "Off");
                SetPillStyle(ClipboardPill, ClipboardPillDot, !f.InputKvm
                    ? Color.FromArgb(255, 232, 158, 27)
                    : (f.Clipboard ? Color.FromArgb(255, 32, 184, 90) : Color.FromArgb(255, 136, 136, 136)));

                // Card 5: Discovery & Trust
                string curPin = string.IsNullOrWhiteSpace(s.Trust.PairingPin) ? "------" : s.Trust.PairingPin;
                DiscoveryPillText.Text = "PIN: " + curPin;
                SetPillStyle(DiscoveryPill, DiscoveryPillDot, Color.FromArgb(255, 24, 180, 212));
                PairingPinText.Text = curPin;
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
                BtnToggleMount.Content = s.StorageMounted ? "Unmount Storage" : "Mount Shared Storage";
                BtnToggleMount.IsEnabled = f.Storage;

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

        private void PopulateGpuCombos(BridgeStatusModel s)
        {
            if (EncodeGpuCombo.Items.Count == 0 || EncodeGpuCombo.Items.Count != s.LocalGpus.Count + 1)
            {
                EncodeGpuCombo.Items.Clear();
                DecodeGpuCombo.Items.Clear();
                EncodeGpuCombo.Items.Add(new ComboBoxItem { Content = "Auto (Recommended)", Tag = "auto" });
                DecodeGpuCombo.Items.Add(new ComboBoxItem { Content = "Auto (Recommended)", Tag = "auto" });

                foreach (var g in s.LocalGpus)
                {
                    EncodeGpuCombo.Items.Add(new ComboBoxItem { Content = g.Name, Tag = g.Name });
                    DecodeGpuCombo.Items.Add(new ComboBoxItem { Content = g.Name, Tag = g.Name });
                }
            }

            SelectComboByTag(EncodeGpuCombo, string.IsNullOrWhiteSpace(s.EncodeGpu) ? "auto" : s.EncodeGpu);
            SelectComboByTag(DecodeGpuCombo, string.IsNullOrWhiteSpace(s.DecodeGpu) ? "auto" : s.DecodeGpu);
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
            AlignmentSlider.Value = _kvmLayout.AlignmentOffset;
            AlignmentValueText.Text = string.Format(CultureInfo.InvariantCulture, "{0:0}%", _kvmLayout.AlignmentOffset * 100f);
            HopDelaySlider.Value = _kvmLayout.HopDelayMs;
            HopDelayValueText.Text = _kvmLayout.HopDelayMs + " ms";

            ChkDeadCorners.IsChecked = _kvmLayout.DeadCorners;
            ChkModifierTrans.IsChecked = _kvmLayout.ModifierTranslation;
            ChkTrackpad.IsChecked = _kvmLayout.PrecisionTouchpad;
            ChkGhostThumb.IsChecked = _kvmLayout.GhostThumbnail;
            ChkQosClamp.IsChecked = _kvmLayout.QosClamp;
            SelectComboByTag(DropFolderCombo, _kvmLayout.DropFolder);

            BtnSaveKvm.IsEnabled = s.FeatureFlags.InputKvm;

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
                    Foreground = accent ? new SolidColorBrush(Colors.White) : (Brush)Application.Current.Resources["TextFillColorPrimaryBrush"],
                    HorizontalAlignment = HorizontalAlignment.Center,
                    TextTrimming = TextTrimming.CharacterEllipsis
                }
            };
        }

        private void RebuildPeersList(BridgeStatusModel s)
        {
            // Preserve user's in-progress PIN text while updating peer statuses cleanly.
            var staleTrusted = s.Trust.TrustedPeers
                .Where(tp => !s.DiscoveredPeers.Any(d => d.DeviceId == tp.DeviceId && d.Trusted))
                .ToList();
            string peerKey = string.Join("|", s.DiscoveredPeers.Select(p => $"{p.DeviceId}:{p.Ip}:{p.Trusted}:{p.Blocked}"))
                + "##" + string.Join("|", staleTrusted.Select(tp => tp.DeviceId));
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
                var untrustBtn = new Button { Content = "Untrust", Padding = new Thickness(10, 4, 10, 4), FontSize = 11 };
                string devId = tp.DeviceId;
                untrustBtn.Click += (_, _) => RunInvoke("untrust_or_block_peer", new { deviceId = devId, block = false });
                Grid.SetColumn(untrustBtn, 1);
                row.Children.Add(untrustBtn);
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

                if (peer.Trusted)
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

                    var untrustBtn = new Button { Content = "Untrust", Padding = new Thickness(10, 4, 10, 4), FontSize = 11 };
                    string devId = peer.DeviceId;
                    untrustBtn.Click += (_, _) => RunInvoke("untrust_or_block_peer", new { deviceId = devId, block = false });
                    Grid.SetColumn(untrustBtn, 2);
                    row.Children.Add(untrustBtn);
                }
                else
                {
                    string ip = peer.Ip;
                    var pinBox = new TextBox
                    {
                        Width = 86,
                        PlaceholderText = "6-digit PIN",
                        Text = _pinInputs.TryGetValue(ip, out string? existing) ? existing : ""
                    };
                    pinBox.TextChanged += (_, _) => _pinInputs[ip] = pinBox.Text;
                    Grid.SetColumn(pinBox, 1);
                    row.Children.Add(pinBox);

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
                        RunInvoke("pair_with_peer", new { ip, pin = entered });
                    };
                    Grid.SetColumn(pairBtn, 2);
                    row.Children.Add(pairBtn);
                }

                PeersListPanel.Children.Add(row);
            }
        }

        private void RebuildLogsPanel(List<LogEntryModel> logs)
        {
            var tail = logs.Count > 60 ? logs.Skip(logs.Count - 60).ToList() : logs;
            LogsCountText.Text = tail.Count + " lines";
            LogsListPanel.Children.Clear();
            foreach (var entry in tail)
            {
                Color color = entry.Level switch
                {
                    "ERROR" => Color.FromArgb(255, 255, 107, 107),
                    "WARN" => Color.FromArgb(255, 255, 196, 61),
                    _ => Color.FromArgb(230, 235, 240, 245)
                };
                LogsListPanel.Children.Add(new TextBlock
                {
                    Text = $"[{entry.Level}] {entry.Message}",
                    FontFamily = new FontFamily("Consolas"),
                    FontSize = 11,
                    Foreground = new SolidColorBrush(color),
                    TextWrapping = TextWrapping.Wrap
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

        private async void RunInvoke(string method, object? parameters = null, bool refreshAfter = true)
        {
            var res = await Task.Run(() => CoreBridge.Invoke<JsonElement>(method, parameters));
            if (!res.Ok && !string.IsNullOrWhiteSpace(res.Error))
            {
                ShowToast(res.Error!, "warn");
            }
            if (refreshAfter)
            {
                await RefreshStatusAsync();
            }
        }

        private void RefreshBtn_Click(object sender, RoutedEventArgs e) => _ = RefreshStatusAsync();
        private void OpenCacheBtn_Click(object sender, RoutedEventArgs e) => RunInvoke("open_cache_folder", refreshAfter: false);
        private void HideWindowBtn_Click(object sender, RoutedEventArgs e) => AppWindow.Hide();

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
                    _ => enabled
                };
                if (current == enabled) return;
                RunInvoke("set_feature_flag", new { feature, enabled });
            }
        }

        private void ExtendMacToPc_Click(object sender, RoutedEventArgs e) => RunInvoke("toggle_mac_to_pc");
        private void ExtendPcToMac_Click(object sender, RoutedEventArgs e) => RunInvoke("toggle_pc_to_mac");

        private void ApplyGpu_Click(object sender, RoutedEventArgs e)
        {
            string enc = (EncodeGpuCombo.SelectedItem as ComboBoxItem)?.Tag as string ?? "auto";
            string dec = (DecodeGpuCombo.SelectedItem as ComboBoxItem)?.Tag as string ?? "auto";
            RunInvoke("set_gpu_preferences", new { encodeGpu = enc, decodeGpu = dec });
        }

        private async void QueryGpu_Click(object sender, RoutedEventArgs e)
        {
            var res = await Task.Run(() => CoreBridge.Invoke<GpuTelemetryModel>("get_gpu_telemetry"));
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
                ShowToast(res.Error ?? "GPU telemetry unavailable", "warn");
            }
        }

        private void EdgeBtn_Click(object sender, RoutedEventArgs e)
        {
            if (_applyingStatus) return;
            if (sender is Button btn && btn.Tag is string edge)
            {
                _kvmLayout.PeerEdge = edge;
                _kvmLayoutDirty = true;
                ApplyKvmLayoutControls(_status ?? new BridgeStatusModel());
                SaveKvmLayoutInternal();
            }
        }

        private void KvmSlider_ValueChanged(object sender, Microsoft.UI.Xaml.Controls.Primitives.RangeBaseValueChangedEventArgs e)
        {
            if (_applyingStatus || _status == null || AlignmentValueText == null || HopDelayValueText == null) return;
            _kvmLayout.AlignmentOffset = (float)AlignmentSlider.Value;
            _kvmLayout.HopDelayMs = (uint)HopDelaySlider.Value;
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
            _kvmLayoutDirty = false;
            RunInvoke("set_kvm_layout", new { layout = _kvmLayout });
            ShowToast("KVM layout & drop preferences synced", "info");
        }

        private void ReleaseKvm_Click(object sender, RoutedEventArgs e) => RunInvoke("release_kvm_control");
        private void PasteRemote_Click(object sender, RoutedEventArgs e) => RunInvoke("paste_remote");
        private void RegenPin_Click(object sender, RoutedEventArgs e) => RunInvoke("regenerate_pairing_pin");

        private void AddManualIp_Click(object sender, RoutedEventArgs e)
        {
            string ip = ManualIpInput.Text.Trim();
            if (string.IsNullOrEmpty(ip)) return;
            ManualIpInput.Text = string.Empty;
            RunInvoke("add_manual_peer_ip", new { ip });
        }

        private async void RunSpeedTest_Click(object sender, RoutedEventArgs e)
        {
            BtnSpeedTest.IsEnabled = false;
            BtnSpeedTest.Content = "Benchmarking...";
            var res = await Task.Run(() => CoreBridge.Invoke<SpeedTestResultModel>("run_speed_test"));
            BtnSpeedTest.IsEnabled = true;
            BtnSpeedTest.Content = "Run Live Speed Test";
            if (res.Ok && res.Data != null)
            {
                SpeedBenchmarkText.Text = string.Format(
                    CultureInfo.InvariantCulture,
                    "{0}  (Peak {1:0.00} Gbps, RTT {2:0.0} ms)",
                    res.Data.Summary, res.Data.MaxGbps, res.Data.LatencyMs);
                SpeedBenchmarkText.Visibility = Visibility.Visible;
            }
            else
            {
                ShowToast(res.Error ?? "Speed test failed", "warn");
            }
        }

        private void SetShare_Click(object sender, RoutedEventArgs e)
        {
            string trimmed = PreferredShareInput.Text.Trim();
            string? share = string.IsNullOrEmpty(trimmed) ? null : trimmed;
            RunInvoke("set_preferred_peer_share", new { share });
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
            ToastDot.Fill = new SolidColorBrush(level == "warn"
                ? Color.FromArgb(255, 232, 158, 27)
                : Color.FromArgb(255, 24, 180, 212));
            ToastBanner.Visibility = Visibility.Visible;

            _toastTimer?.Stop();
            _toastTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(4) };
            _toastTimer.Tick += (_, _) =>
            {
                _toastTimer?.Stop();
                ToastBanner.Visibility = Visibility.Collapsed;
            };
            _toastTimer.Start();
        }
    }
}
