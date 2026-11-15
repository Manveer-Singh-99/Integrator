using System;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;

namespace IntegratorUI
{
    public partial class App : Application
    {
        private MainWindow? _window;
        private TrayIconManager? _tray;

        private readonly bool _startHidden;
        private System.Action<string, string>? _uiEventHandler;
        private bool _exiting;

        public App() : this(false) { }

        public App(bool startHidden)
        {
            _startHidden = startHidden;
            InitializeComponent();
        }

        protected override void OnLaunched(LaunchActivatedEventArgs args)
        {
            _window = new MainWindow(this, _startHidden);
            DispatcherQueue dispatcher = _window.DispatcherQueue;

            _tray = new TrayIconManager(
                onShowWindow: () => dispatcher.TryEnqueue(ShowMainWindow),
                onQuit: () => dispatcher.TryEnqueue(ExitApplication)
            );

            _uiEventHandler = (evt, payload) =>
            {
                // Ignore high-frequency log_entry pushes; UI polls snapshots cleanly.
                if (evt == "log_entry") { return; }
                dispatcher.TryEnqueue(() =>
                {
                    if (evt == "show_window" || evt == "show-window")
                    {
                        ShowMainWindow();
                    }
                    else if (evt == "hide_window" || evt == "hide-window")
                    {
                        _window?.HideToTray();
                    }
                    else if (evt == "quit" || evt == "exit")
                    {
                        ExitApplication(fromCoreQuitEvent: true);
                    }
                    else
                    {
                        _window?.HandleCoreEvent(evt, payload);
                    }
                });
            };
            CoreBridge.UiEventReceived += _uiEventHandler;

            if (_startHidden)
            {
                _window.HideToTray();
            }
            else
            {
                _window.Activate();
            }
        }

        public void ShowMainWindow()
        {
            _window?.RestoreAndActivate();
        }

        public void ExitApplication() => ExitApplication(fromCoreQuitEvent: false);

        private void ExitApplication(bool fromCoreQuitEvent)
        {
            if (_exiting) { return; }
            _exiting = true;

            if (_uiEventHandler != null)
            {
                CoreBridge.UiEventReceived -= _uiEventHandler;
                _uiEventHandler = null;
            }

            try
            {
                _window?.CleanupForExit();
            }
            catch { }

            try
            {
                _tray?.Dispose();
                _tray = null;
            }
            catch { }

            if (!fromCoreQuitEvent)
            {
                try
                {
                    CoreBridge.TrayAction("quit");
                }
                catch { }
            }

            CoreBridge.Shutdown();
            Exit();
        }
    }
}
