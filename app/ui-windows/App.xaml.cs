using System;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;

namespace IntegratorUI
{
    public partial class App : Application
    {
        private MainWindow? _window;
        private TrayIconManager? _tray;

        public App()
        {
            InitializeComponent();
        }

        protected override void OnLaunched(LaunchActivatedEventArgs args)
        {
            _window = new MainWindow(this);
            DispatcherQueue dispatcher = _window.DispatcherQueue;

            _tray = new TrayIconManager(
                onShowWindow: () => dispatcher.TryEnqueue(ShowMainWindow),
                onQuit: () => dispatcher.TryEnqueue(ExitApplication)
            );

            CoreBridge.UiEventReceived += (evt, payload) =>
            {
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
                    else
                    {
                        _window?.HandleCoreEvent(evt, payload);
                    }
                });
            };

            _window.Activate();
        }

        public void ShowMainWindow()
        {
            _window?.RestoreAndActivate();
        }

        public void ExitApplication()
        {
            try
            {
                _tray?.Dispose();
                _tray = null;
            }
            catch { }

            try
            {
                CoreBridge.TrayAction("quit");
            }
            catch { }

            Exit();
        }
    }
}
