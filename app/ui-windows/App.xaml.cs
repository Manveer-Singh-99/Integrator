// ==============================================================================================
// Integrator Windows Application Lifecycle & Event Dispatcher (`ui-windows/App.xaml.cs`)
//
// 1. Module Purpose & System Scope:
//    - Represents the top-level WinUI 3 `Application` container for the Integrator desktop client.
//    - Manages the lifecycle of the primary window (`MainWindow`) and the native Win32 system tray
//      notification icon (`TrayIconManager`).
//    - Bridges asynchronous reverse events received from `integrator_core.dll` via `CoreBridge.UiEventReceived`
//      onto the WinUI 3 UI DispatcherQueue.
//
// 2. Architectural Linkages & Native Core Bridge:
//    - Upstream Caller: `Program.cs` instantiates `App` inside `Application.Start`.
//    - Downstream Components:
//        * `MainWindow`: The primary XAML dashboard displaying all 13 subsystem cards.
//        * `TrayIconManager`: Pure Win32 `Shell_NotifyIconW` tray icon and context menu.
//        * `CoreBridge`: Static P/Invoke bridge into `integrator_core.dll`.
//    - Cross-Platform & Remote Coordination:
//        * Listens for core-driven window commands (`show_window`, `hide_window`) triggered by global hotkeys
//          or secondary instance activations.
//        * Forwards remote notifications (e.g., peer discovery, pairing requests, toasts) to the active window.
//
// 3. Threading & Concurrency Model:
//    - STA Thread Affinity: All WinUI 3 controls, windows, and timers must be accessed exclusively on the
//      Single-Threaded Apartment (STA) UI thread.
//    - Cross-Thread Marshaling: Native C-ABI callback events originate from background Tokio threads in Rust.
//      The `_uiEventHandler` uses `_window.DispatcherQueue.TryEnqueue(...)` to safely marshal payloads
//      onto the UI thread without risking deadlocks or COM RPC apartment violations.
//
// 4. Security & Safety Invariants:
//    - Idempotent Shutdown: The `_exiting` atomic guard prevents re-entrant teardown during simultaneous
//      tray exit clicks, window close events, and native core termination signals.
//    - Clean Native Teardown: Unregisters C-ABI callbacks and disposes the Win32 notification icon before
//      invoking `CoreBridge.Shutdown()`, ensuring zero memory or resource leaks.
// ==============================================================================================

using System;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;

namespace IntegratorUI
{
    /// <summary>
    /// Provides application-specific behavior to supplement the default Application class.
    /// Manages window lifecycle, system tray integration, and reverse C-ABI event marshaling.
    /// </summary>
    public partial class App : Application
    {
        /// <summary>
        /// Main application dashboard window instance.
        /// </summary>
        private MainWindow? _window;

        /// <summary>
        /// Native Win32 notification icon manager in the Windows taskbar system tray.
        /// </summary>
        private TrayIconManager? _tray;

        /// <summary>
        /// Indicates whether the application was launched in headless/minimized mode.
        /// </summary>
        private readonly bool _startHidden;

        /// <summary>
        /// Strongly held event handler delegate for reverse core notifications, preventing GC collection.
        /// </summary>
        private System.Action<string, string>? _uiEventHandler;

        /// <summary>
        /// Reentrancy guard ensuring application exit sequence runs exactly once.
        /// </summary>
        private bool _exiting;

        /// <summary>
        /// Initializes the singleton application object with default visible window presentation.
        /// </summary>
        public App() : this(false) { }

        /// <summary>
        /// Initializes the singleton application object with configurable startup visibility.
        /// </summary>
        /// <param name="startHidden">True to launch minimized directly to the system tray.</param>
        public App(bool startHidden)
        {
            _startHidden = startHidden;
            InitializeComponent();
        }

        /// <summary>
        /// Invoked when the application is launched normally by the end user or Windows startup.
        /// </summary>
        /// <param name="args">Details about the launch request and process activation.</param>
        protected override void OnLaunched(LaunchActivatedEventArgs args)
        {
            // 1. Construct the main dashboard window and capture its STA DispatcherQueue
            _window = new MainWindow(this, _startHidden);
            DispatcherQueue dispatcher = _window.DispatcherQueue;

            // 2. Initialize the native Win32 system tray icon with action callbacks
            _tray = new TrayIconManager(
                onShowWindow: () => dispatcher.TryEnqueue(ShowMainWindow),
                onQuit: () => dispatcher.TryEnqueue(ExitApplication)
            );

            // 3. Register reverse event handler for asynchronous events pushed from integrator_core.dll
            _uiEventHandler = (evt, payload) =>
            {
                // High-frequency log entry pushes are ignored at the boundary; UI polls logs on a timer.
                if (evt == "log_entry") { return; }

                // Marshal all other events (window visibility, toasts, quit) onto the WinUI STA thread.
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

            // 4. Present or hide the main window based on launch flags
            if (_startHidden)
            {
                _window.HideToTray();
            }
            else
            {
                _window.Activate();
            }
        }

        /// <summary>
        /// Restores and activates the main dashboard window, bringing it to the foreground.
        /// </summary>
        public void ShowMainWindow()
        {
            _window?.RestoreAndActivate();
        }

        /// <summary>
        /// Initiates normal user-requested application termination sequence.
        /// </summary>
        public void ExitApplication() => ExitApplication(fromCoreQuitEvent: false);

        /// <summary>
        /// Coordinates graceful shutdown of the window, system tray icon, and native Rust backend.
        /// </summary>
        /// <param name="fromCoreQuitEvent">True if shutdown was triggered by a core termination event.</param>
        private void ExitApplication(bool fromCoreQuitEvent)
        {
            if (_exiting) { return; }
            _exiting = true;

            // Unsubscribe reverse event callback to prevent invoking disposed dispatchers
            if (_uiEventHandler != null)
            {
                CoreBridge.UiEventReceived -= _uiEventHandler;
                _uiEventHandler = null;
            }

            // Cleanup window timers and event subscriptions
            try
            {
                _window?.CleanupForExit();
            }
            catch { }

            // Destroy the Win32 notification icon and unregister its window class
            try
            {
                _tray?.Dispose();
                _tray = null;
            }
            catch { }

            // Notify core backend of user exit if initiated from UI
            if (!fromCoreQuitEvent)
            {
                try
                {
                    CoreBridge.TrayAction("quit");
                }
                catch { }
            }

            // Perform synchronous shutdown of Rust runtime (Tokio listeners, network sockets)
            CoreBridge.Shutdown();

            // Terminate WinUI 3 application message loop
            Exit();
        }
    }
}
