// ==============================================================================================
// Integrator Windows Application Lifecycle & Event Dispatcher (`ui-windows/App.xaml.cs`)
//
// 1. Module Purpose & System Scope:
//    - Represents the top-level WinUI 3 `Application` container for the Integrator desktop client.
//    - Manages the lifecycle of the primary window (`MainWindow`) and the native Win32 system tray
//      notification icon (`TrayIconManager`).
//    - Bridges asynchronous reverse events received from `integrator_core.dll` via `CoreBridge.UiEventReceived`
//      onto the WinUI 3 UI `DispatcherQueue`.
//
// 2. Architectural Linkages & Dependencies:
//    - Upstream Callers:
//        * `Program.cs`: Instantiates `App` inside `Microsoft.UI.Xaml.Application.Start` on the STA thread.
//        * `MainWindow.xaml.cs`: Calls `RequestQuit`, `ExitApplication`, `DisposeTrayIcon`,
//          `TerminateSessionPasskeyHosts`, and `FinishExitAfterVisualShutdown` during shutdown workflows.
//        * `TrayIconManager.cs`: Invokes `ShowMainWindow` and `RequestQuit` callbacks on tray interactions.
//    - Downstream Callees:
//        * `MainWindow`: The primary XAML dashboard displaying all 13 subsystem cards.
//        * `TrayIconManager`: Pure Win32 `Shell_NotifyIconW` tray icon and context menu.
//        * `CoreBridge`: Static P/Invoke bridge into `integrator_core.dll` (`TrayAction`, `Shutdown`).
//        * `PasskeyAuthenticatorPlugin`: In-process COM passkey revocation during application exit.
//    - Cross-Platform / Cross-Device Flow:
//        * Listens for core-driven window commands (`show_window`, `hide_window`, `quit`) triggered by
//          global hotkeys, secondary instance activations, or paired macOS control signals.
//        * Forwards remote peer notifications (e.g., peer discovery, SPAKE2 pairing requests, camera/clipboard
//          toasts received over TCP :58281-:58287 / UDP :58280-:58284) to `MainWindow.HandleCoreEvent`.
//
// 3. Threading & Concurrency Model:
//    - STA Thread Affinity: All WinUI 3 controls, windows, and timers must be accessed exclusively on the
//      Single-Threaded Apartment (STA) UI thread. Public lifecycle entry points (`ShowMainWindow`,
//      `RequestQuit`) verify `DispatcherQueue.HasThreadAccess` and marshal onto the UI thread when invoked
//      from background worker threads.
//    - Cross-Thread Marshaling: Native C-ABI callback events originate from background Tokio worker threads
//      in Rust. The `_uiEventHandler` uses `_window.DispatcherQueue.TryEnqueue(...)` to asynchronously
//      marshal payloads onto the STA UI thread without risking deadlocks or COM RPC apartment violations.
//
// 4. Security & Safety Invariants:
//    - Atomic Idempotent Shutdown: The `_exiting` atomic guard (`Interlocked.Exchange`) prevents re-entrant
//      teardown during simultaneous tray exit clicks, window close events, and native core termination signals.
//    - Clean Native & Helper Teardown: Unregisters C-ABI callbacks, disposes the Win32 notification icon,
//      terminates session-scoped `IntegratorPasskeyHost.exe` COM servers, and invokes `CoreBridge.Shutdown()`,
//      ensuring zero unmanaged memory, socket, or process handle leaks.
// ==============================================================================================

using System;
using System.Threading;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;

namespace IntegratorUI
{
    /// <summary>
    /// Provides application-specific behavior to supplement the default WinUI 3 <see cref="Application"/> class.
    /// Manages window lifecycle, system tray integration, and reverse C-ABI event marshaling.
    /// </summary>
    public partial class App : Application
    {
        /// <summary>
        /// Maximum time in milliseconds (1500 ms, range: 100..5000 ms) to wait for a killed
        /// <c>IntegratorPasskeyHost.exe</c> helper process to release kernel handles during shutdown.
        /// Chosen to keep UI teardown responsive while allowing clean OS handle reclamation.
        /// </summary>
        private const int PasskeyHostWaitForExitTimeoutMs = 1500;

        /// <summary>
        /// Executable base name (without <c>.exe</c> extension) of the out-of-process COM passkey helper.
        /// </summary>
        private const string PasskeyHostProcessName = "IntegratorPasskeyHost";

        /// <summary>
        /// Main application dashboard window instance, created once on the STA thread during <see cref="OnLaunched"/>.
        /// </summary>
        private MainWindow? _window;

        /// <summary>
        /// Native Win32 notification icon manager in the Windows taskbar system tray.
        /// </summary>
        private TrayIconManager? _tray;

        /// <summary>
        /// Indicates whether the application was launched in headless/minimized mode (<c>--minimized</c>, <c>--hidden</c>, <c>--daemon</c>).
        /// </summary>
        private readonly bool _startHidden;

        /// <summary>
        /// Strongly held event handler delegate for reverse core notifications, preventing premature GC collection
        /// while registered with <see cref="CoreBridge.UiEventReceived"/>.
        /// </summary>
        private Action<string, string>? _uiEventHandler;

        /// <summary>
        /// Atomic reentrancy guard (0 = running, 1 = exiting) ensuring the application exit sequence runs at most once.
        /// Manipulated via <see cref="Interlocked.Exchange(ref int, int)"/> and <see cref="Volatile.Read(ref int)"/>.
        /// </summary>
        private int _exiting;

        /// <summary>
        /// Initializes the singleton application object with default visible window presentation.
        /// </summary>
        public App() : this(false) { }

        /// <summary>
        /// Initializes the singleton application object with configurable startup visibility.
        /// </summary>
        /// <param name="startHidden">True to launch minimized directly to the system tray; false to activate the dashboard window.</param>
        public App(bool startHidden)
        {
            _startHidden = startHidden;
            InitializeComponent();
        }

        /// <summary>
        /// Invoked by the WinUI 3 framework on the STA thread when the application is launched.
        /// Initializes <see cref="MainWindow"/>, registers the Win32 system tray icon, wires reverse
        /// C-ABI event listeners from <c>integrator_core.dll</c>, and sets initial window visibility.
        /// </summary>
        /// <param name="args">Details about the launch request and process activation.</param>
        protected override void OnLaunched(LaunchActivatedEventArgs args)
        {
            // 1. Construct the main dashboard window and capture its STA DispatcherQueue
            _window = new MainWindow(this, _startHidden);
            DispatcherQueue dispatcher = _window.DispatcherQueue;

            // 2. Initialize the native Win32 system tray icon with STA-marshaled action callbacks
            _tray = new TrayIconManager(
                onShowWindow: () => dispatcher.TryEnqueue(ShowMainWindow),
                onQuit: () => dispatcher.TryEnqueue(RequestQuit)
            );

            // 3. Register reverse event handler for asynchronous events pushed from integrator_core.dll
            _uiEventHandler = (evt, payload) =>
            {
                // High-frequency log entry pushes are ignored at the event boundary; UI polls logs on a 2s timer.
                if (evt == "log_entry") { return; }

                // Marshal all other events (window visibility, toasts, quit) onto the WinUI STA thread.
                dispatcher.TryEnqueue(() =>
                {
                    if (Volatile.Read(ref _exiting) != 0) { return; }

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
        /// Automatically marshals onto the WinUI 3 STA <see cref="DispatcherQueue"/> if called from a background thread.
        /// </summary>
        public void ShowMainWindow()
        {
            MainWindow? win = _window;
            if (win == null) { return; }

            // Enforce STA UI-thread affinity before touching WinUI 3 window APIs
            DispatcherQueue? dispatcher = win.DispatcherQueue;
            if (dispatcher != null && !dispatcher.HasThreadAccess)
            {
                dispatcher.TryEnqueue(() => win.RestoreAndActivate());
                return;
            }

            win.RestoreAndActivate();
        }

        /// <summary>
        /// Initiates the user-requested quit flow. Displays a quit confirmation dialog (unless suppressed by user preference),
        /// then runs the live step-by-step subsystem shutdown progress modal before terminating the process.
        /// Safe to invoke from any thread; marshals onto the STA UI thread if needed.
        /// </summary>
        public void RequestQuit()
        {
            if (Volatile.Read(ref _exiting) != 0) { return; }

            MainWindow? win = _window;
            if (win != null)
            {
                DispatcherQueue? dispatcher = win.DispatcherQueue;
                if (dispatcher != null && !dispatcher.HasThreadAccess)
                {
                    dispatcher.TryEnqueue(() => _ = win.RequestQuitAsync());
                    return;
                }
                _ = win.RequestQuitAsync();
            }
            else
            {
                ExitApplication(fromCoreQuitEvent: false);
            }
        }

        /// <summary>
        /// Terminates any lingering <c>IntegratorPasskeyHost.exe</c> COM helper processes owned by the current
        /// Windows logon session so no background Integrator helper processes remain running after full Quit.
        /// Explicitly disposes all <see cref="System.Diagnostics.Process"/> handles to prevent kernel handle leaks.
        /// </summary>
        internal static void TerminateSessionPasskeyHosts()
        {
            try
            {
                // Dispose the current process wrapper immediately after reading its Windows Terminal Services session ID.
                using var currentProc = System.Diagnostics.Process.GetCurrentProcess();
                int currentSession = currentProc.SessionId;

                foreach (var proc in System.Diagnostics.Process.GetProcessesByName(PasskeyHostProcessName))
                {
                    try
                    {
                        if (proc.SessionId == currentSession && !proc.HasExited)
                        {
                            proc.Kill();
                            proc.WaitForExit(PasskeyHostWaitForExitTimeoutMs);
                        }
                    }
                    catch
                    {
                        // Ignore access denied or race conditions if the process exited concurrently.
                    }
                    finally
                    {
                        proc.Dispose();
                    }
                }
            }
            catch
            {
                // Swallow process enumeration failures during teardown to guarantee non-throwing exit.
            }
        }

        /// <summary>
        /// Disposes the Win32 system tray icon safely and idempotently during graceful shutdown.
        /// </summary>
        internal void DisposeTrayIcon()
        {
            try
            {
                TrayIconManager? tray = Interlocked.Exchange(ref _tray, null);
                tray?.Dispose();
            }
            catch
            {
                // Never allow tray cleanup errors to interrupt application exit.
            }
        }

        /// <summary>
        /// Completes process exit after <see cref="MainWindow"/> has finished executing and
        /// displaying all interactive subsystem teardown steps.
        /// </summary>
        internal void FinishExitAfterVisualShutdown()
        {
            if (Interlocked.Exchange(ref _exiting, 1) != 0) { return; }

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

            DisposeTrayIcon();

            // Idempotent safety net: ensure passkey COM registration and native Rust runtime are torn down
            try
            {
                PasskeyAuthenticatorPlugin.Shutdown();
            }
            catch { }

            CoreBridge.Shutdown();
            Exit();
        }

        /// <summary>
        /// Initiates the normal user-requested application termination sequence without interactive modal confirmation.
        /// </summary>
        public void ExitApplication() => ExitApplication(fromCoreQuitEvent: false);

        /// <summary>
        /// Coordinates graceful synchronous shutdown of the window, system tray icon, passkey helper processes,
        /// and native Rust backend runtime. Guarded by atomic <see cref="_exiting"/> state to prevent double-dispose.
        /// </summary>
        /// <param name="fromCoreQuitEvent">
        /// True if shutdown was triggered by an incoming core termination event (skipping redundant <c>TrayAction("quit")</c>);
        /// false if initiated from the Windows UI layer.
        /// </param>
        private void ExitApplication(bool fromCoreQuitEvent)
        {
            if (Interlocked.Exchange(ref _exiting, 1) != 0) { return; }

            // 1. Unsubscribe reverse event callback to prevent invoking disposed dispatchers
            if (_uiEventHandler != null)
            {
                CoreBridge.UiEventReceived -= _uiEventHandler;
                _uiEventHandler = null;
            }

            // 2. Cleanup window timers and event subscriptions
            try
            {
                _window?.CleanupForExit();
            }
            catch { }

            // 3. Destroy the Win32 notification icon and unregister its window class
            DisposeTrayIcon();

            // 4. Notify core backend of user exit if initiated from UI
            if (!fromCoreQuitEvent)
            {
                try
                {
                    CoreBridge.TrayAction("quit");
                }
                catch { }
            }

            // 5. Stop Windows passkey COM registration and helper process in this session
            try
            {
                PasskeyAuthenticatorPlugin.Shutdown();
                TerminateSessionPasskeyHosts();
            }
            catch { }

            // 6. Perform synchronous idempotent shutdown of Rust runtime (Tokio listeners, network sockets)
            CoreBridge.Shutdown();

            // 7. Terminate WinUI 3 application message loop
            Exit();
        }
    }
}
