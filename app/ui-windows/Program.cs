// ==============================================================================================
// Integrator Windows Native Client Bootstrap & Single-Instance Controller (`ui-windows/Program.cs`)
//
// 1. Module Purpose & System Scope:
//    - Serves as the native process entry point (`Main`) for the Integrator WinUI 3 desktop client.
//    - Enforces single-instance execution via a Win32 Named Mutex (`Local\IntegratorUI_SingleInstance_Mutex`).
//    - Intercepts and executes CLI helper routines (`--mount-helper`, `--clipboard-helper`) via `CoreBridge`
//      without incurring the overhead of initializing XAML / WinUI 3 composition engines.
//    - Initializes COM interop (`ComWrappersSupport`) and bootstraps the WinUI 3 application lifecycle
//      with an STA-bound `DispatcherQueueSynchronizationContext`.
//
// 2. Architectural Linkages & Native Core Bridge:
//    - Upstream Caller: Operating system process loader (executing `IntegratorUI.exe`).
//    - Downstream Core: Interacts with `integrator_core.dll` via `CoreBridge.RunCliIfRequested`,
//      `CoreBridge.TryFocusExisting`, `CoreBridge.Initialize`, and `CoreBridge.Shutdown`.
//    - Downstream UI: Hands execution to `IntegratorUI.App` inside `Microsoft.UI.Xaml.Application.Start`.
//    - Native Win32 Subsystems:
//        * Win32 Kernel32: Named Mutex for single-instance inter-process synchronization.
//        * Win32 User32: `MessageBoxW` for early fatal startup error reporting before XAML is initialized.
//
// 3. Threading & Concurrency Model:
//    - Single-Threaded Apartment (`[STAThread]`): Required unconditionally by WinUI 3 and Windows App SDK.
//    - Synchronization Context: Replaces the default STA context with `DispatcherQueueSynchronizationContext`
//      bound to the current thread's `DispatcherQueue` prior to constructing `App`.
//
// 4. Security & Safety Invariants:
//    - Re-entrancy & Process Contention: Ensures only one instance of Integrator runs per Windows session,
//      preventing port collisions on TCP :58281-:58287 and conflicting low-level keyboard/mouse hooks.
//    - Graceful Teardown: Guaranteed cleanup of the named mutex and native Rust runtime via `try/finally`.
//    - Error Containment: Surfaces missing or corrupted `integrator_core.dll` binaries cleanly using a modal
//      Win32 message dialog rather than terminating abruptly with unhandled Win32/SEH exceptions.
// ==============================================================================================

using System;
using System.Threading;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using WinRT;

namespace IntegratorUI
{
    /// <summary>
    /// Application entry class responsible for process bootstrapping, command-line routing,
    /// single-instance enforcement, and WinUI 3 runtime initialization.
    /// </summary>
    public static class Program
    {
        /// <summary>Win32 MessageBox style flag rendering a stop-sign error icon.</summary>
        private const uint MB_ICONERROR = 0x00000010u;

        /// <summary>
        /// Main application entry point running in a Single-Threaded Apartment (STA).
        /// </summary>
        /// <param name="args">Command-line arguments passed to the process.</param>
        /// <returns>Exit code: 0 on clean exit, non-zero on startup failure or CLI execution.</returns>
        [STAThread]
        public static int Main(string[] args)
        {
            // 1. Check for command-line helper modes (e.g., --mount-helper, --clipboard-helper).
            // These sub-commands run headlessly inside the Rust core without loading XAML/WinUI 3.
            int cliRc = CoreBridge.RunCliIfRequested(args);
            if (cliRc >= 0)
            {
                return cliRc;
            }

            // 2. Parse startup flags for background / minimized mode (e.g., launched at Windows login).
            bool startHidden = false;
            foreach (string arg in args)
            {
                if (string.Equals(arg, "--minimized", System.StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(arg, "--hidden", System.StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(arg, "--daemon", System.StringComparison.OrdinalIgnoreCase))
                {
                    startHidden = true;
                    break;
                }
            }

            // 3. Enforce single-instance execution per Windows logon session using a named Win32 Mutex.
            using var singleInstanceMutex = new System.Threading.Mutex(
                initiallyOwned: true,
                name: @"Local\IntegratorUI_SingleInstance_Mutex",
                createdNew: out bool createdNew);

            if (!createdNew)
            {
                // Another instance is already running. If the user launched interactively (not hidden),
                // request the existing instance to unhide and focus its dashboard window.
                if (!startHidden)
                {
                    CoreBridge.TryFocusExisting();
                }
                return 0;
            }

            // 4. Initialize Windows Runtime COM interop wrappers for Windows App SDK / WinUI 3.
            ComWrappersSupport.InitializeComWrappers();

            // 5. Initialize the native Rust core library (integrator_core.dll).
            // This loads Tokio runtimes, keystores, and network discovery beacons.
            if (!CoreBridge.Initialize())
            {
                MessageBoxW(
                    System.IntPtr.Zero,
                    "Integrator failed to initialize the core backend (integrator_core.dll).\n\nPlease verify that integrator_core.dll is present alongside IntegratorUI.exe and check the application logs.",
                    "Integrator — Startup Error",
                    MB_ICONERROR);
                try { singleInstanceMutex.ReleaseMutex(); } catch { }
                return 1;
            }

            // 6. Enter the WinUI 3 XAML Application message pump with an STA dispatcher context.
            try
            {
                Application.Start((p) =>
                {
                    var context = new DispatcherQueueSynchronizationContext(
                        DispatcherQueue.GetForCurrentThread());
                    SynchronizationContext.SetSynchronizationContext(context);
                    new App(startHidden);
                });
            }
            finally
            {
                // Ensure native core shutdown and mutex release on process termination.
                CoreBridge.Shutdown();
                try { singleInstanceMutex.ReleaseMutex(); } catch { }
            }

            return 0;
        }

        /// <summary>
        /// Win32 User32 modal message dialog used for early fatal error presentation prior to XAML init.
        /// </summary>
        /// <param name="hWnd">Parent window handle (IntPtr.Zero for desktop-anchored).</param>
        /// <param name="text">Dialog message body text.</param>
        /// <param name="caption">Dialog title caption.</param>
        /// <param name="type">Win32 MB_* style flags (e.g., MB_ICONERROR = 0x10).</param>
        /// <returns>Win32 dialog result code.</returns>
        [System.Runtime.InteropServices.DllImport("user32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
        private static extern int MessageBoxW(System.IntPtr hWnd, string text, string caption, uint type);
    }
}
