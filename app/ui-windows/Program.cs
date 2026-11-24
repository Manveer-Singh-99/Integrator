// ==============================================================================================
// Integrator Windows Native Client Bootstrap & Single-Instance Controller (`ui-windows/Program.cs`)
//
// 1. Module Purpose & System Scope:
//    - Serves as the native process entry point (`Main`) for the Integrator WinUI 3 desktop client.
//    - Enforces single-instance execution per Windows logon session via a Win32 Named Mutex
//      (`Local\IntegratorUI_SingleInstance_Mutex`).
//    - Intercepts and executes CLI helper routines (`--mount-helper`, `--clipboard-helper`) via `CoreBridge`
//      without incurring the memory or latency overhead of initializing XAML / WinUI 3 composition engines.
//    - Initializes Windows Runtime COM interop (`ComWrappersSupport`) and bootstraps the WinUI 3 application
//      lifecycle with an STA-bound `DispatcherQueueSynchronizationContext`.
//
// 2. Architectural Linkages & Dependencies:
//    - Upstream Caller: Operating system process loader (executing `Integrator.exe` / `IntegratorUI.exe`).
//    - Downstream Callees:
//        * `CoreBridge`: Static P/Invoke bridge into `integrator_core.dll` (`RunCliIfRequested`,
//          `TryFocusExisting`, `Initialize`, `Shutdown`).
//        * `PasskeyAuthenticatorPlugin`: Revokes any in-process COM passkey class registration on exit.
//        * `IntegratorUI.App`: Top-level WinUI 3 `Application` instantiated inside `Application.Start`.
//        * Win32 `kernel32.dll` (via `System.Threading.Mutex`): Named Mutex for single-instance synchronization.
//        * Win32 `user32.dll` (`MessageBoxW`): Modal error dialog for early fatal startup failures prior to XAML init.
//    - Cross-Platform / Cross-Device Flow:
//        * Calling `CoreBridge.Initialize()` launches the embedded Rust Tokio runtime, UDP/mDNS/BLE discovery
//          listeners (:58280), encrypted `TransportSessionV2` control server (:58281), KVM server (:58282),
//          clipboard/drag-drop server (:58283), spatial audio UDP sink (:58284), and virtual camera bridge (:58287)
//          that communicate with the paired macOS workstation.
//
// 3. Threading & Concurrency Model:
//    - Single-Threaded Apartment (`[STAThread]`): Required unconditionally by WinUI 3, Windows App SDK,
//      and OLE/COM drag-and-drop / clipboard operations.
//    - Synchronization Context: Replaces the default STA synchronization context with a
//      `DispatcherQueueSynchronizationContext` bound to the current thread's `DispatcherQueue` prior to
//      constructing `App`, ensuring all `async`/`await` continuations resume on the WinUI 3 STA thread.
//
// 4. Security & Safety Invariants:
//    - Session-Scoped Process Contention Prevention: Uses the `Local\` kernel object namespace to ensure
//      only one instance of Integrator runs per interactive Windows user session, preventing port collisions
//      on TCP :58281-:58287 / UDP :58280-:58284 and conflicting low-level `WH_KEYBOARD_LL`/`WH_MOUSE_LL` hooks.
//    - DLL Hijacking Mitigation: P/Invoke into `user32.dll` is hardened with
//      `[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]`.
//    - Guaranteed Resource Teardown: Ensures deterministic cleanup of the named mutex, passkey COM registration,
//      and native Rust runtime via `try/finally` blocks even if unhandled exceptions terminate the message pump.
//    - Error Containment: Surfaces missing or corrupted `integrator_core.dll` binaries cleanly using a modal
//      Win32 message dialog rather than terminating silently or crashing with unhandled SEH exceptions.
// ==============================================================================================

using System;
using System.Runtime.InteropServices;
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
        /// <summary>
        /// Win32 <c>MessageBoxW</c> style flag (<c>MB_OK | MB_ICONERROR</c> = <c>0x00000010</c>, defined in <c>winuser.h</c>)
        /// rendering a modal dialog with a single OK button and a stop-sign error icon.
        /// </summary>
        private const uint MB_ICONERROR = 0x00000010u;

        /// <summary>
        /// Win32 session-local named mutex path enforcing single-instance execution per user logon session.
        /// The <c>Local\</c> prefix scopes the kernel object to the current Terminal Services session rather than
        /// <c>Global\</c>, avoiding cross-session denial-of-service on multi-user workstations.
        /// </summary>
        private const string SingleInstanceMutexName = @"Local\IntegratorUI_SingleInstance_Mutex";

        /// <summary>
        /// Main application entry point running in a Single-Threaded Apartment (STA).
        /// Evaluates headless CLI helper flags, enforces single-instance mutex ownership, initializes
        /// <c>integrator_core.dll</c>, and runs the WinUI 3 XAML message pump until exit.
        /// </summary>
        /// <param name="args">Command-line arguments passed to the process by the OS loader.</param>
        /// <returns>
        /// Process exit code: <c>0</c> on normal UI shutdown or secondary-instance focus handoff;
        /// <c>1</c> if <c>integrator_core.dll</c> fails initialization; or the sub-command exit code (<c>&gt;= 0</c>)
        /// when invoked in headless CLI helper mode.
        /// </returns>
        [STAThread]
        public static int Main(string[] args)
        {
            // 1. Check for command-line helper modes (e.g., --mount-helper, --clipboard-helper).
            // These sub-commands run headlessly inside the Rust core without loading XAML/WinUI 3.
            // A negative return code (-1) indicates no CLI helper mode matched and normal UI boot should proceed.
            int cliRc = CoreBridge.RunCliIfRequested(args ?? Array.Empty<string>());
            if (cliRc >= 0)
            {
                return cliRc;
            }

            // 2. Parse startup flags for background / minimized mode (e.g., launched at Windows login via Run key).
            bool startHidden = false;
            if (args != null)
            {
                foreach (string arg in args)
                {
                    if (string.Equals(arg, "--minimized", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(arg, "--hidden", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(arg, "--daemon", StringComparison.OrdinalIgnoreCase))
                    {
                        startHidden = true;
                        break;
                    }
                }
            }

            // 3. Enforce single-instance execution per Windows logon session using a named Win32 Mutex.
            using var singleInstanceMutex = new Mutex(
                initiallyOwned: true,
                name: SingleInstanceMutexName,
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
            // This loads Tokio runtimes, DPAPI keystores, and network discovery beacons.
            if (!CoreBridge.Initialize())
            {
                MessageBoxW(
                    IntPtr.Zero,
                    "Integrator failed to initialize the core backend (integrator_core.dll).\n\nPlease verify that integrator_core.dll is present alongside IntegratorUI.exe and check the application logs.",
                    "Integrator — Startup Error",
                    MB_ICONERROR);
                try { singleInstanceMutex.ReleaseMutex(); } catch { }
                return 1;
            }

            // 5.1 Passkey COM hosting runs in dedicated Medium-IL packaged IntegratorPasskeyHost.exe
            // (registered via Integrator.PasskeyProvider sparse MSIX windows.comServer).

            // 6. Enter the WinUI 3 XAML Application message pump with an STA dispatcher context.
            try
            {
                Application.Start((p) =>
                {
                    DispatcherQueue? queue = DispatcherQueue.GetForCurrentThread();
                    if (queue != null)
                    {
                        var context = new DispatcherQueueSynchronizationContext(queue);
                        SynchronizationContext.SetSynchronizationContext(context);
                    }
                    _ = new App(startHidden);
                });
            }
            finally
            {
                // Ensure passkey plugin revocation, native core shutdown, and mutex release on process termination.
                try { PasskeyAuthenticatorPlugin.Shutdown(); } catch { }
                CoreBridge.Shutdown();
                try { singleInstanceMutex.ReleaseMutex(); } catch { }
            }

            return 0;
        }

        /// <summary>
        /// Win32 <c>user32.dll</c> modal message dialog used for early fatal error presentation prior to XAML initialization.
        /// Restricted to <see cref="DllImportSearchPath.System32"/> to prevent DLL search-order hijacking.
        /// </summary>
        /// <param name="hWnd">Parent window handle (<see cref="IntPtr.Zero"/> for desktop-anchored modal dialog).</param>
        /// <param name="text">Null-terminated UTF-16 dialog message body text.</param>
        /// <param name="caption">Null-terminated UTF-16 dialog title bar caption.</param>
        /// <param name="type">Bitmask of Win32 <c>MB_*</c> button and icon style flags (e.g., <see cref="MB_ICONERROR"/> = <c>0x10</c>).</param>
        /// <returns>Win32 dialog button selection identifier (e.g., <c>IDOK = 1</c>, or <c>0</c> on failure).</returns>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int MessageBoxW(IntPtr hWnd, string text, string caption, uint type);
    }
}
