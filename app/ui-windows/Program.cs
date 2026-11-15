using System;
using System.Threading;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using WinRT;

namespace IntegratorUI
{
    public static class Program
    {
        [STAThread]
        public static int Main(string[] args)
        {
            // Handle CLI helpers (--mount-helper, --clipboard-helper, etc.) without booting WinUI.
            int cliRc = CoreBridge.RunCliIfRequested(args);
            if (cliRc >= 0)
            {
                return cliRc;
            }

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

            using var singleInstanceMutex = new System.Threading.Mutex(
                initiallyOwned: true,
                name: @"Local\IntegratorUI_SingleInstance_Mutex",
                createdNew: out bool createdNew);

            if (!createdNew)
            {
                // Focus existing tray/window instance if launched interactively.
                if (!startHidden)
                {
                    CoreBridge.TryFocusExisting();
                }
                return 0;
            }

            ComWrappersSupport.InitializeComWrappers();

            if (!CoreBridge.Initialize())
            {
                MessageBoxW(
                    System.IntPtr.Zero,
                    "Integrator failed to initialize the core backend (integrator_core.dll).\n\nPlease verify that integrator_core.dll is present alongside IntegratorUI.exe and check the application logs.",
                    "Integrator — Startup Error",
                    0x00000010u);
                try { singleInstanceMutex.ReleaseMutex(); } catch { }
                return 1;
            }

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
                CoreBridge.Shutdown();
                try { singleInstanceMutex.ReleaseMutex(); } catch { }
            }

            return 0;
        }

        [System.Runtime.InteropServices.DllImport("user32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
        private static extern int MessageBoxW(System.IntPtr hWnd, string text, string caption, uint type);
    }
}
