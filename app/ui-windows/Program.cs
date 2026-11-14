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

            // Focus existing tray/window instance if already running.
            if (CoreBridge.TryFocusExisting())
            {
                return 0;
            }

            ComWrappersSupport.InitializeComWrappers();

            if (!CoreBridge.Initialize())
            {
                return 1;
            }

            try
            {
                Application.Start((p) =>
                {
                    var context = new DispatcherQueueSynchronizationContext(
                        DispatcherQueue.GetForCurrentThread());
                    SynchronizationContext.SetSynchronizationContext(context);
                    new App();
                });
            }
            finally
            {
                CoreBridge.Shutdown();
            }

            return 0;
        }
    }
}
