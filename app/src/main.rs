#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use anyhow::Result;
use integrator_core::core;

#[cfg(target_os = "macos")]
extern "C" {
    fn integrator_macos_run_app(is_hidden: bool);
}

fn main() -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        std::hint::black_box((
            integrator_core::ffi::integrator_core_invoke as *const (),
            integrator_core::ffi::integrator_core_free_string as *const (),
            integrator_core::ffi::integrator_core_tray_action as *const (),
            integrator_core::ffi::integrator_core_shutdown as *const (),
            integrator_core::ffi::integrator_core_set_ui_callback as *const (),
        ));
    }
    let args: Vec<String> = std::env::args().collect();

    if let Some(cli_res) = core::run_cli_if_requested(&args) {
        return cli_res;
    }

    if core::try_focus_existing_instance() {
        println!("Existing Integrator instance is already running. Brought window to front.");
        return Ok(());
    }

    let _core = core::IntegratorCore::init_global()?;

    let is_hidden = args
        .iter()
        .any(|a| a == "--hidden" || a == "--daemon" || a == "--minimized");

    #[cfg(target_os = "macos")]
    unsafe {
        integrator_macos_run_app(is_hidden);
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = is_hidden;
        // On Windows, native WinUI 3 (`app/ui-windows/Integrator.exe`) hosts `integrator_core.dll` directly.
        // If `integrator.exe` CLI binary is run standalone as a headless daemon, park cleanly.
        loop {
            std::thread::sleep(std::time::Duration::from_secs(60));
        }
    }

    Ok(())
}
