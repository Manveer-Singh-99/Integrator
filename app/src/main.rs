#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;
use integrator_core::{core, ffi};

static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "macos")]
extern "C" {
    fn integrator_macos_run_app(is_hidden: bool);
}

#[cfg(unix)]
extern "C" fn handle_termination_signal(_sig: libc::c_int) {
    SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
}

#[cfg(unix)]
fn install_signal_handlers() {
    // SAFETY: Setting an async-signal-safe AtomicBool handler for SIGINT/SIGTERM.
    unsafe {
        libc::signal(
            libc::SIGINT,
            handle_termination_signal as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGTERM,
            handle_termination_signal as *const () as libc::sighandler_t,
        );
    }
}

#[cfg(not(unix))]
fn install_signal_handlers() {}

fn main() -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        std::hint::black_box((
            ffi::integrator_core_try_focus_existing as *const (),
            ffi::integrator_core_run_cli as *const (),
            ffi::integrator_core_init as *const (),
            ffi::integrator_core_set_ui_callback as *const (),
            ffi::integrator_core_invoke as *const (),
            ffi::integrator_core_free_string as *const (),
            ffi::integrator_core_tray_action as *const (),
            ffi::integrator_core_shutdown as *const (),
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

    install_signal_handlers();

    let core_instance = core::IntegratorCore::init_global()?;

    let is_hidden = args
        .iter()
        .any(|a| a == "--hidden" || a == "--daemon" || a == "--minimized");

    #[cfg(unix)]
    {
        let core_for_sig = std::sync::Arc::clone(&core_instance);
        std::thread::Builder::new()
            .name("signal-watcher".to_string())
            .spawn(move || {
                while !SHUTDOWN_REQUESTED.load(Ordering::SeqCst) {
                    std::thread::sleep(std::time::Duration::from_millis(200));
                }
                core_for_sig.shutdown();
            })
            .ok();
    }

    #[cfg(target_os = "macos")]
    unsafe {
        integrator_macos_run_app(is_hidden);
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = is_hidden;
        // On Windows, native WinUI 3 (`app/ui-windows/Integrator.exe`) hosts `integrator_core.dll` directly.
        // If `integrator.exe` CLI binary is run standalone as a headless daemon, park until shutdown.
        while !SHUTDOWN_REQUESTED.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
    }

    core_instance.shutdown();
    Ok(())
}
