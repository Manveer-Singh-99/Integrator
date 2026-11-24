//! # Standalone Application Binary & Process Lifecycle Supervisor (`main.rs`)
//!
//! ## 1. Module Purpose & Scope
//! `main.rs` defines the executable entry point for the compiled Integrator standalone binary.
//! It is responsible for top-level operating system process bootstrapping, command-line argument
//! parsing and execution, single-instance verification, POSIX termination signal trapping,
//! runtime engine lifecycle orchestration, and native graphical window launch.
//!
//! Depending on the invocation context and target platform, `main.rs` operates in one of three modes:
//! 1. **CLI Utility Mode**: Dispatches commands like `integrator pair`, `integrator status`, or
//!    `integrator benchmark` directly to the terminal, printing results and exiting cleanly.
//! 2. **GUI Host Mode (macOS)**: Initializes the core engine, prevents symbol stripping of exported C FFI
//!    entry points, and transitions the main operating system thread into the Cocoa AppKit event runloop
//!    (`integrator_macos_run_app`).
//! 3. **Headless Daemon Mode (Windows / Unix)**: Runs when launched as a background service or tray daemon
//!    (via `--daemon`, `--hidden`, or `--minimized`), maintaining Tokio network listeners and background
//!    threads until SIGINT, SIGTERM, or an explicit IPC shutdown request is received.
//!
//! ## 2. Architectural Linkages & Dependencies
//! ### Upstream Callers:
//! - Operating System Shell / Process Launcher (`launchd` on macOS, Windows Service Control Manager / Task Scheduler,
//!   or interactive terminal sessions).
//!
//! ### Downstream Callees:
//! - `core::run_cli_if_requested`: Evaluates command-line subcommands without starting GUI.
//! - `core::try_focus_existing_instance`: Inter-process communication check to prevent duplicate process instances.
//! - `core::IntegratorCore::init_global`: Instantiates the central Tokio runtime and all subsystems.
//! - `ffi::*`: Preserved via `std::hint::black_box` to prevent link-time optimization (LTO) from dead-stripping
//!   C ABI symbols required by dynamically loaded native UI libraries.
//! - `integrator_macos_run_app`: Native Swift/Objective-C AppKit entry point that constructs the macOS status item
//!   and main window.
//!
//! ### Cross-Platform / Cross-Device Flow:
//! On macOS, the compiled binary is packaged inside `Integrator.app/Contents/MacOS/Integrator`.
//! On Windows, the binary is compiled with `#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]`
//! to suppress the console window during standard GUI launches, while the CLI binary can be invoked from PowerShell/CMD.
//!
//! ## 3. Threading & Concurrency Model
//! - **Main Thread**:
//!   - On macOS: Must be surrendered to the Cocoa/AppKit main runloop (`NSApplicationMain`), which drives UI rendering
//!     and display sync (ProMotion 120Hz).
//!   - On Windows headless mode: Sleeps in a 500ms polling loop monitoring the atomic shutdown flag.
//! - **Signal Watcher Thread**: A dedicated background OS thread (`"signal-watcher"`) monitors the atomic
//!   `SHUTDOWN_REQUESTED` flag on Unix systems, notifies the UI to quit, and invokes `core_instance.shutdown()`
//!   synchronously on that watcher thread.
//! - **Asynchronous Runtime**: `IntegratorCore` hosts the Tokio multi-thread worker pool for all network and IPC activity.
//!
//! ## 4. Security & Safety Invariants
//! - **Async-Signal Safety**: Signal handlers (`SIGINT`, `SIGTERM`) only mutate an `AtomicBool` using `Ordering::SeqCst`.
//!   No heap allocation, locking, or non-reentrant system calls occur inside the signal handler frame.
//! - **Single-Instance Enforcement**: `try_focus_existing_instance()` ensures only one Integrator engine accesses local
//!   hardware devices (display capture, virtual camera DAL, audio endpoints) at a time, preventing driver conflicts.

// Suppress creating a visible Win32 console window when launching the standalone binary on Windows GUI sessions.
#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Result;
use integrator_core::{core, ffi};

/// Polling interval used by the POSIX signal watcher thread to check `SHUTDOWN_REQUESTED`.
#[cfg(unix)]
const SIGNAL_POLL_INTERVAL: Duration = Duration::from_millis(200);

/// Polling interval used by the headless daemon wait loop on non-macOS platforms.
#[cfg(not(target_os = "macos"))]
const DAEMON_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Global atomic flag signaling that a process termination signal (SIGINT, SIGTERM)
/// has been intercepted and asynchronous shutdown must commence.
static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "macos")]
extern "C" {
    /// External C symbol exported by the macOS Swift/AppKit layer (`ui-macos/`),
    /// initializing NSApplication and the native SwiftUI window hierarchy.
    fn integrator_macos_run_app(is_hidden: bool);
}

/// Asynchronous-signal-safe signal handler for POSIX `SIGINT` (Ctrl+C) and `SIGTERM` (kill).
///
/// Stores `true` into `SHUTDOWN_REQUESTED` using sequential consistency.
/// Performs zero heap allocations or complex logic to guarantee POSIX compliance.
#[cfg(unix)]
extern "C" fn handle_termination_signal(_sig: libc::c_int) {
    SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
}

/// Registers POSIX signal handlers for graceful process shutdown on Unix platforms.
///
/// Attaches `handle_termination_signal` to `libc::SIGINT` and `libc::SIGTERM`.
#[cfg(unix)]
fn install_signal_handlers() {
    // SAFETY: Setting an async-signal-safe AtomicBool handler for SIGINT/SIGTERM.
    // The handler does not invoke any unsafe or non-reentrant C runtime functions.
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

/// No-op signal handler registration for non-Unix operating systems (Windows).
#[cfg(not(unix))]
fn install_signal_handlers() {}

/// Main entry point for the Integrator process.
///
/// # Execution Flow:
/// 1. Prevents dead-stripping of FFI symbols on macOS via `std::hint::black_box`.
/// 2. Inspects command-line arguments to determine whether a CLI subcommand was requested.
/// 3. Executes single-instance detection; if another instance is already running, brings it to front and exits.
/// 4. Installs OS termination signal handlers.
/// 5. Initializes the global `IntegratorCore` engine.
/// 6. Spawns background signal monitoring thread.
/// 7. Enters macOS AppKit event loop or Windows headless wait loop.
/// 8. Executes clean shutdown sequence on exit.
fn main() -> Result<()> {
    // ------------------------------------------------------------------------
    // Step 1: Retain C ABI FFI Symbols
    // ------------------------------------------------------------------------
    // When building universal or release binaries, the Rust linker may strip
    // unreferenced extern "C" functions. Passing their pointers through `black_box`
    // guarantees they remain in the export symbol table for native dynamic loaders.
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

    // ------------------------------------------------------------------------
    // Step 2: Command-Line Interface (CLI) Dispatch
    // ------------------------------------------------------------------------
    let args: Vec<String> = std::env::args().collect();

    // If command line arguments match a known CLI subcommand (e.g. status, pair, benchmark),
    // execute it synchronously in terminal mode and terminate the process immediately.
    if let Some(cli_res) = core::run_cli_if_requested(&args) {
        return cli_res;
    }

    // ------------------------------------------------------------------------
    // Step 3: Single-Instance Verification & Focus Forwarding
    // ------------------------------------------------------------------------
    // Probe local system mutex / IPC socket to detect whether Integrator is already active.
    // If running, signals the active instance to bring its main window forward and exits.
    if core::try_focus_existing_instance() {
        println!("Existing Integrator instance is already running. Brought window to front.");
        return Ok(());
    }

    // ------------------------------------------------------------------------
    // Step 4: Operating System Signal Handler Registration
    // ------------------------------------------------------------------------
    install_signal_handlers();

    // ------------------------------------------------------------------------
    // Step 5: Initialize Global Core Runtime Singleton
    // ------------------------------------------------------------------------
    let core_instance = core::IntegratorCore::init_global()?;

    // Check if user requested silent / headless launch via command line flags
    let is_hidden = args
        .iter()
        .any(|a| a == "--hidden" || a == "--daemon" || a == "--minimized");

    // ------------------------------------------------------------------------
    // Step 6: Spawn Asynchronous Signal Watcher Thread
    // ------------------------------------------------------------------------
    #[cfg(unix)]
    {
        let core_for_sig = std::sync::Arc::clone(&core_instance);
        std::thread::Builder::new()
            .name("signal-watcher".to_string())
            .spawn(move || {
                // Poll atomic flag periodically to respond promptly to SIGINT/SIGTERM
                while !SHUTDOWN_REQUESTED.load(Ordering::SeqCst) {
                    std::thread::sleep(SIGNAL_POLL_INTERVAL);
                }
                // Notify any active native UI (e.g., macOS AppKit runloop) before unregistering callbacks
                core::emit_ui_event("quit", "{}");
                // Initiate orderly subsystem shutdown (idempotent if main() also calls shutdown())
                core_for_sig.shutdown();
            })
            .ok();
    }

    // ------------------------------------------------------------------------
    // Step 7: Enter Native Platform Event Loop
    // ------------------------------------------------------------------------
    #[cfg(target_os = "macos")]
    unsafe {
        // Transfer control of the main thread to AppKit NSApplicationMain runloop
        integrator_macos_run_app(is_hidden);
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = is_hidden;
        // On Windows, native WinUI 3 (`app/ui-windows/Integrator.exe`) hosts `integrator_core.dll` directly.
        // If `integrator.exe` CLI binary is run standalone as a headless daemon, park until shutdown.
        while !SHUTDOWN_REQUESTED.load(Ordering::SeqCst) {
            std::thread::sleep(DAEMON_POLL_INTERVAL);
        }
    }

    // ------------------------------------------------------------------------
    // Step 8: Final Teardown
    // ------------------------------------------------------------------------
    core_instance.shutdown();
    Ok(())
}
