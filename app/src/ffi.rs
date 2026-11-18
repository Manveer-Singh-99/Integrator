//! # Foreign Function Interface (FFI) C ABI Layer (`ffi.rs`)
//!
//! ## 1. Module Purpose & Scope
//! `ffi.rs` defines the external C Application Binary Interface (ABI) exported by the Integrator
//! core library. It serves as the primary boundary bridge connecting native platform graphical user
//! interfaces (macOS Swift/AppKit/SwiftUI and Windows 11 C#/WinUI 3/WPF) to the unified Rust
//! backend engine.
//!
//! Through this boundary, native frontends:
//! - Initialize the global asynchronous runtime and register event notification callbacks.
//! - Dispatch asynchronous JSON-RPC-style control commands (`integrator_core_invoke`).
//! - Manage single-instance activation and CLI delegation.
//! - Handle system tray actions and graceful application shutdown.
//!
//! ## 2. Architectural Linkages & Dependencies
//! ### Upstream Callers:
//! - **macOS**: `ui-macos/` written in Swift. Invokes C functions via Swift-Clang bridging headers
//!   or module maps (e.g. `IntegratorBridge.swift`).
//! - **Windows 11**: `ui-windows/` written in C# (.NET 8/9 / WinUI 3). Invokes entry points via
//!   `[DllImport("integrator.dll")]` or `[LibraryImport]` P/Invoke bindings.
//! - **Native Process Bootstrap**: Platform launchers checking for existing running instances before UI startup.
//!
//! ### Downstream Callees:
//! - `core::IntegratorCore`: Accesses the global runtime singleton (`GLOBAL_CORE`).
//! - `core::register_ui_callback`: Stores native UI function pointer for asynchronous push notifications.
//! - `core::run_cli_if_requested`: Dispatches command-line arguments when invoked from shell wrappers.
//! - `core::try_focus_existing_instance`: Interacts with OS window managers to bring active instances forward.
//!
//! ### Cross-Platform / Cross-Device Flow:
//! High-level user interactions (e.g., toggling virtual display mirroring, initiating peer pairing,
//! adjusting audio sync delay) are serialized to JSON in the native UI layer, passed across this FFI
//! boundary as NUL-terminated UTF-8 C strings, parsed and executed by `core.rs`, and routed over the
//! encrypted network transport to the peer device. Asynchronous responses or peer state changes
//! flow back across the boundary via `UiEventCallback`.
//!
//! ## 3. Threading & Concurrency Model
//! - **Caller Thread Agnostic**: FFI methods may be invoked from any thread, including the macOS main
//!   Grand Central Dispatch (GCD) thread, Windows Single-Threaded Apartment (STA) UI threads, or background worker pools.
//! - **Panic Isolation (`catch_unwind`)**: Every exported C ABI function wraps its internal execution in
//!   `std::panic::catch_unwind(AssertUnwindSafe(...))`. Rust panics are intercepted at the FFI boundary
//!   and converted into error status codes or JSON error responses; panics NEVER unwind across the C ABI,
//!   which would cause undefined behavior and process termination.
//! - **Asynchronous Dispatch**: The Rust engine processes tasks asynchronously on the Tokio multi-thread runtime.
//!   Returned values from `integrator_core_invoke` provide synchronous RPC execution or asynchronous task tracking tokens.
//!
//! ## 4. Security & Safety Invariants
//! - **Raw Pointer Validation**: All incoming pointer arguments (`*const c_char`, `*const *const c_char`, `*mut c_char`)
//!   are verified for non-nullness prior to dereferencing.
//! - **NUL-Byte Sanitization**: Outgoing C strings are sanitized via `to_cstring_sanitized` to prevent premature
//!   NUL-byte truncation attacks.
//! - **Memory Ownership Invariants**:
//!   - Strings returned by `integrator_core_invoke` are allocated on the Rust heap via `CString::into_raw`.
//!     The native caller OWNS this memory and MUST pass the pointer back to `integrator_core_free_string`
//!     to reclaim heap memory.
//!   - Strings passed into Rust by the caller (`method`, `params_json`) remain owned by the caller.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::core::{
    c_str_to_rust, register_ui_callback, IntegratorCore, UiEventCallback, GLOBAL_CORE,
};

/// Maximum permissible command-line argument count accepted from FFI callers.
/// Protects against unbounded stack/heap allocation from corrupted C arrays.
const MAX_CLI_ARGC: c_int = 256;

/// Sanitizes a Rust string slice into a valid `CString` safe for C ABI transfer.
///
/// If the input string contains interior NUL bytes (`\0`), they are filtered out to prevent
/// premature string termination in C consumers. In the catastrophic event that allocation fails,
/// a pre-allocated static JSON error literal is returned.
///
/// # Arguments
/// * `s` - Source string slice to convert.
///
/// # Return Value
/// A owned `CString` guaranteed to have no interior NUL bytes and a terminating NUL byte.
fn to_cstring_sanitized(s: &str) -> CString {
    // Fast path: if no interior NUL bytes exist, attempt direct CString creation
    if !s.as_bytes().contains(&0) {
        if let Ok(cs) = CString::new(s) {
            return cs;
        }
    }

    // Slow path: strip any embedded NUL characters
    let cleaned: String = s.chars().filter(|&c| c != '\0').collect();
    CString::new(cleaned).unwrap_or_else(|_| {
        // Fallback static error JSON containing no NUL bytes
        CString::new(r#"{"ok":false,"error":"ffi string encoding error"}"#)
            .expect("static JSON literal contains no NUL")
    })
}

/// Attempts to find and bring to foreground an already running instance of the application.
///
/// # Return Value
/// Returns `true` if an existing instance was discovered and signaled to activate its window,
/// or `false` if no other instance was detected or if activation failed.
///
/// # Safety & Panic Guarantee
/// Safe for C callers. Encapsulated in `catch_unwind` and returns `false` on panic.
#[no_mangle]
pub extern "C" fn integrator_core_try_focus_existing() -> bool {
    catch_unwind(crate::core::try_focus_existing_instance).unwrap_or(false)
}

/// Executes command-line interface arguments passed from the native executable wrapper.
///
/// Converts a C-style `(argc, argv)` array into Rust strings and dispatches to the CLI handler.
///
/// # Arguments
/// * `argc` - Count of elements in the `argv` array. Must be between 2 and `MAX_CLI_ARGC`.
/// * `argv` - Pointer to an array of NUL-terminated C string pointers.
///
/// # Return Value
/// - `0`: CLI command executed successfully; application should exit cleanly.
/// - `1`: CLI command execution failed; application should exit with error code.
/// - `-1`: Arguments did not match a CLI command or were invalid; application should proceed to launch GUI.
///
/// # Safety
/// Caller must ensure `argv` points to a valid memory block containing at least `argc` pointers.
#[no_mangle]
pub extern "C" fn integrator_core_run_cli(argc: c_int, argv: *const *const c_char) -> c_int {
    // Validate bounds: argc <= 1 means only process binary name was passed (no subcommand)
    if argc <= 1 || argc > MAX_CLI_ARGC || argv.is_null() {
        return -1;
    }

    catch_unwind(AssertUnwindSafe(|| {
        let mut args = Vec::with_capacity(argc as usize);
        for i in 0..argc as isize {
            // SAFETY: Caller supplies an array of at least `argc` C string pointers.
            let p = unsafe { *argv.offset(i) };
            if p.is_null() {
                args.push(String::new());
            } else {
                // SAFETY: Non-null element points to a valid NUL-terminated C string.
                let s = unsafe { CStr::from_ptr(p).to_string_lossy().into_owned() };
                args.push(s);
            }
        }

        // Dispatch parsed arguments to core CLI runner
        match crate::core::run_cli_if_requested(&args) {
            Some(Ok(())) => 0,
            Some(Err(e)) => {
                eprintln!("CLI command failed: {}", e);
                1
            }
            None => -1,
        }
    }))
    .unwrap_or(1)
}

/// Registers the native UI event callback function pointer without initializing core.
///
/// # Arguments
/// * `callback` - Optional C function pointer accepting an event name and JSON payload.
///   Passing `None` deregisters any previously active callback.
#[no_mangle]
pub extern "C" fn integrator_core_set_ui_callback(callback: Option<UiEventCallback>) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        register_ui_callback(callback);
    }));
}

/// Initializes the global `IntegratorCore` engine and spawns all background async services.
///
/// # Arguments
/// * `callback` - Optional C function pointer for push event notifications from core to UI.
///
/// # Return Value
/// Returns `0` on successful initialization, or `-1` if initialization failed or if core was already initialized.
#[no_mangle]
pub extern "C" fn integrator_core_init(callback: Option<UiEventCallback>) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        // Register the UI notification bridge callback
        register_ui_callback(callback);

        // Initialize Tokio runtime, subsystems, listeners, and state machines
        match IntegratorCore::init_global() {
            Ok(_) => 0,
            Err(e) => {
                eprintln!("Failed to initialize Integrator Core: {}", e);
                -1
            }
        }
    }))
    .unwrap_or(-1)
}

/// Primary JSON-RPC dispatch gateway from native UI to Rust core.
///
/// # Arguments
/// * `method` - NUL-terminated C string specifying the method name (e.g. `"get_status"`, `"start_pairing"`).
/// * `params_json` - NUL-terminated C string containing JSON-encoded arguments.
///
/// # Return Value
/// Returns a heap-allocated NUL-terminated C string (`*mut c_char`) containing the JSON response.
///
/// # Ownership & Memory Management
/// **IMPORTANT**: The returned pointer is owned by the caller. The caller MUST release this memory
/// by passing the pointer to `integrator_core_free_string`. Failing to do so causes a memory leak.
#[no_mangle]
pub extern "C" fn integrator_core_invoke(
    method: *const c_char,
    params_json: *const c_char,
) -> *mut c_char {
    catch_unwind(AssertUnwindSafe(|| {
        // Convert input C strings to owned Rust Strings with lossy UTF-8 fallback
        let m = c_str_to_rust(method);
        let p = c_str_to_rust(params_json);

        // Dispatch call to global singleton if available
        let out = if let Some(core) = GLOBAL_CORE.get() {
            core.dispatch_json(&m, &p)
        } else {
            serde_json::json!({ "ok": false, "error": "Integrator core is not initialized" })
                .to_string()
        };

        // Transfer string ownership to C caller as raw pointer
        to_cstring_sanitized(&out).into_raw()
    }))
    .unwrap_or_else(|_| {
        to_cstring_sanitized(r#"{"ok":false,"error":"internal panic in integrator core"}"#)
            .into_raw()
    })
}

/// Frees a heap-allocated C string previously returned by `integrator_core_invoke`.
///
/// # Arguments
/// * `ptr` - Raw pointer to a C string allocated by Rust via `CString::into_raw`.
///   Passing a null pointer is safe and performs a no-op.
///
/// # Safety
/// `ptr` must either be null or have been created by a prior call to `integrator_core_invoke`.
/// It must not be freed twice.
#[no_mangle]
pub extern "C" fn integrator_core_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            // SAFETY: Pointer was allocated via CString::into_raw in integrator_core_invoke.
            // Reconstructing CString takes back ownership and drops it at end of scope.
            unsafe {
                let _ = CString::from_raw(ptr);
            }
        }));
    }
}

/// Dispatches a system tray icon action to the core engine.
///
/// # Arguments
/// * `action` - NUL-terminated C string identifying the tray menu action (e.g. `"toggle_mute"`, `"quit"`).
#[no_mangle]
pub extern "C" fn integrator_core_tray_action(action: *const c_char) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let act = c_str_to_rust(action);
        if let Some(core) = GLOBAL_CORE.get() {
            core.trigger_tray_action(&act);
        }
    }));
}

/// Initiates clean graceful shutdown of the global core engine and background daemons.
///
/// Flushes pending telemetry, unregisters OS hooks, closes active network sessions,
/// and releases native UI callback bindings.
#[no_mangle]
pub extern "C" fn integrator_core_shutdown() {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if let Some(core) = GLOBAL_CORE.get() {
            core.shutdown();
        } else {
            register_ui_callback(None);
        }
    }));
}
