use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::core::{
    c_str_to_rust, register_ui_callback, IntegratorCore, UiEventCallback, GLOBAL_CORE,
};

const MAX_CLI_ARGC: c_int = 256;

fn to_cstring_sanitized(s: &str) -> CString {
    if !s.as_bytes().contains(&0) {
        if let Ok(cs) = CString::new(s) {
            return cs;
        }
    }
    let cleaned: String = s.chars().filter(|&c| c != '\0').collect();
    CString::new(cleaned).unwrap_or_else(|_| {
        CString::new(r#"{"ok":false,"error":"ffi string encoding error"}"#)
            .expect("static JSON literal contains no NUL")
    })
}

#[no_mangle]
pub extern "C" fn integrator_core_try_focus_existing() -> bool {
    catch_unwind(crate::core::try_focus_existing_instance).unwrap_or(false)
}

#[no_mangle]
pub extern "C" fn integrator_core_run_cli(argc: c_int, argv: *const *const c_char) -> c_int {
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
                // SAFETY: Non-null element points to a NUL-terminated C string.
                let s = unsafe { CStr::from_ptr(p).to_string_lossy().into_owned() };
                args.push(s);
            }
        }

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

#[no_mangle]
pub extern "C" fn integrator_core_set_ui_callback(callback: Option<UiEventCallback>) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        register_ui_callback(callback);
    }));
}

#[no_mangle]
pub extern "C" fn integrator_core_init(callback: Option<UiEventCallback>) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        register_ui_callback(callback);
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

#[no_mangle]
pub extern "C" fn integrator_core_invoke(
    method: *const c_char,
    params_json: *const c_char,
) -> *mut c_char {
    catch_unwind(AssertUnwindSafe(|| {
        let m = c_str_to_rust(method);
        let p = c_str_to_rust(params_json);
        let out = if let Some(core) = GLOBAL_CORE.get() {
            core.dispatch_json(&m, &p)
        } else {
            serde_json::json!({ "ok": false, "error": "Integrator core is not initialized" })
                .to_string()
        };
        to_cstring_sanitized(&out).into_raw()
    }))
    .unwrap_or_else(|_| {
        to_cstring_sanitized(r#"{"ok":false,"error":"internal panic in integrator core"}"#)
            .into_raw()
    })
}

#[no_mangle]
pub extern "C" fn integrator_core_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            // SAFETY: Pointer was allocated via CString::into_raw in integrator_core_invoke.
            unsafe {
                let _ = CString::from_raw(ptr);
            }
        }));
    }
}

#[no_mangle]
pub extern "C" fn integrator_core_tray_action(action: *const c_char) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let act = c_str_to_rust(action);
        if let Some(core) = GLOBAL_CORE.get() {
            core.trigger_tray_action(&act);
        }
    }));
}

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
