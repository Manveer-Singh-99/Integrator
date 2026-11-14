use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use crate::core::{c_str_to_rust, register_ui_callback, IntegratorCore, UiEventCallback, GLOBAL_CORE};

#[no_mangle]
pub extern "C" fn integrator_core_try_focus_existing() -> bool {
    crate::core::try_focus_existing_instance()
}

#[no_mangle]
pub extern "C" fn integrator_core_run_cli(argc: i32, argv: *const *const c_char) -> i32 {
    if argc <= 1 || argv.is_null() {
        return -1;
    }
    let mut args = Vec::with_capacity(argc as usize);
    for i in 0..argc as isize {
        let p = unsafe { *argv.offset(i) };
        if p.is_null() {
            args.push(String::new());
        } else {
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
}

#[no_mangle]
pub extern "C" fn integrator_core_set_ui_callback(callback: Option<UiEventCallback>) {
    register_ui_callback(callback);
}

#[no_mangle]
pub extern "C" fn integrator_core_init(callback: Option<UiEventCallback>) -> i32 {
    register_ui_callback(callback);
    match IntegratorCore::init_global() {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("Failed to initialize Integrator Core: {}", e);
            1
        }
    }
}

#[no_mangle]
pub extern "C" fn integrator_core_invoke(
    method: *const c_char,
    params_json: *const c_char,
) -> *mut c_char {
    let m = c_str_to_rust(method);
    let p = c_str_to_rust(params_json);
    let out = if let Some(core) = GLOBAL_CORE.get() {
        core.dispatch_json(&m, &p)
    } else {
        serde_json::json!({ "ok": false, "error": "Integrator core is not initialized" })
            .to_string()
    };
    CString::new(out)
        .unwrap_or_else(|_| CString::new("{\"ok\":false,\"error\":\"null byte in json\"}").unwrap())
        .into_raw()
}

#[no_mangle]
pub extern "C" fn integrator_core_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = CString::from_raw(ptr);
        }
    }
}

#[no_mangle]
pub extern "C" fn integrator_core_tray_action(action: *const c_char) {
    let act = c_str_to_rust(action);
    if let Some(core) = GLOBAL_CORE.get() {
        core.trigger_tray_action(&act);
    }
}

#[no_mangle]
pub extern "C" fn integrator_core_shutdown() {
    if let Some(core) = GLOBAL_CORE.get() {
        core.kvm.force_release_all(true);
    }
}
