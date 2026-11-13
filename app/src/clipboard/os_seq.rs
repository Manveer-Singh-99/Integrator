//! Native OS clipboard sequence tracking and ownership markers.
//! Inspired by Deskflow (Synergy/Barrier) platform clipboard implementations.

#[cfg(target_os = "macos")]
pub mod os_impl {
    #[link(name = "AppKit", kind = "framework")]
    #[link(name = "objc", kind = "dylib")]
    extern "C" {
        fn objc_getClass(name: *const std::os::raw::c_char) -> *mut std::ffi::c_void;
        fn sel_registerName(name: *const std::os::raw::c_char) -> *mut std::ffi::c_void;
        fn objc_msgSend();
    }

    /// Returns the monotonic changeCount of the general pasteboard on macOS.
    pub fn get_clipboard_sequence() -> i64 {
        unsafe {
            let cls = objc_getClass(b"NSPasteboard\0".as_ptr() as *const _);
            let sel_general = sel_registerName(b"generalPasteboard\0".as_ptr() as *const _);
            let pasteboard: *mut std::ffi::c_void = {
                let msg_send: extern "C" fn(*mut std::ffi::c_void, *mut std::ffi::c_void) -> *mut std::ffi::c_void =
                    std::mem::transmute(objc_msgSend as *const ());
                msg_send(cls, sel_general)
            };
            let sel_change = sel_registerName(b"changeCount\0".as_ptr() as *const _);
            let count: isize = {
                let msg_send: extern "C" fn(*mut std::ffi::c_void, *mut std::ffi::c_void) -> isize =
                    std::mem::transmute(objc_msgSend as *const ());
                msg_send(pasteboard, sel_change)
            };
            count as i64
        }
    }
}

#[cfg(target_os = "windows")]
pub mod os_impl {
    #[link(name = "user32")]
    extern "system" {
        fn GetClipboardSequenceNumber() -> u32;
    }

    /// Returns the 32-bit monotonic clipboard sequence number on Windows.
    pub fn get_clipboard_sequence() -> i64 {
        unsafe { GetClipboardSequenceNumber() as i64 }
    }
}

pub fn get_clipboard_sequence() -> i64 {
    os_impl::get_clipboard_sequence()
}
