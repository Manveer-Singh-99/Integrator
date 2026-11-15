#[cfg(target_os = "macos")]
mod os_impl {
    use std::ffi::c_void;

    #[link(name = "objc")]
    extern "C" {
        fn objc_getClass(name: *const std::ffi::c_char) -> *mut c_void;
        fn sel_registerName(name: *const std::ffi::c_char) -> *mut c_void;
        fn objc_msgSend();
        fn objc_autoreleasePoolPush() -> *mut c_void;
        fn objc_autoreleasePoolPop(pool: *mut c_void);
    }

    struct AutoreleasePool(*mut c_void);

    impl Drop for AutoreleasePool {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { objc_autoreleasePoolPop(self.0) };
            }
        }
    }

    /// Returns the monotonic `changeCount` of `NSPasteboard.generalPasteboard`,
    /// or `-1` if the Objective-C pasteboard handle is unavailable.
    pub fn get_clipboard_sequence() -> i64 {
        unsafe {
            let _pool = AutoreleasePool(objc_autoreleasePoolPush());
            let cls = objc_getClass(c"NSPasteboard".as_ptr());
            if cls.is_null() {
                return -1;
            }
            let sel_general = sel_registerName(c"generalPasteboard".as_ptr());
            let send_id: unsafe extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void =
                std::mem::transmute(objc_msgSend as *const ());
            let pasteboard = send_id(cls, sel_general);
            if pasteboard.is_null() {
                return -1;
            }
            let sel_change = sel_registerName(c"changeCount".as_ptr());
            let send_isize: unsafe extern "C" fn(*mut c_void, *mut c_void) -> isize =
                std::mem::transmute(objc_msgSend as *const ());
            let count = send_isize(pasteboard, sel_change) as i64;
            if count < 0 {
                -1
            } else {
                count
            }
        }
    }
}

#[cfg(target_os = "windows")]
mod os_impl {
    #[link(name = "user32")]
    extern "system" {
        fn GetClipboardSequenceNumber() -> u32;
    }

    /// Returns the 32-bit monotonic clipboard sequence number on Windows, or `-1`
    /// when access is denied (e.g., locked desktop / UAC prompt returns `0`).
    pub fn get_clipboard_sequence() -> i64 {
        let seq = unsafe { GetClipboardSequenceNumber() };
        if seq == 0 {
            -1
        } else {
            seq as i64
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
mod os_impl {
    pub fn get_clipboard_sequence() -> i64 {
        -1
    }
}

pub fn get_clipboard_sequence() -> i64 {
    os_impl::get_clipboard_sequence()
}

#[cfg(test)]
mod tests {
    use super::get_clipboard_sequence;

    #[test]
    fn sequence_probe_does_not_crash() {
        let seq = get_clipboard_sequence();
        assert!(seq >= -1);
    }
}
