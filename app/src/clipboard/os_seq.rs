//! # Low-Overhead OS Clipboard Sequence Number Probing
//!
//! ## 1. Module Purpose & Scope
//! This module provides a sub-microsecond, zero-allocation probe for detecting OS-level clipboard
//! changes on macOS and Windows.
//!
//! Inspecting clipboard payloads directly (e.g. reading 10 MiB of text or querying complex OLE
//! data objects) is computationally expensive, incurs inter-process communication overhead, and can
//! interfere with foreground applications currently writing to the clipboard. To eliminate this
//! overhead, Integrator polls the native operating system's monotonic sequence counter every 250ms.
//! Only when this lightweight counter increments does the clipboard engine perform deeper format
//! inspection and cryptographic hashing.
//!
//! ## 2. Architectural Linkages & Dependencies
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────────────────────────────────┐
//! │                           OS Clipboard Sequence Probe Flow                             │
//! └────────────────────────────────────────────────────────────────────────────────────────┘
//!
//!                        ┌──────────────────────────────────────┐
//!                        │    ClipboardService Polling Loop     │
//!                        │     (src/clipboard/service.rs)       │
//!                        └──────────────────┬───────────────────┘
//!                                           │ Every 250ms
//!                                           ▼
//!                        ┌──────────────────────────────────────┐
//!                        │    os_seq::get_clipboard_sequence()  │
//!                        └──────────────┬────────────────┬──────┘
//!                                       │                │
//!                     macOS Compilation │                │ Windows Compilation
//!                                       ▼                ▼
//!              ┌─────────────────────────────┐    ┌─────────────────────────────┐
//!              │  Objective-C Runtime FFI    │    │  Win32 user32.dll FFI       │
//!              │  [NSPasteboard general-     │    │  GetClipboardSequence-      │
//!              │   Pasteboard].changeCount   │    │  Number()                   │
//!              └─────────────────────────────┘    └─────────────────────────────┘
//! ```
//!
//! ### Upstream Callers:
//! - `src/clipboard/service.rs`: `ClipboardService::start_sequence_watcher` calls `get_clipboard_sequence()`
//!   in a continuous 250ms loop.
//!
//! ### Downstream Callees:
//! - macOS: `libobjc.dylib` functions (`objc_getClass`, `sel_registerName`, `objc_msgSend`,
//!   `objc_autoreleasePoolPush`, `objc_autoreleasePoolPop`).
//! - Windows: `user32.dll` API `GetClipboardSequenceNumber()`.
//!
//! ## 3. Threading & Concurrency Model
//! - Invoked synchronously from Tokio async background tasks.
//! - Non-blocking, re-entrant, and thread-safe.
//!
//! ## 4. Security & Safety Invariants
//! - **Objective-C Autorelease Pool**: On macOS, every call wraps `objc_msgSend` inside a scoped
//!   RAII `AutoreleasePool` to ensure temporary Objective-C objects allocated by AppKit are immediately
//!   freed and never leaked into long-running daemon heaps.
//! - **Sentinel Mapping**: Windows `GetClipboardSequenceNumber()` returns `0` when the desktop is
//!   locked or a secure UAC prompt is displayed; this is mapped cleanly to `-1` to avoid false triggers.

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

    /// RAII wrapper managing Objective-C autorelease pool lifetime.
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

    /// Checks if the active clipboard payload is flagged with password-manager confidentiality
    /// markers or Apple Universal Clipboard transient sync markers.
    pub fn is_clipboard_concealed() -> bool {
        unsafe {
            let _pool = AutoreleasePool(objc_autoreleasePoolPush());
            let cls = objc_getClass(c"NSPasteboard".as_ptr());
            if cls.is_null() {
                return false;
            }
            let sel_general = sel_registerName(c"generalPasteboard".as_ptr());
            let send_id: unsafe extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void =
                std::mem::transmute(objc_msgSend as *const ());
            let pasteboard = send_id(cls, sel_general);
            if pasteboard.is_null() {
                return false;
            }
            let sel_types = sel_registerName(c"types".as_ptr());
            let types_arr = send_id(pasteboard, sel_types);
            if types_arr.is_null() {
                return false;
            }
            let sel_count = sel_registerName(c"count".as_ptr());
            let send_count: unsafe extern "C" fn(*mut c_void, *mut c_void) -> usize =
                std::mem::transmute(objc_msgSend as *const ());
            let count = send_count(types_arr, sel_count);

            let sel_obj_at = sel_registerName(c"objectAtIndex:".as_ptr());
            let send_obj_at: unsafe extern "C" fn(*mut c_void, *mut c_void, usize) -> *mut c_void =
                std::mem::transmute(objc_msgSend as *const ());
            let sel_utf8 = sel_registerName(c"UTF8String".as_ptr());
            let send_utf8: unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const std::ffi::c_char =
                std::mem::transmute(objc_msgSend as *const ());

            for i in 0..count {
                let item = send_obj_at(types_arr, sel_obj_at, i);
                if !item.is_null() {
                    let cstr = send_utf8(item, sel_utf8);
                    if !cstr.is_null() {
                        let s = std::ffi::CStr::from_ptr(cstr).to_string_lossy();
                        if s == "org.nspasteboard.ConcealedType"
                            || s == "org.nspasteboard.TransientType"
                            || s == "org.nspasteboard.AutoGeneratedType"
                            || s == "com.agilebits.onepassword"
                            || s == "com.apple.is-remote-clipboard"
                        {
                            return true;
                        }
                    }
                }
            }
            false
        }
    }
}

#[cfg(target_os = "windows")]
mod os_impl {
    #[link(name = "user32")]
    extern "system" {
        fn GetClipboardSequenceNumber() -> u32;
        fn RegisterClipboardFormatW(lpszFormat: *const u16) -> u32;
        fn IsClipboardFormatAvailable(format: u32) -> i32;
        fn OpenClipboard(hWndNewOwner: *mut std::ffi::c_void) -> i32;
        fn CloseClipboard() -> i32;
        fn GetClipboardData(uFormat: u32) -> *mut std::ffi::c_void;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GlobalLock(hMem: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
        fn GlobalUnlock(hMem: *mut std::ffi::c_void) -> i32;
    }

    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
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

    /// Checks if the Windows clipboard payload is marked as sensitive/concealed by password managers.
    pub fn is_clipboard_concealed() -> bool {
        unsafe {
            let fmt_exclude = RegisterClipboardFormatW(to_wide("ExcludeClipboardContentFromMonitorProcessing").as_ptr());
            if fmt_exclude != 0 && IsClipboardFormatAvailable(fmt_exclude) != 0 {
                return true;
            }

            let fmt_ignore = RegisterClipboardFormatW(to_wide("Clipboard Viewer Ignore").as_ptr());
            if fmt_ignore != 0 && IsClipboardFormatAvailable(fmt_ignore) != 0 {
                return true;
            }

            let fmt_history = RegisterClipboardFormatW(to_wide("CanIncludeInClipboardHistory").as_ptr());
            if fmt_history != 0 && IsClipboardFormatAvailable(fmt_history) != 0 {
                if OpenClipboard(std::ptr::null_mut()) != 0 {
                    let h_data = GetClipboardData(fmt_history);
                    let mut concealed = false;
                    if !h_data.is_null() {
                        let ptr = GlobalLock(h_data);
                        if !ptr.is_null() {
                            let val = *(ptr as *const u32);
                            if val == 0 {
                                concealed = true;
                            }
                            GlobalUnlock(h_data);
                        }
                    }
                    CloseClipboard();
                    if concealed {
                        return true;
                    }
                }
            }
            false
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
mod os_impl {
    /// Non-supported OS fallback returning sentinel value `-1`.
    pub fn get_clipboard_sequence() -> i64 {
        -1
    }

    pub fn is_clipboard_concealed() -> bool {
        false
    }
}

/// Queries the platform-native monotonic clipboard modification sequence counter.
///
/// Increments each time any application on the operating system copies or modifies
/// clipboard contents.
///
/// # Returns
/// A non-negative 64-bit sequence integer on success, or `-1` if unavailable or access is restricted.
pub fn get_clipboard_sequence() -> i64 {
    os_impl::get_clipboard_sequence()
}

/// Returns `true` if the current clipboard content is flagged as concealed/transient by password managers.
pub fn is_clipboard_concealed() -> bool {
    os_impl::is_clipboard_concealed()
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
