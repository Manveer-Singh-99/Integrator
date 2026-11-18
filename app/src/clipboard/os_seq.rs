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
    /// Non-supported OS fallback returning sentinel value `-1`.
    pub fn get_clipboard_sequence() -> i64 {
        -1
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

#[cfg(test)]
mod tests {
    use super::get_clipboard_sequence;

    #[test]
    fn sequence_probe_does_not_crash() {
        let seq = get_clipboard_sequence();
        assert!(seq >= -1);
    }
}
