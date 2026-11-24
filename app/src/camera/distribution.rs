//! # Multi-Peer Camera Frame Distribution Subsystem
//!
//! ## 1. Module Purpose & Scope
//! This module implements [`CameraFrameHub`] and [`SubscriberMailbox`], an isolated,
//! reference-counted, multi-subscriber video frame distribution hub for the **Shared Camera
//! Subsystem** (`camera` feature).
//!
//! It replaces legacy single-slot destructive `take()` buffering with a zero-copy fan-out
//! architecture so one physical macOS AVFoundation 720p30 NV12 capture session can feed
//! multiple authorized remote peers and local preview simultaneously without head-of-line
//! blocking or per-peer frame buffer duplication.
//!
//! ## 2. Architectural Linkages & Dependencies
//! - **Upstream Callers**:
//!   - [`crate::camera::integrator_on_mac_camera_frame`]: Encodes incoming AVFoundation NV12
//!     sample buffers into 22-byte `ICAM` + 1,382,400-byte payload packets and invokes
//!     [`CameraFrameHub::publish_frame`].
//!   - [`crate::camera::CameraService`]: Subscribes per-peer sender tasks via
//!     [`CameraFrameHub::subscribe`], unsubscribes on stream teardown or consent revocation via
//!     [`CameraFrameHub::unsubscribe`], and clears all mailboxes on shutdown via
//!     [`CameraFrameHub::clear_all`].
//! - **Downstream Callees**:
//!   - `tokio::sync::Notify`: Wakes async per-peer sender loops (`run_mac_sender_for_peer`)
//!     immediately upon new frame arrival.
//! - **Cross-Platform / Cross-Device Flow**:
//!   - Wraps each serialized `ICAM` NV12 frame in a single [`SharedCameraFrame`] (`Arc<Vec<u8>>`)
//!     on macOS and fans out `Arc` pointers into each authorized peer's [`SubscriberMailbox`],
//!     which `run_mac_sender_for_peer` transmits over encrypted `TransportSessionV2` (`TCP :58287`)
//!     to the Windows 11 Media Foundation FrameServer virtual webcam (`integrator_vcam.dll`).
//!
//! ## 3. Threading & Concurrency Model
//! - **Producer Thread**: CoreMedia / AVFoundation real-time capture dispatch queue invokes
//!   [`CameraFrameHub::publish_frame`], holding the `subscribers` `std::sync::Mutex` only long
//!   enough to clone `Arc` pointers into per-subscriber single-slot mutexes and signal `Notify`.
//! - **Consumer Tasks**: Independent Tokio async tasks wait on `SubscriberMailbox::notify` and
//!   extract the latest frame via [`SubscriberMailbox::take`].
//! - **Zero Head-of-Line Blocking**: A slow receiver or stalled network connection never starves,
//!   intercepts, or slows down another peer. Stale unread frames are overwritten in place.
//!
//! ## 4. Security & Safety Invariants
//! - **Bounded $O(N)$ Memory**: Each subscriber holds at most one unread [`SharedCameraFrame`],
//!   preventing unbounded queue growth under network congestion.
//! - **Immediate Revocation Isolation**: Calling [`CameraFrameHub::unsubscribe`] immediately
//!   removes the peer's mailbox, purges any buffered frame, and wakes any blocked sender task.
//! - **Poison-Resilient Locking**: All internal mutex locks recover gracefully via
//!   `unwrap_or_else(|e| e.into_inner())` so a panic in one consumer cannot DoS other peers.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;

/// Reference-counted shared camera frame containing the serialized NV12 datagram.
pub type SharedCameraFrame = Arc<Vec<u8>>;

/// Dedicated, bounded mailbox for a single authorized stream consumer.
pub struct SubscriberMailbox {
    /// Holds at most 1 latest unread frame. Replaced by newer frames to prevent buffering latency.
    latest: Mutex<Option<SharedCameraFrame>>,
    /// Woken when a newly captured frame is published to this mailbox.
    pub notify: Notify,
}

impl SubscriberMailbox {
    /// Creates a new empty subscriber mailbox.
    pub fn new() -> Self {
        Self {
            latest: Mutex::new(None),
            notify: Notify::new(),
        }
    }

    /// Publishes a reference-counted frame into this mailbox, replacing any stale unread frame.
    pub fn publish(&self, frame: SharedCameraFrame) {
        if let Ok(mut guard) = self.latest.lock() {
            *guard = Some(frame);
        }
        // Use `notify_one` so a frame arriving between `take()` and `.notified().await`
        // stores a wakeup permit instead of dropping the edge notification.
        self.notify.notify_one();
    }

    /// Takes the pending frame out of the mailbox, leaving it empty until the next frame arrives.
    pub fn take(&self) -> Option<SharedCameraFrame> {
        self.latest.lock().ok()?.take()
    }

    /// Clears any pending frame data from the mailbox.
    pub fn clear(&self) {
        if let Ok(mut guard) = self.latest.lock() {
            *guard = None;
        }
    }
}

/// Central frame distribution hub fanning out captured frames to all active subscribers.
pub struct CameraFrameHub {
    /// Active remote peer stream subscribers keyed by peer device ID hex.
    subscribers: Mutex<HashMap<String, Arc<SubscriberMailbox>>>,
    /// Dedicated mailbox for local camera preview.
    local_preview_mailbox: Arc<SubscriberMailbox>,
}

impl CameraFrameHub {
    /// Creates an empty frame distribution hub.
    pub fn new() -> Self {
        Self {
            subscribers: Mutex::new(HashMap::new()),
            local_preview_mailbox: Arc::new(SubscriberMailbox::new()),
        }
    }

    /// Subscribes a peer stream to the frame distribution hub.
    ///
    /// Returns the peer's dedicated `SubscriberMailbox`. If the peer was already subscribed,
    /// returns the existing mailbox.
    pub fn subscribe(&self, peer_device_id_hex: &str) -> Arc<SubscriberMailbox> {
        let clean_id = peer_device_id_hex.trim().to_ascii_lowercase();
        let mut subs = self.subscribers.lock().unwrap_or_else(|e| e.into_inner());
        subs.entry(clean_id)
            .or_insert_with(|| Arc::new(SubscriberMailbox::new()))
            .clone()
    }

    /// Unsubscribes a peer stream from the hub, clearing its mailbox and waking any waiters.
    pub fn unsubscribe(&self, peer_device_id_hex: &str) {
        let clean_id = peer_device_id_hex.trim().to_ascii_lowercase();
        let removed = {
            let mut subs = self.subscribers.lock().unwrap_or_else(|e| e.into_inner());
            subs.remove(&clean_id)
        };
        if let Some(mailbox) = removed {
            mailbox.clear();
            mailbox.notify.notify_waiters();
        }
    }

    /// Returns the dedicated mailbox for local camera preview.
    pub fn local_preview_mailbox(&self) -> Arc<SubscriberMailbox> {
        Arc::clone(&self.local_preview_mailbox)
    }

    /// Publishes a raw encoded frame datagram to all active peer subscribers and local preview.
    ///
    /// Wraps the byte payload in a single `SharedCameraFrame` (`Arc<Vec<u8>>`), avoiding buffer
    /// copies across subscribers.
    pub fn publish_frame(&self, frame_bytes: Vec<u8>, local_preview_active: bool) {
        let shared = Arc::new(frame_bytes);

        // 1. Fan-out to all active remote peer subscribers
        {
            let subs = self.subscribers.lock().unwrap_or_else(|e| e.into_inner());
            for mailbox in subs.values() {
                mailbox.publish(Arc::clone(&shared));
            }
        }

        // 2. Deliver to local preview if enabled
        if local_preview_active {
            self.local_preview_mailbox.publish(shared);
        }
    }

    /// Clears all mailboxes and wakes any waiting subscriber loops (e.g. during daemon shutdown).
    pub fn clear_all(&self) {
        let subs = {
            let mut guard = self.subscribers.lock().unwrap_or_else(|e| e.into_inner());
            let list: Vec<Arc<SubscriberMailbox>> = guard.values().cloned().collect();
            guard.clear();
            list
        };
        for mailbox in subs {
            mailbox.clear();
            mailbox.notify.notify_waiters();
        }
        self.local_preview_mailbox.clear();
        self.local_preview_mailbox.notify.notify_waiters();
    }

    /// Returns the number of currently active remote subscribers.
    pub fn active_subscriber_count(&self) -> usize {
        let subs = self.subscribers.lock().unwrap_or_else(|e| e.into_inner());
        subs.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_hub_multi_subscriber_fanout() {
        let hub = CameraFrameHub::new();
        let peer_a = "peer_aaa";
        let peer_b = "peer_bbb";

        let sub_a = hub.subscribe(peer_a);
        let sub_b = hub.subscribe(peer_b);
        let preview = hub.local_preview_mailbox();

        assert_eq!(hub.active_subscriber_count(), 2);

        let frame1 = vec![1, 2, 3, 4];
        hub.publish_frame(frame1.clone(), true);

        let got_a = sub_a.take().expect("Peer A must receive frame");
        let got_b = sub_b.take().expect("Peer B must receive frame");
        let got_prev = preview.take().expect("Preview must receive frame");

        assert_eq!(*got_a, frame1);
        assert_eq!(*got_b, frame1);
        assert_eq!(*got_prev, frame1);

        // Mailboxes are now empty after take()
        assert!(sub_a.take().is_none());
        assert!(sub_b.take().is_none());
        assert!(preview.take().is_none());
    }

    #[test]
    fn test_frame_hub_slow_receiver_does_not_starve_fast_receiver() {
        let hub = CameraFrameHub::new();
        let fast_peer = "peer_fast";
        let slow_peer = "peer_slow";

        let sub_fast = hub.subscribe(fast_peer);
        let sub_slow = hub.subscribe(slow_peer);

        // Publish frame 1
        hub.publish_frame(vec![10], false);
        // Fast peer reads frame 1
        assert_eq!(*sub_fast.take().unwrap(), vec![10]);

        // Publish frame 2 (slow peer has not read frame 1 yet)
        hub.publish_frame(vec![20], false);
        // Fast peer reads frame 2
        assert_eq!(*sub_fast.take().unwrap(), vec![20]);

        // Slow peer only reads now; it should receive the LATEST frame (20), overwriting stale frame (10)
        let got_slow = sub_slow.take().expect("Slow peer should receive frame");
        assert_eq!(*got_slow, vec![20]);
    }

    #[test]
    fn test_frame_hub_unsubscribe_clears_mailbox_and_wakes_waiters() {
        let hub = CameraFrameHub::new();
        let peer = "peer_unsub";
        let sub = hub.subscribe(peer);

        hub.publish_frame(vec![42], false);
        assert!(sub.latest.lock().unwrap().is_some());

        hub.unsubscribe(peer);
        assert_eq!(hub.active_subscriber_count(), 0);
        assert!(sub.take().is_none(), "Unsubscribed mailbox must be cleared");
    }

    #[test]
    fn test_frame_hub_clear_all_during_shutdown() {
        let hub = CameraFrameHub::new();
        let sub_a = hub.subscribe("peer_1");
        let sub_b = hub.subscribe("peer_2");
        let prev = hub.local_preview_mailbox();

        hub.publish_frame(vec![99], true);
        assert_eq!(hub.active_subscriber_count(), 2);

        hub.clear_all();
        assert_eq!(hub.active_subscriber_count(), 0);
        assert!(sub_a.take().is_none());
        assert!(sub_b.take().is_none());
        assert!(prev.take().is_none());
    }
}
