//! # Bounded Audio Jitter Buffer & Playout Sequencer
//!
//! ## 1. Module Purpose & Scope
//! This module implements a deterministic, zero-steady-state-allocation, slot-indexed ring jitter
//! buffer (`JitterBuffer`) for reassembling out-of-order authenticated UDP audio datagrams (`IUA2`)
//! into sequential 5 ms stereo 16-bit PCM frames (`AUDIO_FRAME_BYTES = 960` bytes at 48 kHz).
//!
//! ### Hardened Batch 1G.8-r2 Playout & Sequencing Invariants (`AUD-1G7-11`, `AUD-1G7-20`, `NEW-08`):
//! 1. **Monotonic Session-Order Isolation**: Tracks `(active_session_order, active_session_id)`.
//!    Delayed packets from an older superseded session (`session_order < active_session_order`) are
//!    dropped cleanly instead of thrashing `reset()` against the newer active session.
//! 2. **Monotonic Played-Sequence Floor (`min_seq_floor`)**: Updates `min_seq_floor` on
//!    stall resyncs AND whenever `pop_frame_into()` re-enters prebuffering after draining
//!    or snapping forward — preventing delayed in-window packets from rewinding `playhead_seq`
//!    into already-played frames.
//! 3. **Overrun & Gap Stall Recovery**: Automatically resynchronizes on sustained future
//!    overruns while `!prebuffering` (`OVERRUN_RESYNC_THRESHOLD = 4`) and snaps forward after
//!    bounded consecutive Packet Loss Concealment (PLC) silence frames (`MAX_CONSECUTIVE_PLC_FRAMES = 4`).
//! 4. **Zero Steady-State Allocations**: `pop_frame_into(&mut [u8; AUDIO_FRAME_BYTES])` copies
//!    directly into a stack-allocated 960-byte caller buffer while retaining all preallocated
//!    slot capacities (`slot.data.clear()`).
//!
//! ## 2. Architectural Linkages & Dependencies
//! - **Upstream Callers**:
//!   - `crate::audio::AudioManager` (`app/src/audio/mod.rs`): The UDP sink receiver loop pushes
//!     authenticated `IUA2` frames via `push_packet_for_session()`, and the 5 ms playout worker
//!     drains sequential frames via `pop_frame_into()`.
//! - **Downstream Callees**:
//!   - `crate::security::audio_udp`: Uses `AudioDatagramHeader`, `AUDIO_FLAG_SILENCE`, and
//!     `AUDIO_FRAME_BYTES` constants for canonical framing validation and compact silence expansion.
//! - **Cross-Platform / Cross-Device Flow**:
//!   - Bridges the asynchronous network transport layer (Windows WASAPI / macOS SHM sender over
//!     UDP port 58284) and the deterministic real-time CoreAudio C11 SPSC consumer (`audio_macos.c`).
//!
//! ## 3. Threading & Concurrency Model
//! - Protected by `PLAYOUT_STATE_LOCK` and `JITTER_BUFFER: OnceLock<Mutex<JitterBuffer>>` inside
//!   `app/src/audio/mod.rs`.
//! - Never held across `.await` points; all push, pop, and reset operations execute in $O(1)$
//!   or bounded $O(\text{JITTER\_CAPACITY\_SLOTS})$ time ($64$ slots max) with zero heap allocations.
//!
//! ## 4. Security & Safety Invariants
//! - **Bounded Memory Footprint**: Preallocates exactly `JITTER_CAPACITY_SLOTS = 64` slots × 960 bytes
//!   ($61.44\text{ KiB}$ total), making memory exhaustion via sequence number spraying impossible.
//! - **Replay & Rewind Immunity**: Rejects `pkt_seq == 0`, duplicate sequence numbers, late frames
//!   behind `playhead_seq` or `min_seq_floor`, and stale packets from older `session_order` epochs.
//! - **Overflow-Safe Arithmetic**: Uses `saturating_add` and `saturating_sub` across sequence window
//!   calculations and telemetry counters to prevent integer wraparound panics.

use crate::security::audio_udp::{
    AudioDatagramHeader, AUDIO_FLAG_SILENCE, AUDIO_FRAME_BYTES,
};

/// Maximum number of 5ms audio frames buffered concurrently (64 frames = 320ms).
pub const JITTER_CAPACITY_SLOTS: usize = 64;

/// Target prebuffer frame threshold before commencing playout (4 frames = 20ms).
pub const PREBUFFER_FRAMES: usize = 4;

/// Maximum backward shift permitted during initial prebuffering (bounded to 2x prebuffer = 40 ms).
const MAX_PREBUFFER_BACKSHIFT: u64 = (PREBUFFER_FRAMES as u64) * 2;

/// Number of consecutive future overruns while active before resynchronizing playhead.
const OVERRUN_RESYNC_THRESHOLD: u32 = PREBUFFER_FRAMES as u32;

/// Maximum consecutive missing-frame PLC pops before snapping forward / re-entering prebuffering.
const MAX_CONSECUTIVE_PLC_FRAMES: u32 = 4;

/// Individual ring-buffer slot holding a single 5 ms audio frame or compact silence marker.
#[derive(Clone, Default)]
struct JitterSlot {
    /// Monotonic 1-based packet sequence number (`AudioDatagramHeader::pkt_seq`) stored in this slot.
    seq: u64,
    /// Sender-assigned presentation timestamp in microseconds (`AudioDatagramHeader::timestamp_us`).
    #[allow(dead_code)]
    timestamp_us: u32,
    /// Preallocated 960-byte PCM buffer (empty when `is_silence == true`).
    data: Vec<u8>,
    /// True if this frame carries `AUDIO_FLAG_SILENCE` and should expand to 960 zero bytes on pop.
    is_silence: bool,
    /// True if this slot currently contains an unplayed frame waiting for `playhead_seq`.
    occupied: bool,
}

/// Bounded slot-indexed jitter buffer for out-of-order UDP audio packet reassembly.
pub struct JitterBuffer {
    /// Fixed-size ring of `JITTER_CAPACITY_SLOTS` (64) preallocated frame slots indexed by `seq % 64`.
    slots: Vec<JitterSlot>,
    /// 8-byte cryptographic session identifier of the currently active audio stream.
    active_session_id: Option<[u8; 8]>,
    /// Monotonic session registration order from `AudioSessionRegistry` used to reject older sessions.
    active_session_order: u64,
    /// Next 1-based packet sequence number scheduled to be popped by the 5 ms playout timer.
    playhead_seq: u64,
    /// Highest valid packet sequence number accepted into the buffer for the current session.
    highest_seq: u64,
    /// Monotonic lower bound below which delayed packets are rejected even during prebuffering.
    min_seq_floor: u64,
    /// True while accumulating `PREBUFFER_FRAMES` (4 frames = 20 ms) prior to starting or resuming playout.
    prebuffering: bool,
    /// Count of consecutive packets arriving beyond `playhead_seq + JITTER_CAPACITY_SLOTS` while active.
    consecutive_overruns: u32,
    /// Count of consecutive missing-frame PLC silence insertions emitted during active playout.
    consecutive_plc: u32,
    /// Cumulative count of valid audio packets accepted into the jitter buffer.
    total_received: u64,
    /// Cumulative count of packets dropped because they arrived late or belonged to a superseded session.
    total_dropped_late: u64,
    /// Cumulative count of packets arriving ahead of the 64-slot capacity window while active.
    total_overruns: u64,
    /// Cumulative count of playout ticks where `playhead_seq` was missing (PLC silence emitted).
    total_underruns: u64,
    /// Cumulative count of 1-byte `AUDIO_FLAG_SILENCE` packets expanded into 960-byte zero frames.
    total_silence_expanded: u64,
}

impl Default for JitterBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl JitterBuffer {
    /// Constructs a new `JitterBuffer` in the `prebuffering` state with 64 preallocated 960-byte slots.
    pub fn new() -> Self {
        let mut slots = Vec::with_capacity(JITTER_CAPACITY_SLOTS);
        for _ in 0..JITTER_CAPACITY_SLOTS {
            slots.push(JitterSlot {
                seq: 0,
                timestamp_us: 0,
                data: Vec::with_capacity(AUDIO_FRAME_BYTES),
                is_silence: false,
                occupied: false,
            });
        }
        Self {
            slots,
            active_session_id: None,
            active_session_order: 0,
            playhead_seq: 0,
            highest_seq: 0,
            min_seq_floor: 0,
            prebuffering: true,
            consecutive_overruns: 0,
            consecutive_plc: 0,
            total_received: 0,
            total_dropped_late: 0,
            total_overruns: 0,
            total_underruns: 0,
            total_silence_expanded: 0,
        }
    }

    /// Pushes a decrypted datagram tagged with its monotonic `session_order` (`NEW-08`).
    ///
    /// Packets belonging to a strictly older `session_order` are silently dropped rather than
    /// triggering a buffer wipe on the active session.
    ///
    /// # Arguments
    /// * `session_order` - Monotonic session generation assigned by `AudioSessionRegistry`.
    /// * `hdr` - Authenticated 32-byte `IUA2` datagram header.
    /// * `payload` - Decrypted payload bytes (960 bytes for PCM, 1 byte for compact silence).
    ///
    /// # Returns
    /// `true` if the frame was accepted into a jitter slot, or `false` if dropped (late, duplicate,
    /// out-of-window overrun, or stale session).
    pub fn push_packet_for_session(
        &mut self,
        session_order: u64,
        hdr: &AudioDatagramHeader,
        payload: &[u8],
    ) -> bool {
        // 1. Verify session continuity; isolate active stream from delayed packets of older sessions.
        if let Some(active_id) = self.active_session_id {
            if active_id != hdr.session_id {
                if session_order > 0 && self.active_session_order > 0 && session_order < self.active_session_order {
                    // Reject delayed packet from an older superseded session without resetting active session (`NEW-08`)
                    self.total_dropped_late = self.total_dropped_late.saturating_add(1);
                    return false;
                }
                self.reset();
                self.active_session_id = Some(hdr.session_id);
                self.active_session_order = session_order;
            }
        } else {
            self.active_session_id = Some(hdr.session_id);
            self.active_session_order = session_order;
        }

        // Sequence number 0 is reserved as the uninitialized sentinel in IUA2.
        let seq = hdr.pkt_seq;
        if seq == 0 {
            return false;
        }

        // 2. Anchor initial playhead or permit bounded backward shift during initial prebuffering.
        if self.playhead_seq == 0 {
            self.playhead_seq = seq;
            self.highest_seq = seq;
            self.min_seq_floor = 0;
        } else if self.prebuffering && seq < self.playhead_seq {
            // Never rewind below `min_seq_floor` (already played before re-entering prebuffering).
            if seq < self.min_seq_floor {
                self.total_dropped_late = self.total_dropped_late.saturating_add(1);
                return false;
            }
            // Bound backward shift to 2x prebuffer (8 frames = 40ms) so stale packets cannot bloat latency.
            if self.highest_seq.saturating_sub(seq) > MAX_PREBUFFER_BACKSHIFT {
                self.total_dropped_late = self.total_dropped_late.saturating_add(1);
                return false;
            }
            self.playhead_seq = seq;
        }

        // 3. During active playout (`!prebuffering`), any packet behind `playhead_seq` is late and dropped.
        if !self.prebuffering && seq < self.playhead_seq {
            self.total_dropped_late = self.total_dropped_late.saturating_add(1);
            return false;
        }

        // 4. Handle future packets arriving beyond the 64-slot ring window (`playhead_seq + 64`).
        if seq >= self.playhead_seq.saturating_add(JITTER_CAPACITY_SLOTS as u64) {
            if self.prebuffering {
                // While prebuffering, immediately resynchronize window to the new sequence burst.
                self.reset_to_seq(seq);
            } else {
                // While actively playing, require `OVERRUN_RESYNC_THRESHOLD` (4) consecutive overruns
                // before snapping to avoid resetting on a single anomalous out-of-order spike.
                self.total_overruns = self.total_overruns.saturating_add(1);
                self.consecutive_overruns = self.consecutive_overruns.saturating_add(1);
                if self.consecutive_overruns >= OVERRUN_RESYNC_THRESHOLD {
                    self.reset_to_seq(seq);
                } else {
                    return false;
                }
            }
        } else {
            self.consecutive_overruns = 0;
        }

        if seq > self.highest_seq {
            self.highest_seq = seq;
        }

        // 5. Map sequence number into the 64-slot circular array and reject duplicates.
        let slot_idx = (seq % (JITTER_CAPACITY_SLOTS as u64)) as usize;
        let slot = &mut self.slots[slot_idx];

        if slot.occupied && slot.seq == seq {
            return false;
        }

        // 6. Store frame metadata and PCM payload (or mark compact silence without copying 960 zeros).
        let is_silence = (hdr.flags & AUDIO_FLAG_SILENCE) != 0;
        slot.seq = seq;
        slot.timestamp_us = hdr.timestamp_us;
        slot.is_silence = is_silence;
        slot.data.clear();
        if !is_silence {
            let copy_len = payload.len().min(AUDIO_FRAME_BYTES);
            slot.data.extend_from_slice(&payload[..copy_len]);
            if copy_len < AUDIO_FRAME_BYTES {
                slot.data.resize(AUDIO_FRAME_BYTES, 0);
            }
        }
        slot.occupied = true;
        self.total_received = self.total_received.saturating_add(1);

        // 7. Exit prebuffering once `PREBUFFER_FRAMES` (4 frames = 20ms) are ready.
        if self.prebuffering {
            let buffered_count = self.buffered_frames_count();
            if buffered_count >= PREBUFFER_FRAMES {
                self.prebuffering = false;
                self.consecutive_plc = 0;
            }
        }

        true
    }

    /// Backwards-compatible helper for unit tests without explicit session order tracking.
    #[cfg(test)]
    pub fn push_packet(&mut self, hdr: &AudioDatagramHeader, payload: &[u8]) -> bool {
        self.push_packet_for_session(0, hdr, payload)
    }

    /// Pops the next sequential 5ms audio frame directly into a caller-owned 960-byte buffer
    /// with zero steady-state heap allocation.
    ///
    /// If the next sequential frame is missing during active playout, emits a zeroed PLC frame
    /// and either re-enters prebuffering (if caught up past `highest_seq`) or snaps forward
    /// after `MAX_CONSECUTIVE_PLC_FRAMES` (4) missing frames.
    pub fn pop_frame_into(&mut self, out: &mut [u8; AUDIO_FRAME_BYTES]) -> bool {
        if self.playhead_seq == 0 || self.prebuffering {
            return false;
        }

        let slot_idx = (self.playhead_seq % (JITTER_CAPACITY_SLOTS as u64)) as usize;
        let slot = &mut self.slots[slot_idx];

        if slot.occupied && slot.seq == self.playhead_seq {
            // Sequential frame hit: consume slot, advance playhead, and copy or expand silence.
            slot.occupied = false;
            let is_silence = slot.is_silence;
            self.playhead_seq = self.playhead_seq.saturating_add(1);
            self.consecutive_plc = 0;

            if is_silence {
                self.total_silence_expanded = self.total_silence_expanded.saturating_add(1);
                out.fill(0);
            } else {
                let n = slot.data.len().min(AUDIO_FRAME_BYTES);
                out[..n].copy_from_slice(&slot.data[..n]);
                if n < AUDIO_FRAME_BYTES {
                    out[n..].fill(0);
                }
            }
            // Clear vector length while preserving the 960-byte heap capacity for zero-alloc reuse.
            slot.data.clear();
            true
        } else {
            // Frame miss (underrun / packet loss): advance playhead and emit 5ms PLC silence.
            self.playhead_seq = self.playhead_seq.saturating_add(1);
            self.total_underruns = self.total_underruns.saturating_add(1);
            self.consecutive_plc = self.consecutive_plc.saturating_add(1);

            if self.playhead_seq > self.highest_seq {
                // Anchor `min_seq_floor` to `playhead_seq` so delayed packets from already-played
                // sequence numbers can NEVER rewind playback upon re-entering prebuffering (`NEW-08`).
                self.min_seq_floor = self.playhead_seq;
                self.prebuffering = true;
                self.consecutive_plc = 0;
            } else if self.consecutive_plc >= MAX_CONSECUTIVE_PLC_FRAMES {
                // Wide sequence gap: snap playhead directly to the next occupied frame to avoid
                // walking across a large gap at 5ms per frame.
                if let Some(next_seq) = self.earliest_occupied_seq_from(self.playhead_seq) {
                    self.playhead_seq = next_seq;
                    self.min_seq_floor = next_seq;
                } else {
                    self.min_seq_floor = self.playhead_seq;
                    self.prebuffering = true;
                }
                self.consecutive_plc = 0;
            }

            out.fill(0);
            true
        }
    }

    /// Allocating convenience wrapper around `pop_frame_into` used by unit tests.
    #[cfg(test)]
    pub fn pop_frame(&mut self) -> Option<Vec<u8>> {
        let mut buf = [0u8; AUDIO_FRAME_BYTES];
        if self.pop_frame_into(&mut buf) {
            Some(buf.to_vec())
        } else {
            None
        }
    }

    /// Finds the lowest sequence number `>= min_seq` currently occupying a slot in the buffer.
    fn earliest_occupied_seq_from(&self, min_seq: u64) -> Option<u64> {
        self.slots
            .iter()
            .filter(|s| s.occupied && s.seq >= min_seq)
            .map(|s| s.seq)
            .min()
    }

    /// Returns the number of currently occupied frame slots in the jitter buffer (`0..=64`).
    pub fn buffered_frames_count(&self) -> usize {
        self.slots.iter().filter(|s| s.occupied).count()
    }

    /// Returns `true` if the jitter buffer is currently accumulating prebuffer frames before playout.
    #[cfg(test)]
    pub fn is_prebuffering(&self) -> bool {
        self.prebuffering
    }

    /// Returns the cumulative count of late or superseded packets dropped by the buffer.
    #[cfg(test)]
    pub fn total_dropped_late(&self) -> u64 {
        self.total_dropped_late
    }

    /// Returns the cumulative count of compact 1-byte silence frames expanded into 960 zero bytes.
    #[cfg(test)]
    pub fn total_silence_expanded(&self) -> u64 {
        self.total_silence_expanded
    }

    /// Clears all buffered slots, resets session bindings, and returns to the initial `prebuffering` state.
    pub fn reset(&mut self) {
        for slot in &mut self.slots {
            slot.occupied = false;
            slot.seq = 0;
            slot.data.clear();
        }
        self.active_session_id = None;
        self.active_session_order = 0;
        self.playhead_seq = 0;
        self.highest_seq = 0;
        self.min_seq_floor = 0;
        self.prebuffering = true;
        self.consecutive_overruns = 0;
        self.consecutive_plc = 0;
    }

    /// Clears all buffered slots and re-anchors `playhead_seq`, `highest_seq`, and `min_seq_floor`
    /// to `seq` while preserving the active session identity.
    pub fn reset_to_seq(&mut self, seq: u64) {
        for slot in &mut self.slots {
            slot.occupied = false;
            slot.seq = 0;
            slot.data.clear();
        }
        self.playhead_seq = seq;
        self.highest_seq = seq;
        self.min_seq_floor = seq;
        self.prebuffering = true;
        self.consecutive_overruns = 0;
        self.consecutive_plc = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::audio_udp::{AUDIO_FLAG_PCM_FRAME, AUDIO_FRAME_SAMPLES_PER_CH};

    fn make_header_with_session(session_id: [u8; 8], seq: u64, flags: u16) -> AudioDatagramHeader {
        AudioDatagramHeader {
            version: 2,
            flags,
            session_id,
            pkt_seq: seq,
            timestamp_us: (seq as u32) * 5000,
            frame_samples: AUDIO_FRAME_SAMPLES_PER_CH,
            payload_len: if flags == AUDIO_FLAG_SILENCE {
                1
            } else {
                AUDIO_FRAME_BYTES as u16
            },
        }
    }

    fn make_header(seq: u64, flags: u16) -> AudioDatagramHeader {
        make_header_with_session([1u8; 8], seq, flags)
    }

    #[test]
    fn test_jitter_buffer_prebuffering_and_in_order_playout() {
        let mut jb = JitterBuffer::new();
        assert!(jb.is_prebuffering());

        for i in 1..=3 {
            let hdr = make_header(i, AUDIO_FLAG_PCM_FRAME);
            let pcm = vec![i as u8; AUDIO_FRAME_BYTES];
            assert!(jb.push_packet(&hdr, &pcm));
            assert!(jb.is_prebuffering());
            assert_eq!(jb.pop_frame(), None);
        }

        let hdr4 = make_header(4, AUDIO_FLAG_PCM_FRAME);
        let pcm4 = vec![4u8; AUDIO_FRAME_BYTES];
        assert!(jb.push_packet(&hdr4, &pcm4));
        assert!(!jb.is_prebuffering());

        for i in 1..=4 {
            let frame = jb.pop_frame().expect("expected frame");
            assert_eq!(frame.len(), AUDIO_FRAME_BYTES);
            assert!(frame.iter().all(|&b| b == i as u8));
        }
    }

    #[test]
    fn test_jitter_buffer_out_of_order_reassembly() {
        let mut jb = JitterBuffer::new();
        let order = [3u64, 1, 4, 2];
        for &seq in &order {
            let hdr = make_header(seq, AUDIO_FLAG_PCM_FRAME);
            let pcm = vec![seq as u8; AUDIO_FRAME_BYTES];
            assert!(jb.push_packet(&hdr, &pcm));
        }
        assert!(!jb.is_prebuffering());

        for expected in 1..=4u8 {
            let frame = jb.pop_frame().expect("expected reordered frame");
            assert!(frame.iter().all(|&b| b == expected));
        }
    }

    #[test]
    fn test_jitter_buffer_compact_silence_expansion() {
        let mut jb = JitterBuffer::new();
        for seq in 1..=4 {
            let hdr = make_header(seq, AUDIO_FLAG_SILENCE);
            assert!(jb.push_packet(&hdr, &[0u8; 1]));
        }
        let frame = jb.pop_frame().expect("expected expanded silence");
        assert_eq!(frame.len(), AUDIO_FRAME_BYTES);
        assert!(frame.iter().all(|&b| b == 0));
        assert_eq!(jb.total_silence_expanded(), 1);
    }

    #[test]
    fn test_jitter_buffer_late_and_duplicate_dropping() {
        let mut jb = JitterBuffer::new();
        for seq in 1..=4 {
            assert!(jb.push_packet(&make_header(seq, AUDIO_FLAG_PCM_FRAME), &[seq as u8; AUDIO_FRAME_BYTES]));
        }
        assert!(!jb.push_packet(&make_header(2, AUDIO_FLAG_PCM_FRAME), &[2u8; AUDIO_FRAME_BYTES]));
        let _ = jb.pop_frame();
        assert!(!jb.push_packet(&make_header(1, AUDIO_FLAG_PCM_FRAME), &[1u8; AUDIO_FRAME_BYTES]));
        assert_eq!(jb.total_dropped_late(), 1);
    }

    #[test]
    fn test_jitter_buffer_stall_recovery_deadlock_prevention() {
        let mut jb = JitterBuffer::new();
        for seq in 1..=4 {
            assert!(jb.push_packet(&make_header(seq, AUDIO_FLAG_PCM_FRAME), &[1u8; AUDIO_FRAME_BYTES]));
        }
        for _ in 0..5 {
            let _ = jb.pop_frame();
        }
        assert!(jb.is_prebuffering());

        for seq in 500..=503 {
            assert!(jb.push_packet(&make_header(seq, AUDIO_FLAG_PCM_FRAME), &[0x7Au8; AUDIO_FRAME_BYTES]));
        }
        assert!(!jb.is_prebuffering());
        let frame = jb.pop_frame().expect("recovered frame after stall");
        assert!(frame.iter().all(|&b| b == 0x7A));
    }

    #[test]
    fn test_jitter_buffer_session_rotation_isolates_and_drops_older_session() {
        let mut jb = JitterBuffer::new();
        for seq in 97..=100 {
            assert!(jb.push_packet_for_session(
                1,
                &make_header_with_session([0xAA; 8], seq, AUDIO_FLAG_PCM_FRAME),
                &[0x11; AUDIO_FRAME_BYTES],
            ));
        }
        assert!(!jb.is_prebuffering());

        // Newer session (order=2) replaces session 1
        for seq in 1..=4 {
            assert!(jb.push_packet_for_session(
                2,
                &make_header_with_session([0xBB; 8], seq, AUDIO_FLAG_PCM_FRAME),
                &[0x22; AUDIO_FRAME_BYTES],
            ));
        }
        assert!(!jb.is_prebuffering());

        // Delayed packet from older session (order=1) must be dropped without resetting session 2 (`NEW-08`)
        assert!(!jb.push_packet_for_session(
            1,
            &make_header_with_session([0xAA; 8], 101, AUDIO_FLAG_PCM_FRAME),
            &[0x11; AUDIO_FRAME_BYTES],
        ));
        assert!(!jb.is_prebuffering());
        let frame = jb.pop_frame().expect("session 2 frame must remain intact");
        assert!(frame.iter().all(|&b| b == 0x22));
    }

    #[test]
    fn test_jitter_buffer_reenter_prebuffer_sets_floor_blocking_played_rewind() {
        let mut jb = JitterBuffer::new();
        // Receive 1, 2, 4, 5 (missing 3) -> play out past 5 and re-enter prebuffering
        for &seq in &[1u64, 2, 4, 5] {
            assert!(jb.push_packet(&make_header(seq, AUDIO_FLAG_PCM_FRAME), &[seq as u8; AUDIO_FRAME_BYTES]));
        }
        for _ in 0..6 {
            let _ = jb.pop_frame();
        }
        assert!(jb.is_prebuffering());

        // Delayed packet seq=3 (within 8 frames of highest_seq=5, already played past!) MUST be rejected (`NEW-08`)
        assert!(
            !jb.push_packet(&make_header(3, AUDIO_FLAG_PCM_FRAME), &[3u8; AUDIO_FRAME_BYTES]),
            "Delayed packet behind already-played playhead must not rewind playback"
        );
    }

    #[test]
    fn test_jitter_buffer_post_stall_floor_blocks_delayed_backshift_and_active_overrun_resyncs() {
        let mut jb = JitterBuffer::new();
        for seq in 1..=4 {
            assert!(jb.push_packet(&make_header(seq, AUDIO_FLAG_PCM_FRAME), &[1u8; AUDIO_FRAME_BYTES]));
        }
        assert!(!jb.is_prebuffering());

        for seq in 300..=308 {
            let _ = jb.push_packet(&make_header(seq, AUDIO_FLAG_PCM_FRAME), &[0x55u8; AUDIO_FRAME_BYTES]);
        }
        assert!(!jb.push_packet(&make_header(250, AUDIO_FLAG_PCM_FRAME), &[0x99u8; AUDIO_FRAME_BYTES]));

        assert!(!jb.is_prebuffering());
        let frame = jb.pop_frame().expect("recovered active-overrun frame");
        assert!(frame.iter().all(|&b| b == 0x55));
    }

    #[test]
    fn test_jitter_buffer_wide_gap_snaps_forward_instead_of_blackout_walk() {
        let mut jb = JitterBuffer::new();
        for seq in 1..=4 {
            assert!(jb.push_packet(&make_header(seq, AUDIO_FLAG_PCM_FRAME), &[0x10; AUDIO_FRAME_BYTES]));
        }
        for seq in 45..=48 {
            assert!(jb.push_packet(&make_header(seq, AUDIO_FLAG_PCM_FRAME), &[0x45; AUDIO_FRAME_BYTES]));
        }
        for _ in 0..4 {
            let f = jb.pop_frame().unwrap();
            assert!(f.iter().all(|&b| b == 0x10));
        }
        for _ in 0..MAX_CONSECUTIVE_PLC_FRAMES {
            let plc = jb.pop_frame().unwrap();
            assert!(plc.iter().all(|&b| b == 0));
        }
        let recovered = jb.pop_frame().expect("snapped frame 45");
        assert!(recovered.iter().all(|&b| b == 0x45));
    }
}
