//! ============================================================================
//! Bounded Audio Jitter Buffer & Playout Sequencer
//! ============================================================================
//!
//! Hardened Batch 1G.8-r2 implementation resolving AUD-1G7-11, AUD-1G7-20,
//! and NEW-08:
//! 1. **Monotonic Session-Order Isolation**: Tracks `(active_session_order, active_session_id)`.
//!    Delayed packets from an older session (`session_order < active_session_order`) are
//!    dropped cleanly instead of thrashing `reset()` against the newer session.
//! 2. **Monotonic Played-Sequence Floor (`min_seq_floor`)**: Updates `min_seq_floor` on
//!    stall resyncs AND whenever `pop_frame_into()` re-enters prebuffering after draining
//!    or snapping forward — preventing delayed in-window packets from rewinding `playhead_seq`
//!    into already-played frames.
//! 3. **Overrun & Gap Stall Recovery**: Automatically resynchronizes on sustained future
//!    overruns while `!prebuffering` and snaps forward after bounded consecutive PLC frames.
//! 4. **Zero Steady-State Allocations**: `pop_frame_into(&mut [u8; AUDIO_FRAME_BYTES])`
//!    retains all preallocated 960-byte slot buffers (`slot.data.clear()`).
//! ============================================================================

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

#[derive(Clone, Default)]
struct JitterSlot {
    seq: u64,
    #[allow(dead_code)]
    timestamp_us: u32,
    data: Vec<u8>,
    is_silence: bool,
    occupied: bool,
}

/// Bounded slot-indexed jitter buffer for out-of-order UDP audio packet reassembly.
pub struct JitterBuffer {
    slots: Vec<JitterSlot>,
    active_session_id: Option<[u8; 8]>,
    active_session_order: u64,
    playhead_seq: u64,
    highest_seq: u64,
    min_seq_floor: u64,
    prebuffering: bool,
    consecutive_overruns: u32,
    consecutive_plc: u32,
    total_received: u64,
    total_dropped_late: u64,
    total_overruns: u64,
    total_underruns: u64,
    total_silence_expanded: u64,
}

impl Default for JitterBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl JitterBuffer {
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
    pub fn push_packet_for_session(
        &mut self,
        session_order: u64,
        hdr: &AudioDatagramHeader,
        payload: &[u8],
    ) -> bool {
        if let Some(active_id) = self.active_session_id {
            if active_id != hdr.session_id {
                if session_order > 0 && self.active_session_order > 0 && session_order < self.active_session_order {
                    // Reject delayed packet from an older superseded session without resetting active session (`NEW-08`)
                    self.total_dropped_late += 1;
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

        let seq = hdr.pkt_seq;
        if seq == 0 {
            return false;
        }

        if self.playhead_seq == 0 {
            self.playhead_seq = seq;
            self.highest_seq = seq;
            self.min_seq_floor = 0;
        } else if self.prebuffering && seq < self.playhead_seq {
            if seq < self.min_seq_floor {
                self.total_dropped_late += 1;
                return false;
            }
            if self.highest_seq.saturating_sub(seq) > MAX_PREBUFFER_BACKSHIFT {
                self.total_dropped_late += 1;
                return false;
            }
            self.playhead_seq = seq;
        }

        if !self.prebuffering && seq < self.playhead_seq {
            self.total_dropped_late += 1;
            return false;
        }

        if seq >= self.playhead_seq.saturating_add(JITTER_CAPACITY_SLOTS as u64) {
            if self.prebuffering {
                self.reset_to_seq(seq);
            } else {
                self.total_overruns += 1;
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

        let slot_idx = (seq % (JITTER_CAPACITY_SLOTS as u64)) as usize;
        let slot = &mut self.slots[slot_idx];

        if slot.occupied && slot.seq == seq {
            return false;
        }

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
        self.total_received += 1;

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
    #[allow(dead_code)]
    pub fn push_packet(&mut self, hdr: &AudioDatagramHeader, payload: &[u8]) -> bool {
        self.push_packet_for_session(0, hdr, payload)
    }

    /// Pops the next sequential 5ms audio frame directly into a caller-owned 960-byte buffer
    /// with zero steady-state heap allocation.
    pub fn pop_frame_into(&mut self, out: &mut [u8; AUDIO_FRAME_BYTES]) -> bool {
        if self.playhead_seq == 0 || self.prebuffering {
            return false;
        }

        let slot_idx = (self.playhead_seq % (JITTER_CAPACITY_SLOTS as u64)) as usize;
        let slot = &mut self.slots[slot_idx];

        if slot.occupied && slot.seq == self.playhead_seq {
            slot.occupied = false;
            let is_silence = slot.is_silence;
            self.playhead_seq += 1;
            self.consecutive_plc = 0;

            if is_silence {
                self.total_silence_expanded += 1;
                out.fill(0);
            } else {
                let n = slot.data.len().min(AUDIO_FRAME_BYTES);
                out[..n].copy_from_slice(&slot.data[..n]);
                if n < AUDIO_FRAME_BYTES {
                    out[n..].fill(0);
                }
            }
            slot.data.clear();
            true
        } else {
            self.playhead_seq += 1;
            self.total_underruns += 1;
            self.consecutive_plc = self.consecutive_plc.saturating_add(1);

            if self.playhead_seq > self.highest_seq {
                // Anchor `min_seq_floor` to `playhead_seq` so delayed packets from already-played
                // sequence numbers can NEVER rewind playback upon re-entering prebuffering (`NEW-08`).
                self.min_seq_floor = self.playhead_seq;
                self.prebuffering = true;
                self.consecutive_plc = 0;
            } else if self.consecutive_plc >= MAX_CONSECUTIVE_PLC_FRAMES {
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

    #[allow(dead_code)]
    pub fn pop_frame(&mut self) -> Option<Vec<u8>> {
        let mut buf = [0u8; AUDIO_FRAME_BYTES];
        if self.pop_frame_into(&mut buf) {
            Some(buf.to_vec())
        } else {
            None
        }
    }

    fn earliest_occupied_seq_from(&self, min_seq: u64) -> Option<u64> {
        self.slots
            .iter()
            .filter(|s| s.occupied && s.seq >= min_seq)
            .map(|s| s.seq)
            .min()
    }

    pub fn buffered_frames_count(&self) -> usize {
        self.slots.iter().filter(|s| s.occupied).count()
    }

    #[allow(dead_code)]
    pub fn is_prebuffering(&self) -> bool {
        self.prebuffering
    }

    #[allow(dead_code)]
    pub fn total_received(&self) -> u64 {
        self.total_received
    }

    #[allow(dead_code)]
    pub fn total_dropped_late(&self) -> u64 {
        self.total_dropped_late
    }

    #[allow(dead_code)]
    pub fn total_overruns(&self) -> u64 {
        self.total_overruns
    }

    #[allow(dead_code)]
    pub fn total_underruns(&self) -> u64 {
        self.total_underruns
    }

    #[allow(dead_code)]
    pub fn total_silence_expanded(&self) -> u64 {
        self.total_silence_expanded
    }

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
