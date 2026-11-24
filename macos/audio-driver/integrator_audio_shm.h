/*
 * ============================================================================
 * Integrator macOS CoreAudio HAL Audio Sink: POSIX Shared-Memory ABI Header
 * ============================================================================
 *
 * 1. MODULE PURPOSE & ARCHITECTURAL SCOPE
 * ----------------------------------------------------------------------------
 * Defines the fixed-layout POSIX shared-memory ring-buffer structure mapped
 * simultaneously by the macOS CoreAudio HAL driver (`IntegratorAudioDriver.c`,
 * executing inside `coreaudiod`) and the Integrator Rust audio capture task
 * (`app/src/audio/mod.rs::start_mac_shm_audio_capture`).
 *
 * 2. ARCHITECTURAL LINKAGES & CROSS-LANGUAGE ABI CONTRACT
 * ----------------------------------------------------------------------------
 * - Producer (`macos/audio-driver/IntegratorAudioDriver.c`): Writes stereo
 *   48 kHz 16-bit PCM frames into `buffer` and publishes `write_pos` (`Release`).
 * - Consumer (`app/src/audio/mod.rs::IntegratorAudioShmHeader`): Maps the exact
 *   `131,128`-byte (`#[repr(C, align(8))]`) memory region, verifies `magic`,
 *   consumes 960-byte (5 ms) frames, and publishes `read_pos` (`Release`).
 *
 * 3. THREADING & CONCURRENCY MODEL
 * ----------------------------------------------------------------------------
 * Lock-free Single-Producer / Single-Consumer ring buffer across processes
 * via C11 `_Atomic` 32/64-bit fields and acquire/release memory barriers.
 *
 * 4. SECURITY & SAFETY INVARIANTS
 * ----------------------------------------------------------------------------
 * - Exact `#pragma pack(push, 8)` layout must match Rust's `IntegratorAudioShmHeader`
 *   test (`test_mac_audio_shm_struct_layout`) byte-for-byte (`131,128` bytes total).
 * - Both producer and consumer enforce modulo `INTEGRATOR_AUDIO_RING_BUFFER_BYTES`
 *   bounds before indexing `buffer` so corrupt offsets never escape bounds.
 * ============================================================================
 */

#ifndef INTEGRATOR_AUDIO_SHM_H
#define INTEGRATOR_AUDIO_SHM_H

#include <stdint.h>
#include <stdatomic.h>

/** Canonical POSIX `shm_open` object identifier shared with `app/src/audio/mod.rs`. */
#define INTEGRATOR_AUDIO_SHM_NAME "/com.manveersingh.integrator.audio.sink.shm"

/** FourCC initialization sentinel `'ITGS'` (`0x49544753`) validating mapped shared memory. */
#define INTEGRATOR_AUDIO_SHM_MAGIC 0x49544753U

/** Circular SPSC PCM byte buffer capacity: `131,072` bytes (128 KiB, power of 2, ~341.3 ms @ 48 kHz stereo S16LE). */
#define INTEGRATOR_AUDIO_RING_BUFFER_BYTES (128 * 1024)

/**
 * Lock-free cross-process POSIX shared-memory header and 128 KiB PCM ring buffer (`131,128` bytes total).
 *
 * Must remain layout-identical to `app/src/audio/mod.rs::IntegratorAudioShmHeader`.
 */
#pragma pack(push, 8)
typedef struct {
    /** FourCC magic (`INTEGRATOR_AUDIO_SHM_MAGIC`); written last with release fence after init. */
    uint32_t magic;
    /** Shared-memory wire ABI version number (`1`). */
    uint32_t version;
    /** `1` while CoreAudio IO is actively running in `coreaudiod`, `0` when idle. */
    _Atomic uint32_t active;
    /** Sample format identifier: `0 = Int16 48kHz 2ch` (canonical), `1 = Float32 48kHz 2ch`. */
    _Atomic uint32_t format;
    /** Nominal device sample rate in Hz (`48000`). */
    _Atomic uint32_t sample_rate;
    /** Nominal stream channel count (`2` = stereo). */
    _Atomic uint32_t channels;
    /** Monotonic count of stereo PCM frames written by the HAL producer. */
    _Atomic uint64_t total_frames_written;
    /** Monotonic count of stereo PCM frames read by the Rust consumer. */
    _Atomic uint64_t total_frames_read;
    /** Producer write cursor byte offset within `buffer` (`[0 .. INTEGRATOR_AUDIO_RING_BUFFER_BYTES - 1]`). */
    _Atomic uint32_t write_pos;
    /** Consumer read cursor byte offset within `buffer` (`[0 .. INTEGRATOR_AUDIO_RING_BUFFER_BYTES - 1]`). */
    _Atomic uint32_t read_pos;
    /** Cumulative count of ring-buffer overflow/overrun drops reported by the HAL producer. */
    _Atomic uint32_t underruns;
    /** Interleaved stereo 16-bit PCM circular byte ring buffer (`131,072` bytes). */
    uint8_t buffer[INTEGRATOR_AUDIO_RING_BUFFER_BYTES];
} IntegratorAudioShmHeader;
#pragma pack(pop)

#endif /* INTEGRATOR_AUDIO_SHM_H */
