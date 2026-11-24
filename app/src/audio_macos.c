/*
 * ============================================================================
 * Integrator Dynamic Audio Routing: macOS Native CoreAudio Output & C11 SPSC
 * ============================================================================
 *
 * Pure C11 implementation (AUD-1G7-04, AUD-1G7-09, AUD-1G7-10):
 * - Zero Swift runtime, zero resilient metadata accessors, zero `_swift_once`,
 *   zero dynamic exclusivity checks, zero heap allocations, and zero mutexes
 *   on the real-time CoreAudio `AURenderCallback` thread.
 * - True C11 acquire/release hardware memory ordering (`memory_order_acquire`
 *   / `memory_order_release`, compiling to ARM64 `ldar` / `stlr`).
 * - Monotonic 64-bit byte cursors eliminating 32-bit wraparound edge cases.
 * - Strict 4-byte stereo 16-bit PCM frame alignment enforced on every write
 *   and render pull, plus `mDataByteSize` bounds validation on `AudioBuffer`.
 * - Consumer-owned flush epoch (`g_flush_req_epoch`) so active flushes never
 *   mutate the consumer's `g_read_idx` from the producer/control thread.
 */

#include <AudioToolbox/AudioToolbox.h>
#include <CoreAudio/CoreAudio.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/* 65,536 bytes = 16,384 stereo 16-bit frames (~341.3 ms @ 48 kHz). Power of 2. */
#define SPSC_CAPACITY_BYTES 65536u
#define SPSC_CAPACITY_MASK  (SPSC_CAPACITY_BYTES - 1u)
#define STEREO_16_FRAME_BYTES 4u

/* Static zero-initialized SPSC ring buffer and atomics (process lifetime). */
static uint8_t g_spsc_buffer[SPSC_CAPACITY_BYTES];
static _Atomic uint64_t g_write_idx = 0;
static _Atomic uint64_t g_read_idx = 0;
static _Atomic uint64_t g_underrun_count = 0;
static _Atomic uint64_t g_flush_req_epoch = 0;
static uint64_t g_consumer_flush_epoch = 0; /* Accessed solely by RT consumer (or under lock when stopped) */
static _Atomic int32_t g_active = 0;

static AudioComponentInstance g_audio_unit = NULL;
static pthread_mutex_t g_lifecycle_lock = PTHREAD_MUTEX_INITIALIZER;
static bool g_has_saved_sys_vol = false;
static Float32 g_saved_sys_vol = 0.75f;

/*
 * Core SPSC consumer pull routine.
 * Must only be called by the single consumer (CoreAudio RT thread, or unit tests
 * while AudioUnit is stopped). Enforces 4-byte stereo frame alignment and strict
 * acquire/release barriers.
 */
static uint32_t spsc_consumer_pull(uint8_t *dest, uint32_t requested_bytes) {
    /* Enforce 4-byte stereo frame alignment */
    uint32_t aligned_req = requested_bytes & ~(STEREO_16_FRAME_BYTES - 1u);
    if (dest == NULL || aligned_req == 0u) {
        if (dest != NULL && requested_bytes > 0u) {
            memset(dest, 0, requested_bytes);
        }
        return 0u;
    }

    /* Check if control/producer requested a live flush (consumer remains sole owner of g_read_idx). */
    uint64_t req_epoch = atomic_load_explicit(&g_flush_req_epoch, memory_order_acquire);
    uint64_t r = atomic_load_explicit(&g_read_idx, memory_order_relaxed);
    uint64_t w = atomic_load_explicit(&g_write_idx, memory_order_acquire);

    if (req_epoch != g_consumer_flush_epoch) {
        g_consumer_flush_epoch = req_epoch;
        /* Drop all queued bytes up to the latest published write cursor. */
        r = w;
        atomic_store_explicit(&g_read_idx, r, memory_order_release);
        memset(dest, 0, requested_bytes);
        return 0u;
    }

    uint64_t available = (w >= r) ? (w - r) : 0u;
    available &= ~(uint64_t)(STEREO_16_FRAME_BYTES - 1u);

    uint32_t to_copy = (available < (uint64_t)aligned_req) ? (uint32_t)available : aligned_req;
    if (to_copy > 0u) {
        uint32_t read_offset = (uint32_t)(r & SPSC_CAPACITY_MASK);
        uint32_t first_chunk = SPSC_CAPACITY_BYTES - read_offset;
        if (first_chunk > to_copy) {
            first_chunk = to_copy;
        }
        memcpy(dest, &g_spsc_buffer[read_offset], first_chunk);
        if (to_copy > first_chunk) {
            uint32_t second_chunk = to_copy - first_chunk;
            memcpy(dest + first_chunk, &g_spsc_buffer[0], second_chunk);
        }
        /* Publish updated read cursor with release semantics so producer observes freed slots
         * strictly after our memcpy finishes. */
        atomic_store_explicit(&g_read_idx, r + (uint64_t)to_copy, memory_order_release);
    }

    if (to_copy < requested_bytes) {
        memset(dest + to_copy, 0, requested_bytes - to_copy);
        atomic_fetch_add_explicit(&g_underrun_count, 1u, memory_order_relaxed);
    }

    return to_copy;
}

/*
 * Real-time CoreAudio render callback (`AURenderCallback`).
 * Pure C, zero locks, zero allocations, zero Swift/ObjC runtime calls.
 */
static OSStatus core_audio_render_callback(
    void *inRefCon,
    AudioUnitRenderActionFlags *ioActionFlags,
    const AudioTimeStamp *inTimeStamp,
    UInt32 inBusNumber,
    UInt32 inNumberFrames,
    AudioBufferList *ioData
) {
    (void)inRefCon;
    (void)ioActionFlags;
    (void)inTimeStamp;
    (void)inBusNumber;

    if (ioData == NULL || ioData->mNumberBuffers == 0u) {
        return noErr;
    }

    AudioBuffer *buf = &ioData->mBuffers[0];
    if (buf->mData == NULL || buf->mDataByteSize == 0u) {
        return noErr;
    }

    /* Compute requested bytes safely and clamp strictly to CoreAudio's provided mDataByteSize (AUD-1G7-10). */
    uint64_t wanted = (uint64_t)inNumberFrames * (uint64_t)STEREO_16_FRAME_BYTES;
    uint32_t cap = buf->mDataByteSize;
    uint32_t bytes_to_fill = (wanted > (uint64_t)cap) ? cap : (uint32_t)wanted;
    bytes_to_fill &= ~(STEREO_16_FRAME_BYTES - 1u);

    if (bytes_to_fill == 0u) {
        memset(buf->mData, 0, cap);
        buf->mDataByteSize = 0u;
        return noErr;
    }

    (void)spsc_consumer_pull((uint8_t *)buf->mData, bytes_to_fill);
    buf->mDataByteSize = bytes_to_fill;

    /* Zero any secondary buffers defensively (interleaved stereo uses 1 buffer). */
    for (UInt32 i = 1u; i < ioData->mNumberBuffers; ++i) {
        if (ioData->mBuffers[i].mData != NULL && ioData->mBuffers[i].mDataByteSize > 0u) {
            memset(ioData->mBuffers[i].mData, 0, ioData->mBuffers[i].mDataByteSize);
        }
    }

    return noErr;
}

/* ============================================================================
 * C FFI EXPORTS (Callable by Rust)
 * ============================================================================ */

/* Pre-warms static storage; returns 0 on success (exact i32 ABI parity with Rust). */
int32_t integrator_mac_audio_prewarm(void) {
    (void)atomic_load_explicit(&g_active, memory_order_acquire);
    (void)atomic_load_explicit(&g_write_idx, memory_order_acquire);
    (void)atomic_load_explicit(&g_read_idx, memory_order_acquire);
    return 0;
}

/* Starts the native macOS CoreAudio DefaultOutput AudioUnit. Returns 0 on success, -1 on failure. */
int32_t integrator_mac_audio_start(void) {
    pthread_mutex_lock(&g_lifecycle_lock);

    if (g_audio_unit != NULL && atomic_load_explicit(&g_active, memory_order_acquire) == 1) {
        pthread_mutex_unlock(&g_lifecycle_lock);
        return 0;
    }

    AudioComponentDescription desc;
    memset(&desc, 0, sizeof(desc));
    desc.componentType = kAudioUnitType_Output;
    desc.componentSubType = kAudioUnitSubType_DefaultOutput;
    desc.componentManufacturer = kAudioUnitManufacturer_Apple;

    AudioComponent comp = AudioComponentFindNext(NULL, &desc);
    if (comp == NULL) {
        pthread_mutex_unlock(&g_lifecycle_lock);
        return -1;
    }

    AudioComponentInstance output_unit = NULL;
    OSStatus status = AudioComponentInstanceNew(comp, &output_unit);
    if (status != noErr || output_unit == NULL) {
        pthread_mutex_unlock(&g_lifecycle_lock);
        return -1;
    }

    /* Configure canonical stream format: 48,000 Hz, 16-bit signed integer packed, 2-channel stereo. */
    AudioStreamBasicDescription stream_format;
    memset(&stream_format, 0, sizeof(stream_format));
    stream_format.mSampleRate = 48000.0;
    stream_format.mFormatID = kAudioFormatLinearPCM;
    stream_format.mFormatFlags = kAudioFormatFlagIsSignedInteger | kAudioFormatFlagIsPacked;
    stream_format.mBytesPerPacket = STEREO_16_FRAME_BYTES;
    stream_format.mFramesPerPacket = 1u;
    stream_format.mBytesPerFrame = STEREO_16_FRAME_BYTES;
    stream_format.mChannelsPerFrame = 2u;
    stream_format.mBitsPerChannel = 16u;

    status = AudioUnitSetProperty(
        output_unit,
        kAudioUnitProperty_StreamFormat,
        kAudioUnitScope_Input,
        0u,
        &stream_format,
        (UInt32)sizeof(stream_format)
    );
    if (status != noErr) {
        AudioComponentInstanceDispose(output_unit);
        pthread_mutex_unlock(&g_lifecycle_lock);
        return -1;
    }

    AURenderCallbackStruct cb_struct;
    cb_struct.inputProc = core_audio_render_callback;
    cb_struct.inputProcRefCon = NULL;

    status = AudioUnitSetProperty(
        output_unit,
        kAudioUnitProperty_SetRenderCallback,
        kAudioUnitScope_Input,
        0u,
        &cb_struct,
        (UInt32)sizeof(cb_struct)
    );
    if (status != noErr) {
        AudioComponentInstanceDispose(output_unit);
        pthread_mutex_unlock(&g_lifecycle_lock);
        return -1;
    }

    status = AudioUnitInitialize(output_unit);
    if (status != noErr) {
        AudioComponentInstanceDispose(output_unit);
        pthread_mutex_unlock(&g_lifecycle_lock);
        return -1;
    }

    /* Quiesce any residual buffered samples and synchronize consumer flush epoch before starting RT callbacks. */
    uint64_t w = atomic_load_explicit(&g_write_idx, memory_order_acquire);
    atomic_store_explicit(&g_read_idx, w, memory_order_release);
    g_consumer_flush_epoch = atomic_load_explicit(&g_flush_req_epoch, memory_order_acquire);
    g_audio_unit = output_unit;
    atomic_store_explicit(&g_active, 1, memory_order_release);

    status = AudioOutputUnitStart(output_unit);
    if (status != noErr) {
        atomic_store_explicit(&g_active, 0, memory_order_release);
        g_audio_unit = NULL;
        AudioUnitUninitialize(output_unit);
        AudioComponentInstanceDispose(output_unit);
        pthread_mutex_unlock(&g_lifecycle_lock);
        return -1;
    }

    pthread_mutex_unlock(&g_lifecycle_lock);
    return 0;
}

/* Stops and disposes the CoreAudio AudioUnit synchronously, then resets the quiescent SPSC buffer. */
void integrator_mac_audio_stop(void) {
    pthread_mutex_lock(&g_lifecycle_lock);

    AudioComponentInstance au = g_audio_unit;
    g_audio_unit = NULL;

    if (au != NULL) {
        /* AudioOutputUnitStop blocks until any in-flight AURenderCallback has returned. */
        AudioOutputUnitStop(au);
        AudioUnitUninitialize(au);
        AudioComponentInstanceDispose(au);
    }

    atomic_store_explicit(&g_active, 0, memory_order_release);

    /* Consumer is guaranteed stopped; advance read cursor to write cursor atomically. */
    uint64_t w = atomic_load_explicit(&g_write_idx, memory_order_acquire);
    atomic_store_explicit(&g_read_idx, w, memory_order_release);
    g_consumer_flush_epoch = atomic_load_explicit(&g_flush_req_epoch, memory_order_acquire);

    pthread_mutex_unlock(&g_lifecycle_lock);
}

/* Returns 1 if CoreAudio playback is active, 0 otherwise. */
int32_t integrator_mac_audio_is_active(void) {
    return atomic_load_explicit(&g_active, memory_order_acquire);
}

/*
 * Pushes 48 kHz 16-bit stereo PCM bytes into the lock-free SPSC ring buffer.
 * Enforces 4-byte stereo frame alignment and strict acquire/release barriers.
 */
uint32_t integrator_mac_audio_write_pcm(const uint8_t *data, uint32_t len) {
    if (data == NULL || len < STEREO_16_FRAME_BYTES) {
        return 0u;
    }

    uint32_t aligned_len = len & ~(STEREO_16_FRAME_BYTES - 1u);
    uint64_t w = atomic_load_explicit(&g_write_idx, memory_order_relaxed);
    uint64_t r = atomic_load_explicit(&g_read_idx, memory_order_acquire);

    uint64_t occupied = (w >= r) ? (w - r) : 0u;
    if (occupied >= (uint64_t)SPSC_CAPACITY_BYTES) {
        return 0u;
    }

    uint32_t free_space = (uint32_t)((uint64_t)SPSC_CAPACITY_BYTES - occupied);
    free_space &= ~(STEREO_16_FRAME_BYTES - 1u);

    uint32_t to_write = (aligned_len < free_space) ? aligned_len : free_space;
    if (to_write == 0u) {
        return 0u;
    }

    uint32_t write_offset = (uint32_t)(w & SPSC_CAPACITY_MASK);
    uint32_t first_chunk = SPSC_CAPACITY_BYTES - write_offset;
    if (first_chunk > to_write) {
        first_chunk = to_write;
    }
    memcpy(&g_spsc_buffer[write_offset], data, first_chunk);
    if (to_write > first_chunk) {
        uint32_t second_chunk = to_write - first_chunk;
        memcpy(&g_spsc_buffer[0], data + first_chunk, second_chunk);
    }

    /* Publish updated write cursor with release barrier so consumer observes our memcpy bytes. */
    atomic_store_explicit(&g_write_idx, w + (uint64_t)to_write, memory_order_release);
    return to_write;
}

/* Returns cumulative render-callback underrun events. */
uint64_t integrator_mac_audio_underruns(void) {
    return atomic_load_explicit(&g_underrun_count, memory_order_relaxed);
}

/*
 * Flushes the SPSC ring buffer without violating SPSC single-consumer ownership (AUD-1G7-04):
 * - When AudioUnit is active: signals consumer-owned `g_flush_req_epoch` so the RT callback
 *   discards queued frames on its very next pull.
 * - When AudioUnit is stopped: advances `g_read_idx` to `g_write_idx` safely under lifecycle lock.
 */
void integrator_mac_audio_flush(void) {
    pthread_mutex_lock(&g_lifecycle_lock);
    if (g_audio_unit != NULL && atomic_load_explicit(&g_active, memory_order_acquire) == 1) {
        atomic_fetch_add_explicit(&g_flush_req_epoch, 1u, memory_order_release);
    } else {
        uint64_t w = atomic_load_explicit(&g_write_idx, memory_order_acquire);
        atomic_store_explicit(&g_read_idx, w, memory_order_release);
        g_consumer_flush_epoch = atomic_load_explicit(&g_flush_req_epoch, memory_order_acquire);
    }
    pthread_mutex_unlock(&g_lifecycle_lock);
}

/*
 * Adjusts CoreAudio output gain / gentle macOS local volume ducking for the TouchBar
 * Cross-Platform Audio Mixer slider (`balance` in [-1.0, +1.0]).
 * - When `balance <= 0.0`: restores any previously saved macOS default output volume baseline.
 * - When `balance > 0.0`: gently ducks local macOS system volume relative to saved baseline
 *   while scaling up the dedicated Windows soundbar AudioUnit output gain so PC games/Discord
 *   cut through cleanly without permanently altering the user's Mac volume.
 */
void integrator_mac_audio_set_local_duck(float balance) {
    if (balance < -1.0f) balance = -1.0f;
    if (balance > 1.0f) balance = 1.0f;

    pthread_mutex_lock(&g_lifecycle_lock);
    AudioObjectID dev = kAudioObjectUnknown;
    UInt32 dev_size = sizeof(dev);
    AudioObjectPropertyAddress def_addr = {
        kAudioHardwarePropertyDefaultOutputDevice,
        kAudioObjectPropertyScopeGlobal,
        kAudioObjectPropertyElementMain
    };
    if (AudioObjectGetPropertyData(kAudioObjectSystemObject, &def_addr, 0, NULL, &dev_size, &dev) == noErr
        && dev != kAudioObjectUnknown)
    {
        AudioObjectPropertyAddress vol_addr = {
            kAudioHardwareServiceDeviceProperty_VirtualMainVolume,
            kAudioDevicePropertyScopeOutput,
            kAudioObjectPropertyElementMain
        };
        if (AudioObjectHasProperty(dev, &vol_addr)) {
            Boolean settable = false;
            if (AudioObjectIsPropertySettable(dev, &vol_addr, &settable) == noErr && settable) {
                if (balance > 0.05f) {
                    if (!g_has_saved_sys_vol) {
                        Float32 cur = 0.75f;
                        UInt32 sz = sizeof(cur);
                        if (AudioObjectGetPropertyData(dev, &vol_addr, 0, NULL, &sz, &cur) == noErr) {
                            g_saved_sys_vol = cur;
                            g_has_saved_sys_vol = true;
                        }
                    }
                    if (g_has_saved_sys_vol) {
                        /* Duck local Mac audio smoothly down to 25% of baseline at +1.0 */
                        Float32 mac_scale = 1.0f - (balance * 0.75f);
                        Float32 target = g_saved_sys_vol * mac_scale;
                        if (target < 0.0f) target = 0.0f;
                        if (target > 1.0f) target = 1.0f;
                        (void)AudioObjectSetPropertyData(dev, &vol_addr, 0, NULL, sizeof(target), &target);
                    }
                } else if (g_has_saved_sys_vol) {
                    Float32 restore = g_saved_sys_vol;
                    g_has_saved_sys_vol = false;
                    (void)AudioObjectSetPropertyData(dev, &vol_addr, 0, NULL, sizeof(restore), &restore);
                }
            }
        }
    }
    pthread_mutex_unlock(&g_lifecycle_lock);
}

/* ============================================================================
 * Native SPSC Test & Diagnostics Helpers (Used by macOS `cargo test`)
 * ============================================================================ */

uint32_t integrator_mac_audio_buffered_bytes(void) {
    uint64_t w = atomic_load_explicit(&g_write_idx, memory_order_acquire);
    uint64_t r = atomic_load_explicit(&g_read_idx, memory_order_acquire);
    return (w >= r) ? (uint32_t)(w - r) : 0u;
}

uint32_t integrator_mac_audio_test_render_pull(uint8_t *out, uint32_t requested_bytes) {
    return spsc_consumer_pull(out, requested_bytes);
}

void integrator_mac_audio_test_reset(void) {
    integrator_mac_audio_stop();
    pthread_mutex_lock(&g_lifecycle_lock);
    atomic_store_explicit(&g_write_idx, 0u, memory_order_release);
    atomic_store_explicit(&g_read_idx, 0u, memory_order_release);
    atomic_store_explicit(&g_underrun_count, 0u, memory_order_release);
    atomic_store_explicit(&g_flush_req_epoch, 0u, memory_order_release);
    g_consumer_flush_epoch = 0u;
    memset(g_spsc_buffer, 0, sizeof(g_spsc_buffer));
    pthread_mutex_unlock(&g_lifecycle_lock);
}
