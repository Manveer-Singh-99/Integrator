/*
 * ============================================================================
 * Integrator Dynamic Audio Routing: Windows 11 WASAPI Loopback Capture Engine
 * ============================================================================
 *
 * MODULE PURPOSE & SCOPE:
 *   Owns the native Windows 11 system render audio capture pipeline using the
 *   Windows Audio Session API (WASAPI) in shared event-driven loopback mode
 *   (`AUDCLNT_SHAREMODE_SHARED | AUDCLNT_STREAMFLAGS_LOOPBACK |
 *   AUDCLNT_STREAMFLAGS_EVENTCALLBACK`). This module captures mixed system
 *   audio output from the active default console render endpoint (`eRender`,
 *   `eConsole`), converts arbitrary device mix formats (1..16 channels,
 *   8 kHz..384 kHz sample rates, 16/24/32-bit signed PCM or 32-bit IEEE
 *   floating-point) into canonical 48 kHz, 16-bit signed little-endian
 *   interleaved stereo PCM frames of exactly 5 ms duration (240 stereo sample
 *   frames = 960 bytes), and delivers them to the Rust audio routing layer.
 *
 *   Core abstractions and state lifecycle owned by this file:
 *   - Exception-safe RAII guards for COM MTA initialization
 *     (`ComApartmentGuard`), System32-pinned dynamic library loading
 *     (`SystemModuleGuard`), Multimedia Class Scheduler Service `"Pro Audio"`
 *     thread prioritization (`MmcssTaskGuard`), and 1 ms Windows kernel timer
 *     resolution (`TimerResolutionGuard`).
 *   - Pure DSP conditioning pipeline: peak-normalized ITU/SMPTE multi-channel
 *     surround-to-stereo downmixer (`DownmixWeights`), 2-pole Butterworth
 *     anti-aliasing biquad low-pass filter (`StereoBiquadLpf`, fc = 20 kHz),
 *     C1-continuous hyperbolic-tangent soft-knee limiter (`soft_limit`), and
 *     cross-packet fractional-phase linear interpolation resampler
 *     (`StatefulStereoResampler`).
 *   - Asynchronous endpoint change observer (`DefaultDeviceNotifier`
 *     implementing `IMMNotificationClient`) with `DuplicateHandle`-isolated
 *     kernel event lifetime so late `MMDevApi` RPC thread-pool callbacks can
 *     never signal a closed or recycled Win32 `HANDLE`.
 *   - Generation-fenced session state machine (`CaptureSessionContext` &
 *     `WasapiCaptureState`: `Initializing` -> `Capturing` <-> `Reconnecting`
 *     -> `Stopped`) with `GetDevicePeriod`-calibrated synthetic silence
 *     holdoff and exponential-backoff hot-swap recovery.
 *
 * ARCHITECTURAL LINKAGES & DEPENDENCIES:
 *   - Upstream Callers:
 *     * `app/src/audio/mod.rs`: Invokes the exported `extern "C"` lifecycle
 *       and telemetry functions (`integrator_win_audio_capture_start`,
 *       `integrator_win_audio_capture_stop`,
 *       `integrator_win_audio_capture_stop_if_gen`,
 *       `integrator_win_audio_capture_is_active`,
 *       `integrator_win_audio_capture_frames_read`,
 *       `integrator_win_audio_capture_silent_frames`,
 *       `integrator_win_audio_capture_discontinuities`) and Windows native
 *       DSP verification test hooks (`integrator_win_audio_test_*`).
 *   - Downstream Callees:
 *     * Windows 11 MMDevice & WASAPI COM APIs (`mmdeviceapi.h`,
 *       `audioclient.h`, `audiopolicy.h`, `ksmedia.h`):
 *       `IMMDeviceEnumerator`, `IMMNotificationClient`, `IMMDevice`,
 *       `IAudioClient`, `IAudioCaptureClient`.
 *     * Windows Kernel & Multimedia Schedulers (`windows.h`, `avrt.dll`,
 *       `winmm.dll`): `CreateEventW`, `DuplicateHandle`,
 *       `WaitForMultipleObjects`, `QueryPerformanceCounter`,
 *       `AvSetMmThreadCharacteristicsW`, `timeBeginPeriod`.
 *     * Rust FFI Callbacks (`app/src/audio/mod.rs`):
 *       `integrator_on_win_audio_captured(data, len, is_silent)` for each
 *       canonical 960-byte frame, and
 *       `integrator_on_win_audio_capture_ended(capture_gen, reason_code)`
 *       when an active session terminates unexpectedly after startup.
 *   - Cross-Platform / Cross-Device Flow:
 *     * Audio captured on Windows 11 by this module is handed via
 *       `integrator_on_win_audio_captured` to `app/src/audio/mod.rs`, which
 *       frames, sequences, encrypts, and transmits the 5 ms canonical PCM
 *       packets over the Mac <-> Windows 11 low-latency transport to the
 *       macOS peer, where `app/src/mac_audio.m` renders them through the
 *       CoreAudio VoiceProcessing / HAL output unit with adaptive jitter
 *       buffering.
 *
 * THREADING & CONCURRENCY MODEL:
 *   - Lifecycle Mutex (`g_lifecycle_mtx`): Serializes all FFI entry points
 *     (`start`, `stop`, `stop_if_gen`, `is_active`). Held across worker thread
 *     termination (`WaitForSingleObject` join in `stop_current_session_locked`)
 *     so two capture worker threads can never overlap in time.
 *   - Capture Worker Thread (`win_audio_capture_thread_proc`): A dedicated
 *     Win32 thread running in a `COINIT_MULTITHREADED` (MTA) COM apartment
 *     elevated to MMCSS `"Pro Audio"` priority. All WASAPI stream interfaces
 *     (`pDevice`, `pAudioClient`, `pCaptureClient`, `pMixFormat`) and DSP
 *     buffers (`stereoScratch`, `accumulator`, `resampler`) are accessed
 *     exclusively on this worker thread.
 *   - MMDevApi RPC Callback Threads: Windows invokes
 *     `DefaultDeviceNotifier::OnDefaultDeviceChanged` on internal OS RPC
 *     threads. Synchronization with the capture worker thread uses only an
 *     atomic release/acq_rel boolean (`m_deviceChanged`) and an independently
 *     duplicated Win32 event handle (`m_ownedEvent`).
 *   - Lock-Free Telemetry Atomics (`g_total_frames_read`,
 *     `g_total_silent_frames`, `g_total_discontinuities`): Updated with
 *     `std::memory_order_relaxed` on the worker thread and read lock-free by
 *     Rust health/watchdog polling.
 *
 * SECURITY & SAFETY INVARIANTS:
 *   - FFI & Memory Safety Boundary: Never exposes internal C++ heap pointers
 *     across FFI after return; `integrator_on_win_audio_captured` receives a
 *     read-only pointer to a contiguous 960-byte buffer valid for the
 *     synchronous duration of the callback, and is never invoked once
 *     `stop_requested` is set.
 *   - DLL Hijacking Prevention: `avrt.dll` and `winmm.dll` are loaded strictly
 *     with `LOAD_LIBRARY_SEARCH_SYSTEM32` (`0x00000800`).
 *   - Format & Arithmetic Bounds Checking: `validate_mix_format` rejects sample
 *     rates outside `[8000, 384000]` Hz, channel counts outside `[1, 16]`,
 *     bit depths other than `16/24/32`-bit, `nBlockAlign` smaller than the
 *     per-frame byte width, and non-PCM/non-IEEE-float encodings. Packet frame
 *     counts are bounded by `MAX_PACKET_FRAMES` (`384000` frames) with
 *     explicit `size_t` overflow guards before buffer indexing or allocation.
 *   - Deterministic COM & Handle Cleanup: Every `IUnknown` pointer,
 *     `CoTaskMemAlloc`-allocated `WAVEFORMATEX`, and Win32 `HANDLE` is
 *     released on state transitions, thread exit, and `~CaptureSessionContext`.
 * ============================================================================
 */

#ifdef _WIN32

#include <windows.h>
#include <initguid.h>
#include <mmdeviceapi.h>
#include <audioclient.h>
#include <audiopolicy.h>
#include <ksmedia.h>
#include <stdint.h>
#include <string.h>
#include <atomic>
#include <vector>
#include <algorithm>
#include <cmath>
#include <memory>
#include <mutex>
#include <new>
#include <limits>

// Standard Windows channel mask bit flags (defined defensively in case sdk headers omit them).
#ifndef SPEAKER_FRONT_LEFT
#define SPEAKER_FRONT_LEFT             0x1
#define SPEAKER_FRONT_RIGHT            0x2
#define SPEAKER_FRONT_CENTER           0x4
#define SPEAKER_LOW_FREQUENCY          0x8
#define SPEAKER_BACK_LEFT              0x10
#define SPEAKER_BACK_RIGHT             0x20
#define SPEAKER_FRONT_LEFT_OF_CENTER   0x40
#define SPEAKER_FRONT_RIGHT_OF_CENTER  0x80
#define SPEAKER_BACK_CENTER            0x100
#define SPEAKER_SIDE_LEFT              0x200
#define SPEAKER_SIDE_RIGHT             0x400
#endif

// Wildcard speaker mask bit indicating all speaker positions in WAVEFORMATEXTENSIBLE.
#ifndef SPEAKER_ALL
#define SPEAKER_ALL                    0x80000000
#endif

// Win32 loader flag restricting DLL resolution exclusively to `%windir%\System32`
// to prevent search-order DLL preloading / hijacking attacks.
#ifndef LOAD_LIBRARY_SEARCH_SYSTEM32
#define LOAD_LIBRARY_SEARCH_SYSTEM32   0x00000800
#endif

// ============================================================================
// Canonical Audio Framing & Protocol Constants
// ============================================================================

/// Canonical output sample rate expected by the Rust audio transport and macOS receiver (Hz).
static const uint32_t CANONICAL_SAMPLE_RATE = 48000;

/// Canonical output channel count (2 = interleaved Left, Right stereo).
static const uint32_t CANONICAL_CHANNELS = 2;

/// Number of stereo sample frames per canonical 5 ms packet at 48 kHz (48000 Hz * 0.005 s = 240 frames).
static const uint32_t CANONICAL_FRAME_SAMPLES_PER_CH = 240;

/// Exact byte length of one canonical 5 ms stereo 16-bit PCM packet (240 frames * 2 channels * 2 bytes = 960 bytes).
static const uint32_t CANONICAL_FRAME_BYTES =
    CANONICAL_FRAME_SAMPLES_PER_CH * CANONICAL_CHANNELS * static_cast<uint32_t>(sizeof(int16_t));

/// Maximum consecutive WASAPI endpoint reconnection attempts before declaring fatal capture loss.
static const uint32_t MAX_RECONNECT_ATTEMPTS = 10;

/// Maximum synthetic 5 ms silence frames emitted in a single scheduler wake tick (8 frames = 40 ms cap)
/// to avoid flooding the outbound UDP/TCP queue after an OS scheduler stall.
static const uint32_t MAX_SILENCE_FRAMES_PER_TICK = 8;

/// Minimum accepted WASAPI device mix sample rate in Hz (8 kHz narrowband floor).
static const uint32_t MIN_VALID_SAMPLE_RATE = 8000;

/// Maximum accepted WASAPI device mix sample rate in Hz (384 kHz studio ceiling).
static const uint32_t MAX_VALID_SAMPLE_RATE = 384000;

/// Maximum accepted frames per single WASAPI `GetBuffer` packet (1 full second at 384 kHz = 384,000 frames;
/// 20x the 50 ms shared ring buffer). Bounds memory allocation and prevents integer overflow in byte offset math.
static const uint32_t MAX_PACKET_FRAMES = MAX_VALID_SAMPLE_RATE;

/// Minimum silence-entry holdoff in microseconds (25,000 us = 25 ms).
/// Must exceed 2x the standard 10 ms Windows 11 WASAPI shared-mode engine period so normal inter-packet
/// idle intervals never trigger spurious synthetic silence injection (`NEW-1G8-01`).
static const double MIN_SILENCE_HOLDOFF_US = 25000.0;

// ============================================================================
// Rust FFI Callback Declarations & Dynamic Win32 Function Pointers
// ============================================================================

/// Synchronous C FFI callback into `app/src/audio/mod.rs` delivering one canonical 960-byte PCM frame.
/// - `data`: Pointer to `len` bytes of 48 kHz 16-bit signed little-endian interleaved stereo PCM.
/// - `len`: Byte length of the frame (always `CANONICAL_FRAME_BYTES = 960`).
/// - `is_silent`: Non-zero (`1`) if every 16-bit sample in the frame is zero, else `0`.
extern "C" void integrator_on_win_audio_captured(const uint8_t* data, uint32_t len, int is_silent);

/// Asynchronous lifecycle notification callback into `app/src/audio/mod.rs` invoked when a capture
/// worker thread exits unexpectedly after initial startup succeeded.
/// - `capture_gen`: Monotonic routing generation ID passed to `integrator_win_audio_capture_start`.
/// - `reason_code`: Non-zero failure classification (`1` = init failure, `2` = reconnect retries exhausted, `3` = exception).
extern "C" void integrator_on_win_audio_capture_ended(uint64_t capture_gen, int reason_code);

/// Function pointer types for dynamic System32-pinned loading of `Avrt.dll` (MMCSS) and `Winmm.dll` (multimedia timer).
typedef HANDLE (WINAPI *pfnAvSetMmThreadCharacteristicsW)(LPCWSTR, LPDWORD);
typedef BOOL (WINAPI *pfnAvRevertMmThreadCharacteristics)(HANDLE);
typedef UINT (WINAPI *pfnTimeBeginPeriod)(UINT);
typedef UINT (WINAPI *pfnTimeEndPeriod)(UINT);

// ============================================================================
// Global Lock-Free Telemetry Counters
// ============================================================================

/// Cumulative count of native WASAPI sample frames read via `IAudioCaptureClient::GetBuffer` across all sessions.
static std::atomic<uint64_t> g_total_frames_read{0};

/// Cumulative count of canonical 48 kHz stereo sample frames emitted as silence (both WASAPI silent buffers and synthetic silence).
static std::atomic<uint64_t> g_total_silent_frames{0};

/// Cumulative count of `AUDCLNT_BUFFERFLAGS_DATA_DISCONTINUITY` flags reported by the Windows audio engine.
static std::atomic<uint64_t> g_total_discontinuities{0};

// ============================================================================
// Exception-Safe RAII Resource Guards (`NEW-1G8-04`)
// ============================================================================

/**
 * @brief Scoped RAII guard for thread-level COM apartment initialization (`CoInitializeEx` / `CoUninitialize`).
 *
 * Ensures every successful `CoInitializeEx` call (`S_OK` or `S_FALSE`) is paired with an exact
 * `CoUninitialize` call when the worker thread exits, even if an unhandled C++ exception unwinds the stack.
 */
struct ComApartmentGuard {
    /// True if `CoInitializeEx` returned `S_OK` or `S_FALSE` and therefore requires `CoUninitialize()`.
    bool initialized = false;

    /**
     * @brief Enters the specified COM apartment concurrency model on the calling thread.
     * @param coInit COM initialization flags (e.g., `COINIT_MULTITHREADED` for real-time audio worker threads).
     */
    explicit ComApartmentGuard(DWORD coInit) {
        HRESULT hr = CoInitializeEx(NULL, coInit);
        // Both S_OK and S_FALSE satisfy SUCCEEDED(hr) and require a balancing CoUninitialize() call per MSDN.
        initialized = SUCCEEDED(hr);
    }

    /// Balances COM apartment initialization on scope exit.
    ~ComApartmentGuard() {
        if (initialized) {
            CoUninitialize();
        }
    }

    ComApartmentGuard(const ComApartmentGuard&) = delete;
    ComApartmentGuard& operator=(const ComApartmentGuard&) = delete;
};

/**
 * @brief Scoped RAII guard for dynamically loading a Windows system DLL strictly from `%windir%\System32`.
 *
 * Uses `LOAD_LIBRARY_SEARCH_SYSTEM32` so an attacker-controlled DLL in the working directory or PATH
 * can never be loaded into the process. Automatically calls `FreeLibrary` on scope exit.
 */
struct SystemModuleGuard {
    /// Win32 module handle returned by `LoadLibraryExW`, or `NULL` if unavailable.
    HMODULE handle = NULL;

    /**
     * @brief Loads `dllName` strictly from the System32 directory.
     * @param dllName Null-terminated wide string naming the system DLL (e.g., `L"avrt.dll"`).
     */
    explicit SystemModuleGuard(LPCWSTR dllName) {
        handle = LoadLibraryExW(dllName, NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    }

    /// Releases the loaded module reference if valid.
    ~SystemModuleGuard() {
        if (handle) {
            FreeLibrary(handle);
        }
    }

    SystemModuleGuard(const SystemModuleGuard&) = delete;
    SystemModuleGuard& operator=(const SystemModuleGuard&) = delete;
};

/**
 * @brief Scoped RAII guard elevating the current thread to a Windows Multimedia Class Scheduler Service (MMCSS) profile.
 *
 * Registers the capture worker thread under `"Pro Audio"` priority via `AvSetMmThreadCharacteristicsW`
 * so the Windows kernel schedules audio packet draining ahead of normal user-mode threads, preventing
 * glitching under heavy CPU load. Reverts thread characteristics on scope exit.
 */
struct MmcssTaskGuard {
    /// Opaque MMCSS task handle returned by `AvSetMmThreadCharacteristicsW`, or `NULL` if registration failed.
    HANDLE task = NULL;
    /// Resolved pointer to `AvRevertMmThreadCharacteristics` inside `avrt.dll`.
    pfnAvRevertMmThreadCharacteristics revertFn = NULL;

    /**
     * @brief Associates the calling thread with the named MMCSS task profile.
     * @param hAvrt Loaded module handle for `avrt.dll`.
     * @param taskName Wide string naming the Windows MMCSS profile (e.g., `L"Pro Audio"`).
     */
    MmcssTaskGuard(HMODULE hAvrt, LPCWSTR taskName) {
        if (!hAvrt) return;
        auto setFn = reinterpret_cast<pfnAvSetMmThreadCharacteristicsW>(
            GetProcAddress(hAvrt, "AvSetMmThreadCharacteristicsW"));
        revertFn = reinterpret_cast<pfnAvRevertMmThreadCharacteristics>(
            GetProcAddress(hAvrt, "AvRevertMmThreadCharacteristics"));
        if (setFn) {
            DWORD idx = 0;
            task = setFn(taskName, &idx);
        }
    }

    /// Reverts MMCSS priority boost before `avrt.dll` is unloaded.
    ~MmcssTaskGuard() {
        if (task && revertFn) {
            revertFn(task);
        }
    }

    MmcssTaskGuard(const MmcssTaskGuard&) = delete;
    MmcssTaskGuard& operator=(const MmcssTaskGuard&) = delete;
};

/**
 * @brief Scoped RAII guard requesting high-resolution Windows kernel timer ticks (`timeBeginPeriod` / `timeEndPeriod`).
 *
 * Windows default timer resolution is 15.625 ms (64 Hz), which is too coarse for 5 ms (`WaitForMultipleObjects(..., 5)`)
 * synthetic silence pacing. Requesting a 1 ms period ensures sub-millisecond wakeup accuracy and pairs
 * `timeBeginPeriod(1)` with `timeEndPeriod(1)` on thread exit as required by Windows 10/11 power management.
 */
struct TimerResolutionGuard {
    /// Requested timer resolution period in milliseconds (typically `1` ms).
    UINT periodMs = 0;
    /// Resolved pointer to `timeEndPeriod` inside `winmm.dll`.
    pfnTimeEndPeriod endFn = NULL;
    /// True if `timeBeginPeriod(periodMs)` succeeded (`TIMERR_NOERROR == 0`).
    bool active = false;

    /**
     * @brief Requests a system timer resolution of `ms` milliseconds.
     * @param hWinmm Loaded module handle for `winmm.dll`.
     * @param ms Desired timer period in milliseconds (`1` ms for real-time audio pacing).
     */
    TimerResolutionGuard(HMODULE hWinmm, UINT ms) : periodMs(ms) {
        if (!hWinmm) return;
        auto beginFn = reinterpret_cast<pfnTimeBeginPeriod>(GetProcAddress(hWinmm, "timeBeginPeriod"));
        endFn = reinterpret_cast<pfnTimeEndPeriod>(GetProcAddress(hWinmm, "timeEndPeriod"));
        if (beginFn && endFn && beginFn(ms) == 0) {
            active = true;
        }
    }

    /// Restores the previous system timer resolution period if `timeBeginPeriod` succeeded.
    ~TimerResolutionGuard() {
        if (active && endFn) {
            endFn(periodMs);
        }
    }

    TimerResolutionGuard(const TimerResolutionGuard&) = delete;
    TimerResolutionGuard& operator=(const TimerResolutionGuard&) = delete;
};

// ============================================================================
// Pure DSP Helpers (Format Validation, Channel Downmix, Soft Limiter, Resampler)
// ============================================================================

/**
 * @brief Validates a WASAPI device mix format descriptor (`WAVEFORMATEX` / `WAVEFORMATEXTENSIBLE`).
 *
 * Algorithm & Preconditions:
 *   1. Verifies `pwfx` is non-null, `nSamplesPerSec` is within `[8000, 384000]` Hz,
 *      `nChannels` is within `[1, 16]`, and `wBitsPerSample` is one of `{16, 24, 32}` bits.
 *   2. Verifies `nBlockAlign >= nChannels * (wBitsPerSample / 8)` so per-channel byte reads
 *      within a frame can never read past the stride of a frame (`NEW-1G8-08`).
 *   3. Checks the format tag:
 *      - `WAVE_FORMAT_IEEE_FLOAT`: Requires `wBitsPerSample == 32`.
 *      - `WAVE_FORMAT_PCM`: Accepts 16, 24, or 32-bit integer PCM.
 *      - `WAVE_FORMAT_EXTENSIBLE`: Requires `cbSize >= 22` (the 22-byte extension payload of
 *        `WAVEFORMATEXTENSIBLE`), validates `wValidBitsPerSample <= wBitsPerSample`, and accepts
 *        only `KSDATAFORMAT_SUBTYPE_IEEE_FLOAT` (32-bit) or `KSDATAFORMAT_SUBTYPE_PCM`.
 *
 * @param pwfx Pointer to the `WAVEFORMATEX` structure returned by `IAudioClient::GetMixFormat`.
 * @param outIsFloat Output boolean set to `true` for 32-bit IEEE float samples, `false` for integer PCM.
 * @return `true` if the format is safe and supported by the DSP pipeline; `false` otherwise.
 */
static bool validate_mix_format(const WAVEFORMATEX* pwfx, bool& outIsFloat) {
    outIsFloat = false;
    if (!pwfx) return false;
    if (pwfx->nSamplesPerSec < MIN_VALID_SAMPLE_RATE ||
        pwfx->nSamplesPerSec > MAX_VALID_SAMPLE_RATE) {
        return false;
    }
    if (pwfx->nChannels == 0 || pwfx->nChannels > 16) {
        return false;
    }
    if (pwfx->wBitsPerSample != 16 && pwfx->wBitsPerSample != 24 && pwfx->wBitsPerSample != 32) {
        return false;
    }
    size_t minBlockAlign = static_cast<size_t>(pwfx->nChannels) * static_cast<size_t>(pwfx->wBitsPerSample / 8);
    if (pwfx->nBlockAlign < minBlockAlign) {
        return false;
    }

    if (pwfx->wFormatTag == WAVE_FORMAT_IEEE_FLOAT) {
        if (pwfx->wBitsPerSample != 32) return false;
        outIsFloat = true;
        return true;
    }
    if (pwfx->wFormatTag == WAVE_FORMAT_PCM) {
        outIsFloat = false;
        return true;
    }
    // WAVEFORMATEXTENSIBLE adds 22 bytes beyond sizeof(WAVEFORMATEX) (2-byte Samples union + 4-byte dwChannelMask + 16-byte SubFormat GUID).
    if (pwfx->wFormatTag == WAVE_FORMAT_EXTENSIBLE && pwfx->cbSize >= 22) {
        const WAVEFORMATEXTENSIBLE* pExt = reinterpret_cast<const WAVEFORMATEXTENSIBLE*>(pwfx);
        // Reject corrupted extensible headers where valid bits exceed container bit width.
        if (pExt->Samples.wValidBitsPerSample > pwfx->wBitsPerSample) {
            return false;
        }
        if (IsEqualGUID(pExt->SubFormat, KSDATAFORMAT_SUBTYPE_IEEE_FLOAT)) {
            if (pwfx->wBitsPerSample != 32) return false;
            outIsFloat = true;
            return true;
        }
        if (IsEqualGUID(pExt->SubFormat, KSDATAFORMAT_SUBTYPE_PCM)) {
            outIsFloat = false;
            return true;
        }
    }
    return false;
}

/**
 * @brief Computes the minimum silence-entry holdoff threshold in microseconds (`NEW-1G8-01`).
 *
 * Why this formula is used instead of a fixed 5 ms timeout:
 *   Windows 11 shared-mode WASAPI delivers audio packets at the audio engine's device period
 *   (typically 10 ms = 10,000 us, or up to 20 ms on some USB/Bluetooth drivers). Because our wait loop
 *   wakes every 5 ms, a fixed 5 ms silence threshold would falsely trigger between every pair of normal
 *   10 ms packets, injecting bogus 5 ms zero frames in the middle of active audio playback and inflating
 *   the output stream rate to 150%. Enforcing `max(2 * default_period_us, 25000.0 us)` guarantees at
 *   least two full device periods (and never less than 25 ms) elapse with zero packets before synthetic
 *   silence heartbeat frames begin.
 *
 * @param default_period_us Device default engine period in microseconds (from `IAudioClient::GetDevicePeriod`).
 * @return Required holdoff duration in microseconds (`>= 25000.0` us).
 */
static inline double compute_silence_holdoff_us(double default_period_us) {
    double doubled = (default_period_us > 0.0) ? (default_period_us * 2.0) : MIN_SILENCE_HOLDOFF_US;
    return (std::max)(doubled, MIN_SILENCE_HOLDOFF_US);
}

/**
 * @brief Determines whether the capture loop should emit synthetic silence frames on an empty packet poll.
 *
 * @param elapsed_since_last_packet_us Elapsed wall-clock time in microseconds since the last non-empty WASAPI packet.
 * @param default_period_us Device default engine period in microseconds.
 * @param already_in_silence `true` if the session has already crossed the holdoff threshold and entered synthetic silence mode.
 * @return `true` if synthetic silence frames should be emitted on this tick; `false` if still within normal inter-packet holdoff.
 */
static inline bool should_emit_synthetic_silence(
    double elapsed_since_last_packet_us,
    double default_period_us,
    bool already_in_silence
) {
    if (already_in_silence) {
        return true;
    }
    return elapsed_since_last_packet_us >= compute_silence_holdoff_us(default_period_us);
}

/**
 * @brief Precomputed per-channel stereo downmix matrix and peak-safe global attenuation factor.
 *
 * Maps up to 16 input channels into Left (`weightL`) and Right (`weightR`) stereo bus gains,
 * followed by a uniform scalar `attenuation` ensuring that simultaneous full-scale (`1.0`) input
 * across all active channels never exceeds `1.0` prior to the soft limiter (`AUD-1G7-06`, `AUD-1G7-14`).
 */
struct DownmixWeights {
    /// Active input channel count clamped to `[0, 16]`.
    int numChannels = 0;
    /// Per-channel linear gain contribution to the Left stereo output channel (dimensionless ratio in `[0.0, 1.0]`).
    float weightL[16] = {0.0f};
    /// Per-channel linear gain contribution to the Right stereo output channel (dimensionless ratio in `[0.0, 1.0]`).
    float weightR[16] = {0.0f};
    /// Global peak-normalization scalar (`1.0 / max(sum(|weightL|), sum(|weightR|))`, in `(0.0, 1.0]`).
    float attenuation = 1.0f;
};

/**
 * @brief Resolves per-channel stereo downmix weights and exact peak-safe normalization from a `WAVEFORMATEX`.
 *
 * Algorithm:
 *   1. Extracts `dwChannelMask` from `WAVEFORMATEXTENSIBLE` if present; otherwise synthesizes standard
 *      ITU-R BS.775 / Windows speaker masks for 1..8+ channels.
 *   2. Assigns standard pan weights in ascending Windows `SPEAKER_*` bit order:
 *      - Front Left / Front Right: `1.0` to L / R respectively.
 *      - Front Center / Front Left-of-Center / Front Right-of-Center: `-3 dB` equal-power (`1/sqrt(2) ≈ 0.70710678f`).
 *      - LFE (`SPEAKER_LOW_FREQUENCY`): `0.0` (excluded from stereo full-range mix to prevent low-frequency mud/clipping).
 *      - Side Left / Side Right: `0.70710678f` to L / R.
 *      - Back Left / Back Right: `0.5f` (-6 dB) when side channels exist (7.1 layout), else `0.70710678f` (5.1/quad layout).
 *      - Back Center: `0.5f` to both L and R.
 *   3. Computes `maxSum = max(sum_i |weightL[i]|, sum_i |weightR[i]|)` and sets `attenuation = 1.0f / maxSum`
 *      whenever `maxSum > 1.0f`, guaranteeing worst-case correlated full-scale surround peaks never exceed unity (`1.0`).
 *
 * @param pwfx Pointer to validated `WAVEFORMATEX` / `WAVEFORMATEXTENSIBLE`.
 * @return Populated `DownmixWeights` table.
 */
static DownmixWeights compute_downmix_weights(const WAVEFORMATEX* pwfx) {
    DownmixWeights dw;
    if (!pwfx || pwfx->nChannels == 0) {
        return dw;
    }

    int ch = static_cast<int>(pwfx->nChannels);
    if (ch > 16) ch = 16;
    dw.numChannels = ch;

    DWORD mask = 0;
    if (pwfx->wFormatTag == WAVE_FORMAT_EXTENSIBLE && pwfx->cbSize >= 22) {
        const WAVEFORMATEXTENSIBLE* pExt = reinterpret_cast<const WAVEFORMATEXTENSIBLE*>(pwfx);
        mask = pExt->dwChannelMask;
    }

    // Fall back to canonical Windows speaker layouts if the driver provides an empty or wildcard mask.
    if (mask == 0 || mask == SPEAKER_ALL) {
        switch (ch) {
            case 1: mask = SPEAKER_FRONT_CENTER; break;
            case 2: mask = SPEAKER_FRONT_LEFT | SPEAKER_FRONT_RIGHT; break;
            case 3: mask = SPEAKER_FRONT_LEFT | SPEAKER_FRONT_RIGHT | SPEAKER_FRONT_CENTER; break;
            case 4: mask = SPEAKER_FRONT_LEFT | SPEAKER_FRONT_RIGHT | SPEAKER_BACK_LEFT | SPEAKER_BACK_RIGHT; break;
            case 5: mask = SPEAKER_FRONT_LEFT | SPEAKER_FRONT_RIGHT | SPEAKER_FRONT_CENTER |
                           SPEAKER_BACK_LEFT | SPEAKER_BACK_RIGHT; break;
            case 6: mask = SPEAKER_FRONT_LEFT | SPEAKER_FRONT_RIGHT | SPEAKER_FRONT_CENTER |
                           SPEAKER_LOW_FREQUENCY | SPEAKER_BACK_LEFT | SPEAKER_BACK_RIGHT; break;
            case 7: mask = SPEAKER_FRONT_LEFT | SPEAKER_FRONT_RIGHT | SPEAKER_FRONT_CENTER |
                           SPEAKER_BACK_LEFT | SPEAKER_BACK_RIGHT | SPEAKER_SIDE_LEFT | SPEAKER_SIDE_RIGHT; break;
            default:
                mask = SPEAKER_FRONT_LEFT | SPEAKER_FRONT_RIGHT | SPEAKER_FRONT_CENTER |
                       SPEAKER_LOW_FREQUENCY | SPEAKER_BACK_LEFT | SPEAKER_BACK_RIGHT |
                       SPEAKER_SIDE_LEFT | SPEAKER_SIDE_RIGHT;
                break;
        }
    }

    // Equal-power -3.01 dB pan coefficient: 1 / sqrt(2).
    const float INV_SQRT2 = 0.70710678f;
    bool hasSide = (mask & (SPEAKER_SIDE_LEFT | SPEAKER_SIDE_RIGHT)) != 0;

    // Mono input maps directly to both stereo channels at unity gain.
    if (ch == 1) {
        dw.weightL[0] = 1.0f;
        dw.weightR[0] = 1.0f;
        dw.attenuation = 1.0f;
        return dw;
    }

    // Windows interleaves multi-channel audio strictly in ascending order of SPEAKER_* bit positions.
    const DWORD speakerBits[] = {
        SPEAKER_FRONT_LEFT,
        SPEAKER_FRONT_RIGHT,
        SPEAKER_FRONT_CENTER,
        SPEAKER_LOW_FREQUENCY,
        SPEAKER_BACK_LEFT,
        SPEAKER_BACK_RIGHT,
        SPEAKER_FRONT_LEFT_OF_CENTER,
        SPEAKER_FRONT_RIGHT_OF_CENTER,
        SPEAKER_BACK_CENTER,
        SPEAKER_SIDE_LEFT,
        SPEAKER_SIDE_RIGHT
    };

    int chIdx = 0;
    bool anyMapped = false;
    for (DWORD bit : speakerBits) {
        if ((mask & bit) && chIdx < ch) {
            if (bit == SPEAKER_FRONT_LEFT) {
                dw.weightL[chIdx] = 1.0f;
                anyMapped = true;
            } else if (bit == SPEAKER_FRONT_RIGHT) {
                dw.weightR[chIdx] = 1.0f;
                anyMapped = true;
            } else if (bit == SPEAKER_FRONT_CENTER) {
                dw.weightL[chIdx] = INV_SQRT2;
                dw.weightR[chIdx] = INV_SQRT2;
                anyMapped = true;
            } else if (bit == SPEAKER_LOW_FREQUENCY) {
                dw.weightL[chIdx] = 0.0f;
                dw.weightR[chIdx] = 0.0f;
            } else if (bit == SPEAKER_BACK_LEFT) {
                dw.weightL[chIdx] = hasSide ? 0.5f : INV_SQRT2;
                anyMapped = true;
            } else if (bit == SPEAKER_BACK_RIGHT) {
                dw.weightR[chIdx] = hasSide ? 0.5f : INV_SQRT2;
                anyMapped = true;
            } else if (bit == SPEAKER_FRONT_LEFT_OF_CENTER) {
                dw.weightL[chIdx] = INV_SQRT2;
                anyMapped = true;
            } else if (bit == SPEAKER_FRONT_RIGHT_OF_CENTER) {
                dw.weightR[chIdx] = INV_SQRT2;
                anyMapped = true;
            } else if (bit == SPEAKER_BACK_CENTER) {
                dw.weightL[chIdx] = 0.5f;
                dw.weightR[chIdx] = 0.5f;
                anyMapped = true;
            } else if (bit == SPEAKER_SIDE_LEFT) {
                dw.weightL[chIdx] = INV_SQRT2;
                anyMapped = true;
            } else if (bit == SPEAKER_SIDE_RIGHT) {
                dw.weightR[chIdx] = INV_SQRT2;
                anyMapped = true;
            }
            chIdx++;
        }
    }

    // Fallback for non-standard vendor bitmasks (e.g. bits above SPEAKER_SIDE_RIGHT): map Ch0 -> L, Ch1 -> R.
    if (!anyMapped) {
        dw.weightL[0] = 1.0f;
        if (ch >= 2) {
            dw.weightR[1] = 1.0f;
        } else {
            dw.weightR[0] = 1.0f;
        }
    }

    float sumL = 0.0f;
    float sumR = 0.0f;
    for (int i = 0; i < ch; ++i) {
        sumL += std::abs(dw.weightL[i]);
        sumR += std::abs(dw.weightR[i]);
    }
    float maxSum = (std::max)(sumL, sumR);
    dw.attenuation = (maxSum > 1.0f) ? (1.0f / maxSum) : 1.0f;
    return dw;
}

/**
 * @brief C1-continuous, strictly monotonic soft-knee limiter mapping `(-inf, +inf)` into `[-1.0, +1.0]` (`AUD-1G7-06`).
 *
 * Transfer function:
 *   - Linear unity pass-through for `|x| <= 0.8f`.
 *   - Smooth `tanh` compression above the `0.8f` knee: `sign(x) * (0.8f + 0.2f * tanh((|x| - 0.8f) / 0.2f))`.
 *   - At `|x| = 0.8f`, both value (`0.8f`) and first derivative (`d/dx = 1.0f`) match continuously,
 *     preventing harmonic distortion clicks while asymptotically bounding hot WASAPI float peaks to `<= 1.0f`.
 *
 * @param x Input sample amplitude (normalized float, nominally `[-1.0, 1.0]`).
 * @return Soft-limited sample in `[-1.0, 1.0]` (or `0.0f` if `x` is NaN or +/-Inf).
 */
static inline float soft_limit(float x) {
    if (!std::isfinite(x)) return 0.0f;
    float abs_x = std::abs(x);
    if (abs_x <= 0.8f) return x;
    float sign = (x >= 0.0f) ? 1.0f : -1.0f;
    return sign * (0.8f + 0.2f * std::tanh((abs_x - 0.8f) / 0.2f));
}

/**
 * @brief Undefined-behavior-free, strict-aliasing-safe 24-bit little-endian signed PCM decoder (`AUD-1G7-17`).
 *
 * Assembles 3 little-endian bytes into an unsigned 32-bit integer, sign-extends bit 23 (`0x00800000u`)
 * into bits 24..31 (`0xFF000000u`), reinterprets as `int32_t`, and normalizes by `2^23` (`8388608.0f`)
 * into `[-1.0f, +0.99999988f]`.
 *
 * @param sPtr Pointer to at least 3 valid bytes representing one 24-bit little-endian signed PCM sample.
 * @return Normalized floating-point sample in `[-1.0f, +1.0f)`.
 */
static inline float decode_pcm24_le(const uint8_t* sPtr) {
    uint32_t u = static_cast<uint32_t>(sPtr[0])
               | (static_cast<uint32_t>(sPtr[1]) << 8)
               | (static_cast<uint32_t>(sPtr[2]) << 16);
    // If the 24-bit sign bit (bit 23) is set, propagate 1s across the upper 8 bits for two's-complement sign extension.
    if (u & 0x00800000u) {
        u |= 0xFF000000u;
    }
    int32_t val = static_cast<int32_t>(u);
    return static_cast<float>(val) / 8388608.0f;
}

/**
 * @brief Reads and normalizes a single channel sample from an interleaved WASAPI capture buffer frame.
 *
 * Uses `memcpy` for 16-bit and 32-bit accesses to guarantee zero unaligned-access faults or strict-aliasing UB.
 *
 * @param pData Base pointer to the WASAPI capture packet byte buffer.
 * @param frameIdx Zero-based sample frame index within the packet (`0 <= frameIdx < numFrames`).
 * @param channelIdx Zero-based channel index within the frame (`0 <= channelIdx < totalChannels`).
 * @param totalChannels Total interleaved channels per frame (`pwfx->nChannels`).
 * @param srcBits Container bit depth per sample (`16`, `24`, or `32`).
 * @param isFloat `true` if samples are 32-bit IEEE 754 floats; `false` if signed integer PCM.
 * @param blockAlign Byte stride of one complete multi-channel frame (`pwfx->nBlockAlign`).
 * @return Normalized floating-point sample value (nominally `[-1.0f, 1.0f]`, sanitizing NaN/Inf to `0.0f`).
 */
static inline float read_channel_float(
    const uint8_t* pData,
    UINT32 frameIdx,
    int channelIdx,
    int totalChannels,
    WORD srcBits,
    bool isFloat,
    size_t blockAlign
) {
    if (!pData || channelIdx < 0 || channelIdx >= totalChannels) return 0.0f;
    const uint8_t* frameBase = pData + static_cast<size_t>(frameIdx) * blockAlign;
    if (isFloat && srcBits == 32) {
        float v = 0.0f;
        memcpy(&v, frameBase + static_cast<size_t>(channelIdx) * 4, sizeof(float));
        return std::isfinite(v) ? v : 0.0f;
    } else if (!isFloat && srcBits == 16) {
        int16_t v = 0;
        memcpy(&v, frameBase + static_cast<size_t>(channelIdx) * 2, sizeof(int16_t));
        return static_cast<float>(v) / 32768.0f;
    } else if (!isFloat && srcBits == 24) {
        return decode_pcm24_le(frameBase + static_cast<size_t>(channelIdx) * 3);
    } else if (!isFloat && srcBits == 32) {
        int32_t v = 0;
        memcpy(&v, frameBase + static_cast<size_t>(channelIdx) * 4, sizeof(int32_t));
        return static_cast<float>(v) / 2147483648.0f;
    }
    return 0.0f;
}

/**
 * @brief 2-pole Butterworth stereo biquad low-pass filter for anti-aliased downsampling (`> 48 kHz -> 48 kHz`).
 *
 * Configured with a 20 kHz cutoff (`fc = 20000.0` Hz, Q = `1/sqrt(2)`) via bilinear transform when the
 * WASAPI mix sample rate exceeds 48 kHz (e.g., 88.2 kHz, 96 kHz, 192 kHz, 384 kHz) so ultrasonic frequencies
 * above the 24 kHz Nyquist limit of the 48 kHz output stream are attenuated before linear decimation.
 * Automatically bypassed (`enabled = false`) when `srcRate <= 48000` Hz.
 */
struct StereoBiquadLpf {
    /// True when `srcRate > CANONICAL_SAMPLE_RATE` (48 kHz) and anti-aliasing filtering is active.
    bool enabled = false;
    /// Normalized feedforward coefficients (`b0`, `b1`, `b2`) of the Direct Form II Transposed biquad.
    float b0 = 1.0f, b1 = 0.0f, b2 = 0.0f;
    /// Normalized feedback coefficients (`a1`, `a2`) of the Direct Form II Transposed biquad.
    float a1 = 0.0f, a2 = 0.0f;
    /// Left-channel delay state registers (`z^-1`, `z^-2`).
    float z1L = 0.0f, z2L = 0.0f;
    /// Right-channel delay state registers (`z^-1`, `z^-2`).
    float z1R = 0.0f, z2R = 0.0f;

    /**
     * @brief Computes bilinear-transformed 2nd-order Butterworth LPF coefficients for `srcRate` (Hz).
     * @param srcRate Input WASAPI device sample rate in Hz.
     */
    void configure(uint32_t srcRate) {
        reset();
        if (srcRate <= CANONICAL_SAMPLE_RATE) {
            enabled = false;
            return;
        }
        // Pre-warp 20 kHz analog cutoff frequency onto the digital unit circle via tan(pi * fc / Fs).
        const double fc = 20000.0;
        const double k = std::tan(3.14159265358979323846 * fc / static_cast<double>(srcRate));
        const double k2 = k * k;
        const double sqrt2 = 1.4142135623730950488;
        const double norm = 1.0 / (1.0 + sqrt2 * k + k2);
        b0 = static_cast<float>(k2 * norm);
        b1 = static_cast<float>(2.0 * k2 * norm);
        b2 = b0;
        a1 = static_cast<float>(2.0 * (k2 - 1.0) * norm);
        a2 = static_cast<float>((1.0 - sqrt2 * k + k2) * norm);
        enabled = true;
    }

    /// Clears internal biquad delay registers to zero.
    void reset() {
        z1L = z2L = z1R = z2R = 0.0f;
    }

    /**
     * @brief Filters one stereo sample pair `(l, r)` in-place using Direct Form II Transposed recurrence.
     * @param l In/out Left channel sample amplitude.
     * @param r In/out Right channel sample amplitude.
     */
    inline void process(float& l, float& r) {
        if (!std::isfinite(l)) l = 0.0f;
        if (!std::isfinite(r)) r = 0.0f;
        if (!enabled) return;
        float outL = b0 * l + z1L;
        z1L = b1 * l - a1 * outL + z2L;
        z2L = b2 * l - a2 * outL;
        l = outL;

        float outR = b0 * r + z1R;
        z1R = b1 * r - a1 * outR + z2R;
        z2R = b2 * r - a2 * outR;
        r = outR;
    }
};

/**
 * @brief Stateful cross-packet fractional-phase stereo resampler (`AUD-1G7-13`, `NEW-1G8-07`).
 *
 * Converts arbitrary input sample rates (`srcRate` in `[8000, 384000]` Hz) into canonical 48 kHz
 * 16-bit signed little-endian stereo PCM bytes appended directly to `accumulator`.
 *
 * Why fractional phase (`phase` in `[-1.0, 0.0)`) and `prevL`/`prevR` are preserved across packets:
 *   For non-integer ratios such as 44.1 kHz -> 48 kHz (`step = 44100 / 48000 = 0.91875`), a 10 ms input
 *   packet contains 441 frames, and the final output sample of a packet lands at a fractional offset
 *   between frame 440 of the current packet (`prevL`/`prevR`) and frame 0 of the next packet. Preserving
 *   `phase = p - numFrames` (which is negative when `numFrames - 1 <= p < numFrames`) and interpolating
 *   against `prevL`/`prevR` when `i0 < 0` eliminates inter-packet phase resets, pitch warble, and boundary clicks.
 */
struct StatefulStereoResampler {
    /// Configured source sample rate in Hz.
    uint32_t srcRate = CANONICAL_SAMPLE_RATE;
    /// Source-to-canonical sample advance ratio (`srcRate / 48000.0` source frames per output frame).
    double step = 1.0;
    /// Fractional source frame position carried across packet boundaries (in `[-1.0, 0.0]` at packet entry).
    double phase = 0.0;
    /// Final Left channel sample of the immediately preceding packet (`frame[numFrames - 1]`).
    float prevL = 0.0f;
    /// Final Right channel sample of the immediately preceding packet (`frame[numFrames - 1]`).
    float prevR = 0.0f;
    /// True once at least one non-empty packet has been processed since `configure()`.
    bool hasPrev = false;
    /// Anti-aliasing low-pass filter applied prior to resampling when `srcRate > 48000` Hz.
    StereoBiquadLpf lpf;

    /**
     * @brief Initializes resampler ratio, clears phase history, and configures the anti-aliasing LPF.
     * @param rate Source WASAPI mix sample rate in Hz.
     */
    void configure(uint32_t rate) {
        srcRate = (rate >= MIN_VALID_SAMPLE_RATE && rate <= MAX_VALID_SAMPLE_RATE) ? rate : CANONICAL_SAMPLE_RATE;
        step = static_cast<double>(srcRate) / static_cast<double>(CANONICAL_SAMPLE_RATE);
        phase = 0.0;
        prevL = 0.0f;
        prevR = 0.0f;
        hasPrev = false;
        lpf.configure(srcRate);
    }

    /**
     * @brief Clamps a stereo float pair `(l, r)` to `[-1.0, 1.0]`, quantizes to 16-bit signed PCM, and appends 4 little-endian bytes.
     * @param accumulator Destination byte buffer accumulating canonical 48 kHz s16le stereo frames.
     * @param l Normalized Left sample in `[-1.0, 1.0]`.
     * @param r Normalized Right sample in `[-1.0, 1.0]`.
     */
    void append_pcm16(std::vector<uint8_t>& accumulator, float l, float r) {
        if (!std::isfinite(l)) l = 0.0f;
        if (!std::isfinite(r)) r = 0.0f;
        l = (std::max)(-1.0f, (std::min)(1.0f, l));
        r = (std::max)(-1.0f, (std::min)(1.0f, r));
        int16_t sL = static_cast<int16_t>(l * 32767.0f);
        int16_t sR = static_cast<int16_t>(r * 32767.0f);
        uint8_t bytes[4];
        bytes[0] = static_cast<uint8_t>(sL & 0xFF);
        bytes[1] = static_cast<uint8_t>((sL >> 8) & 0xFF);
        bytes[2] = static_cast<uint8_t>(sR & 0xFF);
        bytes[3] = static_cast<uint8_t>((sR >> 8) & 0xFF);
        accumulator.insert(accumulator.end(), bytes, bytes + 4);
    }

    /**
     * @brief Resamples `numFrames` of interleaved stereo float frames at `srcRate` into 48 kHz s16le bytes.
     *
     * Fast-path: When `srcRate == 48000` Hz, performs direct quantization without interpolation overhead.
     * General path: Steps `p` by `srcRate / 48000.0`, linearly interpolating between `(prevL, prevR)` and
     * `stereoPairs[0]` when `-1.0 <= p < 0.0`, and between `stereoPairs[u0]` and `stereoPairs[u0 + 1]`
     * when `0 <= u0 < numFrames - 1`.
     *
     * @param stereoPairs Pointer to `numFrames * 2` interleaved stereo floats `[L0, R0, L1, R1, ...]`.
     * @param numFrames Number of stereo frames in `stereoPairs`.
     * @param accumulator Destination byte vector receiving quantized 4-byte stereo s16le samples.
     */
    void process_stereo_block(
        const float* stereoPairs,
        UINT32 numFrames,
        std::vector<uint8_t>& accumulator
    ) {
        if (numFrames == 0 || !stereoPairs) return;

        if (srcRate == CANONICAL_SAMPLE_RATE) {
            for (UINT32 f = 0; f < numFrames; ++f) {
                append_pcm16(accumulator, stereoPairs[f * 2], stereoPairs[f * 2 + 1]);
            }
            prevL = stereoPairs[(numFrames - 1) * 2];
            prevR = stereoPairs[(numFrames - 1) * 2 + 1];
            hasPrev = true;
            return;
        }

        double p = phase;
        while (p < static_cast<double>(numFrames)) {
            int64_t i0 = static_cast<int64_t>(std::floor(p));
            float frac = static_cast<float>(p - static_cast<double>(i0));

            float l0 = 0.0f, r0 = 0.0f;
            float l1 = 0.0f, r1 = 0.0f;

            if (i0 < 0) {
                // Cross-packet boundary interpolation between the last sample of the previous packet and sample 0 of this packet.
                l0 = hasPrev ? prevL : stereoPairs[0];
                r0 = hasPrev ? prevR : stereoPairs[1];
                l1 = stereoPairs[0];
                r1 = stereoPairs[1];
            } else {
                UINT32 u0 = static_cast<UINT32>(i0);
                l0 = stereoPairs[u0 * 2];
                r0 = stereoPairs[u0 * 2 + 1];
                if (u0 + 1 < numFrames) {
                    l1 = stereoPairs[(u0 + 1) * 2];
                    r1 = stereoPairs[(u0 + 1) * 2 + 1];
                } else {
                    // Hold fractional position `p` in `[numFrames - 1, numFrames)` for the next packet's `i0 < 0` step.
                    break;
                }
            }

            float l = l0 + (l1 - l0) * frac;
            float r = r0 + (r1 - r0) * frac;
            append_pcm16(accumulator, l, r);
            p += step;
        }

        phase = p - static_cast<double>(numFrames);
        prevL = stereoPairs[(numFrames - 1) * 2];
        prevR = stereoPairs[(numFrames - 1) * 2 + 1];
        hasPrev = true;
    }
};

// ============================================================================
// IMMNotificationClient With Owned Duplicated Event Handle (`NEW-1G8-02`)
// ============================================================================

/**
 * @brief COM notification sink (`IMMNotificationClient`) monitoring Windows default audio output endpoint hot-swaps.
 *
 * Threading & Lifetime Safety (`NEW-1G8-02`):
 *   Windows `MMDevApi.dll` dispatches `OnDefaultDeviceChanged` on background OS RPC threads and holds its own
 *   COM reference (`AddRef`/`Release`) to this object. Even after `UnregisterEndpointNotificationCallback` is
 *   called during session teardown, an in-flight RPC callback on another CPU core may still be executing
 *   until its final `Release()`. By duplicating `borrowedEvent` via `DuplicateHandle` in the constructor and
 *   closing `m_ownedEvent` only in `~DefaultDeviceNotifier()` (when `m_refCount` reaches 0), `SetEvent(m_ownedEvent)`
 *   is guaranteed to never touch a closed or recycled Win32 handle after `~CaptureSessionContext()`.
 */
class DefaultDeviceNotifier final : public IMMNotificationClient {
public:
    /**
     * @brief Constructs a notification client owning an independent duplicated reference to `borrowedEvent`.
     * @param borrowedEvent Session device-change event handle (`hDeviceChangeEvent`) to duplicate.
     */
    explicit DefaultDeviceNotifier(HANDLE borrowedEvent)
        : m_refCount(1), m_ownedEvent(NULL), m_deviceChanged(false) {
        if (borrowedEvent) {
            // Own an independent kernel handle reference so MMDevApi RPC callbacks can NEVER
            // call SetEvent on a closed/recycled handle after ~CaptureSessionContext() (`NEW-1G8-02`).
            DuplicateHandle(
                GetCurrentProcess(),
                borrowedEvent,
                GetCurrentProcess(),
                &m_ownedEvent,
                EVENT_MODIFY_STATE,
                FALSE,
                0
            );
        }
    }

    /// Closes the duplicated kernel event handle once the final COM reference is released.
    ~DefaultDeviceNotifier() {
        if (m_ownedEvent) {
            CloseHandle(m_ownedEvent);
            m_ownedEvent = NULL;
        }
    }

    /// Increments the atomic COM reference count (`IUnknown::AddRef`).
    ULONG STDMETHODCALLTYPE AddRef() override {
        return static_cast<ULONG>(m_refCount.fetch_add(1) + 1);
    }

    /// Decrements the atomic COM reference count and self-destructs on reaching zero (`IUnknown::Release`).
    ULONG STDMETHODCALLTYPE Release() override {
        ULONG r = static_cast<ULONG>(m_refCount.fetch_sub(1) - 1);
        if (r == 0) {
            delete this;
        }
        return r;
    }

    /// Standard COM interface query supporting `IUnknown` and `IMMNotificationClient`.
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, VOID** ppvInterface) override {
        if (!ppvInterface) return E_POINTER;
        if (riid == __uuidof(IUnknown) || riid == __uuidof(IMMNotificationClient)) {
            *ppvInterface = static_cast<IMMNotificationClient*>(this);
            AddRef();
            return S_OK;
        }
        *ppvInterface = NULL;
        return E_NOINTERFACE;
    }

    /**
     * @brief Invoked by Windows MMDevApi when the user or OS changes the default audio endpoint.
     *
     * Signals `m_deviceChanged` and wakes the capture worker's `WaitForMultipleObjects` call when the
     * default console render endpoint (`flow == eRender && role == eConsole`) changes (e.g., headphone plug/unplug).
     */
    HRESULT STDMETHODCALLTYPE OnDefaultDeviceChanged(EDataFlow flow, ERole role, LPCWSTR) override {
        if (flow == eRender && role == eConsole) {
            m_deviceChanged.store(true, std::memory_order_release);
            if (m_ownedEvent) {
                SetEvent(m_ownedEvent);
            }
        }
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE OnDeviceStateChanged(LPCWSTR, DWORD) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE OnDeviceAdded(LPCWSTR) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE OnDeviceRemoved(LPCWSTR) override { return S_OK; }
    HRESULT STDMETHODCALLTYPE OnPropertyValueChanged(LPCWSTR, const PROPERTYKEY) override { return S_OK; }

    /**
     * @brief Atomically reads and clears the pending device-changed flag.
     * @return `true` if a default console render endpoint change occurred since the last call.
     */
    bool consume_changed() {
        return m_deviceChanged.exchange(false, std::memory_order_acq_rel);
    }

private:
    /// Atomic COM reference counter starts at 1 on construction.
    std::atomic<LONG> m_refCount;
    /// Duplicated Win32 event handle with `EVENT_MODIFY_STATE` rights owned exclusively by this notifier.
    HANDLE m_ownedEvent;
    /// Latching atomic flag set by `OnDefaultDeviceChanged` and cleared by `consume_changed()`.
    std::atomic<bool> m_deviceChanged;
};

// ============================================================================
// Per-Session Worker Context (`AUD-1G7-03`)
// ============================================================================

/**
 * @brief Finite state machine phases for the WASAPI loopback capture worker thread.
 */
enum class WasapiCaptureState {
    /// Initial stream creation before entering the main event loop.
    Initializing,
    /// Actively waiting on WASAPI packet events, draining audio buffers, or emitting holdoff-gated synthetic silence.
    Capturing,
    /// Tearing down a lost/changed endpoint and retrying `init_stream(true)` with exponential backoff.
    Reconnecting,
    /// Terminal state entered upon stop request, startup failure, or exhaustion of `MAX_RECONNECT_ATTEMPTS`.
    Stopped
};

/**
 * @brief Isolated per-session state container shared via `std::shared_ptr` between the FFI lifecycle controller and its worker thread.
 *
 * All COM pointers (`pEnumerator`, `pNotifier`, `pDevice`, `pAudioClient`, `pCaptureClient`, `pMixFormat`)
 * and DSP buffers (`downmix`, `resampler`, `stereoScratch`, `accumulator`) are touched strictly by the
 * session's dedicated worker thread. Cross-thread coordination uses only atomic flags (`stop_requested`,
 * `is_active`, `initial_init_succeeded`) and Win32 kernel event handles (`hStopEvent`, `hStartDoneEvent`, `hDeviceChangeEvent`).
 */
struct CaptureSessionContext {
    /// Monotonic routing generation ID assigned by Rust (`app/src/audio/mod.rs`) to fence stale callbacks.
    uint64_t capture_gen = 0;
    /// Atomic stop signal set by `stop_current_session_locked` or startup timeout.
    std::atomic<bool> stop_requested{false};
    /// Atomic health indicator (`true` while in `WasapiCaptureState::Capturing` with a running `IAudioClient`).
    std::atomic<bool> is_active{false};
    /// Latching flag set to `true` iff the initial `init_stream(false)` call succeeded before `hStartDoneEvent` was signaled.
    std::atomic<bool> initial_init_succeeded{false};

    // Lifecycle Win32 manual-reset events owned by this session context (closed only in destructor).
    /// Manual-reset event signaled to immediately wake the worker thread from any wait on stop.
    HANDLE hStopEvent = NULL;
    /// Manual-reset event signaled by the worker thread once initial stream setup succeeds or fails.
    HANDLE hStartDoneEvent = NULL;
    /// Manual-reset event signaled (via `DefaultDeviceNotifier`'s duplicated handle) on default render device change.
    HANDLE hDeviceChangeEvent = NULL;

    // Worker-thread-private COM interfaces, format descriptors, and event handles.
    /// Auto-reset event passed to `IAudioClient::SetEventHandle` and signaled by WASAPI when a packet is ready.
    HANDLE hCaptureEvent = NULL;
    /// COM multimedia device enumerator (`CLSID_MMDeviceEnumerator`).
    IMMDeviceEnumerator* pEnumerator = NULL;
    /// Registered COM endpoint notification client observing default render device changes.
    DefaultDeviceNotifier* pNotifier = NULL;
    /// Active default console render audio endpoint (`IMMDevice`).
    IMMDevice* pDevice = NULL;
    /// WASAPI audio client bound in shared loopback mode (`IAudioClient`).
    IAudioClient* pAudioClient = NULL;
    /// WASAPI capture service used to read loopback packets (`IAudioCaptureClient`).
    IAudioCaptureClient* pCaptureClient = NULL;
    /// Device mix format allocated by `IAudioClient::GetMixFormat` and freed via `CoTaskMemFree`.
    WAVEFORMATEX* pMixFormat = NULL;
    /// `true` if `pMixFormat` carries 32-bit IEEE float samples; `false` for 16/24/32-bit integer PCM.
    bool mixFormatIsFloat = false;
    /// WASAPI engine default scheduling period in microseconds (from `GetDevicePeriod`; defaults to `10000.0` us = 10 ms).
    double defaultPeriodUs = 10000.0;

    // Worker-thread-private preallocated DSP state and scratch buffers.
    /// Channel-to-stereo downmix matrix and peak-safe attenuation factor for the current `pMixFormat`.
    DownmixWeights downmix;
    /// Stateful fractional-phase stereo resampler and anti-aliasing Butterworth LPF.
    StatefulStereoResampler resampler;
    /// Preallocated scratch buffer storing downmixed, filtered, soft-limited stereo float frames (`[L0, R0, L1, R1, ...]`).
    std::vector<float> stereoScratch;
    /// Byte ring/queue accumulating quantized 48 kHz s16le stereo samples until complete 960-byte (5 ms) frames are drained.
    std::vector<uint8_t> accumulator;

    /// Destructor guarantees deterministic release of all COM interfaces, `CoTaskMemAlloc` memory, and Win32 kernel handles.
    ~CaptureSessionContext() {
        release_stream_resources();
        release_enumerator();
        if (hStopEvent) {
            CloseHandle(hStopEvent);
            hStopEvent = NULL;
        }
        if (hStartDoneEvent) {
            CloseHandle(hStartDoneEvent);
            hStartDoneEvent = NULL;
        }
        if (hDeviceChangeEvent) {
            CloseHandle(hDeviceChangeEvent);
            hDeviceChangeEvent = NULL;
        }
    }

    /**
     * @brief Stops and releases all per-stream WASAPI COM objects (`pCaptureClient`, `pAudioClient`, `pDevice`),
     *        frees `pMixFormat` via `CoTaskMemFree`, and closes `hCaptureEvent`.
     */
    void release_stream_resources() {
        if (pCaptureClient) {
            pCaptureClient->Release();
            pCaptureClient = NULL;
        }
        if (pAudioClient) {
            pAudioClient->Stop();
            pAudioClient->Release();
            pAudioClient = NULL;
        }
        if (hCaptureEvent) {
            CloseHandle(hCaptureEvent);
            hCaptureEvent = NULL;
        }
        if (pMixFormat) {
            CoTaskMemFree(pMixFormat);
            pMixFormat = NULL;
        }
        if (pDevice) {
            pDevice->Release();
            pDevice = NULL;
        }
    }

    /**
     * @brief Unregisters `pNotifier` from `pEnumerator` and releases both COM references.
     */
    void release_enumerator() {
        if (pEnumerator && pNotifier) {
            pEnumerator->UnregisterEndpointNotificationCallback(pNotifier);
        }
        if (pNotifier) {
            pNotifier->Release();
            pNotifier = NULL;
        }
        if (pEnumerator) {
            pEnumerator->Release();
            pEnumerator = NULL;
        }
    }

    /**
     * @brief Opens (or re-opens) the default console render endpoint in shared event-driven WASAPI loopback mode.
     *
     * Algorithm:
     *   1. Releases any prior stream resources (and optionally recreates `IMMDeviceEnumerator` + `DefaultDeviceNotifier`).
     *   2. Clears any stale `hDeviceChangeEvent` signal (`NEW-1G8-05`) so a burst of device notifications during
     *      reconnection does not trigger an immediate redundant reconnect cycle.
     *   3. Queries `GetDefaultAudioEndpoint(eRender, eConsole)`, activates `IAudioClient`, retrieves and validates
     *      `GetMixFormat`, and calibrates `defaultPeriodUs` via `GetDevicePeriod`.
     *   4. Initializes the shared loopback stream with a 50 ms (`500,000` x 100-ns `REFERENCE_TIME`) engine buffer
     *      and `AUDCLNT_STREAMFLAGS_LOOPBACK | AUDCLNT_STREAMFLAGS_EVENTCALLBACK`.
     *   5. Binds an auto-reset `hCaptureEvent`, acquires `IAudioCaptureClient`, preallocates DSP buffers, checks
     *      that `stop_requested` has not been set during slow driver initialization, and starts the stream.
     *
     * @param recreate_enumerator If `true`, tears down and recreates `pEnumerator` and `pNotifier` before endpoint lookup.
     * @return `true` if the WASAPI loopback stream is initialized and actively started; `false` on any error or stop request.
     */
    bool init_stream(bool recreate_enumerator) {
        release_stream_resources();
        if (recreate_enumerator) {
            release_enumerator();
        }
        if (stop_requested.load(std::memory_order_acquire)) {
            return false;
        }
        // Clear any pending device-change signal before opening new stream (`NEW-1G8-05`)
        if (hDeviceChangeEvent) {
            ResetEvent(hDeviceChangeEvent);
        }
        if (pNotifier) {
            (void)pNotifier->consume_changed();
        }

        if (!pEnumerator) {
            HRESULT hr = CoCreateInstance(
                __uuidof(MMDeviceEnumerator),
                NULL,
                CLSCTX_ALL,
                __uuidof(IMMDeviceEnumerator),
                reinterpret_cast<void**>(&pEnumerator)
            );
            if (FAILED(hr) || !pEnumerator) {
                pEnumerator = NULL;
                return false;
            }
            if (hDeviceChangeEvent) {
                pNotifier = new (std::nothrow) DefaultDeviceNotifier(hDeviceChangeEvent);
                if (pNotifier) {
                    if (FAILED(pEnumerator->RegisterEndpointNotificationCallback(pNotifier))) {
                        pNotifier->Release();
                        pNotifier = NULL;
                    }
                }
            }
        }

        HRESULT hr = pEnumerator->GetDefaultAudioEndpoint(eRender, eConsole, &pDevice);
        if (FAILED(hr) || !pDevice) {
            release_stream_resources();
            return false;
        }

        hr = pDevice->Activate(__uuidof(IAudioClient), CLSCTX_ALL, NULL, reinterpret_cast<void**>(&pAudioClient));
        if (FAILED(hr) || !pAudioClient) {
            release_stream_resources();
            return false;
        }

        hr = pAudioClient->GetMixFormat(&pMixFormat);
        if (FAILED(hr) || !pMixFormat || !validate_mix_format(pMixFormat, mixFormatIsFloat)) {
            release_stream_resources();
            return false;
        }

        REFERENCE_TIME defPeriod = 0;
        REFERENCE_TIME minPeriod = 0;
        if (SUCCEEDED(pAudioClient->GetDevicePeriod(&defPeriod, &minPeriod)) && defPeriod > 0) {
            // 1 REFERENCE_TIME unit = 100 ns -> divide by 10 for microseconds
            defaultPeriodUs = static_cast<double>(defPeriod) / 10.0;
        } else {
            defaultPeriodUs = 10000.0;
        }

        // 500,000 reference time units = 50 ms shared buffer (1 REFERENCE_TIME = 100 ns)
        hr = pAudioClient->Initialize(
            AUDCLNT_SHAREMODE_SHARED,
            AUDCLNT_STREAMFLAGS_LOOPBACK | AUDCLNT_STREAMFLAGS_EVENTCALLBACK,
            500000,
            0,
            pMixFormat,
            NULL
        );
        if (FAILED(hr)) {
            release_stream_resources();
            return false;
        }

        hCaptureEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
        if (!hCaptureEvent) {
            release_stream_resources();
            return false;
        }

        hr = pAudioClient->SetEventHandle(hCaptureEvent);
        if (FAILED(hr)) {
            release_stream_resources();
            return false;
        }

        hr = pAudioClient->GetService(__uuidof(IAudioCaptureClient), reinterpret_cast<void**>(&pCaptureClient));
        if (FAILED(hr) || !pCaptureClient) {
            release_stream_resources();
            return false;
        }

        downmix = compute_downmix_weights(pMixFormat);
        resampler.configure(pMixFormat->nSamplesPerSec);
        accumulator.clear();
        if (accumulator.capacity() < 8192) {
            accumulator.reserve(8192);
        }
        if (stereoScratch.capacity() < 16384) {
            stereoScratch.reserve(16384);
        }

        // Abort before starting the hardware stream if stop was requested while COM initialization was blocked.
        if (stop_requested.load(std::memory_order_acquire)) {
            release_stream_resources();
            return false;
        }

        hr = pAudioClient->Start();
        if (FAILED(hr)) {
            release_stream_resources();
            return false;
        }

        return true;
    }

    /**
     * @brief Downmixes, filters, soft-limits, and resamples one WASAPI capture packet into `accumulator`.
     *
     * Bounds & Overflow Safety:
     *   Rejects `numFrames == 0` or `numFrames > MAX_PACKET_FRAMES` (`384000` frames) and verifies that
     *   `numFrames * nBlockAlign` cannot overflow `size_t` before indexing `pData`.
     *
     * Why `AUDCLNT_BUFFERFLAGS_SILENT` feeds zeros through `lpf` and `resampler` instead of bypassing them (`NEW-1G8-07`):
     *   Bypassing the resampler or resetting its fractional `phase` on silent packets causes cumulative sample-count
     *   drift at non-48 kHz rates (such as 44.1 kHz) and creates step discontinuities in the Butterworth biquad delay
     *   registers (`z1`/`z2`). Feeding continuous zero samples preserves exact fractional phase continuity and ring-down.
     *
     * @param pData Pointer to the raw WASAPI packet buffer returned by `IAudioCaptureClient::GetBuffer` (may be `NULL` when silent).
     * @param numFrames Number of multi-channel sample frames in the packet.
     * @param flags WASAPI buffer status flags (`AUDCLNT_BUFFERFLAGS_SILENT`, `AUDCLNT_BUFFERFLAGS_DATA_DISCONTINUITY`, etc.).
     */
    void normalize_and_append(const BYTE* pData, UINT32 numFrames, DWORD flags) {
        if (numFrames == 0 || numFrames > MAX_PACKET_FRAMES || !pMixFormat) return;
        const int srcChannels = static_cast<int>(pMixFormat->nChannels);
        const size_t blockAlign = static_cast<size_t>(pMixFormat->nBlockAlign);
        if (srcChannels <= 0 || blockAlign == 0) return;

        // Guard against size_t multiplication overflow on both 32-bit and 64-bit targets.
        if (static_cast<size_t>(numFrames) > (std::numeric_limits<size_t>::max)() / blockAlign ||
            static_cast<size_t>(numFrames) > (std::numeric_limits<size_t>::max)() / (2 * sizeof(float))) {
            return;
        }

        const size_t neededFloats = static_cast<size_t>(numFrames) * 2;
        if (stereoScratch.size() < neededFloats) {
            stereoScratch.resize(neededFloats);
        }

        const bool is_silent_buffer = (flags & AUDCLNT_BUFFERFLAGS_SILENT) != 0 || pData == NULL;
        if (is_silent_buffer) {
            // Feed zeros continuously through LPF & StatefulStereoResampler to eliminate 44.1 kHz
            // rounding drift and filter discontinuities (`NEW-1G8-07`).
            for (UINT32 f = 0; f < numFrames; ++f) {
                float l = 0.0f;
                float r = 0.0f;
                resampler.lpf.process(l, r);
                stereoScratch[static_cast<size_t>(f) * 2] = l;
                stereoScratch[static_cast<size_t>(f) * 2 + 1] = r;
            }
            resampler.process_stereo_block(stereoScratch.data(), numFrames, accumulator);
            return;
        }

        const int mapCh = (std::min)(srcChannels, downmix.numChannels);
        const uint8_t* rawBytes = reinterpret_cast<const uint8_t*>(pData);

        for (UINT32 f = 0; f < numFrames; ++f) {
            float l = 0.0f;
            float r = 0.0f;
            for (int c = 0; c < mapCh; ++c) {
                float wL = downmix.weightL[c];
                float wR = downmix.weightR[c];
                if (wL == 0.0f && wR == 0.0f) continue;
                float s = read_channel_float(
                    rawBytes, f, c, srcChannels, pMixFormat->wBitsPerSample, mixFormatIsFloat, blockAlign
                );
                l += s * wL;
                r += s * wR;
            }
            l *= downmix.attenuation;
            r *= downmix.attenuation;
            resampler.lpf.process(l, r);
            l = soft_limit(l);
            r = soft_limit(r);
            stereoScratch[static_cast<size_t>(f) * 2] = l;
            stereoScratch[static_cast<size_t>(f) * 2 + 1] = r;
        }

        resampler.process_stereo_block(stereoScratch.data(), numFrames, accumulator);
    }

    /**
     * @brief Emits all complete 960-byte (5 ms) canonical stereo frames currently queued in `accumulator`.
     *
     * Checks `stop_requested` before each callback invocation so no audio frame callback is ever delivered
     * after a stop request has been issued.
     *
     * @return Number of canonical 5 ms frames delivered to `integrator_on_win_audio_captured`.
     */
    uint32_t drain_complete_frames() {
        uint32_t emitted = 0;
        while (accumulator.size() >= CANONICAL_FRAME_BYTES && !stop_requested.load(std::memory_order_acquire)) {
            const uint8_t* framePtr = accumulator.data();
            bool frame_is_silent = true;
            for (size_t offset = 0; offset < CANONICAL_FRAME_BYTES; offset += 2) {
                int16_t sample = 0;
                memcpy(&sample, framePtr + offset, sizeof(int16_t));
                if (sample != 0) {
                    frame_is_silent = false;
                    break;
                }
            }
            integrator_on_win_audio_captured(framePtr, CANONICAL_FRAME_BYTES, frame_is_silent ? 1 : 0);
            if (frame_is_silent) {
                g_total_silent_frames.fetch_add(CANONICAL_FRAME_SAMPLES_PER_CH, std::memory_order_relaxed);
            }
            accumulator.erase(accumulator.begin(), accumulator.begin() + CANONICAL_FRAME_BYTES);
            emitted++;
        }
        return emitted;
    }

    /**
     * @brief Zero-pads any sub-5 ms residue in `accumulator` to a full 960-byte boundary and drains it (`NEW-1G8-07`).
     *
     * Called once when transitioning from active audio packets into synthetic silence or endpoint reconnection
     * so trailing audio samples at non-integer sample rates (e.g. 44.1 kHz) are flushed cleanly rather than
     * stranded in the accumulator.
     *
     * @return Number of 5 ms canonical frames emitted (0 if `accumulator` was empty or `stop_requested` was set).
     */
    uint32_t flush_partial_accumulator_to_silence() {
        if (accumulator.empty() || stop_requested.load(std::memory_order_acquire)) return 0;
        size_t rem = accumulator.size() % CANONICAL_FRAME_BYTES;
        if (rem != 0) {
            accumulator.insert(accumulator.end(), CANONICAL_FRAME_BYTES - rem, 0);
        }
        return drain_complete_frames();
    }
};

/**
 * @brief Heap-allocated startup envelope transferring `std::shared_ptr<CaptureSessionContext>` ownership into `CreateThread`.
 */
struct WorkerThreadArg {
    /// Shared pointer keeping the session context alive for the entire lifetime of the worker thread.
    std::shared_ptr<CaptureSessionContext> ctx;
};

/// Global mutex serializing all session start/stop transitions and held across worker thread joins.
static std::mutex g_lifecycle_mtx;
/// Active capture session context pointer, or `nullptr` when no session is running. Protected by `g_lifecycle_mtx`.
static std::shared_ptr<CaptureSessionContext> g_current_session;
/// Win32 thread handle for the active capture worker thread, or `NULL` when stopped. Protected by `g_lifecycle_mtx`.
static HANDLE g_worker_thread = NULL;

/**
 * @brief Dedicated Win32 real-time WASAPI loopback capture worker thread procedure.
 *
 * Lifecycle & State Machine:
 *   1. Takes ownership of `WorkerThreadArg` via `std::unique_ptr` and initializes exception-safe RAII guards
 *      outside the `try` block (`ComApartmentGuard(COINIT_MULTITHREADED)`, `avrt.dll` `"Pro Audio"` MMCSS boost,
 *      and `winmm.dll` 1 ms timer period).
 *   2. Calls `ctx->init_stream(false)` and signals `ctx->hStartDoneEvent` to release the waiting caller in
 *      `integrator_win_audio_capture_start`.
 *   3. Executes the state loop (`Capturing` <-> `Reconnecting`) until `ctx->stop_requested` is set or
 *      `MAX_RECONNECT_ATTEMPTS` (10) consecutive reconnection attempts fail with exponential backoff
 *      (`100 ms, 250 ms, 500 ms, 1000 ms`).
 *   4. In `Capturing`:
 *      - Waits up to 5 ms on `{hStopEvent, hCaptureEvent, hDeviceChangeEvent}`.
 *      - On device change or `WAIT_FAILED`/WASAPI error, flushes partial accumulator bytes and enters `Reconnecting`.
 *      - When `GetNextPacketSize` is 0, checks `should_emit_synthetic_silence` against the `GetDevicePeriod`-calibrated
 *        holdoff (`>= max(2 * defaultPeriodUs, 25000 us)`) before emitting 5 ms zero heartbeat frames capped at
 *        `MAX_SILENCE_FRAMES_PER_TICK` (8 frames).
 *      - When `packetLength > 0`, drains all queued WASAPI buffers via `GetBuffer` / `normalize_and_append` /
 *        `ReleaseBuffer` / `drain_complete_frames`.
 *   5. On exit, releases all COM resources and invokes `integrator_on_win_audio_capture_ended(ctx->capture_gen, exit_reason)`
 *      iff startup succeeded (`initial_init_succeeded`) and termination was not requested by `stop` (`!stop_requested`).
 *
 * @param lpParam Raw pointer to a heap-allocated `WorkerThreadArg`.
 * @return Win32 thread exit code (`0` on normal exit, `1` on invalid argument or COM init failure).
 */
static DWORD WINAPI win_audio_capture_thread_proc(LPVOID lpParam) {
    std::unique_ptr<WorkerThreadArg> arg(reinterpret_cast<WorkerThreadArg*>(lpParam));
    if (!arg || !arg->ctx) {
        return 1;
    }
    std::shared_ptr<CaptureSessionContext> ctx = arg->ctx;
    int exit_reason = 0; // 0 = requested stop, 1 = init failure, 2 = reconnect exhausted, 3 = exception

    // Declare RAII guards OUTSIDE `try` so exceptions can NEVER leak COM, MMCSS, timer period, or DLLs (`NEW-1G8-04`).
    ComApartmentGuard comGuard(COINIT_MULTITHREADED);
    if (!comGuard.initialized) {
        ctx->initial_init_succeeded.store(false, std::memory_order_release);
        if (ctx->hStartDoneEvent) SetEvent(ctx->hStartDoneEvent);
        return 1;
    }
    SystemModuleGuard avrtMod(L"avrt.dll");
    MmcssTaskGuard mmcssGuard(avrtMod.handle, L"Pro Audio");
    SystemModuleGuard winmmMod(L"winmm.dll");
    TimerResolutionGuard timerGuard(winmmMod.handle, 1);

    try {
        HRESULT hr = S_OK;
        LARGE_INTEGER qpcFreq{};
        QueryPerformanceFrequency(&qpcFreq);
        LARGE_INTEGER lastPacketQpc{};
        LARGE_INTEGER lastSilenceTickQpc{};
        QueryPerformanceCounter(&lastPacketQpc);
        lastSilenceTickQpc = lastPacketQpc;
        bool inSyntheticSilence = false;
        double silenceAccumUs = 0.0;

        WasapiCaptureState state = WasapiCaptureState::Initializing;
        uint32_t reconnectAttempts = 0;
        const uint32_t backoffDelaysMs[] = { 100, 250, 500, 1000 };

        if (ctx->init_stream(false) && !ctx->stop_requested.load(std::memory_order_acquire)) {
            state = WasapiCaptureState::Capturing;
            ctx->is_active.store(true, std::memory_order_release);
            ctx->initial_init_succeeded.store(true, std::memory_order_release);
            if (ctx->hStartDoneEvent) SetEvent(ctx->hStartDoneEvent);
            QueryPerformanceCounter(&lastPacketQpc);
            lastSilenceTickQpc = lastPacketQpc;
        } else {
            ctx->release_stream_resources();
            ctx->initial_init_succeeded.store(false, std::memory_order_release);
            if (ctx->hStartDoneEvent) SetEvent(ctx->hStartDoneEvent);
            state = WasapiCaptureState::Stopped;
            exit_reason = ctx->stop_requested.load(std::memory_order_acquire) ? 0 : 1;
        }

        while (!ctx->stop_requested.load(std::memory_order_acquire) && state != WasapiCaptureState::Stopped) {
            switch (state) {
                case WasapiCaptureState::Reconnecting: {
                    ctx->is_active.store(false, std::memory_order_release);
                    ctx->release_stream_resources();

                    if (reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) {
                        state = WasapiCaptureState::Stopped;
                        exit_reason = 2;
                        break;
                    }

                    uint32_t delayIdx = (std::min)(
                        reconnectAttempts,
                        static_cast<uint32_t>(sizeof(backoffDelaysMs) / sizeof(backoffDelaysMs[0]) - 1)
                    );
                    uint32_t delayMs = backoffDelaysMs[delayIdx];
                    reconnectAttempts++;

                    if (ctx->hStopEvent) {
                        DWORD w = WaitForSingleObject(ctx->hStopEvent, delayMs);
                        if (w == WAIT_OBJECT_0 || ctx->stop_requested.load(std::memory_order_acquire)) {
                            state = WasapiCaptureState::Stopped;
                            break;
                        }
                    } else {
                        Sleep(delayMs);
                    }

                    if (ctx->init_stream(true) && !ctx->stop_requested.load(std::memory_order_acquire)) {
                        state = WasapiCaptureState::Capturing;
                        ctx->is_active.store(true, std::memory_order_release);
                        reconnectAttempts = 0;
                        inSyntheticSilence = false;
                        silenceAccumUs = 0.0;
                        QueryPerformanceCounter(&lastPacketQpc);
                        lastSilenceTickQpc = lastPacketQpc;
                    }
                    break;
                }

                case WasapiCaptureState::Capturing: {
                    if (!ctx->pCaptureClient || !ctx->hCaptureEvent || !ctx->hStopEvent) {
                        state = WasapiCaptureState::Reconnecting;
                        break;
                    }

                    if (ctx->pNotifier && ctx->pNotifier->consume_changed()) {
                        if (ctx->hDeviceChangeEvent) ResetEvent(ctx->hDeviceChangeEvent);
                        (void)ctx->flush_partial_accumulator_to_silence();
                        state = WasapiCaptureState::Reconnecting;
                        break;
                    }

                    HANDLE waitHandles[3];
                    DWORD handleCount = 0;
                    waitHandles[handleCount++] = ctx->hStopEvent;
                    waitHandles[handleCount++] = ctx->hCaptureEvent;
                    if (ctx->hDeviceChangeEvent) {
                        waitHandles[handleCount++] = ctx->hDeviceChangeEvent;
                    }

                    DWORD waitRes = WaitForMultipleObjects(handleCount, waitHandles, FALSE, 5);
                    if (ctx->stop_requested.load(std::memory_order_acquire) || waitRes == WAIT_OBJECT_0) {
                        state = WasapiCaptureState::Stopped;
                        break;
                    }
                    if (waitRes == WAIT_FAILED) {
                        // Prevent a 0 ms busy-spin if a wait handle becomes invalid; back off via Reconnecting.
                        (void)ctx->flush_partial_accumulator_to_silence();
                        state = WasapiCaptureState::Reconnecting;
                        break;
                    }
                    if (handleCount == 3 && waitRes == WAIT_OBJECT_0 + 2) {
                        if (ctx->pNotifier) (void)ctx->pNotifier->consume_changed();
                        ResetEvent(ctx->hDeviceChangeEvent);
                        (void)ctx->flush_partial_accumulator_to_silence();
                        state = WasapiCaptureState::Reconnecting;
                        break;
                    }

                    UINT32 packetLength = 0;
                    hr = ctx->pCaptureClient->GetNextPacketSize(&packetLength);
                    if (FAILED(hr)) {
                        (void)ctx->flush_partial_accumulator_to_silence();
                        state = WasapiCaptureState::Reconnecting;
                        break;
                    }

                    if (packetLength == 0) {
                        LARGE_INTEGER nowQpc{};
                        QueryPerformanceCounter(&nowQpc);
                        double sincePacketUs = (qpcFreq.QuadPart > 0)
                            ? (static_cast<double>(nowQpc.QuadPart - lastPacketQpc.QuadPart) * 1000000.0
                               / static_cast<double>(qpcFreq.QuadPart))
                            : 0.0;

                        // Silence-entry holdoff (`NEW-1G8-01`): do NOT inject synthetic silence between
                        // normal 10–20 ms WASAPI audio packets!
                        if (!should_emit_synthetic_silence(sincePacketUs, ctx->defaultPeriodUs, inSyntheticSilence)) {
                            break;
                        }

                        if (!inSyntheticSilence) {
                            inSyntheticSilence = true;
                            silenceAccumUs = 0.0;
                            lastSilenceTickQpc = nowQpc;
                            // Flush any partial accumulator residue once upon true silence entry (`NEW-1G8-07`),
                            // and verify stop_requested was not set before emitting a synthetic zero frame.
                            uint32_t flushed = ctx->flush_partial_accumulator_to_silence();
                            if (flushed == 0 && !ctx->stop_requested.load(std::memory_order_acquire)) {
                                uint8_t zeroFrame[CANONICAL_FRAME_BYTES] = {0};
                                integrator_on_win_audio_captured(zeroFrame, CANONICAL_FRAME_BYTES, 1);
                                g_total_silent_frames.fetch_add(CANONICAL_FRAME_SAMPLES_PER_CH, std::memory_order_relaxed);
                            }
                            break;
                        }

                        double elapsedUs = (qpcFreq.QuadPart > 0)
                            ? (static_cast<double>(nowQpc.QuadPart - lastSilenceTickQpc.QuadPart) * 1000000.0
                               / static_cast<double>(qpcFreq.QuadPart))
                            : 5000.0;
                        lastSilenceTickQpc = nowQpc;

                        if (elapsedUs > 0.0 && elapsedUs < 250000.0) {
                            silenceAccumUs += elapsedUs;
                        } else if (elapsedUs >= 250000.0) {
                            silenceAccumUs = 5000.0 * static_cast<double>(MAX_SILENCE_FRAMES_PER_TICK);
                        }

                        uint32_t framesToEmit = static_cast<uint32_t>(silenceAccumUs / 5000.0);
                        if (framesToEmit > 0) {
                            uint32_t capped = (std::min)(framesToEmit, MAX_SILENCE_FRAMES_PER_TICK);
                            uint8_t zeroFrame[CANONICAL_FRAME_BYTES] = {0};
                            for (uint32_t i = 0; i < capped && !ctx->stop_requested.load(std::memory_order_acquire); ++i) {
                                integrator_on_win_audio_captured(zeroFrame, CANONICAL_FRAME_BYTES, 1);
                                g_total_silent_frames.fetch_add(CANONICAL_FRAME_SAMPLES_PER_CH, std::memory_order_relaxed);
                            }
                            silenceAccumUs -= static_cast<double>(framesToEmit) * 5000.0;
                            if (silenceAccumUs < 0.0) silenceAccumUs = 0.0;
                        }
                        break;
                    }

                    // Active WASAPI packet arrived: exit synthetic silence cleanly
                    inSyntheticSilence = false;
                    silenceAccumUs = 0.0;
                    QueryPerformanceCounter(&lastPacketQpc);
                    lastSilenceTickQpc = lastPacketQpc;

                    while (packetLength > 0 && !ctx->stop_requested.load(std::memory_order_acquire)) {
                        BYTE* pData = NULL;
                        UINT32 numFramesRead = 0;
                        DWORD flags = 0;
                        UINT64 devPos = 0;
                        UINT64 qpcPos = 0;

                        hr = ctx->pCaptureClient->GetBuffer(
                            &pData,
                            &numFramesRead,
                            &flags,
                            &devPos,
                            &qpcPos
                        );
                        if (hr == AUDCLNT_S_BUFFER_EMPTY) {
                            break;
                        }
                        if (FAILED(hr)) {
                            state = WasapiCaptureState::Reconnecting;
                            break;
                        }

                        if (flags & AUDCLNT_BUFFERFLAGS_DATA_DISCONTINUITY) {
                            g_total_discontinuities.fetch_add(1, std::memory_order_relaxed);
                        }

                        ctx->normalize_and_append(pData, numFramesRead, flags);
                        g_total_frames_read.fetch_add(numFramesRead, std::memory_order_relaxed);

                        HRESULT relHr = ctx->pCaptureClient->ReleaseBuffer(numFramesRead);
                        if (FAILED(relHr)) {
                            state = WasapiCaptureState::Reconnecting;
                            break;
                        }
                        // Guard against buggy drivers reporting packetLength > 0 while returning 0 frames from GetBuffer.
                        if (numFramesRead == 0) {
                            break;
                        }

                        (void)ctx->drain_complete_frames();

                        hr = ctx->pCaptureClient->GetNextPacketSize(&packetLength);
                        if (FAILED(hr)) {
                            state = WasapiCaptureState::Reconnecting;
                            break;
                        }
                    }
                    break;
                }

                case WasapiCaptureState::Initializing:
                case WasapiCaptureState::Stopped:
                default:
                    state = WasapiCaptureState::Stopped;
                    break;
            }
        }
    } catch (...) {
        exit_reason = 3;
    }

    ctx->is_active.store(false, std::memory_order_release);
    ctx->release_stream_resources();
    ctx->release_enumerator();
    if (ctx->hStartDoneEvent) SetEvent(ctx->hStartDoneEvent);

    // Only notify Rust for post-startup unexpected termination (`NEW-1G8-06`), carrying `capture_gen`
    // so Rust ignores stale callbacks if a newer generation has started (`NEW-1G8-03`).
    if (exit_reason != 0 &&
        ctx->initial_init_succeeded.load(std::memory_order_acquire) &&
        !ctx->stop_requested.load(std::memory_order_acquire)) {
        integrator_on_win_audio_capture_ended(ctx->capture_gen, exit_reason);
    }
    return 0;
}

/**
 * @brief Internal helper stopping and joining the active capture worker thread while holding `g_lifecycle_mtx`.
 *
 * Preconditions:
 *   Caller MUST hold `g_lifecycle_mtx` across this call. Holding the mutex across `WaitForSingleObject`
 *   guarantees that a concurrent `integrator_win_audio_capture_start` can never spawn a second worker thread
 *   before the first worker thread has exited (`NEW-1G8-03`).
 *
 * @param expected_gen If non-zero, stops the current session ONLY if its `capture_gen == expected_gen`
 *                     (preventing a stale watchdog timer from stopping a newly restarted session).
 *                     If `0`, unconditionally stops any active session.
 */
static void stop_current_session_locked(uint64_t expected_gen) {
    // Caller MUST hold `g_lifecycle_mtx` across thread join so a concurrent start() can NEVER
    // spawn Worker 2 while Worker 1 is still alive (`NEW-1G8-03`).
    if (expected_gen != 0 && g_current_session && g_current_session->capture_gen != expected_gen) {
        return;
    }
    if (expected_gen != 0 && !g_current_session) {
        return;
    }

    std::shared_ptr<CaptureSessionContext> sessionToStop = g_current_session;
    HANDLE threadToJoin = g_worker_thread;
    g_current_session.reset();
    g_worker_thread = NULL;

    if (sessionToStop) {
        sessionToStop->stop_requested.store(true, std::memory_order_release);
        if (sessionToStop->hStopEvent) {
            SetEvent(sessionToStop->hStopEvent);
        }
    }

    if (threadToJoin != NULL) {
        WaitForSingleObject(threadToJoin, 3000);
        CloseHandle(threadToJoin);
    }
}

// ============================================================================
// C FFI EXPORTS (Callable by Rust `app/src/audio/mod.rs`)
// ============================================================================

extern "C" {

/**
 * @brief Starts a new generation-fenced Windows 11 WASAPI loopback capture session.
 *
 * Algorithm:
 *   1. Acquires `g_lifecycle_mtx` and cleanly stops/joins any existing worker thread.
 *   2. Allocates a fresh `CaptureSessionContext` bound to `capture_gen` and creates its manual-reset
 *      synchronization events (`hStopEvent`, `hStartDoneEvent`, `hDeviceChangeEvent`).
 *   3. Spawns `win_audio_capture_thread_proc` and waits up to 1500 ms for `hStartDoneEvent` to confirm
 *      that WASAPI endpoint activation and `IAudioClient::Start()` succeeded on the worker thread.
 *   4. If startup fails or times out within 1500 ms, signals `stop_requested` + `hStopEvent`, joins
 *      the worker thread (up to 2000 ms), closes the thread handle, and returns `false`.
 *
 * @param capture_gen Monotonic routing generation ID assigned by `app/src/audio/mod.rs`.
 * @return `true` if the WASAPI loopback stream initialized and started capturing; `false` on error.
 */
bool integrator_win_audio_capture_start(uint64_t capture_gen) {
    std::lock_guard<std::mutex> lock(g_lifecycle_mtx);

    // Always cleanly join any previous worker before spawning a new one (`NEW-1G8-03`).
    if (g_worker_thread != NULL) {
        stop_current_session_locked(0);
    }

    auto ctx = std::make_shared<CaptureSessionContext>();
    ctx->capture_gen = capture_gen;
    ctx->hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    ctx->hStartDoneEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    ctx->hDeviceChangeEvent = CreateEventW(NULL, TRUE, FALSE, NULL); // Manual-reset cleared explicitly in init_stream
    if (!ctx->hStopEvent || !ctx->hStartDoneEvent || !ctx->hDeviceChangeEvent) {
        return false;
    }

    auto* arg = new (std::nothrow) WorkerThreadArg{ctx};
    if (!arg) {
        return false;
    }

    HANDLE hThread = CreateThread(NULL, 0, win_audio_capture_thread_proc, arg, 0, NULL);
    if (!hThread) {
        delete arg;
        return false;
    }

    DWORD waitRes = WaitForSingleObject(ctx->hStartDoneEvent, 1500);
    bool ok = (waitRes == WAIT_OBJECT_0) && ctx->initial_init_succeeded.load(std::memory_order_acquire);

    if (!ok) {
        ctx->stop_requested.store(true, std::memory_order_release);
        SetEvent(ctx->hStopEvent);
        WaitForSingleObject(hThread, 2000);
        CloseHandle(hThread);
        return false;
    }

    g_current_session = ctx;
    g_worker_thread = hThread;
    return true;
}

/**
 * @brief Unconditionally stops the active WASAPI loopback capture session and joins its worker thread.
 */
void integrator_win_audio_capture_stop() {
    std::lock_guard<std::mutex> lock(g_lifecycle_mtx);
    stop_current_session_locked(0);
}

/**
 * @brief Stops the active WASAPI loopback capture session only if its generation matches `expected_gen`.
 * @param expected_gen Target routing generation ID to stop (ignored if `0` or mismatched).
 */
void integrator_win_audio_capture_stop_if_gen(uint64_t expected_gen) {
    std::lock_guard<std::mutex> lock(g_lifecycle_mtx);
    stop_current_session_locked(expected_gen);
}

/**
 * @brief Queries whether a WASAPI loopback capture session is currently in the active `Capturing` state.
 * @return `true` if a session exists and its worker thread is actively capturing; `false` otherwise.
 */
bool integrator_win_audio_capture_is_active() {
    std::lock_guard<std::mutex> lock(g_lifecycle_mtx);
    if (!g_current_session) return false;
    return g_current_session->is_active.load(std::memory_order_acquire);
}

/**
 * @brief Returns the cumulative count of native WASAPI sample frames read since process start.
 * @return Lock-free monotonic frame count.
 */
uint64_t integrator_win_audio_capture_frames_read() {
    return g_total_frames_read.load(std::memory_order_relaxed);
}

/**
 * @brief Returns the cumulative count of canonical 48 kHz silent sample frames emitted since process start.
 * @return Lock-free monotonic silent frame count.
 */
uint64_t integrator_win_audio_capture_silent_frames() {
    return g_total_silent_frames.load(std::memory_order_relaxed);
}

/**
 * @brief Returns the cumulative count of WASAPI `AUDCLNT_BUFFERFLAGS_DATA_DISCONTINUITY` events observed.
 * @return Lock-free monotonic discontinuity count.
 */
uint64_t integrator_win_audio_capture_discontinuities() {
    return g_total_discontinuities.load(std::memory_order_relaxed);
}

// ============================================================================
// Native DSP & Silence-Holdoff Verification Helpers (Used by Windows `cargo test`)
// ============================================================================

/**
 * @brief FFI test hook exposing `soft_limit(x)` to Rust unit tests in `app/src/audio/mod.rs`.
 * @param x Input floating-point sample amplitude.
 * @return Soft-limited output sample in `[-1.0f, 1.0f]`.
 */
float integrator_win_audio_test_soft_limit(float x) {
    return soft_limit(x);
}

/**
 * @brief FFI test hook exposing `decode_pcm24_le` to Rust unit tests in `app/src/audio/mod.rs`.
 * @param b0 Least-significant byte (bits 0..7) of a 24-bit signed little-endian PCM sample.
 * @param b1 Middle byte (bits 8..15) of a 24-bit signed little-endian PCM sample.
 * @param b2 Most-significant byte (bits 16..23, including sign bit 23) of a 24-bit signed little-endian PCM sample.
 * @return Normalized floating-point sample in `[-1.0f, +1.0f)`.
 */
float integrator_win_audio_test_decode_pcm24(uint8_t b0, uint8_t b1, uint8_t b2) {
    uint8_t bytes[3] = { b0, b1, b2 };
    return decode_pcm24_le(bytes);
}

/**
 * @brief FFI test hook exposing `should_emit_synthetic_silence` to Rust unit tests in `app/src/audio/mod.rs`.
 * @param elapsed_since_packet_us Elapsed time in microseconds since the last active WASAPI packet.
 * @param default_period_us WASAPI engine default period in microseconds.
 * @param already_in_silence `true` if synthetic silence mode is already active.
 * @return `true` if synthetic silence should be emitted; `false` if still within holdoff window.
 */
bool integrator_win_audio_test_should_emit_silence(
    double elapsed_since_packet_us,
    double default_period_us,
    bool already_in_silence
) {
    return should_emit_synthetic_silence(elapsed_since_packet_us, default_period_us, already_in_silence);
}

/**
 * @brief FFI test hook verifying that full-scale unity (`1.0f`) input on every active surround channel
 *        never produces a downmixed stereo output exceeding `1.0f` after attenuation.
 *
 * @param channels Number of input channels to simulate (clamped to `[0, 16]` to prevent `WORD` overflow).
 * @param channel_mask Windows `SPEAKER_*` channel mask bitfield.
 * @param out_l Optional output pointer receiving the peak-attenuated Left channel sum.
 * @param out_r Optional output pointer receiving the peak-attenuated Right channel sum.
 * @return Maximum absolute stereo peak `max(|L|, |R|)` (guaranteed `<= 1.0f`).
 */
float integrator_win_audio_test_downmix_unity_peak(uint16_t channels, uint32_t channel_mask, float* out_l, float* out_r) {
    uint16_t safe_channels = (channels > 16) ? 16 : channels;
    WAVEFORMATEXTENSIBLE wfx{};
    wfx.Format.wFormatTag = WAVE_FORMAT_EXTENSIBLE;
    wfx.Format.nChannels = safe_channels;
    wfx.Format.nSamplesPerSec = 48000;
    wfx.Format.wBitsPerSample = 32;
    wfx.Format.nBlockAlign = static_cast<WORD>(safe_channels * 4u);
    wfx.Format.nAvgBytesPerSec = 48000u * static_cast<DWORD>(wfx.Format.nBlockAlign);
    wfx.Format.cbSize = 22;
    wfx.Samples.wValidBitsPerSample = 32;
    wfx.dwChannelMask = channel_mask;
    wfx.SubFormat = KSDATAFORMAT_SUBTYPE_IEEE_FLOAT;

    DownmixWeights dw = compute_downmix_weights(&wfx.Format);
    float l = 0.0f, r = 0.0f;
    for (int i = 0; i < dw.numChannels; ++i) {
        l += dw.weightL[i];
        r += dw.weightR[i];
    }
    l *= dw.attenuation;
    r *= dw.attenuation;
    if (out_l) *out_l = l;
    if (out_r) *out_r = r;
    return (std::max)(std::abs(l), std::abs(r));
}

} // extern "C"

#endif // _WIN32
