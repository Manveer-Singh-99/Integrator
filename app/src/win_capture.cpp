/*
 * ============================================================================
 * Integrator Dynamic Audio Routing: Windows 11 WASAPI Loopback Capture
 * ============================================================================
 *
 * Hardened Batch 1G.8-r2 implementation resolving ALL Batch 1G.7 & 1G.8-r1
 * native audit findings (`AUD-1G7-03/06/12/13/14/17/19` & `NEW-1G8-01..08`):
 * 1. Full cross-thread synchronization via `g_lifecycle_mtx` held across worker
 *    thread join (zero dual-worker overlap), generation-bound `start(gen)` /
 *    `stop_if_gen(gen)` / `capture_ended(gen, reason)` eliminating stale-thread
 *    crosstalk, and `DuplicateHandle`-owned event handle in `DefaultDeviceNotifier`
 *    (eliminating Win32 handle use-after-close on in-flight MMDevApi callbacks).
 * 2. Exception-safe RAII guards for COM, MMCSS `Pro Audio`, `timeBeginPeriod(1)`,
 *    and System32-pinned `HMODULE` handles (zero resource leaks on `catch (...)`).
 * 3. `GetDevicePeriod`-calibrated silence-entry holdoff (`>= max(2 * period, 25 ms)`)
 *    so normal 10–20 ms Windows 11 WASAPI packet cadences NEVER trigger spurious
 *    5 ms silence injection or 150% frame-rate bursts (`NEW-1G8-01`), plus exact
 *    accounting of flushed partial frames on silence entry (`NEW-1G8-07`).
 * 4. `ResetEvent(hDeviceChangeEvent)` before reconnecting (no double-reconnect),
 *    `initial_init_succeeded` guard on `capture_ended` (no spurious callback on
 *    failed startup), and continuous zero-sample feeding through
 *    `StatefulStereoResampler` on `AUDCLNT_BUFFERFLAGS_SILENT` (zero 44.1 kHz drift).
 * 5. Strict `WAVEFORMATEX` bounds/SubFormat validation (`16/24/32`-bit,
 *    `nBlockAlign >= nChannels * (wBitsPerSample / 8)`, PCM/IEEE_FLOAT only),
 *    exact dynamic peak-safe surround downmix (`<= 1.0`), UB-free 24-bit decode,
 *    and C1-smooth strictly monotonic `soft_limit()`.
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

#ifndef SPEAKER_ALL
#define SPEAKER_ALL                    0x80000000
#endif

#ifndef LOAD_LIBRARY_SEARCH_SYSTEM32
#define LOAD_LIBRARY_SEARCH_SYSTEM32   0x00000800
#endif

// Canonical 5 ms frame parameters
static const uint32_t CANONICAL_SAMPLE_RATE = 48000;
static const uint32_t CANONICAL_CHANNELS = 2;
static const uint32_t CANONICAL_FRAME_SAMPLES_PER_CH = 240; // 5 ms @ 48 kHz
static const uint32_t CANONICAL_FRAME_BYTES = 960;          // 240 * 2 * 2
static const uint32_t MAX_RECONNECT_ATTEMPTS = 10;
static const uint32_t MAX_SILENCE_FRAMES_PER_TICK = 8;
static const uint32_t MIN_VALID_SAMPLE_RATE = 8000;
static const uint32_t MAX_VALID_SAMPLE_RATE = 384000;
static const double MIN_SILENCE_HOLDOFF_US = 25000.0;       // 25 ms (> 2x standard 10 ms WASAPI period)

// C FFI callbacks into Rust
extern "C" void integrator_on_win_audio_captured(const uint8_t* data, uint32_t len, int is_silent);
extern "C" void integrator_on_win_audio_capture_ended(uint64_t capture_gen, int reason_code);

// Dynamic loading for Avrt.dll and Winmm.dll (System32-pinned)
typedef HANDLE (WINAPI *pfnAvSetMmThreadCharacteristicsW)(LPCWSTR, LPDWORD);
typedef BOOL (WINAPI *pfnAvRevertMmThreadCharacteristics)(HANDLE);
typedef UINT (WINAPI *pfnTimeBeginPeriod)(UINT);
typedef UINT (WINAPI *pfnTimeEndPeriod)(UINT);

// Cumulative telemetry counters (atomic, lock-free reads)
static std::atomic<uint64_t> g_total_frames_read{0};
static std::atomic<uint64_t> g_total_silent_frames{0};
static std::atomic<uint64_t> g_total_discontinuities{0};

// ============================================================================
// Exception-Safe RAII Resource Guards (`NEW-1G8-04`)
// ============================================================================

struct ComApartmentGuard {
    bool initialized = false;
    explicit ComApartmentGuard(DWORD coInit) {
        HRESULT hr = CoInitializeEx(NULL, coInit);
        initialized = SUCCEEDED(hr);
    }
    ~ComApartmentGuard() {
        if (initialized) {
            CoUninitialize();
        }
    }
    ComApartmentGuard(const ComApartmentGuard&) = delete;
    ComApartmentGuard& operator=(const ComApartmentGuard&) = delete;
};

struct SystemModuleGuard {
    HMODULE handle = NULL;
    explicit SystemModuleGuard(LPCWSTR dllName) {
        handle = LoadLibraryExW(dllName, NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    }
    ~SystemModuleGuard() {
        if (handle) {
            FreeLibrary(handle);
        }
    }
    SystemModuleGuard(const SystemModuleGuard&) = delete;
    SystemModuleGuard& operator=(const SystemModuleGuard&) = delete;
};

struct MmcssTaskGuard {
    HANDLE task = NULL;
    pfnAvRevertMmThreadCharacteristics revertFn = NULL;
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
    ~MmcssTaskGuard() {
        if (task && revertFn) {
            revertFn(task);
        }
    }
    MmcssTaskGuard(const MmcssTaskGuard&) = delete;
    MmcssTaskGuard& operator=(const MmcssTaskGuard&) = delete;
};

struct TimerResolutionGuard {
    UINT periodMs = 0;
    pfnTimeEndPeriod endFn = NULL;
    bool active = false;
    TimerResolutionGuard(HMODULE hWinmm, UINT ms) : periodMs(ms) {
        if (!hWinmm) return;
        auto beginFn = reinterpret_cast<pfnTimeBeginPeriod>(GetProcAddress(hWinmm, "timeBeginPeriod"));
        endFn = reinterpret_cast<pfnTimeEndPeriod>(GetProcAddress(hWinmm, "timeEndPeriod"));
        if (beginFn && endFn && beginFn(ms) == 0) {
            active = true;
        }
    }
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

// Validates WASAPI mix format bounds and supported encodings (PCM / IEEE_FLOAT, 16/24/32-bit; `NEW-1G8-08`).
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
    if (pwfx->wFormatTag == WAVE_FORMAT_EXTENSIBLE && pwfx->cbSize >= 22) {
        const WAVEFORMATEXTENSIBLE* pExt = reinterpret_cast<const WAVEFORMATEXTENSIBLE*>(pwfx);
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

// Pure helper deciding silence-entry holdoff (`NEW-1G8-01`): returns true ONLY once elapsed silence
// exceeds `max(2 * default_period_us, 25000 us)` (or immediately once already in silence state).
static inline double compute_silence_holdoff_us(double default_period_us) {
    double doubled = (default_period_us > 0.0) ? (default_period_us * 2.0) : MIN_SILENCE_HOLDOFF_US;
    return (std::max)(doubled, MIN_SILENCE_HOLDOFF_US);
}

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

struct DownmixWeights {
    int numChannels = 0;
    float weightL[16] = {0.0f};
    float weightR[16] = {0.0f};
    float attenuation = 1.0f;
};

// Resolves per-channel stereo downmix weights and exact peak-safe normalization (`AUD-1G7-06`, `AUD-1G7-14`).
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

    const float INV_SQRT2 = 0.70710678f;
    bool hasSide = (mask & (SPEAKER_SIDE_LEFT | SPEAKER_SIDE_RIGHT)) != 0;

    if (ch == 1) {
        dw.weightL[0] = 1.0f;
        dw.weightR[0] = 1.0f;
        dw.attenuation = 1.0f;
        return dw;
    }

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

// C1-smooth, strictly monotonic soft-knee limiter with zero step discontinuity (`AUD-1G7-06`).
static inline float soft_limit(float x) {
    if (!std::isfinite(x)) return 0.0f;
    float abs_x = std::abs(x);
    if (abs_x <= 0.8f) return x;
    float sign = (x >= 0.0f) ? 1.0f : -1.0f;
    return sign * (0.8f + 0.2f * std::tanh((abs_x - 0.8f) / 0.2f));
}

// UB-free, strict-aliasing-safe 24-bit little-endian signed integer decoder (`AUD-1G7-17`).
static inline float decode_pcm24_le(const uint8_t* sPtr) {
    uint32_t u = static_cast<uint32_t>(sPtr[0])
               | (static_cast<uint32_t>(sPtr[1]) << 8)
               | (static_cast<uint32_t>(sPtr[2]) << 16);
    if (u & 0x00800000u) {
        u |= 0xFF000000u;
    }
    int32_t val = static_cast<int32_t>(u);
    return static_cast<float>(val) / 8388608.0f;
}

static inline float read_channel_float(
    const uint8_t* pData,
    UINT32 frameIdx,
    int channelIdx,
    int totalChannels,
    WORD srcBits,
    bool isFloat,
    size_t blockAlign
) {
    if (channelIdx < 0 || channelIdx >= totalChannels) return 0.0f;
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

// 2-pole Butterworth stereo biquad low-pass filter for anti-aliased downsampling (>48 kHz -> 48 kHz).
struct StereoBiquadLpf {
    bool enabled = false;
    float b0 = 1.0f, b1 = 0.0f, b2 = 0.0f;
    float a1 = 0.0f, a2 = 0.0f;
    float z1L = 0.0f, z2L = 0.0f;
    float z1R = 0.0f, z2R = 0.0f;

    void configure(uint32_t srcRate) {
        reset();
        if (srcRate <= CANONICAL_SAMPLE_RATE) {
            enabled = false;
            return;
        }
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

    void reset() {
        z1L = z2L = z1R = z2R = 0.0f;
    }

    inline void process(float& l, float& r) {
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

// Stateful cross-packet fractional-phase stereo resampler (`AUD-1G7-13`, `NEW-1G8-07`).
struct StatefulStereoResampler {
    uint32_t srcRate = CANONICAL_SAMPLE_RATE;
    double step = 1.0;
    double phase = 0.0;
    float prevL = 0.0f;
    float prevR = 0.0f;
    bool hasPrev = false;
    StereoBiquadLpf lpf;

    void configure(uint32_t rate) {
        srcRate = (rate >= MIN_VALID_SAMPLE_RATE && rate <= MAX_VALID_SAMPLE_RATE) ? rate : CANONICAL_SAMPLE_RATE;
        step = static_cast<double>(srcRate) / static_cast<double>(CANONICAL_SAMPLE_RATE);
        phase = 0.0;
        prevL = 0.0f;
        prevR = 0.0f;
        hasPrev = false;
        lpf.configure(srcRate);
    }

    void append_pcm16(std::vector<uint8_t>& accumulator, float l, float r) {
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

    void process_stereo_block(
        const float* stereoPairs,
        UINT32 numFrames,
        std::vector<uint8_t>& accumulator
    ) {
        if (numFrames == 0) return;

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

class DefaultDeviceNotifier final : public IMMNotificationClient {
public:
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

    ~DefaultDeviceNotifier() {
        if (m_ownedEvent) {
            CloseHandle(m_ownedEvent);
            m_ownedEvent = NULL;
        }
    }

    ULONG STDMETHODCALLTYPE AddRef() override {
        return static_cast<ULONG>(m_refCount.fetch_add(1) + 1);
    }

    ULONG STDMETHODCALLTYPE Release() override {
        ULONG r = static_cast<ULONG>(m_refCount.fetch_sub(1) - 1);
        if (r == 0) {
            delete this;
        }
        return r;
    }

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

    bool consume_changed() {
        return m_deviceChanged.exchange(false, std::memory_order_acq_rel);
    }

private:
    std::atomic<LONG> m_refCount;
    HANDLE m_ownedEvent;
    std::atomic<bool> m_deviceChanged;
};

// ============================================================================
// Per-Session Worker Context (`AUD-1G7-03`)
// ============================================================================

enum class WasapiCaptureState {
    Initializing,
    Capturing,
    Reconnecting,
    Stopped
};

struct CaptureSessionContext {
    uint64_t capture_gen = 0;
    std::atomic<bool> stop_requested{false};
    std::atomic<bool> is_active{false};
    std::atomic<bool> initial_init_succeeded{false};

    // Lifecycle events owned by this session context (closed only after worker exits)
    HANDLE hStopEvent = NULL;
    HANDLE hStartDoneEvent = NULL;
    HANDLE hDeviceChangeEvent = NULL;

    // Worker-thread-private COM & event handles
    HANDLE hCaptureEvent = NULL;
    IMMDeviceEnumerator* pEnumerator = NULL;
    DefaultDeviceNotifier* pNotifier = NULL;
    IMMDevice* pDevice = NULL;
    IAudioClient* pAudioClient = NULL;
    IAudioCaptureClient* pCaptureClient = NULL;
    WAVEFORMATEX* pMixFormat = NULL;
    bool mixFormatIsFloat = false;
    double defaultPeriodUs = 10000.0; // Default 10 ms; updated from GetDevicePeriod()

    // Worker-thread-private preallocated DSP buffers
    DownmixWeights downmix;
    StatefulStereoResampler resampler;
    std::vector<float> stereoScratch;
    std::vector<uint8_t> accumulator;

    ~CaptureSessionContext() {
        if (hStopEvent) CloseHandle(hStopEvent);
        if (hStartDoneEvent) CloseHandle(hStartDoneEvent);
        if (hDeviceChangeEvent) CloseHandle(hDeviceChangeEvent);
    }

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

    bool init_stream(bool recreate_enumerator) {
        release_stream_resources();
        if (recreate_enumerator) {
            release_enumerator();
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

        // 500,000 reference time units = 50 ms shared buffer
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

        hr = pAudioClient->Start();
        if (FAILED(hr)) {
            release_stream_resources();
            return false;
        }

        return true;
    }

    void normalize_and_append(const BYTE* pData, UINT32 numFrames, DWORD flags) {
        if (numFrames == 0 || !pMixFormat) return;
        const int srcChannels = static_cast<int>(pMixFormat->nChannels);
        if (srcChannels == 0 || pMixFormat->nBlockAlign == 0) return;

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
                    rawBytes, f, c, srcChannels, pMixFormat->wBitsPerSample, mixFormatIsFloat, pMixFormat->nBlockAlign
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

    // Flushes any partial accumulator residue padded with zeros; returns number of 5 ms frames emitted (`NEW-1G8-07`).
    uint32_t flush_partial_accumulator_to_silence() {
        if (accumulator.empty()) return 0;
        size_t rem = accumulator.size() % CANONICAL_FRAME_BYTES;
        if (rem != 0) {
            accumulator.insert(accumulator.end(), CANONICAL_FRAME_BYTES - rem, 0);
        }
        return drain_complete_frames();
    }
};

struct WorkerThreadArg {
    std::shared_ptr<CaptureSessionContext> ctx;
};

static std::mutex g_lifecycle_mtx;
static std::shared_ptr<CaptureSessionContext> g_current_session;
static HANDLE g_worker_thread = NULL;

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

        if (ctx->init_stream(false)) {
            state = WasapiCaptureState::Capturing;
            ctx->is_active.store(true, std::memory_order_release);
            ctx->initial_init_succeeded.store(true, std::memory_order_release);
            if (ctx->hStartDoneEvent) SetEvent(ctx->hStartDoneEvent);
            QueryPerformanceCounter(&lastPacketQpc);
            lastSilenceTickQpc = lastPacketQpc;
        } else {
            ctx->initial_init_succeeded.store(false, std::memory_order_release);
            if (ctx->hStartDoneEvent) SetEvent(ctx->hStartDoneEvent);
            state = WasapiCaptureState::Stopped;
            exit_reason = 1;
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

                    if (ctx->init_stream(true)) {
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
                    if (!ctx->pCaptureClient || !ctx->hCaptureEvent) {
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
                            // Flush any partial accumulator residue once upon true silence entry (`NEW-1G8-07`)
                            uint32_t flushed = ctx->flush_partial_accumulator_to_silence();
                            if (flushed == 0) {
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
// C FFI EXPORTS (Callable by Rust)
// ============================================================================

extern "C" {

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

void integrator_win_audio_capture_stop() {
    std::lock_guard<std::mutex> lock(g_lifecycle_mtx);
    stop_current_session_locked(0);
}

void integrator_win_audio_capture_stop_if_gen(uint64_t expected_gen) {
    std::lock_guard<std::mutex> lock(g_lifecycle_mtx);
    stop_current_session_locked(expected_gen);
}

bool integrator_win_audio_capture_is_active() {
    std::lock_guard<std::mutex> lock(g_lifecycle_mtx);
    if (!g_current_session) return false;
    return g_current_session->is_active.load(std::memory_order_acquire);
}

uint64_t integrator_win_audio_capture_frames_read() {
    return g_total_frames_read.load(std::memory_order_relaxed);
}

uint64_t integrator_win_audio_capture_silent_frames() {
    return g_total_silent_frames.load(std::memory_order_relaxed);
}

uint64_t integrator_win_audio_capture_discontinuities() {
    return g_total_discontinuities.load(std::memory_order_relaxed);
}

// ============================================================================
// Native DSP & Silence-Holdoff Verification Helpers (Used by Windows `cargo test`)
// ============================================================================

float integrator_win_audio_test_soft_limit(float x) {
    return soft_limit(x);
}

float integrator_win_audio_test_decode_pcm24(uint8_t b0, uint8_t b1, uint8_t b2) {
    uint8_t bytes[3] = { b0, b1, b2 };
    return decode_pcm24_le(bytes);
}

bool integrator_win_audio_test_should_emit_silence(
    double elapsed_since_packet_us,
    double default_period_us,
    bool already_in_silence
) {
    return should_emit_synthetic_silence(elapsed_since_packet_us, default_period_us, already_in_silence);
}

float integrator_win_audio_test_downmix_unity_peak(uint16_t channels, uint32_t channel_mask, float* out_l, float* out_r) {
    WAVEFORMATEXTENSIBLE wfx{};
    wfx.Format.wFormatTag = WAVE_FORMAT_EXTENSIBLE;
    wfx.Format.nChannels = channels;
    wfx.Format.nSamplesPerSec = 48000;
    wfx.Format.wBitsPerSample = 32;
    wfx.Format.nBlockAlign = channels * 4;
    wfx.Format.nAvgBytesPerSec = 48000 * wfx.Format.nBlockAlign;
    wfx.Format.cbSize = 22;
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
