/*
 * ============================================================================
 * Integrator CoreAudio HAL Audio Server Plugin Driver (`IntegratorAudioDriver.c`)
 * ============================================================================
 *
 * 1. MODULE PURPOSE & ARCHITECTURAL SCOPE
 * ----------------------------------------------------------------------------
 * Implements a user-space macOS CoreAudio `AudioServerPlugIn` virtual speaker
 * device named **"Windows PC (Integrator)"** (`com.manveersingh.integrator.audio.sink`)
 * loaded into Apple's `coreaudiod` daemon from `/Library/Audio/Plug-Ins/HAL/`.
 *
 * When a user selects **"Windows PC (Integrator)"** in macOS Control Center,
 * Menu Bar Sound, or System Settings, CoreAudio mixes all macOS application
 * audio as interleaved 48 kHz 32-bit floating-point stereo (`2 ch`) and delivers
 * it to `Driver_DoIOOperation` (`kAudioServerPlugInIOOperationWriteMix`). This
 * driver applies hardware scalar volume/mute controls, converts finite floats
 * cleanly to canonical 16-bit signed PCM (`4` bytes/frame), and writes them into
 * the POSIX shared-memory SPSC ring buffer defined by `integrator_audio_shm.h`.
 *
 * 2. ARCHITECTURAL LINKAGES & CROSS-DEVICE FLOW
 * ----------------------------------------------------------------------------
 * - Upstream Host (`coreaudiod`): Loads the bundle via factory entrypoint
 *   `IntegratorAudioDriver_Create` (`CFPlugInFactories` UUID `8A7B5492-...`) and
 *   dispatches HAL property queries, client I/O lifecycle transitions, and real-time
 *   mix callbacks through `AudioServerPlugInDriverInterface`.
 * - Downstream Consumer (`app/src/audio/mod.rs::start_mac_shm_audio_capture`):
 *   Maps `/com.manveersingh.integrator.audio.sink.shm` (`131,128` bytes), polls for
 *   960-byte (5 ms) S16LE stereo chunks, detects silence, and streams frames over
 *   encrypted `IUA2` UDP (`PORT 58284`) to Windows 11 (`audio_windows` / WASAPI).
 * - Packaging & Installer: Compiled universal (`arm64 + x86_64`) via
 *   `macos/audio-driver/build-audio-driver.sh`, bundled inside `Integrator.app`,
 *   and installed via `install-audio-driver.sh`.
 *
 * 3. THREADING & CONCURRENCY MODEL
 * ----------------------------------------------------------------------------
 * - Property/Lifecycle Threads (`coreaudiod` control plane): Execute `Initialize`,
 *   `HasProperty`, `GetPropertyData`, `SetPropertyData`, `StartIO`, and `StopIO`.
 *   `g_shm_init_lock` protects lazy shared-memory opening/mapping during
 *   `Initialize` and `StartIO`. Multiple concurrent CoreAudio clients are
 *   reference-counted via `_Atomic uint32_t g_io_client_count`.
 * - Real-Time Audio IO Thread (`Driver_DoIOOperation`, `Driver_GetZeroTimeStamp`):
 *   Strictly zero locks, zero heap allocations, and zero blocking syscalls (`shm_open`/
 *   `mmap` never run inside `DoIOOperation`). Uses C11 `_Atomic` acquire/release
 *   barriers for `g_shm`, `g_volume`, `g_mute`, `write_pos`, and `read_pos`.
 *
 * 4. SECURITY & SAFETY INVARIANTS
 * ----------------------------------------------------------------------------
 * - Cross-User POSIX SHM Permissions: `coreaudiod` runs as `_coreaudiod` with
 *   restricted umask while `Integrator.app` runs as the desktop user; `ensure_shm_mapped()`
 *   explicitly applies `fchmod(fd, 0666)` and validates `fstat` size before `mmap`.
 * - Publication Ordering: `magic = INTEGRATOR_AUDIO_SHM_MAGIC` is written LAST
 *   after `atomic_thread_fence(memory_order_release)` so the Rust consumer never
 *   observes partially initialized header fields.
 * - Buffer & Ring Bounds Validation: All `GetPropertyData` writes verify
 *   `inDataSize` (`kAudioHardwareBadPropertySizeError`), `translateUID` checks
 *   `CFStringGetTypeID()`, and `DoIOOperation` masks `curr_write`/`curr_read`
 *   modulo `INTEGRATOR_AUDIO_RING_BUFFER_BYTES` and clamps oversized frames + NaN floats.
 * ============================================================================
 */

#include <CoreAudio/AudioServerPlugIn.h>
#include <CoreAudio/AudioHardwareBase.h>
#include <CoreFoundation/CoreFoundation.h>
#include <fcntl.h>
#include <mach/mach_time.h>
#include <math.h>
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "integrator_audio_shm.h"

/* ----------------------------------------------------------------------------------------------
 * UUID & CoreAudio HAL Object Identifiers
 * ---------------------------------------------------------------------------------------------- */

/** Plug-in factory CFUUID bytes matching `Info.plist` (`8A7B5492-9C4F-4E82-9B7E-7F89B4896201`). */
#define kFactoryUUID_Bytes 0x8A, 0x7B, 0x54, 0x92, 0x9C, 0x4F, 0x4E, 0x82, 0x9B, 0x7E, 0x7F, 0x89, 0xB4, 0x89, 0x62, 0x01

/** CoreAudio object ID for the top-level HAL plug-in container (`1` per Apple HAL convention). */
#define kObjectID_PlugIn 1
/** CoreAudio object ID for the virtual output audio device ("Windows PC (Integrator)"). */
#define kObjectID_Device 2
/** CoreAudio object ID for the single 2-channel 48 kHz output audio stream. */
#define kObjectID_Stream 3
/** CoreAudio object ID for the virtual device scalar volume control. */
#define kObjectID_Volume 4
/** CoreAudio object ID for the virtual device boolean mute control. */
#define kObjectID_Mute   5

/** Persistent HAL device UID serialized by macOS Audio MIDI Setup. */
#define kDevice_UID      CFSTR("com.manveersingh.integrator.audio.sink")
/** Model identifier string exposed in HAL device metadata. */
#define kDevice_ModelUID CFSTR("com.manveersingh.integrator.audio.sink.model")
/** User-visible device name displayed in Control Center -> Sound. */
#define kDevice_Name     CFSTR("Windows PC (Integrator)")
/** Manufacturer string reported to CoreAudio HAL clients. */
#define kManufacturer    CFSTR("Integrator")

/** Nominal stereo channel count for `WriteMix` input buffers. */
#define kStereoChannels 2u
/** Minimum decibel floor matching linear silence clamp (`-96 dB`). */
#define kMinVolumeDb    (-96.0f)

/* ----------------------------------------------------------------------------------------------
 * Driver Singleton State & POSIX Shared-Memory Handles
 * ---------------------------------------------------------------------------------------------- */

/** COM-style HAL driver instance backing `AudioServerPlugInDriverRef`. */
typedef struct {
    /** Pointer to static HAL vtable `g_driver_interface`. */
    AudioServerPlugInDriverInterface* mInterface;
    /** Optional factory UUID assigned by host (`NULL` for static singleton). */
    CFUUIDRef                         mFactoryUUID;
    /** Atomic COM reference count (`AddRef` / `Release`). */
    _Atomic UInt32                    mRefCount;
    /** Host callback table supplied during `Driver_Initialize`. */
    AudioServerPlugInHostRef          mHost;
} IntegratorAudioDriver;

static AudioServerPlugInDriverInterface g_driver_interface;
static IntegratorAudioDriver g_driver = {
    &g_driver_interface,
    NULL,
    1,
    NULL
};
static AudioServerPlugInDriverRef g_driver_ref = (AudioServerPlugInDriverRef)&g_driver;

/** Non-zero while at least one CoreAudio client has active IO started (`g_io_client_count > 0`). */
static _Atomic uint32_t g_device_running = 0;
/** Number of active CoreAudio clients currently bracketed between `StartIO` and `StopIO`. */
static _Atomic uint32_t g_io_client_count = 0;
/** Normalized linear scalar output gain `[0.0, 1.0]` controlled by macOS volume slider. */
static _Atomic float g_volume = 1.0f;
/** Boolean mute state (`0` = unmuted, `1` = muted) controlled by macOS Sound menu. */
static _Atomic UInt32 g_mute = 0;
/** Fixed device sample rate in Hertz (`48,000 Hz`). */
static const Float64 kSampleRate = 48000.0;
/** CoreAudio HAL zero-timestamp sample period (`16,384` frames ≈ `341.3 ms` @ 48 kHz). */
static const UInt32 kZeroTimeStampPeriod = 16384;

/** Non-RT mutex serializing lazy POSIX shared-memory opening and mapping. */
static pthread_mutex_t g_shm_init_lock = PTHREAD_MUTEX_INITIALIZER;
/** POSIX `shm_open` descriptor (`-1` until opened). */
static int g_shm_fd = -1;
/** Mapped shared-memory header published with release semantics for lock-free RT reads. */
static _Atomic(IntegratorAudioShmHeader*) g_shm = NULL;

/** Mach monotonic tick-to-nanosecond conversion ratio captured in `Driver_Initialize`. */
static mach_timebase_info_data_t g_timebase = { 1, 1 };
/** Mach absolute host timestamp captured when `StartIO` transitions `0 -> 1`. */
static _Atomic uint64_t g_timeline_start_host_time = 0;
/** Timeline clock-discontinuity seed incremented on every `0 -> 1` `StartIO` transition. */
static _Atomic uint64_t g_timeline_seed = 1;

/* ----------------------------------------------------------------------------------------------
 * Helper Functions
 * ---------------------------------------------------------------------------------------------- */

/**
 * Opens, permissions, sizes, initializes, and `mmap`s the POSIX shared-memory SPSC ring buffer.
 *
 * Must only execute on control threads (`Driver_Initialize` / `Driver_StartIO`), never inside
 * the real-time `Driver_DoIOOperation` callback. Applies `fchmod(..., 0666)` so desktop
 * user processes (`Integrator.app`) can open the segment created by `_coreaudiod` with `O_RDWR`,
 * validates the backing size via `fstat`, and orders `g_shm->magic` after a release fence.
 */
static void ensure_shm_mapped(void) {
    if (atomic_load_explicit(&g_shm, memory_order_acquire) != NULL) {
        return;
    }

    pthread_mutex_lock(&g_shm_init_lock);
    if (atomic_load_explicit(&g_shm, memory_order_relaxed) != NULL) {
        pthread_mutex_unlock(&g_shm_init_lock);
        return;
    }

    int fd = shm_open(INTEGRATOR_AUDIO_SHM_NAME, O_RDWR | O_CREAT, 0666);
    if (fd < 0) {
        pthread_mutex_unlock(&g_shm_init_lock);
        return;
    }

    /* Bypass daemon umask restrictions so unprivileged desktop Integrator process can R/W read_pos. */
    (void)fchmod(fd, 0666);

    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < (off_t)sizeof(IntegratorAudioShmHeader)) {
        if (ftruncate(fd, (off_t)sizeof(IntegratorAudioShmHeader)) != 0) {
            close(fd);
            pthread_mutex_unlock(&g_shm_init_lock);
            return;
        }
    }

    void* ptr = mmap(
        NULL,
        sizeof(IntegratorAudioShmHeader),
        PROT_READ | PROT_WRITE,
        MAP_SHARED,
        fd,
        0
    );
    if (ptr == MAP_FAILED) {
        close(fd);
        pthread_mutex_unlock(&g_shm_init_lock);
        return;
    }

    IntegratorAudioShmHeader* mapped = (IntegratorAudioShmHeader*)ptr;
    if (mapped->magic != INTEGRATOR_AUDIO_SHM_MAGIC) {
        memset(mapped, 0, sizeof(IntegratorAudioShmHeader));
        mapped->version = 1;
        atomic_store_explicit(&mapped->format, 0u, memory_order_relaxed);      /* Int16 PCM 48kHz */
        atomic_store_explicit(&mapped->sample_rate, 48000u, memory_order_relaxed);
        atomic_store_explicit(&mapped->channels, kStereoChannels, memory_order_relaxed);
        /* Publish initialized header metadata before making magic visible to external processes. */
        atomic_thread_fence(memory_order_release);
        mapped->magic = INTEGRATOR_AUDIO_SHM_MAGIC;
    }

    g_shm_fd = fd;
    atomic_store_explicit(&g_shm, mapped, memory_order_release);
    pthread_mutex_unlock(&g_shm_init_lock);
}

/**
 * Converts a normalized 32-bit float PCM sample (`[-1.0, +1.0]`) to clamped signed 16-bit PCM.
 *
 * Non-finite inputs (`NaN` / `+/-Inf`) return digital silence (`0`) rather than invoking UB.
 */
static inline int16_t float_to_int16(float f) {
    if (!isfinite(f)) return 0;
    if (f > 1.0f) f = 1.0f;
    else if (f < -1.0f) f = -1.0f;
    return (int16_t)(f * 32767.0f);
}

/* ----------------------------------------------------------------------------------------------
 * COM IUnknown Implementation
 * ---------------------------------------------------------------------------------------------- */

/** Resolves `IUnknown` or `kAudioServerPlugInDriverInterfaceUUID` onto the driver singleton. */
static HRESULT Driver_QueryInterface(void* inDriver, REFIID inUUID, LPVOID* outInterface) {
    (void)inDriver;
    if (!outInterface) return kAudioHardwareIllegalOperationError;
    *outInterface = NULL;

    CFUUIDRef req = CFUUIDCreateFromUUIDBytes(kCFAllocatorDefault, inUUID);
    if (!req) return kAudioHardwareIllegalOperationError;

    if (CFEqual(req, IUnknownUUID) || CFEqual(req, kAudioServerPlugInDriverInterfaceUUID)) {
        atomic_fetch_add_explicit(&g_driver.mRefCount, 1u, memory_order_relaxed);
        *outInterface = g_driver_ref;
        CFRelease(req);
        return 0;
    }

    CFRelease(req);
    return 0x80004002L; /* E_NOINTERFACE */
}

/** Atomically increments the COM driver singleton reference count. */
static ULONG Driver_AddRef(void* inDriver) {
    (void)inDriver;
    return atomic_fetch_add_explicit(&g_driver.mRefCount, 1u, memory_order_relaxed) + 1u;
}

/** Atomically decrements the COM driver singleton reference count (clamped at 0). */
static ULONG Driver_Release(void* inDriver) {
    (void)inDriver;
    UInt32 cur = atomic_load_explicit(&g_driver.mRefCount, memory_order_relaxed);
    while (cur > 0u) {
        if (atomic_compare_exchange_weak_explicit(
                &g_driver.mRefCount,
                &cur,
                cur - 1u,
                memory_order_relaxed,
                memory_order_relaxed)) {
            return cur - 1u;
        }
    }
    return 0u;
}

/* ----------------------------------------------------------------------------------------------
 * Basic HAL Plug-In Operations
 * ---------------------------------------------------------------------------------------------- */

/** Stores host interface, queries Mach timebase scaling, and pre-maps POSIX shared memory. */
static OSStatus Driver_Initialize(AudioServerPlugInDriverRef inDriver, AudioServerPlugInHostRef inHost) {
    (void)inDriver;
    g_driver.mHost = inHost;
    mach_timebase_info_data_t tb = { 0, 0 };
    if (mach_timebase_info(&tb) == KERN_SUCCESS && tb.denom != 0u) {
        g_timebase = tb;
    }
    ensure_shm_mapped();
    return kAudioHardwareNoError;
}

/** Dynamic device creation is unsupported; device list is statically managed. */
static OSStatus Driver_CreateDevice(AudioServerPlugInDriverRef inDriver, CFDictionaryRef inDescription, const AudioServerPlugInClientInfo* inClientInfo, AudioObjectID* outDeviceObjectID) {
    return kAudioHardwareUnsupportedOperationError;
}

/** Dynamic device destruction is unsupported. */
static OSStatus Driver_DestroyDevice(AudioServerPlugInDriverRef inDriver, AudioObjectID inDeviceObjectID) {
    return kAudioHardwareUnsupportedOperationError;
}

/** Accepts new CoreAudio HAL client registrations cleanly. */
static OSStatus Driver_AddDeviceClient(AudioServerPlugInDriverRef inDriver, AudioObjectID inDeviceObjectID, const AudioServerPlugInClientInfo* inClientInfo) {
    return kAudioHardwareNoError;
}

/** Handles CoreAudio HAL client teardowns cleanly. */
static OSStatus Driver_RemoveDeviceClient(AudioServerPlugInDriverRef inDriver, AudioObjectID inDeviceObjectID, const AudioServerPlugInClientInfo* inClientInfo) {
    return kAudioHardwareNoError;
}

/** No asynchronous format configuration transitions are required (fixed 48 kHz stereo). */
static OSStatus Driver_PerformDeviceConfigurationChange(AudioServerPlugInDriverRef inDriver, AudioObjectID inDeviceObjectID, UInt64 inChangeAction, void* inChangeInfo) {
    return kAudioHardwareNoError;
}

/** Handles aborted configuration changes as a clean no-op. */
static OSStatus Driver_AbortDeviceConfigurationChange(AudioServerPlugInDriverRef inDriver, AudioObjectID inDeviceObjectID, UInt64 inChangeAction, void* inChangeInfo) {
    return kAudioHardwareNoError;
}

/* ----------------------------------------------------------------------------------------------
 * HAL Property Query & Mutation Implementation
 * ---------------------------------------------------------------------------------------------- */

/** Returns `true` when `inAddress->mSelector` is implemented on `inObjectID`. */
static Boolean Driver_HasProperty(AudioServerPlugInDriverRef inDriver, AudioObjectID inObjectID, pid_t inClientProcessID, const AudioObjectPropertyAddress* inAddress) {
    (void)inDriver;
    (void)inClientProcessID;
    if (!inAddress) return false;

    switch (inObjectID) {
        case kObjectID_PlugIn:
            switch (inAddress->mSelector) {
                case kAudioObjectPropertyBaseClass:
                case kAudioObjectPropertyClass:
                case kAudioObjectPropertyOwner:
                case kAudioObjectPropertyManufacturer:
                case kAudioPlugInPropertyDeviceList:
                case kAudioPlugInPropertyTranslateUIDToDevice:
                case kAudioPlugInPropertyResourceBundle:
                    return true;
            }
            break;

        case kObjectID_Device:
            switch (inAddress->mSelector) {
                case kAudioObjectPropertyBaseClass:
                case kAudioObjectPropertyClass:
                case kAudioObjectPropertyOwner:
                case kAudioObjectPropertyName:
                case kAudioObjectPropertyManufacturer:
                case kAudioDevicePropertyDeviceUID:
                case kAudioDevicePropertyModelUID:
                case kAudioDevicePropertyTransportType:
                case kAudioDevicePropertyRelatedDevices:
                case kAudioDevicePropertyClockDomain:
                case kAudioDevicePropertyDeviceIsAlive:
                case kAudioDevicePropertyDeviceIsRunning:
                case kAudioDevicePropertyDeviceCanBeDefaultDevice:
                case kAudioDevicePropertyDeviceCanBeDefaultSystemDevice:
                case kAudioDevicePropertyLatency:
                case kAudioDevicePropertySafetyOffset:
                case kAudioDevicePropertyNominalSampleRate:
                case kAudioDevicePropertyAvailableNominalSampleRates:
                case kAudioDevicePropertyZeroTimeStampPeriod:
                case kAudioDevicePropertyStreams:
                case kAudioObjectPropertyControlList:
                    return true;
            }
            break;

        case kObjectID_Stream:
            switch (inAddress->mSelector) {
                case kAudioObjectPropertyBaseClass:
                case kAudioObjectPropertyClass:
                case kAudioObjectPropertyOwner:
                case kAudioStreamPropertyDirection:
                case kAudioStreamPropertyTerminalType:
                case kAudioStreamPropertyStartingChannel:
                case kAudioStreamPropertyLatency:
                case kAudioStreamPropertyVirtualFormat:
                case kAudioStreamPropertyPhysicalFormat:
                case kAudioStreamPropertyAvailableVirtualFormats:
                case kAudioStreamPropertyAvailablePhysicalFormats:
                    return true;
            }
            break;

        case kObjectID_Volume:
            switch (inAddress->mSelector) {
                case kAudioObjectPropertyBaseClass:
                case kAudioObjectPropertyClass:
                case kAudioObjectPropertyOwner:
                case kAudioControlPropertyScope:
                case kAudioControlPropertyElement:
                case kAudioLevelControlPropertyScalarValue:
                case kAudioLevelControlPropertyDecibelValue:
                case kAudioLevelControlPropertyDecibelRange:
                    return true;
            }
            break;

        case kObjectID_Mute:
            switch (inAddress->mSelector) {
                case kAudioObjectPropertyBaseClass:
                case kAudioObjectPropertyClass:
                case kAudioObjectPropertyOwner:
                case kAudioControlPropertyScope:
                case kAudioControlPropertyElement:
                case kAudioBooleanControlPropertyValue:
                    return true;
            }
            break;
    }
    return false;
}

/** Reports whether the specified property selector accepts client `SetPropertyData` mutations. */
static OSStatus Driver_IsPropertySettable(AudioServerPlugInDriverRef inDriver, AudioObjectID inObjectID, pid_t inClientProcessID, const AudioObjectPropertyAddress* inAddress, Boolean* outIsSettable) {
    (void)inDriver;
    (void)inClientProcessID;
    if (!outIsSettable || !inAddress) return kAudioHardwareIllegalOperationError;
    *outIsSettable = false;

    if (inObjectID == kObjectID_Volume && inAddress->mSelector == kAudioLevelControlPropertyScalarValue) {
        *outIsSettable = true;
    } else if (inObjectID == kObjectID_Mute && inAddress->mSelector == kAudioBooleanControlPropertyValue) {
        *outIsSettable = true;
    }
    return kAudioHardwareNoError;
}

/** Reports exact byte capacity required by `Driver_GetPropertyData` for `inAddress`. */
static OSStatus Driver_GetPropertyDataSize(AudioServerPlugInDriverRef inDriver, AudioObjectID inObjectID, pid_t inClientProcessID, const AudioObjectPropertyAddress* inAddress, UInt32 inQualifierDataSize, const void* inQualifierData, UInt32* outDataSize) {
    (void)inDriver;
    (void)inClientProcessID;
    (void)inQualifierDataSize;
    (void)inQualifierData;
    if (!outDataSize || !inAddress) return kAudioHardwareIllegalOperationError;

    switch (inObjectID) {
        case kObjectID_PlugIn:
            switch (inAddress->mSelector) {
                case kAudioObjectPropertyBaseClass:
                case kAudioObjectPropertyClass:
                case kAudioObjectPropertyOwner:
                    *outDataSize = sizeof(AudioClassID);
                    return kAudioHardwareNoError;
                case kAudioObjectPropertyManufacturer:
                case kAudioPlugInPropertyResourceBundle:
                    *outDataSize = sizeof(CFStringRef);
                    return kAudioHardwareNoError;
                case kAudioPlugInPropertyDeviceList:
                    *outDataSize = sizeof(AudioObjectID);
                    return kAudioHardwareNoError;
                case kAudioPlugInPropertyTranslateUIDToDevice:
                    *outDataSize = sizeof(AudioObjectID);
                    return kAudioHardwareNoError;
            }
            break;

        case kObjectID_Device:
            switch (inAddress->mSelector) {
                case kAudioObjectPropertyBaseClass:
                case kAudioObjectPropertyClass:
                case kAudioObjectPropertyOwner:
                    *outDataSize = sizeof(AudioClassID);
                    return kAudioHardwareNoError;
                case kAudioObjectPropertyName:
                case kAudioObjectPropertyManufacturer:
                case kAudioDevicePropertyDeviceUID:
                case kAudioDevicePropertyModelUID:
                    *outDataSize = sizeof(CFStringRef);
                    return kAudioHardwareNoError;
                case kAudioDevicePropertyTransportType:
                case kAudioDevicePropertyClockDomain:
                case kAudioDevicePropertyDeviceIsAlive:
                case kAudioDevicePropertyDeviceIsRunning:
                case kAudioDevicePropertyDeviceCanBeDefaultDevice:
                case kAudioDevicePropertyDeviceCanBeDefaultSystemDevice:
                case kAudioDevicePropertyLatency:
                case kAudioDevicePropertySafetyOffset:
                case kAudioDevicePropertyZeroTimeStampPeriod:
                    *outDataSize = sizeof(UInt32);
                    return kAudioHardwareNoError;
                case kAudioDevicePropertyRelatedDevices:
                    *outDataSize = sizeof(AudioObjectID);
                    return kAudioHardwareNoError;
                case kAudioDevicePropertyNominalSampleRate:
                    *outDataSize = sizeof(Float64);
                    return kAudioHardwareNoError;
                case kAudioDevicePropertyAvailableNominalSampleRates:
                    *outDataSize = sizeof(AudioValueRange);
                    return kAudioHardwareNoError;
                case kAudioDevicePropertyStreams:
                    if (inAddress->mScope == kAudioObjectPropertyScopeOutput || inAddress->mScope == kAudioObjectPropertyScopeGlobal) {
                        *outDataSize = sizeof(AudioObjectID);
                    } else {
                        *outDataSize = 0;
                    }
                    return kAudioHardwareNoError;
                case kAudioObjectPropertyControlList:
                    *outDataSize = 2 * sizeof(AudioObjectID);
                    return kAudioHardwareNoError;
            }
            break;

        case kObjectID_Stream:
            switch (inAddress->mSelector) {
                case kAudioObjectPropertyBaseClass:
                case kAudioObjectPropertyClass:
                case kAudioObjectPropertyOwner:
                    *outDataSize = sizeof(AudioClassID);
                    return kAudioHardwareNoError;
                case kAudioStreamPropertyDirection:
                case kAudioStreamPropertyTerminalType:
                case kAudioStreamPropertyStartingChannel:
                case kAudioStreamPropertyLatency:
                    *outDataSize = sizeof(UInt32);
                    return kAudioHardwareNoError;
                case kAudioStreamPropertyVirtualFormat:
                case kAudioStreamPropertyPhysicalFormat:
                    *outDataSize = sizeof(AudioStreamBasicDescription);
                    return kAudioHardwareNoError;
                case kAudioStreamPropertyAvailableVirtualFormats:
                case kAudioStreamPropertyAvailablePhysicalFormats:
                    *outDataSize = sizeof(AudioStreamRangedDescription);
                    return kAudioHardwareNoError;
            }
            break;

        case kObjectID_Volume:
            switch (inAddress->mSelector) {
                case kAudioObjectPropertyBaseClass:
                case kAudioObjectPropertyClass:
                case kAudioObjectPropertyOwner:
                    *outDataSize = sizeof(AudioClassID);
                    return kAudioHardwareNoError;
                case kAudioControlPropertyScope:
                    *outDataSize = sizeof(AudioObjectPropertyScope);
                    return kAudioHardwareNoError;
                case kAudioControlPropertyElement:
                    *outDataSize = sizeof(AudioObjectPropertyElement);
                    return kAudioHardwareNoError;
                case kAudioLevelControlPropertyScalarValue:
                case kAudioLevelControlPropertyDecibelValue:
                    *outDataSize = sizeof(Float32);
                    return kAudioHardwareNoError;
                case kAudioLevelControlPropertyDecibelRange:
                    *outDataSize = sizeof(AudioValueRange);
                    return kAudioHardwareNoError;
            }
            break;

        case kObjectID_Mute:
            switch (inAddress->mSelector) {
                case kAudioObjectPropertyBaseClass:
                case kAudioObjectPropertyClass:
                case kAudioObjectPropertyOwner:
                    *outDataSize = sizeof(AudioClassID);
                    return kAudioHardwareNoError;
                case kAudioControlPropertyScope:
                    *outDataSize = sizeof(AudioObjectPropertyScope);
                    return kAudioHardwareNoError;
                case kAudioControlPropertyElement:
                    *outDataSize = sizeof(AudioObjectPropertyElement);
                    return kAudioHardwareNoError;
                case kAudioBooleanControlPropertyValue:
                    *outDataSize = sizeof(UInt32);
                    return kAudioHardwareNoError;
            }
            break;
    }
    return kAudioHardwareUnknownPropertyError;
}

/**
 * Reads a HAL object property into caller-supplied `outData`, validating `inDataSize`
 * strictly before every write and validating qualifier CF types before dereferencing.
 */
static OSStatus Driver_GetPropertyData(AudioServerPlugInDriverRef inDriver, AudioObjectID inObjectID, pid_t inClientProcessID, const AudioObjectPropertyAddress* inAddress, UInt32 inQualifierDataSize, const void* inQualifierData, UInt32 inDataSize, UInt32* outDataSize, void* outData) {
    (void)inDriver;
    (void)inClientProcessID;
    if (!outDataSize || !inAddress) return kAudioHardwareIllegalOperationError;

    /* Helper macro enforcing strict output buffer capacity check prior to writing outData. */
    #define REQUIRE_OUT_BYTES(needed_bytes)                                      \
        do {                                                                     \
            if (outData == NULL || inDataSize < (UInt32)(needed_bytes)) {        \
                return kAudioHardwareBadPropertySizeError;                       \
            }                                                                    \
        } while (0)

    static AudioStreamBasicDescription streamFormat = {
        .mSampleRate = 48000.0,
        .mFormatID = kAudioFormatLinearPCM,
        .mFormatFlags = kAudioFormatFlagIsFloat | kAudioFormatFlagIsPacked,
        .mBytesPerPacket = 8,
        .mFramesPerPacket = 1,
        .mBytesPerFrame = 8,
        .mChannelsPerFrame = 2,
        .mBitsPerChannel = 32
    };

    switch (inObjectID) {
        case kObjectID_PlugIn:
            switch (inAddress->mSelector) {
                case kAudioObjectPropertyBaseClass:
                case kAudioObjectPropertyClass:
                    REQUIRE_OUT_BYTES(sizeof(AudioClassID));
                    *(AudioClassID*)outData = kAudioPlugInClassID;
                    *outDataSize = sizeof(AudioClassID);
                    return kAudioHardwareNoError;
                case kAudioObjectPropertyOwner:
                    REQUIRE_OUT_BYTES(sizeof(AudioClassID));
                    *(AudioClassID*)outData = kAudioObjectUnknown;
                    *outDataSize = sizeof(AudioClassID);
                    return kAudioHardwareNoError;
                case kAudioObjectPropertyManufacturer:
                    REQUIRE_OUT_BYTES(sizeof(CFStringRef));
                    *(CFStringRef*)outData = CFStringCreateCopy(kCFAllocatorDefault, kManufacturer);
                    *outDataSize = sizeof(CFStringRef);
                    return kAudioHardwareNoError;
                case kAudioPlugInPropertyResourceBundle:
                    REQUIRE_OUT_BYTES(sizeof(CFStringRef));
                    *(CFStringRef*)outData = CFStringCreateCopy(kCFAllocatorDefault, CFSTR(""));
                    *outDataSize = sizeof(CFStringRef);
                    return kAudioHardwareNoError;
                case kAudioPlugInPropertyDeviceList:
                    REQUIRE_OUT_BYTES(sizeof(AudioObjectID));
                    *(AudioObjectID*)outData = kObjectID_Device;
                    *outDataSize = sizeof(AudioObjectID);
                    return kAudioHardwareNoError;
                case kAudioPlugInPropertyTranslateUIDToDevice:
                    REQUIRE_OUT_BYTES(sizeof(AudioObjectID));
                    if (inQualifierData && inQualifierDataSize >= sizeof(CFStringRef)) {
                        CFStringRef queryUID = *(const CFStringRef*)inQualifierData;
                        if (queryUID != NULL &&
                            CFGetTypeID(queryUID) == CFStringGetTypeID() &&
                            CFStringCompare(queryUID, kDevice_UID, 0) == kCFCompareEqualTo) {
                            *(AudioObjectID*)outData = kObjectID_Device;
                            *outDataSize = sizeof(AudioObjectID);
                            return kAudioHardwareNoError;
                        }
                    }
                    *(AudioObjectID*)outData = kAudioObjectUnknown;
                    *outDataSize = sizeof(AudioObjectID);
                    return kAudioHardwareNoError;
            }
            break;

        case kObjectID_Device:
            switch (inAddress->mSelector) {
                case kAudioObjectPropertyBaseClass:
                    REQUIRE_OUT_BYTES(sizeof(AudioClassID));
                    *(AudioClassID*)outData = kAudioObjectClassID;
                    *outDataSize = sizeof(AudioClassID);
                    return kAudioHardwareNoError;
                case kAudioObjectPropertyClass:
                    REQUIRE_OUT_BYTES(sizeof(AudioClassID));
                    *(AudioClassID*)outData = kAudioDeviceClassID;
                    *outDataSize = sizeof(AudioClassID);
                    return kAudioHardwareNoError;
                case kAudioObjectPropertyOwner:
                    REQUIRE_OUT_BYTES(sizeof(AudioClassID));
                    *(AudioClassID*)outData = kObjectID_PlugIn;
                    *outDataSize = sizeof(AudioClassID);
                    return kAudioHardwareNoError;
                case kAudioObjectPropertyName:
                    REQUIRE_OUT_BYTES(sizeof(CFStringRef));
                    *(CFStringRef*)outData = CFStringCreateCopy(kCFAllocatorDefault, kDevice_Name);
                    *outDataSize = sizeof(CFStringRef);
                    return kAudioHardwareNoError;
                case kAudioObjectPropertyManufacturer:
                    REQUIRE_OUT_BYTES(sizeof(CFStringRef));
                    *(CFStringRef*)outData = CFStringCreateCopy(kCFAllocatorDefault, kManufacturer);
                    *outDataSize = sizeof(CFStringRef);
                    return kAudioHardwareNoError;
                case kAudioDevicePropertyDeviceUID:
                    REQUIRE_OUT_BYTES(sizeof(CFStringRef));
                    *(CFStringRef*)outData = CFStringCreateCopy(kCFAllocatorDefault, kDevice_UID);
                    *outDataSize = sizeof(CFStringRef);
                    return kAudioHardwareNoError;
                case kAudioDevicePropertyModelUID:
                    REQUIRE_OUT_BYTES(sizeof(CFStringRef));
                    *(CFStringRef*)outData = CFStringCreateCopy(kCFAllocatorDefault, kDevice_ModelUID);
                    *outDataSize = sizeof(CFStringRef);
                    return kAudioHardwareNoError;
                case kAudioDevicePropertyTransportType:
                    REQUIRE_OUT_BYTES(sizeof(UInt32));
                    *(UInt32*)outData = kAudioDeviceTransportTypeVirtual;
                    *outDataSize = sizeof(UInt32);
                    return kAudioHardwareNoError;
                case kAudioDevicePropertyRelatedDevices:
                    REQUIRE_OUT_BYTES(sizeof(AudioObjectID));
                    *(AudioObjectID*)outData = kObjectID_Device;
                    *outDataSize = sizeof(AudioObjectID);
                    return kAudioHardwareNoError;
                case kAudioDevicePropertyClockDomain:
                    REQUIRE_OUT_BYTES(sizeof(UInt32));
                    *(UInt32*)outData = 0;
                    *outDataSize = sizeof(UInt32);
                    return kAudioHardwareNoError;
                case kAudioDevicePropertyDeviceIsAlive:
                    REQUIRE_OUT_BYTES(sizeof(UInt32));
                    *(UInt32*)outData = 1;
                    *outDataSize = sizeof(UInt32);
                    return kAudioHardwareNoError;
                case kAudioDevicePropertyDeviceIsRunning:
                    REQUIRE_OUT_BYTES(sizeof(UInt32));
                    *(UInt32*)outData = atomic_load_explicit(&g_device_running, memory_order_acquire);
                    *outDataSize = sizeof(UInt32);
                    return kAudioHardwareNoError;
                case kAudioDevicePropertyDeviceCanBeDefaultDevice:
                case kAudioDevicePropertyDeviceCanBeDefaultSystemDevice:
                    REQUIRE_OUT_BYTES(sizeof(UInt32));
                    *(UInt32*)outData = 1;
                    *outDataSize = sizeof(UInt32);
                    return kAudioHardwareNoError;
                case kAudioDevicePropertyLatency:
                case kAudioDevicePropertySafetyOffset:
                    REQUIRE_OUT_BYTES(sizeof(UInt32));
                    *(UInt32*)outData = 0;
                    *outDataSize = sizeof(UInt32);
                    return kAudioHardwareNoError;
                case kAudioDevicePropertyNominalSampleRate:
                    REQUIRE_OUT_BYTES(sizeof(Float64));
                    *(Float64*)outData = kSampleRate;
                    *outDataSize = sizeof(Float64);
                    return kAudioHardwareNoError;
                case kAudioDevicePropertyAvailableNominalSampleRates:
                    {
                        REQUIRE_OUT_BYTES(sizeof(AudioValueRange));
                        AudioValueRange range = { kSampleRate, kSampleRate };
                        *(AudioValueRange*)outData = range;
                        *outDataSize = sizeof(AudioValueRange);
                        return kAudioHardwareNoError;
                    }
                case kAudioDevicePropertyZeroTimeStampPeriod:
                    REQUIRE_OUT_BYTES(sizeof(UInt32));
                    *(UInt32*)outData = kZeroTimeStampPeriod;
                    *outDataSize = sizeof(UInt32);
                    return kAudioHardwareNoError;
                case kAudioDevicePropertyStreams:
                    if (inAddress->mScope == kAudioObjectPropertyScopeOutput || inAddress->mScope == kAudioObjectPropertyScopeGlobal) {
                        REQUIRE_OUT_BYTES(sizeof(AudioObjectID));
                        *(AudioObjectID*)outData = kObjectID_Stream;
                        *outDataSize = sizeof(AudioObjectID);
                    } else {
                        *outDataSize = 0;
                    }
                    return kAudioHardwareNoError;
                case kAudioObjectPropertyControlList:
                    {
                        AudioObjectID controls[2] = { kObjectID_Volume, kObjectID_Mute };
                        REQUIRE_OUT_BYTES(sizeof(controls));
                        memcpy(outData, controls, sizeof(controls));
                        *outDataSize = sizeof(controls);
                        return kAudioHardwareNoError;
                    }
            }
            break;

        case kObjectID_Stream:
            switch (inAddress->mSelector) {
                case kAudioObjectPropertyBaseClass:
                    REQUIRE_OUT_BYTES(sizeof(AudioClassID));
                    *(AudioClassID*)outData = kAudioObjectClassID;
                    *outDataSize = sizeof(AudioClassID);
                    return kAudioHardwareNoError;
                case kAudioObjectPropertyClass:
                    REQUIRE_OUT_BYTES(sizeof(AudioClassID));
                    *(AudioClassID*)outData = kAudioStreamClassID;
                    *outDataSize = sizeof(AudioClassID);
                    return kAudioHardwareNoError;
                case kAudioObjectPropertyOwner:
                    REQUIRE_OUT_BYTES(sizeof(AudioClassID));
                    *(AudioClassID*)outData = kObjectID_Device;
                    *outDataSize = sizeof(AudioClassID);
                    return kAudioHardwareNoError;
                case kAudioStreamPropertyDirection:
                    REQUIRE_OUT_BYTES(sizeof(UInt32));
                    *(UInt32*)outData = 0; /* Output */
                    *outDataSize = sizeof(UInt32);
                    return kAudioHardwareNoError;
                case kAudioStreamPropertyTerminalType:
                    REQUIRE_OUT_BYTES(sizeof(UInt32));
                    *(UInt32*)outData = kAudioStreamTerminalTypeSpeaker;
                    *outDataSize = sizeof(UInt32);
                    return kAudioHardwareNoError;
                case kAudioStreamPropertyStartingChannel:
                    REQUIRE_OUT_BYTES(sizeof(UInt32));
                    *(UInt32*)outData = 1;
                    *outDataSize = sizeof(UInt32);
                    return kAudioHardwareNoError;
                case kAudioStreamPropertyLatency:
                    REQUIRE_OUT_BYTES(sizeof(UInt32));
                    *(UInt32*)outData = 0;
                    *outDataSize = sizeof(UInt32);
                    return kAudioHardwareNoError;
                case kAudioStreamPropertyVirtualFormat:
                case kAudioStreamPropertyPhysicalFormat:
                    REQUIRE_OUT_BYTES(sizeof(AudioStreamBasicDescription));
                    *(AudioStreamBasicDescription*)outData = streamFormat;
                    *outDataSize = sizeof(AudioStreamBasicDescription);
                    return kAudioHardwareNoError;
                case kAudioStreamPropertyAvailableVirtualFormats:
                case kAudioStreamPropertyAvailablePhysicalFormats:
                    {
                        REQUIRE_OUT_BYTES(sizeof(AudioStreamRangedDescription));
                        AudioStreamRangedDescription ranged = {
                            .mFormat = streamFormat,
                            .mSampleRateRange = { kSampleRate, kSampleRate }
                        };
                        *(AudioStreamRangedDescription*)outData = ranged;
                        *outDataSize = sizeof(AudioStreamRangedDescription);
                        return kAudioHardwareNoError;
                    }
            }
            break;

        case kObjectID_Volume:
            switch (inAddress->mSelector) {
                case kAudioObjectPropertyBaseClass:
                    REQUIRE_OUT_BYTES(sizeof(AudioClassID));
                    *(AudioClassID*)outData = kAudioControlClassID;
                    *outDataSize = sizeof(AudioClassID);
                    return kAudioHardwareNoError;
                case kAudioObjectPropertyClass:
                    REQUIRE_OUT_BYTES(sizeof(AudioClassID));
                    *(AudioClassID*)outData = kAudioVolumeControlClassID;
                    *outDataSize = sizeof(AudioClassID);
                    return kAudioHardwareNoError;
                case kAudioObjectPropertyOwner:
                    REQUIRE_OUT_BYTES(sizeof(AudioClassID));
                    *(AudioClassID*)outData = kObjectID_Device;
                    *outDataSize = sizeof(AudioClassID);
                    return kAudioHardwareNoError;
                case kAudioControlPropertyScope:
                    REQUIRE_OUT_BYTES(sizeof(AudioObjectPropertyScope));
                    *(AudioObjectPropertyScope*)outData = kAudioObjectPropertyScopeOutput;
                    *outDataSize = sizeof(AudioObjectPropertyScope);
                    return kAudioHardwareNoError;
                case kAudioControlPropertyElement:
                    REQUIRE_OUT_BYTES(sizeof(AudioObjectPropertyElement));
                    *(AudioObjectPropertyElement*)outData = kAudioObjectPropertyElementMain;
                    *outDataSize = sizeof(AudioObjectPropertyElement);
                    return kAudioHardwareNoError;
                case kAudioLevelControlPropertyScalarValue:
                    REQUIRE_OUT_BYTES(sizeof(Float32));
                    *(Float32*)outData = atomic_load_explicit(&g_volume, memory_order_relaxed);
                    *outDataSize = sizeof(Float32);
                    return kAudioHardwareNoError;
                case kAudioLevelControlPropertyDecibelValue:
                    {
                        REQUIRE_OUT_BYTES(sizeof(Float32));
                        float v = atomic_load_explicit(&g_volume, memory_order_relaxed);
                        *(Float32*)outData = 20.0f * log10f(fmaxf(v, 0.00001f));
                        *outDataSize = sizeof(Float32);
                        return kAudioHardwareNoError;
                    }
                case kAudioLevelControlPropertyDecibelRange:
                    {
                        REQUIRE_OUT_BYTES(sizeof(AudioValueRange));
                        AudioValueRange range = { kMinVolumeDb, 0.0 };
                        *(AudioValueRange*)outData = range;
                        *outDataSize = sizeof(AudioValueRange);
                        return kAudioHardwareNoError;
                    }
            }
            break;

        case kObjectID_Mute:
            switch (inAddress->mSelector) {
                case kAudioObjectPropertyBaseClass:
                    REQUIRE_OUT_BYTES(sizeof(AudioClassID));
                    *(AudioClassID*)outData = kAudioControlClassID;
                    *outDataSize = sizeof(AudioClassID);
                    return kAudioHardwareNoError;
                case kAudioObjectPropertyClass:
                    REQUIRE_OUT_BYTES(sizeof(AudioClassID));
                    *(AudioClassID*)outData = kAudioMuteControlClassID;
                    *outDataSize = sizeof(AudioClassID);
                    return kAudioHardwareNoError;
                case kAudioObjectPropertyOwner:
                    REQUIRE_OUT_BYTES(sizeof(AudioClassID));
                    *(AudioClassID*)outData = kObjectID_Device;
                    *outDataSize = sizeof(AudioClassID);
                    return kAudioHardwareNoError;
                case kAudioControlPropertyScope:
                    REQUIRE_OUT_BYTES(sizeof(AudioObjectPropertyScope));
                    *(AudioObjectPropertyScope*)outData = kAudioObjectPropertyScopeOutput;
                    *outDataSize = sizeof(AudioObjectPropertyScope);
                    return kAudioHardwareNoError;
                case kAudioControlPropertyElement:
                    REQUIRE_OUT_BYTES(sizeof(AudioObjectPropertyElement));
                    *(AudioObjectPropertyElement*)outData = kAudioObjectPropertyElementMain;
                    *outDataSize = sizeof(AudioObjectPropertyElement);
                    return kAudioHardwareNoError;
                case kAudioBooleanControlPropertyValue:
                    REQUIRE_OUT_BYTES(sizeof(UInt32));
                    *(UInt32*)outData = atomic_load_explicit(&g_mute, memory_order_relaxed);
                    *outDataSize = sizeof(UInt32);
                    return kAudioHardwareNoError;
            }
            break;
    }

    #undef REQUIRE_OUT_BYTES
    return kAudioHardwareUnknownPropertyError;
}

/** Updates scalar volume (`[0.0, 1.0]`, finite-validated) or mute flag atomically. */
static OSStatus Driver_SetPropertyData(AudioServerPlugInDriverRef inDriver, AudioObjectID inObjectID, pid_t inClientProcessID, const AudioObjectPropertyAddress* inAddress, UInt32 inQualifierDataSize, const void* inQualifierData, UInt32 inDataSize, const void* inData) {
    (void)inDriver;
    (void)inClientProcessID;
    (void)inQualifierDataSize;
    (void)inQualifierData;
    if (!inAddress || !inData) return kAudioHardwareIllegalOperationError;

    if (inObjectID == kObjectID_Volume && inAddress->mSelector == kAudioLevelControlPropertyScalarValue) {
        if (inDataSize < sizeof(Float32)) return kAudioHardwareBadPropertySizeError;
        Float32 raw = *(const Float32*)inData;
        if (!isfinite(raw)) return kAudioHardwareIllegalOperationError;
        Float32 clamped = fminf(fmaxf(raw, 0.0f), 1.0f);
        atomic_store_explicit(&g_volume, clamped, memory_order_relaxed);
        return kAudioHardwareNoError;
    } else if (inObjectID == kObjectID_Mute && inAddress->mSelector == kAudioBooleanControlPropertyValue) {
        if (inDataSize < sizeof(UInt32)) return kAudioHardwareBadPropertySizeError;
        UInt32 muted = (*(const UInt32*)inData != 0) ? 1u : 0u;
        atomic_store_explicit(&g_mute, muted, memory_order_relaxed);
        return kAudioHardwareNoError;
    }
    return kAudioHardwareUnknownPropertyError;
}

/* ----------------------------------------------------------------------------------------------
 * CoreAudio HAL IO Cycle Implementation
 * ---------------------------------------------------------------------------------------------- */

/**
 * Starts CoreAudio IO for a client, reference-counting concurrent HAL clients and initializing
 * shared-memory mapping and timeline timestamps on the `0 -> 1` transition.
 */
static OSStatus Driver_StartIO(AudioServerPlugInDriverRef inDriver, AudioObjectID inDeviceObjectID, UInt32 inClientID) {
    (void)inDriver;
    (void)inDeviceObjectID;
    (void)inClientID;

    ensure_shm_mapped();
    uint32_t prev = atomic_fetch_add_explicit(&g_io_client_count, 1u, memory_order_acq_rel);
    if (prev == 0u) {
        atomic_store_explicit(&g_device_running, 1u, memory_order_release);
        atomic_store_explicit(&g_timeline_start_host_time, mach_absolute_time(), memory_order_release);
        atomic_fetch_add_explicit(&g_timeline_seed, 1u, memory_order_acq_rel);

        IntegratorAudioShmHeader* shm = atomic_load_explicit(&g_shm, memory_order_acquire);
        if (shm) {
            atomic_store_explicit(&shm->active, 1u, memory_order_release);
        }
    }
    return kAudioHardwareNoError;
}

/** Decrements active client IO refcount and marks device/SHM idle only when the last client stops. */
static OSStatus Driver_StopIO(AudioServerPlugInDriverRef inDriver, AudioObjectID inDeviceObjectID, UInt32 inClientID) {
    (void)inDriver;
    (void)inDeviceObjectID;
    (void)inClientID;

    uint32_t cur = atomic_load_explicit(&g_io_client_count, memory_order_acquire);
    while (cur > 0u) {
        if (atomic_compare_exchange_weak_explicit(
                &g_io_client_count,
                &cur,
                cur - 1u,
                memory_order_acq_rel,
                memory_order_acquire)) {
            if (cur == 1u) {
                atomic_store_explicit(&g_device_running, 0u, memory_order_release);
                IntegratorAudioShmHeader* shm = atomic_load_explicit(&g_shm, memory_order_acquire);
                if (shm) {
                    atomic_store_explicit(&shm->active, 0u, memory_order_release);
                }
            }
            break;
        }
    }
    return kAudioHardwareNoError;
}

/** Synthesizes continuous hardware-clock timestamps anchored to `g_timeline_start_host_time` without 64-bit overflow. */
static OSStatus Driver_GetZeroTimeStamp(AudioServerPlugInDriverRef inDriver, AudioObjectID inDeviceObjectID, UInt32 inClientID, Float64* outSampleTime, UInt64* outHostTime, UInt64* outSeed) {
    (void)inDriver;
    (void)inDeviceObjectID;
    (void)inClientID;
    if (!outSampleTime || !outHostTime || !outSeed) return kAudioHardwareIllegalOperationError;

    uint64_t now = mach_absolute_time();
    uint64_t start_host = atomic_load_explicit(&g_timeline_start_host_time, memory_order_acquire);
    uint64_t elapsed_ticks = (now > start_host) ? (now - start_host) : 0u;
    uint32_t denom = (g_timebase.denom != 0u) ? g_timebase.denom : 1u;
    uint64_t elapsed_nanos = (uint64_t)(((__uint128_t)elapsed_ticks * (__uint128_t)g_timebase.numer) / (__uint128_t)denom);
    Float64 elapsed_samples = (Float64)elapsed_nanos * kSampleRate / 1000000000.0;

    *outSampleTime = elapsed_samples;
    *outHostTime = now;
    *outSeed = atomic_load_explicit(&g_timeline_seed, memory_order_acquire);
    return kAudioHardwareNoError;
}

/** Advertises support for in-place `kAudioServerPlugInIOOperationWriteMix`. */
static OSStatus Driver_WillDoIOOperation(AudioServerPlugInDriverRef inDriver, AudioObjectID inDeviceObjectID, UInt32 inClientID, UInt32 inOperationID, Boolean* outWillDo, Boolean* outWillDoInPlace) {
    (void)inDriver;
    (void)inDeviceObjectID;
    (void)inClientID;
    if (!outWillDo || !outWillDoInPlace) return kAudioHardwareIllegalOperationError;

    if (inOperationID == kAudioServerPlugInIOOperationWriteMix) {
        *outWillDo = true;
        *outWillDoInPlace = true;
    } else {
        *outWillDo = false;
        *outWillDoInPlace = true;
    }
    return kAudioHardwareNoError;
}

/** Real-time IO cycle prelude hook (no-op). */
static OSStatus Driver_BeginIOOperation(AudioServerPlugInDriverRef inDriver, AudioObjectID inDeviceObjectID, UInt32 inClientID, UInt32 inOperationID, UInt32 inIOBufferFrameSize, const AudioServerPlugInIOCycleInfo* inIOCycleInfo) {
    return kAudioHardwareNoError;
}

/**
 * Real-time `WriteMix` callback converting interleaved stereo F32 PCM to S16LE into shared memory.
 *
 * Strictly lock-free and syscall-free. Clamps indices modulo `INTEGRATOR_AUDIO_RING_BUFFER_BYTES`,
 * enforces 2-byte PCM alignment, handles oversized cycles cleanly, and avoids strict-aliasing UB
 * via `memcpy`.
 */
static OSStatus Driver_DoIOOperation(AudioServerPlugInDriverRef inDriver, AudioObjectID inDeviceObjectID, AudioObjectID inStreamObjectID, UInt32 inClientID, UInt32 inOperationID, UInt32 inIOBufferFrameSize, const AudioServerPlugInIOCycleInfo* inIOCycleInfo, void* ioMainBuffer, void* ioSecondaryBuffer) {
    (void)inDriver;
    (void)inDeviceObjectID;
    (void)inStreamObjectID;
    (void)inClientID;
    (void)inIOCycleInfo;
    (void)ioSecondaryBuffer;

    if (inOperationID != kAudioServerPlugInIOOperationWriteMix || !ioMainBuffer || inIOBufferFrameSize == 0u) {
        return kAudioHardwareNoError;
    }

    IntegratorAudioShmHeader* shm = atomic_load_explicit(&g_shm, memory_order_acquire);
    if (!shm) {
        return kAudioHardwareNoError;
    }

    /* Interleaved stereo 32-bit float PCM */
    const float* in_samples = (const float*)ioMainBuffer;
    uint32_t max_ring_frames = (INTEGRATOR_AUDIO_RING_BUFFER_BYTES / (kStereoChannels * sizeof(int16_t))) - 1u;
    uint32_t frame_start = 0u;
    uint32_t frames_to_write = inIOBufferFrameSize;
    if (frames_to_write > max_ring_frames) {
        frame_start = frames_to_write - max_ring_frames;
        frames_to_write = max_ring_frames;
    }

    uint32_t start_sample = frame_start * kStereoChannels;
    uint32_t total_samples = frames_to_write * kStereoChannels;
    uint32_t bytes_to_write = total_samples * (uint32_t)sizeof(int16_t);
    float vol = (atomic_load_explicit(&g_mute, memory_order_relaxed) != 0u)
        ? 0.0f
        : atomic_load_explicit(&g_volume, memory_order_relaxed);

    /* Load and normalize cursors inside [0 .. INTEGRATOR_AUDIO_RING_BUFFER_BYTES - 1] with 2-byte sample alignment. */
    uint32_t curr_write = atomic_load_explicit(&shm->write_pos, memory_order_relaxed) % INTEGRATOR_AUDIO_RING_BUFFER_BYTES;
    curr_write &= ~(uint32_t)(sizeof(int16_t) - 1u);
    uint32_t curr_read = atomic_load_explicit(&shm->read_pos, memory_order_acquire) % INTEGRATOR_AUDIO_RING_BUFFER_BYTES;
    curr_read &= ~(uint32_t)(sizeof(int16_t) - 1u);

    uint32_t used_bytes = (curr_write >= curr_read)
        ? (curr_write - curr_read)
        : (INTEGRATOR_AUDIO_RING_BUFFER_BYTES - (curr_read - curr_write));

    if (used_bytes + bytes_to_write >= INTEGRATOR_AUDIO_RING_BUFFER_BYTES) {
        atomic_fetch_add_explicit(&shm->underruns, 1u, memory_order_relaxed);
        /* Advance read pointer to discard oldest queued frames and prevent ring wrap collision. */
        uint32_t overflow_advance = (used_bytes + bytes_to_write + (kStereoChannels * (uint32_t)sizeof(int16_t))) - INTEGRATOR_AUDIO_RING_BUFFER_BYTES;
        uint32_t aligned_adv = (overflow_advance + 3u) & ~3u;
        uint32_t new_read = (curr_read + aligned_adv) % INTEGRATOR_AUDIO_RING_BUFFER_BYTES;
        atomic_store_explicit(&shm->read_pos, new_read, memory_order_release);
    }

    for (uint32_t i = 0u; i < total_samples; i++) {
        int16_t pcm = float_to_int16(in_samples[start_sample + i] * vol);
        memcpy(&shm->buffer[curr_write], &pcm, sizeof(pcm));
        curr_write = (curr_write + (uint32_t)sizeof(int16_t)) % INTEGRATOR_AUDIO_RING_BUFFER_BYTES;
    }

    /* Publish write_pos with release semantics so Integrator consumer observes completed ring bytes. */
    atomic_store_explicit(&shm->write_pos, curr_write, memory_order_release);
    atomic_fetch_add_explicit(&shm->total_frames_written, (uint64_t)frames_to_write, memory_order_relaxed);

    return kAudioHardwareNoError;
}

/** Real-time IO cycle postlude hook (no-op). */
static OSStatus Driver_EndIOOperation(AudioServerPlugInDriverRef inDriver, AudioObjectID inDeviceObjectID, UInt32 inClientID, UInt32 inOperationID, UInt32 inIOBufferFrameSize, const AudioServerPlugInIOCycleInfo* inIOCycleInfo) {
    return kAudioHardwareNoError;
}

/* ----------------------------------------------------------------------------------------------
 * AudioServerPlugIn Driver Function Table
 * ---------------------------------------------------------------------------------------------- */

/** Static CoreAudio `AudioServerPlugInDriverInterface` dispatch table exported via COM `QueryInterface`. */
static AudioServerPlugInDriverInterface g_driver_interface = {
    ._reserved = NULL,
    .QueryInterface = Driver_QueryInterface,
    .AddRef = Driver_AddRef,
    .Release = Driver_Release,
    .Initialize = Driver_Initialize,
    .CreateDevice = Driver_CreateDevice,
    .DestroyDevice = Driver_DestroyDevice,
    .AddDeviceClient = Driver_AddDeviceClient,
    .RemoveDeviceClient = Driver_RemoveDeviceClient,
    .PerformDeviceConfigurationChange = Driver_PerformDeviceConfigurationChange,
    .AbortDeviceConfigurationChange = Driver_AbortDeviceConfigurationChange,
    .HasProperty = Driver_HasProperty,
    .IsPropertySettable = Driver_IsPropertySettable,
    .GetPropertyDataSize = Driver_GetPropertyDataSize,
    .GetPropertyData = Driver_GetPropertyData,
    .SetPropertyData = Driver_SetPropertyData,
    .StartIO = Driver_StartIO,
    .StopIO = Driver_StopIO,
    .GetZeroTimeStamp = Driver_GetZeroTimeStamp,
    .WillDoIOOperation = Driver_WillDoIOOperation,
    .BeginIOOperation = Driver_BeginIOOperation,
    .DoIOOperation = Driver_DoIOOperation,
    .EndIOOperation = Driver_EndIOOperation
};

/* ----------------------------------------------------------------------------------------------
 * CFPlugIn Factory Entry Point
 * ---------------------------------------------------------------------------------------------- */

/**
 * CoreFoundation CFPlugIn factory entrypoint invoked by `coreaudiod` upon loading `IntegratorAudioDriver.driver`.
 *
 * @param inAllocator Unused allocator reference passed by CFPlugIn loader.
 * @param inTypeUUID  Plug-in interface type UUID; returns singleton only for `kAudioServerPlugInTypeUUID`.
 * @return Pointer to `&g_driver_ref` on type match, or `NULL` on unsupported type.
 */
__attribute__((visibility("default")))
void* IntegratorAudioDriver_Create(CFAllocatorRef inAllocator, CFUUIDRef inTypeUUID) {
    (void)inAllocator;
    if (!inTypeUUID) return NULL;

    if (CFEqual(inTypeUUID, kAudioServerPlugInTypeUUID)) {
        Driver_AddRef(g_driver_ref);
        return g_driver_ref;
    }
    return NULL;
}
