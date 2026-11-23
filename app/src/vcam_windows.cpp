/*
 * ============================================================================
 * Integrator Shared Camera: Windows 11 Media Foundation Virtual Camera COM DLL
 * ============================================================================
 *
 * 1. MODULE PURPOSE & ARCHITECTURAL SCOPE
 * ----------------------------------------------------------------------------
 * This module is the standalone COM dynamic-link library (`integrator_vcam.dll`)
 * implementing the Windows 11 Media Foundation Virtual Camera in-process server.
 * Registered under `CLSID_IntegratorVCamActivate` ({8E4A6D21-7C4B-4F31-9B18-3A62F4B7E912}),
 * it is loaded by the Windows Camera Frame Server service (`svchost.exe -k CameraService`
 * running as `NT AUTHORITY\LOCAL SERVICE`) and camera client applications.
 *
 * Core COM and Media Foundation Interfaces Implemented:
 * - `IMFActivate`: Instantiates and configures the `IMFMediaSourceEx` instance.
 * - `IMFMediaSourceEx`: Represents the camera capture device to the Windows Media pipeline.
 * - `IMFMediaStream2`: Generates discrete 720p30 NV12 video samples on demand (`RequestSample`).
 * - `IMFSampleAllocatorControl`: Coordinates DirectX / system memory buffer allocation with FrameServer.
 * - `IKsControl`: Handles kernel-streaming camera control property queries.
 * - `IClassFactory`: Standard COM class factory for `CLSID_IntegratorVCamActivate`.
 *
 * 2. END-TO-END CROSS-OS CAMERA PIPELINE
 * ----------------------------------------------------------------------------
 * 1. Capture (macOS AVFoundation):
 *    FaceTime HD camera captured at 1280x720, 30 fps, NV12 bi-planar (`camera_macos.swift`).
 * 2. Network Transport:
 *    Streamed across mutually authenticated `TransportSessionV2` (port 58287, ChaCha20-Poly1305)
 *    to the Windows Integrator host process.
 * 3. Shared Memory Ingestion:
 *    The Windows host process writes frames into `Global\IntegratorVCamShm_v1` and pulses
 *    `Global\IntegratorVCamEvt_v1` via lock-free slot swapping (`camera_windows.cpp`).
 * 4. Sample Generation & Delivery (This File):
 *    - `IntegratorMediaStream::RequestSample` is invoked by the Media Foundation pipeline.
 *    - Waits up to 33 ms on `Global\IntegratorVCamEvt_v1` for 30 fps frame pacing.
 *    - Allocates an `IMFSample` via `IMFVideoSampleAllocator`.
 *    - Locks the sample buffer via `IMF2DBuffer2::Lock2DSize` to determine hardware pitch.
 *    - Copies the active NV12 frame row-by-row respecting pitch alignment.
 *    - If publisher is inactive or sequence is 0, renders a dark neutral standby frame (Y=22, UV=128).
 *    - Dispatches `MEMediaSample` into the media event queue.
 *
 * 3. DIRECT SOFTWARE SOURCE CONTRACT (ZERO THIRD-PARTY DRIVERS)
 * ----------------------------------------------------------------------------
 * Windows 11 Media Foundation Virtual Camera API supports two modes:
 * - Filter/wrapper camera: Wraps an existing physical webcam using
 *   `MF_VIRTUALCAMERA_PROVIDE_ASSOCIATED_CAMERA_SOURCES`.
 * - Pure standalone software camera: Generates synthetic video without physical hardware.
 * Integrator explicitly omits `MF_VIRTUALCAMERA_PROVIDE_ASSOCIATED_CAMERA_SOURCES`.
 * This direct software source contract ensures the virtual camera functions completely
 * standalone, requiring zero physical camera hardware and zero kernel/filter drivers on the PC.
 *
 * 4. STRIDE CALCULATIONS, MEMORY ALIGNMENT & 2D BUFFER LOCKING
 * ----------------------------------------------------------------------------
 * - Frame Geometry: 1280 x 720 pixels (720p).
 * - NV12 Plane 0 (Y): 1280 x 720 bytes (luma).
 * - NV12 Plane 1 (UV): 1280 x 360 bytes (interleaved chroma, subsampled 4:2:0).
 * - Total Contiguous Size: 1,382,400 bytes (`1280 * 720 * 3 / 2`).
 * - Pitch Handling: Media Foundation video allocators frequently pad row pitch
 *   (e.g., 1280 aligned to 1536 or 2048 for DirectX / GPU alignment).
 *   `IMF2DBuffer2::Lock2DSize` retrieves the actual row stride. Both `CopyNV12ToOutput`
 *   and `FillStandbyNV12` copy Y and UV rows individually respecting `pitch >= 1280`,
 *   preventing display skew, green artifacts, or buffer overruns.
 *
 * 5. THREADING & CONCURRENCY MODEL
 * ----------------------------------------------------------------------------
 * - Threading Model: COM Free-Threaded / "Both" (`COINIT_MULTITHREADED`).
 * - Critical Sections: `CRITICAL_SECTION m_cs` protects internal state per COM object.
 * - Non-Blocking Frame Polling: Shared memory reads use memory barriers and sequence checks;
 *   no mutex is shared between the host publisher and the FrameServer consumer.
 * ============================================================================
 */

#define WIN32_LEAN_AND_MEAN
#include <cstdio>
#include <unknwn.h>
#include <windows.h>
#include <ole2.h>
#include <initguid.h>
#include <ks.h>
#include <ksproxy.h>
#include <ksmedia.h>
#include <mfapi.h>
#include <mfidl.h>
#include <mfobjects.h>
#include <mferror.h>
#include <mfvirtualcamera.h>
#include <mftransform.h>
#include <propvarutil.h>
#include <cstdint>
#include <cstring>

// {8E4A6D21-7C4B-4F31-9B18-3A62F4B7E912}
DEFINE_GUID(CLSID_IntegratorVCamActivate,
    0x8e4a6d21, 0x7c4b, 0x4f31, 0x9b, 0x18, 0x3a, 0x62, 0xf4, 0xb7, 0xe9, 0x12);

// {B4894D81-62B7-4EEC-8740-80658C4A9D3E}
DEFINE_GUID(PROFILE_Legacy,
    0xb4894d81, 0x62b7, 0x4eec, 0x87, 0x40, 0x80, 0x65, 0x8c, 0x4a, 0x9d, 0x3e);

// {566E6113-8C35-48E7-B89F-D23FDC1219DC}
DEFINE_GUID(PROFILE_HighFrameRate,
    0x566e6113, 0x8c35, 0x48e7, 0xb8, 0x9f, 0xd2, 0x3f, 0xdc, 0x12, 0x19, 0xdc);

/// Determines whether diagnostic VCAM trace logging is enabled.
///
/// Tracing is active automatically in `_DEBUG` builds and opt-in via the
/// `INTEGRATOR_VCAM_TRACE=1` environment variable in release builds.
static bool IsVCamTraceEnabled() {
#ifdef _DEBUG
    return true;
#else
    static volatile LONG s_traceState = -1;
    LONG state = InterlockedCompareExchange(&s_traceState, -1, -1);
    if (state == -1) {
        char envVal[16] = {};
        DWORD n = GetEnvironmentVariableA("INTEGRATOR_VCAM_TRACE", envVal, sizeof(envVal));
        LONG resolved = (n > 0 && n < sizeof(envVal) && std::strcmp(envVal, "1") == 0) ? 1 : 0;
        InterlockedCompareExchange(&s_traceState, resolved, -1);
        state = resolved;
    }
    return state == 1;
#endif
}

/// Writes diagnostic trace lines to Win32 debug output and `%TEMP%\integrator_vcam_trace.log`
/// when debug or `INTEGRATOR_VCAM_TRACE=1` tracing is active.
static void LogTrace(const char* msg) {
    if (!IsVCamTraceEnabled()) return;

    char line[512] = {};
    std::snprintf(line, sizeof(line), "[IntegratorVCam PID %lu] %s\n",
        static_cast<unsigned long>(GetCurrentProcessId()),
        msg ? msg : "");
    OutputDebugStringA(line);

    char tempDir[MAX_PATH] = {};
    DWORD len = GetTempPathA(MAX_PATH, tempDir);
    if (len == 0 || len >= MAX_PATH) return;

    char logPath[MAX_PATH] = {};
    const char* sep = (tempDir[len - 1] == '\\' || tempDir[len - 1] == '/') ? "" : "\\";
    std::snprintf(logPath, sizeof(logPath), "%s%sintegrator_vcam_trace.log", tempDir, sep);
    FILE* f = std::fopen(logPath, "a");
    if (f) {
        std::fputs(line, f);
        std::fclose(f);
    }
}

namespace {

/// Four-character shared memory magic identifier ("IVCM").
constexpr uint32_t kShmMagic = 0x4D435649;

/// Shared memory layout version number.
constexpr uint32_t kShmVersion = 1;

/// Default video frame width in pixels (1280).
constexpr uint32_t kWidth = 1280;

/// Default video frame height in pixels (720).
constexpr uint32_t kHeight = 720;

/// Total raw byte size of one default 720p NV12 video frame (1,382,400 bytes).
constexpr uint32_t kFrameBytes = kWidth * kHeight * 3 / 2;

/// Target video stream frame rate in frames per second.
constexpr uint32_t kTargetFps = 30;

/// Frame pacing event wait interval in milliseconds (~33 ms at 30 fps).
constexpr DWORD kFrameIntervalMs = 1000 / kTargetFps;

/// Single video sample duration in Media Foundation 100-nanosecond units (333,333 at 30 fps).
constexpr LONGLONG kSampleDuration100ns = 10000000LL / kTargetFps;

/// Nominal uncompressed NV12 average bitrate in bits per second.
constexpr uint32_t kAvgBitrate = kFrameBytes * 8 * kTargetFps;

/// Dark neutral grey Y (luma) byte value used for standby frames.
constexpr uint8_t kStandbyLumaY = 22;

/// Neutral chroma (Cb/Cr) byte value used for standby frames.
constexpr uint8_t kStandbyChromaUV = 128;

#pragma pack(push, 1)
/// Double-buffered shared memory structure mapped read-only by the virtual camera DLL.
struct SharedVCamMemory {
    /// Magic header identifier.
    uint32_t magic;
    /// Memory structure version.
    uint32_t version;
    /// Frame width in pixels.
    uint32_t width;
    /// Frame height in pixels.
    uint32_t height;
    /// Frame buffer size in bytes.
    uint32_t frame_bytes;
    /// Index of the active completed slot (0 or 1).
    volatile LONG active_slot;
    /// Frame sequence number incremented by host publisher.
    volatile LONG64 seq;
    /// Frame timestamp in 100-nanosecond units.
    volatile LONG64 timestamp_100ns;
    /// Host publisher heartbeat flag.
    volatile LONG publisher_alive;
    /// Alignment padding.
    uint32_t reserved;
    /// Double-buffered raw NV12 pixel slots.
    uint8_t slots[2][kFrameBytes];
};
#pragma pack(pop)

/// Global module reference counter for `DllCanUnloadNow`.
volatile LONG g_moduleRefCount = 0;

/// Increments the DLL module reference counter.
void ModuleAddRef() { InterlockedIncrement(&g_moduleRefCount); }

/// Decrements the DLL module reference counter.
void ModuleRelease() { InterlockedDecrement(&g_moduleRefCount); }

/// RAII lock guard wrapping a Win32 `CRITICAL_SECTION`.
class CriticalLockGuard {
public:
    explicit CriticalLockGuard(CRITICAL_SECTION& cs) : m_cs(cs) { EnterCriticalSection(&m_cs); }
    ~CriticalLockGuard() { LeaveCriticalSection(&m_cs); }
private:
    CRITICAL_SECTION& m_cs;
};

/// Fills the output sample buffer with a dark neutral grey standby NV12 frame.
///
/// Respects output buffer row stride (pitch) to prevent display skew or memory corruptions.
///
/// - Parameters:
///   - dst: Destination buffer base pointer.
///   - stride: Bytes per row (pitch) reported by `IMF2DBuffer2::Lock2DSize`.
///   - bufLen: Total locked buffer length in bytes.
///   - width: Active frame width in pixels (defaults to `kWidth`).
///   - height: Active frame height in pixels (defaults to `kHeight`).
void FillStandbyNV12(
    uint8_t* dst,
    uint32_t stride,
    uint32_t bufLen,
    uint32_t width = kWidth,
    uint32_t height = kHeight
) {
    uint32_t ySize = width * height;
    uint32_t totalBytes = ySize + (ySize / 2);
    // Fast path: contiguous buffer without stride padding
    if (stride == width && bufLen >= totalBytes) {
        std::memset(dst, kStandbyLumaY, ySize);
        std::memset(dst + ySize, kStandbyChromaUV, ySize / 2);
        return;
    }
    // Stride-aware Y plane fill
    for (uint32_t r = 0; r < height; ++r) {
        if ((static_cast<size_t>(r) + 1) * stride <= bufLen) {
            std::memset(dst + static_cast<size_t>(r) * stride, kStandbyLumaY, width);
        }
    }
    // Stride-aware UV plane fill
    uint8_t* uvBase = dst + static_cast<size_t>(height) * stride;
    uint32_t uvRows = height / 2;
    for (uint32_t r = 0; r < uvRows; ++r) {
        size_t offset = static_cast<size_t>(height + r) * stride;
        if (offset + width <= bufLen) {
            std::memset(uvBase + static_cast<size_t>(r) * stride, kStandbyChromaUV, width);
        }
    }
}

/// Copies an uncompressed NV12 frame from shared memory into a destination Media Foundation buffer.
///
/// Unpacks rows row-by-row into the destination buffer according to the destination row pitch.
///
/// - Parameters:
///   - dst: Destination buffer base pointer.
///   - dstStride: Row stride (pitch) of destination buffer in bytes.
///   - dstLen: Total locked length of destination buffer.
///   - src: Source contiguous NV12 frame buffer.
///   - width: Active frame width in pixels (defaults to `kWidth`).
///   - height: Active frame height in pixels (defaults to `kHeight`).
void CopyNV12ToOutput(
    uint8_t* dst,
    uint32_t dstStride,
    uint32_t dstLen,
    const uint8_t* src,
    uint32_t width = kWidth,
    uint32_t height = kHeight
) {
    const uint32_t yBytes = width * height;
    const uint32_t frameBytes = yBytes + (yBytes / 2);
    // Fast path: destination pitch matches source width
    if (dstStride == width && dstLen >= frameBytes) {
        std::memcpy(dst, src, frameBytes);
        return;
    }
    // Row-by-row copy for Plane 0 (Y / Luma)
    for (uint32_t r = 0; r < height; ++r) {
        if (static_cast<size_t>(r) * dstStride + width <= dstLen) {
            std::memcpy(dst + static_cast<size_t>(r) * dstStride, src + static_cast<size_t>(r) * width, width);
        }
    }
    // Row-by-row copy for Plane 1 (CbCr / Chroma)
    const uint8_t* uvSrc = src + yBytes;
    uint8_t* uvDst = dst + static_cast<size_t>(height) * dstStride;
    for (uint32_t r = 0; r < height / 2; ++r) {
        size_t outEnd = static_cast<size_t>(height + r) * dstStride + width;
        if (outEnd <= dstLen) {
            std::memcpy(uvDst + static_cast<size_t>(r) * dstStride, uvSrc + static_cast<size_t>(r) * width, width);
        }
    }
}

class IntegratorMediaSource;

/// Media Foundation stream object generating 720p30 NV12 camera samples on demand.
///
/// Implements `IMFMediaStream2` for stream state control and sample dispatch,
/// `IMFAttributes` for stream descriptor metadata, and `IKsControl` for kernel streaming stubs.
class IntegratorMediaStream final :
    public IMFMediaStream2,
    public IMFAttributes,
    public IKsControl {
public:
    /// Constructs a new stream instance and initializes internal synchronization.
    IntegratorMediaStream() : m_ref(1) {
        ModuleAddRef();
        InitializeCriticalSection(&m_cs);
    }

    /// Releases resources and shuts down stream queues.
    ~IntegratorMediaStream() {
        Shutdown();
        DeleteCriticalSection(&m_cs);
        ModuleRelease();
    }

    /// Initializes stream descriptor, media type (720p30 NV12), and FrameServer attributes.
    ///
    /// - Parameters:
    ///   - parent: Parent `IMFMediaSource` interface pointer.
    ///   - streamId: Stream identifier index (0).
    /// - Returns: `S_OK` on success, or standard COM `HRESULT` failure.
    HRESULT Initialize(IMFMediaSource* parent, DWORD streamId) {
        CriticalLockGuard lock(m_cs);
        m_parent = parent;
        if (m_parent) m_parent->AddRef();
        m_streamId = streamId;

        HRESULT hr = MFCreateEventQueue(&m_eventQueue);
        if (FAILED(hr)) return hr;

        // Configure 720p30 NV12 video media type
        IMFMediaType* mediaType = nullptr;
        hr = MFCreateMediaType(&mediaType);
        if (FAILED(hr)) return hr;
        mediaType->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video);
        mediaType->SetGUID(MF_MT_SUBTYPE, MFVideoFormat_NV12);
        mediaType->SetUINT32(MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive);
        mediaType->SetUINT32(MF_MT_ALL_SAMPLES_INDEPENDENT, TRUE);
        mediaType->SetUINT32(MF_MT_DEFAULT_STRIDE, kWidth);
        mediaType->SetUINT32(MF_MT_SAMPLE_SIZE, kFrameBytes);
        MFSetAttributeSize(mediaType, MF_MT_FRAME_SIZE, kWidth, kHeight);
        MFSetAttributeRatio(mediaType, MF_MT_FRAME_RATE, kTargetFps, 1);
        MFSetAttributeRatio(mediaType, MF_MT_PIXEL_ASPECT_RATIO, 1, 1);
        mediaType->SetUINT32(MF_MT_AVG_BITRATE, kAvgBitrate);

        // Configure FrameServer stream attributes
        hr = MFCreateAttributes(&m_attributes, 8);
        if (SUCCEEDED(hr)) {
            m_attributes->SetGUID(MF_DEVICESTREAM_STREAM_CATEGORY, PINNAME_VIDEO_CAPTURE);
            m_attributes->SetUINT32(MF_DEVICESTREAM_STREAM_ID, m_streamId);
            m_attributes->SetUINT32(MF_DEVICESTREAM_FRAMESERVER_SHARED, 1);
            m_attributes->SetUINT32(MF_DEVICESTREAM_ATTRIBUTE_FRAMESOURCE_TYPES, MFFrameSourceTypes_Color);
        }

        if (SUCCEEDED(hr)) {
            hr = MFCreateStreamDescriptor(m_streamId, 1, &mediaType, &m_streamDesc);
        }
        if (SUCCEEDED(hr)) {
            IMFMediaTypeHandler* handler = nullptr;
            if (SUCCEEDED(m_streamDesc->GetMediaTypeHandler(&handler))) {
                handler->SetCurrentMediaType(mediaType);
                handler->Release();
            }
            m_streamDesc->SetGUID(MF_DEVICESTREAM_STREAM_CATEGORY, PINNAME_VIDEO_CAPTURE);
            m_streamDesc->SetUINT32(MF_DEVICESTREAM_STREAM_ID, m_streamId);
            m_streamDesc->SetUINT32(MF_DEVICESTREAM_FRAMESERVER_SHARED, 1);
            m_streamDesc->SetUINT32(MF_DEVICESTREAM_ATTRIBUTE_FRAMESOURCE_TYPES, MFFrameSourceTypes_Color);
            m_currentType = mediaType;
            m_currentType->AddRef();
        }
        mediaType->Release();
        return hr;
    }

    // IUnknown
    STDMETHODIMP QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        *ppv = nullptr;
        char buf[128];
        snprintf(buf, sizeof(buf), "MediaStream QI: {%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
            riid.Data1, riid.Data2, riid.Data3,
            riid.Data4[0], riid.Data4[1], riid.Data4[2], riid.Data4[3],
            riid.Data4[4], riid.Data4[5], riid.Data4[6], riid.Data4[7]);
        LogTrace(buf);
        if (riid == IID_IUnknown || riid == IID_IMFMediaEventGenerator ||
            riid == IID_IMFMediaStream || riid == IID_IMFMediaStream2) {
            *ppv = static_cast<IMFMediaStream2*>(this);
        } else if (riid == IID_IMFAttributes) {
            *ppv = static_cast<IMFAttributes*>(this);
        } else if (riid == __uuidof(IKsControl)) {
            *ppv = static_cast<IKsControl*>(this);
        } else {
            return E_NOINTERFACE;
        }
        AddRef();
        return S_OK;
    }
    STDMETHODIMP_(ULONG) AddRef() override { return InterlockedIncrement(&m_ref); }
    STDMETHODIMP_(ULONG) Release() override {
        ULONG c = InterlockedDecrement(&m_ref);
        if (c == 0) delete this;
        return c;
    }

    // IMFMediaEventGenerator
    STDMETHODIMP GetEvent(DWORD dwFlags, IMFMediaEvent** ppEvent) override {
        IMFMediaEventQueue* queue = nullptr;
        {
            CriticalLockGuard lock(m_cs);
            if (m_isShutdown || !m_eventQueue) return MF_E_SHUTDOWN;
            queue = m_eventQueue;
            queue->AddRef();
        }
        HRESULT hr = queue->GetEvent(dwFlags, ppEvent);
        queue->Release();
        return hr;
    }
    STDMETHODIMP BeginGetEvent(IMFAsyncCallback* pCallback, IUnknown* punkState) override {
        CriticalLockGuard lock(m_cs);
        if (m_isShutdown || !m_eventQueue) return MF_E_SHUTDOWN;
        return m_eventQueue->BeginGetEvent(pCallback, punkState);
    }
    STDMETHODIMP EndGetEvent(IMFAsyncResult* pResult, IMFMediaEvent** ppEvent) override {
        CriticalLockGuard lock(m_cs);
        if (m_isShutdown || !m_eventQueue) return MF_E_SHUTDOWN;
        return m_eventQueue->EndGetEvent(pResult, ppEvent);
    }
    STDMETHODIMP QueueEvent(MediaEventType met, REFGUID guidExtendedType, HRESULT hrStatus, const PROPVARIANT* pvValue) override {
        CriticalLockGuard lock(m_cs);
        if (m_isShutdown || !m_eventQueue) return MF_E_SHUTDOWN;
        return m_eventQueue->QueueEventParamVar(met, guidExtendedType, hrStatus, pvValue);
    }

    // IMFMediaStream
    STDMETHODIMP GetMediaSource(IMFMediaSource** ppMediaSource) override {
        if (!ppMediaSource) return E_POINTER;
        *ppMediaSource = nullptr;
        CriticalLockGuard lock(m_cs);
        if (m_isShutdown) return MF_E_SHUTDOWN;
        if (!m_parent) return E_UNEXPECTED;
        *ppMediaSource = m_parent;
        m_parent->AddRef();
        return S_OK;
    }
    STDMETHODIMP GetStreamDescriptor(IMFStreamDescriptor** ppStreamDescriptor) override {
        if (!ppStreamDescriptor) return E_POINTER;
        *ppStreamDescriptor = nullptr;
        CriticalLockGuard lock(m_cs);
        if (m_isShutdown) return MF_E_SHUTDOWN;
        if (!m_streamDesc) return E_UNEXPECTED;
        *ppStreamDescriptor = m_streamDesc;
        m_streamDesc->AddRef();
        return S_OK;
    }

    /// Media Foundation sample request callback.
    ///
    /// Waits on shared memory event for frame pacing (33ms timeout for 30fps),
    /// allocates an IMFSample, locks the buffer using `IMF2DBuffer2` to query pitch,
    /// copies live NV12 video or renders standby frame, and posts `MEMediaSample`.
    STDMETHODIMP RequestSample(IUnknown* pToken) override {
        HANDLE waitEvt = nullptr;
        {
            CriticalLockGuard lock(m_cs);
            if (m_isShutdown || !m_eventQueue) return MF_E_SHUTDOWN;
            if (m_streamState != MF_STREAM_STATE_RUNNING) return MF_E_INVALIDREQUEST;
            EnsureSharedMapping();
            waitEvt = m_frameEvt;
        }
        if (waitEvt) {
            WaitForSingleObject(waitEvt, kFrameIntervalMs);
        } else {
            Sleep(kFrameIntervalMs);
        }

        CriticalLockGuard lock(m_cs);
        if (m_isShutdown || !m_eventQueue) return MF_E_SHUTDOWN;
        if (m_streamState != MF_STREAM_STATE_RUNNING) return MF_E_INVALIDREQUEST;
        if (!m_allocator) return E_UNEXPECTED;

        IMFSample* sample = nullptr;
        HRESULT hr = m_allocator->AllocateSample(&sample);
        if (FAILED(hr) || !sample) return hr;

        IMFMediaBuffer* buffer = nullptr;
        hr = sample->GetBufferByIndex(0, &buffer);
        if (SUCCEEDED(hr) && buffer) {
            IMF2DBuffer2* buf2d = nullptr;
            BYTE* dstPtr = nullptr;
            BYTE* bufStart = nullptr;
            LONG pitch = 0;
            DWORD lockedLen = 0;
            bool locked2D = false;

            // Attempt 2D buffer locking to retrieve stride pitch
            if (SUCCEEDED(buffer->QueryInterface(IID_PPV_ARGS(&buf2d))) && buf2d) {
                hr = buf2d->Lock2DSize(MF2DBuffer_LockFlags_Write, &dstPtr, &pitch, &bufStart, &lockedLen);
                if (SUCCEEDED(hr)) locked2D = true;
            }
            if (!locked2D) {
                DWORD maxLen = 0, curLen = 0;
                hr = buffer->Lock(&dstPtr, &maxLen, &curLen);
                lockedLen = maxLen;
                pitch = static_cast<LONG>(kWidth);
            }

            uint32_t outputFrameBytes = kFrameBytes;
            if (SUCCEEDED(hr) && dstPtr && pitch >= static_cast<LONG>(kWidth)) {
                bool copiedLive = false;
                // Verify publisher heartbeat and sequence freshness
                if (m_shm && m_shm->magic == kShmMagic && m_shm->version == kShmVersion &&
                    m_shm->publisher_alive != 0 && m_shm->seq > 0) {
                    LONG64 seq1 = m_shm->seq;
                    MemoryBarrier();
                    LONG slot = m_shm->active_slot & 1;

                    // Read active geometry from shared memory when valid (even dimensions fitting slot),
                    // falling back safely to compile-time defaults (`kWidth` x `kHeight`).
                    uint32_t activeW = kWidth;
                    uint32_t activeH = kHeight;
                    uint32_t shmW = m_shm->width;
                    uint32_t shmH = m_shm->height;
                    if (shmW > 0 && shmH > 0 &&
                        (shmW & 1u) == 0 && (shmH & 1u) == 0 &&
                        shmW <= kWidth && shmH <= kHeight) {
                        uint64_t expectedBytes = static_cast<uint64_t>(shmW) * static_cast<uint64_t>(shmH) * 3ULL / 2ULL;
                        if (expectedBytes <= kFrameBytes &&
                            (m_shm->frame_bytes == 0 || m_shm->frame_bytes == expectedBytes)) {
                            activeW = shmW;
                            activeH = shmH;
                            outputFrameBytes = static_cast<uint32_t>(expectedBytes);
                        }
                    }

                    if (pitch >= static_cast<LONG>(activeW)) {
                        CopyNV12ToOutput(dstPtr, static_cast<uint32_t>(pitch), lockedLen, m_shm->slots[slot], activeW, activeH);
                        MemoryBarrier();
                        LONG64 seq2 = m_shm->seq;
                        if (seq1 == seq2) {
                            m_lastSeq = seq1;
                            copiedLive = true;
                        }
                    }
                }
                // Fallback to clean standby frame if stream is idling or host is disconnected
                if (!copiedLive) {
                    FillStandbyNV12(dstPtr, static_cast<uint32_t>(pitch), lockedLen, kWidth, kHeight);
                }
            }

            if (locked2D && buf2d) {
                buf2d->Unlock2D();
                buf2d->Release();
            } else {
                buffer->Unlock();
                buffer->SetCurrentLength(outputFrameBytes);
            }
            buffer->Release();
        }

        // Set sample timestamps and target frame duration in 100ns units
        sample->SetSampleTime(MFGetSystemTime());
        sample->SetSampleDuration(kSampleDuration100ns);
        if (pToken) {
            sample->SetUnknown(MFSampleExtension_Token, pToken);
        }
        hr = m_eventQueue->QueueEventParamUnk(MEMediaSample, GUID_NULL, S_OK, sample);
        sample->Release();
        return hr;
    }

    // IMFMediaStream2
    STDMETHODIMP SetStreamState(MF_STREAM_STATE value) override {
        CriticalLockGuard lock(m_cs);
        if (m_isShutdown) return MF_E_SHUTDOWN;
        if (m_streamState == value) return S_OK;
        switch (value) {
        case MF_STREAM_STATE_PAUSED:
            if (m_streamState != MF_STREAM_STATE_RUNNING) return MF_E_INVALID_STATE_TRANSITION;
            m_streamState = MF_STREAM_STATE_PAUSED;
            return S_OK;
        case MF_STREAM_STATE_RUNNING:
            return StartInternal(false);
        case MF_STREAM_STATE_STOPPED:
            return StopInternal(false);
        default:
            return MF_E_INVALID_STATE_TRANSITION;
        }
    }

    STDMETHODIMP GetStreamState(MF_STREAM_STATE* pState) override {
        if (!pState) return E_INVALIDARG;
        CriticalLockGuard lock(m_cs);
        if (m_isShutdown) return MF_E_SHUTDOWN;
        *pState = m_streamState;
        return S_OK;
    }

    // IMFAttributes forwarding
    STDMETHODIMP GetItem(REFGUID k, PROPVARIANT* v) override { return m_attributes ? m_attributes->GetItem(k, v) : MF_E_SHUTDOWN; }
    STDMETHODIMP GetItemType(REFGUID k, MF_ATTRIBUTE_TYPE* t) override { return m_attributes ? m_attributes->GetItemType(k, t) : MF_E_SHUTDOWN; }
    STDMETHODIMP CompareItem(REFGUID k, REFPROPVARIANT v, BOOL* r) override { return m_attributes ? m_attributes->CompareItem(k, v, r) : MF_E_SHUTDOWN; }
    STDMETHODIMP Compare(IMFAttributes* t, MF_ATTRIBUTES_MATCH_TYPE m, BOOL* r) override { return m_attributes ? m_attributes->Compare(t, m, r) : MF_E_SHUTDOWN; }
    STDMETHODIMP GetUINT32(REFGUID k, UINT32* v) override { return m_attributes ? m_attributes->GetUINT32(k, v) : MF_E_SHUTDOWN; }
    STDMETHODIMP GetUINT64(REFGUID k, UINT64* v) override { return m_attributes ? m_attributes->GetUINT64(k, v) : MF_E_SHUTDOWN; }
    STDMETHODIMP GetDouble(REFGUID k, double* v) override { return m_attributes ? m_attributes->GetDouble(k, v) : MF_E_SHUTDOWN; }
    STDMETHODIMP GetGUID(REFGUID k, GUID* v) override { return m_attributes ? m_attributes->GetGUID(k, v) : MF_E_SHUTDOWN; }
    STDMETHODIMP GetStringLength(REFGUID k, UINT32* l) override { return m_attributes ? m_attributes->GetStringLength(k, l) : MF_E_SHUTDOWN; }
    STDMETHODIMP GetString(REFGUID k, LPWSTR s, UINT32 b, UINT32* l) override { return m_attributes ? m_attributes->GetString(k, s, b, l) : MF_E_SHUTDOWN; }
    STDMETHODIMP GetAllocatedString(REFGUID k, LPWSTR* s, UINT32* l) override { return m_attributes ? m_attributes->GetAllocatedString(k, s, l) : MF_E_SHUTDOWN; }
    STDMETHODIMP GetBlobSize(REFGUID k, UINT32* s) override { return m_attributes ? m_attributes->GetBlobSize(k, s) : MF_E_SHUTDOWN; }
    STDMETHODIMP GetBlob(REFGUID k, UINT8* b, UINT32 bs, UINT32* s) override { return m_attributes ? m_attributes->GetBlob(k, b, bs, s) : MF_E_SHUTDOWN; }
    STDMETHODIMP GetAllocatedBlob(REFGUID k, UINT8** b, UINT32* s) override { return m_attributes ? m_attributes->GetAllocatedBlob(k, b, s) : MF_E_SHUTDOWN; }
    STDMETHODIMP GetUnknown(REFGUID k, REFIID r, LPVOID* p) override { return m_attributes ? m_attributes->GetUnknown(k, r, p) : MF_E_SHUTDOWN; }
    STDMETHODIMP SetItem(REFGUID k, REFPROPVARIANT v) override { return m_attributes ? m_attributes->SetItem(k, v) : MF_E_SHUTDOWN; }
    STDMETHODIMP DeleteItem(REFGUID k) override { return m_attributes ? m_attributes->DeleteItem(k) : MF_E_SHUTDOWN; }
    STDMETHODIMP DeleteAllItems() override { return m_attributes ? m_attributes->DeleteAllItems() : MF_E_SHUTDOWN; }
    STDMETHODIMP SetUINT32(REFGUID k, UINT32 v) override { return m_attributes ? m_attributes->SetUINT32(k, v) : MF_E_SHUTDOWN; }
    STDMETHODIMP SetUINT64(REFGUID k, UINT64 v) override { return m_attributes ? m_attributes->SetUINT64(k, v) : MF_E_SHUTDOWN; }
    STDMETHODIMP SetDouble(REFGUID k, double v) override { return m_attributes ? m_attributes->SetDouble(k, v) : MF_E_SHUTDOWN; }
    STDMETHODIMP SetGUID(REFGUID k, REFGUID v) override { return m_attributes ? m_attributes->SetGUID(k, v) : MF_E_SHUTDOWN; }
    STDMETHODIMP SetString(REFGUID k, LPCWSTR v) override { return m_attributes ? m_attributes->SetString(k, v) : MF_E_SHUTDOWN; }
    STDMETHODIMP SetBlob(REFGUID k, const UINT8* b, UINT32 s) override { return m_attributes ? m_attributes->SetBlob(k, b, s) : MF_E_SHUTDOWN; }
    STDMETHODIMP SetUnknown(REFGUID k, IUnknown* u) override { return m_attributes ? m_attributes->SetUnknown(k, u) : MF_E_SHUTDOWN; }
    STDMETHODIMP LockStore() override { return m_attributes ? m_attributes->LockStore() : MF_E_SHUTDOWN; }
    STDMETHODIMP UnlockStore() override { return m_attributes ? m_attributes->UnlockStore() : MF_E_SHUTDOWN; }
    STDMETHODIMP GetCount(UINT32* c) override { return m_attributes ? m_attributes->GetCount(c) : MF_E_SHUTDOWN; }
    STDMETHODIMP GetItemByIndex(UINT32 i, GUID* k, PROPVARIANT* v) override { return m_attributes ? m_attributes->GetItemByIndex(i, k, v) : MF_E_SHUTDOWN; }
    STDMETHODIMP CopyAllItems(IMFAttributes* d) override { return m_attributes ? m_attributes->CopyAllItems(d) : MF_E_SHUTDOWN; }

    // IKsControl (Kernel streaming property handling)
    STDMETHODIMP KsProperty(PKSPROPERTY, ULONG, LPVOID, ULONG, ULONG* pBytesReturned) override {
        if (pBytesReturned) *pBytesReturned = 0;
        return HRESULT_FROM_WIN32(ERROR_SET_NOT_FOUND);
    }
    STDMETHODIMP KsMethod(PKSMETHOD, ULONG, LPVOID, ULONG, ULONG* pBytesReturned) override {
        if (pBytesReturned) *pBytesReturned = 0;
        return HRESULT_FROM_WIN32(ERROR_SET_NOT_FOUND);
    }
    STDMETHODIMP KsEvent(PKSEVENT, ULONG, LPVOID, ULONG, ULONG* pBytesReturned) override {
        if (pBytesReturned) *pBytesReturned = 0;
        return HRESULT_FROM_WIN32(ERROR_SET_NOT_FOUND);
    }

    /// Starts stream delivery with configured media type.
    HRESULT StartStream(IMFMediaType* mediaType) {
        CriticalLockGuard lock(m_cs);
        if (m_isShutdown) return MF_E_SHUTDOWN;
        if (mediaType) {
            if (m_currentType) m_currentType->Release();
            m_currentType = mediaType;
            m_currentType->AddRef();
        }
        return StartInternal(true);
    }

    /// Stops stream sample delivery.
    HRESULT StopStream(bool sendEvent) {
        CriticalLockGuard lock(m_cs);
        if (m_isShutdown) return MF_E_SHUTDOWN;
        return StopInternal(sendEvent);
    }

    /// Binds external video sample allocator (e.g. from FrameServer pipeline).
    HRESULT SetSampleAllocator(IMFVideoSampleAllocator* alloc) {
        CriticalLockGuard lock(m_cs);
        if (m_isShutdown) return MF_E_SHUTDOWN;
        if (m_streamState == MF_STREAM_STATE_RUNNING) return MF_E_INVALIDREQUEST;
        if (m_allocator) m_allocator->Release();
        m_allocator = alloc;
        if (m_allocator) m_allocator->AddRef();
        return S_OK;
    }

    IMFAttributes* AttributesPtr() const { return m_attributes; }
    DWORD StreamId() const { return m_streamId; }

    /// Shuts down stream, releases event queue, and unmaps shared memory.
    void Shutdown() {
        CriticalLockGuard lock(m_cs);
        m_isShutdown = true;
        m_streamState = MF_STREAM_STATE_STOPPED;
        if (m_parent) { m_parent->Release(); m_parent = nullptr; }
        if (m_eventQueue) { m_eventQueue->Shutdown(); m_eventQueue->Release(); m_eventQueue = nullptr; }
        if (m_allocator) { m_allocator->UninitializeSampleAllocator(); m_allocator->Release(); m_allocator = nullptr; }
        if (m_currentType) { m_currentType->Release(); m_currentType = nullptr; }
        if (m_streamDesc) { m_streamDesc->Release(); m_streamDesc = nullptr; }
        if (m_attributes) { m_attributes->Release(); m_attributes = nullptr; }
        CloseSharedMapping();
    }

private:
    /// Maps shared video memory and sync event read-only.
    void EnsureSharedMapping() {
        if (!m_shm) {
            m_shmMap = OpenFileMappingW(FILE_MAP_READ, FALSE, L"Global\\IntegratorVCamShm_v1");
            if (m_shmMap) {
                m_shm = static_cast<SharedVCamMemory*>(
                    MapViewOfFile(m_shmMap, FILE_MAP_READ, 0, 0, sizeof(SharedVCamMemory))
                );
                if (!m_shm) {
                    CloseHandle(m_shmMap);
                    m_shmMap = nullptr;
                }
            }
        }
        if (!m_frameEvt) {
            m_frameEvt = OpenEventW(SYNCHRONIZE, FALSE, L"Global\\IntegratorVCamEvt_v1");
        }
    }

    /// Closes shared memory mapping and event handles.
    void CloseSharedMapping() {
        if (m_shm) { UnmapViewOfFile(const_cast<SharedVCamMemory*>(m_shm)); m_shm = nullptr; }
        if (m_shmMap) { CloseHandle(m_shmMap); m_shmMap = nullptr; }
        if (m_frameEvt) { CloseHandle(m_frameEvt); m_frameEvt = nullptr; }
    }

    HRESULT StartInternal(bool sendEvent) {
        if (!m_allocator) {
            HRESULT hr = MFCreateVideoSampleAllocatorEx(IID_PPV_ARGS(&m_allocator));
            if (FAILED(hr)) return hr;
        }
        if (m_currentType) {
            HRESULT hr = m_allocator->InitializeSampleAllocator(8, m_currentType);
            if (FAILED(hr)) return hr;
        }
        m_streamState = MF_STREAM_STATE_RUNNING;
        if (sendEvent && m_eventQueue) {
            return m_eventQueue->QueueEventParamVar(MEStreamStarted, GUID_NULL, S_OK, nullptr);
        }
        return S_OK;
    }

    HRESULT StopInternal(bool sendEvent) {
        m_streamState = MF_STREAM_STATE_STOPPED;
        if (m_allocator) {
            m_allocator->UninitializeSampleAllocator();
        }
        if (sendEvent && m_eventQueue) {
            return m_eventQueue->QueueEventParamVar(MEStreamStopped, GUID_NULL, S_OK, nullptr);
        }
        return S_OK;
    }

    volatile LONG m_ref;
    CRITICAL_SECTION m_cs{};
    bool m_isShutdown = false;
    DWORD m_streamId = 0;
    MF_STREAM_STATE m_streamState = MF_STREAM_STATE_STOPPED;
    IMFMediaSource* m_parent = nullptr;
    IMFMediaEventQueue* m_eventQueue = nullptr;
    IMFAttributes* m_attributes = nullptr;
    IMFStreamDescriptor* m_streamDesc = nullptr;
    IMFMediaType* m_currentType = nullptr;
    IMFVideoSampleAllocator* m_allocator = nullptr;

    HANDLE m_shmMap = nullptr;
    const SharedVCamMemory* m_shm = nullptr;
    HANDLE m_frameEvt = nullptr;
    LONG64 m_lastSeq = 0;
};

/// Media Foundation capture source representing the "Integrator MacBook Camera".
///
/// Implements `IMFMediaSourceEx` for capture control, `IMFGetService`, `IKsControl`,
/// and `IMFSampleAllocatorControl` for allocator sharing with FrameServer.
class IntegratorMediaSource final :
    public IMFMediaSourceEx,
    public IMFGetService,
    public IKsControl,
    public IMFSampleAllocatorControl {
public:
    IntegratorMediaSource() : m_ref(1) {
        ModuleAddRef();
        InitializeCriticalSection(&m_cs);
    }

    ~IntegratorMediaSource() {
        Shutdown();
        DeleteCriticalSection(&m_cs);
        ModuleRelease();
    }

    /// Initializes event queue, presentation descriptors, and child media stream.
    HRESULT Initialize(IMFAttributes* activateAttrs) {
        LogTrace("IntegratorMediaSource::Initialize start");
        CriticalLockGuard lock(m_cs);
        HRESULT hr = MFCreateEventQueue(&m_eventQueue);
        if (FAILED(hr)) return hr;

        hr = MFCreateAttributes(&m_attributes, 16);
        if (FAILED(hr)) return hr;
        if (activateAttrs) {
            activateAttrs->CopyAllItems(m_attributes);
        }

        m_stream = new IntegratorMediaStream();
        hr = m_stream->Initialize(this, 0);
        if (FAILED(hr)) {
            LogTrace("m_stream->Initialize failed");
            return hr;
        }

        IMFStreamDescriptor* sd = nullptr;
        hr = m_stream->GetStreamDescriptor(&sd);
        if (FAILED(hr)) return hr;

        hr = MFCreatePresentationDescriptor(1, &sd, &m_presDesc);
        sd->Release();
        if (FAILED(hr)) return hr;

        m_presDesc->SelectStream(0);
        m_state = State::Stopped;
        LogTrace("IntegratorMediaSource::Initialize succeeded");
        return S_OK;
    }

    // IUnknown
    STDMETHODIMP QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        *ppv = nullptr;
        char buf[128];
        snprintf(buf, sizeof(buf), "MediaSource QI: {%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
            riid.Data1, riid.Data2, riid.Data3,
            riid.Data4[0], riid.Data4[1], riid.Data4[2], riid.Data4[3],
            riid.Data4[4], riid.Data4[5], riid.Data4[6], riid.Data4[7]);
        LogTrace(buf);
        if (riid == IID_IUnknown || riid == IID_IMFMediaEventGenerator ||
            riid == IID_IMFMediaSource || riid == IID_IMFMediaSourceEx) {
            *ppv = static_cast<IMFMediaSourceEx*>(this);
        } else if (riid == IID_IMFGetService) {
            *ppv = static_cast<IMFGetService*>(this);
        } else if (riid == __uuidof(IKsControl)) {
            *ppv = static_cast<IKsControl*>(this);
        } else if (riid == IID_IMFSampleAllocatorControl) {
            *ppv = static_cast<IMFSampleAllocatorControl*>(this);
        } else if (riid == IID_IMFAttributes) {
            if (m_attributes) {
                return m_attributes->QueryInterface(riid, ppv);
            }
            return E_NOINTERFACE;
        } else {
            return E_NOINTERFACE;
        }
        AddRef();
        return S_OK;
    }
    STDMETHODIMP_(ULONG) AddRef() override { return InterlockedIncrement(&m_ref); }
    STDMETHODIMP_(ULONG) Release() override {
        ULONG c = InterlockedDecrement(&m_ref);
        if (c == 0) delete this;
        return c;
    }

    // IMFMediaEventGenerator
    STDMETHODIMP GetEvent(DWORD dwFlags, IMFMediaEvent** ppEvent) override {
        IMFMediaEventQueue* queue = nullptr;
        {
            CriticalLockGuard lock(m_cs);
            if (m_state == State::Shutdown || !m_eventQueue) return MF_E_SHUTDOWN;
            queue = m_eventQueue;
            queue->AddRef();
        }
        HRESULT hr = queue->GetEvent(dwFlags, ppEvent);
        queue->Release();
        return hr;
    }
    STDMETHODIMP BeginGetEvent(IMFAsyncCallback* pCallback, IUnknown* punkState) override {
        CriticalLockGuard lock(m_cs);
        if (m_state == State::Shutdown || !m_eventQueue) return MF_E_SHUTDOWN;
        return m_eventQueue->BeginGetEvent(pCallback, punkState);
    }
    STDMETHODIMP EndGetEvent(IMFAsyncResult* pResult, IMFMediaEvent** ppEvent) override {
        CriticalLockGuard lock(m_cs);
        if (m_state == State::Shutdown || !m_eventQueue) return MF_E_SHUTDOWN;
        return m_eventQueue->EndGetEvent(pResult, ppEvent);
    }
    STDMETHODIMP QueueEvent(MediaEventType met, REFGUID guidExtendedType, HRESULT hrStatus, const PROPVARIANT* pvValue) override {
        CriticalLockGuard lock(m_cs);
        if (m_state == State::Shutdown || !m_eventQueue) return MF_E_SHUTDOWN;
        return m_eventQueue->QueueEventParamVar(met, guidExtendedType, hrStatus, pvValue);
    }

    // IMFMediaSource
    STDMETHODIMP GetCharacteristics(DWORD* pdwCharacteristics) override {
        if (!pdwCharacteristics) return E_POINTER;
        CriticalLockGuard lock(m_cs);
        if (m_state == State::Shutdown) return MF_E_SHUTDOWN;
        *pdwCharacteristics = MFMEDIASOURCE_IS_LIVE;
        return S_OK;
    }
    STDMETHODIMP CreatePresentationDescriptor(IMFPresentationDescriptor** ppPresentationDescriptor) override {
        LogTrace("CreatePresentationDescriptor called");
        if (!ppPresentationDescriptor) return E_POINTER;
        *ppPresentationDescriptor = nullptr;
        CriticalLockGuard lock(m_cs);
        if (m_state == State::Shutdown || !m_presDesc) return MF_E_SHUTDOWN;
        return m_presDesc->Clone(ppPresentationDescriptor);
    }
    STDMETHODIMP Start(IMFPresentationDescriptor* pPD, const GUID* pguidTimeFormat, const PROPVARIANT* pvarStartPos) override {
        CriticalLockGuard lock(m_cs);
        if (m_state == State::Shutdown || !m_stream || !m_eventQueue) return MF_E_SHUTDOWN;
        if (!pPD || !pvarStartPos) return E_INVALIDARG;
        if (pguidTimeFormat && *pguidTimeFormat != GUID_NULL) return MF_E_UNSUPPORTED_TIME_FORMAT;

        DWORD count = 0;
        pPD->GetStreamDescriptorCount(&count);
        if (count == 0) return E_INVALIDARG;

        BOOL selected = FALSE;
        IMFStreamDescriptor* sd = nullptr;
        HRESULT hr = pPD->GetStreamDescriptorByIndex(0, &selected, &sd);
        if (FAILED(hr) || !sd) return E_INVALIDARG;

        IMFMediaType* curMt = nullptr;
        if (selected) {
            IMFMediaTypeHandler* handler = nullptr;
            if (SUCCEEDED(sd->GetMediaTypeHandler(&handler))) {
                handler->GetCurrentMediaType(&curMt);
                handler->Release();
            }
            m_presDesc->SelectStream(0);
            MediaEventType met = m_wasSelected ? MEUpdatedStream : MENewStream;
            m_wasSelected = true;
            m_eventQueue->QueueEventParamUnk(met, GUID_NULL, S_OK, static_cast<IMFMediaStream2*>(m_stream));
            hr = m_stream->StartStream(curMt);
            if (curMt) curMt->Release();
        } else {
            m_presDesc->DeselectStream(0);
            hr = m_stream->StopStream(false);
        }
        sd->Release();
        if (FAILED(hr)) return hr;

        PROPVARIANT startTime;
        InitPropVariantFromInt64(MFGetSystemTime(), &startTime);
        m_eventQueue->QueueEventParamVar(MESourceStarted, GUID_NULL, S_OK, &startTime);
        PropVariantClear(&startTime);
        m_state = State::Started;
        return S_OK;
    }
    STDMETHODIMP Stop() override {
        CriticalLockGuard lock(m_cs);
        if (m_state == State::Shutdown) return MF_E_SHUTDOWN;
        if (m_state != State::Started) return MF_E_INVALID_STATE_TRANSITION;
        m_state = State::Stopped;
        if (m_stream) m_stream->StopStream(true);
        if (m_presDesc) m_presDesc->DeselectStream(0);
        m_wasSelected = false;

        PROPVARIANT stopTime;
        InitPropVariantFromInt64(MFGetSystemTime(), &stopTime);
        if (m_eventQueue) m_eventQueue->QueueEventParamVar(MESourceStopped, GUID_NULL, S_OK, &stopTime);
        PropVariantClear(&stopTime);
        return S_OK;
    }
    STDMETHODIMP Pause() override { return MF_E_INVALID_STATE_TRANSITION; }
    STDMETHODIMP Shutdown() override {
        CriticalLockGuard lock(m_cs);
        if (m_state == State::Shutdown) return S_OK;
        m_state = State::Shutdown;
        if (m_stream) { m_stream->Shutdown(); m_stream->Release(); m_stream = nullptr; }
        if (m_eventQueue) { m_eventQueue->Shutdown(); m_eventQueue->Release(); m_eventQueue = nullptr; }
        if (m_presDesc) { m_presDesc->Release(); m_presDesc = nullptr; }
        if (m_attributes) { m_attributes->Release(); m_attributes = nullptr; }
        return S_OK;
    }

    // IMFMediaSourceEx
    STDMETHODIMP GetSourceAttributes(IMFAttributes** ppAttributes) override {
        LogTrace("GetSourceAttributes called");
        if (!ppAttributes) return E_POINTER;
        CriticalLockGuard lock(m_cs);
        if (m_state == State::Shutdown || !m_attributes) return MF_E_SHUTDOWN;
        *ppAttributes = m_attributes;
        (*ppAttributes)->AddRef();
        return S_OK;
    }
    STDMETHODIMP GetStreamAttributes(DWORD dwStreamIdentifier, IMFAttributes** ppAttributes) override {
        char buf[80];
        snprintf(buf, sizeof(buf), "GetStreamAttributes called for id %lu", dwStreamIdentifier);
        LogTrace(buf);
        if (!ppAttributes) return E_POINTER;
        CriticalLockGuard lock(m_cs);
        if (m_state == State::Shutdown || !m_stream) return MF_E_SHUTDOWN;
        if (dwStreamIdentifier != m_stream->StreamId()) return MF_E_NOT_FOUND;
        return m_stream->QueryInterface(IID_PPV_ARGS(ppAttributes));
    }
    STDMETHODIMP SetD3DManager(IUnknown*) override { return E_NOTIMPL; }

    // IMFGetService
    STDMETHODIMP GetService(REFGUID, REFIID, LPVOID* ppvObject) override {
        if (ppvObject) *ppvObject = nullptr;
        return MF_E_UNSUPPORTED_SERVICE;
    }

    // IKsControl
    STDMETHODIMP KsProperty(PKSPROPERTY, ULONG, LPVOID, ULONG, ULONG* pBytesReturned) override {
        if (pBytesReturned) *pBytesReturned = 0;
        return HRESULT_FROM_WIN32(ERROR_SET_NOT_FOUND);
    }
    STDMETHODIMP KsMethod(PKSMETHOD, ULONG, LPVOID, ULONG, ULONG* pBytesReturned) override {
        if (pBytesReturned) *pBytesReturned = 0;
        return HRESULT_FROM_WIN32(ERROR_SET_NOT_FOUND);
    }
    STDMETHODIMP KsEvent(PKSEVENT, ULONG, LPVOID, ULONG, ULONG* pBytesReturned) override {
        if (pBytesReturned) *pBytesReturned = 0;
        return HRESULT_FROM_WIN32(ERROR_SET_NOT_FOUND);
    }

    // IMFSampleAllocatorControl
    STDMETHODIMP SetDefaultAllocator(DWORD dwOutputStreamID, IUnknown* pAllocator) override {
        CriticalLockGuard lock(m_cs);
        if (m_state == State::Shutdown || !m_stream) return MF_E_SHUTDOWN;
        if (dwOutputStreamID != 0 || !pAllocator) return MF_E_NOT_FOUND;
        IMFVideoSampleAllocator* alloc = nullptr;
        HRESULT hr = pAllocator->QueryInterface(IID_PPV_ARGS(&alloc));
        if (FAILED(hr)) return hr;
        hr = m_stream->SetSampleAllocator(alloc);
        alloc->Release();
        return hr;
    }
    STDMETHODIMP GetAllocatorUsage(DWORD dwOutputStreamID, DWORD* pdwInputStreamID, MFSampleAllocatorUsage* peUsage) override {
        if (!pdwInputStreamID || !peUsage) return E_POINTER;
        CriticalLockGuard lock(m_cs);
        if (m_state == State::Shutdown) return MF_E_SHUTDOWN;
        if (dwOutputStreamID != 0) return MF_E_NOT_FOUND;
        *pdwInputStreamID = 0;
        *peUsage = MFSampleAllocatorUsage_UsesProvidedAllocator;
        return S_OK;
    }

private:
    enum class State { Invalid, Stopped, Started, Shutdown };
    volatile LONG m_ref;
    CRITICAL_SECTION m_cs{};
    State m_state = State::Invalid;
    bool m_wasSelected = false;
    IMFMediaEventQueue* m_eventQueue = nullptr;
    IMFPresentationDescriptor* m_presDesc = nullptr;
    IMFAttributes* m_attributes = nullptr;
    IntegratorMediaStream* m_stream = nullptr;
};

/// COM activation object implementing `IMFActivate` to defer `IntegratorMediaSource` creation until needed.
class IntegratorVCamActivate final : public IMFActivate {
public:
    IntegratorVCamActivate() : m_ref(1) {
        ModuleAddRef();
        MFCreateAttributes(&m_attrs, 16);
        if (m_attrs) {
            m_attrs->SetGUID(MFT_TRANSFORM_CLSID_Attribute, CLSID_IntegratorVCamActivate);
        }
    }
    ~IntegratorVCamActivate() {
        if (m_source) { m_source->Release(); m_source = nullptr; }
        if (m_attrs) { m_attrs->Release(); m_attrs = nullptr; }
        ModuleRelease();
    }

    STDMETHODIMP QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        *ppv = nullptr;
        if (riid == IID_IUnknown || riid == IID_IMFAttributes || riid == IID_IMFActivate) {
            *ppv = static_cast<IMFActivate*>(this);
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }
    STDMETHODIMP_(ULONG) AddRef() override { return InterlockedIncrement(&m_ref); }
    STDMETHODIMP_(ULONG) Release() override {
        ULONG c = InterlockedDecrement(&m_ref);
        if (c == 0) delete this;
        return c;
    }

    // IMFActivate
    STDMETHODIMP ActivateObject(REFIID riid, void** ppv) override {
        LogTrace("ActivateObject called");
        if (!ppv) return E_POINTER;
        *ppv = nullptr;
        if (!m_source) {
            m_source = new IntegratorMediaSource();
            HRESULT hr = m_source->Initialize(m_attrs);
            if (FAILED(hr)) {
                LogTrace("ActivateObject Initialize failed");
                m_source->Release();
                m_source = nullptr;
                return hr;
            }
        }
        return m_source->QueryInterface(riid, ppv);
    }
    STDMETHODIMP ShutdownObject() override {
        if (m_source) {
            m_source->Shutdown();
            m_source->Release();
            m_source = nullptr;
        }
        return S_OK;
    }
    STDMETHODIMP DetachObject() override {
        if (m_source) {
            m_source->Release();
            m_source = nullptr;
        }
        return S_OK;
    }

    // IMFAttributes forwarding
    STDMETHODIMP GetItem(REFGUID k, PROPVARIANT* v) override { return m_attrs ? m_attrs->GetItem(k, v) : MF_E_SHUTDOWN; }
    STDMETHODIMP GetItemType(REFGUID k, MF_ATTRIBUTE_TYPE* t) override { return m_attrs ? m_attrs->GetItemType(k, t) : MF_E_SHUTDOWN; }
    STDMETHODIMP CompareItem(REFGUID k, REFPROPVARIANT v, BOOL* r) override { return m_attrs ? m_attrs->CompareItem(k, v, r) : MF_E_SHUTDOWN; }
    STDMETHODIMP Compare(IMFAttributes* t, MF_ATTRIBUTES_MATCH_TYPE m, BOOL* r) override { return m_attrs ? m_attrs->Compare(t, m, r) : MF_E_SHUTDOWN; }
    STDMETHODIMP GetUINT32(REFGUID k, UINT32* v) override { return m_attrs ? m_attrs->GetUINT32(k, v) : MF_E_SHUTDOWN; }
    STDMETHODIMP GetUINT64(REFGUID k, UINT64* v) override { return m_attrs ? m_attrs->GetUINT64(k, v) : MF_E_SHUTDOWN; }
    STDMETHODIMP GetDouble(REFGUID k, double* v) override { return m_attrs ? m_attrs->GetDouble(k, v) : MF_E_SHUTDOWN; }
    STDMETHODIMP GetGUID(REFGUID k, GUID* v) override { return m_attrs ? m_attrs->GetGUID(k, v) : MF_E_SHUTDOWN; }
    STDMETHODIMP GetStringLength(REFGUID k, UINT32* l) override { return m_attrs ? m_attrs->GetStringLength(k, l) : MF_E_SHUTDOWN; }
    STDMETHODIMP GetString(REFGUID k, LPWSTR s, UINT32 b, UINT32* l) override { return m_attrs ? m_attrs->GetString(k, s, b, l) : MF_E_SHUTDOWN; }
    STDMETHODIMP GetAllocatedString(REFGUID k, LPWSTR* s, UINT32* l) override { return m_attrs ? m_attrs->GetAllocatedString(k, s, l) : MF_E_SHUTDOWN; }
    STDMETHODIMP GetBlobSize(REFGUID k, UINT32* s) override { return m_attrs ? m_attrs->GetBlobSize(k, s) : MF_E_SHUTDOWN; }
    STDMETHODIMP GetBlob(REFGUID k, UINT8* b, UINT32 bs, UINT32* s) override { return m_attrs ? m_attrs->GetBlob(k, b, bs, s) : MF_E_SHUTDOWN; }
    STDMETHODIMP GetAllocatedBlob(REFGUID k, UINT8** b, UINT32* s) override { return m_attrs ? m_attrs->GetAllocatedBlob(k, b, s) : MF_E_SHUTDOWN; }
    STDMETHODIMP GetUnknown(REFGUID k, REFIID r, LPVOID* p) override { return m_attrs ? m_attrs->GetUnknown(k, r, p) : MF_E_SHUTDOWN; }
    STDMETHODIMP SetItem(REFGUID k, REFPROPVARIANT v) override { return m_attrs ? m_attrs->SetItem(k, v) : MF_E_SHUTDOWN; }
    STDMETHODIMP DeleteItem(REFGUID k) override { return m_attrs ? m_attrs->DeleteItem(k) : MF_E_SHUTDOWN; }
    STDMETHODIMP DeleteAllItems() override { return m_attrs ? m_attrs->DeleteAllItems() : MF_E_SHUTDOWN; }
    STDMETHODIMP SetUINT32(REFGUID k, UINT32 v) override { return m_attrs ? m_attrs->SetUINT32(k, v) : MF_E_SHUTDOWN; }
    STDMETHODIMP SetUINT64(REFGUID k, UINT64 v) override { return m_attrs ? m_attrs->SetUINT64(k, v) : MF_E_SHUTDOWN; }
    STDMETHODIMP SetDouble(REFGUID k, double v) override { return m_attrs ? m_attrs->SetDouble(k, v) : MF_E_SHUTDOWN; }
    STDMETHODIMP SetGUID(REFGUID k, REFGUID v) override { return m_attrs ? m_attrs->SetGUID(k, v) : MF_E_SHUTDOWN; }
    STDMETHODIMP SetString(REFGUID k, LPCWSTR v) override { return m_attrs ? m_attrs->SetString(k, v) : MF_E_SHUTDOWN; }
    STDMETHODIMP SetBlob(REFGUID k, const UINT8* b, UINT32 s) override { return m_attrs ? m_attrs->SetBlob(k, b, s) : MF_E_SHUTDOWN; }
    STDMETHODIMP SetUnknown(REFGUID k, IUnknown* u) override { return m_attrs ? m_attrs->SetUnknown(k, u) : MF_E_SHUTDOWN; }
    STDMETHODIMP LockStore() override { return m_attrs ? m_attrs->LockStore() : MF_E_SHUTDOWN; }
    STDMETHODIMP UnlockStore() override { return m_attrs ? m_attrs->UnlockStore() : MF_E_SHUTDOWN; }
    STDMETHODIMP GetCount(UINT32* c) override { return m_attrs ? m_attrs->GetCount(c) : MF_E_SHUTDOWN; }
    STDMETHODIMP GetItemByIndex(UINT32 i, GUID* k, PROPVARIANT* v) override { return m_attrs ? m_attrs->GetItemByIndex(i, k, v) : MF_E_SHUTDOWN; }
    STDMETHODIMP CopyAllItems(IMFAttributes* d) override { return m_attrs ? m_attrs->CopyAllItems(d) : MF_E_SHUTDOWN; }

private:
    volatile LONG m_ref;
    IMFAttributes* m_attrs = nullptr;
    IntegratorMediaSource* m_source = nullptr;
};

/// COM Class Factory for instantiating `IntegratorVCamActivate` or direct `IntegratorMediaSource`.
class IntegratorClassFactory final : public IClassFactory {
public:
    IntegratorClassFactory() : m_ref(1) { ModuleAddRef(); }
    ~IntegratorClassFactory() { ModuleRelease(); }

    STDMETHODIMP QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        *ppv = nullptr;
        if (riid == IID_IUnknown || riid == IID_IClassFactory) {
            *ppv = static_cast<IClassFactory*>(this);
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }
    STDMETHODIMP_(ULONG) AddRef() override { return InterlockedIncrement(&m_ref); }
    STDMETHODIMP_(ULONG) Release() override {
        ULONG c = InterlockedDecrement(&m_ref);
        if (c == 0) delete this;
        return c;
    }
    STDMETHODIMP CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppvObject) override {
        LogTrace("CreateInstance called");
        if (pUnkOuter) return CLASS_E_NOAGGREGATION;
        if (!ppvObject) return E_POINTER;
        *ppvObject = nullptr;
        if (riid == IID_IMFMediaSource || riid == IID_IMFMediaSourceEx) {
            LogTrace("CreateInstance activating MediaSource directly");
            IntegratorMediaSource* src = new IntegratorMediaSource();
            HRESULT hr = src->Initialize(nullptr);
            if (FAILED(hr)) {
                src->Release();
                return hr;
            }
            hr = src->QueryInterface(riid, ppvObject);
            src->Release();
            return hr;
        }
        IntegratorVCamActivate* act = new IntegratorVCamActivate();
        HRESULT hr = act->QueryInterface(riid, ppvObject);
        act->Release();
        return hr;
    }
    STDMETHODIMP LockServer(BOOL fLock) override {
        if (fLock) ModuleAddRef();
        else ModuleRelease();
        return S_OK;
    }
private:
    volatile LONG m_ref;
};

} // namespace

// ============================================================================
// STANDARD COM DLL EXPORTS
// ============================================================================

/// DLL entry point managing Media Foundation startup and shutdown per process attach/detach.
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        LogTrace("DllMain DLL_PROCESS_ATTACH");
    } else if (ul_reason_for_call == DLL_PROCESS_DETACH) {
        LogTrace("DllMain DLL_PROCESS_DETACH");
    }
    return TRUE;
}

/// Standard COM export returning whether the DLL has active references.
STDAPI DllCanUnloadNow() {
    return g_moduleRefCount == 0 ? S_OK : S_FALSE;
}

/// Standard COM export instantiating the class factory for `CLSID_IntegratorVCamActivate`.
STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID* ppv) {
    LogTrace("DllGetClassObject called");
    if (!ppv) return E_POINTER;
    *ppv = nullptr;
    if (rclsid == CLSID_IntegratorVCamActivate) {
        LogTrace("DllGetClassObject CLSID matched");
        IntegratorClassFactory* cf = new IntegratorClassFactory();
        HRESULT hr = cf->QueryInterface(riid, ppv);
        cf->Release();
        return hr;
    }
    LogTrace("DllGetClassObject CLSID NOT matched");
    return CLASS_E_CLASSNOTAVAILABLE;
}
