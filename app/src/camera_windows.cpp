/*
 * ============================================================================
 * Integrator Shared Camera: Windows 11 Virtual Camera Host & Shared Memory Manager
 * ============================================================================
 *
 * 1. MODULE PURPOSE & ARCHITECTURAL SCOPE
 * ----------------------------------------------------------------------------
 * This module owns the Windows 11 host-side lifecycle of the "Integrator Mac
 * Camera" virtual webcam. It is responsible for:
 * 1. Safe installation and HKLM COM registration of `integrator_vcam.dll`
 *    (`CLSID_IntegratorVCamActivate`: {8E4A6D21-7C4B-4F31-9B18-3A62F4B7E912}).
 * 2. Configuring protected NTFS Access Control Lists (ACLs) so that the Windows
 *    Camera Frame Server service (`svchost.exe -k CameraService`, running as
 *    `NT AUTHORITY\LOCAL SERVICE`) and UWP AppContainers can load the COM DLL.
 * 3. Allocating and managing double-buffered, ACL-hardened shared memory
 *    (`Global\IntegratorVCamShm_v1`) and synchronization events (`Global\IntegratorVCamEvt_v1`).
 * 4. Activating the virtual camera via Windows 11 Media Foundation Virtual Camera
 *    API (`MFCreateVirtualCamera` in `mfsensorgroup.dll`).
 * 5. Providing high-performance lock-free ingestion (`integrator_win_vcam_push_nv12`)
 *    from the Rust network receiver loop into the shared memory ping-pong slots.
 *
 * 2. END-TO-END CROSS-OS FRAME FLOW
 * ----------------------------------------------------------------------------
 * 1. Capture (Mac):
 *    Mac camera (built-in FaceTime HD, external USB, or Continuity Camera) captured at 720p30 NV12 by AVFoundation (`camera_macos.swift`).
 * 2. Wire Streaming:
 *    Transported over encrypted `TransportSessionV2` (port 58287, ChaCha20-Poly1305)
 *    to the Windows receiver in `camera/mod.rs`.
 * 3. Lock-Free Ingestion (This File):
 *    `integrator_win_vcam_push_nv12` copies incoming 1,382,400-byte NV12 payloads
 *    into the inactive shared memory slot, issues a hardware `MemoryBarrier()`,
 *    updates presentation timestamps (100-nanosecond units for Media Foundation),
 *    toggles `active_slot`, increments `seq` via `InterlockedIncrement64`, and pulses
 *    `Global\IntegratorVCamEvt_v1`.
 * 4. Standalone Virtual Camera Output (Windows 11 FrameServer):
 *    `integrator_vcam.dll` (running inside FrameServer / client process) wakes,
 *    reads the active slot, packs samples via `IMF2DBuffer2::Lock2DSize`, and feeds
 *    standard Windows applications (Teams, Zoom, Discord, OBS, Edge) without
 *    requiring physical camera wrappers or third-party drivers.
 *
 * 3. STANDALONE VIRTUAL CAMERA CONTRACT & DRIVERLESS OPERATION
 * ----------------------------------------------------------------------------
 * Traditional virtual cameras often install kernel-mode virtual drivers or act as
 * source wrappers over an existing physical webcam. In Integrator, the camera
 * is created with:
 * - `MFVirtualCameraType_SoftwareCameraSource`: Standalone direct software source.
 * - `MFVirtualCameraLifetime_Session`: Camera unregisters automatically when session closes.
 * - `MFVirtualCameraAccess_AllUsers` / `CurrentUser`: Accessible system-wide across all apps.
 * - **Crucial Contract Invariant**: We deliberately OMIT the attribute
 *   `MF_VIRTUALCAMERA_PROVIDE_ASSOCIATED_CAMERA_SOURCES`. This guarantees that
 *   Windows 11 Media Foundation treats our virtual camera as a fully autonomous
 *   software video device, requiring zero physical camera hardware and zero third-party
 *   filter drivers on the PC.
 *
 * 4. THREADING & CONCURRENCY MODEL
 * ----------------------------------------------------------------------------
 * - State Management: `std::mutex g_lock` serializes start, stop, and active queries.
 * - High-Rate Ingestion: `integrator_win_vcam_push_nv12` is completely lock-free!
 *   It performs slot ping-ponging using `MemoryBarrier` and `InterlockedIncrement64`,
 *   ensuring zero jitter or lock contention at 30 fps.
 *
 * 5. SECURITY & ACL HARDENING INVARIANTS
 * ----------------------------------------------------------------------------
 * Both the installed DLL file and the Win32 shared memory / event objects are protected
 * with precise SDDL security descriptors:
 * - DLL File SDDL: SYSTEM (Full), Administrators (Full), LOCAL SERVICE (Read/Execute),
 *   ALL APPLICATION PACKAGES (Read/Execute), Users (Read/Execute).
 * - Shared Memory SDDL: SYSTEM (Full), Administrators (Full), LOCAL SERVICE (Read-Only),
 *   ALL APPLICATION PACKAGES (Read-Only).
 * This prevents unprivileged processes from corrupting or spoofing video memory while
 * granting Windows FrameServer and sandbox UWP containers clean access.
 * ============================================================================
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <objbase.h>
#include <mfapi.h>
#include <mfidl.h>
#include <mfvirtualcamera.h>
#include <sddl.h>
#include <aclapi.h>
#include <shlobj.h>
#include <knownfolders.h>
#include <shlwapi.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <mutex>

namespace {

/// Four-character shared memory identification magic ("IVCM" = Integrator Virtual Camera Memory).
constexpr uint32_t kShmMagic = 0x4D435649;

/// Shared memory layout version number.
constexpr uint32_t kShmVersion = 1;

/// Video frame width in pixels (720p).
constexpr uint32_t kWidth = 1280;

/// Video frame height in pixels (720p).
constexpr uint32_t kHeight = 720;

/// Total byte size of one 1280x720 NV12 frame (1,382,400 bytes).
constexpr uint32_t kFrameBytes = kWidth * kHeight * 3 / 2;

/// Dark neutral grey Y (luma) byte value used for initial standby frames.
constexpr uint8_t kStandbyLumaY = 22;

/// Neutral chroma (Cb/Cr) byte value used for initial standby frames.
constexpr uint8_t kStandbyChromaUV = 128;

/// Application subdirectory name created inside Program Files for COM DLL registration.
constexpr wchar_t kAppSubdirName[] = L"Integrator";

#pragma pack(push, 1)
/// Double-buffered shared memory header and slot storage layout.
///
/// Allocated in `Global\IntegratorVCamShm_v1` and mapped by both the host process
/// and the `integrator_vcam.dll` Media Foundation COM in-process server.
struct SharedVCamMemory {
    /// Magic header identifier (must match [`kShmMagic`]).
    uint32_t magic;
    /// Layout version (must match [`kShmVersion`]).
    uint32_t version;
    /// Frame width in pixels (1280).
    uint32_t width;
    /// Frame height in pixels (720).
    uint32_t height;
    /// Byte length of one raw frame slot (1,382,400 bytes).
    uint32_t frame_bytes;
    /// Index of the currently completed slot available for reading (0 or 1).
    volatile LONG active_slot;
    /// Monotonically increasing sequence number incremented upon every pushed frame.
    volatile LONG64 seq;
    /// Presentation timestamp in 100-nanosecond units (Media Foundation standard time format).
    volatile LONG64 timestamp_100ns;
    /// Heartbeat flag set to 1 while the host process actively publishes frames.
    volatile LONG publisher_alive;
    /// 32-bit alignment padding.
    uint32_t reserved;
    /// Double-buffered ping-pong frame storage slots (Slot 0 and Slot 1).
    uint8_t slots[2][kFrameBytes];
};
#pragma pack(pop)

/// CLSID string of the virtual camera activate COM class.
constexpr wchar_t kClsidStr[] = L"{8E4A6D21-7C4B-4F31-9B18-3A62F4B7E912}";

/// Default user-facing friendly display name shown in Windows Device Manager and camera menus.
constexpr wchar_t kFriendlyName[] = L"Integrator Mac Camera";

/// Resolves the active virtual camera friendly name, allowing an `INTEGRATOR_CAMERA_NAME`
/// environment variable override while falling back safely to [`kFriendlyName`].
void ResolveFriendlyCameraName(wchar_t* outBuf, DWORD capChars) {
    if (!outBuf || capChars == 0) return;
    DWORD len = GetEnvironmentVariableW(L"INTEGRATOR_CAMERA_NAME", outBuf, capChars);
    if (len > 0 && len < capChars) {
        // Trim leading/trailing whitespace check: fall back if blank.
        bool hasNonSpace = false;
        for (DWORD i = 0; i < len; ++i) {
            if (outBuf[i] != L' ' && outBuf[i] != L'\t' && outBuf[i] != L'\r' && outBuf[i] != L'\n') {
                hasNonSpace = true;
                break;
            }
        }
        if (hasNonSpace) return;
    }
    _snwprintf_s(outBuf, capChars, _TRUNCATE, L"%s", kFriendlyName);
}

/// Mutex protecting global virtual camera state transitions.
std::mutex g_lock;

/// Win32 file mapping handle for shared video memory (`Global\IntegratorVCamShm_v1`).
HANDLE g_hMap = nullptr;

/// Pointer to mapped shared memory view.
SharedVCamMemory* g_shm = nullptr;

/// Win32 auto-reset synchronization event signaled when a new frame is published.
HANDLE g_hEvent = nullptr;

/// Active Windows 11 Media Foundation virtual camera COM interface pointer.
IMFVirtualCamera* g_virtualCamera = nullptr;

/// Flag indicating whether Media Foundation runtime has been initialized via `MFStartup`.
bool g_mfStarted = false;

/// Writes a null-terminated error string safely into an output buffer.
///
/// - Parameters:
///   - buf: Destination character buffer.
///   - cap: Buffer capacity in bytes.
///   - msg: Error message string.
void WriteErr(char* buf, int32_t cap, const char* msg) {
    if (!buf || cap <= 0) return;
    std::snprintf(buf, static_cast<size_t>(cap), "%s", msg ? msg : "unknown error");
}

/// Applies protected NTFS Access Control Lists to the installed COM DLL file.
///
/// Ensures `NT AUTHORITY\LOCAL SERVICE` (Windows FrameServer service) and AppContainers
/// have read/execute permissions to load `integrator_vcam.dll`.
///
/// - Parameter path: Full filesystem path to the DLL in `Program Files\Integrator`.
/// - Returns: `true` if ACL was successfully applied; otherwise `false`.
bool GrantServiceReadExecuteAcl(const wchar_t* path) {
    PSECURITY_DESCRIPTOR pSd = nullptr;
    // SDDL Explanation:
    // O:BA - Owner: Built-in Administrators
    // G:BA - Group: Built-in Administrators
    // D:PAI - DACL: Protected, Auto-Inherit
    // (A;;FA;;;SY)      - Allow Full Access to SYSTEM
    // (A;;FA;;;BA)      - Allow Full Access to Builtin Administrators
    // (A;;0x1200A9;;;LS) - Allow Read & Execute (0x1200A9) to LOCAL SERVICE (FrameServer)
    // (A;;0x1200A9;;;AC) - Allow Read & Execute to ALL APPLICATION PACKAGES (UWP apps)
    // (A;;0x1200A9;;;BU) - Allow Read & Execute to Builtin Users
    const wchar_t* sddl =
        L"O:BAG:BAD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200A9;;;LS)(A;;0x1200A9;;;AC)(A;;0x1200A9;;;BU)";
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &pSd, nullptr)) {
        return false;
    }
    PACL dacl = nullptr;
    BOOL present = FALSE;
    BOOL defaulted = FALSE;
    bool ok = false;
    if (GetSecurityDescriptorDacl(pSd, &present, &dacl, &defaulted) && present) {
        DWORD res = SetNamedSecurityInfoW(
            const_cast<wchar_t*>(path),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            nullptr, nullptr, dacl, nullptr);
        ok = (res == ERROR_SUCCESS);
    }
    LocalFree(pSd);
    return ok;
}

/// Copies `integrator_vcam.dll` into `Program Files\Integrator`, applies ACLs, and registers CLSID in HKLM.
///
/// - Parameters:
///   - installedPathOut: Output buffer receiving installed DLL destination path.
///   - capChars: Capacity of output buffer in wide characters.
///   - errBuf: Output buffer for error description.
///   - errCap: Capacity of error buffer in bytes.
/// - Returns: `true` on successful installation and registration; otherwise `false`.
bool InstallAndRegisterVCamDll(wchar_t* installedPathOut, DWORD capChars, char* errBuf, int32_t errCap) {
    wchar_t exeDir[MAX_PATH] = {};
    if (GetModuleFileNameW(nullptr, exeDir, MAX_PATH) == 0) {
        WriteErr(errBuf, errCap, "GetModuleFileNameW failed");
        return false;
    }
    PathRemoveFileSpecW(exeDir);

    wchar_t sourceDll[MAX_PATH] = {};
    _snwprintf_s(sourceDll, MAX_PATH, _TRUNCATE, L"%s\\integrator_vcam.dll", exeDir);
    if (GetFileAttributesW(sourceDll) == INVALID_FILE_ATTRIBUTES) {
        WriteErr(errBuf, errCap, "integrator_vcam.dll not found alongside executable");
        return false;
    }

    wchar_t progFiles[MAX_PATH] = {};
    PWSTR knownPath = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_ProgramFiles, 0, nullptr, &knownPath)) && knownPath) {
        _snwprintf_s(progFiles, MAX_PATH, _TRUNCATE, L"%s", knownPath);
        CoTaskMemFree(knownPath);
    } else if (GetEnvironmentVariableW(L"ProgramFiles", progFiles, MAX_PATH) == 0) {
        WriteErr(errBuf, errCap, "Failed to resolve Program Files folder path");
        return false;
    }

    wchar_t installDir[MAX_PATH] = {};
    _snwprintf_s(installDir, MAX_PATH, _TRUNCATE, L"%s\\%s", progFiles, kAppSubdirName);
    CreateDirectoryW(installDir, nullptr);

    _snwprintf_s(installedPathOut, capChars, _TRUNCATE, L"%s\\integrator_vcam.dll", installDir);

    // Replace existing COM DLL safely even if previously loaded in FrameServer.
    if (!CopyFileW(sourceDll, installedPathOut, FALSE)) {
        if (GetFileAttributesW(installedPathOut) == INVALID_FILE_ATTRIBUTES) {
            WriteErr(errBuf, errCap, "Failed to install integrator_vcam.dll into Program Files (Admin required)");
            return false;
        }
    }
    GrantServiceReadExecuteAcl(installedPathOut);

    // Register CLSID in HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{8E4A6D21-7C4B-4F31-9B18-3A62F4B7E912}
    wchar_t friendlyName[128] = {};
    ResolveFriendlyCameraName(friendlyName, 128);
    wchar_t regPath[256] = {};
    _snwprintf_s(regPath, 256, _TRUNCATE, L"SOFTWARE\\Classes\\CLSID\\%s", kClsidStr);
    HKEY hKey = nullptr;
    LONG rc = RegCreateKeyExW(HKEY_LOCAL_MACHINE, regPath, 0, nullptr, 0, KEY_WRITE, nullptr, &hKey, nullptr);
    if (rc != ERROR_SUCCESS) {
        WriteErr(errBuf, errCap, "Failed to register CLSID in HKLM (run as Administrator)");
        return false;
    }
    RegSetValueExW(hKey, nullptr, 0, REG_SZ, reinterpret_cast<const BYTE*>(friendlyName),
                   static_cast<DWORD>((wcslen(friendlyName) + 1) * sizeof(wchar_t)));

    HKEY hInproc = nullptr;
    rc = RegCreateKeyExW(hKey, L"InprocServer32", 0, nullptr, 0, KEY_WRITE, nullptr, &hInproc, nullptr);
    RegCloseKey(hKey);
    if (rc != ERROR_SUCCESS) {
        WriteErr(errBuf, errCap, "Failed to create InprocServer32 COM registry key");
        return false;
    }
    RegSetValueExW(hInproc, nullptr, 0, REG_SZ, reinterpret_cast<const BYTE*>(installedPathOut),
                   static_cast<DWORD>((wcslen(installedPathOut) + 1) * sizeof(wchar_t)));
    const wchar_t threading[] = L"Both";
    RegSetValueExW(hInproc, L"ThreadingModel", 0, REG_SZ, reinterpret_cast<const BYTE*>(threading), sizeof(threading));
    RegCloseKey(hInproc);
    return true;
}

/// Allocates and initializes the double-buffered shared memory region and synchronization event with hardened DACLs.
///
/// - Parameters:
///   - errBuf: Output buffer for error message.
///   - errCap: Capacity of error buffer.
/// - Returns: `true` if shared memory and event are valid and ready; otherwise `false`.
bool EnsureSharedObjects(char* errBuf, int32_t errCap) {
    if (g_shm && g_hEvent) return true;

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = FALSE;

    // DACL for Shared Memory:
    // (A;;GA;;;SY) - SYSTEM: Generic All
    // (A;;GA;;;BA) - Administrators: Generic All
    // (A;;GR;;;LS) - LOCAL SERVICE (FrameServer): Generic Read
    // (A;;GR;;;AC) - ALL APPLICATION PACKAGES: Generic Read
    PSECURITY_DESCRIPTOR pShmSd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;LS)(A;;GR;;;AC)",
            SDDL_REVISION_1, &pShmSd, nullptr)) {
        WriteErr(errBuf, errCap, "Failed to create shared memory DACL");
        return false;
    }
    sa.lpSecurityDescriptor = pShmSd;

    if (!g_hMap) {
        g_hMap = CreateFileMappingW(
            INVALID_HANDLE_VALUE, &sa, PAGE_READWRITE, 0,
            static_cast<DWORD>(sizeof(SharedVCamMemory)),
            L"Global\\IntegratorVCamShm_v1");
        if (!g_hMap) {
            DWORD err = GetLastError();
            LocalFree(pShmSd);
            char msg[160];
            std::snprintf(msg, sizeof(msg), "CreateFileMappingW failed (err=%lu)", static_cast<unsigned long>(err));
            WriteErr(errBuf, errCap, msg);
            return false;
        }
    }
    LocalFree(pShmSd);

    if (!g_shm) {
        g_shm = static_cast<SharedVCamMemory*>(
            MapViewOfFile(g_hMap, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SharedVCamMemory)));
        if (!g_shm) {
            WriteErr(errBuf, errCap, "MapViewOfFile failed");
            return false;
        }
        std::memset(g_shm, 0, sizeof(SharedVCamMemory));
        g_shm->magic = kShmMagic;
        g_shm->version = kShmVersion;
        g_shm->width = kWidth;
        g_shm->height = kHeight;
        g_shm->frame_bytes = kFrameBytes;
        g_shm->active_slot = 0;
        g_shm->seq = 0;
        // Initialize standby NV12 frame (dark neutral grey luma, neutral chroma)
        std::memset(g_shm->slots[0], kStandbyLumaY, kWidth * kHeight);
        std::memset(g_shm->slots[0] + kWidth * kHeight, kStandbyChromaUV, (kWidth * kHeight) / 2);
        std::memcpy(g_shm->slots[1], g_shm->slots[0], kFrameBytes);
    }

    if (!g_hEvent) {
        // Event DACL: SYNCHRONIZE access (0x00100000) for LOCAL SERVICE and AppContainers
        PSECURITY_DESCRIPTOR pEvtSd = nullptr;
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00100000;;;LS)(A;;0x00100000;;;AC)",
            SDDL_REVISION_1, &pEvtSd, nullptr);
        SECURITY_ATTRIBUTES evtSa{ sizeof(evtSa), pEvtSd, FALSE };
        g_hEvent = CreateEventW(&evtSa, FALSE, FALSE, L"Global\\IntegratorVCamEvt_v1");
        if (pEvtSd) LocalFree(pEvtSd);
    }
    return g_shm && g_hEvent;
}

} // namespace

extern "C" {

/// Activates the Windows 11 virtual camera, registers COM in-process server, and initializes shared memory.
///
/// - Parameters:
///   - err_buf: Output buffer for error description on failure.
///   - err_cap: Size of error buffer in bytes.
/// - Returns: `0` on success, negative error code on failure.
int32_t integrator_win_vcam_start(char* err_buf, int32_t err_cap) {
    std::lock_guard<std::mutex> guard(g_lock);
    if (g_virtualCamera) {
        if (g_shm) g_shm->publisher_alive = 1;
        return 0;
    }

    wchar_t installedPath[MAX_PATH] = {};
    if (!InstallAndRegisterVCamDll(installedPath, MAX_PATH, err_buf, err_cap)) {
        return -1;
    }
    if (!EnsureSharedObjects(err_buf, err_cap)) {
        return -2;
    }

    CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (!g_mfStarted) {
        if (SUCCEEDED(MFStartup(MF_VERSION))) {
            g_mfStarted = true;
        }
    }

    // Dynamically resolve Windows 11 MFCreateVirtualCamera entry point
    using PFN_MFCreateVirtualCamera = HRESULT(STDAPICALLTYPE*)(
        MFVirtualCameraType,
        MFVirtualCameraLifetime,
        MFVirtualCameraAccess,
        LPCWSTR,
        LPCWSTR,
        const GUID*,
        ULONG,
        IMFVirtualCamera**
    );
    HMODULE hMfSensorGroup = LoadLibraryW(L"mfsensorgroup.dll");
    auto pfnCreateVCam = hMfSensorGroup
        ? reinterpret_cast<PFN_MFCreateVirtualCamera>(
              GetProcAddress(hMfSensorGroup, "MFCreateVirtualCamera"))
        : nullptr;
    if (!pfnCreateVCam) {
        WriteErr(err_buf, err_cap, "Windows 11 mfsensorgroup.dll (MFCreateVirtualCamera) unavailable");
        return -3;
    }

    wchar_t friendlyName[128] = {};
    ResolveFriendlyCameraName(friendlyName, 128);

    // Register standalone software camera source (zero physical camera source wrapper attributes)
    HRESULT hr = pfnCreateVCam(
        MFVirtualCameraType_SoftwareCameraSource,
        MFVirtualCameraLifetime_Session,
        MFVirtualCameraAccess_AllUsers,
        friendlyName,
        kClsidStr,
        nullptr,
        0,
        &g_virtualCamera);
    if (FAILED(hr)) {
        hr = pfnCreateVCam(
            MFVirtualCameraType_SoftwareCameraSource,
            MFVirtualCameraLifetime_Session,
            MFVirtualCameraAccess_CurrentUser,
            friendlyName,
            kClsidStr,
            nullptr,
            0,
            &g_virtualCamera);
    }
    if (FAILED(hr) || !g_virtualCamera) {
        char msg[160];
        std::snprintf(msg, sizeof(msg), "MFCreateVirtualCamera failed (hr=0x%08lX)", static_cast<unsigned long>(hr));
        WriteErr(err_buf, err_cap, msg);
        return -3;
    }

    hr = g_virtualCamera->Start(nullptr);
    if (FAILED(hr)) {
        char msg[160];
        std::snprintf(msg, sizeof(msg), "IMFVirtualCamera::Start failed (hr=0x%08lX)", static_cast<unsigned long>(hr));
        WriteErr(err_buf, err_cap, msg);
        g_virtualCamera->Release();
        g_virtualCamera = nullptr;
        return -4;
    }

    g_shm->publisher_alive = 1;
    SetEvent(g_hEvent);
    return 0;
}

/// Pushes an uncompressed 720p NV12 frame into shared memory using lock-free double-buffered slot ping-pong.
///
/// - Parameters:
///   - data: Raw NV12 pixel buffer (must be exactly 1,382,400 bytes).
///   - len: Length of data buffer in bytes.
///   - timestamp_us: Monotonic presentation timestamp in microseconds.
void integrator_win_vcam_push_nv12(const uint8_t* data, uint32_t len, uint64_t timestamp_us) {
    if (!data || len != kFrameBytes) return;
    SharedVCamMemory* shm = g_shm;
    HANDLE evt = g_hEvent;
    if (!shm) return;

    // Ping-pong to alternate slot (0 -> 1, 1 -> 0)
    LONG nextSlot = (shm->active_slot ^ 1) & 1;
    std::memcpy(shm->slots[nextSlot], data, kFrameBytes);

    // Hardware memory barrier ensures pixel payload is completely committed prior to slot publication
    MemoryBarrier();

    // Convert microsecond timestamp to Media Foundation 100-nanosecond units (1 us = 10 x 100ns)
    shm->timestamp_100ns = static_cast<LONG64>(timestamp_us) * 10;
    shm->active_slot = nextSlot;
    shm->publisher_alive = 1;

    // Atomic increment of sequence number signals consumer of fresh frame arrival
    InterlockedIncrement64(&shm->seq);
    if (evt) SetEvent(evt);
}

/// Tears down the virtual camera, shuts down Media Foundation session, and cleans up shared memory handles.
void integrator_win_vcam_stop() {
    std::lock_guard<std::mutex> guard(g_lock);
    if (g_shm) {
        g_shm->publisher_alive = 0;
    }
    if (g_virtualCamera) {
        g_virtualCamera->Shutdown();
        g_virtualCamera->Remove();
        g_virtualCamera->Release();
        g_virtualCamera = nullptr;
    }
    if (g_hEvent) {
        CloseHandle(g_hEvent);
        g_hEvent = nullptr;
    }
    if (g_shm) {
        UnmapViewOfFile(g_shm);
        g_shm = nullptr;
    }
    if (g_hMap) {
        CloseHandle(g_hMap);
        g_hMap = nullptr;
    }
}

/// Returns whether the virtual camera is currently instantiated and registered in Media Foundation.
int32_t integrator_win_vcam_is_active() {
    std::lock_guard<std::mutex> guard(g_lock);
    return g_virtualCamera != nullptr ? 1 : 0;
}

} // extern "C"
