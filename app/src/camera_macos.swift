/*
 * ============================================================================
 * Integrator Shared Camera & Microphone: macOS AVFoundation Capture Controller
 * ============================================================================
 *
 * 1. MODULE PURPOSE & ARCHITECTURAL SCOPE
 * ----------------------------------------------------------------------------
 * This file implements the native macOS video capture pipeline and microphone
 * discovery/permission/selection bridge for Integrator's Shared Camera & Mic
 * subsystem (`camera` feature). Its responsibilities are:
 * - Interfacing directly with macOS AVFoundation to capture raw video from the
 *   Mac's built-in FaceTime HD Camera, external USB webcam, or Continuity
 *   Camera at 720p30, stripping hardware row-stride padding into tightly
 *   contiguous bi-planar NV12 buffers, and streaming them into the Rust core
 *   via C FFI (`integrator_on_mac_camera_frame`).
 * - Querying and requesting macOS TCC microphone capture permissions
 *   (`AVMediaType.audio`) without ever blocking the main AppKit UI thread.
 * - Enumerating connected macOS audio input devices (built-in microphone,
 *   external USB/Thunderbolt audio interfaces, Continuity/AirPods mics) via
 *   `AVCaptureDevice.DiscoverySession` and persisting thread-safe microphone
 *   selection state for the Shared Camera & Mic pipeline.
 *
 * 2. ARCHITECTURAL LINKAGES & DEPENDENCIES
 * ----------------------------------------------------------------------------
 * - Upstream Callers:
 *   * `app/src/camera/mod.rs`: Invokes `@_cdecl` entry points for camera
 *     permission checks, device enumeration, capture start/stop, and microphone
 *     permission/listing/selection (`integrator_mac_mic_permission_granted`,
 *     `integrator_mac_request_mic_permission`, `integrator_mac_list_mics`,
 *     `integrator_mac_select_mic`).
 * - Downstream Callees:
 *   * `AVFoundation`: `AVCaptureSession`, `AVCaptureDevice`,
 *     `AVCaptureDeviceInput`, `AVCaptureVideoDataOutput`,
 *     `AVCaptureDevice.DiscoverySession`.
 *   * `CoreMedia` & `CoreVideo`: `CMSampleBuffer`, `CVPixelBuffer` plane
 *     locking and stride normalization.
 *   * Rust C-ABI Callback: `integrator_on_mac_camera_frame`.
 * - Cross-Platform / Cross-Device Flow:
 *   1. Capture (macOS):
 *      - `AVCaptureSession` configured with preset `.hd1280x720`.
 *      - Captures the selected or preferred camera (`builtInWideAngleCamera`,
 *        external USB webcam, or Continuity Camera).
 *      - Pixel format forced to `kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange` (NV12 video range).
 *      - Frame rate locked to 30 fps via `videoMinFrameDuration` / `videoMaxFrameDuration` = CMTime(1, 30).
 *   2. Buffer Normalization & Memory Layout (macOS Swift):
 *      - Hardware camera buffers frequently arrive with row padding (stride > width, e.g. 1280 vs 1312).
 *      - `MacCameraCaptureController.captureOutput`:
 *        * Plane 0 (Y / Luma): 1280 x 720 pixels = 921,600 bytes.
 *        * Plane 1 (CbCr / Chroma): 1280 x 360 interleaved bytes (2x2 subsampled) = 460,800 bytes.
 *        * Unpacks rows stripping any hardware stride padding into a tightly packed 1,382,400-byte buffer.
 *   3. Rust Ingestion & Transport (Rust `camera/mod.rs`):
 *      - Invokes `integrator_on_mac_camera_frame` C FFI export.
 *      - Wraps payload in 22-byte `ICAM` binary header with microsecond timestamp.
 *      - Published into `LatestFrameSlot` (dropping old unread frames for 0-latency delivery).
 *      - Streamed over `TransportSessionV2` (TCP port 58287, ChaCha20-Poly1305 AEAD, Ed25519 mutual auth).
 *   4. Windows 11 Media Foundation Virtual Camera (Windows 11):
 *      - Received on Windows TCP :58287, forwarded via `integrator_win_vcam_push_nv12`.
 *      - Pushed into double-buffered ACL-hardened shared memory (`Global\IntegratorVCamShm_v1`).
 *      - Ingested by standalone COM DLL `integrator_vcam.dll` (`Integrator Mac Camera`).
 *      - Windows 11 Media Foundation FrameServer delivers live frames to any consumer (Teams, Zoom, OBS)
 *        without requiring third-party drivers or physical camera source wrapper attributes
 *        (`MF_VIRTUALCAMERA_PROVIDE_ASSOCIATED_CAMERA_SOURCES` is omitted).
 *
 * 3. THREADING & CONCURRENCY MODEL
 * ----------------------------------------------------------------------------
 * - Capture Queue: Dedicated high-priority serial dispatch queue
 *   `com.integrator.camera.capture` (`qos: .userInteractive`).
 * - Mutual Exclusion: `NSLock` guards session lifecycle transitions (`running`,
 *   `session`, `packedBuffer`, `selectedDeviceId`, `selectedMicDeviceId`).
 * - Main-Thread Non-Blocking Guarantee: TCC permission requests check
 *   `Thread.isMainThread` and never block the main UI RunLoop on a semaphore.
 * - Teardown Synchronization: Synchronous `captureQueue.sync` during `stop()`
 *   guarantees no dangling frame callbacks execute after camera stop returns.
 *
 * 4. SECURITY & SAFETY INVARIANTS
 * ----------------------------------------------------------------------------
 * - macOS TCC Enforcement: Inspects `Bundle.main.object(forInfoDictionaryKey:)`
 *   for `NSCameraUsageDescription` and `NSMicrophoneUsageDescription` prior to
 *   invoking TCC prompts in `.app` bundles to prevent fatal `SIGABRT` crashes.
 * - User Privacy: Checks `AVCaptureDevice.authorizationStatus` for `.video` and
 *   `.audio`, bounding background worker waits to 30 seconds via `DispatchSemaphore`.
 * - Strict Buffer Bounds: C-ABI JSON output buffers (`integrator_mac_camera_list_json`,
 *   `integrator_mac_list_mics`) and plane stride pointers validate non-null pointers,
 *   positive capacities, and plane stride >= pixel width before copying memory.
 * ============================================================================
 */

import Foundation
import AVFoundation
import CoreMedia
import CoreVideo

/// C-ABI frame callback exported by Rust (`camera/mod.rs`).
///
/// Passes a contiguous, tightly-packed NV12 frame buffer (1,382,400 bytes for 720p)
/// into the Rust async streaming pipeline.
///
/// - Parameters:
///   - data: Raw pointer to contiguous NV12 byte buffer. Guaranteed valid for the duration of the call.
///   - len: Length of buffer in bytes (must equal 1,382,400 for 1280x720).
///   - width: Frame width in pixels (1280).
///   - height: Frame height in pixels (720).
///   - timestampUs: Microsecond presentation timestamp from `CMSampleBuffer`.
@_silgen_name("integrator_on_mac_camera_frame")
func integrator_on_mac_camera_frame(
    _ data: UnsafePointer<UInt8>,
    _ len: UInt32,
    _ width: UInt32,
    _ height: UInt32,
    _ timestampUs: UInt64
)

/// Default horizontal capture resolution in pixels (720p HD).
private let kDefaultCameraWidth: UInt32 = 1280

/// Default vertical capture resolution in pixels (720p HD).
private let kDefaultCameraHeight: UInt32 = 720

/// Default capture frame rate in frames per second.
private let kDefaultCameraFps: Int32 = 30

/// Timeout in seconds while waiting for the macOS TCC camera or microphone authorization prompt.
private let kCameraAuthTimeoutSec: Int = 30

/// Info.plist key required by macOS TCC for video camera access.
private let kCameraUsageDescPlistKey: String = "NSCameraUsageDescription"

/// Info.plist key required by macOS TCC for audio microphone access.
private let kMicUsageDescPlistKey: String = "NSMicrophoneUsageDescription"

/// Maximum horizontal capture resolution accepted for NV12 stride normalization (8K UHD).
private let kMaxCameraWidth: UInt32 = 7680

/// Maximum vertical capture resolution accepted for NV12 stride normalization (8K UHD).
private let kMaxCameraHeight: UInt32 = 4320

/// Thread-safe synchronization box bridging asynchronous TCC completion callbacks to a bounded wait.
private final class AuthResultBox: @unchecked Sendable {
    /// Lock protecting `granted`.
    private let lock = NSLock()
    /// Recorded authorization outcome (`false` until TCC callback signals completion).
    private var granted = false

    /// Records the TCC authorization result safely from any callback queue.
    func set(_ value: Bool) {
        lock.lock()
        granted = value
        lock.unlock()
    }

    /// Reads the recorded TCC authorization result safely without data races on timeout.
    func get() -> Bool {
        lock.lock()
        let v = granted
        lock.unlock()
        return v
    }
}

/// Singleton controller managing the macOS AVFoundation video capture lifecycle,
/// audio input discovery/selection, and sample buffer delegate callbacks.
private final class MacCameraCaptureController: NSObject, AVCaptureVideoDataOutputSampleBufferDelegate {
    /// Callback signature invoked with each tightly-packed NV12 frame on the capture queue.
    typealias FrameCallback = (UnsafePointer<UInt8>, UInt32, UInt32, UInt32, UInt64) -> Void

    /// Shared singleton instance accessible via C FFI functions.
    static let shared = MacCameraCaptureController()

    /// Mutual exclusion lock guarding session reference, capture geometry, selected device IDs, and running state.
    private let lock = NSLock()

    /// Serial GCD queue executing video sample buffer delivery at interactive priority.
    private let captureQueue = DispatchQueue(label: "com.integrator.camera.capture", qos: .userInteractive)

    /// Active AVFoundation capture session managing input device and video data output.
    private var session: AVCaptureSession?

    /// User-selected or explicitly requested video camera unique device ID.
    private var selectedDeviceId: String?

    /// User-selected or explicitly requested microphone audio input unique device ID.
    private var selectedMicDeviceId: String?

    /// Reusable contiguous heap buffer holding tightly-packed NV12 frame bytes (owned by `captureQueue` while running).
    private var packedBuffer = Data()

    /// Boolean flag indicating whether the capture session is logically active.
    private var running = false

    /// Active horizontal capture resolution in pixels.
    private var targetWidth: UInt32 = kDefaultCameraWidth

    /// Active vertical capture resolution in pixels.
    private var targetHeight: UInt32 = kDefaultCameraHeight

    /// Active capture frame rate in frames per second.
    private var targetFps: Int32 = kDefaultCameraFps

    /// Active frame consumer callback (defaults to the Rust C-ABI export).
    private var frameCallback: FrameCallback = integrator_on_mac_camera_frame

    /// Returns the current macOS TCC camera permission state.
    ///
    /// - Returns:
    ///   - `2`: Authorized.
    ///   - `1`: Denied or Restricted.
    ///   - `0`: Not Determined.
    func permissionState() -> Int32 {
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized:
            return 2
        case .denied, .restricted:
            return 1
        case .notDetermined:
            return 0
        @unknown default:
            return 1
        }
    }

    /// Verifies whether the application bundle's `Info.plist` contains a non-empty `NSCameraUsageDescription`.
    ///
    /// macOS requires this description string; accessing camera hardware without it triggers a fatal `SIGABRT`.
    /// - Returns: `true` if description is present and valid; otherwise `false`.
    func hasUsageDescription() -> Bool {
        guard let desc = Bundle.main.object(forInfoDictionaryKey: kCameraUsageDescPlistKey) as? String else {
            return false
        }
        return !desc.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    /// Verifies whether the current process is safe to trigger an interactive TCC microphone prompt.
    ///
    /// Unbundled CLI test binaries inherit Terminal's TCC context, while `.app` bundles must declare
    /// a non-empty `NSMicrophoneUsageDescription` in `Info.plist` to avoid a TCC `SIGABRT`.
    /// - Returns: `true` if invoking `AVCaptureDevice.requestAccess(for: .audio)` will not abort TCC.
    private func canRequestMicrophoneAccessSafely() -> Bool {
        if !Bundle.main.bundlePath.hasSuffix(".app") {
            return true
        }
        guard let desc = Bundle.main.object(forInfoDictionaryKey: kMicUsageDescPlistKey) as? String else {
            return false
        }
        return !desc.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    /// Requests camera capture permission from the user if not yet determined.
    ///
    /// Never blocks the main thread if invoked on `Thread.isMainThread`.
    ///
    /// - Returns:
    ///   - `2`: Permission granted.
    ///   - `1`: Permission denied or prompt dispatched asynchronously on main thread.
    ///   - `-2`: Bundle missing `NSCameraUsageDescription`.
    func requestPermissionIfNeeded() -> Int32 {
        let current = permissionState()
        if current != 0 {
            return current
        }
        guard hasUsageDescription() else {
            return -2 // Missing NSCameraUsageDescription in bundle Info.plist
        }

        // Never block the main UI thread on a semaphore wait.
        if Thread.isMainThread {
            AVCaptureDevice.requestAccess(for: .video) { _ in }
            return permissionState() == 2 ? 2 : 1
        }

        let sem = DispatchSemaphore(value: 0)
        let box = AuthResultBox()
        AVCaptureDevice.requestAccess(for: .video) { granted in
            box.set(granted)
            sem.signal()
        }
        let waitRes = sem.wait(timeout: .now() + .seconds(kCameraAuthTimeoutSec))
        if waitRes == .timedOut {
            return permissionState() == 2 ? 2 : 1
        }
        return box.get() ? 2 : 1
    }

    /// Returns `true` if macOS TCC microphone authorization is currently `.authorized`.
    ///
    /// - Returns: `true` when `AVCaptureDevice.authorizationStatus(for: .audio) == .authorized`.
    func micPermissionGranted() -> Bool {
        return AVCaptureDevice.authorizationStatus(for: .audio) == .authorized
    }

    /// Requests macOS TCC microphone authorization if `.notDetermined`, waiting up to 30 seconds
    /// when invoked on a background thread and never blocking the main thread if invoked on main.
    ///
    /// - Returns: `true` if microphone access is authorized; `false` otherwise.
    func requestMicPermission() -> Bool {
        let status = AVCaptureDevice.authorizationStatus(for: .audio)
        switch status {
        case .authorized:
            return true
        case .notDetermined:
            guard canRequestMicrophoneAccessSafely() else {
                return false
            }
            if Thread.isMainThread {
                // Dispatch TCC prompt asynchronously without blocking the main AppKit thread.
                AVCaptureDevice.requestAccess(for: .audio) { _ in }
                return AVCaptureDevice.authorizationStatus(for: .audio) == .authorized
            }
            let sem = DispatchSemaphore(value: 0)
            let box = AuthResultBox()
            AVCaptureDevice.requestAccess(for: .audio) { granted in
                box.set(granted)
                sem.signal()
            }
            let waitRes = sem.wait(timeout: .now() + .seconds(kCameraAuthTimeoutSec))
            if waitRes == .timedOut {
                return AVCaptureDevice.authorizationStatus(for: .audio) == .authorized
            }
            return box.get()
        case .denied, .restricted:
            return false
        @unknown default:
            return false
        }
    }

    /// Discovers all connected audio input devices using `AVCaptureDevice.DiscoverySession`.
    ///
    /// Uses `[.microphone, .external]` on macOS 14.0+ and `[.builtInMicrophone, .externalUnknown]`
    /// on earlier macOS versions, filtering out disconnected or suspended devices when active ones exist.
    /// - Returns: Array of discovered `AVCaptureDevice` audio inputs.
    private static func allDiscoveredAudioDevices() -> [AVCaptureDevice] {
        let deviceTypes: [AVCaptureDevice.DeviceType]
        if #available(macOS 14.0, *) {
            deviceTypes = [.microphone, .external]
        } else {
            deviceTypes = [.builtInMicrophone, .externalUnknown]
        }
        let session = AVCaptureDevice.DiscoverySession(
            deviceTypes: deviceTypes,
            mediaType: .audio,
            position: .unspecified
        )
        let active = session.devices.filter { $0.isConnected && !$0.isSuspended }
        return active.isEmpty ? session.devices : active
    }

    /// Serializes discovered audio input devices as a JSON array:
    /// `[{"id":"...","name":"...","is_default":bool}]`.
    ///
    /// Marks `AVCaptureDevice.default(for: .audio)?.uniqueID` with `is_default: true`.
    /// - Returns: UTF-8 JSON array string, or `"[]"` on serialization failure.
    func listMicsJson() -> String {
        let devices = Self.allDiscoveredAudioDevices()
        let defaultId = AVCaptureDevice.default(for: .audio)?.uniqueID ?? ""
        let list: [[String: Any]] = devices.map { dev in
            [
                "id": dev.uniqueID,
                "name": dev.localizedName,
                "is_default": (dev.uniqueID == defaultId)
            ]
        }
        guard let data = try? JSONSerialization.data(withJSONObject: list, options: []),
              let json = String(data: data, encoding: .utf8) else {
            return "[]"
        }
        return json
    }

    /// Validates that an audio input device with `deviceId` exists in the discovery session
    /// and stores the selected microphone unique ID thread-safely.
    ///
    /// - Parameter deviceId: Unique identifier (`AVCaptureDevice.uniqueID`) of the microphone to select.
    /// - Returns: `true` if the device exists and was selected; `false` otherwise.
    func selectMic(deviceId: String) -> Bool {
        let trimmed = deviceId.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return false
        }
        let devices = Self.allDiscoveredAudioDevices()
        guard devices.contains(where: { $0.uniqueID == trimmed }) else {
            return false
        }
        lock.lock()
        self.selectedMicDeviceId = trimmed
        lock.unlock()
        return true
    }

    /// Maps requested pixel dimensions to the closest matching `AVCaptureSession.Preset`.
    ///
    /// - Parameters:
    ///   - width: Desired horizontal width in pixels.
    ///   - height: Desired vertical height in pixels.
    /// - Returns: Closest supported `AVCaptureSession.Preset` (defaults to `.hd1280x720`).
    private static func preferredSessionPreset(width: UInt32, height: UInt32) -> AVCaptureSession.Preset {
        switch (width, height) {
        case (1920, 1080):
            return .hd1920x1080
        case (640, 480):
            return .vga640x480
        default:
            return .hd1280x720
        }
    }

    /// Discovers the preferred video capture device across built-in Mac cameras, external USB webcams
    /// (for Mac mini, Mac Studio, Mac Pro, or docked setups), and Continuity Camera devices.
    ///
    /// - Returns: Best connected video capture device, or `nil` when no camera hardware exists.
    private static func discoverPreferredCameraDevice() -> AVCaptureDevice? {
        if let builtIn = AVCaptureDevice.default(.builtInWideAngleCamera, for: .video, position: .unspecified) {
            return builtIn
        }
        var deviceTypes: [AVCaptureDevice.DeviceType] = [.builtInWideAngleCamera]
        if #available(macOS 14.0, *) {
            deviceTypes.append(.external)
            deviceTypes.append(.continuityCamera)
        } else {
            deviceTypes.append(.externalUnknown)
        }
        let session = AVCaptureDevice.DiscoverySession(
            deviceTypes: deviceTypes,
            mediaType: .video,
            position: .unspecified
        )
        if let discovered = session.devices.first(where: { $0.isConnected && !$0.isSuspended }) ?? session.devices.first {
            return discovered
        }
        return AVCaptureDevice.default(for: .video)
    }

    /// Discovers all connected, non-suspended video capture devices.
    ///
    /// - Returns: Array of active `AVCaptureDevice` video sources.
    private static func allDiscoveredDevices() -> [AVCaptureDevice] {
        var deviceTypes: [AVCaptureDevice.DeviceType] = [.builtInWideAngleCamera]
        if #available(macOS 14.0, *) {
            deviceTypes.append(.external)
            deviceTypes.append(.continuityCamera)
        } else {
            deviceTypes.append(.externalUnknown)
        }
        let session = AVCaptureDevice.DiscoverySession(
            deviceTypes: deviceTypes,
            mediaType: .video,
            position: .unspecified
        )
        return session.devices.filter { $0.isConnected && !$0.isSuspended }
    }

    /// Finds a specific camera device by unique identifier.
    ///
    /// - Parameter id: `AVCaptureDevice.uniqueID` string to match.
    /// - Returns: Matching active device or `nil` if disconnected/unknown.
    private static func discoverDeviceWithId(_ id: String) -> AVCaptureDevice? {
        return allDiscoveredDevices().first { $0.uniqueID == id }
    }

    /// Enumerates all available camera devices as a JSON array string (`[{"id","name","is_active"}]`).
    ///
    /// - Returns: UTF-8 JSON string, or `"[]"` if serialization fails.
    func listCamerasJson() -> String {
        let devices = Self.allDiscoveredDevices()
        lock.lock()
        let activeId = self.selectedDeviceId ?? Self.discoverPreferredCameraDevice()?.uniqueID ?? ""
        lock.unlock()

        let list: [[String: Any]] = devices.map { dev in
            [
                "id": dev.uniqueID,
                "name": dev.localizedName,
                "is_active": (dev.uniqueID == activeId)
            ]
        }
        guard let data = try? JSONSerialization.data(withJSONObject: list, options: []),
              let s = String(data: data, encoding: .utf8) else {
            return "[]"
        }
        return s
    }

    /// Selects a specific camera device by unique ID. If capture is actively running, hot-swaps the device input.
    ///
    /// Constructs the replacement `AVCaptureDeviceInput` prior to modifying the running session and
    /// restores prior inputs if attaching the replacement fails.
    /// - Parameter deviceId: Target `AVCaptureDevice.uniqueID`.
    /// - Returns: `true` on success; `false` if the device is unknown or input swap fails.
    func selectCamera(deviceId: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }

        guard let target = Self.discoverDeviceWithId(deviceId) else {
            return false
        }

        guard let currentSession = self.session, currentSession.isRunning else {
            self.selectedDeviceId = deviceId
            return true
        }

        do {
            // Allocate new input before mutating active session inputs so failure cannot strip camera feed.
            let newInput = try AVCaptureDeviceInput(device: target)
            let oldInputs = currentSession.inputs
            currentSession.beginConfiguration()
            for input in oldInputs {
                currentSession.removeInput(input)
            }
            if currentSession.canAddInput(newInput) {
                currentSession.addInput(newInput)
                currentSession.commitConfiguration()
                self.selectedDeviceId = deviceId
                return true
            }
            for input in oldInputs where currentSession.canAddInput(input) {
                currentSession.addInput(input)
            }
            currentSession.commitConfiguration()
            return false
        } catch {
            return false
        }
    }

    /// Returns `true` if at least one physical, external USB, or Continuity video capture device is present.
    func hasCameraHardware() -> Bool {
        return Self.discoverPreferredCameraDevice() != nil
    }

    /// Configures and starts the AVFoundation camera capture session with explicit geometry, frame rate, and callback.
    ///
    /// - Parameters:
    ///   - width: Desired horizontal resolution in pixels (defaults to `kDefaultCameraWidth`).
    ///   - height: Desired vertical resolution in pixels (defaults to `kDefaultCameraHeight`).
    ///   - fps: Desired capture frame rate in frames per second (defaults to `kDefaultCameraFps`).
    ///   - callback: Frame delivery callback invoked with tightly packed NV12 bytes.
    /// - Returns:
    ///   - `0`: Successfully started.
    ///   - `-1`: Camera permission denied.
    ///   - `-2`: Bundle missing `NSCameraUsageDescription`.
    ///   - `-3`: No camera hardware detected.
    ///   - `-4`: Unable to add camera device input to session.
    ///   - `-5`: Unable to add video data output to session.
    ///   - `-6`: Initialization exception or invalid geometry.
    func startCapture(
        width: UInt32 = kDefaultCameraWidth,
        height: UInt32 = kDefaultCameraHeight,
        fps: Int32 = kDefaultCameraFps,
        callback: @escaping FrameCallback = integrator_on_mac_camera_frame
    ) -> Int32 {
        let resolvedWidth = (width >= 2 && width <= kMaxCameraWidth) ? width : kDefaultCameraWidth
        let resolvedHeight = (height >= 2 && height <= kMaxCameraHeight) ? height : kDefaultCameraHeight
        let resolvedFps = fps > 0 ? fps : kDefaultCameraFps

        lock.lock()
        if running, session?.isRunning == true {
            lock.unlock()
            return 0
        }
        let targetDevId = self.selectedDeviceId
        lock.unlock()

        // Verify that a built-in, external USB, or Continuity camera exists before prompting or starting
        guard let device = (targetDevId.flatMap { Self.discoverDeviceWithId($0) }) ?? Self.discoverPreferredCameraDevice() else {
            return -3
        }

        let auth = requestPermissionIfNeeded()
        if auth == -2 {
            return -2
        }
        if auth != 2 {
            return -1
        }

        do {
            let input = try AVCaptureDeviceInput(device: device)
            let newSession = AVCaptureSession()
            newSession.beginConfiguration()
            let preset = Self.preferredSessionPreset(width: resolvedWidth, height: resolvedHeight)
            if newSession.canSetSessionPreset(preset) {
                newSession.sessionPreset = preset
            } else if newSession.canSetSessionPreset(.hd1280x720) {
                newSession.sessionPreset = .hd1280x720
            } else {
                newSession.sessionPreset = .medium
            }

            guard newSession.canAddInput(input) else {
                newSession.commitConfiguration()
                return -4
            }
            newSession.addInput(input)

            // Configure video output for Bi-Planar NV12 video range
            let output = AVCaptureVideoDataOutput()
            output.alwaysDiscardsLateVideoFrames = true
            output.videoSettings = [
                kCVPixelBufferPixelFormatTypeKey as String: Int(kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange)
            ]
            output.setSampleBufferDelegate(self, queue: captureQueue)

            guard newSession.canAddOutput(output) else {
                newSession.commitConfiguration()
                return -5
            }
            newSession.addOutput(output)

            // Lock frame rate to target FPS (min/max frame duration = 1/fps)
            if let conn = output.connection(with: .video), conn.isVideoMinFrameDurationSupported {
                conn.videoMinFrameDuration = CMTime(value: 1, timescale: resolvedFps)
                conn.videoMaxFrameDuration = CMTime(value: 1, timescale: resolvedFps)
            }
            newSession.commitConfiguration()

            let wInt = Int(resolvedWidth)
            let hInt = Int(resolvedHeight)
            let expectedBytes = (wInt * hInt) + (wInt * (hInt / 2))
            lock.lock()
            self.targetWidth = resolvedWidth
            self.targetHeight = resolvedHeight
            self.targetFps = resolvedFps
            self.frameCallback = callback
            if packedBuffer.count != expectedBytes {
                packedBuffer = Data(count: expectedBytes)
            }
            self.session = newSession
            self.running = true
            lock.unlock()

            newSession.startRunning()
            return 0
        } catch {
            stop()
            return -6
        }
    }

    /// Starts AVFoundation capture using the default 720p30 configuration and Rust C-ABI callback.
    func start() -> Int32 {
        return startCapture(
            width: kDefaultCameraWidth,
            height: kDefaultCameraHeight,
            fps: kDefaultCameraFps,
            callback: integrator_on_mac_camera_frame
        )
    }

    /// Stops the AVFoundation camera capture session and flushes pending capture queue work.
    func stop() {
        lock.lock()
        let activeSession = session
        session = nil
        running = false
        lock.unlock()

        if let s = activeSession {
            // Synchronously stop session on the capture queue to guarantee no trailing callbacks
            captureQueue.sync {
                if s.isRunning {
                    s.stopRunning()
                }
            }
        }
    }

    /// Returns whether the capture session is currently active and capturing video frames.
    func isRunning() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return running && (session?.isRunning == true)
    }

    /// AVFoundation sample buffer delegate callback receiving live video frames.
    ///
    /// Performs row-by-row stride stripping to guarantee contiguous NV12 memory layout
    /// before forwarding the frame across C FFI to Rust.
    func captureOutput(
        _ output: AVCaptureOutput,
        didOutput sampleBuffer: CMSampleBuffer,
        from connection: AVCaptureConnection
    ) {
        lock.lock()
        let active = running
        let expectedWidth = targetWidth
        let expectedHeight = targetHeight
        let callback = frameCallback
        lock.unlock()
        if !active { return }

        guard let pixelBuffer = CMSampleBufferGetImageBuffer(sampleBuffer) else { return }
        let fmt = CVPixelBufferGetPixelFormatType(pixelBuffer)
        guard fmt == kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange
            || fmt == kCVPixelFormatType_420YpCbCr8BiPlanarFullRange
        else { return }

        let width = CVPixelBufferGetWidth(pixelBuffer)
        let height = CVPixelBufferGetHeight(pixelBuffer)
        guard width == Int(expectedWidth), height == Int(expectedHeight) else { return }
        guard CVPixelBufferGetPlaneCount(pixelBuffer) >= 2 else { return }

        // Lock pixel buffer base address for reading
        CVPixelBufferLockBaseAddress(pixelBuffer, .readOnly)
        defer { CVPixelBufferUnlockBaseAddress(pixelBuffer, .readOnly) }

        guard let ySrc = CVPixelBufferGetBaseAddressOfPlane(pixelBuffer, 0),
              let uvSrc = CVPixelBufferGetBaseAddressOfPlane(pixelBuffer, 1)
        else { return }

        let yStride = CVPixelBufferGetBytesPerRowOfPlane(pixelBuffer, 0)
        let uvStride = CVPixelBufferGetBytesPerRowOfPlane(pixelBuffer, 1)
        // Guard against malformed pixel buffers where reported row stride is smaller than pixel width
        guard yStride >= width, uvStride >= width else { return }

        let yPlaneBytes = width * height
        let uvRows = height / 2
        let uvPlaneBytes = width * uvRows
        let totalBytes = yPlaneBytes + uvPlaneBytes

        if packedBuffer.count != totalBytes {
            packedBuffer = Data(count: totalBytes)
        }

        // Copy and compact pixel rows, stripping hardware stride padding if present
        packedBuffer.withUnsafeMutableBytes { rawDst in
            guard let dstBase = rawDst.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return }
            let yPtr = ySrc.assumingMemoryBound(to: UInt8.self)
            let uvPtr = uvSrc.assumingMemoryBound(to: UInt8.self)

            // 1. Pack Plane 0 (Y / Luma)
            if yStride == width {
                // Fast path: contiguous rows without stride padding
                memcpy(dstBase, yPtr, yPlaneBytes)
            } else {
                // Stride normalization: copy row-by-row
                for row in 0..<height {
                    memcpy(dstBase.advanced(by: row * width), yPtr.advanced(by: row * yStride), width)
                }
            }

            // 2. Pack Plane 1 (CbCr / Chroma interleaved)
            let uvDst = dstBase.advanced(by: yPlaneBytes)
            if uvStride == width {
                // Fast path: contiguous chroma rows
                memcpy(uvDst, uvPtr, uvPlaneBytes)
            } else {
                // Stride normalization: copy row-by-row
                for row in 0..<uvRows {
                    memcpy(uvDst.advanced(by: row * width), uvPtr.advanced(by: row * uvStride), width)
                }
            }
        }

        // Calculate presentation timestamp in microseconds
        let pts = CMSampleBufferGetPresentationTimeStamp(sampleBuffer)
        let tsUs: UInt64 = pts.isValid && pts.seconds.isFinite && pts.seconds >= 0
            ? UInt64(pts.seconds * 1_000_000.0)
            : UInt64(DispatchTime.now().uptimeNanoseconds / 1000)

        // Dispatch into Rust core via C FFI
        packedBuffer.withUnsafeBytes { rawBuf in
            guard let ptr = rawBuf.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return }
            callback(ptr, UInt32(totalBytes), expectedWidth, expectedHeight, tsUs)
        }
    }
}

// ============================================================================
// C-ABI FFI EXPORTS (Consumed by Rust `camera/mod.rs`)
// ============================================================================

/// Returns current macOS TCC camera permission state (2: Authorized, 1: Denied, 0: Not Determined).
@_cdecl("integrator_mac_camera_permission_state")
public func integrator_mac_camera_permission_state() -> Int32 {
    return MacCameraCaptureController.shared.permissionState()
}

/// Returns 1 if `Info.plist` defines `NSCameraUsageDescription`, or 0 if missing.
@_cdecl("integrator_mac_camera_has_usage_desc")
public func integrator_mac_camera_has_usage_desc() -> Int32 {
    return MacCameraCaptureController.shared.hasUsageDescription() ? 1 : 0
}

/// Returns 1 if at least one video capture device (built-in, external USB, or Continuity) is present, or 0 if none.
@_cdecl("integrator_mac_camera_has_hardware")
public func integrator_mac_camera_has_hardware() -> Int32 {
    return MacCameraCaptureController.shared.hasCameraHardware() ? 1 : 0
}

/// Starts 720p30 NV12 AVFoundation camera capture. Returns 0 on success, negative error code on failure.
@_cdecl("integrator_mac_camera_start")
public func integrator_mac_camera_start() -> Int32 {
    return MacCameraCaptureController.shared.start()
}

/// Stops AVFoundation camera capture cleanly.
@_cdecl("integrator_mac_camera_stop")
public func integrator_mac_camera_stop() {
    MacCameraCaptureController.shared.stop()
}

/// Returns 1 if camera capture is currently active, or 0 if stopped.
@_cdecl("integrator_mac_camera_is_running")
public func integrator_mac_camera_is_running() -> Int32 {
    return MacCameraCaptureController.shared.isRunning() ? 1 : 0
}

/// Returns available video capture devices as a NUL-terminated JSON string written to `outBuf`.
///
/// - Parameters:
///   - outBuf: Caller-allocated C character buffer receiving the UTF-8 JSON array.
///   - cap: Capacity of `outBuf` in bytes (including trailing NUL terminator).
/// - Returns: Byte count written (excluding trailing NUL), or `-1` if `outBuf` is null or `cap` is insufficient.
@_cdecl("integrator_mac_camera_list_json")
public func integrator_mac_camera_list_json(outBuf: UnsafeMutablePointer<CChar>?, cap: Int32) -> Int32 {
    guard let outBuf = outBuf, cap > 0 else {
        return -1
    }
    let json = MacCameraCaptureController.shared.listCamerasJson()
    let cStr = json.utf8CString
    if cStr.count > Int(cap) {
        return -1
    }
    cStr.withUnsafeBufferPointer { buf in
        if let base = buf.baseAddress {
            memcpy(outBuf, base, buf.count)
        }
    }
    return Int32(cStr.count - 1)
}

/// Selects the active video capture device on macOS by its unique device ID.
///
/// - Parameter deviceIdUtf8: NUL-terminated UTF-8 string containing the target `AVCaptureDevice.uniqueID`.
/// - Returns: `1` on success, `0` if pointer is null or device was not found.
@_cdecl("integrator_mac_camera_select")
public func integrator_mac_camera_select(deviceIdUtf8: UnsafePointer<CChar>?) -> Int32 {
    guard let deviceIdUtf8 = deviceIdUtf8 else {
        return 0
    }
    let id = String(cString: deviceIdUtf8)
    return MacCameraCaptureController.shared.selectCamera(deviceId: id) ? 1 : 0
}

// ============================================================================
// MACOS MICROPHONE C-ABI FFI EXPORTS (Consumed by Rust `camera/mod.rs`)
// ============================================================================

/// Queries whether macOS TCC microphone capture permission is currently authorized.
///
/// - Returns: `true` if `AVCaptureDevice.authorizationStatus(for: .audio) == .authorized`; otherwise `false`.
@_cdecl("integrator_mac_mic_permission_granted")
public func integrator_mac_mic_permission_granted() -> Bool {
    return MacCameraCaptureController.shared.micPermissionGranted()
}

/// Requests macOS TCC microphone capture permission if not yet determined.
///
/// - Preconditions: If invoked from an `.app` bundle, `Info.plist` must contain `NSMicrophoneUsageDescription`.
/// - Threading: Never blocks the main thread if invoked on `Thread.isMainThread`; waits up to 30 seconds
///   on a `DispatchSemaphore` when invoked from a background worker thread.
/// - Returns: `true` if microphone access is authorized; `false` if denied, restricted, or timed out.
@_cdecl("integrator_mac_request_mic_permission")
public func integrator_mac_request_mic_permission() -> Bool {
    return MacCameraCaptureController.shared.requestMicPermission()
}

/// Enumerates connected macOS microphone devices as a UTF-8 JSON array (`[{"id":"...","name":"...","is_default":bool}]`)
/// written into `outBuf` safely bounded by `cap`.
///
/// - Parameters:
///   - outBuf: Caller-allocated byte buffer receiving the UTF-8 JSON string.
///   - cap: Maximum capacity of `outBuf` in bytes.
/// - Returns: Exact number of UTF-8 bytes written into `outBuf`, or `0` if `outBuf` is null, `cap <= 0`,
///   or the serialized payload exceeds `cap`.
@_cdecl("integrator_mac_list_mics")
public func integrator_mac_list_mics(_ outBuf: UnsafeMutablePointer<UInt8>?, _ cap: Int) -> Int {
    guard let outBuf = outBuf, cap > 0 else {
        return 0
    }
    let json = MacCameraCaptureController.shared.listMicsJson()
    let utf8 = Array(json.utf8)
    guard !utf8.isEmpty, utf8.count <= cap else {
        return 0
    }
    for i in 0..<utf8.count {
        outBuf[i] = utf8[i]
    }
    if utf8.count < cap {
        outBuf[utf8.count] = 0
    }
    return utf8.count
}

/// Validates and selects the active macOS microphone input device by its unique ID (`AVCaptureDevice.uniqueID`).
///
/// - Parameter deviceIdPtr: NUL-terminated UTF-8 C string specifying the desired microphone `uniqueID`.
/// - Returns: `true` if the device exists in the audio discovery session and was stored thread-safely;
///   `false` if `deviceIdPtr` is null, empty, or does not match any discovered audio input device.
@_cdecl("integrator_mac_select_mic")
public func integrator_mac_select_mic(_ deviceIdPtr: UnsafePointer<CChar>?) -> Bool {
    guard let deviceIdPtr = deviceIdPtr else {
        return false
    }
    let id = String(cString: deviceIdPtr)
    return MacCameraCaptureController.shared.selectMic(deviceId: id)
}
