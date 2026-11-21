/*
 * ============================================================================
 * Integrator Shared Camera: macOS AVFoundation Capture Controller
 * ============================================================================
 *
 * 1. MODULE PURPOSE & ARCHITECTURAL SCOPE
 * ----------------------------------------------------------------------------
 * This file implements the native macOS video capture pipeline for Integrator's
 * Shared Camera subsystem (`camera` feature). Its sole mission is to interface
 * directly with macOS AVFoundation, capture raw video from the Mac's built-in
 * FaceTime HD Camera, external USB webcam, or Continuity Camera at 720p30, convert and pack the native bi-planar CVPixelBuffers
 * into tightly contiguous NV12 format, and stream them into the Rust core via C FFI.
 *
 * 2. END-TO-END CROSS-PLATFORM ARCHITECTURAL FLOW
 * ----------------------------------------------------------------------------
 * 1. Capture (macOS):
 *    - `AVCaptureSession` configured with preset `.hd1280x720`.
 *    - Captures the built-in wide-angle camera (`AVCaptureDevice.default(.builtInWideAngleCamera, for: .video)`).
 *    - Pixel format forced to `kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange` (NV12 video range).
 *    - Frame rate locked to exactly 30 fps via `videoMinFrameDuration` / `videoMaxFrameDuration` = CMTime(1, 30).
 * 2. Buffer Normalization & Memory Layout (macOS Swift):
 *    - Hardware camera buffers frequently arrive with row padding (stride > width, e.g. 1280 vs 1312).
 *    - `MacCameraCaptureController.captureOutput`:
 *      * Plane 0 (Y / Luma): 1280 x 720 pixels = 921,600 bytes.
 *      * Plane 1 (CbCr / Chroma): 1280 x 360 interleaved bytes (2x2 subsampled) = 460,800 bytes.
 *      * Unpacks rows stripping any hardware stride padding into a tightly packed 1,382,400-byte buffer.
 * 3. Rust Ingestion & Transport (Rust `camera/mod.rs`):
 *    - Invokes `integrator_on_mac_camera_frame` C FFI export.
 *    - Wraps payload in 22-byte `ICAM` binary header with microsecond timestamp.
 *    - Published into `LatestFrameSlot` (dropping old unread frames for 0-latency delivery).
 *    - Streamed over `TransportSessionV2` (TCP port 58287, ChaCha20-Poly1305 AEAD, Ed25519 mutual auth).
 * 4. Windows 11 Media Foundation Virtual Camera (Windows 11):
 *    - Received on Windows TCP :58287, forwarded via `integrator_win_vcam_push_nv12`.
 *    - Pushed into double-buffered ACL-hardened shared memory (`Global\IntegratorVCamShm_v1`).
 *    - Ingested by standalone COM DLL `integrator_vcam.dll` (`Integrator Mac Camera`).
 *    - Windows 11 Media Foundation FrameServer delivers live frames to any consumer (Teams, Zoom, OBS)
 *      without requiring third-party drivers or physical camera source wrapper attributes
 *      (`MF_VIRTUALCAMERA_PROVIDE_ASSOCIATED_CAMERA_SOURCES` is omitted).
 *
 * 3. THREADING & CONCURRENCY MODEL
 * ----------------------------------------------------------------------------
 * - Capture Queue: Dedicated high-priority serial dispatch queue
 *   `com.integrator.camera.capture` (`qos: .userInteractive`).
 * - Mutual Exclusion: `NSLock` guards session lifecycle transitions (`running`, `session`, `packedBuffer`).
 * - Teardown Synchronization: Synchronous `captureQueue.sync` during `stop()` guarantees no
 *   dangling frame callbacks execute after camera stop returns.
 *
 * 4. SECURITY & PERMISSION INVARIANTS
 * ----------------------------------------------------------------------------
 * - macOS TCC Enforcement: Inspects `Bundle.main.object(forInfoDictionaryKey: "NSCameraUsageDescription")`
 *   to avoid OS kill (-2 return code if missing).
 * - User Privacy: Checks `AVCaptureDevice.authorizationStatus(for: .video)` and requests permission
 *   with a 30-second bounded timeout via `DispatchSemaphore`.
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
///   - len: Length of buffer in bytes (must equal 1,382,400).
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

/// Timeout in seconds while waiting for the macOS TCC camera authorization prompt.
private let kCameraAuthTimeoutSec: Int = 30

/// Singleton controller managing the macOS AVFoundation capture lifecycle and sample buffer delegate.
private final class MacCameraCaptureController: NSObject, AVCaptureVideoDataOutputSampleBufferDelegate {
    /// Callback signature invoked with each tightly-packed NV12 frame on the capture queue.
    typealias FrameCallback = (UnsafePointer<UInt8>, UInt32, UInt32, UInt32, UInt64) -> Void

    /// Shared singleton instance accessible via C FFI functions.
    static let shared = MacCameraCaptureController()

    /// Mutual exclusion lock guarding session reference, capture geometry, and running state.
    private let lock = NSLock()

    /// Serial GCD queue executing video sample buffer delivery at interactive priority.
    private let captureQueue = DispatchQueue(label: "com.integrator.camera.capture", qos: .userInteractive)

    /// Active AVFoundation capture session managing input device and video data output.
    private var session: AVCaptureSession?

    /// Reusable contiguous heap buffer holding tightly-packed NV12 frame bytes.
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
    /// macOS requires this description string; accessing camera hardware without it triggers a fatal SIGABRT.
    /// - Returns: `true` if description is present and valid; otherwise `false`.
    func hasUsageDescription() -> Bool {
        guard let desc = Bundle.main.object(forInfoDictionaryKey: "NSCameraUsageDescription") as? String else {
            return false
        }
        return !desc.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    /// Requests camera capture permission from the user if not yet determined.
    ///
    /// - Returns:
    ///   - `2`: Permission granted.
    ///   - `1`: Permission denied.
    ///   - `-2`: Bundle missing `NSCameraUsageDescription`.
    func requestPermissionIfNeeded() -> Int32 {
        let current = permissionState()
        if current != 0 {
            return current
        }
        guard hasUsageDescription() else {
            return -2 // Missing NSCameraUsageDescription in bundle Info.plist
        }

        let sem = DispatchSemaphore(value: 0)
        var grantedResult = false
        AVCaptureDevice.requestAccess(for: .video) { granted in
            grantedResult = granted
            sem.signal()
        }
        _ = sem.wait(timeout: .now() + .seconds(kCameraAuthTimeoutSec))
        return grantedResult ? 2 : 1
    }

    /// Maps requested pixel dimensions to the closest matching `AVCaptureSession.Preset`.
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
    ///   - `-6`: Initialization exception.
    func startCapture(
        width: UInt32 = kDefaultCameraWidth,
        height: UInt32 = kDefaultCameraHeight,
        fps: Int32 = kDefaultCameraFps,
        callback: @escaping FrameCallback = integrator_on_mac_camera_frame
    ) -> Int32 {
        let resolvedWidth = width > 0 ? width : kDefaultCameraWidth
        let resolvedHeight = height > 0 ? height : kDefaultCameraHeight
        let resolvedFps = fps > 0 ? fps : kDefaultCameraFps

        lock.lock()
        if running, session?.isRunning == true {
            lock.unlock()
            return 0
        }
        lock.unlock()

        // Verify that a built-in, external USB, or Continuity camera exists before prompting or starting
        guard let device = Self.discoverPreferredCameraDevice() else {
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

            let expectedBytes = Int(resolvedWidth * resolvedHeight * 3 / 2)
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
