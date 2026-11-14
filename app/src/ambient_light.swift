import Foundation
import IOKit

// MARK: - Dynamic IOKit HID Function Bindings
typealias IOHIDEventSystemClientRef = CFTypeRef
typealias IOHIDEventRef = CFTypeRef

private let ioKitHandle: UnsafeMutableRawPointer? = dlopen(
    "/System/Library/Frameworks/IOKit.framework/IOKit",
    RTLD_NOW
)

private let iohidClientCreateWithType: (@convention(c) (CFAllocator?, UInt32, CFDictionary?) -> Unmanaged<CFTypeRef>?)? = {
    guard let handle = ioKitHandle,
          let sym = dlsym(handle, "IOHIDEventSystemClientCreateWithType") else { return nil }
    return unsafeBitCast(
        sym,
        to: (@convention(c) (CFAllocator?, UInt32, CFDictionary?) -> Unmanaged<CFTypeRef>?).self
    )
}()

private let iohidClientSetMatching: (@convention(c) (IOHIDEventSystemClientRef, CFDictionary) -> Void)? = {
    guard let handle = ioKitHandle,
          let sym = dlsym(handle, "IOHIDEventSystemClientSetMatching") else { return nil }
    return unsafeBitCast(
        sym,
        to: (@convention(c) (IOHIDEventSystemClientRef, CFDictionary) -> Void).self
    )
}()

private let iohidClientCopyServices: (@convention(c) (IOHIDEventSystemClientRef) -> Unmanaged<CFArray>?)? = {
    guard let handle = ioKitHandle,
          let sym = dlsym(handle, "IOHIDEventSystemClientCopyServices") else { return nil }
    return unsafeBitCast(
        sym,
        to: (@convention(c) (IOHIDEventSystemClientRef) -> Unmanaged<CFArray>?).self
    )
}()

private let iohidServiceCopyEvent: (@convention(c) (CFTypeRef, Int64, Int32, Int64) -> Unmanaged<CFTypeRef>?)? = {
    guard let handle = ioKitHandle,
          let sym = dlsym(handle, "IOHIDServiceClientCopyEvent") else { return nil }
    return unsafeBitCast(
        sym,
        to: (@convention(c) (CFTypeRef, Int64, Int32, Int64) -> Unmanaged<CFTypeRef>?).self
    )
}()

private let iohidEventGetFloatValue: (@convention(c) (IOHIDEventRef, Int32) -> Double)? = {
    guard let handle = ioKitHandle,
          let sym = dlsym(handle, "IOHIDEventGetFloatValue") else { return nil }
    return unsafeBitCast(
        sym,
        to: (@convention(c) (IOHIDEventRef, Int32) -> Double).self
    )
}()

// MARK: - Ambient Light Sensor Reader FFI
/// Reads the macOS hardware Ambient Light Sensor via IOKit HID.
///
/// FFI Return Contract (consumed by `src/truetone/mod.rs`):
/// - Returns `true` when an ambient light sensor is present and yields a valid
///   reading, writing `outLux >= 0.0` (finite lux) and `outCct` (2500..9000 K;
///   defaults to 6500 K D65 neutral when RGB color channels are absent).
/// - Returns `false` when no IOKit HID / AppleLMU ambient sensor exists
///   (e.g., Mac Studio, Mac mini, desktop Mac, or unavailable sensor) or when the
///   sensor reading is non-finite/negative, explicitly writing sentinel
///   `outLux = -1.0` and `outCct = 0` instead of fabricating positive lux.
@_cdecl("read_mac_ambient_sensor")
public func read_mac_ambient_sensor(
    outLux: UnsafeMutablePointer<Float>?,
    outCct: UnsafeMutablePointer<UInt32>?
) -> Bool {
    let setUnsupported: () -> Bool = {
        outLux?.pointee = -1.0
        outCct?.pointee = 0
        return false
    }

    guard let createClient = iohidClientCreateWithType,
          let setMatching = iohidClientSetMatching,
          let copyServices = iohidClientCopyServices,
          let copyEvent = iohidServiceCopyEvent,
          let getFloatValue = iohidEventGetFloatValue else {
        return setUnsupported()
    }

    guard let client = createClient(kCFAllocatorDefault, 1, nil)?.takeRetainedValue() else {
        return setUnsupported()
    }

    // Apple HID Ambient Light Sensor usage page/usage (covers Apple Silicon SPU & Intel LMU HID)
    let matching: [String: Any] = [
        "PrimaryUsagePage": 0xff00,
        "PrimaryUsage": 4
    ]
    setMatching(client, matching as CFDictionary)

    guard let servicesRef = copyServices(client)?.takeRetainedValue() else {
        return setUnsupported()
    }
    let services = servicesRef as [CFTypeRef]
    guard !services.isEmpty else {
        return setUnsupported()
    }

    // kIOHIDEventTypeAmbientLightSensor = 12
    let alsEventType: Int64 = 12
    let luxField: Int32 = Int32(alsEventType << 16)
    let ch0Field: Int32 = Int32((alsEventType << 16) | 1)
    let ch2Field: Int32 = Int32((alsEventType << 16) | 3)

    for service in services {
        guard let event = copyEvent(service, alsEventType, 0, 0)?.takeRetainedValue() else {
            continue
        }

        let luxRaw = getFloatValue(event, luxField)
        guard luxRaw.isFinite, luxRaw >= 0.0 else {
            continue
        }

        let lux = Float(luxRaw)
        let ch0 = getFloatValue(event, ch0Field) // Red / Warm channel
        let ch2 = getFloatValue(event, ch2Field) // Blue / Cool channel

        // Calculate Correlated Color Temperature (Kelvin) relative to D65 (6500K).
        var cctKelvin: Double = 6500.0
        if ch0.isFinite, ch2.isFinite, ch0 > 0.0, ch2 > 0.0 {
            let ratio = ch2 / ch0
            cctKelvin = 3000.0 + (ratio * 3500.0)
            cctKelvin = min(max(cctKelvin, 2500.0), 9000.0)
        }

        outLux?.pointee = lux
        outCct?.pointee = UInt32(cctKelvin.rounded())
        return true
    }

    return setUnsupported()
}
