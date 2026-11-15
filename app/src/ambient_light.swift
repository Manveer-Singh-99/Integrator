import Foundation
import IOKit

// MARK: - Dynamic IOKit HID Function Bindings (Strict C Pointer ABI)
private let ioKitHandle: UnsafeMutableRawPointer? = dlopen(
    "/System/Library/Frameworks/IOKit.framework/IOKit",
    RTLD_NOW | RTLD_LOCAL
)

private typealias FnIOHIDClientCreateWithType = @convention(c) (
    UnsafeRawPointer?, UInt32, UnsafeRawPointer?
) -> UnsafeMutableRawPointer?
private typealias FnIOHIDClientSetMatching = @convention(c) (
    UnsafeRawPointer, UnsafeRawPointer
) -> Void
private typealias FnIOHIDClientCopyServices = @convention(c) (
    UnsafeRawPointer
) -> UnsafeMutableRawPointer?
private typealias FnIOHIDServiceCopyEvent = @convention(c) (
    UnsafeRawPointer, Int64, UnsafeRawPointer?, UInt32
) -> UnsafeMutableRawPointer?
private typealias FnIOHIDEventGetFloatValue = @convention(c) (
    UnsafeRawPointer, Int32
) -> Double

private let iohidClientCreateWithType: FnIOHIDClientCreateWithType? = {
    guard let handle = ioKitHandle,
          let sym = dlsym(handle, "IOHIDEventSystemClientCreateWithType") else { return nil }
    return unsafeBitCast(sym, to: FnIOHIDClientCreateWithType.self)
}()

private let iohidClientSetMatching: FnIOHIDClientSetMatching? = {
    guard let handle = ioKitHandle,
          let sym = dlsym(handle, "IOHIDEventSystemClientSetMatching") else { return nil }
    return unsafeBitCast(sym, to: FnIOHIDClientSetMatching.self)
}()

private let iohidClientCopyServices: FnIOHIDClientCopyServices? = {
    guard let handle = ioKitHandle,
          let sym = dlsym(handle, "IOHIDEventSystemClientCopyServices") else { return nil }
    return unsafeBitCast(sym, to: FnIOHIDClientCopyServices.self)
}()

private let iohidServiceCopyEvent: FnIOHIDServiceCopyEvent? = {
    guard let handle = ioKitHandle,
          let sym = dlsym(handle, "IOHIDServiceClientCopyEvent") else { return nil }
    return unsafeBitCast(sym, to: FnIOHIDServiceCopyEvent.self)
}()

private let iohidEventGetFloatValue: FnIOHIDEventGetFloatValue? = {
    guard let handle = ioKitHandle,
          let sym = dlsym(handle, "IOHIDEventGetFloatValue") else { return nil }
    return unsafeBitCast(sym, to: FnIOHIDEventGetFloatValue.self)
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

    guard let clientPtr = createClient(nil, 1, nil) else {
        return setUnsupported()
    }
    let clientObj = Unmanaged<CFTypeRef>.fromOpaque(clientPtr).takeRetainedValue()
    let clientRaw = UnsafeRawPointer(clientPtr)

    // Apple HID Ambient Light Sensor usage page/usage (covers Apple Silicon SPU & Intel LMU HID)
    let matching = [
        "PrimaryUsagePage": 0xff00,
        "PrimaryUsage": 4
    ] as NSDictionary
    setMatching(clientRaw, Unmanaged.passUnretained(matching).toOpaque())

    guard let servicesRaw = copyServices(clientRaw) else {
        return setUnsupported()
    }
    let servicesObj = Unmanaged<CFTypeRef>.fromOpaque(servicesRaw).takeRetainedValue()
    guard CFGetTypeID(servicesObj) == CFArrayGetTypeID() else {
        return setUnsupported()
    }
    let services = servicesObj as! CFArray
    let count = CFArrayGetCount(services)
    guard count > 0 else {
        return setUnsupported()
    }

    // kIOHIDEventTypeAmbientLightSensor = 12
    let alsEventType: Int64 = 12
    let luxField: Int32 = Int32(alsEventType << 16)
    let ch0Field: Int32 = Int32((alsEventType << 16) | 1)
    let ch2Field: Int32 = Int32((alsEventType << 16) | 3)

    _ = clientObj // keep retained until loop finishes
    for idx in 0..<count {
        guard let serviceRaw = CFArrayGetValueAtIndex(services, idx) else {
            continue
        }
        guard let eventRaw = copyEvent(serviceRaw, alsEventType, nil, 0) else {
            continue
        }
        let eventObj = Unmanaged<CFTypeRef>.fromOpaque(eventRaw).takeRetainedValue()
        let luxRaw = getFloatValue(UnsafeRawPointer(eventRaw), luxField)
        guard luxRaw.isFinite, luxRaw >= 0.0 else {
            _ = eventObj
            continue
        }

        let lux = Float(luxRaw)
        guard lux.isFinite, lux >= 0.0 else {
            _ = eventObj
            continue
        }

        let ch0 = getFloatValue(UnsafeRawPointer(eventRaw), ch0Field) // Red / Warm channel
        let ch2 = getFloatValue(UnsafeRawPointer(eventRaw), ch2Field) // Blue / Cool channel
        _ = eventObj

        // Calculate Correlated Color Temperature (Kelvin) relative to D65 (6500K).
        var cctKelvin: Double = 6500.0
        if ch0.isFinite, ch2.isFinite, ch0 > 0.0, ch2 > 0.0 {
            let ratio = ch2 / ch0
            if ratio.isFinite {
                cctKelvin = 3000.0 + (ratio * 3500.0)
                cctKelvin = min(max(cctKelvin, 2500.0), 9000.0)
            }
        }
        guard cctKelvin.isFinite else {
            continue
        }

        outLux?.pointee = lux
        outCct?.pointee = UInt32(cctKelvin.rounded())
        return true
    }

    return setUnsupported()
}
