import Foundation
import IOKit

// MARK: - Dynamic IOKit HID Function Types
typealias IOHIDEventSystemClientRef = CFTypeRef
typealias IOHIDEventRef = CFTypeRef

private let IOHIDEventSystemClientCreateWithType: @convention(c) (CFAllocator?, UInt32, CFDictionary?) -> IOHIDEventSystemClientRef? = {
    guard let handle = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_NOW),
          let sym = dlsym(handle, "IOHIDEventSystemClientCreateWithType") else { return { _, _, _ in nil } }
    return unsafeBitCast(sym, to: (@convention(c) (CFAllocator?, UInt32, CFDictionary?) -> IOHIDEventSystemClientRef?).self)
}()

private let IOHIDEventSystemClientSetMatching: @convention(c) (IOHIDEventSystemClientRef, CFDictionary) -> Void = {
    guard let handle = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_NOW),
          let sym = dlsym(handle, "IOHIDEventSystemClientSetMatching") else { return { _, _ in } }
    return unsafeBitCast(sym, to: (@convention(c) (IOHIDEventSystemClientRef, CFDictionary) -> Void).self)
}()

private let IOHIDEventSystemClientCopyServices: @convention(c) (IOHIDEventSystemClientRef) -> CFArray? = {
    guard let handle = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_NOW),
          let sym = dlsym(handle, "IOHIDEventSystemClientCopyServices") else { return { _ in nil } }
    return unsafeBitCast(sym, to: (@convention(c) (IOHIDEventSystemClientRef) -> CFArray?).self)
}()

private let IOHIDServiceClientCopyEvent: @convention(c) (CFTypeRef, Int64, Int32, Int64) -> IOHIDEventRef? = {
    guard let handle = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_NOW),
          let sym = dlsym(handle, "IOHIDServiceClientCopyEvent") else { return { _, _, _, _ in nil } }
    return unsafeBitCast(sym, to: (@convention(c) (CFTypeRef, Int64, Int32, Int64) -> IOHIDEventRef?).self)
}()

private let IOHIDEventGetFloatValue: @convention(c) (IOHIDEventRef, Int32) -> Double = {
    guard let handle = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_NOW),
          let sym = dlsym(handle, "IOHIDEventGetFloatValue") else { return { _, _ in 0.0 } }
    return unsafeBitCast(sym, to: (@convention(c) (IOHIDEventRef, Int32) -> Double).self)
}()

// MARK: - Ambient Light Sensor Reader FFI
@_cdecl("read_mac_ambient_sensor")
public func read_mac_ambient_sensor(outLux: UnsafeMutablePointer<Float>, outCct: UnsafeMutablePointer<UInt32>) -> Bool {
    guard let client = IOHIDEventSystemClientCreateWithType(kCFAllocatorDefault, 1, nil) else {
        return false
    }

    let matching: [String: Any] = [
        "PrimaryUsagePage": 0xff00,
        "PrimaryUsage": 4
    ]
    IOHIDEventSystemClientSetMatching(client, matching as CFDictionary)

    guard let services = IOHIDEventSystemClientCopyServices(client) as? [CFTypeRef],
          let service = services.first else {
        return false
    }

    // kIOHIDEventTypeAmbientLightSensor = 12
    guard let event = IOHIDServiceClientCopyEvent(service, 12, 0, 0) else {
        return false
    }

    let lux = Float(IOHIDEventGetFloatValue(event, (12 << 16)))
    let ch0 = IOHIDEventGetFloatValue(event, (12 << 16) | 1) // Red / Warm channel
    let ch2 = IOHIDEventGetFloatValue(event, (12 << 16) | 3) // Blue / Cool channel

    // Calculate Correlated Color Temperature (Kelvin):
    // Standard daylight D65 is ~6500K. Warm incandescent is ~2700-3000K. Cool sky is 7500-9000K.
    var cctKelvin: Double = 5500.0
    if ch0 > 0 && ch2 > 0 {
        let ratio = ch2 / ch0
        // Calibrated against MacBook Pro Retina True Tone curve:
        // ratio ~ 0.50 -> ~3200K
        // ratio ~ 0.76 -> ~5600K
        // ratio ~ 1.00 -> ~6500K
        cctKelvin = 3000.0 + (ratio * 3500.0)
        cctKelvin = min(max(cctKelvin, 2500.0), 9000.0)
    }

    outLux.pointee = lux
    outCct.pointee = UInt32(cctKelvin)

    return true
}
