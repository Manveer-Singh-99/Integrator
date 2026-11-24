//
//  ambient_light.swift
//  Integrator Cross-Screen TrueTone - macOS Hardware Ambient Light Sensor Driver
//
//  ========================================================================================
//  1. MODULE PURPOSE & ARCHITECTURAL SCOPE
//  ========================================================================================
//  This file implements the low-level macOS hardware Ambient Light Sensor (ALS) driver for
//  Integrator's Cross-Screen TrueTone and Chromatic Adaptation subsystem.
//
//  Key Subsystem Capabilities:
//  - Dynamic IOKit HID Event System Client: Dynamically binds IOKit framework symbols at runtime
//    via `dlopen`/`dlsym` (`IOHIDEventSystemClientCreateWithType`, `IOHIDServiceClientCopyEvent`),
//    avoiding hard private framework link dependencies while maintaining ABI compatibility
//    across macOS Monterey through macOS Sequoia.
//  - Apple Silicon SPU & Intel LMU HID Ingestion: Queries the HID Event System matching
//    `PrimaryUsagePage = 0xff00` (Apple Vendor Specific) and `PrimaryUsage = 4` (Ambient Light Sensor),
//    and falls back cleanly to IOKit `AppleLMUController` for pre-T2 Intel Macs.
//  - Photometric Extraction: Interrogates HID event type 12 (`kIOHIDEventTypeAmbientLightSensor`)
//    to extract raw hardware sensor channels only (zero CCT/color calculation on Mac):
//    - Illuminance in Lux (`field[11]` float lux with fallback to `field[0]` level)
//    - Raw ADC channels (`ch0`, `ch1`, `ch2`, `ch3`)
//    - Calibrated CIE XYZ chromaticity (`field[7..9]` when `field[6]` color space is active)
//
//  ========================================================================================
//  2. ARCHITECTURAL LINKAGES & CALL FLOW
//  ========================================================================================
//  Upstream Caller:
//  - `src/truetone/mod.rs`: Rust TrueTone daemon invokes the C-ABI function:
//    `read_mac_raw_ambient_sensor(...)` every 2 seconds and forwards raw telemetry to Windows,
//    where the PC performs all CCT estimation, chromatic adaptation, and 4s smooth LUT transitions.
//
//  Downstream Callees:
//  - `/System/Library/Frameworks/IOKit.framework/IOKit`: Dynamic symbol invocation and `AppleLMUController` fallback.
//  - CoreFoundation: `CFArray`, `CFTypeRef` memory lifecycle management via `withExtendedLifetime`.
//
//  ========================================================================================
//  3. THREADING & CONCURRENCY MODEL
//  ========================================================================================
//  - Synchronous FFI Invocation: `read_mac_ambient_sensor` executes re-entrantly on the caller's
//    thread (typically a background Tokio worker thread).
//  - Transient Resource Management: All IOKit client handles, `io_connect_t` ports, and CFArray
//    references are created, inspected, and released within the scope of a single invocation,
//    preventing memory leaks or resource lock contention.
//
//  ========================================================================================
//  4. SECURITY & SAFETY INVARIANTS
//  ========================================================================================
//  - Non-MacBook / Desktop Machine Containment: Devices lacking ambient hardware sensors
//    (Mac mini, Mac Studio, Mac Pro, Hackintosh) or clamshell closed MacBooks safely return `false`
//    with sentinel values `outLux = -1.0` and `outCct = 0` without crashing.
//  - ARC Pointer Lifetime Safety: Uses `withExtendedLifetime` around CoreFoundation objects backing
//    raw pointers so Swift `-O` release optimization cannot drop `clientObj`/`eventObj` prematurely.
//  - Finite Arithmetic Sanitization: All floating-point readings are tested with `.isFinite` and
//    `lux >= 0.0` before propagating into the Bradford CAT matrix.
//

import Foundation
import IOKit

// MARK: - Dynamic IOKit HID Function Bindings (Strict C Pointer ABI)

/// Dynamic handle to `/System/Library/Frameworks/IOKit.framework/IOKit` kept open for process lifetime.
private let ioKitHandle: UnsafeMutableRawPointer? = dlopen(
    "/System/Library/Frameworks/IOKit.framework/IOKit",
    RTLD_NOW | RTLD_LOCAL
)

/// C function pointer type for `IOHIDEventSystemClientCreateWithType`.
private typealias FnIOHIDClientCreateWithType = @convention(c) (
    UnsafeRawPointer?, UInt32, UnsafeRawPointer?
) -> UnsafeMutableRawPointer?
/// C function pointer type for `IOHIDEventSystemClientSetMatching`.
private typealias FnIOHIDClientSetMatching = @convention(c) (
    UnsafeRawPointer, UnsafeRawPointer
) -> Void
/// C function pointer type for `IOHIDEventSystemClientCopyServices`.
private typealias FnIOHIDClientCopyServices = @convention(c) (
    UnsafeRawPointer
) -> UnsafeMutableRawPointer?
/// C function pointer type for `IOHIDServiceClientCopyEvent`.
private typealias FnIOHIDServiceCopyEvent = @convention(c) (
    UnsafeRawPointer, Int64, UnsafeRawPointer?, UInt32
) -> UnsafeMutableRawPointer?
/// C function pointer type for `IOHIDEventGetFloatValue`.
private typealias FnIOHIDEventGetFloatValue = @convention(c) (
    UnsafeRawPointer, Int32
) -> Double

/// Dynamically resolved `IOHIDEventSystemClientCreateWithType` symbol (returns retained `IOHIDEventSystemClientRef`).
private let iohidClientCreateWithType: FnIOHIDClientCreateWithType? = {
    guard let handle = ioKitHandle,
          let sym = dlsym(handle, "IOHIDEventSystemClientCreateWithType") else { return nil }
    return unsafeBitCast(sym, to: FnIOHIDClientCreateWithType.self)
}()

/// Dynamically resolved `IOHIDEventSystemClientSetMatching` symbol for narrowing HID ALS queries.
private let iohidClientSetMatching: FnIOHIDClientSetMatching? = {
    guard let handle = ioKitHandle,
          let sym = dlsym(handle, "IOHIDEventSystemClientSetMatching") else { return nil }
    return unsafeBitCast(sym, to: FnIOHIDClientSetMatching.self)
}()

/// Dynamically resolved `IOHIDEventSystemClientCopyServices` symbol (returns retained `CFArrayRef`).
private let iohidClientCopyServices: FnIOHIDClientCopyServices? = {
    guard let handle = ioKitHandle,
          let sym = dlsym(handle, "IOHIDEventSystemClientCopyServices") else { return nil }
    return unsafeBitCast(sym, to: FnIOHIDClientCopyServices.self)
}()

/// Dynamically resolved `IOHIDServiceClientCopyEvent` symbol (returns retained `IOHIDEventRef`).
private let iohidServiceCopyEvent: FnIOHIDServiceCopyEvent? = {
    guard let handle = ioKitHandle,
          let sym = dlsym(handle, "IOHIDServiceClientCopyEvent") else { return nil }
    return unsafeBitCast(sym, to: FnIOHIDServiceCopyEvent.self)
}()

/// Dynamically resolved `IOHIDEventGetFloatValue` symbol for extracting double-precision ALS fields.
private let iohidEventGetFloatValue: FnIOHIDEventGetFloatValue? = {
    guard let handle = ioKitHandle,
          let sym = dlsym(handle, "IOHIDEventGetFloatValue") else { return nil }
    return unsafeBitCast(sym, to: FnIOHIDEventGetFloatValue.self)
}()

// MARK: - Photometric Physical Constants

/// Empirical scale divisor converting pre-T2 `AppleLMUController` 26-bit integer sensor readings to lux.
private let kPreT2LmuRawToLuxDivisor: Double = 2000.0

/// IOKit user-client scalar selector (`kGetSensorReadingID`) on legacy `AppleLMUController`.
private let kLmuGetSensorReadingSelector: UInt32 = 0

/// Expected Apple IOKit HID ambient sensor color space tag (`1.0` = CIE XYZ tristimulus).
private let kAlsColorSpaceCieXyz: Double = 1.0

/// Fallback reader for pre-T2 Intel Macs exposing the monochrome `AppleLMUController` IOKit service
/// when no HID Event System ALS service is registered.
///
/// - Returns: Non-negative finite illuminance in lux (`>= 0.0`) on success, or `nil` if absent/unreadable.
private func readPreT2LmuLux() -> Float? {
    guard let matching = IOServiceMatching("AppleLMUController") else {
        return nil
    }
    let mainPort: mach_port_t = 0
    let service = IOServiceGetMatchingService(mainPort, matching)
    guard service != 0 else {
        return nil
    }
    defer { IOObjectRelease(service) }

    var conn: io_connect_t = 0
    guard IOServiceOpen(service, mach_task_self_, 0, &conn) == KERN_SUCCESS, conn != 0 else {
        return nil
    }
    defer { IOServiceClose(conn) }

    var values: [UInt64] = [0, 0]
    var outCount: UInt32 = 2
    let kr = values.withUnsafeMutableBufferPointer { buf in
        IOConnectCallScalarMethod(
            conn,
            kLmuGetSensorReadingSelector,
            nil,
            0,
            buf.baseAddress,
            &outCount
        )
    }
    guard kr == KERN_SUCCESS, outCount >= 1 else {
        return nil
    }
    let avgRaw: Double = outCount >= 2
        ? (Double(values[0]) + Double(values[1])) * 0.5
        : Double(values[0])
    let luxDouble = avgRaw / kPreT2LmuRawToLuxDivisor
    let lux = Float(luxDouble)
    guard lux.isFinite, lux >= 0.0 else {
        return nil
    }
    return lux
}

// MARK: - Raw Ambient Light Sensor Reader FFI (Zero Colour Calculation on Mac)

/// Reads the macOS hardware Ambient Light Sensor raw channels via IOKit HID (with `AppleLMUController` fallback).
///
/// FFI Return Contract (consumed by `src/truetone/mod.rs`):
/// - Performs **no** color temperature, chromaticity, or white-point adaptation math on macOS;
///   only extracts finite raw sensor values (`lux`, raw ADC channels `ch0..ch2`, and calibrated
///   CIE XYZ tristimulus values when `ColorSpace == 1`) so the receiving Windows PC computes all color math.
/// - Returns `true` when an ambient light sensor is present and yields a valid non-negative finite `outLux`.
/// - Returns `false` with `-1.0` sentinels when no ambient sensor exists (e.g., Mac mini/Studio/Pro or closed lid).
@_cdecl("read_mac_raw_ambient_sensor")
public func read_mac_raw_ambient_sensor(
    outLux: UnsafeMutablePointer<Float>?,
    outCh0: UnsafeMutablePointer<Float>?,
    outCh1: UnsafeMutablePointer<Float>?,
    outCh2: UnsafeMutablePointer<Float>?,
    outCieX: UnsafeMutablePointer<Float>?,
    outCieY: UnsafeMutablePointer<Float>?,
    outCieZ: UnsafeMutablePointer<Float>?
) -> Bool {
    let resetOutputs: () -> Void = {
        outLux?.pointee = -1.0
        outCh0?.pointee = -1.0
        outCh1?.pointee = -1.0
        outCh2?.pointee = -1.0
        outCieX?.pointee = -1.0
        outCieY?.pointee = -1.0
        outCieZ?.pointee = -1.0
    }
    resetOutputs()

    if let createClient = iohidClientCreateWithType,
       let setMatching = iohidClientSetMatching,
       let copyServices = iohidClientCopyServices,
       let copyEvent = iohidServiceCopyEvent,
       let getFloatValue = iohidEventGetFloatValue,
       let clientPtr = createClient(nil, 1, nil)
    {
        let clientObj = Unmanaged<CFTypeRef>.fromOpaque(clientPtr).takeRetainedValue()
        let clientRaw = UnsafeRawPointer(clientPtr)

        let foundHid = withExtendedLifetime(clientObj) { () -> Bool in
            // Apple HID Ambient Light Sensor usage page/usage (covers Apple Silicon SPU & Intel T2 HID)
            let matching = [
                "PrimaryUsagePage": 0xff00,
                "PrimaryUsage": 4
            ] as NSDictionary
            setMatching(clientRaw, Unmanaged.passUnretained(matching).toOpaque())

            guard let servicesRaw = copyServices(clientRaw) else {
                return false
            }
            let servicesObj = Unmanaged<CFTypeRef>.fromOpaque(servicesRaw).takeRetainedValue()
            return withExtendedLifetime(servicesObj) { () -> Bool in
                guard CFGetTypeID(servicesObj) == CFArrayGetTypeID() else {
                    return false
                }
                let services = servicesObj as! CFArray
                let count = CFArrayGetCount(services)
                guard count > 0 else {
                    return false
                }

                // kIOHIDEventTypeAmbientLightSensor = 12
                let alsEventType: Int64 = 12
                let luxField: Int32 = Int32(alsEventType << 16)
                let ch0Field: Int32 = Int32((alsEventType << 16) | 1)
                let ch1Field: Int32 = Int32((alsEventType << 16) | 2)
                let ch2Field: Int32 = Int32((alsEventType << 16) | 3)
                let colorSpaceField: Int32 = Int32((alsEventType << 16) | 6)
                let cieXField: Int32 = Int32((alsEventType << 16) | 7)
                let cieYField: Int32 = Int32((alsEventType << 16) | 8)
                let cieZField: Int32 = Int32((alsEventType << 16) | 9)
                let preciseLuxField: Int32 = Int32((alsEventType << 16) | 11)

                for idx in 0..<count {
                    guard let serviceRaw = CFArrayGetValueAtIndex(services, idx) else {
                        continue
                    }
                    guard let eventRaw = copyEvent(serviceRaw, alsEventType, nil, 0) else {
                        continue
                    }
                    let eventObj = Unmanaged<CFTypeRef>.fromOpaque(eventRaw).takeRetainedValue()
                    let ok = withExtendedLifetime(eventObj) { () -> Bool in
                        let evPtr = UnsafeRawPointer(eventRaw)
                        let fineLux = getFloatValue(evPtr, preciseLuxField)
                        let coarseLux = getFloatValue(evPtr, luxField)
                        let luxDouble = (fineLux.isFinite && fineLux >= 0.0) ? fineLux : coarseLux
                        guard luxDouble.isFinite, luxDouble >= 0.0 else {
                            return false
                        }
                        let lux = Float(luxDouble)
                        guard lux.isFinite, lux >= 0.0 else {
                            return false
                        }

                        let ch0 = Float(getFloatValue(evPtr, ch0Field))
                        let ch1 = Float(getFloatValue(evPtr, ch1Field))
                        let ch2 = Float(getFloatValue(evPtr, ch2Field))
                        let colorSpace = getFloatValue(evPtr, colorSpaceField)
                        let xRaw = Float(getFloatValue(evPtr, cieXField))
                        let yRaw = Float(getFloatValue(evPtr, cieYField))
                        let zRaw = Float(getFloatValue(evPtr, cieZField))

                        outLux?.pointee = lux
                        outCh0?.pointee = (ch0.isFinite && ch0 > 0.0) ? ch0 : -1.0
                        outCh1?.pointee = (ch1.isFinite && ch1 > 0.0) ? ch1 : -1.0
                        outCh2?.pointee = (ch2.isFinite && ch2 > 0.0) ? ch2 : -1.0

                        if colorSpace == kAlsColorSpaceCieXyz,
                           xRaw.isFinite, yRaw.isFinite, zRaw.isFinite,
                           xRaw > 0.0, yRaw > 0.0, zRaw >= 0.0
                        {
                            outCieX?.pointee = xRaw
                            outCieY?.pointee = yRaw
                            outCieZ?.pointee = zRaw
                        }
                        return true
                    }

                    if ok {
                        return true
                    }
                }
                return false
            }
        }

        if foundHid {
            return true
        }
    }

    // Fallback for pre-T2 Intel Macs exposing the legacy monochrome AppleLMUController (lux only).
    if let lmuLux = readPreT2LmuLux() {
        outLux?.pointee = lmuLux
        return true
    }

    return false
}
