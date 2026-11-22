//
//  ble_macos.swift
//  Integrator BLE Magic-Packet Proximity Discovery Bridge (macOS CoreBluetooth)
//
//  ========================================================================================
//  1. MODULE PURPOSE & ARCHITECTURAL SCOPE
//  ========================================================================================
//  This module implements native macOS Bluetooth Low Energy (BLE) advertising and scanning
//  via Apple's CoreBluetooth framework for Integrator peer proximity discovery.
//
//  Because macOS `CBPeripheralManager.startAdvertising` restricts payload keys to
//  `CBAdvertisementDataServiceUUIDsKey` and `CBAdvertisementDataLocalNameKey` (stripping
//  `ManufacturerData`), while Windows `BluetoothLEAdvertisementPublisher` publishes
//  `ManufacturerData` (`CompanyId = 0xFFFF`), this bridge uses an asymmetric-compatible
//  dual-format scheme:
//  - **Advertise (macOS -> Windows/macOS)**: Broadcasts Integrator's private 128-bit Service
//    UUID (`7A4E9C10-5B2F-4D81-9E3A-1C6F8B2D4E90`) plus a 27-character masked LocalName
//    magic packet (`IG2...`) in Scan Response, and exposes a matching read-only GATT
//    characteristic (`7A4E9C11-5B2F-4D81-9E3A-1C6F8B2D4E90`) carrying the 17-byte binary packet.
//  - **Scan (Windows/macOS -> macOS)**: Runs `CBCentralManager` with duplicate reporting
//    enabled (`withServices: nil` so Windows `ManufacturerData`-only beacons are received)
//    and forwards both binary `ManufacturerData` (Company ID `0xFFFF`, `IG2` magic) and
//    `LocalName` (`IG2...`) payloads to Rust via C ABI callbacks.
//
//  ========================================================================================
//  2. ARCHITECTURAL LINKAGES & CALL FLOW
//  ========================================================================================
//  Upstream Callers:
//  - `app/src/ble_discovery.rs`: Starts/stops BLE engine, pushes rotated magic payloads
//    every 15 seconds, and receives discovered hints via C callback pointers.
//  - `app/src/setup.rs`: Queries `integrator_mac_ble_auth_status()` to report macOS
//    Bluetooth TCC status in the Setup & Permissions Assistant.
//
//  Downstream Callees:
//  - `CoreBluetooth`: `CBCentralManager`, `CBPeripheralManager`, `CBMutableService`,
//    `CBMutableCharacteristic`, `CBUUID`, `CBManager.authorization`.
//
//  ========================================================================================
//  3. THREADING & CONCURRENCY MODEL
//  ========================================================================================
//  - All CoreBluetooth delegate callbacks and state mutations execute strictly on a private
//    serial GCD queue (`com.integrator.ble`), preventing race conditions between peripheral
//    advertisement updates, central scan callbacks, and Rust lifecycle calls.
//  - Atomic/lock-protected snapshots expose powered-on state without deadlocking the GCD queue.
//
//  ========================================================================================
//  4. SECURITY & SAFETY INVARIANTS
//  ========================================================================================
//  - **Zero Apple Ecosystem Interference**: Uses a private RFC 4122 v4 Service UUID and
//    Bluetooth SIG internal company ID `0xFFFF` (never Apple's `0x004C`), so nearby iPhones,
//    iPads, Apple TVs, and AirPods completely ignore Integrator BLE beacons.
//  - **Untrusted Hint Only**: BLE payloads only carry masked IPv4/port discovery hints;
//    trust and session establishment strictly require Ed25519 + ChaCha20-Poly1305
//    `TransportSessionV2` authentication on TCP `:58281`.
//  - **Plist Guard**: Checks for `NSBluetoothAlwaysUsageDescription` in `Bundle.main` when
//    invoked inside an unbundled test binary so macOS TCC never aborts unit tests.
//

import CoreBluetooth
import Foundation

/// Private 128-bit Integrator BLE Service UUID (matches `config::BLE_SERVICE_UUID`).
private let kIntegratorBleServiceUuid = CBUUID(string: "7A4E9C10-5B2F-4D81-9E3A-1C6F8B2D4E90")

/// Read-only GATT characteristic UUID mirroring the 17-byte binary magic packet.
private let kIntegratorBleCharUuid = CBUUID(string: "7A4E9C11-5B2F-4D81-9E3A-1C6F8B2D4E90")

/// Bluetooth SIG internal/custom Manufacturer Company ID (`0xFFFF`, little-endian `[0xFF, 0xFF]`).
private let kIntegratorBleCompanyIdLow: UInt8 = 0xFF
private let kIntegratorBleCompanyIdHigh: UInt8 = 0xFF

/// ASCII prefix identifying Integrator v2 BLE LocalName magic packets.
private let kIntegratorBleLocalNamePrefix: String = "IG2"

/// Dedicated serial GCD queue identifier for CoreBluetooth operations.
private let kIntegratorBleQueueLabel: String = "com.integrator.ble"

/// Info.plist key required by macOS TCC for CoreBluetooth access.
private let kBluetoothUsageDescKey: String = "NSBluetoothAlwaysUsageDescription"

/// C callback signature delivering raw 17-byte binary magic packets (without 2-byte company ID).
public typealias IntegratorBleBinaryCallback = @convention(c) (UnsafePointer<UInt8>?, Int, Int16) -> Void

/// C callback signature delivering NUL-terminated LocalName magic packets (`IG2...`).
public typealias IntegratorBleNameCallback = @convention(c) (UnsafePointer<CChar>?, Int16) -> Void

/// Singleton coordinator driving macOS CoreBluetooth peripheral advertising and central scanning.
final class IntegratorBleController: NSObject, CBCentralManagerDelegate, CBPeripheralManagerDelegate {
    static let shared = IntegratorBleController()

    private let bleQueue = DispatchQueue(label: kIntegratorBleQueueLabel, qos: .utility)
    private let stateLock = NSLock()

    private var centralManager: CBCentralManager?
    private var peripheralManager: CBPeripheralManager?
    private var gattServiceAdded: Bool = false
    private var gattCharacteristic: CBMutableCharacteristic?

    private var onBinaryCb: IntegratorBleBinaryCallback?
    private var onNameCb: IntegratorBleNameCallback?

    private var pendingServiceUuid: String?
    private var pendingLocalName: String?
    private var pendingBinaryPayload: Data?
    private var wantsScan: Bool = false
    private var wantsAdvertise: Bool = false

    private var _centralPoweredOn: Bool = false
    private var _peripheralPoweredOn: Bool = false

    var isPoweredOn: Bool {
        stateLock.lock()
        defer { stateLock.unlock() }
        return _centralPoweredOn || _peripheralPoweredOn
    }

    private static func hasBluetoothUsageDescription() -> Bool {
        // Unbundled CLI binaries launched from Terminal inherit Terminal's TCC context, while
        // `.app` bundles must declare `NSBluetoothAlwaysUsageDescription` in `Info.plist`.
        let bundlePath = Bundle.main.bundlePath
        if !bundlePath.hasSuffix(".app") {
            return true
        }
        guard let desc = Bundle.main.object(forInfoDictionaryKey: kBluetoothUsageDescKey) as? String else {
            return false
        }
        return !desc.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    func start(
        enableScan: Bool,
        enableAdvertise: Bool,
        binaryCb: IntegratorBleBinaryCallback?,
        nameCb: IntegratorBleNameCallback?
    ) -> Bool {
        guard Self.hasBluetoothUsageDescription() else {
            return false
        }
        bleQueue.async { [weak self] in
            guard let self = self else { return }
            self.onBinaryCb = binaryCb
            self.onNameCb = nameCb
            self.wantsScan = enableScan
            self.wantsAdvertise = enableAdvertise

            if enableScan {
                if self.centralManager == nil {
                    self.centralManager = CBCentralManager(
                        delegate: self,
                        queue: self.bleQueue,
                        options: [CBCentralManagerOptionShowPowerAlertKey: false]
                    )
                } else if self.centralManager?.state == .poweredOn {
                    self.startScanningLocked()
                }
            }

            if enableAdvertise {
                if self.peripheralManager == nil {
                    self.peripheralManager = CBPeripheralManager(
                        delegate: self,
                        queue: self.bleQueue,
                        options: [CBPeripheralManagerOptionShowPowerAlertKey: false]
                    )
                } else if self.peripheralManager?.state == .poweredOn {
                    self.applyAdvertisementLocked()
                }
            }
        }
        return true
    }

    func updateAdvertisement(serviceUuid: String, localName: String, binaryPayload: Data) {
        bleQueue.async { [weak self] in
            guard let self = self else { return }
            self.pendingServiceUuid = serviceUuid
            self.pendingLocalName = localName
            self.pendingBinaryPayload = binaryPayload
            if self.wantsAdvertise, self.peripheralManager?.state == .poweredOn {
                self.applyAdvertisementLocked()
            }
        }
    }

    func stop() {
        bleQueue.async { [weak self] in
            guard let self = self else { return }
            self.wantsScan = false
            self.wantsAdvertise = false
            self.centralManager?.stopScan()
            if self.peripheralManager?.isAdvertising == true {
                self.peripheralManager?.stopAdvertising()
            }
            self.onBinaryCb = nil
            self.onNameCb = nil
        }
    }

    private func startScanningLocked() {
        guard wantsScan, let cm = centralManager, cm.state == .poweredOn else { return }
        // Pass `withServices: nil` so macOS also receives Windows ManufacturerData-only beacons.
        cm.scanForPeripherals(
            withServices: nil,
            options: [CBCentralManagerScanOptionAllowDuplicatesKey: true]
        )
    }

    private func applyAdvertisementLocked() {
        guard wantsAdvertise, let pm = peripheralManager, pm.state == .poweredOn else { return }
        guard let localName = pendingLocalName, !localName.isEmpty else { return }

        if !gattServiceAdded {
            let char = CBMutableCharacteristic(
                type: kIntegratorBleCharUuid,
                properties: [.read],
                value: nil,
                permissions: [.readable]
            )
            let service = CBMutableService(type: kIntegratorBleServiceUuid, primary: true)
            service.characteristics = [char]
            gattCharacteristic = char
            gattServiceAdded = true
            pm.add(service)
        }

        if pm.isAdvertising {
            pm.stopAdvertising()
        }
        let advUuid: CBUUID
        if let dyn = pendingServiceUuid, !dyn.isEmpty {
            advUuid = CBUUID(string: dyn)
        } else {
            advUuid = kIntegratorBleServiceUuid
        }
        let adData: [String: Any] = [
            CBAdvertisementDataServiceUUIDsKey: [advUuid],
            CBAdvertisementDataLocalNameKey: localName,
        ]
        pm.startAdvertising(adData)
    }

    // MARK: - CBCentralManagerDelegate

    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        let on = (central.state == .poweredOn)
        stateLock.lock()
        _centralPoweredOn = on
        stateLock.unlock()

        if on && wantsScan {
            startScanningLocked()
        }
    }

    func centralManager(
        _ central: CBCentralManager,
        didDiscover peripheral: CBPeripheral,
        advertisementData: [String: Any],
        rssi RSSI: NSNumber
    ) {
        let rssiVal = Int16(clamping: RSSI.intValue)

        // 1. Check ManufacturerData (Company ID 0xFFFF + 17-byte IG2 magic packet from Windows)
        if let mfg = advertisementData[CBAdvertisementDataManufacturerDataKey] as? Data,
           mfg.count >= 19,
           mfg[0] == kIntegratorBleCompanyIdLow,
           mfg[1] == kIntegratorBleCompanyIdHigh
        {
            let payload = mfg.subdata(in: 2..<mfg.count)
            if payload.count >= 17,
               payload[0] == 0x49, // 'I'
               payload[1] == 0x47, // 'G'
               payload[2] == 0x32  // '2'
            {
                if let cb = onBinaryCb {
                    payload.withUnsafeBytes { rawBuf in
                        if let ptr = rawBuf.baseAddress?.assumingMemoryBound(to: UInt8.self) {
                            cb(ptr, payload.count, rssiVal)
                        }
                    }
                }
            }
        }

        // 2. Check 128-bit Service UUIDs (`7A4E...` ADV_IND magic packet from macOS)
        if let uuids = advertisementData[CBAdvertisementDataServiceUUIDsKey] as? [CBUUID],
           let cb = onNameCb
        {
            for uuid in uuids {
                let s = uuid.uuidString
                if s.hasPrefix("7A4E") || s.hasPrefix("7a4e") {
                    s.withCString { cstr in
                        cb(cstr, rssiVal)
                    }
                }
            }
        }

        // 3. Check LocalName (`IG2...` 27-byte scan-response magic packet from macOS)
        if let name = advertisementData[CBAdvertisementDataLocalNameKey] as? String,
           name.hasPrefix(kIntegratorBleLocalNamePrefix),
           let cb = onNameCb
        {
            name.withCString { cstr in
                cb(cstr, rssiVal)
            }
        }
    }

    // MARK: - CBPeripheralManagerDelegate

    func peripheralManagerDidUpdateState(_ peripheral: CBPeripheralManager) {
        let on = (peripheral.state == .poweredOn)
        stateLock.lock()
        _peripheralPoweredOn = on
        stateLock.unlock()

        if on && wantsAdvertise {
            applyAdvertisementLocked()
        }
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, didReceiveRead request: CBATTRequest) {
        if request.characteristic.uuid == kIntegratorBleCharUuid,
           let payload = pendingBinaryPayload
        {
            if request.offset <= payload.count {
                request.value = payload.subdata(in: request.offset..<payload.count)
                peripheral.respond(to: request, withResult: .success)
                return
            }
        }
        peripheral.respond(to: request, withResult: .attributeNotFound)
    }
}

// MARK: - C FFI Exports

/// Starts macOS CoreBluetooth BLE scanning and/or advertising with the given C hint callbacks.
@_cdecl("integrator_mac_ble_start")
public func integrator_mac_ble_start(
    enableScan: Bool,
    enableAdvertise: Bool,
    binaryCb: IntegratorBleBinaryCallback?,
    nameCb: IntegratorBleNameCallback?
) -> Bool {
    return IntegratorBleController.shared.start(
        enableScan: enableScan,
        enableAdvertise: enableAdvertise,
        binaryCb: binaryCb,
        nameCb: nameCb
    )
}

/// Updates the advertised macOS BLE 128-bit Service UUID magic packet, LocalName, and mirrored GATT payload.
@_cdecl("integrator_mac_ble_update_advertisement")
public func integrator_mac_ble_update_advertisement(
    serviceUuidPtr: UnsafePointer<CChar>?,
    localNamePtr: UnsafePointer<CChar>?,
    binPtr: UnsafePointer<UInt8>?,
    binLen: Int
) {
    guard let serviceUuidPtr = serviceUuidPtr,
          let localNamePtr = localNamePtr,
          let binPtr = binPtr,
          binLen > 0
    else { return }
    let serviceUuid = String(cString: serviceUuidPtr)
    let localName = String(cString: localNamePtr)
    let data = Data(bytes: binPtr, count: binLen)
    IntegratorBleController.shared.updateAdvertisement(
        serviceUuid: serviceUuid,
        localName: localName,
        binaryPayload: data
    )
}

/// Stops macOS CoreBluetooth BLE scanning and advertising cleanly.
@_cdecl("integrator_mac_ble_stop")
public func integrator_mac_ble_stop() {
    IntegratorBleController.shared.stop()
}

/// Returns current macOS Bluetooth TCC authorization status:
/// `0` = notDetermined, `1` = denied/restricted, `2` = allowedAlways.
@_cdecl("integrator_mac_ble_auth_status")
public func integrator_mac_ble_auth_status() -> Int32 {
    if #available(macOS 10.15, *) {
        switch CBManager.authorization {
        case .allowedAlways:
            return 2
        case .denied, .restricted:
            return 1
        case .notDetermined:
            return 0
        @unknown default:
            return 1
        }
    }
    return 2
}

/// Returns `true` if either the CoreBluetooth central or peripheral radio is powered on.
@_cdecl("integrator_mac_ble_is_powered_on")
public func integrator_mac_ble_is_powered_on() -> Bool {
    return IntegratorBleController.shared.isPoweredOn
}
