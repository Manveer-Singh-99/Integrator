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
//  Cross-Platform / Cross-Device Flow:
//  - **macOS -> Windows 11**: `CBPeripheralManager` advertises the 16-byte masked IPv4+port
//    payload as a 128-bit `ADV_IND` Service UUID (`7A4E...`) alongside the 27-character
//    `LocalName` (`IG2...`) in `SCAN_RSP` and a read-only GATT characteristic mirror.
//  - **Windows 11 -> macOS**: `CBCentralManager` receives Windows 11 `ManufacturerData`
//    beacons (`CompanyId = 0xFFFF`, `IG2` magic) and forwards the 17-byte payload to Rust
//    `ble_discovery::macos_ble::on_binary_packet` for SHA-256 tag verification and IP unmasking.
//
//  ========================================================================================
//  3. THREADING & CONCURRENCY MODEL
//  ========================================================================================
//  - All CoreBluetooth delegate callbacks and state mutations execute strictly on a private
//    serial GCD queue (`com.integrator.ble`), preventing race conditions between peripheral
//    advertisement updates, central scan callbacks, and Rust lifecycle calls.
//  - Bluetooth hardware authorization state (`CBManager.authorization`) is queried directly
//    via CoreBluetooth without blocking caller threads.
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

/// Bluetooth SIG internal/custom Manufacturer Company ID low byte (`0xFFFF` little-endian `[0xFF, 0xFF]`).
private let kIntegratorBleCompanyIdLow: UInt8 = 0xFF

/// Bluetooth SIG internal/custom Manufacturer Company ID high byte (`0xFFFF` little-endian `[0xFF, 0xFF]`).
private let kIntegratorBleCompanyIdHigh: UInt8 = 0xFF

/// ASCII prefix identifying Integrator v2 BLE LocalName magic packets.
private let kIntegratorBleLocalNamePrefix: String = "IG2"

/// Dedicated serial GCD queue identifier for CoreBluetooth operations.
private let kIntegratorBleQueueLabel: String = "com.integrator.ble"

/// Info.plist key required by macOS TCC for CoreBluetooth access.
private let kBluetoothUsageDescKey: String = "NSBluetoothAlwaysUsageDescription"

/// Maximum BLE binary magic packet payload accepted over C FFI (`1024` bytes, bounding allocations).
private let kMaxBleBinaryPayloadBytes: Int = 1024

/// C callback signature delivering raw 17-byte binary magic packets (without 2-byte company ID).
public typealias IntegratorBleBinaryCallback = @convention(c) (UnsafePointer<UInt8>?, Int, Int16) -> Void

/// C callback signature delivering NUL-terminated LocalName magic packets (`IG2...`).
public typealias IntegratorBleNameCallback = @convention(c) (UnsafePointer<CChar>?, Int16) -> Void

/// Singleton coordinator driving macOS CoreBluetooth peripheral advertising and central scanning.
final class IntegratorBleController: NSObject, CBCentralManagerDelegate, CBPeripheralManagerDelegate {
    /// Process-wide singleton instance backing the C FFI entry points.
    static let shared = IntegratorBleController()

    /// Private serial GCD queue serializing all CoreBluetooth delegate events and state transitions.
    private let bleQueue = DispatchQueue(label: kIntegratorBleQueueLabel, qos: .utility)

    /// CoreBluetooth central scanner receiving peer Windows/macOS beacons.
    private var centralManager: CBCentralManager?
    /// CoreBluetooth peripheral advertiser broadcasting service UUID, LocalName, and GATT mirror.
    private var peripheralManager: CBPeripheralManager?
    /// Tracks whether `kIntegratorBleServiceUuid` has already been registered on `peripheralManager`.
    private var gattServiceAdded: Bool = false
    /// Cached read-only GATT characteristic mirroring the latest binary magic packet.
    private var gattCharacteristic: CBMutableCharacteristic?

    /// Registered Rust callback invoked on discovered `ManufacturerData` binary magic packets.
    private var onBinaryCb: IntegratorBleBinaryCallback?
    /// Registered Rust callback invoked on discovered Service UUID or `LocalName` hints.
    private var onNameCb: IntegratorBleNameCallback?

    /// Pending 128-bit dynamic Service UUID string queued for peripheral advertisement.
    private var pendingServiceUuid: String?
    /// Pending `IG2...` LocalName string queued for scan-response advertisement.
    private var pendingLocalName: String?
    /// Pending 17-byte binary magic packet served over GATT read requests.
    private var pendingBinaryPayload: Data?
    /// Desired central scanning state across Bluetooth power-state transitions.
    private var wantsScan: Bool = false
    /// Desired peripheral advertising state across Bluetooth power-state transitions.
    private var wantsAdvertise: Bool = false

    /// Verifies that `.app` bundles declare `NSBluetoothAlwaysUsageDescription` in `Info.plist` before
    /// initializing CoreBluetooth objects (preventing fatal macOS TCC termination).
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

    /// Initializes CoreBluetooth central/peripheral managers on `bleQueue` and applies scan/advertise flags.
    ///
    /// - Parameters:
    ///   - enableScan: Enables central scanning with duplicate reporting (`withServices: nil`).
    ///   - enableAdvertise: Enables peripheral advertising for macOS discovery hints.
    ///   - binaryCb: Optional callback receiving binary `ManufacturerData` magic packets.
    ///   - nameCb: Optional callback receiving Service UUID or `LocalName` string hints.
    /// - Returns: `true` if TCC plist check passes and startup was queued; `false` if missing usage description.
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
                        options: [CBCentralManagerOptionShowPowerAlertKey: false]
                    )
                } else if self.peripheralManager?.state == .poweredOn {
                    self.applyAdvertisementLocked()
                }
            }
        }
        return true
    }

    /// Updates the pending advertisement payload on `bleQueue` and refreshes active CoreBluetooth advertising.
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

    /// Halts scanning and advertising on `bleQueue` and clears pending payloads and callbacks.
    func stop() {
        bleQueue.async { [weak self] in
            guard let self = self else { return }
            self.wantsScan = false
            self.wantsAdvertise = false
            self.centralManager?.stopScan()
            if self.peripheralManager?.isAdvertising == true {
                self.peripheralManager?.stopAdvertising()
            }
            self.pendingServiceUuid = nil
            self.pendingLocalName = nil
            self.pendingBinaryPayload = nil
            self.onBinaryCb = nil
            self.onNameCb = nil
        }
    }

    /// Begins duplicate-enabled passive BLE scanning when radio is powered on (`bleQueue` only).
    private func startScanningLocked() {
        guard wantsScan, let cm = centralManager, cm.state == .poweredOn else { return }
        // Pass `withServices: nil` so macOS also receives Windows ManufacturerData-only beacons.
        cm.scanForPeripherals(
            withServices: nil,
            options: [CBCentralManagerScanOptionAllowDuplicatesKey: true]
        )
    }

    /// Registers the mirrored read-only GATT service once and starts advertising Service UUID + LocalName (`bleQueue` only).
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
        // Validate dynamic UUID before calling CBUUID(string:), which throws NSInvalidArgumentException on invalid strings.
        let advUuid: CBUUID
        if let dyn = pendingServiceUuid?.trimmingCharacters(in: .whitespacesAndNewlines),
           !dyn.isEmpty,
           UUID(uuidString: dyn) != nil
        {
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

    /// Starts scanning automatically when CoreBluetooth reports `.poweredOn`.
    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        if central.state == .poweredOn && wantsScan {
            startScanningLocked()
        }
    }

    /// Parses Integrator magic packets from discovered peripherals' ManufacturerData, ServiceUUIDs, and LocalName.
    func centralManager(
        _ central: CBCentralManager,
        didDiscover peripheral: CBPeripheral,
        advertisementData: [String: Any],
        rssi RSSI: NSNumber
    ) {
        let rssiVal = Int16(clamping: RSSI.intValue)

        // 1. Check ManufacturerData (Company ID 0xFFFF + >=17-byte IG2 magic packet from Windows) without heap copies.
        if let mfg = advertisementData[CBAdvertisementDataManufacturerDataKey] as? Data,
           mfg.count >= 19,
           mfg[0] == kIntegratorBleCompanyIdLow,
           mfg[1] == kIntegratorBleCompanyIdHigh,
           mfg[2] == 0x49, // 'I'
           mfg[3] == 0x47, // 'G'
           mfg[4] == 0x32, // '2'
           let cb = onBinaryCb
        {
            let payloadLen = mfg.count - 2
            mfg.withUnsafeBytes { rawBuf in
                if let ptr = rawBuf.baseAddress?.assumingMemoryBound(to: UInt8.self) {
                    cb(ptr.advanced(by: 2), payloadLen, rssiVal)
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

    /// Starts peripheral advertising automatically when CoreBluetooth reports `.poweredOn`.
    func peripheralManagerDidUpdateState(_ peripheral: CBPeripheralManager) {
        if peripheral.state == .poweredOn && wantsAdvertise {
            applyAdvertisementLocked()
        }
    }

    /// Serves offset-checked GATT reads for the mirrored binary magic characteristic.
    func peripheralManager(_ peripheral: CBPeripheralManager, didReceiveRead request: CBATTRequest) {
        guard request.characteristic.uuid == kIntegratorBleCharUuid,
              let payload = pendingBinaryPayload
        else {
            peripheral.respond(to: request, withResult: .attributeNotFound)
            return
        }
        guard request.offset >= 0 && request.offset <= payload.count else {
            peripheral.respond(to: request, withResult: .invalidOffset)
            return
        }
        request.value = payload.subdata(in: request.offset..<payload.count)
        peripheral.respond(to: request, withResult: .success)
    }
}

// MARK: - C FFI Exports

/// Starts macOS CoreBluetooth BLE scanning and/or advertising with the given C hint callbacks.
///
/// - Parameters:
///   - enableScan: Enable central scan mode (`CBCentralManager`).
///   - enableAdvertise: Enable peripheral advertisement mode (`CBPeripheralManager`).
///   - binaryCb: Optional callback receiving raw `IG2` ManufacturerData bytes and RSSI.
///   - nameCb: Optional callback receiving UTF-8 `IG2` LocalName or `7A4E...` UUID strings and RSSI.
/// - Returns: `true` if startup was scheduled; `false` if bundle lacks `NSBluetoothAlwaysUsageDescription`.
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
///
/// - Parameters:
///   - serviceUuidPtr: NUL-terminated UTF-8 128-bit Service UUID string.
///   - localNamePtr: NUL-terminated UTF-8 `IG2...` LocalName string.
///   - binPtr: Raw pointer to binary magic payload bytes.
///   - binLen: Length of `binPtr` in bytes (`1..kMaxBleBinaryPayloadBytes`).
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
          binLen > 0,
          binLen <= kMaxBleBinaryPayloadBytes
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
