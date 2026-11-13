# 📦 Legacy Proof-of-Concept Scripts

This folder contains the original standalone scripts, kernel bridge implementations, and detection utilities developed during **Phase 1 and Phase 2** of the project before the unified [Integrator Tauri v2 Companion App](../app/) was created.

---

## Folder Contents

### 1. `windows/` (Standalone Windows CDC-NCM Setup)
* **`Install-AppleUsbNcm.ps1`**: Automated script that generates a compliant Windows 11 v2 Security Catalog (`AppleWinUsb.cat`) directly via `wintrust.dll` (`CryptCATOpen` `0x200` with `DRIVER_ACTION_VERIFY`), creates a local TrustedPublisher certificate, signs the catalog, and installs `WinUSB.sys` for `USB\VID_05AC&PID_1902` with **Secure Boot ON**, **Test Signing OFF**, and zero reboots.
* **`AppleUsbNcmBridge.cs`**: Zero-polling kernel interrupt-driven user-mode bridge that decapsulates/encapsulates 16-bit CDC-NCM Network Transfer Blocks (`NCMH` / `NCM0`) between `WinUSB` and the `WinTun` virtual network adapter (`10.99.99.1/24`). Compiled automatically by `Install-AppleUsbNcm.ps1` using Windows built-in `csc.exe`.

### 2. `macos/` (Standalone macOS Network Setup)
* **`install-macos.sh`**: Configures the Mac's `AppleUSBDeviceNCM` interface (`en3` / `en5`) to static IP `10.99.99.2/24` and installs an event-driven LaunchDaemon watchdog (`apple-usb-ncm-watchdog.sh`) via `scutil` dynamic store notifications (`0.0%` CPU, zero polling).

### 3. `moonlight-second-screen/` (Moonlight + Sunshine Auto-Switcher)
* **`detect_connection.ps1` & `detect-pc-link.sh`**: Fast, zero-CIM mutual connection watchdogs that detect USB-C cable links (`10.99.99.x` / `192.168.2.x`) vs. Wi-Fi (`192.168.137.x`).
* **`Stream-Mac-Second-Screen.ps1` & `Stream-Mac-Second-Screen.bat`**: Windows-side stream launcher syncing Sunshine and Moonlight with `<80 ms` handshake.
* **`set_sunshine_display.swift` & `stream-pc-screen.sh`**: Mac-side virtual display switcher and stream orchestrator.
* **`CfgMgr.cs`**: Native P/Invoke wrapper for `cfgmgr32.dll` to listen for device arrival and removal notifications without polling.

---

> [!NOTE]
> All new development, GUI dashboards, Touch Bar HUD, clipboard streaming, and master switches are now integrated into the [Integrator Tauri Companion App](../app/). These scripts are preserved here for transparency, headless/CLI server deployments, and standalone driver debugging.
