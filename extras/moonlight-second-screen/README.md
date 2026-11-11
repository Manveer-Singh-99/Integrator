# Moonlight + Sunshine Second-Screen Auto-Switcher

Fast, automated second-screen display extensions across macOS, Windows, and iPadOS over direct USB-C CDC-NCM (`10.99.99.x` / `192.168.2.x`) or local network fallback.

---

## 1. Mode A: PC &rarr; Mac / iPad (PC as Host)

Windows acts as the host workstation; your MacBook and/or iPad acts as high-refresh extended monitors.

- **`detect_connection.ps1`**: Probes USB-C, Hotspot, and Wi-Fi links in `<80 ms`, updating registry host addresses.
- **`toggle.ps1`**: Dynamically toggles Virtual Display Driver (VDD) monitors (1 or 2 virtual monitors) and signals Sunshine / Moonlight.
- **`stream-pc-screen.sh`**: macOS client launcher for Moonlight.

---

## 2. Mode B: Mac &rarr; Windows PC (Mac as Host)

MacBook Pro acts as the primary workstation; your Windows laptop / PC (e.g. HP OMEN 16" 165Hz) acts as an ultra-smooth extended second screen.

### Mac Side
- **`Toggle-Second-Screen.applescript`**: Toggles the second display workflow:
  - Spawns/terminates `vd165` virtual display (`1920x1200 @ 165Hz`).
  - Sets Sunshine display ID using `set_sunshine_display`.
  - Starts Sunshine and signals Windows over SSH to launch Moonlight via Task Scheduler (`LaunchMoonlightWin`).
  - On toggle off, kills `vd165`, Sunshine, and stops Moonlight on Windows.
  - Compile with:
    ```bash
    osacompile -o "/Applications/Toggle Second Screen.app" Toggle-Second-Screen.applescript
    ```
- **`set_sunshine_display.swift`**: Queries CoreGraphics for active virtual display IDs and updates `~/.config/sunshine/sunshine.conf`.
- **`detect-pc-link.sh`**: Rapidly probes the active USB-C / Wi-Fi interface.

### Windows Side
- **`Stream-Mac-Second-Screen.ps1`**:
  - Dynamically resolves Mac host IP (`10.99.99.2`).
  - Updates Moonlight host registry entry (`HKCU:\Software\Moonlight Game Streaming Project\Moonlight\hosts\2`).
  - Probes Mac port `47989` to verify Sunshine readiness before launching.
  - Launches Moonlight in full-screen mode at native resolution (`1920x1200 @ 165Hz`, 100 Mbps bitrate, host audio).
- **`Stream-Mac-Second-Screen.bat`**: Wrapper for Task Scheduler.
- **Windows Task Scheduler (`LaunchMoonlightWin`)**: Configured with `DisallowStartIfOnBatteries = false` and `MultipleInstancesPolicy = StopExisting` so it triggers instantly on battery or AC power.
