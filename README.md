# Integrator (mac-windows-usbc-bridge)

<div align="center">
  <img src="app/icons/icon.png" width="160" alt="Integrator App Icon" />
  <h1>Integrator</h1>
  <p><strong>Direct USB-C, Thunderbolt, Ethernet &amp; Wireless Workstation Fusion Bridge between Macs (Apple Silicon &amp; Post-2016 USB-C Intel) and Windows 11 PCs</strong></p>
  <p>$$\int_{\text{Windows 11}}^{\text{macOS}} (\text{Workstation Fusion})\, dt = \text{\textbf{Integrator}}$$</p>
</div>

**Low-latency (`<1 ms` wired) workstation fusion between Macs and Windows PCs — over a plain USB-C cable (`<1 ms` CDC-NCM on Apple Silicon with Secure Boot ON and zero reboots), Thunderbolt 3/4 Bridge, Wired Ethernet, or the Windows PC's Wireless Hotspot.**

> [!WARNING]
> **Intel Mac Testing Status:** Support for post-2016 Intel Macs with USB-C ports (Universal `arm64` + `x86_64` macOS `12.0+` build, wired via Ethernet / USB-C Ethernet adapters / Thunderbolt 3–4 Bridge or wireless via Windows PC Mobile Hotspot / LAN) has been added cleanly to the app, **however Intel Macs have NOT been tested at all as of now or for the foreseeable future.** Only Apple Silicon (M1) + Windows 11 have been physically tested.

Even though native Mac-to-Mac and Windows-to-Windows tools exist that can do this without any installation, this solution offers true zero latency and total flexibility. Furthermore, mobile devices (such as iPads, iPhones, and Android tablets) that can install Moonlight from their respective app stores can also act as high-performance extended displays. For now, only this cross-platform (Mac $\leftrightarrow$ Windows) implementation exists supporting USB 2.0 bidirectionally (meaning even standard USB-C charging cables work); other implementations for Mac-to-Mac and PC-to-PC will arrive when I get time.

> [!TIP]
> **Recommended: Use a Terminal / CLI Agentic AI for Setup**  
> While the overarching idea, architecture, and deployment logic behind this bridge were designed and directed by a human, all of the underlying code was 100% "vibecoded" using an agentic AI assistant. Because low-level USB-C gadget negotiation, custom WinUSB drivers, virtual WinTun adapters, and macOS dynamic store watchdogs can encounter system-specific quirks (such as interface name shifts, UAC permissions, or firewall rules), **you should really use a CLI-based agentic AI with terminal and system access (such as Antigravity CLI, Claude Code, Aider, Goose, etc. — rather than browser-based chat models) to help you set it up and adapt it to your specific machines.** Handing this repository to an agent in your terminal allows it to directly inspect your network interfaces, run the PowerShell and Bash scripts, and diagnose any environment-specific quirks automatically.
> 
> You can also enable auto-continue / auto-execution permissions on your agent so it runs commands and scripts autonomously without stopping to prompt you at every single step.
> 
> **⚠️ Disclaimer & Zero Liability:** This project interacts with low-level drivers, network adapters, device certificates, and system configurations. If you allow an AI agent to execute commands automatically or if anything gets messed up, broken, or misconfigured on your machine, **I take zero responsibility**. Use entirely at your own risk.

---

## Why Does Mac $\leftrightarrow$ Windows USB-C Networking Fail Out of the Box?

When you plug a standard USB-C cable (even a basic USB 2.0 charging cable) between an Apple Silicon Mac and another computer, the Mac's USB-C controller enters Dual-Role Device (`DRD`) gadget mode and exposes a **USB CDC-NCM Ethernet interface**:
* **On macOS:** Appears as `en3` / `en5` (`AppleUSBDeviceNCM`).
* **On Windows:** Appears in Device Manager under `USB\VID_05AC&PID_1902` (`MacBook Pro` / `Mac`).

Between two Macs (or a Mac and Linux), this brings up a point-to-point network link immediately. **On Windows 10 & 11, it completely fails (`CM_PROB_FAILED_START` / Code 10 or driverless interfaces).**

### The Root Cause (Hardware Descriptor & Driver Mismatch)
1. **Apple's Missing 8-Byte `IAD` (`VID_05AC&PID_1902`):**
   * Apple's USB Configuration Descriptor exposes **4 interfaces**:
     * `Interface 0`: CDC Communications Control (`Class 0x02`, `SubClass 0x0D` — CDC-NCM)
     * `Interface 1`: CDC Data (`Class 0x0A`, `AltSetting 0` = idle, `AltSetting 1` = Bulk IN `0x81` / Bulk OUT `0x01`)
     * `Interface 2 & 3`: Apple Vendor-Specific Debug Interfaces (`Class 0xFF`)
   * Under the USB-IF CDC-NCM specification, a composite device combining a 2-interface CDC-NCM function (`0` & `1`) with other interfaces (`2` & `3`) must include an **8-byte Interface Association Descriptor (`IAD`, `0x0B`)** grouping `Interface 0` and `Interface 1`.
   * Apple omitted the `IAD` and only included a legacy **CDC Union Functional Descriptor** (`0x24, 0x06`, `Master=0, Slave=1`).
2. **Windows' `usbccgp.sys` & `UsbNcm.sys` Rejection:**
   * Because the `IAD` is missing, Windows' composite bus driver (`usbccgp.sys`) splits `Interface 0` and `Interface 1` into isolated child PnP devices (`MI_00` and `MI_01`), preventing `UsbNcm.sys` on `MI_00` from accessing the Bulk data pipes on `MI_01`.
   * If you bypass `usbccgp.sys` and force `UsbNcm.sys` onto the parent composite device (`USB\VID_05AC&PID_1902`), `UsbNcm.sys` aborts `EvtDevicePrepareHardware` with `STATUS_INVALID_DEVICE_REQUEST` (`Code 10`) because of the extra `0xFF` vendor interfaces.

---

## How This Project Solves It (With Secure Boot ON & Zero Reboots)

```mermaid
flowchart LR
    subgraph Mac["Apple Silicon Mac (10.99.99.2/24)"]
        M_NCM["en3 / en5 (AppleUSBDeviceNCM)"]
    end

    subgraph Cable["Standard USB-C Cable"]
        USB["USB Bulk IN (0x81) / OUT (0x01)\nCDC-NCM 16-bit NTB ('NCMH' / 'NCM0')"]
    end

    subgraph Win["Windows 11 PC (10.99.99.1/24)"]
        W_USB["WinUSB.sys (Signed v2 Catalog oem.inf)\nBound to USB\\VID_05AC&PID_1902"]
        W_BRIDGE["AppleUsbNcmBridge.exe\n(Zero-CPU Kernel Interrupt Driven)"]
        W_TUN["WinTun Adapter ('Apple USB-C NCM')\nWHQL-Signed wintun.sys"]
        W_USB <--> W_BRIDGE <--> W_TUN
    end

    M_NCM <--> USB <--> W_USB
```

1. **Automated Windows 11 v2 Catalog & `WinUSB` Driver Installer (`Install-AppleUsbNcm.ps1`):**
   * Generates `AppleWinUsb.inf` binding Microsoft's inbox kernel-signed `WinUSB.sys` directly to the parent composite device `USB\VID_05AC&PID_1902` (giving a single handle access to both `Interface 0` and `Interface 1`).
   * Builds a compliant **Windows 11 v2 Security Catalog (`AppleWinUsb.cat`)** directly via `wintrust.dll` (`CryptCATOpen` `0x200` with `DRIVER_ACTION_VERIFY` SHA256 + SHA1 indirect data attributes), signs it with a locally generated Root/TrustedPublisher certificate, and installs it via `pnputil.exe`.
   * **Result:** Installs cleanly on Windows 11 with **Secure Boot ON**, **Test Signing OFF**, and **zero reboots**.
2. **Zero-Polling `WinUSB` $\leftrightarrow$ `WinTun` CDC-NCM Bridge (`AppleUsbNcmBridge.cs`):**
   * Opens `USB\VID_05AC&PID_1902` via `winusb.dll`, queries `GET_NTB_PARAMETERS`, sends `SET_NTB_INPUT_SIZE = 32764` (`0x86`), and flips USB `Interface 1` to `Alternate Setting 1`—which immediately activates `en3`/`en5` on the Mac (`status: active`).
   * Decapsulates/encapsulates 16-bit CDC-NCM Network Transfer Blocks (`NCMH` / `NCM0`), handles ARP (`0x0806`) in user-space, and bridges IPv4/IPv6 packets directly into a WHQL-signed **WireGuard `WinTun`** virtual network adapter (`10.99.99.1/24`).
   * **Zero Idle Battery Drain:** Uses `cfgmgr32.dll`'s `CM_Register_Notification` and infinite kernel waits (`WaitForSingleObject(..., INFINITE)`)—consuming **`0.00%` CPU** and zero timer wakeups when unplugged or idle.

---

## Benchmarks (USB-C Cable vs. Wi-Fi Hotspot)

| Metric | Wi-Fi Hotspot (`192.168.137.1`) | Direct USB-C Cable (`10.99.99.1`) |
| :--- | :--- | :--- |
| **Min Ping** | `3.64 ms` | **`0.72 ms`** |
| **Avg Ping** | `27.10 ms` | **`0.85 ms`** |
| **Max Ping (Spikes)** | `82.17 ms` | **`1.08 ms`** |
| **Jitter (`stddev`)** | `31.23 ms` | **`0.09 ms`** |
| **Packet Loss** | `0.0%` | **`0.0%`** |

---

## Hardware & Devices Tested

This project was developed, tested, and benchmarked on the following physical hardware:

| Device | Specifications | Role |
| :--- | :--- | :--- |
| **Apple Silicon Mac** *(Tested)* | **MacBook Pro 13" (M1, 2020)**<br>• Chip: Apple M1 (8 cores)<br>• Memory: 8 GB Unified Memory<br>• Native Display: 2560 × 1600 Retina @ 60Hz<br>• OS: macOS Sequoia | Client / Second Screen Display (supports plain USB-C CDC-NCM) |
| **Post-2016 Intel USB-C Macs** *(Untested)* | **MacBook / MacBook Pro / MacBook Air (2016–2020 USB-C, macOS 12.0+)**<br>• Architecture: `x86_64` Universal build<br>• Transports: Wired Ethernet (USB-C adapter or RJ-45), Thunderbolt 3/4 Bridge, or PC Wireless Hotspot<br>• ⚠️ **Not tested at all as of now or for the foreseeable future** | Best-effort `x86_64` target (plain USB-C CDC-NCM not supported on Intel xHCI) |
| **Windows 11 PC** | **HP OMEN Gaming Laptop (16")**<br>• CPU: Intel Core Ultra 9 285H (Arrow Lake)<br>• iGPU: Intel Arc 140T GPU (16GB shared, QuickSync Xe2)<br>• dGPU: NVIDIA GeForce RTX 5070 Laptop GPU (8GB GDDR6)<br>• Internal Display: 1920 × 1200 16:10 @ 165Hz<br>• OS: Windows 11 (Secure Boot ON, Test Signing OFF) | Host Workstation & Stream Server |
| **Mobile Extended Display** | **iPad (A16 / 10.9" Liquid Retina)**<br>• Native Resolution: 2360 × 1640 @ 60Hz<br>• Software: Moonlight Game Streaming (iPadOS App Store)<br>• Link: USB-C wired (Personal Hotspot NCM) or 5GHz Wi-Fi | Auxiliary Extended Display (Slot 0) |
| **Cables Tested** | Standard USB-C to USB-C charging cables (USB 2.0 480 Mbps lines) & full-spec USB4 / Thunderbolt cables | Point-to-point physical connection |

---

## Port & Cable Guide (Plain-English Edition)

Integrator connects a **Mac** and a **Windows PC** so they feel like one computer (shared mouse & keyboard, copy-paste, file drag-and-drop, and second screen).
Which cable you should use depends on **what kind of Mac you have** and **which ports are on your computers**.

### Step 1: Check Which Mac You Have
Click the **Apple logo ()** in the top-left corner of your screen → **About This Mac**:

* **Says "Chip: Apple M1 / M2 / M3 / M4..."** *(Late 2020 or newer)*
  **Great news:** You can connect directly to a Windows PC using just a regular **USB-C cable**. *(You'll just run the quick Windows setup script once in [Quick Start](#quick-start) below.)*
* **Says "Processor: Intel..."** *(2016–2020 Macs)*
  **Important:** Intel Macs **cannot** connect directly with a plain USB-C cable. Instead, connect them using an **Ethernet cable/adapter**, a **Thunderbolt cable** (if your PC also has Thunderbolt), or **Wi-Fi / PC Hotspot**.
  *(Note: Intel Macs are supported in software, but have **not been tested at all as of now or for the foreseeable future**.)*
* **macOS Version:** Your Mac needs **macOS 12 (Monterey) or newer**.

### Step 2: Know Your Ports (What They Look Like)

| Port Shape | Name | What It Looks Like |
| :--- | :--- | :--- |
| **Small oval** | **USB-C** | Looks like a modern phone / MacBook charger port (plugs in either way up). |
| **Small oval + ⚡ icon** | **Thunderbolt 3 / 4** | Same oval shape as USB-C, usually with a tiny **lightning bolt (⚡)** printed next to it. |
| **Big rectangle** | **USB-A** | The classic rectangular USB port (often blue inside on faster ports). |
| **Square clip-in port** | **Ethernet (LAN)** | Looks like an oversized phone jack where a network cable clicks in. |

#### Which Mac port should you plug into?
* **If you have a MacBook (Air or Pro):** Try the **USB-C port on the left side closest to the screen hinge** first. On some Macs, only that main port allows PC-to-Mac direct USB connections.
* **If you have a Mac mini, Mac Studio, or iMac with BOTH oval and rectangular ports:** **Always plug into an oval USB-C port**, never the big rectangular USB-A port on the Mac. *(On Mac mini / Studio, use the USB-C port closest to the power cord or Ethernet port first.)*

### Step 3: Pick the Right Cable or Connection

#### Option A: USB-C to USB-C Cable *(Small oval plug on both ends — Apple Silicon Macs only)*
This is the cleanest setup if you have an **M1 / M2 / M3 / M4 Mac** and your Windows PC has a **USB-C port**:
* **Best cable to use:** A **USB-C Data Cable** (the thicker, shorter kind that comes with portable SSDs or monitors, labeled **5 Gbps / 10 Gbps / 20 Gbps / USB 3.2**). It gives `<1 ms` delay, smooth high-refresh display streaming, and fast multi-gigabyte file copies.
* **MacBook charging cables (like Apple's white cord):** **Usually work!** Most MacBook charging cords are **USB 2.0 (480 Mbps)** — slower for giant files and extreme refresh rates, totally fine for mouse/keyboard, clipboard, and 60Hz screen extension.
* **Cheap phone charger cables:** Some very cheap charging-only cords have **no data wires inside** — if your PC doesn't react at all when plugged in, swap to a different USB-C cable.
* **Avoid active Thunderbolt cables for USB mode:** Some expensive Thunderbolt 3/4 cables (with a ⚡ and `3` or `4` on the plug) are wired only for Thunderbolt/video and skip standard USB wires. A regular USB-C data cable is much more reliable unless you specifically want Option C below.

#### Option B: USB-A to USB-C Cable *(Big rectangle on PC → Small oval on Apple Silicon Mac)*
Use this only if your **Windows PC has no USB-C port**, only rectangular USB-A ports:
* Plug the **big rectangle (USB-A)** into the **Windows PC**, and the **small oval (USB-C)** into the **M-series Mac**.
* Look inside the big USB-A plug: **blue (or teal/red) plastic inside** = faster 5–10 Gbps cable; **white or black plastic** = slower USB 2.0 cable. Make sure it's a **data cable**, not a power-only cord.
* *(Heads up: USB-A to USB-C should work per USB standards, though only USB-C to USB-C has been physically tested so far.)*
* **Never use a USB-A to USB-A cable** (big rectangle on both ends) — it will not work.

#### Option C: Thunderbolt 3 / 4 Bridge *(Lightning bolt ⚡ port on BOTH Mac and PC)*
* Only works if **both** your Mac and your Windows PC specifically have **⚡ Thunderbolt 3/4 or USB4 ports** (most Windows gaming/office laptops only have regular USB-C, not Thunderbolt networking).
* Use a **Thunderbolt 3 or Thunderbolt 4 cable**. Gives ultra-fast 10–40 Gbps speeds with zero extra USB drivers — works on **both Apple Silicon and Intel Macs** *(Intel Macs untested)*.

#### Option D: Wired Ethernet *(Universal fallback — works on EVERY Mac & PC)*
* If your Mac doesn't have an Ethernet port, buy a basic **USB-C to Gigabit Ethernet adapter** (an inexpensive adapter, around 15 USD), plug it into the Mac, and run a standard Ethernet cable to your **Windows PC's Ethernet port** (or connect both to your Wi-Fi router).
* Gives `<1 ms` wired speed and works on **Intel Macs, Apple Silicon Macs, and older USB-A Macs**.

#### Option E: Windows PC Wireless Hotspot or Wi-Fi *(Zero cables)*
* On your Windows PC, open **Settings → Network & internet → Mobile hotspot** and turn it on, then connect your Mac's Wi-Fi to that hotspot.
* Great when traveling or on college/office Wi-Fi where normal Wi-Fi blocks laptops from talking to each other.

### Step 4: Quick "Will My Setup Work?" Cheat Sheet

| Your Mac | Your Windows PC | Best Way to Connect | Will It Work? |
| :--- | :--- | :--- | :--- |
| **Apple M1–M4** (USB-C) | **USB-C** port | USB-C to USB-C data cable | **Yes — tested & primary setup** |
| **Apple M1–M4** (USB-C) | **Only USB-A** (rectangular) ports | USB-A (PC) → USB-C (Mac) data cable | **Should work** *(data cable only; not yet live-tested)* |
| **Apple M1–M4** (USB-C) | **Ethernet** or **Wi-Fi** | USB-C Ethernet adapter or PC Hotspot | **Yes** |
| **2016–2020 Intel Mac** (USB-C) | **USB-C** only (no Thunderbolt) | PC Wireless Hotspot, or USB-C Ethernet adapter | **Supported in app** *(Ethernet/Hotspot only — Intel Macs untested)* |
| **2016–2020 Intel Mac** (USB-C / ⚡) | **⚡ Thunderbolt 3/4 / USB4** port | Thunderbolt 3 or 4 cable | **Supported in app** *(Intel Macs untested)* |
| **Any Mac** using its **USB-A** port | Any **PC USB** port directly | Direct USB-A cable | **No** — use a **USB-A Ethernet adapter** or **Wi-Fi / Hotspot** instead |

### Quick Troubleshooting If It Doesn't Connect Right Away
1. **Try flipping or switching ports on the Mac:** Move the cable to the **left-side port closest to the screen** (MacBook) or **closest to the power plug** (Mac mini/Studio).
2. **Swap the cable:** If nothing happens at all, your cable is probably **charging-only** (no data wires). Try a thicker USB-C data cable.
3. **Check your Mac type:** If it's an **Intel Mac**, a plain USB-C cable won't create a network connection — switch to **Ethernet**, **Thunderbolt** (if supported by the PC), or **Windows Mobile Hotspot**.

---

## Quick Start

### 1. Connect the USB-C Cable
Plug any USB-C to USB-C cable between your Apple Silicon Mac and your Windows 11 PC.

### 2. Install on Windows 11 (Run PowerShell as Administrator)
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\windows\Install-AppleUsbNcm.ps1
```
This automatically:
* Generates, signs, and installs the `WinUSB` driver for `USB\VID_05AC&PID_1902` (zero reboots required).
* Downloads WHQL-signed `wintun.dll` (`v0.14.1`) from `wintun.net`.
* Compiles `AppleUsbNcmBridge.cs` using Windows' built-in `.NET Framework` compiler (`csc.exe`).
* Registers and starts the `AppleUsbNcmBridge` background service (`10.99.99.1/24`) and opens the Windows Firewall for `10.99.99.0/24`.

### 3. Install on macOS
```bash
sudo bash ./macos/install-macos.sh
```
This configures your Mac's `AppleUSBDeviceNCM` interface (`en3` / `en5`) at **`10.99.99.2/24`** and installs an event-driven LaunchDaemon watchdog (`apple-usb-ncm-watchdog.sh`) via `scutil` dynamic store notifications (`0.0%` CPU, zero polling). It automatically adapts to macOS Internet Sharing (`bridge100`), port changes (`en3`/`en5`), and cable reconnections.

### 4. Test the Link
From your Mac:
```bash
ping 10.99.99.1
```
From your Windows PC:
```powershell
ping 10.99.99.2
```
You can now use `10.99.99.1` (Windows) and `10.99.99.2` (Mac) for **Moonlight/Sunshine (`<1 ms` display streaming)**, **SMB file sharing (`smb://10.99.99.1`)**, **SSH**, **iperf3**, or **Synergy/Barrier**.

---

## Bidirectional Internet Sharing (Mac &harr; Windows)

The bridge supports dual-homed operation with **direct link-local (`10.99.99.x`)** running simultaneously alongside native internet sharing in **either direction** over the exact same physical USB-C cable:

* **Share Mac's Internet to Windows (`192.168.2.x`):** 
  * In macOS **System Settings > General > Sharing > Internet Sharing**, choose *Share your connection from: Wi-Fi* to *computers using: Ethernet Adapter (en3)* (or `en5`).
  * `AppleUsbNcmBridge` responds to ARP requests for both `10.99.99.1` and `192.168.2.2`, assigns default gateway `192.168.2.1` and DNS `192.168.2.1` / `1.1.1.1` to Windows automatically.
* **Share Windows' Internet to Mac (`192.168.137.x`):** 
  * In Windows **Network Connections (`ncpa.cpl`)**, right-click your active connection (e.g. high-speed physical Ethernet or 5G SIM card) &rarr; **Properties > Sharing > "Allow other network users to connect"** and select **Apple USB-C NCM**.
  * Windows ICS automatically binds gateway `192.168.137.1` and runs DHCP/NAT. The Mac receives high-speed wired internet directly over the USB-C charging cable without requiring a bulky USB-C Ethernet dongle!
* **Zero Disruption:** Moonlight, SSH, and SMB continue working seamlessly across either subnet regardless of which machine is sharing internet.

---

## Legacy Proof-of-Concept & Moonlight Auto-Switcher

In [`Legacy/moonlight-second-screen/`](Legacy/moonlight-second-screen/), you'll find fast, zero-CIM mutual detection scripts (`detect_connection.ps1`, `toggle.ps1`, `detect-pc-link.sh`, and `set_sunshine_display.swift`) that automatically detect whether your USB-C cable (`10.99.99.x` or `192.168.2.x`) is active or if you're on Wi-Fi (`192.168.137.x`), syncing Moonlight and Sunshine across both systems in `<80 ms`.

* **Bidirectional Second-Screen Display**: Supports both **PC &rarr; Mac/iPad** (using Windows Virtual Display Driver + Sunshine host and Moonlight client) and **Mac &rarr; PC** (using macOS `vd165` virtual display + Sunshine host and automated Moonlight fullscreen on Windows at native 1920&times;1200 @ 165Hz via `Toggle-Second-Screen.applescript`).
* **Mobile Devices as Extended Displays**: Any mobile device that can install the free Moonlight app from their app store (iOS/iPadOS App Store or Google Play) can also act as an ultra-low-latency extended display (wired over USB-C or wireless). The dynamic switcher automatically detects connected devices and dynamically allocates independent virtual displays (e.g. iPad 2360x1640 @ 60Hz and Mac 2560x1600 @ 60Hz) with plug-and-play auto-attach and zero phantom displays.

---

## ⚡ Integrator: The Unified Desktop Companion App (`v2.0` - Current Progress)

> [!IMPORTANT]
> **Project Status: Companion App Built & Operational!**
> What originally began as a collection of standalone shell scripts and PowerShell drivers has officially evolved into **Integrator**: a single, unified desktop companion application powered by a memory-safe **Rust core library** (`integrator_core` + CLI binary `integrator`) paired with native OS frontends — **SwiftUI / Liquid Glass on macOS** (`app/ui-macos`) and **WinUI 3 / Mica on Windows 11** (`app/ui-windows`).
>
> * **Icon & Branding**: Features a custom mathematical integration icon ($\int_{\text{Windows 11}}^{\text{macOS}}$) featuring a centered integral sign with pixel-matched Windows 11 (bottom-left) and macOS Finder (top-right) limits separated by a clean 54 px air-gap.
> * **Zero Ghost Daemons**: Enforces strict single-instance mutual exclusion (`Integrator` OS named `Mutex` on Windows + local control socket lock). Quitting the application cleanly terminates all background threads and hooks.
> * **Master ON/OFF Switches**: Every single fusion feature has an independent, persistent master toggle that gracefully winds down active socket streams, unmounts volumes, or dismisses HUDs when disabled.
> * **Clean Launch at Login**: Autostart is managed natively via macOS LaunchAgents (`~/Library/LaunchAgents`) and an elevated Windows Scheduled Task (`IntegratorAutostart`, `RunLevel Highest`) for UIPI-safe KVM input injection.

### Feature Implementation Status Matrix

| Fusion Feature | Platform | Status | Implementation Details |
| :--- | :---: | :---: | :--- |
| **Direct USB-C CDC-NCM Bridge** | macOS & Win 11 | ✅ **Live** | Hardened `WinUSB` $\leftrightarrow$ `WinTun` (`<0.7ms` ping, locked `C:\ProgramData\AppleUsbNcm` ACLs) |
| **Dual-Subnet Networking & ICS** | macOS & Win 11 | ✅ **Live** | Bidirectional Internet Sharing simultaneously alongside direct USB-C link |
| **Native SwiftUI & WinUI 3 UI** | macOS & Win 11 | ✅ **Live** | Real-time latency, peer discovery/block controls, category filters, Light/Dark contrast & live status pills |
| **Cryptographic Pairing & Transport** | macOS & Win 11 | ✅ **Live** | OS CSPRNG 6-digit PIN SPAKE2 RFC 9382 + Ed25519 mutual auth + ChaCha20-Poly1305 AEAD & SAS verification |
| **Universal Clipboard (Text & Images)** | macOS & Win 11 | ✅ **Live** | Bidirectional text & PNG/TIFF with SHA-256 verification and echo-loop prevention |
| **Universal Clipboard (Folders & Files)** | macOS & Win 11 | ✅ **Live** | Multi-GB, multi-item recursive folder copy-paste streaming over NVMe buffers with LRU pruning |
| **Live Network Benchmark Engine** | macOS & Win 11 | ✅ **Live** | Built-in real-time throughput benchmark saturating USB-C NVMe transfer speeds |
| **Touch Bar NVIDIA Performance HUD** | macOS (client) | ✅ **Live** | Liquid Glass OLED HUD with interactive physics and native Control Strip integration |
| **Auto-Mounted Shared Storage** | macOS & Win 11 | ✅ **Live** | Dynamic peer SMB share discovery (trust-gated), mount & clean teardown on macOS (`/Volumes/<Share>`) and Windows |
| **True Tone & Chromatic Adaptation** | macOS & Win 11 | ✅ **Live** | Mac ambient sensor (Kelvin) $\to$ Bradford CAT GPU gamma ramp injection |
| **Second-Screen Extended Display** | macOS & Win 11 | ✅ **Live** | Bidirectional streaming via Sunshine host + Moonlight client with dynamic resolution & refresh rate |
| **Universal Input KVM & Edge Hopping** | macOS & Win 11 | ✅ **Live** | Edge-hopping mouse/keyboard sharing, 2D desk alignment schematic, corner guard & panic key (`Ctrl+Alt+Shift+Esc`) |
| **Cross-Border File Drag & Drop** | macOS & Win 11 | ✅ **Live** | Cursor-following cross-screen file staging & transfer over authenticated AEAD transport |
| **Master ON/OFF Feature Switches** | macOS & Win 11 | ✅ **Live** | Independent persistent toggles saved to `~/.usbc_clipboard_cache/features.json` |
| **Native Launch at Login** | macOS & Win 11 | ✅ **Live** | User LaunchAgent (macOS) & Elevated Scheduled Task (`IntegratorAutostart` on Win 11) |
| **Dynamic Audio Routing** | macOS & Win 11 | 🧪 **Preview** | Experimental UDP packet sink (`58284`) & local 24-bit/48kHz spatial test chime; full CoreAudio/WASAPI duplex playback planned |
| **Touch ID Passkey & Windows Lock** | macOS & Win 11 | 🚧 **Scaffolded** | WebAuthn FIDO2 HID over USB/IP + Credential Provider DLL (`LogonUI.exe`) |
| **Apple Precision Trackpad Gestures** | macOS & Win 11 | 📋 **Planned** | Raw contact points streamed to virtual `vmulti` Precision Touchpad driver (`input_kvm` feature toggle) |
| **Universal Camera & Virtual Mic** | macOS & Win 11 | 📋 **Planned** | Hardware-accelerated `CMIOExtension` & DirectShow virtual media pipelines (`camera` feature toggle) |
| **Multi-WAN Packet Bonding** | macOS & Win 11 | 📋 **Planned** | Dynamic dual-gateway load balancing, ping protection, and failover (`multiwan` feature toggle) |

---

### Building & Running the Integrator Desktop App

The companion app is located in the [`app/`](app/) directory:

#### On macOS (Universal Apple Silicon + Intel, macOS 12.0+):
```bash
# Single-architecture build for this Mac:
cd app && cargo build --release

# Or build a Universal (arm64 + x86_64) .app bundle targeting macOS 12.0+ at app/target/bundle/Integrator.app:
bash ./macos/build-universal-app.sh
```
To run the packaged bundle or copy to your Applications folder:
```bash
# Executable binary located at:
./target/release/integrator

# Packaged macOS Application bundle:
open /Applications/Integrator.app
```

> [!NOTE]
> **Post-2016 Intel Macs (`x86_64`, USB-C):** Intel Macs cannot act as a plain USB-C CDC-NCM gadget (`USB\VID_05AC&PID_1902`), so skip `Install-AppleUsbNcm.ps1` and `install-macos.sh`. Instead, connect via **Thunderbolt 3/4 Bridge**, **Wired Ethernet** (USB-C Ethernet dongle / RJ-45, including routerless `169.254.x.x`), or the **Windows PC's Mobile Hotspot** (`192.168.137.x` — Integrator automatically opens scoped `LocalSubnet` Windows Firewall rules on startup and binds per-interface UDP broadcasts across both hosts). **Intel Macs have NOT been tested at all as of now or for the foreseeable future.**

#### On Windows 11 (x64 or ARM64):
```powershell
cd app
cargo build --release
dotnet build ui-windows\IntegratorUI.csproj -c Release -p:Platform=x64
```
`cargo build --release` builds `target\release\integrator.exe` (CLI) and `target\release\integrator_core.dll` (core FFI library), which `IntegratorUI.csproj` automatically copies alongside the elevated (`requireAdministrator`) WinUI 3 GUI binary `IntegratorUI.exe`.

---

### The Two Core Operating States

The unified app is designed around **two primary, mutually exclusive operating states** that govern how the two computers interact:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        PRIMARY OPERATING STATES                        │
│                                                                        │
│   ┌─────────────────────────────────┐ ┌────────────────────────────┐   │
│   │   STATE 1: EXTENDED DESKTOP     │ │ STATE 2: INPUT SHARING     │   │
│   │   • Single OS across displays   │ │ • Dual OS running together │   │
│   │   • Master & Slave hierarchy    │ │ • Dynamic Temporary Master │   │
│   │   • Slave inputs map to Master  │ │ • Active OS dictates keys  │   │
│   └─────────────────────────────────┘ └────────────────────────────┘   │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
               ┌────────────────────┴───────────────────┐
               ▼                                        ▼
┌────────────────────────────────────────────────────────────────────────┐
│                     INDEPENDENT MODULAR TOGGLES                        │
│  [✓] Universal Clipboard   [✓] Shared Folders   [✓] Camera & Mic       │
└────────────────────────────────────────────────────────────────────────┘
```

#### 🖥️ State 1: Extended Desktop Mode (Single-OS Workspace)
*In this mode, only **one operating system** is in control of the entire physical workspace, using the other machine's screen as a high-refresh external monitor.*

* **Role Definitions:**
  * **Master (Host):** The primary computer running the operating system and transmitting the low-latency display feed (e.g., your MacBook running macOS).
  * **Slave (Client):** The secondary computer whose physical screen acts as the extended display (e.g., your Windows laptop running the client display).
* **Unified Input & Smart Modifier Mapping:**
  * All input devices connected to the **Slave** (its built-in keyboard, trackpad, mouse, touchscreen) are forwarded across the USB-C link to control the **Master**.
  * **Automatic Modifier Translation:** Keystrokes originating on the Slave are dynamically remapped to match the Master's native OS conventions:
    * *When Mac is Master and Windows is Slave:* Pressing `Ctrl + C` or `Ctrl + V` on the Windows laptop keyboard maps to `Command ⌘ + C` / `Command ⌘ + V` on the Mac host.
    * *When Windows is Master and Mac is Slave:* Pressing `Command ⌘` on the Mac keyboard maps to `Ctrl` (or `Windows Key`) on the Windows host.
* **Touch Bar Integration (Windows Telemetry & Control Strip):**
  * When Windows is the Master and an OLED Touch Bar-equipped Mac acts as the extended display/terminal, the frontmost Mac client app captures the Touch Bar via `NSTouchBar`.
  * **Off-Screen NVIDIA Performance HUD**: Direct queries to NVIDIA Management Library (`nvml.dll` on Windows) stream GPU temperatures, power draw (Watts), GPU utilization, and clock speeds onto the 2170&times;60 OLED strip. This gives gamers a real-time hardware HUD without cluttering the primary gaming monitor with intrusive on-screen overlays (like GeForce `Alt+R`).
  * **Strict Scope Isolation**: Windows **only** gains control of the Touch Bar while in this specific mode. When Mac is the Master, or when running in Input Sharing mode, macOS retains 100% native control over its Touch Bar.

#### 🖱️ State 2: Universal Input Sharing Mode (Dual-OS KVM Workspace)
*In this mode, **both operating systems** run independently and visibly side-by-side. You use a single keyboard and mouse seamlessly across both machines via clean-room edge-hopping.*

* **Role Definitions (Dynamic Handover):**
  * **Temporary Master:** Whichever computer currently holds the active cursor on its screen.
  * **Temporary Slave:** The computer whose screen is currently idle without the cursor.
* **Dynamic Keyboard & Modifier Governance:**
  * The **Temporary Master** dictates the active keyboard mapping rules.
  * Whichever physical keyboard you type on, the inputs strictly adapt to the operating system where the cursor currently resides:
    * When your cursor crosses the border onto the **Mac**, the active modifier context switches to macOS (`Command ⌘` shortcuts, Mac-specific accents).
    * When your cursor crosses back onto **Windows**, the active modifier context immediately switches to native Windows (`Ctrl` / `Alt` / `Win` shortcuts).
* **Apple Glass Trackpad &rarr; Windows Precision Touchpad Gestures:**
  * When controlling Windows from the Mac, raw multi-touch contact points are streamed to a virtual **Windows Precision Touchpad** driver (`vmulti`).
  * Enables native Windows 11 multi-finger gestures on the Mac trackpad: **3-finger swipe up** for Task View, **3-finger swipe left/right** for Virtual Desktops, and 165Hz smooth inertia scrolling and pinch-to-zoom.
* **Bi-Directional Input Agnostic:** Seamlessly accepts input whether the user is typing on the MacBook keyboard/trackpad or their Windows gaming mouse and mechanical keyboard.
* **Edge Detection & Guard Logic:**
  * **Dead Corners:** User-configurable edge margins to prevent accidental switching when clicking the Apple menu, taskbars, or window close buttons (`X`).
  * **Switch Delay & Double-Tap:** Optional threshold buffers (e.g., 50–100ms) requiring an intentional push against the border to initiate the hop.

---

### Independent Modular Features (Live, Preview, Scaffolded & Planned)

Regardless of whether the app is in **Extended Desktop** or **Input Sharing** mode, all other features are organized as modular background services with independent feature flags:

* **📋 Universal Clipboard (✅ Live):**
  * Bidirectional clipboard synchronization for plain text, image bitmaps (PNG/TIFF), and recursive folder/file trees over authenticated `TransportSessionV2` (`ITR2`, X25519 + ChaCha20-Poly1305 AEAD) transport.
  * Cryptographic SHA-256 payload verification and hash-based deduplication to prevent infinite ping-pong echo loops between devices.
* **📂 Cross-Border File Drag & Drop ("AirDrop Across Screens" — ✅ Live):**
  * Click and drag any file from macOS Finder past the screen boundary onto the Windows desktop (or vice versa).
  * A semi-transparent ghost thumbnail follows the cursor across operating systems, and releasing the mouse button streams the file buffer over the USB-C link directly into the target folder in milliseconds.
* **📁 Auto-Mounted Shared Folders (✅ Live):**
  * Discovers advertised or enumerated SMB shares on the connected peer and mounts them into `/Volumes/<Share>` on macOS and mapped drives on Windows.
  * Clean, automated unmounting when the link is disconnected or the storage toggle is turned off.
* **🔑 Touch ID as a Windows Security Key & Passkey Authenticator (🚧 Scaffolded):**
  * **Browser & Passkey Mode (WebAuthn / FIDO2 over Virtual USB/IP)**:
    * Turns your Mac into a biometric hardware security key (like a YubiKey) for Windows 11.
    * When Windows or a browser (Chrome/Edge) prompts for a WebAuthn passkey or hardware security key (Google, Microsoft, GitHub login), the Windows agent exposes a virtual FIDO2 HID device (`0xF1D0`) over `USBIP-Win`.
    * The Mac prompts Touch ID via `LocalAuthentication`, the Secure Enclave signs the assertion, and Windows completes authentication seamlessly with zero physical driver renegotiation.
  * **Native Windows 11 Lock Screen Unlock (Custom Credential Provider)**:
    * Solves the consumer Windows 11 lock screen limitation (where FIDO2 keys are restricted to Microsoft Entra ID / Azure AD) for fingerprint-less laptops like the HP OMEN.
    * Integrates a custom Windows Credential Provider DLL (`TouchIdCredentialProvider.dll`) directly into `LogonUI.exe`.
    * User credentials remain sealed with Windows **DPAPI**. When locked, a challenge nonce is transmitted over the direct USB-C link.
    * Resting your finger on the MacBook’s Touch ID sensor signs the nonce via the Apple Secure Enclave (`kSecAccessControlTouchIDCurrentSet`). The Credential Provider validates the signature and hands the logon token to **LSASS**, unlocking the Windows desktop in `<150ms`.
* **🎨 True Tone & Chromatic Adaptation Sync (Bradford CAT — ✅ Live):**
  * Reads ambient room lighting (CCT in Kelvin) from the Mac’s bezel ambient sensor.
  * Applies a **Bradford Chromatic Adaptation Transform (CAT)** with perceptual gamma compensation for matte vs. glossy panel differences.
  * Injects the resulting curves directly into the Windows GPU hardware Look-Up Table (`SetDeviceGammaRamp`) in `<0.1 ms`, ensuring both screens smoothly transition to the exact same paper-white warmth as ambient room lighting changes.
* **🎥 Universal Camera & Virtual Microphone (📋 Planned):**
  * Stream the MacBook’s FaceTime HD camera and studio mic into Windows as a native DirectShow / Media Foundation webcam.
  * Stream Windows camera or studio audio hardware into macOS via modern `CMIOExtension` virtual camera plugins.
  * Hardware-accelerated low latency (Apple VideoToolbox & NVIDIA NVENC).
* **🔊 Dynamic Audio Routing (System Tray Selector — 🧪 Experimental Preview):**
  * Currently implements an experimental UDP audio packet validator/sink (`58284`), topology state persistence, and a local 24-bit/48kHz spatial stereo test chime. Full cross-machine CoreAudio/WASAPI duplex playback is planned across three topologies:
    * **Mac Studio Speakers Only**: Automatically mutes the PC and pipes uncompressed 24-bit master audio to the MacBook's high-fidelity Spatial Audio sound system (<6ms latency).
    * **Windows PC / Headset Only**: Leaves audio on the PC (ideal when gaming with a low-latency headset or DAC plugged into Windows).
    * **Dual Stereo / Surround (Both Simultaneously)**: Plays across both physical machines with an integrated millisecond sync-calibration slider to eliminate room echo and comb-filtering.
* **📡 Cryptographic Pairing & Automatic Handover (✅ Live):**
  * Mutual peer discovery across direct USB-C (`10.99.99.x` / `192.168.2.x`) and local Wi-Fi/LAN with Ed25519-signed UDP beacon verification (`58280`).
  * Seamless fallback to wireless if the cable is disconnected, and instant handover to wired speed when plugged back in.
  * End-to-end encrypted control (`58281`), clipboard (`58283`), benchmark (`58285`), and KVM/drag-drop (`58286`) channels via `TransportSessionV2` (`ITR2`: ephemeral X25519 ECDH + HKDF-SHA256 + ChaCha20-Poly1305 AEAD), paired via an OS CSPRNG 6-digit PIN SPAKE2 (RFC 9382) + Ed25519 + SAS handshake with per-IP/global rate-limiting and lockout.
* **🌐 Multi-WAN Bonding & Dynamic Dual-Gateway Load Balancing (📋 Planned):**
  * Turns your desk into a high-availability dual-WAN router node by bonding independent internet connections across both machines over the `<0.6ms` USB-C interconnect:
    * **Local Multi-Socket Balancing (Zero 3rd Device / Zero Cloud)**: Routes distinct connections and chunked downloads (HTTP range requests, Steam, git clones, large assets) across both connections simultaneously (e.g. 100 Mbps Mac Wi-Fi + 150 Mbps Windows 5G/Ethernet = 250 Mbps combined throughput) without session breaking or account lockouts.
    * **Traffic Isolation & Ping Protection**: Routes latency-sensitive gaming packets (UDP) exclusively through the stable wired connection while offloading heavy background downloads and 4K video to the secondary link, guaranteeing zero in-game ping spikes.
    * **True Packet Bonding (Cloud-Assisted Option)**: For seamless single-stream aggregation (e.g. uninterrupted Zoom calls or live Twitch broadcasts across dropping Wi-Fi), optionally tunnels through an MPTCP / Speedify-style VPS proxy to present a single unified public IP.

---

### 🛡️ Architectural Safeguards & Quality of Service (QoS)

To guarantee that the companion app never causes frame drops, audio stutter, memory thrashing, or connection drops—even under worst-case cable bottlenecks—the system enforces strict hardware safeguards:

#### 1. Bandwidth Precedence & Automatic Degradation Ladder (USB 2.0 Fallback)
When running all features simultaneously over a standard USB-C charging cable (USB 2.0 physical limit: 480 Mbps half-duplex / ~320 Mbps usable throughput), the daemon's internal packet scheduler enforces a strict **6-Tier QoS Hierarchy**:

```
[ Tier 0: Strict Priority ]  Mouse, Keyboard, Touch ID, Keepalives    (< 0.5 Mbps)  --> NEVER DELAY / NEVER DROP
[ Tier 1: Isochronous     ]  Low-Latency Audio (Mac Soundbar Sink)    (~ 0.3 - 2 Mbps) --> DYNAMIC OPUS FALLBACK
[ Tier 2: Real-Time Stream]  165Hz Display (Sunshine -> Moonlight)    (Adaptive)   --> DYNAMIC BITRATE ABR / FRAME DROP
[ Tier 3: Secondary Video ]  Universal Webcam Feed                    (Adaptive)   --> DOWNSCALED TO 720p30
[ Tier 4: Background Bulk ]  File Drag-and-Drop / Large Clipboard     (Elastic)    --> TOKEN-BUCKET CLAMPED
[ Tier 5: Scavenger       ]  Multi-WAN / Two-Way Internet Sharing     (Elastic)    --> FIRST TO BE CHOKED
```

* **Automatic Graceful Degradation Ladder**:
  1. *Link > 220 Mbps*: Audio automatically flips from uncompressed 24-bit PCM to transparent Opus (256 kbps), saving ~2 Mbps with zero audible difference.
  2. *Link > 250 Mbps*: Background file transfers and internet sharing are clamped to a 40 Mbps ceiling via a token-bucket rate limiter.
  3. *Queue Delay > 12ms*: Sunshine drops HEVC bitrate dynamically (80 Mbps $\to$ 35 Mbps) via NVENC/VideoToolbox rate control.
  4. *Persistent Congestion*: Universal Webcam scales down from 1080p60 to 720p30.
  5. *Critical Saturation*: Display frame rate steps down (165Hz $\to$ 120Hz $\to$ 60Hz), dropping frames rather than buffering latency. **Input (Tier 0) is never delayed.**

#### 2. Hardware Engine & Memory Safeguards (8 GB M1 & RTX 5070 Rules)
* **Apple M1 Single Media Engine Protection**: The base M1 processor features **only one hardware video encode ASIC**. Running a 165Hz display stream concurrently with a 1080p webcam will time-slice the encoder (spiking display latency from 5ms to 30ms) or drop to CPU software encoding. When the 165Hz display is active, the webcam stream automatically drops to 720p or utilizes uncompressed USB transfer to spare the hardware encoder.
* **Zero-RAM File Streaming Policy**: On memory-constrained machines (such as 8 GB unified memory MacBooks), the clipboard and drag-and-drop engines are strictly forbidden from buffering files in RAM. All transfers use fixed 64 KB ring buffers streaming directly from disk to disk (`std::fs::File`), guaranteeing an active memory footprint under 35 MB regardless of whether transferring 10 MB or 50 GB.
* **macOS `WindowServer` 165Hz Idle Throttling**: To prevent `WindowServer` from consuming 40–60% CPU redrawing static frames at 165Hz, the capture engine monitors dirty rectangles. When no screen changes occur for >200ms, frame polling drops to 10 FPS and ramps back to 165 FPS on the first cursor movement.
* **Dedicated CDC-NCM Cable Integrity**: The physical USB-C connection never re-enumerates or switches device personalities live. The physical wire remains 100% CDC-NCM Ethernet (`10.99.99.x`), and all auxiliary USB devices (FIDO2 keys, virtual gamepads, Precision Trackpad) are virtualized over IP, eliminating physical bus disconnects.

---

*The ultimate goal: two computers, one workspace.*

---

## License
MIT License
