//! # Display Subsystem: High-Performance Cross-Platform Extended Desktop
//!
//! ## 1. Module Purpose & Scope
//! This module owns the end-to-end orchestration of the **Display Extension Subsystem**
//! (`display` feature flag) for Integrator. It enables seamless, low-latency, bi-directional
//! extended desktop streaming between macOS and Windows 11 over high-speed physical links
//! (Thunderbolt / USB4 direct cable) and local area networks (Wi-Fi 6 / 2.5GbE).
//!
//! ### Core Subsystem Responsibilities
//! - **Dual-Directional Display Pipeline**:
//!   - **Mac -> PC**: macOS serves as the host machine extending its workspace onto the Windows PC.
//!     Spawns an in-process virtual display (`virtual_display.m` via private `CGVirtualDisplay` SPI),
//!     dynamically targets Sunshine capture (`sunshine.conf` `output_name`), encodes via Apple Silicon
//!     VideoToolbox hardware encoders, and streams to Moonlight on Windows (decoded via D3D11 / NVDEC /
//!     AMF / Intel QSV).
//!   - **PC -> Mac**: Windows 11 serves as the host machine extending its workspace onto the Mac.
//!     Enables a native Windows Virtual Display Driver (VDD - IddSampleDriver / Apollo Indirect Display)
//!     via PnP and `VddCtl.exe`, captures the virtual display via DXGI Desktop Duplication, encodes via
//!     discrete GPU hardware (NVIDIA NVENC, AMD AMF, or Intel QuickSync), and streams to Moonlight on
//!     macOS (decoded via VideoToolbox).
//! - **Control & Session Orchestration**: Manages RPC messaging over mutually authenticated
//!   `TransportSessionV2` (`ServiceId::DisplayRpc`, port [`crate::config::CONTROL_PORT`] = `58281`).
//!   Handles automated resolution/refresh matching, dynamic bitrate calculations, non-destructive
//!   Moonlight pairing slot preservation, and clean teardown.
//! - **GPU Preference Routing**: On Windows, directs high-power discrete GPUs for video encoding
//!   while managing decoder preferences via `HKCU\Software\Microsoft\DirectX\UserGpuPreferences`.
//!
//! ## 2. Cross-Subsystem Architectural Coexistence
//!
//! ### Display Streaming vs. Camera Streaming
//! The display streaming subsystem operates concurrently alongside the **Shared Camera Subsystem**
//! (`camera/mod.rs`, `camera_macos.swift`, `camera_windows.cpp`, `vcam_windows.cpp`):
//! - **Display Pipeline**: Operates over Sunshine/Moonlight streaming ports (TCP/UDP 47989, 48989, 47998-48010)
//!   and Display Control RPC (TCP 58281). Utilizes hardware-accelerated H.264/HEVC compression to deliver
//!   high-framerate (up to 240Hz), low-latency desktop imagery.
//! - **Camera Pipeline**: Operates over a dedicated authenticated channel (`TransportSessionV2` on TCP 58287).
//!   Transfers uncompressed 720p30 NV12 bi-planar video frames directly into Windows 11 Media Foundation
//!   FrameServer (`integrator_vcam.dll`), bypassing video compression artifacts to provide instant,
//!   low-overhead camera input to Windows conferencing apps without third-party drivers or physical camera
//!   source wrapper attributes.
//!
//! Both pipelines run concurrently without port conflicts, thread contention, or encoder resource starvation.
//!
//! ## 3. Architectural Linkages & Cross-Platform Flow
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────────────────┐
//! │                          macOS (Display Host)                          │
//! │                                                                        │
//! │  DisplayController::start_mac_to_pc                                    │
//! │         │                                                              │
//! │         ├─► CGVirtualDisplay (`virtual_display.m`) [Integrator EDID]   │
//! │         ├─► Configure Sunshine `output_name` (`mac_display.rs`)        │
//! │         ├─► Launch Sunshine.app via LaunchServices                     │
//! │         └─► Send DisplayRpcRequest::StartMoonlight (TCP :58281)        │
//! └─────────┼──────────────────────────────────────────────────────────────┘
//!           │
//!           │  Encrypted TransportSessionV2 (ServiceId::DisplayRpc)
//!           ▼
//! ┌────────────────────────────────────────────────────────────────────────┐
//! │                        Windows 11 (Display Client)                     │
//! │                                                                        │
//! │  DisplayServer (:58281) -> DisplayController::handle_rpc               │
//! │         │                                                              │
//! │         ├─► Non-destructive Moonlight registry slot resolution         │
//! │         ├─► WinDisplayManager::start_moonlight_client                  │
//! │         └─► Fullscreen D3D11 / NVDEC Hardware Accelerated Render       │
//! └────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## 4. Threading & Concurrency Model
//! - **Tokio Multi-Threaded Async Runtime**: Manages the TCP listener (`DisplayServer`) and RPC client requests.
//! - **Session Transition Serialization**: `DisplayController` uses an internal Tokio `Mutex<()>`
//!   (`transition_lock`) to guarantee that start, stop, and toggle operations are strictly serialized,
//!   preventing race conditions or concurrent display reconfigurations.
//! - **Blocking OS Isolation**: All process spawning (`open`, `schtasks.exe`, `taskkill.exe`, `powershell.exe`)
//!   and registry queries are executed on blocking worker threads via `tokio::task::spawn_blocking`.
//!
//! ## 5. Security & Safety Invariants
//! - **Mutual Ed25519 Authentication**: Display RPC connections require mutual authentication and SPAKE2 pairing.
//! - **Loopback Command Guarding**: Sensitive RPC requests (`PasteRemote`, `ShowWindow`, `GetPairingPin`,
//!   `PairWithPeer`) are restricted to local loopback CLI callers.
//! - **Path Traversal Protection**: Binary discovery for `sunshine` and `moonlight` searches only trusted system
//!   directories and protected Program Files paths.

/// Wire protocol data structures, serialization logic, and feature mapping.
pub mod protocol;

/// macOS display manager: in-process CGVirtualDisplay, Sunshine configuration, and Moonlight execution.
pub mod mac_display;

/// Windows display manager: Virtual Display Driver (VDD) PnP control, GPU routing, and Moonlight client.
pub mod win_display;

/// High-level display session controller, state machine, and RPC handler.
pub mod controller;

/// TCP RPC listener and connection demultiplexer for display control commands.
pub mod server;

pub use controller::DisplayController;
pub use server::DisplayServer;
pub use protocol::DisplayRpcRequest;
#[allow(unused_imports)]
pub use win_display::WinDisplayManager;
#[allow(unused_imports)]
pub use mac_display::MacDisplayManager;
