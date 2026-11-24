//! # Integrator Core Library (`lib.rs`)
//!
//! ## 1. Module Purpose & Scope
//! `lib.rs` defines the top-level crate root for the `integrator` application engine.
//! The Integrator system delivers seamless, hardware-accelerated cross-platform integration
//! between macOS (Apple Silicon & Intel) and Windows 11 (x86_64 & ARM64).
//!
//! This library exposes:
//! - High-performance virtual display mirroring and extension with hardware H.264/HEVC/AV1 encoding.
//! - Bidirectional low-latency KVM (keyboard, mouse, trackpad gestures, scroll wheel injection).
//! - Sub-millisecond synchronized bidirectional clipboard sharing (text, RTF, HTML, PNG/TIFF images, and lazy file transfers).
//! - High-fidelity bidirectional audio streaming (48 kHz 16-bit stereo PCM) with jitter buffering and drift compensation.
//! - Virtual camera forwarding with native OS camera source registration.
//! - Automated peer discovery over local subnets, link-local interfaces, and direct Thunderbolt/USB4 bridges.
//! - Cryptographic device pairing, mutual authentication, and encrypted wire transport using SPAKE2+, X25519, Ed25519, and ChaCha20-Poly1305.
//! - System telemetry, adaptive bitrate control, TrueTone color profile synchronization, and native OS autostart lifecycle.
//!
//! ## 2. Architectural Linkages & Dependencies
//! ### Upstream Callers:
//! - **Native Executable Entry Point**: `main.rs` (launches headless daemon, CLI subcommands, or diagnostics).
//! - **C / FFI Consumers**: `ffi.rs` exports standard C ABI entry points (`integrator_core_init`, `integrator_core_invoke`, etc.)
//!   consumed by:
//!   - `ui-macos/`: Native Swift / SwiftUI macOS application.
//!   - `ui-windows/`: Native C# / WinUI 3 / WPF Windows 11 application.
//!
//! ### Downstream Callees & Subsystems:
//! - `audio`: Low-latency audio capture and playback via CoreAudio (macOS) and WASAPI (Windows).
//! - `autostart`: OS login item / registry persistence via LaunchAgents (macOS) and Registry Run keys (Windows).
//! - `benchmark`: Network throughput, RTT, and hardware encode/decode benchmarking suite.
//! - `bridge`: Active connection RTT monitoring and physical link medium detection (Thunderbolt vs. Wi-Fi).
//! - `camera`: Virtual webcam pipeline leveraging CoreMediaIO DAL (macOS) and Media Foundation FrameServer (Windows).
//! - `clipboard`: OS pasteboard synchronization using `NSPasteboard` (macOS) and Win32 Clipboard API (Windows).
//! - `config`: Well-known protocol port constants and network configuration defaults.
//! - `core`: Global singleton runtime orchestrating lifecycle, state machines, IPC dispatch, and subsystem coordination.
//! - `discovery`: UDP multicast beacon broadcasting and listener daemon for zero-conf peer discovery.
//! - `display`: Screen capture (ScreenCaptureKit/Desktop Duplication) and display stream encoding/decoding.
//! - `features`: Dynamic capability negotiation and feature flag toggles between peers.
//! - `ffi`: C-compatible Foreign Function Interface bridge for native GUI frontends.
//! - `kvm`: Low-level input hooking (CGEventTap / SendInput) and synthetic remote input injection.
//! - `security`: Mutual authentication (SPAKE2+), wire encryption (ChaCha20-Poly1305), and replay-protected UDP datagrams.
//! - `storage`: Persistent local JSON configuration, trusted peer keystores, and device identity storage.
//! - `system_info`: Physical network interface topology, MTU probing, route classification, and battery/power metrics.
//! - `telemetry`: End-to-end metrics collection, packet loss calculation, RTT tracking, and IPC streaming.
//! - `truetone`: Ambient light sensing and display color temperature synchronization between paired machines.
//! - `trust`: Cryptographic trust store managing Ed25519 peer public keys and authorization states.
//!
//! ### Cross-Platform / Cross-Device Flow:
//! Data originates on a host machine (e.g. macOS capturing screen frames via ScreenCaptureKit or audio via CoreAudio),
//! is framed into versioned binary protocols, encrypted via the `security` transport layer, and transmitted over
//! TCP/UDP sockets to the peer machine (e.g. Windows 11 decoding via Direct3D11/DXVA-HD and playing via WASAPI).
//! Control commands, clipboard payloads, and state notifications flow symmetrically in both directions.
//!
//! ## 3. Threading & Concurrency Model
//! - **Tokio Asynchronous Multi-Thread Runtime**: Drives all network I/O, discovery loops, heartbeats, and IPC dispatch.
//! - **Dedicated OS Hook Threads**: Input hooks (macOS `CFRunLoop` event taps, Windows `WH_KEYBOARD_LL`/`WH_MOUSE_LL` message pumps)
//!   run on dedicated high-priority native OS threads to prevent input lag.
//! - **Media Pipeline Threads**: Display capture/encode and audio capture loops execute on dedicated real-time threads
//!   with OS-level thread priority boosting (`THREAD_PRIORITY_HIGHEST` / `QOS_CLASS_USER_INTERACTIVE`).
//!
//! ## 4. Security & Safety Invariants
//! - **Zero Plaintext Wire Exposure**: All communication past initial SPAKE2+ handshake uses authenticated ChaCha20-Poly1305 AEAD.
//! - **Memory Safety**: Rust safe code encapsulates all platform-specific `unsafe` FFI bindings with strict boundary validation.
//! - **Strict Rate Limiting**: All network listeners enforce bounded receive buffers and anti-DoS rate clamping.

#![deny(unsafe_op_in_unsafe_fn)]

/// Audio capture, resampling, jitter-buffered packetization, and WASAPI/CoreAudio playback.
pub(crate) mod audio;

/// Operating system startup registration (macOS LaunchAgent plist vs. Windows Run registry key).
pub(crate) mod autostart;

/// Network bandwidth saturation, latency evaluation, and hardware codec benchmark utilities.
pub(crate) mod benchmark;

/// Bluetooth Low Energy (BLE) magic-packet proximity discovery engine.
pub(crate) mod ble_discovery;

/// Standard Bonjour / mDNS (`_integrator._tcp.local.`) zero-configuration discovery engine.
pub(crate) mod bonjour_discovery;

/// Transport link latency (RTT) tracking and physical medium classification (Thunderbolt/Wi-Fi).
pub(crate) mod bridge;

/// Virtual webcam frame capture, packet framing, and OS virtual camera source integration.
pub(crate) mod camera;

/// Synchronized bidirectional clipboard engine supporting plain text, rich text, images, and files.
pub(crate) mod clipboard;

/// System-wide static network port assignments and protocol transport constants.
pub(crate) mod config;

/// Central application orchestrator managing lifecycle, state machines, and native UI dispatch.
pub mod core;

/// Local network peer beacon broadcasting, listener socket, and zero-conf neighbor discovery.
pub(crate) mod discovery;

/// Hardware-accelerated virtual display capture, H.264/HEVC/AV1 encoding, and remote rendering.
pub(crate) mod display;

/// Peer capability negotiation, runtime feature flags, and graceful degradation rules.
pub(crate) mod features;

/// External C ABI interface exposing `IntegratorCore` functions to Swift and C# frontends.
pub mod ffi;

/// Seamless cross-machine mouse, keyboard, and gesture routing with coordinate normalization.
pub(crate) mod kvm;

/// Windows GSMTC media session telemetry and remote playback transport controls.
pub(crate) mod media;

/// Cryptographic security layer implementing SPAKE2+, X25519, ChaCha20-Poly1305, and replay protection.
pub(crate) mod security;

/// Cross-platform OS permissions audit, launch prompting, and guided companion dependency installer.
pub(crate) mod setup;

/// Local filesystem persistence for device keys, trusted peers, and application configurations.
pub(crate) mod storage;

/// Hardware topology inspection, physical NIC enumeration, route table parsing, and thermal metrics.
pub(crate) mod system_info;

/// Real-time health monitoring, frame drop counters, latency histograms, and diagnostics reporting.
pub(crate) mod telemetry;

/// Ambient color profile reading and display white point synchronization across host and client.
pub(crate) mod truetone;

/// Persistent cryptographic peer identity trust management and authorization state storage.
pub(crate) mod trust;
