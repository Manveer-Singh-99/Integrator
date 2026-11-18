//! # Universal Input KVM Subsystem Module
//!
//! ## 1. Module Purpose & Scope
//! The `kvm` module implements the core Input KVM (Keyboard, Video/Mouse control multiplexer)
//! and cross-screen drag-and-drop subsystem for Integrator. It enables seamless cursor and
//! keyboard boundary-hopping between a macOS host (Apple Silicon / Intel) and a Windows 11 host
//! connected over high-speed encrypted network links (Thunderbolt 4 / USB4, 10GbE, or Wi-Fi 6E).
//!
//! ### Core Subsystem Responsibilities:
//! - **Boundary Hopping & Coordinate Normalization**: Captures pointer events approaching
//!   configured display edges, computes normalized fractional offsets `[0.0, 1.0]`, and projects
//!   them onto the peer machine's display coordinate space regardless of DPI, physical resolution,
//!   or aspect ratio disparities.
//! - **OS Event Interception & Low-Level Ingestion**: Utilizes native OS hooks
//!   (`CGEventTap` on macOS, low-level hooks `WH_MOUSE_LL` / `WH_KEYBOARD_LL` on Windows) to swallow
//!   hardware input events when crossing borders and forward them over low-latency encrypted TCP.
//! - **Remote Synthetic Injection**: Injects remote input events natively via Quartz Display
//!   Services (`CGEventPost`) and IOKit HID on macOS, or Win32 `SendInput` on Windows.
//! - **Cross-Screen Drag & Drop**: Extends boundary hopping to active OS drag sessions (`NSDraggingSession`
//!   on macOS, OLE `IDropTarget` / `IDataObject` on Windows) with live ghost window overlays,
//!   metadata preview negotiation, and seamless payload handoff.
//!
//! ## 2. Architectural Linkages & Dependencies
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────────────────────────────────┐
//! │                                  KVM Subsystem Architecture                            │
//! └────────────────────────────────────────────────────────────────────────────────────────┘
//!
//!              ┌─────────────────────────────────────────────────────────┐
//!              │                 Integrator Core Engine                  │
//!              │             (src/core.rs / src/main.rs)                 │
//!              └────────────────────────────┬────────────────────────────┘
//!                                           │ Instantiates & Supervises
//!                                           ▼
//!              ┌─────────────────────────────────────────────────────────┐
//!              │              KvmService (src/kvm/service.rs)            │
//!              │    - Session Lifecycle & Wire Protocol Dispatch         │
//!              │    - State Machine (Idle, Controlling, Controlled)      │
//!              │    - Edge Dwell Timers & Dead Corner Filters            │
//!              └──────────────┬───────────────────────────┬──────────────┘
//!                             │                           │
//!            ┌────────────────┴──────────────┐            │
//!            ▼                               ▼            ▼
//! ┌─────────────────────┐       ┌──────────────────────┐ ┌──────────────────────┐
//! │ macos_backend.rs    │       │ windows_backend.rs   │ │ layout.rs            │
//! │ (CGEventTap, IOKit) │       │ (LL-Hooks, SendInput)│ │ (Geometry, Mirroring,│
//! └──────────┬──────────┘       └──────────┬───────────┘ │  Atomic Persistence) │
//!            │                             │             └──────────────────────┘
//!            ▼                             ▼
//! ┌─────────────────────┐       ┌──────────────────────┐
//! │ kvm_macos.swift     │       │ kvm_windows.cpp      │
//! │ (Obj-C / Swift Run- │       │ (Win32 Message Pump, │
//! │ Loop, Ghost HUD)    │       │  Ghost Win, OLE D&D) │
//! └─────────────────────┘       └──────────────────────┘
//!            │                             │
//!            └───────────────┬─────────────┘
//!                            │ Wire Serialization (protocol.rs)
//!                            ▼
//!        ┌───────────────────────────────────────────────┐
//!        │  TransportSessionV2 (ServiceId::InputKvm)     │
//!        │  TCP Port 58286 with ChaCha20-Poly1305 AEAD   │
//!        └───────────────────────────────────────────────┘
//! ```
//!
//! ### Upstream Callers:
//! - `src/core.rs`: Instantiates `KvmService` during system bootstrap, passes handles to
//!   `DiscoveryManager`, `ClipboardService`, and `FeatureManager`, and manages the service lifecycle.
//! - Native UI Bridges (`ui-macos/IntegratorApp.swift`, `ui-windows/MainWindow.xaml.cs`):
//!   Query runtime status via `KvmStatusSnapshot` and submit dynamic layout configuration updates.
//!
//! ### Downstream Callees:
//! - `protocol`: Defines the wire message types (`KvmWireMessage`), key codes (`LogicalKey`),
//!   modifier masks (`ModifierMask`), and serialized layout contracts (`KvmLayoutConfig`).
//! - `layout`: Implements desk geometry calculations, display rect transforms, dead-corner guards,
//!   and atomic disk persistence (`kvm_layout.json`).
//! - `macos_backend` / `kvm_macos.swift`: Interacts directly with macOS CoreGraphics, Quartz Event Services,
//!   AppKit, and IOKit HID.
//! - `windows_backend` / `kvm_windows.cpp`: Interacts with Win32 User32, GDI, and OLE/COM subsystems.
//! - `crate::security::transport::TransportSessionV2`: Encrypted bi-directional framing tunnel over TCP port 58286.
//!
//! ## 3. Threading & Concurrency Model
//! - **Tokio Async Runtime**: Manages connection establishment, mutual authentication handshakes,
//!   outbound command batching, and inbound wire message parsing.
//! - **OS Hook Threads**: Dedicated native threads running platform-specific event loops:
//!   - macOS: Dedicated `CFRunLoop` thread hosting the Mach port `CGEventTap`.
//!   - Windows: Dedicated Win32 message-pump thread hosting `WH_MOUSE_LL` and `WH_KEYBOARD_LL` hooks.
//! - **Synchronization Primitives**: Atomic flags (`controlling_peer_fast`, `TAP_ACTIVE`, `HOOK_ACTIVE`)
//!   provide sub-microsecond state checks inside performance-critical OS hook callbacks without acquiring
//!   heavy asynchronous mutexes.
//!
//! ## 4. Security & Safety Invariants
//! - **Cryptographic Authentication**: Strictly requires authenticated `TransportSessionV2` sessions
//!   validated against the pinned trust store. No unauthenticated or cleartext fallback is permitted.
//! - **Zero Foreign Injection**: Injected synthetic events are explicitly tagged (`0x494E5447` / "INTG")
//!   to prevent feedback looping through local capture hooks.
//! - **Safety Boundaries**: All FFI boundaries between Rust, Swift, and C++ enforce strict pointer validation,
//!   null-checks, and exception-safe unwinding barriers.

pub mod layout;

#[cfg(target_os = "macos")]
pub mod macos_backend;

pub mod protocol;
pub mod service;

#[cfg(target_os = "windows")]
pub mod windows_backend;

#[allow(unused_imports)]
pub use protocol::{KvmLayoutConfig, ScreenEdge};
pub use service::{KvmService, KvmStatusSnapshot};
