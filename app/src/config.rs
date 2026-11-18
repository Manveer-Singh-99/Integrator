//! # Network Protocol Configuration & Static Port Registry (`config.rs`)
//!
//! ## 1. Module Purpose & Scope
//! `config.rs` provides the centralized, canonical definition of well-known TCP and UDP port
//! numbers used across the entire Integrator peer-to-peer ecosystem.
//!
//! While network interface addresses, subnets, and routing topologies are probed dynamically
//! at runtime by `system_info.rs` and negotiated via `discovery.rs`, all Integrator services
//! bind to predictable, deterministic port numbers in the dynamic/private port range (58280–58287)
//! to avoid collisions with standard IANA registered services.
//!
//! ## 2. Architectural Linkages & Dependencies
//! ### Upstream Callers:
//! - `core.rs`: Initializes background listener daemons and connects client transport sessions using these ports.
//! - `discovery.rs`: Broadcasts discovery beacons containing control and service port metadata.
//! - `bridge.rs`: Performs TCP RTT probes against peer service endpoints using `CONTROL_PORT`.
//! - `kvm/`, `clipboard/`, `audio/`, `camera/`, `telemetry/`: Subsystem transports bind or dial using their respective constants.
//!
//! ### Downstream Callees:
//! - Standard library network sockets (`std::net::SocketAddr`, `std::net::TcpListener`, `tokio::net::UdpSocket`).
//!
//! ### Cross-Platform / Cross-Device Flow:
//! Both macOS and Windows 11 instances bind listener sockets to `0.0.0.0:<PORT>` or `[::]:<PORT>`
//! across all active physical and virtual interfaces (Ethernet, Wi-Fi, Thunderbolt bridge).
//! The peer connects directly to `<PEER_IP>:<PORT>` once discovery has resolved peer reachability.
//!
//! ## 3. Threading & Concurrency Model
//! Constants defined in this module are immutable, static `u16` primitives. They are safe for
//! lockless, concurrent read access from any asynchronous task, thread, or interrupt handler.
//!
//! ## 4. Security & Safety Invariants
//! - **Static Allocation Boundary**: All ports reside in the 58280–58287 block.
//! - **Traffic Segregation**: Independent functional services run on dedicated distinct ports.
//!   This prevents head-of-line blocking (e.g., bulk clipboard transfers stalling real-time KVM input)
//!   and allows OS-level QoS packet prioritization (e.g., DSCP tagging for audio and KVM datagrams).
//! - **Mutual Authentication Prerequisite**: With the exception of discovery beacons, no unauthenticated
//!   traffic is accepted on any TCP/UDP port; incoming streams must immediately execute the encrypted
//!   handshake (`security::transport::TransportSessionV2`).

/// UDP Multicast / Broadcast Discovery Port (58280).
///
/// Used exclusively for zero-configuration peer announcement and query beacons.
/// Nodes broadcast signed discovery payloads over IPv4 subnet broadcast (`255.255.255.255`
/// and interface directed broadcast) and link-local multicast.
pub const DISCOVERY_PORT: u16 = 58280;

/// Primary Control and Handshake Port (58281, TCP).
///
/// Handles session establishment, SPAKE2+ password-authenticated key exchange,
/// cryptographic capability negotiation, pairing confirmations, and top-level session control.
/// Also used by `bridge::LinkMonitor` to measure baseline TCP connection latency (RTT).
pub const CONTROL_PORT: u16 = 58281;

/// High-Capacity Clipboard Synchronization Port (58283, TCP).
///
/// Dedicated TCP stream used for transferring clipboard contents, including plain text,
/// UTF-8/RTF payloads, high-resolution image bitstreams (PNG/TIFF), and lazy-read file descriptors.
/// Isolating clipboard traffic on port 58283 ensures that multi-megabyte image transfers do not
/// compete with or delay low-latency input or display stream frames.
pub const CLIPBOARD_PORT: u16 = 58283;

/// Low-Latency Bidirectional Audio Streaming Port (58284, UDP/TCP).
///
/// Carries 48 kHz 16-bit stereo PCM audio packets encapsulated in encrypted datagrams
/// with sequence numbers, sample timestamps, and drift correction markers.
/// Primarily operates over UDP for sub-10ms delivery, falling back to TCP when firewall
/// configurations restrict UDP hole punching.
pub const AUDIO_PORT: u16 = 58284;

/// Real-Time Telemetry and Health Streaming Port (58285, TCP).
///
/// Transmits periodic diagnostic metrics, link quality estimations, packet loss percentages,
/// CPU/GPU thermal states, and frame timing histograms between peers and local UI diagnostics views.
pub const TELEMETRY_PORT: u16 = 58285;

/// High-Priority Low-Latency Input (KVM) Port (58286, TCP/UDP).
///
/// Handles remote keyboard keycodes, mouse pointer delta movements, absolute coordinate mappings,
/// mouse wheel delta events, and multi-touch trackpad gestures.
/// Designed for maximum throughput and minimal queueing delay to preserve 120Hz/144Hz input responsiveness.
pub const INPUT_PORT: u16 = 58286;

/// High-Bandwidth Virtual Camera Streaming Port (58287, TCP).
///
/// Transmits compressed virtual camera frames (H.264/HEVC/MJPEG bitstreams) from the capturing host
/// to the peer's virtual camera driver (CoreMediaIO DAL plugin on macOS, Media Foundation FrameServer on Windows).
pub const CAMERA_PORT: u16 = 58287;
