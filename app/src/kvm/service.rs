//! # Universal Input KVM & Cross-Screen Drag-and-Drop Engine
//!
//! ## 1. Module Purpose & Scope
//! The `KvmService` is the central orchestration engine for Integrator's Universal Control KVM
//! (Keyboard, Video/Mouse control multiplexer) and Cross-Screen Drag-and-Drop subsystem.
//!
//! It binds TCP port `INPUT_PORT = 58286`, running full-duplex encrypted communication over
//! `TransportSessionV2` (`ServiceId::InputKvm`). The service strictly requires mutual cryptographic
//! authentication against the local Ed25519 pinned trust store (`trust.rs`), enforcing zero IP bypass
//! and zero legacy fallback.
//!
//! ### Core Responsibilities:
//! 1. **State Machine Management**: Tracks workstation control roles across three mutually exclusive
//!    states: `Idle` (local mouse/keyboard control active), `ControllingPeer` (swallowing local input
//!    and streaming deltas to remote workstation), and `ControlledByPeer` (synthesizing remote inputs
//!    locally).
//! 2. **Edge Dwell & Boundary Hopping**: Filters raw mouse coordinates through edge dwell timers
//!    (`hop_delay_ms`) and corner guard thresholds (`DEAD_CORNER_PX`) to prevent accidental transitions
//!    during casual cursor gestures near display borders.
//! 3. **Input Transformation & Remapping**: Normalizes coordinates into unit intervals `[0.0, 1.0]`
//!    accounting for asymmetric desk offsets, and bidirectionally maps modifier keys (e.g. macOS `Command ⌘`
//!    ↔ Windows `Ctrl`) when modifier translation is enabled.
//! 4. **Cross-Screen Drag & Drop**: Detects active OS file drags when approaching edges, generates
//!    metadata previews (`DragOffer`), renders floating liquid glass HUD badges, streams payload chunks
//!    concurrently over `ClipboardService`, and initiates native drops (`NSDraggingSession` / OLE `DoDragDrop`).
//!
//! ## 2. Architectural Linkages & Dependencies
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────────────────────────────────┐
//! │                            KvmService Subsystem Architecture                           │
//! └────────────────────────────────────────────────────────────────────────────────────────┘
//!
//!              ┌─────────────────────────────────────────────────────────┐
//!              │                     Core Bootstrap                      │
//!              │                 (src/core.rs / main.rs)                 │
//!              └────────────────────────────┬────────────────────────────┘
//!                                           │ Instantiates & Starts
//!                                           ▼
//!              ┌─────────────────────────────────────────────────────────┐
//!              │                       KvmService                        │
//!              │  - State Machine: Idle | ControllingPeer | Controlled   │
//!              │  - Edge Dwell & Dead Corner Detection                   │
//!              │  - Key Remapping & Modifier Bitmask Harmonization       │
//!              │  - Drag Session Lifetime & Staged Temp Cleanup          │
//!              └───────┬─────────────────┬───────────────────┬───────────┘
//!                      │                 │                   │
//!           Outbound   │     Inbound     │                   │
//!           Commands   │     Packets     │                   │
//!                      ▼                 ▼                   │
//!       ┌───────────────────────────────┐                    │
//!       │      TransportSessionV2       │                    │
//!       │     (ServiceId::InputKvm)     │                    │
//!       │   ChaCha20-Poly1305 over TCP  │                    │
//!       └──────────────┬────────────────┘                    │
//!                      │ Port 58286                          │
//!                      ▼                                     │
//!             Remote Workstation                             │
//!                                                            │
//!       ┌────────────────────────────────────────────────────┴───────────┐
//!       │ Native OS Hooks & Hardware Injection Drivers                    │
//!       │  - macOS:   macos_backend.rs -> kvm_macos.swift (CGEventTap)   │
//!       │  - Windows: windows_backend.rs -> kvm_windows.cpp (LL-Hooks)   │
//!       └────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ### Upstream Callers:
//! - `src/core.rs`: Instantiates `KvmService::new`, calls `start()` during startup, monitors status via
//!   `get_status_snapshot()`, and invokes `shutdown()` on exit.
//! - Native OS Hook Callbacks (`on_local_mouse_move`, `on_local_mouse_button`, `on_local_mouse_scroll`,
//!   `on_local_key_event`): Ingest raw OS events synchronously from the platform backend.
//! - UI View Models: Read and write desk layout topology via `get_layout()` and `update_layout()`.
//!
//! ### Downstream Callees:
//! - `crate::security::transport::TransportSessionV2`: Encrypted wire framing.
//! - `crate::clipboard::ClipboardService`: Staging and streaming bulk file payloads during drag-and-drop.
//! - `crate::discovery::DiscoveryManager`: Resolves paired peer IP addresses and OS capabilities.
//! - `crate::features::FeatureManager`: Verifies `"input_kvm"` feature enablement.
//! - `super::layout`: Mathematical projection, coordinate normalization, and mirror symmetry.
//! - `super::macos_backend` / `super::windows_backend`: Hardware input capture and injection.
//!
//! ## 3. State Machine Transitions
//!
//! ```text
//!                  ┌─────────────────────────────────────────┐
//!                  │                  IDLE                   │
//!                  │  (Local inputs control local desktop)   │
//!                  └───────────┬─────────────────▲───────────┘
//!                              │                 │
//!          Cursor pushed past  │                 │ Cursor pushed past
//!          boundary edge with  │                 │ boundary edge back
//!          dwell timer expiry  │                 │ into local screen
//!                              ▼                 │
//!   ┌──────────────────────────────────┐         │
//!   │         CONTROLLING_PEER         │         │
//!   │  - Swallows local mouse/keys     │         │
//!   │  - Cursor parked at center       │─────────┘
//!   │  - Streams deltas over TCP       │
//!   └──────────────────────────────────┘
//!                              ▲
//!                              │
//!            Remote cursor pushed into local display bounds
//!                              │
//!                              ▼
//!   ┌──────────────────────────────────┐
//!   │        CONTROLLED_BY_PEER        │
//!   │  - Replays incoming wire events  │
//!   │  - Warps cursor to entry point   │
//!   │  - Local mouse move can break in │
//!   └──────────────────────────────────┘
//! ```
//!
//! ## 4. Threading & Concurrency Model
//! - **Tokio Async Engine**: Handles inbound TCP listener connections (`INPUT_PORT`), connection retries,
//!   background file staging tasks, and outbound serialization channels.
//! - **Native Hook Threads**: Dedicated platform threads execute OS hooks (`CFRunLoop` on macOS, Win32
//!   `GetMessage` pump on Windows).
//! - **Fast-Path Lock-Free Check**: `controlling_peer_fast` (`AtomicBool`) provides sub-microsecond
//!   atomic state queries inside OS hook procedures without acquiring synchronous locks.
//!
//! ## 5. Security & Safety Invariants
//! - **Cryptographic Mutual Authentication**: Handshakes require verified Ed25519 signatures and
//!   ephemeral X25519 session keys (`TransportSessionV2`).
//! - **Path Traversal Shielding**: Cross-screen drag staging sanitizes relative filenames, blocking
//!   absolute paths, `..` traversals, and symlink creation.
//! - **Automatic Input Release**: Any network disruption or session teardown immediately dispatches
//!   `force_release_all`, releasing all synthetic keys and mouse buttons to prevent stuck keys.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use serde::Serialize;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Semaphore};
use tokio::task::AbortHandle;
use tracing::{info, warn};

use crate::clipboard::ClipboardService;
use crate::config::{
    CLIPBOARD_CACHE_DIR_NAME, DEFAULT_DISPLAY_HEIGHT, DEFAULT_DISPLAY_WIDTH,
    DEFAULT_MACOS_DISPLAY_HEIGHT, DEFAULT_MACOS_DISPLAY_WIDTH, INPUT_PORT, MIN_KVM_DISPLAY_HEIGHT,
    MIN_KVM_DISPLAY_WIDTH,
};
use crate::discovery::DiscoveryManager;
use crate::features::FeatureManager;
use crate::security::transport::{ServiceId, TransportReaderV2, TransportWriterV2, TRANSPORT_WIRE_MAGIC};
use crate::trust;

use super::layout::{
    self, compute_normalized_edge_pos, is_in_dead_corner, mirror_layout_for_peer,
    resolve_entry_point, sanitize_layout, ScreenRect,
};
#[cfg(target_os = "macos")]
use super::macos_backend;
use super::protocol::{
    DragOffer, KvmLayoutConfig, KvmWireMessage, LogicalKey, ModifierMask, RemoteMouseButton,
    ScreenEdge,
};
#[cfg(target_os = "windows")]
use super::windows_backend;

/// Maximum allowable wire message size in bytes (96 KiB) to prevent memory amplification attacks.
const MAX_WIRE_MESSAGE_BYTES: usize = 96 * 1024;

/// Capacity of the asynchronous outbound command channel queue.
const OUTBOUND_QUEUE_CAP: usize = 1024;

/// Reserved queue slots prioritized for critical release and escape commands.
const RESERVED_CONTROL_SLOTS: usize = 128;

/// Maximum simultaneous in-flight TCP accept handshakes permitted.
const MAX_ACCEPT_HANDSHAKES: usize = 16;

/// Timeout for reading the initial 4-byte `ITR2` magic prefix on accepted KVM TCP sockets (5 seconds).
const WIRE_MAGIC_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Timeout for completing an incoming `TransportV2` KVM authentication handshake (10 seconds).
const KVM_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Backoff delay after a KVM TCP listener `accept()` failure before retrying (250 ms).
const TCP_ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(250);

/// Brief grace sleep allowing outbound `ReleaseAll` messages to flush before tearing down a session (25 ms).
const TEARDOWN_SLEEP: Duration = Duration::from_millis(25);

/// Polling interval while the `"input_kvm"` feature gate is disabled (400 ms).
const DISABLED_FEATURE_POLL_INTERVAL: Duration = Duration::from_millis(400);

/// Number of unconnected connector ticks before the non-preferred peer initiates fallback dial (3 ticks).
const UNCONNECTED_CONNECT_TICKS: u32 = 3;

/// Outbound TCP + `TransportV2` connection timeout when dialing the peer KVM port (3 seconds).
const KVM_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// Main connector and display-geometry refresh polling interval (1 second).
const KVM_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Inward cursor entry inset in pixels when remote control enters the local display (`24.0` px).
const REMOTE_ENTRY_INSET_PX: f32 = 24.0;

/// Inward cursor restoration inset in pixels when control returns across the peer edge (`16.0` px).
const RETURN_ENTRY_INSET_PX: f32 = 16.0;

/// Cooldown window after an edge crossing to prevent ping-pong boundary bounce (`180` ms).
const EDGE_TRANSITION_COOLDOWN: Duration = Duration::from_millis(180);

/// Edge proximity threshold in pixels for top/left display boundaries (`1.5` px).
const EDGE_PROXIMITY_INSET_PX: f32 = 1.5;

/// Edge proximity threshold in pixels for bottom/right display boundaries (`2.0` px).
const EDGE_PROXIMITY_OUTSET_PX: f32 = 2.0;

/// Minimum edge dwell delay in milliseconds enforced while dragging files across screens (`25` ms).
const MIN_DRAG_HOP_DELAY_MS: u32 = 25;

/// Maximum validity duration of an active edge dwell timer before resetting (`2` seconds).
const MAX_EDGE_DWELL_VALIDITY: Duration = Duration::from_secs(2);

/// Directive returned by OS hook ingestion routines instructing the OS driver how to handle the event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookDecision {
    /// Pass the event through untouched to the local operating system and foreground application.
    PassThrough,
    /// Swallow the event, preventing the local operating system and windows from processing it.
    Swallow,
    /// Swallow the event and immediately warp the hardware cursor to the center park coordinates.
    SwallowAndParkCenter,
}

/// Comprehensive point-in-time runtime status telemetry snapshot of the KVM subsystem.
#[derive(Debug, Clone, Serialize)]
pub struct KvmStatusSnapshot {
    /// Whether Universal Input KVM functionality is enabled in user settings.
    pub enabled: bool,
    /// Whether Cross-Screen Drag & Drop functionality is enabled.
    pub dragdrop_enabled: bool,
    /// Whether the low-level OS input hook (`CGEventTap` or `WH_MOUSE_LL`) is actively running.
    pub hook_active: bool,
    /// Current state machine role description (`"idle"`, `"controlling"`, `"controlled"`).
    pub role: String,
    /// IP address of the currently paired connected peer workstation, if connected.
    pub connected_peer_ip: Option<String>,
    /// Operating system of the connected peer (`"macos"` or `"windows"`).
    pub peer_os: Option<String>,
    /// Physical width of the remote peer's primary display in pixels.
    pub peer_width: u32,
    /// Physical height of the remote peer's primary display in pixels.
    pub peer_height: u32,
    /// User-visible label of an active file drag-and-drop session in transit.
    pub active_drag_label: Option<String>,
    /// Whether KVM Gaming Boundary Lock is active (freezes edge-hopping during full-screen games).
    #[serde(default)]
    pub boundary_locked: bool,
    /// Current desk layout arrangement and edge configuration.
    pub layout: KvmLayoutConfig,
}

/// State machine variants governing workstation input authority.
#[allow(dead_code)]
#[derive(Debug, Clone)]
enum KvmRole {
    /// Local machine inputs control the local desktop.
    Idle,
    /// Local machine is currently swallowing local inputs and streaming them to the peer.
    ControllingPeer {
        /// Target peer IP address receiving input commands.
        peer_ip: String,
        /// Active drag session identifier if a cross-screen drag is in flight.
        active_drag_session: Option<String>,
        /// Cursor X coordinate to restore when control returns to the local screen.
        restore_x: f32,
        /// Cursor Y coordinate to restore when control returns to the local screen.
        restore_y: f32,
    },
    /// Local machine is currently being remote-controlled by the peer workstation.
    ControlledByPeer {
        /// Controlling peer IP address.
        peer_ip: String,
        /// Edge where the remote cursor entered the local screen.
        entry_edge: ScreenEdge,
        /// Current simulated cursor X position.
        cur_x: f32,
        /// Current simulated cursor Y position.
        cur_y: f32,
        /// Active drag session identifier if receiving files.
        active_drag_session: Option<String>,
        /// User-visible preview title for the active drag operation.
        active_drag_label: Option<String>,
        /// Indicates if a native OS dragging session (`NSDraggingSession` or OLE) has been initiated.
        native_drag_started: bool,
    },
}

/// Outbound commands dispatched across the internal asynchronous actor channel.
#[derive(Debug)]
enum KvmOutboundCmd {
    /// Direct serialized wire message to transmit over the transport session.
    Wire(KvmWireMessage),
    /// Request to initiate a cross-screen drag session with a set of local file paths.
    EnterWithDragPaths {
        entry_edge: ScreenEdge,
        norm_pos: f32,
        left_button_held: bool,
        paths: Vec<PathBuf>,
    },
}

/// Central coordinator service managing KVM state, networking, hooks, and drag sessions.
pub struct KvmService {
    discovery: DiscoveryManager,
    clipboard: ClipboardService,
    features: Arc<FeatureManager>,

    layout: RwLock<KvmLayoutConfig>,
    role: Mutex<KvmRole>,
    controlling_peer_fast: AtomicBool,
    local_rect: RwLock<ScreenRect>,
    peer_rect: RwLock<ScreenRect>,
    connected_peer_device_id: RwLock<Option<String>>,
    connected_peer_ip: RwLock<Option<String>>,
    peer_os: RwLock<Option<String>>,
    peer_diff_os: AtomicBool,
    remote_left_down: AtomicBool,
    pending_drag_drop_label: RwLock<Option<String>>,
    edge_dwell: Mutex<Option<(ScreenEdge, Instant)>>,
    last_edge_transition: Mutex<Instant>,
    held_remote_keys: Mutex<HashSet<LogicalKey>>,
    held_remote_buttons: Mutex<HashSet<RemoteMouseButton>>,
    sent_remote_keys: Mutex<HashMap<LogicalKey, (LogicalKey, ModifierMask)>>,
    outbound_tx: RwLock<Option<mpsc::Sender<KvmOutboundCmd>>>,
    next_session_id: AtomicU64,
    active_session_id: AtomicU64,
    connect_in_flight: AtomicBool,
    shutting_down: AtomicBool,
    active_tasks: Mutex<Vec<AbortHandle>>,
    session_abort: Mutex<Option<(AbortHandle, AbortHandle)>>,
    staging_task: Mutex<Option<AbortHandle>>,
    drag_stage_dirs: Mutex<HashMap<String, PathBuf>>,
    last_controlled_entry_ms: AtomicU64,
    boundary_locked: AtomicBool,
}

impl KvmService {
    pub fn new(
        discovery: DiscoveryManager,
        clipboard: ClipboardService,
        features: Arc<FeatureManager>,
    ) -> Arc<Self> {
        let initial_layout = layout::load_layout_config();
        let svc = Arc::new(Self {
            discovery,
            clipboard,
            features,
            layout: RwLock::new(initial_layout),
            role: Mutex::new(KvmRole::Idle),
            controlling_peer_fast: AtomicBool::new(false),
            local_rect: RwLock::new(ScreenRect {
                x: 0.0,
                y: 0.0,
                width: DEFAULT_MACOS_DISPLAY_WIDTH as f32,
                height: DEFAULT_MACOS_DISPLAY_HEIGHT as f32,
            }),
            peer_rect: RwLock::new(ScreenRect {
                x: 0.0,
                y: 0.0,
                width: DEFAULT_DISPLAY_WIDTH as f32,
                height: DEFAULT_DISPLAY_HEIGHT as f32,
            }),
            connected_peer_device_id: RwLock::new(None),
            connected_peer_ip: RwLock::new(None),
            peer_os: RwLock::new(None),
            peer_diff_os: AtomicBool::new(true),
            remote_left_down: AtomicBool::new(false),
            pending_drag_drop_label: RwLock::new(None),
            edge_dwell: Mutex::new(None),
            last_edge_transition: Mutex::new(Instant::now() - Duration::from_secs(5)),
            held_remote_keys: Mutex::new(HashSet::new()),
            held_remote_buttons: Mutex::new(HashSet::new()),
            sent_remote_keys: Mutex::new(HashMap::new()),
            outbound_tx: RwLock::new(None),
            next_session_id: AtomicU64::new(0),
            active_session_id: AtomicU64::new(0),
            connect_in_flight: AtomicBool::new(false),
            shutting_down: AtomicBool::new(false),
            active_tasks: Mutex::new(Vec::new()),
            session_abort: Mutex::new(None),
            staging_task: Mutex::new(None),
            drag_stage_dirs: Mutex::new(HashMap::new()),
            last_controlled_entry_ms: AtomicU64::new(0),
            boundary_locked: AtomicBool::new(false),
        });
        svc.refresh_local_rect();
        svc
    }

    pub fn is_controlling_peer_fast(&self) -> bool {
        self.controlling_peer_fast.load(Ordering::Acquire)
    }

    fn set_role_locked(&self, role_guard: &mut KvmRole, next_role: KvmRole) -> KvmRole {
        let is_controlling = matches!(next_role, KvmRole::ControllingPeer { .. });
        let is_controlled = matches!(next_role, KvmRole::ControlledByPeer { .. });
        let was_controlled = matches!(*role_guard, KvmRole::ControlledByPeer { .. });
        let prev = std::mem::replace(role_guard, next_role);
        self.controlling_peer_fast
            .store(is_controlling, Ordering::Release);

        if is_controlled && !was_controlled {
            crate::core::emit_ui_event("kvm_remote_control", "{\"active\":true}");
            crate::core::emit_ui_toast(
                "info",
                "Remote workstation controlling local mouse & keyboard (Press any key or move mouse to take over)",
            );
        } else if !is_controlled && was_controlled {
            crate::core::emit_ui_event("kvm_remote_control", "{\"active\":false}");
        }

        prev
    }

    fn abort_active_session_tasks(&self) {
        if let Some((r_abort, w_abort)) = self
            .session_abort
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            r_abort.abort();
            w_abort.abort();
        }
    }

    fn teardown_active_session(&self) {
        self.active_session_id.store(0, Ordering::Release);
        self.abort_active_session_tasks();
        *self
            .connected_peer_ip
            .write()
            .unwrap_or_else(|e| e.into_inner()) = None;
        *self
            .outbound_tx
            .write()
            .unwrap_or_else(|e| e.into_inner()) = None;
        self.force_release_all(false);
        self.sync_platform_probe();
    }

    pub fn shutdown(&self) {
        self.shutting_down.store(true, Ordering::Release);
        self.force_release_all(true);
        self.teardown_active_session();
        if let Some(handle) = self
            .staging_task
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            handle.abort();
        }
        let handles: Vec<AbortHandle> = self
            .active_tasks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain(..)
            .collect();
        for handle in handles {
            handle.abort();
        }
        self.cleanup_all_drag_stage_dirs();
        #[cfg(target_os = "macos")]
        macos_backend::stop();
        #[cfg(target_os = "windows")]
        windows_backend::stop();
    }

    pub async fn start(self: &Arc<Self>) -> Result<()> {
        // Sync initial edge probe config on Windows
        self.sync_platform_probe();

        // Start OS hooks on platform
        #[cfg(target_os = "macos")]
        macos_backend::start(Arc::clone(self));
        #[cfg(target_os = "windows")]
        windows_backend::start(Arc::clone(self));

        // 1. Incoming encrypted TCP listener on INPUT_PORT (58286)
        let listener = TcpListener::bind(format!("0.0.0.0:{}", INPUT_PORT)).await?;
        info!(
            "🖱️ Universal Input KVM & Drag-Drop TransportV2 Server listening on port {}",
            INPUT_PORT
        );

        let accept_sem = Arc::new(Semaphore::new(MAX_ACCEPT_HANDSHAKES));
        let svc_accept = Arc::clone(self);
        let accept_task = tokio::spawn(async move {
            loop {
                if svc_accept.shutting_down.load(Ordering::Acquire) {
                    break;
                }
                match listener.accept().await {
                    Ok((socket, addr)) => {
                        if svc_accept.shutting_down.load(Ordering::Acquire) {
                            break;
                        }
                        if !svc_accept.features.is_enabled("input_kvm") {
                            continue;
                        }
                        let Ok(permit) = accept_sem.clone().try_acquire_owned() else {
                            warn!(
                                "🚫 Dropping excess incoming KVM handshake from {} (limit={})",
                                addr.ip(),
                                MAX_ACCEPT_HANDSHAKES
                            );
                            continue;
                        };
                        let peer_ip = addr.ip();
                        let s = Arc::clone(&svc_accept);
                        tokio::spawn(async move {
                            let _ = socket.set_nodelay(true);
                            let mut magic = [0u8; 4];
                            use tokio::io::AsyncReadExt;
                            let mut sock = socket;
                            let read_res = tokio::time::timeout(
                                WIRE_MAGIC_READ_TIMEOUT,
                                sock.read_exact(&mut magic),
                            )
                            .await;
                            match read_res {
                                Ok(Ok(_)) => {}
                                _ => {
                                    drop(permit);
                                    return;
                                }
                            }
                            if magic != TRANSPORT_WIRE_MAGIC {
                                warn!("🚫 Rejected non-ITR2 magic on KVM port from {}", peer_ip);
                                drop(permit);
                                return;
                            }
                            let auth_res = tokio::time::timeout(
                                KVM_HANDSHAKE_TIMEOUT,
                                trust::accept_transport_from_stream(
                                    sock,
                                    peer_ip,
                                    Some(magic),
                                    ServiceId::InputKvm,
                                ),
                            )
                            .await;
                            drop(permit);
                            match auth_res {
                                Ok(Ok(sess)) => {
                                    s.attach_transport_session(peer_ip.to_string(), sess).await;
                                }
                                Ok(Err(e)) => {
                                    warn!("🚫 Rejected KVM connection from {}: {}", peer_ip, e);
                                }
                                Err(_) => {
                                    warn!("🚫 Timed out KVM TransportV2 handshake from {}", peer_ip);
                                }
                            }
                        });
                    }
                    Err(e) => {
                        if svc_accept.shutting_down.load(Ordering::Acquire) {
                            break;
                        }
                        warn!("KVM TCP accept error: {}", e);
                        tokio::time::sleep(TCP_ACCEPT_RETRY_DELAY).await;
                    }
                }
            }
        });
        self.active_tasks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(accept_task.abort_handle());

        // 2. Persistent peer connector & feature-gate watcher
        let svc_loop = Arc::clone(self);
        let loop_task = tokio::spawn(async move {
            let local_id = crate::system_info::get_or_create_device_id();
            let mut unconnected_ticks: u32 = 0;

            loop {
                if svc_loop.shutting_down.load(Ordering::Acquire) {
                    break;
                }
                svc_loop.refresh_local_rect();
                svc_loop.sync_platform_probe();

                let kvm_on = svc_loop.features.is_enabled("input_kvm");
                if !kvm_on {
                    let has_active_session = svc_loop.active_session_id.load(Ordering::Acquire) != 0
                        || svc_loop
                            .connected_peer_ip
                            .read()
                            .unwrap_or_else(|e| e.into_inner())
                            .is_some();
                    if !matches!(
                        *svc_loop.role.lock().unwrap_or_else(|e| e.into_inner()),
                        KvmRole::Idle
                    ) {
                        svc_loop.force_release_all(true);
                        if has_active_session {
                            tokio::time::sleep(TEARDOWN_SLEEP).await;
                        }
                    }
                    if has_active_session {
                        svc_loop.teardown_active_session();
                    }
                    unconnected_ticks = 0;
                    tokio::time::sleep(DISABLED_FEATURE_POLL_INTERVAL).await;
                    continue;
                }

                let current_conn_ip = svc_loop
                    .connected_peer_ip
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone();

                // Topology failover & upgrade when idle: if the active route IP expired (e.g. USB-C cable
                // unplugged or DHCP lease changed on a hotspot) OR a higher-priority physical cable
                // (Thunderbolt / USB-C Direct) became available while connected over Wi-Fi / Hotspot,
                // cleanly tear down the idle session so the next tick connects over the best route.
                let mut already_connected = current_conn_ip.is_some();
                if let Some(ref cur_ip) = current_conn_ip {
                    let is_idle = matches!(
                        *svc_loop.role.lock().unwrap_or_else(|e| e.into_inner()),
                        KvmRole::Idle
                    );
                    if is_idle {
                        if let Some(best) = svc_loop.discovery.get_best_peer().await {
                            let best_ip = best.addr.ip().to_string();
                            if best.trusted && best_ip != *cur_ip {
                                let all_peers = svc_loop.discovery.get_all_peers().await;
                                let cur_peer = all_peers
                                    .iter()
                                    .find(|p| p.addr.ip().to_string() == *cur_ip);
                                let should_switch = match cur_peer {
                                    None => true,
                                    Some(cp) => {
                                        best.transport.route_priority()
                                            < cp.transport.route_priority()
                                    }
                                };
                                if should_switch {
                                    info!(
                                        "🔄 KVM switching topology route from {} to {} ({})",
                                        cur_ip,
                                        best_ip,
                                        best.transport.label()
                                    );
                                    svc_loop.teardown_active_session();
                                    already_connected = false;
                                }
                            }
                        }
                    }
                }

                if !already_connected {
                    if let Some(peer) = svc_loop.discovery.get_best_peer().await {
                        if peer.trusted {
                            let peer_ip = peer.addr.ip().to_string();
                            {
                                let mut w = svc_loop.peer_rect.write().unwrap_or_else(|e| e.into_inner());
                                if peer.display_width >= MIN_KVM_DISPLAY_WIDTH as u32
                                    && peer.display_height >= MIN_KVM_DISPLAY_HEIGHT as u32
                                {
                                    *w = ScreenRect {
                                        x: 0.0,
                                        y: 0.0,
                                        width: peer.display_width as f32,
                                        height: peer.display_height as f32,
                                    };
                                }
                            }
                            let diff_os = !peer.os.eq_ignore_ascii_case(std::env::consts::OS);
                            svc_loop.peer_diff_os.store(diff_os, Ordering::Relaxed);
                            *svc_loop.peer_os.write().unwrap_or_else(|e| e.into_inner()) =
                                Some(peer.os.clone());

                            let i_am_preferred_client = local_id < peer.device_id;
                            unconnected_ticks += 1;
                            if (i_am_preferred_client || unconnected_ticks >= UNCONNECTED_CONNECT_TICKS)
                                && svc_loop
                                    .connect_in_flight
                                    .compare_exchange(
                                        false,
                                        true,
                                        Ordering::AcqRel,
                                        Ordering::Acquire,
                                    )
                                    .is_ok()
                            {
                                unconnected_ticks = 0;
                                let s = Arc::clone(&svc_loop);
                                tokio::spawn(async move {
                                    struct ResetGuard<'a>(&'a AtomicBool);
                                    impl Drop for ResetGuard<'_> {
                                        fn drop(&mut self) {
                                            self.0.store(false, Ordering::Release);
                                        }
                                    }
                                    let _guard = ResetGuard(&s.connect_in_flight);
                                    if let Ok(sess) = trust::connect_transport_to_ip(
                                        &peer_ip,
                                        INPUT_PORT,
                                        ServiceId::InputKvm,
                                        KVM_CONNECT_TIMEOUT,
                                    )
                                    .await
                                    {
                                        if s.features.is_enabled("input_kvm")
                                            && !s.shutting_down.load(Ordering::Acquire)
                                        {
                                            let s_attach = Arc::clone(&s);
                                            tokio::spawn(async move {
                                                s_attach
                                                    .attach_transport_session(peer_ip, sess)
                                                    .await;
                                            });
                                        }
                                    }
                                });
                            }
                        }
                    } else {
                        unconnected_ticks = 0;
                    }
                } else {
                    unconnected_ticks = 0;
                }

                tokio::time::sleep(KVM_POLL_INTERVAL).await;
            }
        });
        self.active_tasks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(loop_task.abort_handle());

        Ok(())
    }

    pub fn refresh_local_rect(&self) {
        #[cfg(target_os = "macos")]
        let rect = macos_backend::get_primary_screen_rect();
        #[cfg(target_os = "windows")]
        let rect = windows_backend::get_primary_screen_rect();
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        let rect = ScreenRect {
            x: 0.0,
            y: 0.0,
            width: DEFAULT_DISPLAY_WIDTH as f32,
            height: DEFAULT_DISPLAY_HEIGHT as f32,
        };
        *self.local_rect.write().unwrap_or_else(|e| e.into_inner()) = rect;
    }

    fn sync_platform_probe(&self) {
        #[cfg(target_os = "windows")]
        {
            let drag_ok = self.features.is_enabled("input_kvm")
                && self.features.is_enabled("dragdrop")
                && self
                    .connected_peer_ip
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .is_some();
            let edge = self
                .layout
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .peer_edge;
            windows_backend::sync_edge_probe(drag_ok, edge);
        }
    }

    pub fn get_layout(&self) -> KvmLayoutConfig {
        self.layout.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn update_layout(&self, mut cfg: KvmLayoutConfig) -> Result<KvmLayoutConfig> {
        sanitize_layout(&mut cfg);
        cfg.updated_at_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        layout::save_layout_config(&cfg)?;
        *self.layout.write().unwrap_or_else(|e| e.into_inner()) = cfg.clone();
        self.sync_platform_probe();

        let mirrored = mirror_layout_for_peer(&cfg);
        self.try_send_wire(KvmWireMessage::SyncLayout(mirrored));
        Ok(cfg)
    }

    pub fn get_status_snapshot(&self) -> KvmStatusSnapshot {
        let role_str = match *self.role.lock().unwrap_or_else(|e| e.into_inner()) {
            KvmRole::Idle => "idle".to_string(),
            KvmRole::ControllingPeer { .. } => "controlling".to_string(),
            KvmRole::ControlledByPeer { .. } => "controlled".to_string(),
        };
        let peer_rect = *self.peer_rect.read().unwrap_or_else(|e| e.into_inner());
        KvmStatusSnapshot {
            enabled: self.features.is_enabled("input_kvm"),
            dragdrop_enabled: self.features.is_enabled("dragdrop"),
            hook_active: Self::platform_is_hook_active(),
            role: role_str,
            connected_peer_ip: self
                .connected_peer_ip
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .clone(),
            peer_os: self.peer_os.read().unwrap_or_else(|e| e.into_inner()).clone(),
            peer_width: peer_rect.width as u32,
            peer_height: peer_rect.height as u32,
            active_drag_label: self
                .pending_drag_drop_label
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .clone(),
            boundary_locked: self.boundary_locked.load(Ordering::Acquire),
            layout: self.get_layout(),
        }
    }

    /// Returns whether the KVM Gaming Boundary Lock is currently engaged.
    pub fn is_boundary_locked(&self) -> bool {
        self.boundary_locked.load(Ordering::Acquire)
    }

    /// Engages or disengages KVM Gaming Boundary Lock (freezes cursor edge-hopping).
    ///
    /// When `sync_peer` is `true`, propagates `KvmWireMessage::SetBoundaryLock` over the
    /// live KVM transport session so both Mac and PC honor the boundary lock synchronously.
    pub fn set_boundary_locked(&self, locked: bool, sync_peer: bool) -> bool {
        self.boundary_locked.store(locked, Ordering::SeqCst);
        if locked {
            *self.edge_dwell.lock().unwrap_or_else(|e| e.into_inner()) = None;
        }
        if sync_peer {
            self.try_send_wire(KvmWireMessage::SetBoundaryLock { locked });
        }
        crate::core::notify_touchbar_kvm_lock_state(locked);
        info!(
            "🖱️ KVM Gaming Boundary Lock {}",
            if locked { "LOCKED (edge-hopping frozen)" } else { "UNLOCKED (edge-hopping active)" }
        );
        locked
    }

    /// Toggles KVM Gaming Boundary Lock and synchronizes state with the peer.
    pub fn toggle_boundary_locked(&self) -> bool {
        let next = !self.is_boundary_locked();
        self.set_boundary_locked(next, true)
    }

    /// Immediately tears down any active KVM session associated with the specified peer device ID hex.
    pub fn teardown_peer_if_connected(&self, device_id_hex: &str) {
        let clean_id = device_id_hex.trim().to_ascii_lowercase();
        let connected_id = self
            .connected_peer_device_id
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(id) = connected_id {
            if id == clean_id {
                info!("🛑 KVM tearing down active session for revoked peer {}", clean_id);
                self.force_release_all(false);
                self.abort_active_session_tasks();
                *self
                    .connected_peer_device_id
                    .write()
                    .unwrap_or_else(|e| e.into_inner()) = None;
                *self
                    .connected_peer_ip
                    .write()
                    .unwrap_or_else(|e| e.into_inner()) = None;
                *self
                    .outbound_tx
                    .write()
                    .unwrap_or_else(|e| e.into_inner()) = None;
                self.active_session_id.store(0, Ordering::Release);
                self.sync_platform_probe();
            }
        }
    }

    pub fn force_release_all(&self, notify_peer: bool) {
        if notify_peer {
            self.try_send_wire(KvmWireMessage::ReleaseAll);
        }
        if let Some(handle) = self
            .staging_task
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            handle.abort();
        }
        let prev = {
            let mut r = self.role.lock().unwrap_or_else(|e| e.into_inner());
            self.set_role_locked(&mut r, KvmRole::Idle)
        };
        self.sent_remote_keys
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        *self
            .pending_drag_drop_label
            .write()
            .unwrap_or_else(|e| e.into_inner()) = None;
        self.remote_left_down.store(false, Ordering::Release);
        self.cleanup_all_drag_stage_dirs();

        let local_rect = *self.local_rect.read().unwrap_or_else(|e| e.into_inner());
        let park_x = local_rect.x + local_rect.width * 0.5;
        let park_y = local_rect.y + local_rect.height * 0.5;

        match prev {
            KvmRole::ControllingPeer {
                restore_x,
                restore_y,
                active_drag_session,
                ..
            } => {
                if let Some(sid) = active_drag_session {
                    if let Ok(handle) = tokio::runtime::Handle::try_current() {
                        let clipboard = self.clipboard.clone();
                        handle.spawn(async move {
                            clipboard.remove_drag_session(&sid).await;
                        });
                    }
                }
                Self::platform_set_controlling(false, park_x, park_y, restore_x, restore_y);
            }
            KvmRole::ControlledByPeer {
                cur_x,
                cur_y,
                active_drag_session,
                ..
            } => {
                if active_drag_session.is_some() {
                    #[cfg(target_os = "windows")]
                    windows_backend::cancel_remote_drag();
                }
                self.release_all_injected_inputs(cur_x, cur_y);
                Self::platform_hide_ghost();
                Self::platform_set_controlled(false, cur_x, cur_y);
            }
            KvmRole::Idle => {}
        }
    }

    // =========================================================================
    // TransportV2 Full-Duplex Reader / Writer Loop
    // =========================================================================

    async fn attach_transport_session(
        self: &Arc<Self>,
        peer_ip: String,
        session: crate::security::transport::TransportSessionV2<tokio::net::TcpStream>,
    ) {
        if !self.features.is_enabled("input_kvm") || self.shutting_down.load(Ordering::Acquire) {
            return;
        }

        let my_session_id = self.next_session_id.fetch_add(1, Ordering::AcqRel) + 1;
        self.abort_active_session_tasks();
        self.force_release_all(false);
        self.active_session_id.store(my_session_id, Ordering::Release);

        let peer_dev_id = session.peer_device_id_hex().to_string();
        let (mut reader, writer) = session.into_split_tcp();
        let (tx, mut rx) = mpsc::channel::<KvmOutboundCmd>(OUTBOUND_QUEUE_CAP);

        *self
            .connected_peer_device_id
            .write()
            .unwrap_or_else(|e| e.into_inner()) = Some(peer_dev_id);
        *self
            .connected_peer_ip
            .write()
            .unwrap_or_else(|e| e.into_inner()) = Some(peer_ip.clone());
        *self
            .outbound_tx
            .write()
            .unwrap_or_else(|e| e.into_inner()) = Some(tx.clone());

        let peers = self.discovery.get_all_peers().await;
        if let Some(peer) = peers
            .into_iter()
            .find(|p| p.addr.ip().to_string() == peer_ip)
        {
            let diff_os = !peer.os.eq_ignore_ascii_case(std::env::consts::OS);
            self.peer_diff_os.store(diff_os, Ordering::Relaxed);
            *self.peer_os.write().unwrap_or_else(|e| e.into_inner()) = Some(peer.os);
            if peer.display_width >= MIN_KVM_DISPLAY_WIDTH as u32
                && peer.display_height >= MIN_KVM_DISPLAY_HEIGHT as u32
            {
                *self.peer_rect.write().unwrap_or_else(|e| e.into_inner()) = ScreenRect {
                    x: 0.0,
                    y: 0.0,
                    width: peer.display_width as f32,
                    height: peer.display_height as f32,
                };
            }
        }

        self.sync_platform_probe();
        info!("⌨️🖱️ Encrypted Universal Control KVM session linked with {}", peer_ip);

        // Send initial geometry & layout
        let rect = *self.local_rect.read().unwrap_or_else(|e| e.into_inner());
        let layout_cfg = self.get_layout();
        let _ = tx.try_send(KvmOutboundCmd::Wire(KvmWireMessage::ScreenGeometry {
            width: rect.width as u32,
            height: rect.height as u32,
        }));
        if layout_cfg.updated_at_ms > 0 {
            let _ = tx.try_send(KvmOutboundCmd::Wire(KvmWireMessage::SyncLayout(
                mirror_layout_for_peer(&layout_cfg),
            )));
        }

        let svc_w = Arc::clone(self);
        let peer_ip_w = peer_ip.clone();
        let writer_task = tokio::spawn(async move {
            Self::run_writer_loop(&svc_w, writer, &mut rx, &peer_ip_w).await;
        });
        let writer_abort = writer_task.abort_handle();

        let svc_r = Arc::clone(self);
        let peer_ip_r = peer_ip.clone();
        let reader_task = tokio::spawn(async move {
            Self::run_reader_loop(&svc_r, &mut reader, &peer_ip_r).await;
        });
        let reader_abort = reader_task.abort_handle();

        if self.active_session_id.load(Ordering::Acquire) == my_session_id
            && !self.shutting_down.load(Ordering::Acquire)
        {
            let mut slot = self
                .session_abort
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if let Some((old_r, old_w)) = slot.replace((reader_abort.clone(), writer_abort.clone())) {
                old_r.abort();
                old_w.abort();
            }
        } else {
            reader_abort.abort();
            writer_abort.abort();
        }

        let _ = reader_task.await;

        drop(tx);
        writer_abort.abort();

        // Clean disconnect teardown only if we are still the active session
        if self
            .active_session_id
            .compare_exchange(my_session_id, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.abort_active_session_tasks();
            *self
                .connected_peer_device_id
                .write()
                .unwrap_or_else(|e| e.into_inner()) = None;
            *self
                .connected_peer_ip
                .write()
                .unwrap_or_else(|e| e.into_inner()) = None;
            *self
                .outbound_tx
                .write()
                .unwrap_or_else(|e| e.into_inner()) = None;
            self.force_release_all(false);
            self.sync_platform_probe();
        }
        info!("🔌 Universal Control KVM session disconnected from {}", peer_ip);
    }

    async fn run_writer_loop(
        svc: &Arc<Self>,
        mut writer: TransportWriterV2<tokio::net::tcp::OwnedWriteHalf>,
        rx: &mut mpsc::Receiver<KvmOutboundCmd>,
        peer_ip: &str,
    ) {
        let mut ping_interval = tokio::time::interval(Duration::from_secs(1));
        ping_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            let cmd = tokio::select! {
                _ = ping_interval.tick() => {
                    let is_active = {
                        let role = svc.role.lock().unwrap_or_else(|e| e.into_inner());
                        !matches!(*role, KvmRole::Idle)
                    };
                    if is_active {
                        if let Ok(bytes) = serde_json::to_vec(&KvmWireMessage::Ping) {
                            if let Err(e) = writer.send_message(&bytes).await {
                                warn!("KVM TransportV2 ping write error to {}: {}", peer_ip, e);
                                break;
                            }
                        }
                    }
                    continue;
                }
                cmd_opt = rx.recv() => {
                    match cmd_opt {
                        Some(c) => c,
                        None => break,
                    }
                }
            };

            let msg = match cmd {
                KvmOutboundCmd::Wire(m) => m,
                KvmOutboundCmd::EnterWithDragPaths {
                    entry_edge,
                    norm_pos,
                    left_button_held,
                    paths,
                } => {
                    let paths_clone = paths.clone();
                    let first_path = paths.first().cloned();
                    let collected = tokio::task::spawn_blocking(move || {
                        let copy = ClipboardService::collect_local_entries(&paths_clone)?;
                        let icon_b64 = Self::extract_icon_b64(first_path.as_deref());
                        Ok::<_, anyhow::Error>((copy, icon_b64))
                    })
                    .await;
                    let drag_offer = match collected {
                        Ok(Ok((copy, icon_b64))) => {
                            let offer = DragOffer {
                                session_id: copy.session_id.clone(),
                                root_name: copy.root_name.clone(),
                                top_entries: copy.top_entries.clone(),
                                total_files: copy.total_files,
                                total_bytes: copy.total_bytes,
                                is_directory: !copy.directories.is_empty(),
                                icon_png_b64: icon_b64,
                            };
                            let still_controlling = {
                                let mut role_lock =
                                    svc.role.lock().unwrap_or_else(|e| e.into_inner());
                                if let KvmRole::ControllingPeer {
                                    ref mut active_drag_session,
                                    ..
                                } = *role_lock
                                {
                                    *active_drag_session = Some(copy.session_id.clone());
                                    true
                                } else {
                                    false
                                }
                            };
                            if still_controlling {
                                *svc.pending_drag_drop_label
                                    .write()
                                    .unwrap_or_else(|e| e.into_inner()) =
                                    Some(offer.root_name.clone());
                                svc.clipboard.register_drag_session(copy).await;
                                Some(offer)
                            } else {
                                None
                            }
                        }
                        Ok(Err(e)) => {
                            warn!("Could not prepare drag session paths: {}", e);
                            None
                        }
                        Err(e) => {
                            warn!("Drag item collection task error: {}", e);
                            None
                        }
                    };
                    KvmWireMessage::EnterScreen {
                        entry_edge,
                        norm_pos,
                        left_button_held,
                        drag_offer,
                    }
                }
            };

            match serde_json::to_vec(&msg) {
                Ok(bytes) => {
                    if bytes.len() > MAX_WIRE_MESSAGE_BYTES {
                        warn!("Skipping oversized KVM wire frame ({} B)", bytes.len());
                        continue;
                    }
                    if let Err(e) = writer.send_message(&bytes).await {
                        warn!("KVM TransportV2 write error to {}: {}", peer_ip, e);
                        break;
                    }
                }
                Err(e) => {
                    warn!("KVM serialization error: {}", e);
                }
            }
        }
    }

    async fn run_reader_loop(
        svc: &Arc<Self>,
        reader: &mut TransportReaderV2<tokio::net::tcp::OwnedReadHalf>,
        peer_ip: &str,
    ) {
        loop {
            let recv_res = tokio::time::timeout(Duration::from_secs(5), reader.recv_message()).await;
            let bytes = match recv_res {
                Ok(Ok(b)) => b,
                Ok(Err(_)) => break,
                Err(_) => {
                    let is_active = {
                        let role = svc.role.lock().unwrap_or_else(|e| e.into_inner());
                        !matches!(*role, KvmRole::Idle)
                    };
                    if is_active {
                        warn!("⏱️ KVM peer {} silent for 5s while in active role; releasing control", peer_ip);
                        svc.force_release_all(false);
                    }
                    continue;
                }
            };
            if bytes.is_empty() || bytes.len() > MAX_WIRE_MESSAGE_BYTES {
                warn!("Rejected malformed KVM frame size {} from {}", bytes.len(), peer_ip);
                break;
            }
            let Ok(msg) = serde_json::from_slice::<KvmWireMessage>(&bytes) else {
                continue;
            };
            svc.handle_inbound_message(peer_ip, msg).await;
        }
    }

    async fn handle_inbound_message(self: &Arc<Self>, peer_ip: &str, msg: KvmWireMessage) {
        if !self.features.is_enabled("input_kvm") {
            return;
        }

        match msg {
            KvmWireMessage::ScreenGeometry { width, height } => {
                if width >= MIN_KVM_DISPLAY_WIDTH as u32
                    && height >= MIN_KVM_DISPLAY_HEIGHT as u32
                {
                    *self.peer_rect.write().unwrap_or_else(|e| e.into_inner()) = ScreenRect {
                        x: 0.0,
                        y: 0.0,
                        width: width as f32,
                        height: height as f32,
                    };
                }
            }
            KvmWireMessage::SyncLayout(mut incoming) => {
                if !incoming.alignment_offset.is_finite() {
                    return;
                }
                sanitize_layout(&mut incoming);
                let cur_drop_folder = {
                    let cur = self.layout.read().unwrap_or_else(|e| e.into_inner());
                    cur.drop_folder.clone()
                };
                incoming.drop_folder = cur_drop_folder;
                let should_apply = {
                    let cur = self.layout.read().unwrap_or_else(|e| e.into_inner());
                    incoming.updated_at_ms >= cur.updated_at_ms
                };
                if should_apply {
                    let _ = layout::save_layout_config(&incoming);
                    *self.layout.write().unwrap_or_else(|e| e.into_inner()) = incoming;
                    self.sync_platform_probe();
                }
            }
            KvmWireMessage::EnterScreen {
                entry_edge,
                norm_pos,
                left_button_held,
                drag_offer,
            } => {
                if !norm_pos.is_finite() {
                    return;
                }
                if !self.layout.read().unwrap_or_else(|e| e.into_inner()).allow_remote_control {
                    tracing::warn!(
                        "🚫 Rejected KVM EnterScreen from {}: remote control is disabled by local policy",
                        peer_ip
                    );
                    self.try_send_wire(KvmWireMessage::ReleaseAll);
                    return;
                }
                if let Some(handle) = self
                    .staging_task
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .take()
                {
                    handle.abort();
                }
                self.cleanup_all_drag_stage_dirs();

                let local_rect = *self.local_rect.read().unwrap_or_else(|e| e.into_inner());
                let (ex, ey) = resolve_entry_point(local_rect, entry_edge, norm_pos, REMOTE_ENTRY_INSET_PX);

                let allow_drag = drag_offer.is_some() && self.features.is_enabled("dragdrop");
                let offer_opt = if allow_drag { drag_offer } else { None };
                let drag_sid = offer_opt.as_ref().map(|o| o.session_id.clone());
                let drag_label = offer_opt.as_ref().map(|o| o.root_name.clone());

                {
                    let now_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;
                    self.last_controlled_entry_ms.store(now_ms, Ordering::Release);
                    let mut role = self.role.lock().unwrap_or_else(|e| e.into_inner());
                    self.set_role_locked(
                        &mut role,
                        KvmRole::ControlledByPeer {
                            peer_ip: peer_ip.to_string(),
                            entry_edge,
                            cur_x: ex,
                            cur_y: ey,
                            active_drag_session: drag_sid.clone(),
                            active_drag_label: drag_label.clone(),
                            native_drag_started: false,
                        },
                    );
                }
                *self.last_edge_transition.lock().unwrap_or_else(|e| e.into_inner()) =
                    Instant::now();
                info!(
                    "➡️ KVM entered local screen on {:?} edge at ({:.0}, {:.0}) [drag={}]",
                    entry_edge,
                    ex,
                    ey,
                    drag_sid.is_some()
                );
                *self
                    .pending_drag_drop_label
                    .write()
                    .unwrap_or_else(|e| e.into_inner()) = drag_label;
                self.remote_left_down.store(left_button_held, Ordering::Release);
                Self::platform_set_controlled(true, ex, ey);

                if let Some(offer) = offer_opt {
                    let show_ghost = self
                        .layout
                        .read()
                        .unwrap_or_else(|e| e.into_inner())
                        .ghost_thumbnail;
                    if show_ghost {
                        let sub = format!(
                            "{} item{} • {:.1} MB • Staging...",
                            offer.total_files,
                            if offer.total_files == 1 { "" } else { "s" },
                            offer.total_bytes as f64 / (1024.0 * 1024.0)
                        );
                        Self::platform_show_ghost(
                            ex,
                            ey,
                            &offer.root_name,
                            &sub,
                            offer.icon_png_b64.as_deref(),
                        );
                    }

                    let svc_stage = Arc::clone(self);
                    let peer_ip_s = peer_ip.to_string();
                    let stage_handle = tokio::spawn(async move {
                        match svc_stage
                            .clipboard
                            .stream_drag_session_to_staging(
                                &peer_ip_s,
                                &offer.session_id,
                                offer.total_bytes,
                                offer.total_files,
                                &offer.top_entries,
                            )
                            .await
                        {
                            Ok((stage_dir, top_paths)) => {
                                {
                                    let mut dirs = svc_stage
                                        .drag_stage_dirs
                                        .lock()
                                        .unwrap_or_else(|e| e.into_inner());
                                    dirs.insert(offer.session_id.clone(), stage_dir);
                                }
                                svc_stage
                                    .on_drag_staging_ready(&offer.session_id, top_paths)
                                    .await;
                            }
                            Err(e) => {
                                warn!("🚫 Drag staging failed for '{}': {}", offer.root_name, e);
                                Self::platform_hide_ghost();
                                svc_stage.remote_left_down.store(false, Ordering::Release);
                                *svc_stage
                                    .pending_drag_drop_label
                                    .write()
                                    .unwrap_or_else(|e| e.into_inner()) = None;
                                {
                                    let mut role = svc_stage
                                        .role
                                        .lock()
                                        .unwrap_or_else(|e| e.into_inner());
                                    if let KvmRole::ControlledByPeer {
                                        ref mut active_drag_session,
                                        ref mut active_drag_label,
                                        ..
                                    } = *role
                                    {
                                        if active_drag_session.as_deref()
                                            == Some(offer.session_id.as_str())
                                        {
                                            *active_drag_session = None;
                                            *active_drag_label = None;
                                        }
                                    }
                                }
                                svc_stage.try_send_wire(KvmWireMessage::DragDropResult {
                                    session_id: offer.session_id,
                                    accepted: false,
                                    message: format!("Staging failed: {}", e),
                                });
                            }
                        }
                    });
                    *self
                        .staging_task
                        .lock()
                        .unwrap_or_else(|e| e.into_inner()) = Some(stage_handle.abort_handle());
                } else if left_button_held {
                    // Normal window/selection drag across border without files
                    Self::platform_inject_mouse_button(RemoteMouseButton::Left, true, ex, ey);
                    self.held_remote_buttons
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(RemoteMouseButton::Left);
                }
            }
            KvmWireMessage::LeaveScreen {
                exit_edge: _,
                norm_pos,
            } => {
                if !norm_pos.is_finite() {
                    return;
                }
                // Gaming Boundary Lock: keep cursor locked on the remote gaming PC until explicitly unlocked
                if self.boundary_locked.load(Ordering::Acquire) {
                    return;
                }
                let local_rect = *self.local_rect.read().unwrap_or_else(|e| e.into_inner());
                let layout_cfg = self.get_layout();
                let (rx, ry) = resolve_entry_point(local_rect, layout_cfg.peer_edge, norm_pos, RETURN_ENTRY_INSET_PX);

                let old_drag_sid = {
                    let mut role = self.role.lock().unwrap_or_else(|e| e.into_inner());
                    if !matches!(*role, KvmRole::ControllingPeer { .. }) {
                        return;
                    }
                    let sid = match *role {
                        KvmRole::ControllingPeer {
                            ref active_drag_session,
                            ..
                        } => active_drag_session.clone(),
                        _ => None,
                    };
                    self.set_role_locked(&mut role, KvmRole::Idle);
                    sid
                };
                self.sent_remote_keys
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .clear();
                if let Some(sid) = old_drag_sid {
                    self.clipboard.remove_drag_session(&sid).await;
                }
                *self
                    .pending_drag_drop_label
                    .write()
                    .unwrap_or_else(|e| e.into_inner()) = None;
                *self.last_edge_transition.lock().unwrap_or_else(|e| e.into_inner()) =
                    Instant::now();
                info!(
                    "↩️ KVM control returned from peer at ({:.0}, {:.0})",
                    rx, ry
                );
                let park_x = local_rect.x + local_rect.width * 0.5;
                let park_y = local_rect.y + local_rect.height * 0.5;
                Self::platform_set_controlling(false, park_x, park_y, rx, ry);
            }
            KvmWireMessage::MouseMoveDelta { dx, dy } => {
                if !dx.is_finite() || !dy.is_finite() {
                    return;
                }
                let local_rect = *self.local_rect.read().unwrap_or_else(|e| e.into_inner());
                let cfg = self.get_layout();
                let (new_x, new_y, left_down, crossed_back) = {
                    let mut role = self.role.lock().unwrap_or_else(|e| e.into_inner());
                    let KvmRole::ControlledByPeer {
                        entry_edge,
                        ref mut cur_x,
                        ref mut cur_y,
                        ref active_drag_session,
                        ..
                    } = *role
                    else {
                        return;
                    };

                    let next_x = *cur_x + dx;
                    let next_y = *cur_y + dy;

                    let crossed = match entry_edge {
                        ScreenEdge::Left => next_x < local_rect.x,
                        ScreenEdge::Right => next_x > local_rect.max_x(),
                        ScreenEdge::Top => next_y < local_rect.y,
                        ScreenEdge::Bottom => next_y > local_rect.max_y(),
                    };

                    let cooldown_elapsed = self
                        .last_edge_transition
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .elapsed()
                        >= EDGE_TRANSITION_COOLDOWN;

                    let boundary_locked = self.boundary_locked.load(Ordering::Acquire);
                    if crossed && !boundary_locked && active_drag_session.is_none() && cooldown_elapsed {
                        let dead = cfg.dead_corners
                            && is_in_dead_corner(local_rect, entry_edge, next_x, next_y);
                        if !dead {
                            let norm = compute_normalized_edge_pos(
                                local_rect,
                                entry_edge,
                                next_x,
                                next_y,
                                cfg.alignment_offset,
                            );
                            self.set_role_locked(&mut role, KvmRole::Idle);
                            (next_x, next_y, false, Some((entry_edge, norm)))
                        } else {
                            *cur_x = next_x.clamp(local_rect.x + 1.0, local_rect.max_x() - 1.0);
                            *cur_y = next_y.clamp(local_rect.y + 1.0, local_rect.max_y() - 1.0);
                            (
                                *cur_x,
                                *cur_y,
                                self.remote_left_down.load(Ordering::Acquire),
                                None,
                            )
                        }
                    } else {
                        *cur_x = next_x.clamp(local_rect.x + 1.0, local_rect.max_x() - 1.0);
                        *cur_y = next_y.clamp(local_rect.y + 1.0, local_rect.max_y() - 1.0);
                        (
                            *cur_x,
                            *cur_y,
                            self.remote_left_down.load(Ordering::Acquire),
                            None,
                        )
                    }
                };

                if let Some((exit_edge, norm_pos)) = crossed_back {
                    *self.last_edge_transition.lock().unwrap_or_else(|e| e.into_inner()) =
                        Instant::now();
                    info!(
                        "⬅️ Returning KVM control across {:?} edge (next={:.0},{:.0})",
                        exit_edge, new_x, new_y
                    );
                    self.release_all_injected_inputs(new_x, new_y);
                    Self::platform_hide_ghost();
                    Self::platform_set_controlled(false, new_x, new_y);
                    self.try_send_wire(KvmWireMessage::LeaveScreen {
                        exit_edge,
                        norm_pos,
                    });
                } else {
                    Self::platform_move_ghost(new_x, new_y);
                    Self::platform_inject_mouse_move(new_x, new_y, left_down);
                }
            }
            KvmWireMessage::MouseButton { button, pressed } => {
                let (cx, cy, is_controlled) = {
                    let role = self.role.lock().unwrap_or_else(|e| e.into_inner());
                    match *role {
                        KvmRole::ControlledByPeer { cur_x, cur_y, .. } => (cur_x, cur_y, true),
                        _ => (0.0, 0.0, false),
                    }
                };
                if !is_controlled {
                    return;
                }
                if button == RemoteMouseButton::Left {
                    self.remote_left_down.store(pressed, Ordering::Release);
                }
                {
                    let mut held = self
                        .held_remote_buttons
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    if pressed {
                        held.insert(button);
                    } else {
                        held.remove(&button);
                    }
                }
                Self::platform_inject_mouse_button(button, pressed, cx, cy);
            }
            KvmWireMessage::MouseScroll { dx, dy } => {
                if !dx.is_finite() || !dy.is_finite() {
                    return;
                }
                let is_controlled = matches!(
                    *self.role.lock().unwrap_or_else(|e| e.into_inner()),
                    KvmRole::ControlledByPeer { .. }
                );
                if is_controlled && self.get_layout().precision_touchpad {
                    Self::platform_inject_scroll(dx, dy);
                }
            }
            KvmWireMessage::KeyEvent {
                key,
                pressed,
                modifiers,
            } => {
                let is_controlled = matches!(
                    *self.role.lock().unwrap_or_else(|e| e.into_inner()),
                    KvmRole::ControlledByPeer { .. }
                );
                if !is_controlled {
                    return;
                }
                if key != LogicalKey::CapsLock {
                    let mut held = self
                        .held_remote_keys
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    if pressed {
                        held.insert(key);
                    } else {
                        held.remove(&key);
                    }
                }
                Self::platform_inject_key(key, pressed, modifiers);
            }
            KvmWireMessage::DragCancel { session_id } => {
                if let Some(handle) = self
                    .staging_task
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .take()
                {
                    handle.abort();
                }
                #[cfg(target_os = "windows")]
                windows_backend::cancel_remote_drag();
                Self::platform_hide_ghost();
                self.remote_left_down.store(false, Ordering::Release);
                *self
                    .pending_drag_drop_label
                    .write()
                    .unwrap_or_else(|e| e.into_inner()) = None;
                {
                    let mut role = self.role.lock().unwrap_or_else(|e| e.into_inner());
                    match *role {
                        KvmRole::ControlledByPeer {
                            ref mut active_drag_session,
                            ref mut active_drag_label,
                            ..
                        } => {
                            if active_drag_session.as_deref() == Some(session_id.as_str()) {
                                *active_drag_session = None;
                                *active_drag_label = None;
                            }
                        }
                        KvmRole::ControllingPeer {
                            ref mut active_drag_session,
                            ..
                        } => {
                            if active_drag_session.as_deref() == Some(session_id.as_str()) {
                                *active_drag_session = None;
                            }
                        }
                        KvmRole::Idle => {}
                    }
                }
                self.remove_drag_stage_dir(&session_id);
                self.clipboard.remove_drag_session(&session_id).await;
            }
            KvmWireMessage::DragDropResult {
                session_id,
                accepted,
                message,
            } => {
                info!(
                    "📦 Cross-screen drag session {} finished (accepted={}): {}",
                    session_id, accepted, message
                );
                *self
                    .pending_drag_drop_label
                    .write()
                    .unwrap_or_else(|e| e.into_inner()) = None;
                {
                    let mut role = self.role.lock().unwrap_or_else(|e| e.into_inner());
                    if let KvmRole::ControllingPeer {
                        ref mut active_drag_session,
                        ..
                    } = *role
                    {
                        if active_drag_session.as_deref() == Some(session_id.as_str()) {
                            *active_drag_session = None;
                        }
                    }
                }
                self.remove_drag_stage_dir(&session_id);
                self.clipboard.remove_drag_session(&session_id).await;
                crate::core::emit_ui_toast(
                    if accepted { "success" } else { "info" },
                    &message,
                );
            }
            KvmWireMessage::ReleaseAll => {
                self.force_release_all(false);
            }
            KvmWireMessage::SetBoundaryLock { locked } => {
                self.set_boundary_locked(locked, false);
            }
            KvmWireMessage::Ping => {}
        }
    }

    async fn on_drag_staging_ready(self: &Arc<Self>, session_id: &str, top_paths: Vec<PathBuf>) {
        if top_paths.is_empty() {
            Self::platform_hide_ghost();
            self.remote_left_down.store(false, Ordering::Release);
            *self
                .pending_drag_drop_label
                .write()
                .unwrap_or_else(|e| e.into_inner()) = None;
            {
                let mut role = self.role.lock().unwrap_or_else(|e| e.into_inner());
                if let KvmRole::ControlledByPeer {
                    ref mut active_drag_session,
                    ref mut active_drag_label,
                    ..
                } = *role
                {
                    if active_drag_session.as_deref() == Some(session_id) {
                        *active_drag_session = None;
                        *active_drag_label = None;
                    }
                }
            }
            self.remove_drag_stage_dir(session_id);
            return;
        }
        #[cfg_attr(not(target_os = "macos"), allow(unused_variables))]
        let (cx, cy, matches_session) = {
            let mut role = self.role.lock().unwrap_or_else(|e| e.into_inner());
            if let KvmRole::ControlledByPeer {
                cur_x,
                cur_y,
                ref active_drag_session,
                ref mut native_drag_started,
                ..
            } = *role
            {
                let same = active_drag_session.as_deref() == Some(session_id);
                if same {
                    *native_drag_started = true;
                }
                (cur_x, cur_y, same)
            } else {
                (0.0, 0.0, false)
            }
        };

        if !matches_session {
            Self::platform_hide_ghost();
            self.remove_drag_stage_dir(session_id);
            return;
        }

        let left_still_held = self.remote_left_down.load(Ordering::Acquire);
        if left_still_held {
            #[cfg(target_os = "macos")]
            macos_backend::begin_native_drop_drag(&top_paths, session_id, cx, cy);
            #[cfg(target_os = "windows")]
            windows_backend::begin_native_drop_drag(&top_paths, session_id, true);
        } else {
            // User already released the mouse button while a larger file was finishing SHA-256 verification.
            // Commit atomically into the configured fallback folder (`Downloads` / `Desktop` / `Cache`).
            let drop_folder_pref = self.get_layout().drop_folder;
            let count = top_paths.len();
            let first_name = top_paths
                .first()
                .and_then(|p| p.file_name())
                .and_then(|s| s.to_str())
                .unwrap_or("Items")
                .to_string();

            let commit_res = tokio::task::spawn_blocking(move || {
                Self::commit_staged_to_fallback_folder(&top_paths, &drop_folder_pref)
            })
            .await;

            Self::platform_hide_ghost();
            *self
                .pending_drag_drop_label
                .write()
                .unwrap_or_else(|e| e.into_inner()) = None;
            {
                let mut role = self.role.lock().unwrap_or_else(|e| e.into_inner());
                if let KvmRole::ControlledByPeer {
                    ref mut active_drag_session,
                    ref mut active_drag_label,
                    ..
                } = *role
                {
                    if active_drag_session.as_deref() == Some(session_id) {
                        *active_drag_session = None;
                        *active_drag_label = None;
                    }
                }
            }
            self.remove_drag_stage_dir(session_id);

            let (ok, msg) = match commit_res {
                Ok(Ok(dest)) => (
                    true,
                    format!(
                        "Dropped '{}' ({} item{}) into {:?}",
                        first_name,
                        count,
                        if count == 1 { "" } else { "s" },
                        dest
                    ),
                ),
                Ok(Err(e)) => (false, format!("Drop failed: {}", e)),
                Err(e) => (false, format!("Drop task error: {}", e)),
            };
            self.try_send_wire(KvmWireMessage::DragDropResult {
                session_id: session_id.to_string(),
                accepted: ok,
                message: msg,
            });
        }
    }

    pub fn on_native_drag_ended(&self, session_id: &str, accepted: bool) {
        Self::platform_hide_ghost();
        self.remote_left_down.store(false, Ordering::Release);
        *self
            .pending_drag_drop_label
            .write()
            .unwrap_or_else(|e| e.into_inner()) = None;
        {
            let mut role = self.role.lock().unwrap_or_else(|e| e.into_inner());
            if let KvmRole::ControlledByPeer {
                ref mut active_drag_session,
                ref mut active_drag_label,
                ..
            } = *role
            {
                if active_drag_session.as_deref() == Some(session_id) {
                    *active_drag_session = None;
                    *active_drag_label = None;
                }
            }
        }
        self.remove_drag_stage_dir(session_id);
        let msg = if accepted {
            "Cross-screen drop completed".to_string()
        } else {
            "Cross-screen drop cancelled".to_string()
        };
        self.try_send_wire(KvmWireMessage::DragDropResult {
            session_id: session_id.to_string(),
            accepted,
            message: msg,
        });
    }

    // =========================================================================
    // Low-Level OS Hook Decision Handlers (MUST BE SUB-MILLISECOND & NON-BLOCKING)
    // =========================================================================

    pub fn on_local_mouse_move(
        &self,
        x: f32,
        y: f32,
        dx: f32,
        dy: f32,
        left_button_held: bool,
    ) -> HookDecision {
        if !x.is_finite() || !y.is_finite() || !dx.is_finite() || !dy.is_finite() {
            return HookDecision::PassThrough;
        }
        if !self.features.is_enabled("input_kvm") {
            return HookDecision::PassThrough;
        }

        let is_idle = {
            let role = self.role.lock().unwrap_or_else(|e| e.into_inner());
            match *role {
                KvmRole::ControllingPeer { .. } => {
                    drop(role);
                    if dx != 0.0 || dy != 0.0 {
                        self.try_send_wire(KvmWireMessage::MouseMoveDelta { dx, dy });
                    }
                    return HookDecision::SwallowAndParkCenter;
                }
                KvmRole::ControlledByPeer { .. } => {
                    drop(role);
                    let now_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;
                    let entered_at = self.last_controlled_entry_ms.load(Ordering::Acquire);
                    if now_ms.saturating_sub(entered_at) > 150 && (dx.abs() > 3.0 || dy.abs() > 3.0) {
                        info!("👋 Local physical mouse motion detected while controlled; taking back control");
                        self.force_release_all(true);
                        crate::core::emit_ui_toast("info", "KVM remote control suspended by local mouse motion");
                    }
                    return HookDecision::PassThrough;
                }
                KvmRole::Idle => true,
            }
        };
        if !is_idle {
            return HookDecision::PassThrough;
        }
        // KVM Gaming Boundary Lock: freeze all outgoing edge hops while locked
        if self.boundary_locked.load(Ordering::Acquire) {
            *self.edge_dwell.lock().unwrap_or_else(|e| e.into_inner()) = None;
            return HookDecision::PassThrough;
        }

        let connected_ip = self
            .connected_peer_ip
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let Some(peer_ip) = connected_ip else {
            return HookDecision::PassThrough;
        };

        {
            let last = self
                .last_edge_transition
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if last.elapsed() < EDGE_TRANSITION_COOLDOWN {
                return HookDecision::PassThrough;
            }
        }

        let layout_cfg = self.get_layout();
        let rect = *self.local_rect.read().unwrap_or_else(|e| e.into_inner());

        let at_edge = match layout_cfg.peer_edge {
            ScreenEdge::Left => x <= rect.x + EDGE_PROXIMITY_INSET_PX,
            ScreenEdge::Right => x >= rect.max_x() - EDGE_PROXIMITY_OUTSET_PX,
            ScreenEdge::Top => y <= rect.y + EDGE_PROXIMITY_INSET_PX,
            ScreenEdge::Bottom => y >= rect.max_y() - EDGE_PROXIMITY_OUTSET_PX,
        };

        if !at_edge {
            *self.edge_dwell.lock().unwrap_or_else(|e| e.into_inner()) = None;
            return HookDecision::PassThrough;
        }

        if layout_cfg.dead_corners && is_in_dead_corner(rect, layout_cfg.peer_edge, x, y) {
            *self.edge_dwell.lock().unwrap_or_else(|e| e.into_inner()) = None;
            return HookDecision::PassThrough;
        }

        let effective_delay_ms = if left_button_held && self.features.is_enabled("dragdrop") {
            layout_cfg.hop_delay_ms.max(MIN_DRAG_HOP_DELAY_MS)
        } else {
            layout_cfg.hop_delay_ms
        };
        if effective_delay_ms > 0 {
            let mut dwell = self.edge_dwell.lock().unwrap_or_else(|e| e.into_inner());
            let now = Instant::now();
            match *dwell {
                Some((e, started))
                    if e == layout_cfg.peer_edge
                        && now.duration_since(started) <= MAX_EDGE_DWELL_VALIDITY =>
                {
                    if now.duration_since(started)
                        < Duration::from_millis(effective_delay_ms as u64)
                    {
                        return HookDecision::PassThrough;
                    }
                }
                _ => {
                    *dwell = Some((layout_cfg.peer_edge, now));
                    return HookDecision::PassThrough;
                }
            }
            *dwell = None;
        }

        let drag_paths = if left_button_held && self.features.is_enabled("dragdrop") {
            Self::platform_probe_drag_paths()
        } else {
            Vec::new()
        };

        let park_x = rect.x + rect.width * 0.5;
        let park_y = rect.y + rect.height * 0.5;
        let norm_pos = compute_normalized_edge_pos(
            rect,
            layout_cfg.peer_edge,
            x,
            y,
            layout_cfg.alignment_offset,
        );

        {
            let mut role = self.role.lock().unwrap_or_else(|e| e.into_inner());
            if !matches!(*role, KvmRole::Idle) || !self.features.is_enabled("input_kvm") {
                return HookDecision::PassThrough;
            }
            self.set_role_locked(
                &mut role,
                KvmRole::ControllingPeer {
                    peer_ip,
                    active_drag_session: None,
                    restore_x: x,
                    restore_y: y,
                },
            );
        }
        *self.last_edge_transition.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();
        info!(
            "➡️ Handing KVM control to peer across {:?} edge from ({:.0}, {:.0})",
            layout_cfg.peer_edge, x, y
        );

        if !drag_paths.is_empty() {
            Self::platform_cancel_local_drag();
        }
        Self::platform_set_controlling(true, park_x, park_y, x, y);

        let entry_edge = layout_cfg.peer_edge.opposite();
        if !drag_paths.is_empty() {
            if let Some(tx) = self
                .outbound_tx
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
            {
                let _ = tx.try_send(KvmOutboundCmd::EnterWithDragPaths {
                    entry_edge,
                    norm_pos,
                    left_button_held,
                    paths: drag_paths,
                });
            }
        } else {
            self.try_send_wire(KvmWireMessage::EnterScreen {
                entry_edge,
                norm_pos,
                left_button_held,
                drag_offer: None,
            });
        }

        HookDecision::SwallowAndParkCenter
    }

    pub fn on_local_mouse_button(
        &self,
        button: RemoteMouseButton,
        pressed: bool,
        _x: f32,
        _y: f32,
    ) -> HookDecision {
        if !self.features.is_enabled("input_kvm") {
            return HookDecision::PassThrough;
        }
        let role = self.role.lock().unwrap_or_else(|e| e.into_inner());
        match *role {
            KvmRole::ControlledByPeer { .. } => {
                drop(role);
                if pressed {
                    info!("🖱️ Local physical mouse click detected while controlled; taking back control");
                    self.force_release_all(true);
                    crate::core::emit_ui_toast("info", "KVM remote control suspended by local mouse click");
                }
                HookDecision::PassThrough
            }
            KvmRole::ControllingPeer { .. } => {
                drop(role);
                self.try_send_wire(KvmWireMessage::MouseButton { button, pressed });
                HookDecision::Swallow
            }
            KvmRole::Idle => HookDecision::PassThrough,
        }
    }

    pub fn on_local_mouse_scroll(&self, dx: f32, dy: f32) -> HookDecision {
        if !self.features.is_enabled("input_kvm") {
            return HookDecision::PassThrough;
        }
        let controlling = matches!(
            *self.role.lock().unwrap_or_else(|e| e.into_inner()),
            KvmRole::ControllingPeer { .. }
        );
        if !controlling {
            return HookDecision::PassThrough;
        }
        if !dx.is_finite() || !dy.is_finite() {
            return HookDecision::Swallow;
        }
        self.try_send_wire(KvmWireMessage::MouseScroll { dx, dy });
        HookDecision::Swallow
    }

    pub fn on_local_key_event(
        &self,
        key: LogicalKey,
        pressed: bool,
        modifiers: ModifierMask,
    ) -> HookDecision {
        if !self.features.is_enabled("input_kvm") {
            return HookDecision::PassThrough;
        }

        // Panic Escape Hatch: Ctrl + Alt + Shift + Esc immediately breaks remote control
        if pressed
            && key == LogicalKey::Escape
            && modifiers.control
            && modifiers.alt
            && modifiers.shift
        {
            info!("🛟 KVM panic release hotkey triggered (Ctrl+Alt+Shift+Esc)");
            self.force_release_all(true);
            return HookDecision::Swallow;
        }

        // Physical Local Takeover: Any local keyboard event while controlled takes back control
        let is_controlled = matches!(
            *self.role.lock().unwrap_or_else(|e| e.into_inner()),
            KvmRole::ControlledByPeer { .. }
        );
        if is_controlled && pressed {
            info!("⌨️ Local physical keyboard event detected while controlled; taking back control");
            self.force_release_all(true);
            crate::core::emit_ui_toast("info", "KVM remote control suspended by local keyboard input");
            return HookDecision::PassThrough;
        }

        let controlling = matches!(
            *self.role.lock().unwrap_or_else(|e| e.into_inner()),
            KvmRole::ControllingPeer { .. }
        );
        if !controlling {
            return HookDecision::PassThrough;
        }

        let (tx_key, tx_mods) = if pressed {
            let translated = self.translate_key_for_peer(key, modifiers);
            if key != LogicalKey::CapsLock {
                self.sent_remote_keys
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(key, translated);
            }
            translated
        } else if key != LogicalKey::CapsLock {
            let prev = self
                .sent_remote_keys
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&key);
            if let Some((prev_key, _prev_mods)) = prev {
                let (_, cur_mods) = self.translate_key_for_peer(key, modifiers);
                (prev_key, cur_mods)
            } else {
                self.translate_key_for_peer(key, modifiers)
            }
        } else {
            self.translate_key_for_peer(key, modifiers)
        };

        self.try_send_wire(KvmWireMessage::KeyEvent {
            key: tx_key,
            pressed,
            modifiers: tx_mods,
        });
        HookDecision::Swallow
    }

    pub fn translate_key_for_peer(
        &self,
        key: LogicalKey,
        mods: ModifierMask,
    ) -> (LogicalKey, ModifierMask) {
        let cfg = self.get_layout();
        if !cfg.modifier_translation || !self.peer_diff_os.load(Ordering::Relaxed) {
            return (key, mods);
        }
        translate_command_ctrl_pair(key, mods)
    }

    // =========================================================================
    // Internal Helpers
    // =========================================================================

    fn remove_drag_stage_dir(&self, session_id: &str) {
        let dir = self
            .drag_stage_dirs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(session_id);
        if let Some(dir) = dir {
            self.spawn_or_sync_remove_dir(dir);
        }
    }

    fn cleanup_all_drag_stage_dirs(&self) {
        let dirs: Vec<PathBuf> = self
            .drag_stage_dirs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain()
            .map(|(_, d)| d)
            .collect();
        for dir in dirs {
            self.spawn_or_sync_remove_dir(dir);
        }
    }

    fn spawn_or_sync_remove_dir(&self, dir: PathBuf) {
        if !self.shutting_down.load(Ordering::Acquire) {
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn_blocking(move || {
                    let _ = std::fs::remove_dir_all(&dir);
                });
                return;
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn try_send_wire(&self, msg: KvmWireMessage) {
        if let Some(tx) = self
            .outbound_tx
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            let is_lossy = matches!(
                msg,
                KvmWireMessage::MouseMoveDelta { .. } | KvmWireMessage::MouseScroll { .. }
            );
            if is_lossy && tx.capacity() < RESERVED_CONTROL_SLOTS {
                return;
            }
            let _ = tx.try_send(KvmOutboundCmd::Wire(msg));
        }
    }

    fn release_all_injected_inputs(&self, cx: f32, cy: f32) {
        let btns: Vec<RemoteMouseButton> = {
            let mut b = self
                .held_remote_buttons
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            b.drain().collect()
        };
        for btn in btns {
            Self::platform_inject_mouse_button(btn, false, cx, cy);
        }

        let keys: Vec<LogicalKey> = {
            let mut k = self
                .held_remote_keys
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            k.drain().collect()
        };
        for key in keys {
            Self::platform_inject_key(key, false, ModifierMask::default());
        }
    }

    fn commit_staged_to_fallback_folder(top_paths: &[PathBuf], drop_pref: &str) -> Result<PathBuf> {
        let home = crate::system_info::user_home_dir();
        let dest_dir = match drop_pref {
            "desktop" => home.join("Desktop"),
            "cache" => crate::system_info::app_data_dir().join(CLIPBOARD_CACHE_DIR_NAME),
            _ => home.join("Downloads"),
        };
        Self::commit_staged_to_dest_dir(top_paths, &dest_dir)?;
        Ok(dest_dir)
    }

    fn commit_staged_to_dest_dir(top_paths: &[PathBuf], dest_dir: &Path) -> Result<()> {
        const MAX_COLLISION_INDEX: usize = 10_000;
        std::fs::create_dir_all(dest_dir)?;

        for src in top_paths {
            let Some(name) = src.file_name().and_then(|s| s.to_str()) else {
                continue;
            };
            if name.is_empty()
                || name == "."
                || name == ".."
                || name.contains('/')
                || name.contains('\\')
            {
                continue;
            }
            let src_is_dir = std::fs::symlink_metadata(src)
                .map(|m| m.is_dir())
                .unwrap_or(false);
            let mut dest = dest_dir.join(name);
            if std::fs::symlink_metadata(&dest).is_ok() {
                let stem = src.file_stem().and_then(|s| s.to_str()).unwrap_or(name);
                let ext = src.extension().and_then(|s| s.to_str());
                let mut found = None;
                for idx in 1..=MAX_COLLISION_INDEX {
                    let cand = match ext {
                        Some(e) if !src_is_dir => format!("{} ({}).{}", stem, idx, e),
                        _ => format!("{} ({})", name, idx),
                    };
                    let p = dest_dir.join(cand);
                    if std::fs::symlink_metadata(&p).is_err() {
                        found = Some(p);
                        break;
                    }
                }
                dest = match found {
                    Some(p) => p,
                    None => anyhow::bail!(
                        "Exceeded {} destination name collision attempts for '{}'",
                        MAX_COLLISION_INDEX,
                        name
                    ),
                };
            }
            if std::fs::rename(src, &dest).is_err() {
                ClipboardService::copy_entry_all(src, &dest)?;
                if src_is_dir {
                    let _ = std::fs::remove_dir_all(src);
                } else {
                    let _ = std::fs::remove_file(src);
                }
            }
        }
        Ok(())
    }

    fn platform_is_hook_active() -> bool {
        #[cfg(target_os = "macos")]
        {
            macos_backend::is_hook_active()
        }
        #[cfg(target_os = "windows")]
        {
            windows_backend::is_hook_active()
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            false
        }
    }

    fn platform_set_controlling(
        controlling: bool,
        park_x: f32,
        park_y: f32,
        restore_x: f32,
        restore_y: f32,
    ) {
        #[cfg(target_os = "macos")]
        macos_backend::set_controlling_mode(controlling, park_x, park_y, restore_x, restore_y);
        #[cfg(target_os = "windows")]
        windows_backend::set_controlling_mode(controlling, park_x, park_y, restore_x, restore_y);
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        let _ = (controlling, park_x, park_y, restore_x, restore_y);
    }

    fn platform_set_controlled(controlled: bool, entry_x: f32, entry_y: f32) {
        #[cfg(target_os = "macos")]
        macos_backend::set_controlled_mode(controlled, entry_x, entry_y);
        #[cfg(target_os = "windows")]
        windows_backend::set_controlled_mode(controlled, entry_x, entry_y);
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        let _ = (controlled, entry_x, entry_y);
    }

    fn platform_probe_drag_paths() -> Vec<PathBuf> {
        #[cfg(target_os = "macos")]
        {
            macos_backend::probe_active_drag_paths()
        }
        #[cfg(target_os = "windows")]
        {
            windows_backend::probe_active_drag_paths()
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            Vec::new()
        }
    }

    fn platform_cancel_local_drag() {
        #[cfg(target_os = "macos")]
        macos_backend::cancel_local_drag_after_handoff();
        #[cfg(target_os = "windows")]
        windows_backend::cancel_local_drag_after_handoff();
    }

    fn extract_icon_b64(first_path: Option<&Path>) -> Option<String> {
        #[cfg(target_os = "macos")]
        {
            first_path.and_then(macos_backend::extract_file_icon_png_b64)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = first_path;
            None
        }
    }

    fn platform_inject_mouse_move(x: f32, y: f32, left_held: bool) {
        #[cfg(target_os = "macos")]
        macos_backend::inject_mouse_move(x, y, left_held);
        #[cfg(target_os = "windows")]
        windows_backend::inject_mouse_move(x, y, left_held);
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        let _ = (x, y, left_held);
    }

    fn platform_inject_mouse_button(button: RemoteMouseButton, pressed: bool, x: f32, y: f32) {
        #[cfg(target_os = "macos")]
        macos_backend::inject_mouse_button(button, pressed, x, y);
        #[cfg(target_os = "windows")]
        windows_backend::inject_mouse_button(button, pressed, x, y);
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        let _ = (button, pressed, x, y);
    }

    fn platform_inject_scroll(dx: f32, dy: f32) {
        #[cfg(target_os = "macos")]
        macos_backend::inject_scroll(dx, dy);
        #[cfg(target_os = "windows")]
        windows_backend::inject_scroll(dx, dy);
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        let _ = (dx, dy);
    }

    fn platform_inject_key(key: LogicalKey, pressed: bool, mods: ModifierMask) {
        #[cfg(target_os = "macos")]
        macos_backend::inject_key(key, pressed, mods);
        #[cfg(target_os = "windows")]
        windows_backend::inject_key(key, pressed, mods);
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        let _ = (key, pressed, mods);
    }

    fn platform_show_ghost(
        x: f32,
        y: f32,
        title: &str,
        subtitle: &str,
        icon_b64: Option<&str>,
    ) {
        #[cfg(target_os = "macos")]
        macos_backend::show_drag_ghost(x, y, title, subtitle, icon_b64);
        #[cfg(target_os = "windows")]
        windows_backend::show_drag_ghost(x, y, title, subtitle, icon_b64);
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        let _ = (x, y, title, subtitle, icon_b64);
    }

    fn platform_move_ghost(x: f32, y: f32) {
        #[cfg(target_os = "macos")]
        macos_backend::move_drag_ghost(x, y);
        #[cfg(target_os = "windows")]
        windows_backend::move_drag_ghost(x, y);
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        let _ = (x, y);
    }

    fn platform_hide_ghost() {
        #[cfg(target_os = "macos")]
        macos_backend::hide_drag_ghost();
        #[cfg(target_os = "windows")]
        windows_backend::hide_drag_ghost();
    }
}

pub fn translate_command_ctrl_pair(
    key: LogicalKey,
    mods: ModifierMask,
) -> (LogicalKey, ModifierMask) {
    let translated_key = match key {
        LogicalKey::MetaLeft => LogicalKey::ControlLeft,
        LogicalKey::MetaRight => LogicalKey::ControlRight,
        LogicalKey::ControlLeft => LogicalKey::MetaLeft,
        LogicalKey::ControlRight => LogicalKey::MetaRight,
        other => other,
    };
    let translated_mods = ModifierMask {
        shift: mods.shift,
        control: mods.meta,
        alt: mods.alt,
        meta: mods.control,
    };
    (translated_key, translated_mods)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_ctrl_modifier_translation_is_symmetric() {
        let orig_mods = ModifierMask {
            shift: true,
            control: false,
            alt: false,
            meta: true,
        };
        let (k1, m1) = translate_command_ctrl_pair(LogicalKey::MetaLeft, orig_mods);
        assert_eq!(k1, LogicalKey::ControlLeft);
        assert!(m1.control);
        assert!(!m1.meta);
        assert!(m1.shift);

        let (k2, m2) = translate_command_ctrl_pair(k1, m1);
        assert_eq!(k2, LogicalKey::MetaLeft);
        assert_eq!(m2, orig_mods);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_keycode_roundtrip() {
        let sample = [
            LogicalKey::CharA,
            LogicalKey::CharZ,
            LogicalKey::Return,
            LogicalKey::Escape,
            LogicalKey::Space,
            LogicalKey::MetaLeft,
            LogicalKey::ControlLeft,
            LogicalKey::F12,
        ];
        for k in sample {
            let kc = macos_backend::logical_to_macos_keycode(k).unwrap();
            assert_eq!(macos_backend::macos_keycode_to_logical(kc), Some(k));
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_vk_roundtrip() {
        let sample = [
            LogicalKey::CharA,
            LogicalKey::CharZ,
            LogicalKey::Return,
            LogicalKey::Escape,
            LogicalKey::Space,
            LogicalKey::MetaLeft,
            LogicalKey::ControlLeft,
            LogicalKey::F12,
        ];
        for k in sample {
            let (vk, _) = windows_backend::logical_to_win_vk(k).unwrap();
            assert_eq!(windows_backend::win_vk_to_logical(vk), Some(k));
        }
    }

    fn make_test_kvm_service() -> Arc<KvmService> {
        let mut flags = crate::features::FeatureFlags::fail_closed();
        flags.input_kvm = true;
        let features = Arc::new(FeatureManager::from_flags_for_test(flags));
        let discovery = DiscoveryManager::new("test-node");
        let clipboard = ClipboardService::new(discovery.clone()).expect("test clipboard");
        KvmService::new(discovery, clipboard, features)
    }

    #[test]
    fn alignment_offset_roundtrip_is_symmetric() {
        let mut cfg_a = KvmLayoutConfig::default();
        cfg_a.peer_edge = ScreenEdge::Right;
        cfg_a.alignment_offset = 0.15;
        let cfg_b = mirror_layout_for_peer(&cfg_a);

        let rect_a = ScreenRect {
            x: 0.0,
            y: 0.0,
            width: 1920.0,
            height: 1080.0,
        };
        let rect_b = ScreenRect {
            x: 0.0,
            y: 0.0,
            width: 1440.0,
            height: 900.0,
        };
        let y_a = 500.0;
        let norm_to_b = compute_normalized_edge_pos(
            rect_a,
            cfg_a.peer_edge,
            rect_a.max_x(),
            y_a,
            cfg_a.alignment_offset,
        );
        let (_bx, y_b) = resolve_entry_point(rect_b, cfg_b.peer_edge, norm_to_b, 24.0);
        let norm_back = compute_normalized_edge_pos(
            rect_b,
            cfg_b.peer_edge,
            rect_b.x,
            y_b,
            cfg_b.alignment_offset,
        );
        let (_ax, y_a_back) = resolve_entry_point(rect_a, cfg_a.peer_edge, norm_back, 16.0);
        assert!(
            (y_a_back - y_a).abs() <= 2.0,
            "Expected symmetric return y near {y_a}, got {y_a_back}"
        );
    }

    #[tokio::test]
    async fn leave_screen_is_ignored_when_idle_or_controlled() {
        let svc = make_test_kvm_service();
        svc.handle_inbound_message(
            "10.99.99.2",
            KvmWireMessage::LeaveScreen {
                exit_edge: ScreenEdge::Left,
                norm_pos: 0.5,
            },
        )
        .await;
        assert!(matches!(*svc.role.lock().unwrap(), KvmRole::Idle));
        assert!(!svc.is_controlling_peer_fast());

        {
            let mut r = svc.role.lock().unwrap();
            svc.set_role_locked(
                &mut r,
                KvmRole::ControlledByPeer {
                    peer_ip: "10.99.99.2".to_string(),
                    entry_edge: ScreenEdge::Left,
                    cur_x: 100.0,
                    cur_y: 200.0,
                    active_drag_session: None,
                    active_drag_label: None,
                    native_drag_started: false,
                },
            );
        }
        svc.handle_inbound_message(
            "10.99.99.2",
            KvmWireMessage::LeaveScreen {
                exit_edge: ScreenEdge::Left,
                norm_pos: 0.5,
            },
        )
        .await;
        assert!(matches!(
            *svc.role.lock().unwrap(),
            KvmRole::ControlledByPeer { .. }
        ));
    }

    #[test]
    fn sent_remote_keys_release_matches_key_down_when_translation_toggles() {
        let svc = make_test_kvm_service();
        let (tx, mut rx) = mpsc::channel(32);
        *svc.outbound_tx.write().unwrap() = Some(tx);
        svc.peer_diff_os.store(true, Ordering::Relaxed);
        {
            let mut cfg = svc.get_layout();
            cfg.modifier_translation = true;
            *svc.layout.write().unwrap() = cfg;
        }
        {
            let mut r = svc.role.lock().unwrap();
            svc.set_role_locked(
                &mut r,
                KvmRole::ControllingPeer {
                    peer_ip: "10.99.99.2".to_string(),
                    active_drag_session: None,
                    restore_x: 10.0,
                    restore_y: 10.0,
                },
            );
        }

        let mods = ModifierMask {
            shift: false,
            control: false,
            alt: false,
            meta: true,
        };
        assert_eq!(
            svc.on_local_key_event(LogicalKey::MetaLeft, true, mods),
            HookDecision::Swallow
        );
        // Toggle modifier_translation OFF while MetaLeft is physically still held
        {
            let mut cfg = svc.get_layout();
            cfg.modifier_translation = false;
            *svc.layout.write().unwrap() = cfg;
        }
        assert_eq!(
            svc.on_local_key_event(LogicalKey::MetaLeft, false, ModifierMask::default()),
            HookDecision::Swallow
        );

        let first = rx.try_recv().unwrap();
        let second = rx.try_recv().unwrap();
        match (first, second) {
            (
                KvmOutboundCmd::Wire(KvmWireMessage::KeyEvent {
                    key: k_down,
                    pressed: true,
                    ..
                }),
                KvmOutboundCmd::Wire(KvmWireMessage::KeyEvent {
                    key: k_up,
                    pressed: false,
                    ..
                }),
            ) => {
                assert_eq!(k_down, LogicalKey::ControlLeft);
                assert_eq!(k_up, LogicalKey::ControlLeft);
            }
            other => panic!("Unexpected outbound key events: {:?}", other),
        }
    }

    #[cfg(unix)]
    #[test]
    fn commit_staged_avoids_overwriting_broken_symlink() {
        let base = std::env::temp_dir().join(format!(
            "integrator_kvm_symlink_test_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        let stage_dir = base.join("stage");
        let dest_dir = base.join("dest");
        std::fs::create_dir_all(&stage_dir).unwrap();
        std::fs::create_dir_all(&dest_dir).unwrap();

        let src_file = stage_dir.join("report.txt");
        std::fs::write(&src_file, b"hello").unwrap();

        // Create a dangling symlink at dest/report.txt
        let dangling = dest_dir.join("report.txt");
        std::os::unix::fs::symlink(base.join("nonexistent_target.txt"), &dangling).unwrap();
        assert!(!dangling.exists());
        assert!(std::fs::symlink_metadata(&dangling).is_ok());

        KvmService::commit_staged_to_dest_dir(&[src_file], &dest_dir).unwrap();
        // Original broken symlink untouched; file moved to "report (1).txt"
        assert!(std::fs::symlink_metadata(&dangling)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(
            std::fs::read_to_string(dest_dir.join("report (1).txt")).unwrap(),
            "hello"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn test_kvm_local_consent_gate_rejects_enterscreen() {
        let svc = make_test_kvm_service();
        let (tx, mut rx) = mpsc::channel(32);
        *svc.outbound_tx.write().unwrap() = Some(tx);

        // Disable remote control permission
        {
            let mut cfg = svc.get_layout();
            cfg.allow_remote_control = false;
            *svc.layout.write().unwrap() = cfg;
        }

        // Send EnterScreen from peer
        svc.handle_inbound_message(
            "10.99.99.2",
            KvmWireMessage::EnterScreen {
                entry_edge: ScreenEdge::Left,
                norm_pos: 0.5,
                left_button_held: false,
                drag_offer: None,
            },
        )
        .await;

        // Verify role remained Idle and ReleaseAll was transmitted back
        assert!(matches!(*svc.role.lock().unwrap(), KvmRole::Idle));
        let outbound = rx.try_recv().expect("ReleaseAll should be transmitted");
        assert!(matches!(outbound, KvmOutboundCmd::Wire(KvmWireMessage::ReleaseAll)));
    }

    #[test]
    fn test_kvm_physical_takeover_via_keyboard_and_mouse() {
        let svc = make_test_kvm_service();
        let (tx, _rx) = mpsc::channel(32);
        *svc.outbound_tx.write().unwrap() = Some(tx);

        // 1. Put into ControlledByPeer
        {
            let mut r = svc.role.lock().unwrap();
            svc.set_role_locked(
                &mut r,
                KvmRole::ControlledByPeer {
                    peer_ip: "10.99.99.2".to_string(),
                    entry_edge: ScreenEdge::Left,
                    cur_x: 100.0,
                    cur_y: 200.0,
                    active_drag_session: None,
                    active_drag_label: None,
                    native_drag_started: false,
                },
            );
        }
        assert!(matches!(*svc.role.lock().unwrap(), KvmRole::ControlledByPeer { .. }));

        // 2. Physical key press triggers immediate takeover
        let mods = ModifierMask::default();
        let decision = svc.on_local_key_event(LogicalKey::CharA, true, mods);
        assert_eq!(decision, HookDecision::PassThrough);
        assert!(matches!(*svc.role.lock().unwrap(), KvmRole::Idle));

        // 3. Put into ControlledByPeer again
        {
            let mut r = svc.role.lock().unwrap();
            svc.set_role_locked(
                &mut r,
                KvmRole::ControlledByPeer {
                    peer_ip: "10.99.99.2".to_string(),
                    entry_edge: ScreenEdge::Left,
                    cur_x: 100.0,
                    cur_y: 200.0,
                    active_drag_session: None,
                    active_drag_label: None,
                    native_drag_started: false,
                },
            );
        }
        assert!(matches!(*svc.role.lock().unwrap(), KvmRole::ControlledByPeer { .. }));

        // 4. Physical mouse click triggers immediate takeover
        let btn_decision = svc.on_local_mouse_button(RemoteMouseButton::Left, true, 100.0, 200.0);
        assert_eq!(btn_decision, HookDecision::PassThrough);
        assert!(matches!(*svc.role.lock().unwrap(), KvmRole::Idle));

        // 5. Physical mouse motion (>3px displacement) triggers immediate takeover
        {
            let mut r = svc.role.lock().unwrap();
            svc.set_role_locked(
                &mut r,
                KvmRole::ControlledByPeer {
                    peer_ip: "10.99.99.2".to_string(),
                    entry_edge: ScreenEdge::Left,
                    cur_x: 100.0,
                    cur_y: 200.0,
                    active_drag_session: None,
                    active_drag_label: None,
                    native_drag_started: false,
                },
            );
        }
        svc.last_controlled_entry_ms.store(1, Ordering::SeqCst); // Old entry time
        let motion_decision = svc.on_local_mouse_move(100.0, 200.0, 5.0, 5.0, false);
        assert_eq!(motion_decision, HookDecision::PassThrough);
        assert!(matches!(*svc.role.lock().unwrap(), KvmRole::Idle));
    }
}
