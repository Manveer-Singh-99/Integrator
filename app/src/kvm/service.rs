//! Universal Control KVM & Cross-Screen Drag-and-Drop Engine.
//!
//! Runs full-duplex over `TransportSessionV2` (`ServiceId::InputKvm`, TCP port `INPUT_PORT = 58286`),
//! strictly requiring paired + pinned peer trust (zero IP bypass, zero v1 fallback).

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use serde::Serialize;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::clipboard::ClipboardService;
use crate::config::INPUT_PORT;
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

const MAX_WIRE_MESSAGE_BYTES: usize = 96 * 1024;
const OUTBOUND_QUEUE_CAP: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookDecision {
    PassThrough,
    Swallow,
    SwallowAndParkCenter,
}

#[derive(Debug, Clone, Serialize)]
pub struct KvmStatusSnapshot {
    pub enabled: bool,
    pub dragdrop_enabled: bool,
    pub hook_active: bool,
    pub role: String,
    pub connected_peer_ip: Option<String>,
    pub peer_os: Option<String>,
    pub peer_width: u32,
    pub peer_height: u32,
    pub active_drag_label: Option<String>,
    pub layout: KvmLayoutConfig,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
enum KvmRole {
    Idle,
    ControllingPeer {
        peer_ip: String,
        active_drag_session: Option<String>,
        restore_x: f32,
        restore_y: f32,
    },
    ControlledByPeer {
        peer_ip: String,
        entry_edge: ScreenEdge,
        cur_x: f32,
        cur_y: f32,
        active_drag_session: Option<String>,
        active_drag_label: Option<String>,
        native_drag_started: bool,
    },
}

#[derive(Debug)]
enum KvmOutboundCmd {
    Wire(KvmWireMessage),
    EnterWithDragPaths {
        entry_edge: ScreenEdge,
        norm_pos: f32,
        left_button_held: bool,
        paths: Vec<PathBuf>,
    },
}

pub struct KvmService {
    discovery: DiscoveryManager,
    clipboard: ClipboardService,
    features: Arc<FeatureManager>,

    layout: RwLock<KvmLayoutConfig>,
    role: Mutex<KvmRole>,
    local_rect: RwLock<ScreenRect>,
    peer_rect: RwLock<ScreenRect>,
    connected_peer_ip: RwLock<Option<String>>,
    peer_os: RwLock<Option<String>>,
    peer_diff_os: AtomicBool,
    remote_left_down: AtomicBool,
    pending_drag_drop_label: RwLock<Option<String>>,
    edge_dwell: Mutex<Option<(ScreenEdge, Instant)>>,
    last_edge_transition: Mutex<Instant>,
    held_remote_keys: Mutex<HashSet<LogicalKey>>,
    held_remote_buttons: Mutex<HashSet<RemoteMouseButton>>,
    outbound_tx: RwLock<Option<mpsc::Sender<KvmOutboundCmd>>>,
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
            local_rect: RwLock::new(ScreenRect {
                x: 0.0,
                y: 0.0,
                width: 1440.0,
                height: 900.0,
            }),
            peer_rect: RwLock::new(ScreenRect {
                x: 0.0,
                y: 0.0,
                width: 1920.0,
                height: 1080.0,
            }),
            connected_peer_ip: RwLock::new(None),
            peer_os: RwLock::new(None),
            peer_diff_os: AtomicBool::new(true),
            remote_left_down: AtomicBool::new(false),
            pending_drag_drop_label: RwLock::new(None),
            edge_dwell: Mutex::new(None),
            last_edge_transition: Mutex::new(Instant::now() - Duration::from_secs(5)),
            held_remote_keys: Mutex::new(HashSet::new()),
            held_remote_buttons: Mutex::new(HashSet::new()),
            outbound_tx: RwLock::new(None),
        });
        svc.refresh_local_rect();
        svc
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

        let svc_accept = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((socket, addr)) => {
                        let peer_ip = addr.ip();
                        let s = Arc::clone(&svc_accept);
                        tokio::spawn(async move {
                            let _ = socket.set_nodelay(true);
                            let mut magic = [0u8; 4];
                            use tokio::io::AsyncReadExt;
                            if tokio::time::timeout(
                                Duration::from_secs(5),
                                socket.readable(),
                            )
                            .await
                            .is_err()
                            {
                                return;
                            }
                            let mut sock = socket;
                            if sock.read_exact(&mut magic).await.is_err() {
                                return;
                            }
                            if magic != TRANSPORT_WIRE_MAGIC {
                                warn!("🚫 Rejected non-ITR2 magic on KVM port from {}", peer_ip);
                                return;
                            }
                            match trust::accept_transport_from_stream(
                                sock,
                                peer_ip,
                                Some(magic),
                                ServiceId::InputKvm,
                            )
                            .await
                            {
                                Ok(sess) => {
                                    s.attach_transport_session(peer_ip.to_string(), sess).await;
                                }
                                Err(e) => {
                                    warn!("🚫 Rejected KVM connection from {}: {}", peer_ip, e);
                                }
                            }
                        });
                    }
                    Err(e) => {
                        warn!("KVM TCP accept error: {}", e);
                        tokio::time::sleep(Duration::from_millis(250)).await;
                    }
                }
            }
        });

        // 2. Persistent peer connector & feature-gate watcher
        let svc_loop = Arc::clone(self);
        tokio::spawn(async move {
            let local_id = crate::system_info::get_or_create_device_id();
            let mut unconnected_ticks: u32 = 0;

            loop {
                svc_loop.refresh_local_rect();
                svc_loop.sync_platform_probe();

                let kvm_on = svc_loop.features.is_enabled("input_kvm");
                if !kvm_on {
                    if !matches!(*svc_loop.role.lock().unwrap_or_else(|e| e.into_inner()), KvmRole::Idle) {
                        svc_loop.force_release_all(true);
                    }
                    unconnected_ticks = 0;
                    tokio::time::sleep(Duration::from_millis(400)).await;
                    continue;
                }

                let already_connected = svc_loop
                    .connected_peer_ip
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .is_some();

                if !already_connected {
                    if let Some(peer) = svc_loop.discovery.get_best_peer().await {
                        if peer.trusted {
                            let peer_ip = peer.addr.ip().to_string();
                            {
                                let mut w = svc_loop.peer_rect.write().unwrap_or_else(|e| e.into_inner());
                                if peer.display_width >= 320 && peer.display_height >= 200 {
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
                            if i_am_preferred_client || unconnected_ticks >= 3 {
                                if let Ok(sess) = trust::connect_transport_to_ip(
                                    &peer_ip,
                                    INPUT_PORT,
                                    ServiceId::InputKvm,
                                    Duration::from_secs(3),
                                )
                                .await
                                {
                                    unconnected_ticks = 0;
                                    let s = Arc::clone(&svc_loop);
                                    tokio::spawn(async move {
                                        s.attach_transport_session(peer_ip, sess).await;
                                    });
                                }
                            }
                        }
                    } else {
                        unconnected_ticks = 0;
                    }
                } else {
                    unconnected_ticks = 0;
                }

                tokio::time::sleep(Duration::from_millis(1000)).await;
            }
        });

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
            width: 1920.0,
            height: 1080.0,
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
            layout: self.get_layout(),
        }
    }

    pub fn force_release_all(&self, notify_peer: bool) {
        if notify_peer {
            self.try_send_wire(KvmWireMessage::ReleaseAll);
        }
        let prev = {
            let mut r = self.role.lock().unwrap_or_else(|e| e.into_inner());
            let old = r.clone();
            *r = KvmRole::Idle;
            old
        };
        *self
            .pending_drag_drop_label
            .write()
            .unwrap_or_else(|e| e.into_inner()) = None;
        self.remote_left_down.store(false, Ordering::Release);

        match prev {
            KvmRole::ControllingPeer {
                restore_x,
                restore_y,
                ..
            } => {
                Self::platform_set_controlling(false, 400.0, 300.0, restore_x, restore_y);
            }
            KvmRole::ControlledByPeer { cur_x, cur_y, .. } => {
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
        let (mut reader, writer) = session.into_split_tcp();
        let (tx, mut rx) = mpsc::channel::<KvmOutboundCmd>(OUTBOUND_QUEUE_CAP);

        *self
            .connected_peer_ip
            .write()
            .unwrap_or_else(|e| e.into_inner()) = Some(peer_ip.clone());
        *self
            .outbound_tx
            .write()
            .unwrap_or_else(|e| e.into_inner()) = Some(tx.clone());

        if let Some(peer) = self.discovery.get_best_peer().await {
            let diff_os = !peer.os.eq_ignore_ascii_case(std::env::consts::OS);
            self.peer_diff_os.store(diff_os, Ordering::Relaxed);
            *self.peer_os.write().unwrap_or_else(|e| e.into_inner()) = Some(peer.os);
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

        Self::run_reader_loop(self, &mut reader, &peer_ip).await;

        drop(tx);
        writer_task.abort();

        // Clean disconnect teardown
        let mut cur_ip = self
            .connected_peer_ip
            .write()
            .unwrap_or_else(|e| e.into_inner());
        if cur_ip.as_deref() == Some(peer_ip.as_str()) {
            *cur_ip = None;
            *self
                .outbound_tx
                .write()
                .unwrap_or_else(|e| e.into_inner()) = None;
            drop(cur_ip);
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
        while let Some(cmd) = rx.recv().await {
            let msg = match cmd {
                KvmOutboundCmd::Wire(m) => m,
                KvmOutboundCmd::EnterWithDragPaths {
                    entry_edge,
                    norm_pos,
                    left_button_held,
                    paths,
                } => {
                    let paths_clone = paths.clone();
                    let collected = tokio::task::spawn_blocking(move || {
                        ClipboardService::collect_drag_items(&paths_clone)
                    })
                    .await;
                    let drag_offer = match collected {
                        Ok(Ok(copy)) => {
                            let icon_b64 = Self::extract_icon_b64(paths.first().map(|p| p.as_path()));
                            let offer = DragOffer {
                                session_id: copy.session_id.clone(),
                                root_name: copy.root_name.clone(),
                                top_entries: copy.top_entries.clone(),
                                total_files: copy.total_files,
                                total_bytes: copy.total_bytes,
                                is_directory: !copy.directories.is_empty(),
                                icon_png_b64: icon_b64,
                            };
                            {
                                let mut role_lock = svc.role.lock().unwrap_or_else(|e| e.into_inner());
                                if let KvmRole::ControllingPeer {
                                    ref mut active_drag_session,
                                    ..
                                } = *role_lock
                                {
                                    *active_drag_session = Some(copy.session_id.clone());
                                }
                            }
                            *svc.pending_drag_drop_label
                                .write()
                                .unwrap_or_else(|e| e.into_inner()) = Some(offer.root_name.clone());
                            svc.clipboard.register_drag_session(copy).await;
                            Some(offer)
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
            let bytes = match reader.recv_message().await {
                Ok(b) => b,
                Err(_) => break,
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
                if width >= 320 && height >= 200 {
                    *self.peer_rect.write().unwrap_or_else(|e| e.into_inner()) = ScreenRect {
                        x: 0.0,
                        y: 0.0,
                        width: width as f32,
                        height: height as f32,
                    };
                }
            }
            KvmWireMessage::SyncLayout(mut incoming) => {
                sanitize_layout(&mut incoming);
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
                let local_rect = *self.local_rect.read().unwrap_or_else(|e| e.into_inner());
                let (ex, ey) = resolve_entry_point(local_rect, entry_edge, norm_pos, 24.0);

                let allow_drag = drag_offer.is_some() && self.features.is_enabled("dragdrop");
                let offer_opt = if allow_drag { drag_offer } else { None };
                let drag_sid = offer_opt.as_ref().map(|o| o.session_id.clone());
                let drag_label = offer_opt.as_ref().map(|o| o.root_name.clone());

                {
                    let mut role = self.role.lock().unwrap_or_else(|e| e.into_inner());
                    *role = KvmRole::ControlledByPeer {
                        peer_ip: peer_ip.to_string(),
                        entry_edge,
                        cur_x: ex,
                        cur_y: ey,
                        active_drag_session: drag_sid.clone(),
                        active_drag_label: drag_label.clone(),
                        native_drag_started: false,
                    };
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
                    tokio::spawn(async move {
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
                            Ok((_stage_dir, top_paths)) => {
                                svc_stage.on_drag_staging_ready(&offer.session_id, top_paths).await;
                            }
                            Err(e) => {
                                warn!("🚫 Drag staging failed for '{}': {}", offer.root_name, e);
                                Self::platform_hide_ghost();
                                *svc_stage
                                    .pending_drag_drop_label
                                    .write()
                                    .unwrap_or_else(|e| e.into_inner()) = None;
                                svc_stage.try_send_wire(KvmWireMessage::DragDropResult {
                                    session_id: offer.session_id,
                                    accepted: false,
                                    message: format!("Staging failed: {}", e),
                                });
                            }
                        }
                    });
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
                let local_rect = *self.local_rect.read().unwrap_or_else(|e| e.into_inner());
                let layout_cfg = self.get_layout();
                let (rx, ry) = resolve_entry_point(local_rect, layout_cfg.peer_edge, norm_pos, 16.0);

                let old_drag_sid = {
                    let mut role = self.role.lock().unwrap_or_else(|e| e.into_inner());
                    let sid = match *role {
                        KvmRole::ControllingPeer {
                            ref active_drag_session,
                            ..
                        } => active_drag_session.clone(),
                        _ => None,
                    };
                    *role = KvmRole::Idle;
                    sid
                };
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
                Self::platform_set_controlling(false, 400.0, 300.0, rx, ry);
            }
            KvmWireMessage::MouseMoveDelta { dx, dy } => {
                let local_rect = *self.local_rect.read().unwrap_or_else(|e| e.into_inner());
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
                        >= Duration::from_millis(180);

                    if crossed && active_drag_session.is_none() && cooldown_elapsed {
                        let dead = {
                            let cfg = self.get_layout();
                            cfg.dead_corners && is_in_dead_corner(local_rect, entry_edge, next_x, next_y)
                        };
                        if !dead {
                            let norm = compute_normalized_edge_pos(
                                local_rect,
                                entry_edge,
                                next_x,
                                next_y,
                                0.0,
                            );
                            *role = KvmRole::Idle;
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
                #[cfg(target_os = "windows")]
                windows_backend::cancel_remote_drag();
                Self::platform_hide_ghost();
                *self
                    .pending_drag_drop_label
                    .write()
                    .unwrap_or_else(|e| e.into_inner()) = None;
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
                        *active_drag_session = None;
                    }
                }
                self.clipboard.remove_drag_session(&session_id).await;
                crate::core::emit_ui_toast(
                    if accepted { "success" } else { "info" },
                    &message,
                );
            }
            KvmWireMessage::ReleaseAll => {
                self.force_release_all(false);
            }
            KvmWireMessage::Ping => {}
        }
    }

    async fn on_drag_staging_ready(self: &Arc<Self>, session_id: &str, top_paths: Vec<PathBuf>) {
        if top_paths.is_empty() {
            Self::platform_hide_ghost();
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
                    ..
                } = *role
                {
                    *active_drag_session = None;
                }
            }

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
        *self
            .pending_drag_drop_label
            .write()
            .unwrap_or_else(|e| e.into_inner()) = None;
        {
            let mut role = self.role.lock().unwrap_or_else(|e| e.into_inner());
            if let KvmRole::ControlledByPeer {
                ref mut active_drag_session,
                ..
            } = *role
            {
                *active_drag_session = None;
            }
        }
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
        if !self.features.is_enabled("input_kvm") {
            return HookDecision::PassThrough;
        }

        let role_snapshot = self.role.lock().unwrap_or_else(|e| e.into_inner()).clone();
        match role_snapshot {
            KvmRole::ControllingPeer { .. } => {
                if dx != 0.0 || dy != 0.0 {
                    self.try_send_wire(KvmWireMessage::MouseMoveDelta { dx, dy });
                }
                HookDecision::SwallowAndParkCenter
            }
            KvmRole::ControlledByPeer { .. } => HookDecision::PassThrough,
            KvmRole::Idle => {
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
                    if last.elapsed() < Duration::from_millis(180) {
                        return HookDecision::PassThrough;
                    }
                }

                let layout_cfg = self.get_layout();
                let rect = *self.local_rect.read().unwrap_or_else(|e| e.into_inner());

                let at_edge = match layout_cfg.peer_edge {
                    ScreenEdge::Left => x <= rect.x + 1.5,
                    ScreenEdge::Right => x >= rect.max_x() - 2.0,
                    ScreenEdge::Top => y <= rect.y + 1.5,
                    ScreenEdge::Bottom => y >= rect.max_y() - 2.0,
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
                    layout_cfg.hop_delay_ms.max(25)
                } else {
                    layout_cfg.hop_delay_ms
                };
                if effective_delay_ms > 0 {
                    let mut dwell = self.edge_dwell.lock().unwrap_or_else(|e| e.into_inner());
                    let now = Instant::now();
                    match *dwell {
                        Some((e, started)) if e == layout_cfg.peer_edge => {
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
                    *role = KvmRole::ControllingPeer {
                        peer_ip,
                        active_drag_session: None,
                        restore_x: x,
                        restore_y: y,
                    };
                }
                *self.last_edge_transition.lock().unwrap_or_else(|e| e.into_inner()) =
                    Instant::now();
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
        }
    }

    pub fn on_local_mouse_button(
        &self,
        button: RemoteMouseButton,
        pressed: bool,
        _x: f32,
        _y: f32,
    ) -> HookDecision {
        let controlling = matches!(
            *self.role.lock().unwrap_or_else(|e| e.into_inner()),
            KvmRole::ControllingPeer { .. }
        );
        if !controlling {
            return HookDecision::PassThrough;
        }
        self.try_send_wire(KvmWireMessage::MouseButton { button, pressed });
        HookDecision::Swallow
    }

    pub fn on_local_mouse_scroll(&self, dx: f32, dy: f32) -> HookDecision {
        let controlling = matches!(
            *self.role.lock().unwrap_or_else(|e| e.into_inner()),
            KvmRole::ControllingPeer { .. }
        );
        if !controlling {
            return HookDecision::PassThrough;
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
        let controlling = matches!(
            *self.role.lock().unwrap_or_else(|e| e.into_inner()),
            KvmRole::ControllingPeer { .. }
        );
        if !controlling {
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

        let (tx_key, tx_mods) = self.translate_key_for_peer(key, modifiers);
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

    fn try_send_wire(&self, msg: KvmWireMessage) {
        if let Some(tx) = self
            .outbound_tx
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
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
            "cache" => crate::system_info::app_data_dir().join("clipboard_cache"),
            _ => home.join("Downloads"),
        };
        std::fs::create_dir_all(&dest_dir)?;

        for src in top_paths {
            let Some(name) = src.file_name().and_then(|s| s.to_str()) else {
                continue;
            };
            let mut dest = dest_dir.join(name);
            if dest.exists() {
                let stem = src.file_stem().and_then(|s| s.to_str()).unwrap_or(name);
                let ext = src.extension().and_then(|s| s.to_str());
                let mut idx = 1usize;
                loop {
                    let cand = match ext {
                        Some(e) if !src.is_dir() => format!("{} ({}).{}", stem, idx, e),
                        _ => format!("{} ({})", name, idx),
                    };
                    let p = dest_dir.join(cand);
                    if !p.exists() {
                        dest = p;
                        break;
                    }
                    idx += 1;
                }
            }
            if std::fs::rename(src, &dest).is_err() {
                ClipboardService::copy_entry_all(src, &dest)?;
            }
        }
        Ok(dest_dir)
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
}
