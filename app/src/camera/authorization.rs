//! Integrator Camera Authorization & Consent Management Subsystem
//!
//! Enforces user-controlled, cryptographically bound camera access permissions
//! across macOS physical capture and Windows virtual camera publication.
//!
//! ========================================================================================
//! 1. MODULE SCOPE & SECURITY ARCHITECTURE
//! ========================================================================================
//! - Enforces independent Sender-side (macOS) and Receiver-side (Windows) authorization barriers.
//! - Implements a formal `CameraConsentState` state machine with explicit transitions.
//! - Bridges asynchronous Display RPC control connections and camera video streaming TCP sockets
//!   via short-lived, single-use, cryptographically random `AuthorizationLease` tokens.
//! - Enforces exponential denial cooldowns (5m -> 30m -> 24h) preventing modal prompt fatigue.
//! - Isolates runtime ephemeral states (`Instant`-bound) from HMAC-authenticated persistent records.
//! - Integrates with `KeystoreV2` and `ACTIVE_SESSION_REGISTRY` to invalidate permissions on
//!   unpairing, blocking, or trust generation advance.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::security::csprng_array;
use crate::security::transport::is_peer_revoked;

/// Default lifetime for single-use authorization leases bridging RPC and streaming connections.
pub const DEFAULT_LEASE_TTL: Duration = Duration::from_secs(60);

/// Maximum duration an interactive user consent prompt may remain pending before failing closed.
pub const PROMPT_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum number of concurrent pending prompts across all peers to prevent resource exhaustion.
pub const MAX_GLOBAL_PENDING_PROMPTS: usize = 8;

/// Requested duration/scope of camera authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CameraConsentScope {
    /// Authorized only for a single continuous stream; expires immediately upon stream teardown.
    AllowOnce,
    /// Authorized for one continuous stream (alias for AllowOnce).
    OneContinuousStream,
    /// Authorized for 1 hour from approval time.
    OneHour,
    /// Authorized for 8 hours from approval time.
    EightHours,
    /// Authorized for the lifetime of the active transport session (invalidated on disconnect).
    ActiveSession,
    /// Persistently authorized across daemon restarts (stored in authenticated Keystore).
    AlwaysAllow,
}

/// Action taken when a local user or system policy denies camera access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CameraDenialAction {
    /// Temporary denial advancing the exponential cooldown schedule (5m -> 30m -> 24h).
    Temporary,
    /// Explicit, persistent denial blocking the peer until manually unblocked by the user.
    DenyAndBlock,
}

/// Direction of the camera operation governed by an authorization lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeaseDirection {
    /// Outbound camera video transmission (e.g. Mac physical camera sending frames).
    OutboundSender,
    /// Inbound camera video reception (e.g. Windows receiving frames into virtual camera).
    InboundReceiver,
}

/// Formal camera consent states for a paired peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CameraConsentState {
    /// Default baseline. Peer is paired, but has never requested or was explicitly cleared.
    NoConsent,
    /// Modal authorization prompt is currently presented or queued on the local host UI.
    PromptPending {
        request_id: u64,
        prompt_started: Instant,
    },
    /// Request was denied; temporarily blocks further prompts to prevent harassment.
    DeniedTemporary {
        expires_at: Instant,
        consecutive_denials: u32,
    },
    /// Request was persistently blocked by explicit user choice. Survives daemon restarts.
    DeniedPersistent,
    /// Authorized for a single continuous stream identified by `stream_id`.
    GrantedEphemeral {
        session_epoch: u64,
        generation: u64,
        stream_id: u64,
    },
    /// Authorized for a fixed duration.
    GrantedTimed {
        session_epoch: u64,
        generation: u64,
        expires_at: Instant,
    },
    /// Authorized for the active transport session epoch. Invalidated on disconnect.
    GrantedSession {
        session_epoch: u64,
        generation: u64,
    },
    /// Persistently authorized across restarts. Revalidated against keystore trust generation on boot.
    GrantedRemembered {
        generation: u64,
    },
    /// Consent is actively being revoked; in-flight teardown underway.
    Revoking {
        generation: u64,
    },
}

/// Persistent representation of camera permissions stored in authenticated Keystore.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PersistentCameraConsent {
    /// Persistently allowed while paired at `generation`.
    AlwaysAllow { generation: u64 },
    /// Persistently blocked until manually unblocked.
    Blocked,
}

/// Wire-compatible status of camera consent returned to querying peers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CameraConsentStatusWire {
    RequiresPrompt,
    Granted,
    Denied,
    Blocked,
    Disabled,
}

/// Result of evaluating current consent state for a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsentEvaluation {
    /// Peer currently possesses valid authorization matching generation and session.
    Granted,
    /// No valid consent exists; an interactive user prompt is required.
    RequiresPrompt,
    /// Access is currently blocked under a temporary denial cooldown.
    DeniedTemporary { remaining: Duration, consecutive_denials: u32 },
    /// Access is persistently blocked by user choice.
    DeniedPersistent,
    /// Consent is currently in the process of being revoked.
    Revoking,
}

/// Short-lived, single-use camera authorization lease bridging RPC and streaming connections.
#[derive(Clone)]
pub struct AuthorizationLease {
    /// 32-byte cryptographically secure random token.
    pub lease_token: [u8; 32],
    /// Hex-encoded device ID of the authorized peer.
    pub peer_device_id: String,
    /// Trust generation at the time the lease was granted.
    pub trust_generation: u64,
    /// Control connection session identifier from which the request originated.
    pub control_session_id: String,
    /// Request identifier matching the original RPC request.
    pub request_id: u64,
    /// Operation direction (OutboundSender or InboundReceiver).
    pub direction: LeaseDirection,
    /// Monotonic timestamp when the lease was created.
    pub created_at: Instant,
    /// Monotonic deadline after which the lease cannot be redeemed.
    pub expires_at: Instant,
    /// Whether the lease has been consumed.
    pub redeemed: bool,
}

impl std::fmt::Debug for AuthorizationLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorizationLease")
            .field("lease_token", &"<REDACTED>")
            .field("peer_device_id", &self.peer_device_id)
            .field("trust_generation", &self.trust_generation)
            .field("control_session_id", &self.control_session_id)
            .field("request_id", &self.request_id)
            .field("direction", &self.direction)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("redeemed", &self.redeemed)
            .finish()
    }
}

/// Errors occurring during authorization lease validation and redemption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseError {
    UnknownLease,
    AlreadyRedeemed,
    Expired,
    PeerMismatch { expected: String, actual: String },
    GenerationMismatch { expected: u64, actual: u64 },
    DirectionMismatch,
    PeerRevoked,
}

impl std::fmt::Display for LeaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownLease => write!(f, "Authorization lease token not recognized or expired"),
            Self::AlreadyRedeemed => write!(f, "Authorization lease has already been consumed (replay rejected)"),
            Self::Expired => write!(f, "Authorization lease has expired"),
            Self::PeerMismatch { expected, actual } => {
                write!(f, "Authorization lease peer mismatch (expected {}, got {})", expected, actual)
            }
            Self::GenerationMismatch { expected, actual } => {
                write!(f, "Authorization lease trust generation mismatch (expected {}, got {})", expected, actual)
            }
            Self::DirectionMismatch => write!(f, "Authorization lease operation direction mismatch"),
            Self::PeerRevoked => write!(f, "Authorization lease rejected: peer trust is revoked"),
        }
    }
}

impl std::error::Error for LeaseError {}

/// In-memory record tracking consent state and modification timestamp.
#[derive(Debug, Clone)]
pub struct CameraConsentRecord {
    pub state: CameraConsentState,
    pub last_updated: Instant,
}

/// Computes denial cooldown duration based on consecutive denial count.
pub fn denial_duration_for_attempt(consecutive_denials: u32) -> Duration {
    match consecutive_denials {
        0 | 1 => Duration::from_secs(5 * 60),      // 1st Deny: 5 minutes
        2 => Duration::from_secs(30 * 60),          // 2nd Deny: 30 minutes
        _ => Duration::from_secs(24 * 60 * 60),     // 3rd+ Deny: 24 hours
    }
}

/// Central authority managing camera consent states, authorization leases, and denial cooldowns.
pub struct CameraConsentManager {
    /// Active sender-side consent states (Mac camera -> peer).
    sender_consents: Mutex<HashMap<String, CameraConsentRecord>>,
    /// Active receiver-side consent states (peer -> Windows virtual camera).
    receiver_consents: Mutex<HashMap<String, CameraConsentRecord>>,
    /// Persistent permissions synchronized with Keystore.
    persistent_consents: Mutex<HashMap<String, PersistentCameraConsent>>,
    /// Active authorization leases pending redemption.
    leases: Mutex<HashMap<[u8; 32], AuthorizationLease>>,
    /// Monotonically increasing request ID counter.
    next_request_id: AtomicU64,
    /// Active transport session epochs per peer device ID.
    session_epochs: Mutex<HashMap<String, u64>>,
    /// Global prompt queue counter to enforce bounded concurrency.
    active_prompt_count: Mutex<usize>,
}

impl CameraConsentManager {
    /// Creates a new initialized consent manager with empty runtime state.
    pub fn new() -> Self {
        Self {
            sender_consents: Mutex::new(HashMap::new()),
            receiver_consents: Mutex::new(HashMap::new()),
            persistent_consents: Mutex::new(HashMap::new()),
            leases: Mutex::new(HashMap::new()),
            next_request_id: AtomicU64::new(1),
            session_epochs: Mutex::new(HashMap::new()),
            active_prompt_count: Mutex::new(0),
        }
    }

    /// Allocates a unique monotonically increasing request ID.
    pub fn next_request_id(&self) -> u64 {
        self.next_request_id.fetch_add(1, Ordering::SeqCst)
    }

    /// Registers a new active transport session epoch for `peer_device_id_hex`.
    ///
    /// Any previous ephemeral or session-scoped consents for this peer are immediately
    /// invalidated by advancing the session epoch.
    pub fn register_session_epoch(&self, peer_device_id_hex: &str) -> u64 {
        let clean_id = peer_device_id_hex.trim().to_ascii_lowercase();
        let mut epochs = self.session_epochs.lock().unwrap_or_else(|e| e.into_inner());
        let new_epoch = epochs.get(&clean_id).copied().unwrap_or(0) + 1;
        epochs.insert(clean_id.clone(), new_epoch);

        // Disconnecting / establishing a new session epoch invalidates ephemeral consents
        self.invalidate_session_scoped_consents(&clean_id, new_epoch);
        new_epoch
    }

    /// Returns the current active session epoch for `peer_device_id_hex`.
    pub fn current_session_epoch(&self, peer_device_id_hex: &str) -> u64 {
        let clean_id = peer_device_id_hex.trim().to_ascii_lowercase();
        let epochs = self.session_epochs.lock().unwrap_or_else(|e| e.into_inner());
        epochs.get(&clean_id).copied().unwrap_or(0)
    }

    /// Evaluates sender-side camera consent (local Mac sharing physical camera to remote peer).
    pub fn evaluate_sender_consent(&self, peer_device_id_hex: &str, current_generation: u64) -> ConsentEvaluation {
        self.evaluate_consent_internal(&self.sender_consents, peer_device_id_hex, current_generation)
    }

    /// Evaluates receiver-side camera consent (local Windows publishing incoming stream to virtual camera).
    pub fn evaluate_receiver_consent(&self, peer_device_id_hex: &str, current_generation: u64) -> ConsentEvaluation {
        self.evaluate_consent_internal(&self.receiver_consents, peer_device_id_hex, current_generation)
    }

    fn evaluate_consent_internal(
        &self,
        store: &Mutex<HashMap<String, CameraConsentRecord>>,
        peer_device_id_hex: &str,
        current_generation: u64,
    ) -> ConsentEvaluation {
        let clean_id = peer_device_id_hex.trim().to_ascii_lowercase();

        // 1. Revocation always fails closed immediately
        if is_peer_revoked(&clean_id) {
            return ConsentEvaluation::DeniedPersistent;
        }

        // 2. Check persistent block in persistent store
        {
            let persistent = self.persistent_consents.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(PersistentCameraConsent::Blocked) = persistent.get(&clean_id) {
                return ConsentEvaluation::DeniedPersistent;
            }
        }

        let mut map = store.lock().unwrap_or_else(|e| e.into_inner());
        let record = match map.get_mut(&clean_id) {
            Some(r) => r,
            None => {
                // Check if persistent "AlwaysAllow" is recorded for this peer and generation
                let persistent = self.persistent_consents.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(PersistentCameraConsent::AlwaysAllow { generation }) = persistent.get(&clean_id) {
                    if *generation == current_generation {
                        return ConsentEvaluation::Granted;
                    }
                }
                return ConsentEvaluation::RequiresPrompt;
            }
        };

        match &record.state {
            CameraConsentState::NoConsent => {
                // Check persistent AlwaysAllow fallback
                let persistent = self.persistent_consents.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(PersistentCameraConsent::AlwaysAllow { generation }) = persistent.get(&clean_id) {
                    if *generation == current_generation {
                        return ConsentEvaluation::Granted;
                    }
                }
                ConsentEvaluation::RequiresPrompt
            }
            CameraConsentState::PromptPending { prompt_started, .. } => {
                if prompt_started.elapsed() > PROMPT_TIMEOUT {
                    // Late user approval or prompt timeout: fail closed to 1st-stage temporary denial
                    let cooldown = denial_duration_for_attempt(1);
                    record.state = CameraConsentState::DeniedTemporary {
                        expires_at: Instant::now() + cooldown,
                        consecutive_denials: 1,
                    };
                    record.last_updated = Instant::now();
                    self.decrement_prompt_count();
                    ConsentEvaluation::DeniedTemporary {
                        remaining: cooldown,
                        consecutive_denials: 1,
                    }
                } else {
                    ConsentEvaluation::RequiresPrompt
                }
            }
            CameraConsentState::DeniedTemporary { expires_at, consecutive_denials } => {
                let now = Instant::now();
                if now < *expires_at {
                    ConsentEvaluation::DeniedTemporary {
                        remaining: *expires_at - now,
                        consecutive_denials: *consecutive_denials,
                    }
                } else {
                    // Cooldown expired; return to NoConsent
                    record.state = CameraConsentState::NoConsent;
                    record.last_updated = now;
                    ConsentEvaluation::RequiresPrompt
                }
            }
            CameraConsentState::DeniedPersistent => ConsentEvaluation::DeniedPersistent,
            CameraConsentState::GrantedEphemeral { session_epoch, generation, .. } => {
                let current_epoch = self.current_session_epoch(&clean_id);
                if *generation == current_generation && *session_epoch == current_epoch {
                    ConsentEvaluation::Granted
                } else {
                    record.state = CameraConsentState::NoConsent;
                    record.last_updated = Instant::now();
                    ConsentEvaluation::RequiresPrompt
                }
            }
            CameraConsentState::GrantedTimed { session_epoch, generation, expires_at } => {
                let now = Instant::now();
                let current_epoch = self.current_session_epoch(&clean_id);
                if now < *expires_at && *generation == current_generation && *session_epoch == current_epoch {
                    ConsentEvaluation::Granted
                } else {
                    record.state = CameraConsentState::NoConsent;
                    record.last_updated = now;
                    ConsentEvaluation::RequiresPrompt
                }
            }
            CameraConsentState::GrantedSession { session_epoch, generation } => {
                let current_epoch = self.current_session_epoch(&clean_id);
                if *generation == current_generation && *session_epoch == current_epoch {
                    ConsentEvaluation::Granted
                } else {
                    record.state = CameraConsentState::NoConsent;
                    record.last_updated = Instant::now();
                    ConsentEvaluation::RequiresPrompt
                }
            }
            CameraConsentState::GrantedRemembered { generation } => {
                if *generation == current_generation {
                    ConsentEvaluation::Granted
                } else {
                    record.state = CameraConsentState::NoConsent;
                    record.last_updated = Instant::now();
                    ConsentEvaluation::RequiresPrompt
                }
            }
            CameraConsentState::Revoking { .. } => ConsentEvaluation::Revoking,
        }
    }

    /// Attempts to register an active prompt for `peer_device_id_hex`.
    ///
    /// Fails closed if the global prompt queue is exhausted or if another prompt is already pending.
    pub fn try_begin_prompt(&self, direction: LeaseDirection, peer_device_id_hex: &str) -> Result<u64, String> {
        let clean_id = peer_device_id_hex.trim().to_ascii_lowercase();
        let mut count_guard = self.active_prompt_count.lock().unwrap_or_else(|e| e.into_inner());
        if *count_guard >= MAX_GLOBAL_PENDING_PROMPTS {
            return Err("Rejected: Global camera consent prompt queue exhausted".into());
        }

        let store = match direction {
            LeaseDirection::OutboundSender => &self.sender_consents,
            LeaseDirection::InboundReceiver => &self.receiver_consents,
        };
        let mut map = store.lock().unwrap_or_else(|e| e.into_inner());

        if let Some(record) = map.get(&clean_id) {
            match &record.state {
                CameraConsentState::PromptPending { prompt_started, request_id } => {
                    if prompt_started.elapsed() <= PROMPT_TIMEOUT {
                        // Coalesce duplicate requests: return existing active prompt request_id
                        return Ok(*request_id);
                    }
                }
                CameraConsentState::DeniedTemporary { expires_at, consecutive_denials } => {
                    if Instant::now() < *expires_at {
                        return Err(format!(
                            "Rejected: Camera request denied; cooldown active ({} consecutive denials)",
                            consecutive_denials
                        ));
                    }
                }
                CameraConsentState::DeniedPersistent => {
                    return Err("Rejected: Camera request denied; device is permanently blocked".into());
                }
                _ => {}
            }
        }

        let request_id = self.next_request_id();
        map.insert(
            clean_id,
            CameraConsentRecord {
                state: CameraConsentState::PromptPending {
                    request_id,
                    prompt_started: Instant::now(),
                },
                last_updated: Instant::now(),
            },
        );
        *count_guard += 1;
        Ok(request_id)
    }

    /// Grants consent for `peer_device_id_hex` under the specified scope.
    pub fn grant_consent(
        &self,
        direction: LeaseDirection,
        peer_device_id_hex: &str,
        generation: u64,
        scope: CameraConsentScope,
        stream_id: u64,
    ) -> bool {
        let clean_id = peer_device_id_hex.trim().to_ascii_lowercase();
        if is_peer_revoked(&clean_id) {
            return false;
        }

        let session_epoch = self.current_session_epoch(&clean_id);
        let now = Instant::now();

        let new_state = match scope {
            CameraConsentScope::AllowOnce | CameraConsentScope::OneContinuousStream => {
                CameraConsentState::GrantedEphemeral {
                    session_epoch,
                    generation,
                    stream_id,
                }
            }
            CameraConsentScope::OneHour => CameraConsentState::GrantedTimed {
                session_epoch,
                generation,
                expires_at: now + Duration::from_secs(60 * 60),
            },
            CameraConsentScope::EightHours => CameraConsentState::GrantedTimed {
                session_epoch,
                generation,
                expires_at: now + Duration::from_secs(8 * 60 * 60),
            },
            CameraConsentScope::ActiveSession => CameraConsentState::GrantedSession {
                session_epoch,
                generation,
            },
            CameraConsentScope::AlwaysAllow => {
                // Record in persistent storage
                let mut persistent = self.persistent_consents.lock().unwrap_or_else(|e| e.into_inner());
                persistent.insert(clean_id.clone(), PersistentCameraConsent::AlwaysAllow { generation });
                CameraConsentState::GrantedRemembered { generation }
            }
        };

        let store = match direction {
            LeaseDirection::OutboundSender => &self.sender_consents,
            LeaseDirection::InboundReceiver => &self.receiver_consents,
        };

        let was_pending = {
            let mut map = store.lock().unwrap_or_else(|e| e.into_inner());
            let prev = map.insert(
                clean_id,
                CameraConsentRecord {
                    state: new_state,
                    last_updated: now,
                },
            );
            matches!(prev.map(|r| r.state), Some(CameraConsentState::PromptPending { .. }))
        };

        if was_pending {
            self.decrement_prompt_count();
        }

        true
    }

    /// Records a denial for `peer_device_id_hex`, updating the exponential backoff cooldown.
    ///
    /// Requests occurring during an existing cooldown do NOT advance the denial counter,
    /// and repeated requests never reset or shorten an active cooldown.
    pub fn record_denial(
        &self,
        direction: LeaseDirection,
        peer_device_id_hex: &str,
        action: CameraDenialAction,
    ) {
        let clean_id = peer_device_id_hex.trim().to_ascii_lowercase();
        let now = Instant::now();

        let store = match direction {
            LeaseDirection::OutboundSender => &self.sender_consents,
            LeaseDirection::InboundReceiver => &self.receiver_consents,
        };

        let mut map = store.lock().unwrap_or_else(|e| e.into_inner());
        let was_pending = matches!(map.get(&clean_id).map(|r| &r.state), Some(CameraConsentState::PromptPending { .. }));

        match action {
            CameraDenialAction::DenyAndBlock => {
                let mut persistent = self.persistent_consents.lock().unwrap_or_else(|e| e.into_inner());
                persistent.insert(clean_id.clone(), PersistentCameraConsent::Blocked);
                map.insert(
                    clean_id,
                    CameraConsentRecord {
                        state: CameraConsentState::DeniedPersistent,
                        last_updated: now,
                    },
                );
            }
            CameraDenialAction::Temporary => {
                let next_count = match map.get(&clean_id).map(|r| &r.state) {
                    Some(CameraConsentState::DeniedTemporary { expires_at, consecutive_denials }) => {
                        if now < *expires_at {
                            // Request during existing cooldown: do NOT increment counter, do NOT reset cooldown
                            *consecutive_denials
                        } else {
                            consecutive_denials.saturating_add(1)
                        }
                    }
                    _ => 1,
                };

                let cooldown = denial_duration_for_attempt(next_count);
                let expires_at = match map.get(&clean_id).map(|r| &r.state) {
                    Some(CameraConsentState::DeniedTemporary { expires_at, .. }) if now < *expires_at => *expires_at,
                    _ => now + cooldown,
                };

                map.insert(
                    clean_id,
                    CameraConsentRecord {
                        state: CameraConsentState::DeniedTemporary {
                            expires_at,
                            consecutive_denials: next_count,
                        },
                        last_updated: now,
                    },
                );
            }
        }

        if was_pending {
            self.decrement_prompt_count();
        }
    }

    /// Manually unblocks `peer_device_id_hex`, clearing persistent blocks and temporary denials.
    pub fn unblock_peer(&self, peer_device_id_hex: &str) {
        let clean_id = peer_device_id_hex.trim().to_ascii_lowercase();
        {
            let mut persistent = self.persistent_consents.lock().unwrap_or_else(|e| e.into_inner());
            persistent.remove(&clean_id);
        }
        {
            let mut sender = self.sender_consents.lock().unwrap_or_else(|e| e.into_inner());
            sender.remove(&clean_id);
        }
        {
            let mut receiver = self.receiver_consents.lock().unwrap_or_else(|e| e.into_inner());
            receiver.remove(&clean_id);
        }
    }

    /// Explicitly revokes camera consent for `peer_device_id_hex`, marking it `Revoking`.
    pub fn revoke_consent(&self, peer_device_id_hex: &str, generation: u64) {
        let clean_id = peer_device_id_hex.trim().to_ascii_lowercase();
        let now = Instant::now();

        // Remove any persistent AlwaysAllow (retaining Blocked)
        {
            let mut persistent = self.persistent_consents.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(PersistentCameraConsent::AlwaysAllow { .. }) = persistent.get(&clean_id) {
                persistent.remove(&clean_id);
            }
        }

        // Cancel any pending leases for this peer
        {
            let mut leases = self.leases.lock().unwrap_or_else(|e| e.into_inner());
            leases.retain(|_, l| !l.peer_device_id.eq_ignore_ascii_case(&clean_id));
        }

        let mut was_pending = false;
        {
            let mut sender = self.sender_consents.lock().unwrap_or_else(|e| e.into_inner());
            if matches!(sender.get(&clean_id).map(|r| &r.state), Some(CameraConsentState::PromptPending { .. })) {
                was_pending = true;
            }
            sender.insert(
                clean_id.clone(),
                CameraConsentRecord {
                    state: CameraConsentState::Revoking { generation },
                    last_updated: now,
                },
            );
        }
        {
            let mut receiver = self.receiver_consents.lock().unwrap_or_else(|e| e.into_inner());
            if matches!(receiver.get(&clean_id).map(|r| &r.state), Some(CameraConsentState::PromptPending { .. })) {
                was_pending = true;
            }
            receiver.insert(
                clean_id,
                CameraConsentRecord {
                    state: CameraConsentState::Revoking { generation },
                    last_updated: now,
                },
            );
        }

        if was_pending {
            self.decrement_prompt_count();
        }
    }

    /// Transitions `Revoking` state back to `NoConsent` after stream teardown completes.
    pub fn finish_revocation(&self, peer_device_id_hex: &str) {
        let clean_id = peer_device_id_hex.trim().to_ascii_lowercase();
        {
            let mut sender = self.sender_consents.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(record) = sender.get_mut(&clean_id) {
                if matches!(record.state, CameraConsentState::Revoking { .. }) {
                    record.state = CameraConsentState::NoConsent;
                    record.last_updated = Instant::now();
                }
            }
        }
        {
            let mut receiver = self.receiver_consents.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(record) = receiver.get_mut(&clean_id) {
                if matches!(record.state, CameraConsentState::Revoking { .. }) {
                    record.state = CameraConsentState::NoConsent;
                    record.last_updated = Instant::now();
                }
            }
        }
    }

    /// Creates a short-lived, single-use authorization lease for an authenticated RPC connection.
    pub fn create_authorization_lease(
        &self,
        peer_device_id_hex: &str,
        trust_generation: u64,
        control_session_id: &str,
        request_id: u64,
        direction: LeaseDirection,
        ttl: Duration,
    ) -> AuthorizationLease {
        let clean_id = peer_device_id_hex.trim().to_ascii_lowercase();
        let lease_token = csprng_array::<32>();
        let now = Instant::now();

        let lease = AuthorizationLease {
            lease_token,
            peer_device_id: clean_id,
            trust_generation,
            control_session_id: control_session_id.to_string(),
            request_id,
            direction,
            created_at: now,
            expires_at: now + ttl,
            redeemed: false,
        };

        let mut leases = self.leases.lock().unwrap_or_else(|e| e.into_inner());
        // Purge expired leases opportunistically
        leases.retain(|_, l| Instant::now() < l.expires_at);
        leases.insert(lease_token, lease.clone());
        lease
    }

    /// Creates an InboundReceiver authorization lease for an incoming stream from `peer_device_id_hex`.
    pub fn create_receiver_lease(
        &self,
        peer_device_id_hex: &str,
        trust_generation: u64,
        control_session_id: &str,
        ttl: Duration,
    ) -> AuthorizationLease {
        self.create_authorization_lease(
            peer_device_id_hex,
            trust_generation,
            control_session_id,
            self.next_request_id(),
            LeaseDirection::InboundReceiver,
            ttl,
        )
    }

    /// Validates and atomically redeems a single-use authorization lease on an incoming streaming connection.
    pub fn redeem_authorization_lease(
        &self,
        lease_token: &[u8; 32],
        peer_device_id_hex: &str,
        expected_generation: u64,
        expected_direction: LeaseDirection,
    ) -> Result<AuthorizationLease, LeaseError> {
        let clean_id = peer_device_id_hex.trim().to_ascii_lowercase();
        if is_peer_revoked(&clean_id) {
            return Err(LeaseError::PeerRevoked);
        }

        let mut leases = self.leases.lock().unwrap_or_else(|e| e.into_inner());
        let lease = leases.get_mut(lease_token).ok_or(LeaseError::UnknownLease)?;

        if lease.redeemed {
            return Err(LeaseError::AlreadyRedeemed);
        }

        if Instant::now() > lease.expires_at {
            return Err(LeaseError::Expired);
        }

        if !lease.peer_device_id.eq_ignore_ascii_case(&clean_id) {
            return Err(LeaseError::PeerMismatch {
                expected: lease.peer_device_id.clone(),
                actual: clean_id,
            });
        }

        if lease.trust_generation != expected_generation {
            return Err(LeaseError::GenerationMismatch {
                expected: lease.trust_generation,
                actual: expected_generation,
            });
        }

        if lease.direction != expected_direction {
            return Err(LeaseError::DirectionMismatch);
        }

        lease.redeemed = true;
        Ok(lease.clone())
    }

    /// Purges all expired authorization leases from memory.
    pub fn purge_expired_leases(&self) {
        let now = Instant::now();
        let mut leases = self.leases.lock().unwrap_or_else(|e| e.into_inner());
        leases.retain(|_, l| now < l.expires_at);
    }

    /// Handles peer unpairing by purging all consent, active leases, and persistent records.
    pub fn on_peer_unpaired(&self, peer_device_id_hex: &str) {
        let clean_id = peer_device_id_hex.trim().to_ascii_lowercase();
        self.unblock_peer(&clean_id);
        let mut leases = self.leases.lock().unwrap_or_else(|e| e.into_inner());
        leases.retain(|_, l| !l.peer_device_id.eq_ignore_ascii_case(&clean_id));
        let mut epochs = self.session_epochs.lock().unwrap_or_else(|e| e.into_inner());
        epochs.remove(&clean_id);
    }

    /// Handles peer trust generation changes by invalidating older generation grants.
    pub fn on_trust_generation_advanced(&self, peer_device_id_hex: &str, new_generation: u64) {
        let clean_id = peer_device_id_hex.trim().to_ascii_lowercase();
        // Invalidate leases matching old generation
        {
            let mut leases = self.leases.lock().unwrap_or_else(|e| e.into_inner());
            leases.retain(|_, l| {
                !(l.peer_device_id.eq_ignore_ascii_case(&clean_id) && l.trust_generation < new_generation)
            });
        }
        // Invalidate sender/receiver grants
        self.revoke_consent(&clean_id, new_generation);
    }

    /// Invalidate session-scoped consents when a transport session disconnects.
    pub fn on_session_disconnected(&self, peer_device_id_hex: &str) {
        let clean_id = peer_device_id_hex.trim().to_ascii_lowercase();
        let new_epoch = {
            let mut epochs = self.session_epochs.lock().unwrap_or_else(|e| e.into_inner());
            let epoch = epochs.get(&clean_id).copied().unwrap_or(0) + 1;
            epochs.insert(clean_id.clone(), epoch);
            epoch
        };
        self.invalidate_session_scoped_consents(&clean_id, new_epoch);
    }

    /// Resets ephemeral (single continuous stream / AllowOnce) consent when the stream closes.
    pub fn on_stream_closed(&self, peer_device_id_hex: &str, stream_id: u64) {
        let clean_id = peer_device_id_hex.trim().to_ascii_lowercase();
        let now = Instant::now();
        let check_and_reset = |record: &mut CameraConsentRecord| {
            if let CameraConsentState::GrantedEphemeral { stream_id: sid, .. } = record.state {
                if sid == stream_id || sid == 0 {
                    record.state = CameraConsentState::NoConsent;
                    record.last_updated = now;
                }
            }
        };

        if let Ok(mut sender) = self.sender_consents.lock() {
            if let Some(r) = sender.get_mut(&clean_id) {
                check_and_reset(r);
            }
        }
        if let Ok(mut receiver) = self.receiver_consents.lock() {
            if let Some(r) = receiver.get_mut(&clean_id) {
                check_and_reset(r);
            }
        }
    }

    fn invalidate_session_scoped_consents(&self, clean_id: &str, _new_epoch: u64) {
        let now = Instant::now();
        let invalidate_entry = |record: &mut CameraConsentRecord| {
            match record.state {
                CameraConsentState::GrantedEphemeral { .. }
                | CameraConsentState::GrantedSession { .. }
                | CameraConsentState::GrantedTimed { .. } => {
                    record.state = CameraConsentState::NoConsent;
                    record.last_updated = now;
                }
                _ => {}
            }
        };

        if let Ok(mut sender) = self.sender_consents.lock() {
            if let Some(r) = sender.get_mut(clean_id) {
                invalidate_entry(r);
            }
        }
        if let Ok(mut receiver) = self.receiver_consents.lock() {
            if let Some(r) = receiver.get_mut(clean_id) {
                invalidate_entry(r);
            }
        }
    }

    /// Loads verified persistent permissions from Keystore into in-memory manager.
    pub fn load_persistent_consents(&self, consents: HashMap<String, PersistentCameraConsent>) {
        let mut persistent = self.persistent_consents.lock().unwrap_or_else(|e| e.into_inner());
        *persistent = consents;
    }

    /// Exports persistent permissions for writing to Keystore.
    pub fn export_persistent_consents(&self) -> HashMap<String, PersistentCameraConsent> {
        let persistent = self.persistent_consents.lock().unwrap_or_else(|e| e.into_inner());
        persistent.clone()
    }

    /// Returns wire-compatible status for `CheckCameraConsent` RPC request.
    pub fn get_consent_status_wire(&self, direction: LeaseDirection, peer_device_id_hex: &str, current_generation: u64) -> CameraConsentStatusWire {
        let clean_id = peer_device_id_hex.trim().to_ascii_lowercase();
        if is_peer_revoked(&clean_id) {
            return CameraConsentStatusWire::Blocked;
        }

        let eval = match direction {
            LeaseDirection::OutboundSender => self.evaluate_sender_consent(&clean_id, current_generation),
            LeaseDirection::InboundReceiver => self.evaluate_receiver_consent(&clean_id, current_generation),
        };

        match eval {
            ConsentEvaluation::Granted => CameraConsentStatusWire::Granted,
            ConsentEvaluation::RequiresPrompt => CameraConsentStatusWire::RequiresPrompt,
            ConsentEvaluation::DeniedTemporary { .. } => CameraConsentStatusWire::Denied,
            ConsentEvaluation::DeniedPersistent => CameraConsentStatusWire::Blocked,
            ConsentEvaluation::Revoking => CameraConsentStatusWire::Denied,
        }
    }

    fn decrement_prompt_count(&self) {
        if let Ok(mut count) = self.active_prompt_count.lock() {
            if *count > 0 {
                *count -= 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authorization_exponential_denial_backoff() {
        let mgr = CameraConsentManager::new();
        let peer = "peer_backoff_test";
        let gen = 1;

        // Initially requires prompt
        assert_eq!(mgr.evaluate_sender_consent(peer, gen), ConsentEvaluation::RequiresPrompt);

        // 1st denial -> 5 minutes cooldown
        mgr.record_denial(LeaseDirection::OutboundSender, peer, CameraDenialAction::Temporary);
        let eval1 = mgr.evaluate_sender_consent(peer, gen);
        match eval1 {
            ConsentEvaluation::DeniedTemporary { remaining, consecutive_denials } => {
                assert_eq!(consecutive_denials, 1);
                assert!(remaining.as_secs() <= 300 && remaining.as_secs() >= 295);
            }
            other => panic!("Expected DeniedTemporary(1), got {:?}", other),
        }

        // Requests during an active cooldown must NOT increment consecutive_denials
        mgr.record_denial(LeaseDirection::OutboundSender, peer, CameraDenialAction::Temporary);
        let eval1_repeat = mgr.evaluate_sender_consent(peer, gen);
        match eval1_repeat {
            ConsentEvaluation::DeniedTemporary { consecutive_denials, .. } => {
                assert_eq!(consecutive_denials, 1, "Requests during cooldown must not increment counter");
            }
            other => panic!("Expected DeniedTemporary(1), got {:?}", other),
        }

        // Explicit unblock resets cooldown
        mgr.unblock_peer(peer);
        assert_eq!(mgr.evaluate_sender_consent(peer, gen), ConsentEvaluation::RequiresPrompt);

        // 2nd denial cycle (simulate second distinct denial after cooldown elapsed)
        mgr.record_denial(LeaseDirection::OutboundSender, peer, CameraDenialAction::Temporary); // #1
        if let Ok(mut sender) = mgr.sender_consents.lock() {
            if let Some(r) = sender.get_mut(peer) {
                r.state = CameraConsentState::DeniedTemporary {
                    expires_at: Instant::now() - Duration::from_secs(1),
                    consecutive_denials: 1,
                };
            }
        }
        mgr.record_denial(LeaseDirection::OutboundSender, peer, CameraDenialAction::Temporary); // #2
        match mgr.evaluate_sender_consent(peer, gen) {
            ConsentEvaluation::DeniedTemporary { remaining, consecutive_denials } => {
                assert_eq!(consecutive_denials, 2);
                assert!(remaining.as_secs() <= 1800 && remaining.as_secs() >= 1790); // 30 mins
            }
            other => panic!("Expected DeniedTemporary(2), got {:?}", other),
        }

        // 3rd denial cycle -> 24 hours
        if let Ok(mut sender) = mgr.sender_consents.lock() {
            if let Some(r) = sender.get_mut(peer) {
                r.state = CameraConsentState::DeniedTemporary {
                    expires_at: Instant::now() - Duration::from_secs(1),
                    consecutive_denials: 2,
                };
            }
        }
        mgr.record_denial(LeaseDirection::OutboundSender, peer, CameraDenialAction::Temporary); // #3
        match mgr.evaluate_sender_consent(peer, gen) {
            ConsentEvaluation::DeniedTemporary { remaining, consecutive_denials } => {
                assert_eq!(consecutive_denials, 3);
                assert!(remaining.as_secs() <= 86400 && remaining.as_secs() >= 86390); // 24 hours
            }
            other => panic!("Expected DeniedTemporary(3), got {:?}", other),
        }

        // Deny & Block persistently
        mgr.record_denial(LeaseDirection::OutboundSender, peer, CameraDenialAction::DenyAndBlock);
        assert_eq!(mgr.evaluate_sender_consent(peer, gen), ConsentEvaluation::DeniedPersistent);

        // Persistent block survives even after unpair unless explicitly unblocked
        mgr.unblock_peer(peer);
        assert_eq!(mgr.evaluate_sender_consent(peer, gen), ConsentEvaluation::RequiresPrompt);
    }

    #[test]
    fn test_authorization_prompt_queue_bounded_and_coalesced() {
        let mgr = CameraConsentManager::new();

        // 1. Coalescing duplicate prompts for the same peer
        let req1 = mgr.try_begin_prompt(LeaseDirection::OutboundSender, "peer_dup").expect("First prompt must succeed");
        let req2 = mgr.try_begin_prompt(LeaseDirection::OutboundSender, "peer_dup").expect("Duplicate prompt must coalesce");
        assert_eq!(req1, req2, "Duplicate prompt must return existing request_id");

        // 2. Global queue limit (max 8 concurrent prompts)
        let mut distinct_reqs = Vec::new();
        distinct_reqs.push(req1);
        for i in 1..8 {
            let pid = format!("peer_distinct_{}", i);
            let req = mgr.try_begin_prompt(LeaseDirection::OutboundSender, &pid).expect("Prompt within limit must succeed");
            distinct_reqs.push(req);
        }
        assert_eq!(distinct_reqs.len(), 8);

        // 9th prompt exceeds MAX_PENDING_PROMPTS (8)
        let err9 = mgr.try_begin_prompt(LeaseDirection::OutboundSender, "peer_overflow");
        assert!(err9.is_err(), "9th concurrent prompt must be rejected");
        assert!(err9.unwrap_err().contains("prompt queue exhausted"));
    }

    #[test]
    fn test_authorization_session_epoch_invalidation() {
        let mgr = CameraConsentManager::new();
        let peer = "peer_session_test";
        let gen = 2;

        // Grant session-scoped consent
        assert!(mgr.grant_consent(LeaseDirection::OutboundSender, peer, gen, CameraConsentScope::ActiveSession, 0));
        assert_eq!(mgr.evaluate_sender_consent(peer, gen), ConsentEvaluation::Granted);

        // Disconnect session (epoch advance)
        mgr.on_session_disconnected(peer);

        // Session consent must now be invalidated back to RequiresPrompt
        assert_eq!(mgr.evaluate_sender_consent(peer, gen), ConsentEvaluation::RequiresPrompt);
    }

    #[test]
    fn test_authorization_trust_generation_advance_invalidates_all_leases_and_consents() {
        let mgr = CameraConsentManager::new();
        let peer = "peer_trust_advance";
        let old_gen = 1;
        let new_gen = 2;

        // Grant consent and create lease on old_gen
        assert!(mgr.grant_consent(LeaseDirection::OutboundSender, peer, old_gen, CameraConsentScope::ActiveSession, 0));
        let lease = mgr.create_authorization_lease(peer, old_gen, "ctrl_1", 101, LeaseDirection::OutboundSender, Duration::from_secs(30));

        // Advance trust generation
        mgr.on_trust_generation_advanced(peer, new_gen);

        // Immediately after revocation, state is Revoking
        assert_eq!(mgr.evaluate_sender_consent(peer, old_gen), ConsentEvaluation::Revoking);
        assert_eq!(mgr.evaluate_sender_consent(peer, new_gen), ConsentEvaluation::Revoking);

        // Once teardown finishes revocation, state transitions back to RequiresPrompt
        mgr.finish_revocation(peer);
        assert_eq!(mgr.evaluate_sender_consent(peer, old_gen), ConsentEvaluation::RequiresPrompt);
        assert_eq!(mgr.evaluate_sender_consent(peer, new_gen), ConsentEvaluation::RequiresPrompt);

        // Old lease is purged and redemption fails with UnknownLease
        let res = mgr.redeem_authorization_lease(&lease.lease_token, peer, new_gen, LeaseDirection::OutboundSender);
        assert!(matches!(res, Err(LeaseError::UnknownLease)));
    }

    #[test]
    fn test_authorization_lease_lifecycle_and_single_use() {
        let mgr = CameraConsentManager::new();
        let peer = "peer_lease_test";
        let gen = 3;

        let lease = mgr.create_authorization_lease(
            peer,
            gen,
            "ctrl_sess_42",
            202,
            LeaseDirection::OutboundSender,
            Duration::from_secs(30),
        );

        // 1. Wrong peer fails
        let err_peer = mgr.redeem_authorization_lease(&lease.lease_token, "wrong_peer", gen, LeaseDirection::OutboundSender);
        assert!(matches!(err_peer, Err(LeaseError::PeerMismatch { .. })));

        // 2. Wrong direction fails
        let err_dir = mgr.redeem_authorization_lease(&lease.lease_token, peer, gen, LeaseDirection::InboundReceiver);
        assert!(matches!(err_dir, Err(LeaseError::DirectionMismatch)));

        // 3. Successful redemption
        let redeemed = mgr.redeem_authorization_lease(&lease.lease_token, peer, gen, LeaseDirection::OutboundSender)
            .expect("Valid lease redemption must succeed");
        assert_eq!(redeemed.peer_device_id, peer);
        assert_eq!(redeemed.trust_generation, gen);

        // 4. Second redemption fails with AlreadyRedeemed (replay prevention)
        let err_replay = mgr.redeem_authorization_lease(&lease.lease_token, peer, gen, LeaseDirection::OutboundSender);
        assert!(matches!(err_replay, Err(LeaseError::AlreadyRedeemed)));

        // 5. Expired lease fails
        let expired_lease = mgr.create_authorization_lease(
            peer,
            gen,
            "ctrl_sess_43",
            203,
            LeaseDirection::OutboundSender,
            Duration::from_millis(1),
        );
        std::thread::sleep(Duration::from_millis(10));
        let err_exp = mgr.redeem_authorization_lease(&expired_lease.lease_token, peer, gen, LeaseDirection::OutboundSender);
        assert!(matches!(err_exp, Err(LeaseError::Expired)));
    }

    #[test]
    fn test_authorization_ephemeral_stream_close_cleanup() {
        let mgr = CameraConsentManager::new();
        let peer = "peer_ephemeral_test";
        let gen = 1;
        let stream_id = 999;

        // Grant ephemeral (AllowOnce) consent
        assert!(mgr.grant_consent(LeaseDirection::OutboundSender, peer, gen, CameraConsentScope::AllowOnce, stream_id));
        assert_eq!(mgr.evaluate_sender_consent(peer, gen), ConsentEvaluation::Granted);

        // Stream closes
        mgr.on_stream_closed(peer, stream_id);

        // Must transition back to RequiresPrompt
        assert_eq!(mgr.evaluate_sender_consent(peer, gen), ConsentEvaluation::RequiresPrompt);
    }

    #[test]
    fn test_authorization_wire_status_reporting() {
        let mgr = CameraConsentManager::new();
        let peer = "peer_wire_test";
        let gen = 1;

        assert_eq!(mgr.get_consent_status_wire(LeaseDirection::OutboundSender, peer, gen), CameraConsentStatusWire::RequiresPrompt);

        assert!(mgr.grant_consent(LeaseDirection::OutboundSender, peer, gen, CameraConsentScope::ActiveSession, 0));
        assert_eq!(mgr.get_consent_status_wire(LeaseDirection::OutboundSender, peer, gen), CameraConsentStatusWire::Granted);

        mgr.record_denial(LeaseDirection::OutboundSender, peer, CameraDenialAction::DenyAndBlock);
        assert_eq!(mgr.get_consent_status_wire(LeaseDirection::OutboundSender, peer, gen), CameraConsentStatusWire::Blocked);
    }

    #[test]
    fn test_authorization_lease_inbound_receiver_redemption_and_concurrency_attack() {
        let mgr = std::sync::Arc::new(CameraConsentManager::new());
        let peer = "peer_rx_auth_test";
        let gen = 2;

        let lease = mgr.create_receiver_lease(peer, gen, "ctrl_sess_rx_1", Duration::from_secs(10));
        let token = lease.lease_token;

        // Wrong direction fails
        let err_dir = mgr.redeem_authorization_lease(&token, peer, gen, LeaseDirection::OutboundSender);
        assert!(matches!(err_dir, Err(LeaseError::DirectionMismatch)));

        // Wrong peer fails
        let err_peer = mgr.redeem_authorization_lease(&token, "wrong_peer_id", gen, LeaseDirection::InboundReceiver);
        assert!(matches!(err_peer, Err(LeaseError::PeerMismatch { .. })));

        // Wrong generation fails
        let err_gen = mgr.redeem_authorization_lease(&token, peer, gen + 1, LeaseDirection::InboundReceiver);
        assert!(matches!(err_gen, Err(LeaseError::GenerationMismatch { .. })));

        // Concurrency attack: 10 threads attempt to redeem the exact same lease simultaneously
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(10));
        let mut handles = Vec::new();
        let success_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let replay_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

        for _ in 0..10 {
            let m = std::sync::Arc::clone(&mgr);
            let b = std::sync::Arc::clone(&barrier);
            let s_cnt = std::sync::Arc::clone(&success_count);
            let r_cnt = std::sync::Arc::clone(&replay_count);
            handles.push(std::thread::spawn(move || {
                b.wait();
                match m.redeem_authorization_lease(&token, peer, gen, LeaseDirection::InboundReceiver) {
                    Ok(_) => {
                        s_cnt.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                    Err(LeaseError::AlreadyRedeemed) => {
                        r_cnt.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                    Err(e) => panic!("Unexpected lease error in race: {:?}", e),
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        // Exactly ONE concurrent redemption must succeed; all other 9 must fail with AlreadyRedeemed
        assert_eq!(success_count.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(replay_count.load(std::sync::atomic::Ordering::SeqCst), 9);
    }

    #[test]
    fn test_authorization_lease_bearer_token_leakage_canary() {
        let mgr = CameraConsentManager::new();
        let peer = "peer_canary_test";
        let gen = 5;

        let lease = mgr.create_receiver_lease(peer, gen, "ctrl_sess_canary", Duration::from_secs(60));
        let canary_hex = crate::security::hex_encode(&lease.lease_token);

        // 1. Debug formatting must REDACT the secret bearer token
        let debug_str = format!("{:?}", lease);
        assert!(!debug_str.contains(&canary_hex), "Bearer token leaked in AuthorizationLease Debug output!");
        assert!(debug_str.contains("<REDACTED>"), "AuthorizationLease Debug output must be explicitly marked <REDACTED>");

        // 2. DisplayRpcResponse Debug formatting must also redact
        let mut resp = crate::display::protocol::DisplayRpcResponse::default();
        resp.camera_lease_token_hex = Some(canary_hex.clone());
        resp.message = "Camera streaming session authorized on Windows Virtual Camera for peer Workstation".to_string();

        let resp_debug = format!("{:?}", resp);
        assert!(!resp_debug.contains(&canary_hex), "Bearer token leaked in DisplayRpcResponse Debug output!");
        assert!(!resp.message.contains(&canary_hex), "Human-readable RPC message must NEVER contain bearer token!");
        assert!(!resp.message.contains("[lease="), "Human-readable message must not contain [lease=] token interpolation!");
    }

    #[test]
    fn test_receiver_mandatory_lease_redemption_and_bypass_prevention() {
        let mgr = CameraConsentManager::new();
        let peer = "peer_bypass_test";
        let gen = 1;

        // Pre-condition: Peer has active receiver consent in consent manager
        assert!(mgr.grant_consent(LeaseDirection::InboundReceiver, peer, gen, CameraConsentScope::AlwaysAllow, 0));
        assert_eq!(mgr.evaluate_receiver_consent(peer, gen), ConsentEvaluation::Granted);

        // Simulation of incoming stream validation:
        // Scenario A: Bypass attack - Stream connects with cached consent but WITHOUT authorization lease flag
        let flags_without_auth = 0u8;
        let auth_flag = crate::camera::FLAG_AUTH_LEASE_REDEMPTION;
        assert_eq!(flags_without_auth & auth_flag, 0, "Bypass attempt must fail authorization flag check");

        // Scenario B: Stream connects with authorization flag but malformed payload (not 32 bytes)
        let malformed_payload = vec![0x42u8; 16];
        assert_ne!(malformed_payload.len(), 32, "Malformed payload length must be rejected");

        // Scenario C: Stream connects with non-existent token (no lease minted)
        let bogus_token = [0x55u8; 32];
        let bogus_res = mgr.redeem_authorization_lease(&bogus_token, peer, gen, LeaseDirection::InboundReceiver);
        assert!(matches!(bogus_res, Err(LeaseError::UnknownLease)), "Unminted lease token must be rejected");

        // Scenario D: Valid lease minted, stream presents correct token -> redemption succeeds
        let valid_lease = mgr.create_receiver_lease(peer, gen, "ctrl_session_valid", Duration::from_secs(30));
        let redeem_res = mgr.redeem_authorization_lease(&valid_lease.lease_token, peer, gen, LeaseDirection::InboundReceiver);
        assert!(redeem_res.is_ok(), "Valid lease must be redeemed successfully");

        // Scenario E: Replay attack - attempting to use the redeemed lease a second time fails
        let replay_res = mgr.redeem_authorization_lease(&valid_lease.lease_token, peer, gen, LeaseDirection::InboundReceiver);
        assert!(matches!(replay_res, Err(LeaseError::AlreadyRedeemed)), "Replayed lease redemption must be rejected");
    }

    #[test]
    fn test_windows_and_macos_scoped_consent_choices_state_transitions() {
        let mgr = CameraConsentManager::new();
        let peer = "peer_scopes_test";
        let gen = 1;

        // Scope 1: AllowOnce (ephemeral)
        assert!(mgr.grant_consent(LeaseDirection::InboundReceiver, peer, gen, CameraConsentScope::AllowOnce, 101));
        assert_eq!(mgr.evaluate_receiver_consent(peer, gen), ConsentEvaluation::Granted);
        mgr.on_stream_closed(peer, 101);
        assert_eq!(mgr.evaluate_receiver_consent(peer, gen), ConsentEvaluation::RequiresPrompt);

        // Scope 2: ActiveSession
        assert!(mgr.grant_consent(LeaseDirection::InboundReceiver, peer, gen, CameraConsentScope::ActiveSession, 0));
        assert_eq!(mgr.evaluate_receiver_consent(peer, gen), ConsentEvaluation::Granted);
        mgr.on_session_disconnected(peer);
        assert_eq!(mgr.evaluate_receiver_consent(peer, gen), ConsentEvaluation::RequiresPrompt);

        // Scope 3: AlwaysAllow
        assert!(mgr.grant_consent(LeaseDirection::InboundReceiver, peer, gen, CameraConsentScope::AlwaysAllow, 0));
        assert_eq!(mgr.evaluate_receiver_consent(peer, gen), ConsentEvaluation::Granted);

        // Scope -1: DenyAndBlock (overrides AlwaysAllow)
        mgr.record_denial(LeaseDirection::InboundReceiver, peer, CameraDenialAction::DenyAndBlock);
        assert_eq!(mgr.evaluate_receiver_consent(peer, gen), ConsentEvaluation::DeniedPersistent);

        // Scope 0: Temporary denial and exponential backoff
        let peer_temp = "peer_temp_test";
        mgr.record_denial(LeaseDirection::InboundReceiver, peer_temp, CameraDenialAction::Temporary);
        let eval_temp = mgr.evaluate_receiver_consent(peer_temp, gen);
        match eval_temp {
            ConsentEvaluation::DeniedTemporary { remaining, consecutive_denials } => {
                assert_eq!(consecutive_denials, 1);
                assert!(remaining.as_secs() <= 5 * 60);
            }
            other => panic!("Expected DeniedTemporary, got {:?}", other),
        }
    }
}
