//! # Granular Feature Flags & Capability Configuration Engine (`features.rs`)
//!
//! ## 1. Module Purpose & Scope
//! `features.rs` manages the runtime feature flags and capability master switches for the
//! Integrator engine. It gives users and administrative policies fine-grained control over which
//! workstation fusion subsystems are active (e.g., virtual display, KVM input, clipboard sync,
//! audio bridging, virtual camera, TrueTone color sync).
//!
//! Key responsibilities include:
//! - Persisting feature configuration atomically to `features.json` in the user's application data directory.
//! - Enforcing strict functional dependency invariants (e.g. Universal Clipboard and Drag-and-Drop
//!   depend strictly on Universal Input/KVM being active).
//! - Providing a strict fail-closed security posture: corrupt configuration files or queries for unknown
//!   feature identifiers automatically default to disabled (`false`).
//! - Safeguarding against partial write corruption using atomic temporary file creation, POSIX file
//!   permission restrictions (`0o600`), and atomic filesystem renames (`rename(2)`).
//!
//! ## 2. Architectural Linkages & Dependencies
//! ### Upstream Callers:
//! - `core::IntegratorCore`: Checks feature flags before starting background listeners (e.g. not starting
//!   audio capture if `audio == false`) and when negotiating capabilities with connecting peers.
//! - UI View Models (via `ffi::integrator_core_invoke`): Expose toggle switches to enable/disable features in real time.
//! - `discovery::Beacon`: Advertises enabled capability bitmasks to local network peers.
//!
//! ### Downstream Callees:
//! - `system_info::app_data_dir`: Resolves the OS-specific persistent configuration directory
//!   (`~/.usbc_clipboard_cache` by default via `config::APP_DATA_DIR_NAME`).
//! - Local Filesystem (`std::fs`): Writes and renames JSON files atomically.
//!
//! ### Cross-Platform / Cross-Device Flow:
//! When two Integrator nodes connect (macOS ↔ Windows 11), each node advertises its active `FeatureFlags`.
//! Subsystems only establish data streams if BOTH local and remote nodes have enabled the corresponding feature.
//! Toggling a feature locally immediately halts the active stream and notifies the peer. Note that at the
//! `IntegratorCore` orchestration layer (`core.rs`), enabling Extended Screen (`display`) and Universal
//! Input/KVM (`input_kvm`) are mutually exclusive at runtime because Moonlight/Sunshine cursor capture
//! conflicts with KVM low-level mouse/keyboard event hooks.
//!
//! ## 3. Threading & Concurrency Model
//! - `Arc<RwLock<FeatureFlags>>`: Provides lock-free read concurrency for high-frequency queries
//!   (`is_enabled`) across asynchronous tasks and UI threads.
//! - `set_flag_checked`: Acquires an exclusive write lock across the entire serialization and disk
//!   flush pipeline. This prevents race conditions where concurrent updates could clobber each other's
//!   filesystem state.
//! - `AtomicU64`: Allocates monotonic unique sequence numbers for temporary files across threads.
//!
//! ## 4. Security & Safety Invariants
//! - **Fail-Closed on Corruption**: If `features.json` cannot be parsed or read, it is backed up to
//!   `features.json.corrupt.<timestamp>` and an all-disabled `fail_closed()` state is loaded.
//! - **Permission Hardening**: On Unix systems, parent directories are restricted to `0o700` and config
//!   files to `0o600`, preventing local multi-user eavesdropping.
//! - **Input Validation**: Unknown feature strings passed to `is_enabled` return `false` and log warnings;
//!   unknown strings passed to `set_flag_checked` return an `Err` and reject modification.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{error, warn};

/// Global atomic sequence counter for naming transient configuration write files safely across threads.
static FEATURES_TMP_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Complete schema of configurable subsystem feature flags.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FeatureFlags {
    /// Virtual display mirroring and screen extension streaming (H.264/HEVC/AV1).
    pub display: bool,
    /// Bidirectional synchronized system clipboard (text, rich text, images, files).
    /// Strictly requires `input_kvm` to be enabled.
    pub clipboard: bool,
    /// Low-latency keyboard, mouse pointer, and gesture redirection across screens.
    pub input_kvm: bool,
    /// Cross-screen drag-and-drop file and object transfer. Requires `input_kvm`.
    pub dragdrop: bool,
    /// Remote filesystem mounting and peer folder synchronization.
    pub storage: bool,
    /// Remote biometric authentication forwarding (Touch ID on Mac to Windows Hello).
    pub touchid: bool,
    /// Ambient light and display white-point color profile synchronization.
    pub truetone: bool,
    /// Virtual webcam capture and frame forwarding to peer virtual camera device.
    pub camera: bool,
    /// High-fidelity low-latency bidirectional PCM audio streaming.
    pub audio: bool,
    /// MacBook Pro Touch Bar extension and virtual function key surface.
    pub touchbar: bool,
    /// Built-in hardware encode/decode and network bandwidth benchmarking suite.
    pub benchmark: bool,
}

impl Default for FeatureFlags {
    /// Returns default feature configuration for first-time installation.
    ///
    /// Core continuity features (`display`, `clipboard`, `input_kvm`, `storage`, `touchid`,
    /// `truetone`, `audio`, `touchbar`, `benchmark`) are enabled by default.
    /// Camera (`camera`) is disabled by default (`false`) for privacy until explicitly enabled
    /// by the user, and `dragdrop` is permanently disabled (`false`).
    fn default() -> Self {
        Self {
            display: true,
            clipboard: true,
            input_kvm: true,
            dragdrop: false,
            storage: true,
            touchid: true,
            truetone: true,
            camera: false,
            audio: true,
            touchbar: true,
            benchmark: true,
        }
    }
}

impl FeatureFlags {
    /// Safe fail-closed configuration used when existing configuration on disk is corrupt or unreadable.
    ///
    /// Disables all subsystems to prevent unexpected network broadcasts or unauthenticated port exposure.
    pub fn fail_closed() -> Self {
        Self {
            display: false,
            clipboard: false,
            input_kvm: false,
            dragdrop: false,
            storage: false,
            touchid: false,
            truetone: false,
            camera: false,
            audio: false,
            touchbar: false,
            benchmark: false,
        }
    }
}

/// Central state manager governing feature flag inspection and persistent disk updates.
pub struct FeatureManager {
    /// Synchronized in-memory cache of current feature flags.
    flags: Arc<RwLock<FeatureFlags>>,
    /// Absolute path to persistent `features.json` file.
    config_path: PathBuf,
}

impl Default for FeatureManager {
    /// Instantiates `FeatureManager` using standard application data directories.
    fn default() -> Self {
        Self::new()
    }
}

impl FeatureManager {
    /// Initializes `FeatureManager`, reading `features.json` from the OS app data directory.
    ///
    /// # Behavior:
    /// - If `features.json` exists and is valid JSON, parses flags and enforces dependency constraints.
    /// - If `features.json` is malformed, creates a timestamped backup copy and loads `FeatureFlags::fail_closed()`.
    /// - If `features.json` does not exist, returns `FeatureFlags::default()`.
    pub fn new() -> Self {
        let config_dir = crate::system_info::app_data_dir();
        let config_path = config_dir.join("features.json");

        let flags = if config_path.exists() {
            match fs::read_to_string(&config_path) {
                Ok(data) => match serde_json::from_str::<FeatureFlags>(&data) {
                    Ok(mut parsed) => {
                        // Cross-screen drag-and-drop has been retired; keep disabled.
                        parsed.dragdrop = false;
                        // Enforce dependency rule: clipboard cannot be active without KVM
                        if !parsed.input_kvm {
                            parsed.clipboard = false;
                        }
                        parsed
                    }
                    Err(e) => {
                        // Configuration corruption detected: preserve corrupted file for forensic analysis
                        let epoch = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        let backup = config_path.with_extension(format!("json.corrupt.{}", epoch));
                        let _ = fs::copy(&config_path, &backup);
                        error!(
                            "Corrupt features.json at {} ({}); backed up to {} and failing closed",
                            config_path.display(),
                            e,
                            backup.display()
                        );
                        FeatureFlags::fail_closed()
                    }
                },
                Err(e) => {
                    error!(
                        "Failed to read existing features.json at {} ({}); failing closed",
                        config_path.display(),
                        e
                    );
                    FeatureFlags::fail_closed()
                }
            }
        } else {
            FeatureFlags::default()
        };

        Self {
            flags: Arc::new(RwLock::new(flags)),
            config_path,
        }
    }

    /// Internal test constructor allowing injection of arbitrary flags and isolated temp files.
    #[cfg(test)]
    pub fn from_flags_for_test(flags: FeatureFlags) -> Self {
        let seq = FEATURES_TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        Self {
            flags: Arc::new(RwLock::new(flags)),
            config_path: std::env::temp_dir()
                .join(format!("integrator_test_features_{}_{}.json", std::process::id(), seq)),
        }
    }

    /// Returns a cloned snapshot of all current feature flags.
    pub fn get_flags(&self) -> FeatureFlags {
        self.flags
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Returns whether the specified `feature` is currently active and permitted to run.
    ///
    /// # Invariants & Rules:
    /// - Unknown feature names return `false` (fail-closed) and log a warning.
    /// - `"clipboard"` and `"dragdrop"` strictly return `false` if `"input_kvm"` is disabled,
    ///   even if their individual flag bits are set to `true`.
    pub fn is_enabled(&self, feature: &str) -> bool {
        let f = self.flags.read().unwrap_or_else(|e| e.into_inner());
        match feature.trim() {
            "display" => f.display,
            "clipboard" => f.input_kvm && f.clipboard,
            "input_kvm" | "input" => f.input_kvm,
            "dragdrop" => false,
            "storage" => f.storage,
            "touchid" => f.touchid,
            "truetone" => f.truetone,
            "camera" => f.camera,
            "audio" => f.audio,
            "touchbar" => f.touchbar,
            "benchmark" => f.benchmark,
            unknown => {
                warn!("Queried unknown feature flag '{}' — failing closed (false)", unknown);
                false
            }
        }
    }

    /// Updates a specific feature flag with validation and atomic filesystem persistence.
    ///
    /// # Arguments
    /// * `feature` - Name of the feature to modify (e.g. `"audio"`, `"clipboard"`).
    /// * `enabled` - Desired state (`true` or `false`).
    ///
    /// # Errors
    /// Returns `Err(String)` if:
    /// - `feature` is not a recognized feature identifier.
    /// - Enabling `"clipboard"` or `"dragdrop"` is attempted while `"input_kvm"` is disabled.
    /// - Filesystem directory creation, file write, or file rename fails.
    pub fn set_flag_checked(&self, feature: &str, enabled: bool) -> Result<FeatureFlags, String> {
        // Hold write lock across entire persistence cycle to guarantee sequential disk updates
        let mut f = self.flags.write().unwrap_or_else(|e| e.into_inner());
        let mut candidate = f.clone();

        match feature.trim() {
            "display" => candidate.display = enabled,
            "clipboard" => {
                if enabled && !candidate.input_kvm {
                    return Err(
                        "Universal Input & KVM must be enabled before turning on Universal Clipboard."
                            .to_string(),
                    );
                }
                candidate.clipboard = enabled;
            }
            "input_kvm" | "input" => {
                candidate.input_kvm = enabled;
                if !enabled {
                    // Auto-disable coupled continuity features when KVM is turned off
                    candidate.clipboard = false;
                    candidate.dragdrop = false;
                }
            }
            "dragdrop" => {
                candidate.dragdrop = false;
            }
            "storage" => candidate.storage = enabled,
            "touchid" => candidate.touchid = enabled,
            "truetone" => candidate.truetone = enabled,
            "camera" => candidate.camera = enabled,
            "audio" => candidate.audio = enabled,
            "touchbar" => candidate.touchbar = enabled,
            "benchmark" => candidate.benchmark = enabled,
            other => {
                return Err(format!("Unknown feature identifier: '{}'", other));
            }
        }

        // Ensure parent configuration directory exists
        if let Some(parent) = self.config_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create config directory: {}", e))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                // Restrict directory access to owner only (rwx------)
                let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
            }
        }

        // Serialize formatted JSON
        let json = serde_json::to_string_pretty(&candidate)
            .map_err(|e| format!("Failed to serialize feature flags: {}", e))?;

        // Write to temporary file with unique PID and sequence number
        let seq = FEATURES_TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp_path = self
            .config_path
            .with_extension(format!("json.{}.{}.tmp", std::process::id(), seq));

        if let Err(e) = fs::write(&tmp_path, json.as_bytes()) {
            let _ = fs::remove_file(&tmp_path);
            return Err(format!("Failed to write {}: {}", tmp_path.display(), e));
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Restrict file access to owner read/write only (rw-------)
            let _ = fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600));
        }

        // Atomically rename temporary file over target configuration file
        if let Err(e) = fs::rename(&tmp_path, &self.config_path) {
            let _ = fs::remove_file(&tmp_path);
            return Err(format!("Failed to save {}: {}", self.config_path.display(), e));
        }

        // Commit candidate state into in-memory cache
        *f = candidate.clone();
        Ok(candidate)
    }

    /// Convenience wrapper around `set_flag_checked` that logs any error and returns current flags.
    pub fn set_flag(&self, feature: &str, enabled: bool) -> FeatureFlags {
        match self.set_flag_checked(feature, enabled) {
            Ok(flags) => flags,
            Err(e) => {
                warn!("set_flag error: {}", e);
                self.get_flags()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_feature_fails_closed_and_rejects_set() {
        let mgr = FeatureManager {
            flags: Arc::new(RwLock::new(FeatureFlags::default())),
            config_path: std::env::temp_dir().join("integrator_features_test_unused.json"),
        };
        assert!(!mgr.is_enabled("nonexistent_feature"));
        assert!(mgr.set_flag_checked("nonexistent_feature", true).is_err());
    }

    #[test]
    fn clipboard_and_dragdrop_depend_strictly_on_input_kvm() {
        let path = std::env::temp_dir().join("integrator_features_kvm_dep_test.json");
        let _ = fs::remove_file(&path);
        let mgr = FeatureManager {
            flags: Arc::new(RwLock::new(FeatureFlags::default())),
            config_path: path.clone(),
        };

        assert!(mgr.is_enabled("input_kvm"));
        assert!(mgr.is_enabled("clipboard"));
        assert!(!mgr.is_enabled("dragdrop"));

        // Turning KVM off auto-disables clipboard.
        let off = mgr.set_flag_checked("input_kvm", false).unwrap();
        assert!(!off.input_kvm);
        assert!(!off.clipboard);
        assert!(!off.dragdrop);
        assert!(!mgr.is_enabled("clipboard"));
        assert!(!mgr.is_enabled("dragdrop"));

        // Turning clipboard on while KVM is off must fail.
        assert!(mgr.set_flag_checked("clipboard", true).is_err());

        // Re-enabling KVM unlocks clipboard toggling again.
        mgr.set_flag_checked("input_kvm", true).unwrap();
        mgr.set_flag_checked("clipboard", true).unwrap();
        assert!(mgr.is_enabled("clipboard"));
        assert!(!mgr.is_enabled("dragdrop"));

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn partial_json_backwards_compatibility_uses_defaults() {
        let legacy_partial = r#"{"display":false,"input_kvm":true,"clipboard":false}"#;
        let parsed: FeatureFlags =
            serde_json::from_str(legacy_partial).expect("partial JSON should deserialize");
        let defaults = FeatureFlags::default();
        assert!(!parsed.display);
        assert!(parsed.input_kvm);
        assert!(!parsed.clipboard);
        assert_eq!(parsed.dragdrop, defaults.dragdrop);
        assert_eq!(parsed.storage, defaults.storage);
        assert_eq!(parsed.benchmark, defaults.benchmark);
    }
}
