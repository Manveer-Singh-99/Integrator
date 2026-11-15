//! Feature flags and master switches for Integrator.
//!
//! Provides granular master switches for workstation fusion capabilities,
//! persisting user preferences atomically to disk across application restarts
//! with fail-closed semantics on corrupt configuration or unknown feature names.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{error, warn};

static FEATURES_TMP_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FeatureFlags {
    pub display: bool,
    pub clipboard: bool,
    pub input_kvm: bool,
    pub dragdrop: bool,
    pub storage: bool,
    pub touchid: bool,
    pub truetone: bool,
    pub camera: bool,
    pub audio: bool,
    pub touchbar: bool,
    pub multiwan: bool,
    pub benchmark: bool,
}

impl Default for FeatureFlags {
    fn default() -> Self {
        Self {
            display: true,
            clipboard: true,
            input_kvm: true,
            dragdrop: true,
            storage: true,
            touchid: false,
            truetone: true,
            camera: false,
            audio: true,
            touchbar: true,
            multiwan: false,
            benchmark: true,
        }
    }
}

impl FeatureFlags {
    /// Fail-closed configuration used when an existing `features.json` on disk is corrupt.
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
            multiwan: false,
            benchmark: false,
        }
    }
}

pub struct FeatureManager {
    flags: Arc<RwLock<FeatureFlags>>,
    config_path: PathBuf,
}

impl Default for FeatureManager {
    fn default() -> Self {
        Self::new()
    }
}

impl FeatureManager {
    pub fn new() -> Self {
        let config_dir = crate::system_info::app_data_dir();
        let config_path = config_dir.join("features.json");

        let flags = if config_path.exists() {
            match fs::read_to_string(&config_path) {
                Ok(data) => match serde_json::from_str::<FeatureFlags>(&data) {
                    Ok(mut parsed) => {
                        if !parsed.input_kvm {
                            parsed.clipboard = false;
                            parsed.dragdrop = false;
                        }
                        parsed
                    }
                    Err(e) => {
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

    #[cfg(test)]
    pub fn from_flags_for_test(flags: FeatureFlags) -> Self {
        let seq = FEATURES_TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        Self {
            flags: Arc::new(RwLock::new(flags)),
            config_path: std::env::temp_dir()
                .join(format!("integrator_test_features_{}_{}.json", std::process::id(), seq)),
        }
    }

    pub fn get_flags(&self) -> FeatureFlags {
        self.flags
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Returns whether `feature` is enabled. Fails closed (`false`) for unknown feature names.
    /// Both `clipboard` and `dragdrop` depend strictly on `input_kvm`.
    pub fn is_enabled(&self, feature: &str) -> bool {
        let f = self.flags.read().unwrap_or_else(|e| e.into_inner());
        match feature.trim() {
            "display" => f.display,
            "clipboard" => f.input_kvm && f.clipboard,
            "input_kvm" | "input" => f.input_kvm,
            "dragdrop" => f.input_kvm && f.dragdrop,
            "storage" => f.storage,
            "touchid" => f.touchid,
            "truetone" => f.truetone,
            "camera" => f.camera,
            "audio" => f.audio,
            "touchbar" => f.touchbar,
            "multiwan" => f.multiwan,
            "benchmark" => f.benchmark,
            unknown => {
                warn!("Queried unknown feature flag '{}' — failing closed (false)", unknown);
                false
            }
        }
    }

    /// Updates a known feature flag and persists it atomically to disk, returning an error
    /// if the feature identifier is unknown, dependency is unmet, or disk persistence fails.
    pub fn set_flag_checked(&self, feature: &str, enabled: bool) -> Result<FeatureFlags, String> {
        // Hold the write lock across atomic disk persistence so concurrent callers
        // cannot reorder disk snapshots and failed writes never mutate in-memory state.
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
                    // Auto-disable coupled continuity features when KVM is turned off.
                    candidate.clipboard = false;
                    candidate.dragdrop = false;
                }
            }
            "dragdrop" => {
                if enabled && !candidate.input_kvm {
                    return Err(
                        "Universal Input & KVM must be enabled before turning on Cross-Screen Drag & Drop."
                            .to_string(),
                    );
                }
                candidate.dragdrop = enabled;
            }
            "storage" => candidate.storage = enabled,
            "touchid" => candidate.touchid = enabled,
            "truetone" => candidate.truetone = enabled,
            "camera" => candidate.camera = enabled,
            "audio" => candidate.audio = enabled,
            "touchbar" => candidate.touchbar = enabled,
            "multiwan" => candidate.multiwan = enabled,
            "benchmark" => candidate.benchmark = enabled,
            other => {
                return Err(format!("Unknown feature identifier: '{}'", other));
            }
        }

        if let Some(parent) = self.config_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create config directory: {}", e))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
            }
        }
        let json = serde_json::to_string_pretty(&candidate)
            .map_err(|e| format!("Failed to serialize feature flags: {}", e))?;
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
            let _ = fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600));
        }
        if let Err(e) = fs::rename(&tmp_path, &self.config_path) {
            let _ = fs::remove_file(&tmp_path);
            return Err(format!("Failed to save {}: {}", self.config_path.display(), e));
        }

        *f = candidate.clone();
        Ok(candidate)
    }

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
        assert!(mgr.is_enabled("dragdrop"));

        // With KVM on, dragdrop and clipboard toggle independently.
        mgr.set_flag_checked("dragdrop", false).unwrap();
        assert!(!mgr.is_enabled("dragdrop"));
        assert!(mgr.is_enabled("clipboard"));
        mgr.set_flag_checked("dragdrop", true).unwrap();
        assert!(mgr.is_enabled("dragdrop"));

        // Turning KVM off auto-disables both clipboard and dragdrop.
        let off = mgr.set_flag_checked("input_kvm", false).unwrap();
        assert!(!off.input_kvm);
        assert!(!off.clipboard);
        assert!(!off.dragdrop);
        assert!(!mgr.is_enabled("clipboard"));
        assert!(!mgr.is_enabled("dragdrop"));

        // Turning clipboard or dragdrop on while KVM is off must fail.
        assert!(mgr.set_flag_checked("clipboard", true).is_err());
        assert!(mgr.set_flag_checked("dragdrop", true).is_err());

        // Re-enabling KVM unlocks independent toggling again.
        mgr.set_flag_checked("input_kvm", true).unwrap();
        mgr.set_flag_checked("clipboard", true).unwrap();
        mgr.set_flag_checked("dragdrop", true).unwrap();
        assert!(mgr.is_enabled("clipboard"));
        assert!(mgr.is_enabled("dragdrop"));

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
