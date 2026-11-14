//! Feature flags and master switches for Integrator.
//!
//! Provides granular master switches for workstation fusion capabilities,
//! persisting user preferences atomically to disk across application restarts
//! with fail-closed semantics on corrupt configuration or unknown feature names.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{error, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
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
        let updated = {
            let mut f = self.flags.write().unwrap_or_else(|e| e.into_inner());
            match feature.trim() {
                "display" => f.display = enabled,
                "clipboard" => {
                    if enabled && !f.input_kvm {
                        return Err(
                            "Universal Input & KVM must be enabled before turning on Universal Clipboard."
                                .to_string(),
                        );
                    }
                    f.clipboard = enabled;
                }
                "input_kvm" | "input" => {
                    f.input_kvm = enabled;
                    if !enabled {
                        // Auto-disable coupled continuity features when KVM is turned off.
                        f.clipboard = false;
                        f.dragdrop = false;
                    }
                }
                "dragdrop" => {
                    if enabled && !f.input_kvm {
                        return Err(
                            "Universal Input & KVM must be enabled before turning on Cross-Screen Drag & Drop."
                                .to_string(),
                        );
                    }
                    f.dragdrop = enabled;
                }
                "storage" => f.storage = enabled,
                "touchid" => f.touchid = enabled,
                "truetone" => f.truetone = enabled,
                "camera" => f.camera = enabled,
                "audio" => f.audio = enabled,
                "touchbar" => f.touchbar = enabled,
                "multiwan" => f.multiwan = enabled,
                "benchmark" => f.benchmark = enabled,
                other => {
                    return Err(format!("Unknown feature identifier: '{}'", other));
                }
            }
            f.clone()
        };

        if let Some(parent) = self.config_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create config directory: {}", e))?;
        }
        let json = serde_json::to_string_pretty(&updated)
            .map_err(|e| format!("Failed to serialize feature flags: {}", e))?;
        let tmp_path = self.config_path.with_extension("json.tmp");
        fs::write(&tmp_path, json)
            .map_err(|e| format!("Failed to write {}: {}", tmp_path.display(), e))?;
        fs::rename(&tmp_path, &self.config_path)
            .map_err(|e| format!("Failed to save {}: {}", self.config_path.display(), e))?;

        Ok(updated)
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
}
