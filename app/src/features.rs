//! Feature flags and master switches for Integrator.
//!
//! Provides granular master switches for all workstation fusion capabilities,
//! persisting user preferences to disk across application restarts on both macOS and Windows.

use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use serde::{Deserialize, Serialize};

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
            touchid: true,
            truetone: true,
            camera: true,
            audio: true,
            touchbar: true,
            multiwan: true,
            benchmark: true,
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

        let flags = if let Ok(data) = fs::read_to_string(&config_path) {
            serde_json::from_str::<FeatureFlags>(&data).unwrap_or_default()
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

    pub fn is_enabled(&self, feature: &str) -> bool {
        let f = self.flags.read().unwrap_or_else(|e| e.into_inner());
        match feature {
            "display" => f.display,
            "clipboard" => f.clipboard,
            "input_kvm" | "input" => f.input_kvm,
            "dragdrop" => f.dragdrop,
            "storage" => f.storage,
            "touchid" => f.touchid,
            "truetone" => f.truetone,
            "camera" => f.camera,
            "audio" => f.audio,
            "touchbar" => f.touchbar,
            "multiwan" => f.multiwan,
            "benchmark" => f.benchmark,
            _ => true,
        }
    }

    pub fn set_flag(&self, feature: &str, enabled: bool) -> FeatureFlags {
        {
            let mut f = self.flags.write().unwrap_or_else(|e| e.into_inner());
            match feature {
                "display" => f.display = enabled,
                "clipboard" => f.clipboard = enabled,
                "input_kvm" | "input" => f.input_kvm = enabled,
                "dragdrop" => f.dragdrop = enabled,
                "storage" => f.storage = enabled,
                "touchid" => f.touchid = enabled,
                "truetone" => f.truetone = enabled,
                "camera" => f.camera = enabled,
                "audio" => f.audio = enabled,
                "touchbar" => f.touchbar = enabled,
                "multiwan" => f.multiwan = enabled,
                "benchmark" => f.benchmark = enabled,
                _ => {}
            }
        }
        let updated = self.get_flags();
        if let Ok(json) = serde_json::to_string_pretty(&updated) {
            let _ = fs::write(&self.config_path, json);
        }
        updated
    }
}
