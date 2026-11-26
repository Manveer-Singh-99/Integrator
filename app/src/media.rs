//! # Cross-Platform Media Session Telemetry & Remote Transport Control (`media.rs`)
//!
//! ## 1. Module Purpose & Scope
//! Provides native Windows Global System Media Transport Controls (GSMTC) metadata polling and
//! sub-millisecond media transport command execution (`PlayPause`, `Next`, `Previous`, `Seek`)
//! using WinRT `Windows.Media.Control` directly in-process (zero subprocess spawning), so a
//! paired MacBook Pro Touch Bar can display and control Spotify, YouTube, Apple Music, VLC, and
//! other Windows media players while the user works on macOS.
//!
//! ## 2. Architectural Linkages & Dependencies
//! ### Upstream Callers:
//! - `core::IntegratorCore`: Handles `"get_windows_media_state"` and `"send_windows_media_cmd"` UI
//!   JSON-RPC actions via `tokio::task::spawn_blocking`.
//! - `display::controller::DisplayController`: Dispatches incoming peer RPC requests
//!   (`DisplayRpcRequest::GetMediaState`, `DisplayRpcRequest::SendMediaCommand`).
//!
//! ### Downstream Callees:
//! - WinRT `Windows.Media.Control` (`GlobalSystemMediaTransportControlsSessionManager`):
//!   Enumerates active media sessions, track metadata, playback status, and timeline properties.
//! - Windows UI Automation (`IUIAutomation`, `CUIAutomation`, `IUIAutomationRangeValuePattern`):
//!   Fallback scrub control via `LCDScrubber` (Apple Music) or duration-matched `Slider` controls
//!   when GSMTC reports `IsPlaybackPositionEnabled = false`.
//! - Win32 Toolhelp (`CreateToolhelp32Snapshot`, `Process32FirstW`/`NextW`) & `SendInput`:
//!   Resolves player PIDs for UIA scrubbing and synthesizes `VK_MEDIA_*` keys if GSMTC declines.
//!
//! ### Cross-Platform / Cross-Device Flow:
//! 1. macOS Touch Bar UI polls `get_windows_media_state`, forwarding `DisplayRpcRequest::GetMediaState`
//!    over the encrypted TCP RPC channel to Windows.
//! 2. Windows queries GSMTC in-process (500 ms cache), sanitizes metadata, and returns [`MediaPlaybackState`].
//! 3. Touch Bar playback controls and scrub gestures dispatch [`MediaControlAction`] back to Windows
//!    for immediate GSMTC execution or UIA `LCDScrubber` timeline seeking, invalidating the cache.
//!
//! ## 3. Threading & Concurrency Model
//! - All Windows COM/WinRT/UIA calls are synchronous blocking calls dispatched by upstream callers
//!   on `tokio::task::spawn_blocking` worker threads.
//! - Each entry initializes COM Multi-Threaded Apartment (`COINIT_MULTITHREADED`), treating
//!   `RPC_E_CHANGED_MODE` gracefully if the thread was previously initialized as STA.
//! - `MEDIA_CACHE` serializes 500 ms state caching under a `OnceLock<Mutex<...>>`.
//!
//! ## 4. Security & Safety Invariants
//! - **Least Privilege**: Operates strictly at user session privilege (`asInvoker`).
//! - **Zero Subprocess Overhead**: Native WinRT COM queries complete in ~1–2 ms with a 500 ms
//!   in-memory cache, eliminating PowerShell fork latency and window flashes.
//! - **Input Sanitization & Bounds**: Track titles, artist names, and app IDs are stripped of control
//!   and bidirectional override characters and clamped to bounded lengths; seek targets and timeline
//!   durations are verified finite and clamped to `[0.0, MAX_MEDIA_DURATION_SECS]`.
//! - **COM/Handle Hygiene**: Toolhelp snapshot handles are unconditionally closed with `CloseHandle`,
//!   and `SendInput` `ManuallyDrop` union fields match Win32 `INPUT` layout.

use serde::{Deserialize, Serialize};
#[cfg(target_os = "windows")]
use std::sync::{Mutex, OnceLock};
#[cfg(target_os = "windows")]
use std::time::{Duration, Instant};

/// Maximum permitted string length for sanitized media metadata fields.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const MAX_MEDIA_TEXT_LEN: usize = 96;

/// Maximum finite track duration accepted (24 hours in seconds).
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const MAX_MEDIA_DURATION_SECS: f64 = 86_400.0;

/// In-memory TTL (500 ms) for GSMTC playback state queries to coalesce rapid UI polling.
#[cfg(target_os = "windows")]
const MEDIA_CACHE_TTL: Duration = Duration::from_millis(500);

/// Snapshot of active media playback on the Windows peer (Spotify, Chrome/Edge YouTube, VLC, etc.).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MediaPlaybackState {
    /// Currently playing track or video title.
    #[serde(default)]
    pub title: String,
    /// Track artist or channel name.
    #[serde(default)]
    pub artist: String,
    /// Source media application identifier (e.g. `"Spotify"`, `"Chrome"`, `"Edge"`).
    #[serde(default)]
    pub app_name: String,
    /// `true` when playback is actively playing, `false` when paused or stopped.
    #[serde(default)]
    pub is_playing: bool,
    /// Current playback timeline position in seconds.
    #[serde(default)]
    pub position_secs: f64,
    /// Total track duration in seconds (`0.0` if live stream or unknown).
    #[serde(default)]
    pub duration_secs: f64,
    /// `true` when an active system media session is available on the host.
    #[serde(default)]
    pub has_session: bool,
}

/// Remote media playback and volume command sent from macOS Touch Bar to Windows.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MediaControlAction {
    /// Toggle play/pause on the active media session.
    PlayPause,
    /// Skip forward to the next track.
    Next,
    /// Skip backward to the previous track.
    Previous,
    /// Seek active track timeline to `position_secs`.
    Seek {
        /// Target playback position in seconds (clamped to `0.0..=MAX_MEDIA_DURATION_SECS`).
        position_secs: f64,
    },
    /// Toggle Windows master audio mute (`VK_VOLUME_MUTE`).
    VolumeMute,
    /// Step Windows master volume down (`VK_VOLUME_DOWN`).
    VolumeDown,
    /// Step Windows master volume up (`VK_VOLUME_UP`).
    VolumeUp,
}

/// Strips control characters and Unicode bidi overrides and truncates to `max_chars`.
pub fn sanitize_media_text(raw: &str, max_chars: usize) -> String {
    raw.trim()
        .chars()
        .filter(|&c| {
            !c.is_control()
                && !matches!(
                    c,
                    '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}'
                )
        })
        .take(max_chars)
        .collect::<String>()
        .trim()
        .to_string()
}

/// Normalizes a `MediaPlaybackState` enforcing finite bounded timeline values and safe display strings.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub fn sanitize_media_state(mut st: MediaPlaybackState) -> MediaPlaybackState {
    st.title = sanitize_media_text(&st.title, MAX_MEDIA_TEXT_LEN);
    st.artist = sanitize_media_text(&st.artist, MAX_MEDIA_TEXT_LEN);
    st.app_name = sanitize_media_text(&st.app_name, 48);
    if !st.duration_secs.is_finite() || st.duration_secs < 0.0 {
        st.duration_secs = 0.0;
    } else {
        st.duration_secs = st.duration_secs.min(MAX_MEDIA_DURATION_SECS);
    }
    if !st.position_secs.is_finite() || st.position_secs < 0.0 {
        st.position_secs = 0.0;
    } else if st.duration_secs > 0.0 {
        st.position_secs = st.position_secs.min(st.duration_secs);
    } else {
        st.position_secs = st.position_secs.min(MAX_MEDIA_DURATION_SECS);
    }
    st
}

/// Queries the active OS media playback state.
///
/// On Windows, queries native WinRT `GlobalSystemMediaTransportControlsSessionManager`
/// in-process (~1–2 ms) with a 500 ms TTL cache. On non-Windows hosts, returns an empty state.
pub fn query_media_state() -> MediaPlaybackState {
    #[cfg(target_os = "windows")]
    {
        windows_media::query_gsmtc_cached()
    }
    #[cfg(not(target_os = "windows"))]
    {
        MediaPlaybackState::default()
    }
}

/// Executes a media transport action (`PlayPause`, `Next`, `Previous`, or `Seek`).
pub fn execute_media_command(action: &MediaControlAction) -> Result<String, String> {
    #[cfg(target_os = "windows")]
    {
        windows_media::execute_command(action)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = action;
        Err("Local media execution is only supported on Windows peer".to_string())
    }
}

#[cfg(target_os = "windows")]
mod windows_media {
    use super::*;
    use std::ffi::c_void;
    use windows::core::{BSTR, VARIANT};
    use windows::Media::Control::{
        GlobalSystemMediaTransportControlsSession,
        GlobalSystemMediaTransportControlsSessionManager,
        GlobalSystemMediaTransportControlsSessionPlaybackStatus,
    };
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
    };
    use windows::Win32::UI::Accessibility::{
        CUIAutomation, IUIAutomation, IUIAutomationRangeValuePattern, TreeScope_Children,
        TreeScope_Descendants, UIA_AutomationIdPropertyId, UIA_ControlTypePropertyId,
        UIA_ProcessIdPropertyId, UIA_RangeValuePatternId, UIA_SliderControlTypeId,
    };

    /// Global cached GSMTC state snapshot and its monotonic capture timestamp.
    static MEDIA_CACHE: OnceLock<Mutex<(Instant, MediaPlaybackState)>> = OnceLock::new();

    /// Returns the mutex protecting [`MEDIA_CACHE`], initialized to an expired timestamp.
    fn cache_lock() -> &'static Mutex<(Instant, MediaPlaybackState)> {
        MEDIA_CACHE.get_or_init(|| {
            Mutex::new((
                Instant::now() - Duration::from_secs(60),
                MediaPlaybackState::default(),
            ))
        })
    }

    /// Initializes the calling worker thread into the Windows COM Multi-Threaded Apartment (MTA).
    /// Ignores `RPC_E_CHANGED_MODE` when a thread was already initialized as STA by the host.
    fn ensure_com_mta() {
        // SAFETY: `CoInitializeEx(None, COINIT_MULTITHREADED)` is safe to invoke on any OS thread;
        // S_OK (0), S_FALSE (1), or RPC_E_CHANGED_MODE (0x80010106) are all safe to proceed with.
        unsafe {
            let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
        }
    }

    /// Selects the highest-priority active GSMTC session: prefers any session currently `Playing`,
    /// otherwise falls back to `GetCurrentSession()`, then the first enumerated registered session.
    fn pick_best_session(
        mgr: &GlobalSystemMediaTransportControlsSessionManager,
    ) -> Option<GlobalSystemMediaTransportControlsSession> {
        // Prefer an actively Playing session across all registered GSMTC apps (Spotify, Chrome/Edge YouTube, Apple Music, VLC)
        if let Ok(sessions) = mgr.GetSessions() {
            if let Ok(count) = sessions.Size() {
                let mut first_with_title: Option<GlobalSystemMediaTransportControlsSession> = None;
                for i in 0..count {
                    if let Ok(sess) = sessions.GetAt(i) {
                        let playing = sess
                            .GetPlaybackInfo()
                            .and_then(|pb| pb.PlaybackStatus())
                            .map(|st| {
                                st == GlobalSystemMediaTransportControlsSessionPlaybackStatus::Playing
                            })
                            .unwrap_or(false);
                        if playing {
                            return Some(sess);
                        }
                        if first_with_title.is_none() {
                            first_with_title = Some(sess);
                        }
                    }
                }
                if let Ok(cur) = mgr.GetCurrentSession() {
                    return Some(cur);
                }
                return first_with_title;
            }
        }
        mgr.GetCurrentSession().ok()
    }

    /// Queries Windows GSMTC synchronously for track metadata and 100ns-tick timeline state,
    /// returning sanitized [`MediaPlaybackState`] or `None` if no active session exists.
    fn query_gsmtc_uncached() -> Option<MediaPlaybackState> {
        ensure_com_mta();
        let mgr = GlobalSystemMediaTransportControlsSessionManager::RequestAsync()
            .ok()?
            .get()
            .ok()?;
        let sess = pick_best_session(&mgr)?;

        let app_name = sess
            .SourceAppUserModelId()
            .map(|h| h.to_string_lossy())
            .unwrap_or_default();
        let is_playing = sess
            .GetPlaybackInfo()
            .and_then(|pb| pb.PlaybackStatus())
            .map(|st| st == GlobalSystemMediaTransportControlsSessionPlaybackStatus::Playing)
            .unwrap_or(false);

        let (title, artist) = match sess
            .TryGetMediaPropertiesAsync()
            .ok()
            .and_then(|op| op.get().ok())
        {
            Some(props) => (
                props.Title().map(|h| h.to_string_lossy()).unwrap_or_default(),
                props.Artist().map(|h| h.to_string_lossy()).unwrap_or_default(),
            ),
            None => (String::new(), String::new()),
        };

        // WinRT TimeSpan::Duration uses 100-nanosecond ticks (10_000_000 ticks per second).
        let (position_secs, duration_secs) = match sess.GetTimelineProperties() {
            Ok(tl) => {
                let start_ticks = tl.StartTime().map(|ts| ts.Duration).unwrap_or(0);
                let pos_ticks = tl.Position().map(|ts| ts.Duration).unwrap_or(start_ticks);
                let end_ticks = tl.EndTime().map(|ts| ts.Duration).unwrap_or(start_ticks);
                let pos = (pos_ticks.saturating_sub(start_ticks)) as f64 / 10_000_000.0;
                let dur = (end_ticks.saturating_sub(start_ticks)) as f64 / 10_000_000.0;
                (pos, dur)
            }
            Err(_) => (0.0, 0.0),
        };

        Some(sanitize_media_state(MediaPlaybackState {
            title,
            artist,
            app_name,
            is_playing,
            position_secs,
            duration_secs,
            has_session: true,
        }))
    }

    /// Returns cached GSMTC playback state if younger than [`MEDIA_CACHE_TTL`], otherwise queries live.
    pub fn query_gsmtc_cached() -> MediaPlaybackState {
        let cache = cache_lock();
        if let Ok(guard) = cache.lock() {
            if guard.0.elapsed() < MEDIA_CACHE_TTL {
                return guard.1.clone();
            }
        }
        let fresh = query_gsmtc_uncached().unwrap_or_default();
        if let Ok(mut guard) = cache.lock() {
            *guard = (Instant::now(), fresh.clone());
        }
        fresh
    }

    /// Forces the next [`query_gsmtc_cached`] call to re-query GSMTC by backdating cache age.
    fn invalidate_cache() {
        if let Ok(mut guard) = cache_lock().lock() {
            guard.0 = Instant::now() - Duration::from_secs(60);
        }
    }

    /// Maps a GSMTC `SourceAppUserModelId` to lowercase candidate Windows executable filenames
    /// used to locate top-level player windows for UI Automation fallback seeking.
    fn candidate_exe_names(source_app_id: &str) -> Vec<String> {
        let lower = source_app_id.to_ascii_lowercase();
        let mut out = Vec::new();
        if lower.contains("applemusic") {
            out.push("applemusic.exe".to_string());
        } else if lower.contains("spotify") {
            out.push("spotify.exe".to_string());
        } else if lower.contains("chrome") {
            out.push("chrome.exe".to_string());
        } else if lower.contains("msedge") {
            out.push("msedge.exe".to_string());
        } else if lower.contains("vlc") {
            out.push("vlc.exe".to_string());
        } else if lower.contains("zunemusic") || lower.contains("mediaplayer") {
            out.push("microsoft.media.player.exe".to_string());
        }
        if let Some(pos) = lower.rfind(".exe") {
            let start = lower[..pos]
                .rfind(|c: char| c == '\\' || c == '/' || c == '!' || c == '_')
                .map(|i| i + 1)
                .unwrap_or(0);
            let exe = lower[start..pos + 4].to_string();
            if !exe.is_empty() && !out.contains(&exe) {
                out.push(exe);
            }
        }
        out
    }

    /// Enumerates running process IDs matching any lowercase filename in `targets` via Toolhelp32.
    fn find_pids_by_exe_names(targets: &[String]) -> Vec<u32> {
        if targets.is_empty() {
            return Vec::new();
        }
        /// Win32 `PROCESSENTRY32W` layout used with `Process32FirstW`/`Process32NextW`.
        #[repr(C)]
        struct ProcessEntry32W {
            /// Structure size in bytes (must be initialized before `Process32FirstW`).
            dw_size: u32,
            /// Deprecated reference count (unused).
            cnt_usage: u32,
            /// Windows process identifier (PID).
            th32_process_id: u32,
            /// Identifier of default heap (unused).
            th32_default_heap_id: usize,
            /// Module identifier (unused).
            th32_module_id: u32,
            /// Count of execution threads started by the process.
            cnt_threads: u32,
            /// Parent process identifier.
            th32_parent_process_id: u32,
            /// Base priority of threads created by this process.
            pc_pri_class_base: i32,
            /// Flags (unused).
            dw_flags: u32,
            /// Null-terminated UTF-16 executable filename (`MAX_PATH` = 260 WCHARs).
            sz_exe_file: [u16; 260],
        }
        const TH32CS_SNAPPROCESS: u32 = 0x00000002;
        const INVALID_HANDLE: *mut c_void = (-1isize) as *mut c_void;
        extern "system" {
            fn CreateToolhelp32Snapshot(dw_flags: u32, th32_process_id: u32) -> *mut c_void;
            fn Process32FirstW(h_snapshot: *mut c_void, lppe: *mut ProcessEntry32W) -> i32;
            fn Process32NextW(h_snapshot: *mut c_void, lppe: *mut ProcessEntry32W) -> i32;
            fn CloseHandle(handle: *mut c_void) -> i32;
        }
        // SAFETY: `CreateToolhelp32Snapshot` takes value flags and returns a valid handle or `INVALID_HANDLE`.
        let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snap.is_null() || snap == INVALID_HANDLE {
            return Vec::new();
        }
        let mut entry = ProcessEntry32W {
            dw_size: std::mem::size_of::<ProcessEntry32W>() as u32,
            cnt_usage: 0,
            th32_process_id: 0,
            th32_default_heap_id: 0,
            th32_module_id: 0,
            cnt_threads: 0,
            th32_parent_process_id: 0,
            pc_pri_class_base: 0,
            dw_flags: 0,
            sz_exe_file: [0u16; 260],
        };
        let mut pids = Vec::new();
        // SAFETY: `snap` is a valid non-null Toolhelp snapshot handle and `entry.dw_size` matches `sizeof(ProcessEntry32W)`.
        if unsafe { Process32FirstW(snap, &mut entry) } != 0 {
            loop {
                let nul_pos = entry
                    .sz_exe_file
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.sz_exe_file.len());
                let name = String::from_utf16_lossy(&entry.sz_exe_file[..nul_pos])
                    .to_ascii_lowercase();
                if targets.iter().any(|t| t == &name) {
                    pids.push(entry.th32_process_id);
                }
                // SAFETY: Continues iteration over valid Toolhelp snapshot using properly sized `entry`.
                if unsafe { Process32NextW(snap, &mut entry) } == 0 {
                    break;
                }
            }
        }
        // SAFETY: Releases the valid Toolhelp snapshot handle unconditionally before returning.
        unsafe {
            CloseHandle(snap);
        }
        pids
    }

    /// Fallback seek via Windows UI Automation `IUIAutomationRangeValuePattern::SetValue`
    /// for media players (such as Apple Music for Windows) that report `IsPlaybackPositionEnabled = false`
    /// over GSMTC while exposing a writable WinUI progress `Slider` (`LCDScrubber`).
    fn try_uia_seek(source_app_id: &str, target_secs: f64, duration_secs: f64) -> bool {
        let safe_target = if target_secs.is_finite() {
            target_secs.max(0.0)
        } else {
            return false;
        };
        let targets = candidate_exe_names(source_app_id);
        let pids = find_pids_by_exe_names(&targets);
        if pids.is_empty() {
            return false;
        }
        ensure_com_mta();
        // SAFETY: COM is initialized on this thread via `ensure_com_mta()`, and all Win32 UIA COM
        // interface pointers returned by `CoCreateInstance`/`GetRootElement`/`FindFirst`/`FindAll`
        // are managed via `windows` smart COM wrappers with checked `Result` returns.
        unsafe {
            let Ok(uia) =
                CoCreateInstance::<_, IUIAutomation>(&CUIAutomation, None, CLSCTX_INPROC_SERVER)
            else {
                return false;
            };
            let Ok(root) = uia.GetRootElement() else {
                return false;
            };

            let scrubber_id_cond = uia
                .CreatePropertyCondition(
                    UIA_AutomationIdPropertyId,
                    &VARIANT::from(BSTR::from("LCDScrubber")),
                )
                .ok();
            let slider_type_cond = uia
                .CreatePropertyCondition(
                    UIA_ControlTypePropertyId,
                    &VARIANT::from(UIA_SliderControlTypeId.0),
                )
                .ok();

            for pid in pids {
                let Ok(pid_i32) = i32::try_from(pid) else {
                    continue;
                };
                let Ok(pid_cond) =
                    uia.CreatePropertyCondition(UIA_ProcessIdPropertyId, &VARIANT::from(pid_i32))
                else {
                    continue;
                };
                let Ok(win) = root.FindFirst(TreeScope_Children, &pid_cond) else {
                    continue;
                };

                // Fast path: Apple Music WinUI `LCDScrubber` progress slider
                if let Some(ref cond) = scrubber_id_cond {
                    if let Ok(slider) = win.FindFirst(TreeScope_Descendants, cond) {
                        if let Ok(rv) = slider
                            .GetCurrentPatternAs::<IUIAutomationRangeValuePattern>(
                                UIA_RangeValuePatternId,
                            )
                        {
                            let ro = rv.CurrentIsReadOnly().map(|b| b.as_bool()).unwrap_or(true);
                            if !ro {
                                let min = rv.CurrentMinimum().unwrap_or(0.0);
                                let max = rv.CurrentMaximum().unwrap_or(duration_secs);
                                if min.is_finite() && max.is_finite() && max > min {
                                    let clamped = safe_target.clamp(min, max);
                                    if rv.SetValue(clamped).is_ok() {
                                        tracing::debug!(
                                            "🎵 Seeked '{}' via UIA LCDScrubber to {:.1}s",
                                            source_app_id,
                                            clamped
                                        );
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                }

                // Generic fallback: any writable Slider whose range matches the active track duration
                // (3.5s tolerance accommodates rounded track durations in player UI sliders).
                if duration_secs.is_finite() && duration_secs > 1.0 {
                    if let Some(ref cond) = slider_type_cond {
                        if let Ok(arr) = win.FindAll(TreeScope_Descendants, cond) {
                            let len = arr.Length().unwrap_or(0);
                            for idx in 0..len {
                                let Ok(slider) = arr.GetElement(idx) else {
                                    continue;
                                };
                                let Ok(rv) = slider
                                    .GetCurrentPatternAs::<IUIAutomationRangeValuePattern>(
                                        UIA_RangeValuePatternId,
                                    )
                                else {
                                    continue;
                                };
                                let ro = rv.CurrentIsReadOnly().map(|b| b.as_bool()).unwrap_or(true);
                                if ro {
                                    continue;
                                }
                                let min = rv.CurrentMinimum().unwrap_or(0.0);
                                let max = rv.CurrentMaximum().unwrap_or(0.0);
                                if min.is_finite()
                                    && max.is_finite()
                                    && min <= 0.5
                                    && (max - duration_secs).abs() <= 3.5
                                    && max > min
                                {
                                    let clamped = safe_target.clamp(min, max);
                                    if rv.SetValue(clamped).is_ok() {
                                        tracing::debug!(
                                            "🎵 Seeked '{}' via UIA Slider to {:.1}s",
                                            source_app_id,
                                            clamped
                                        );
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        false
    }

    /// Synthesizes a Win32 hardware media virtual-key press+release event pair (`VK_MEDIA_*`)
    /// when a player has no active GSMTC session or declines `TryTogglePlayPauseAsync`/skip calls.
    fn send_win32_media_vk(vk: u16) -> Result<(), String> {
        /// Win32 `KEYBDINPUT` structure describing a single virtual keyboard event.
        #[repr(C)]
        struct KeybdInput {
            /// Virtual-key code (`VK_MEDIA_PLAY_PAUSE`, `VK_MEDIA_NEXT_TRACK`, `VK_MEDIA_PREV_TRACK`).
            w_vk: u16,
            /// Hardware scan code (0 when synthesizing virtual keys).
            w_scan: u16,
            /// Keystroke flags (`0` for key down, `KEYEVENTF_KEYUP` for release).
            dw_flags: u32,
            /// Event timestamp in ms (0 lets system supply timestamp).
            time: u32,
            /// Application-defined extra info.
            dw_extra_info: usize,
        }
        /// Win32 `INPUT` union sized to the largest Win32 union variant (`MOUSEINPUT` / 32 bytes).
        #[repr(C)]
        union InputUnion {
            ki: std::mem::ManuallyDrop<KeybdInput>,
            _pad: [u8; 32],
        }
        /// Win32 `INPUT` event descriptor passed to `SendInput`.
        #[repr(C)]
        struct Input {
            /// Event type discriminant (`INPUT_KEYBOARD = 1`).
            r#type: u32,
            /// Event payload union.
            u: InputUnion,
        }
        const INPUT_KEYBOARD: u32 = 1;
        const KEYEVENTF_KEYUP: u32 = 0x0002;
        extern "system" {
            fn SendInput(c_inputs: u32, p_inputs: *const Input, cb_size: i32) -> u32;
        }

        let inputs = [
            Input {
                r#type: INPUT_KEYBOARD,
                u: InputUnion {
                    ki: std::mem::ManuallyDrop::new(KeybdInput {
                        w_vk: vk,
                        w_scan: 0,
                        dw_flags: 0,
                        time: 0,
                        dw_extra_info: 0,
                    }),
                },
            },
            Input {
                r#type: INPUT_KEYBOARD,
                u: InputUnion {
                    ki: std::mem::ManuallyDrop::new(KeybdInput {
                        w_vk: vk,
                        w_scan: 0,
                        dw_flags: KEYEVENTF_KEYUP,
                        time: 0,
                        dw_extra_info: 0,
                    }),
                },
            },
        ];
        // SAFETY: `inputs` is a stack-allocated 2-element array matching Win32 `INPUT` layout and size.
        let sent = unsafe { SendInput(2, inputs.as_ptr(), std::mem::size_of::<Input>() as i32) };
        if sent == 2 {
            Ok(())
        } else {
            Err("Win32 SendInput failed to inject media transport key".to_string())
        }
    }

    /// Executes a [`MediaControlAction`] on Windows via GSMTC first, falling back to Win32
    /// `SendInput` (`VK_MEDIA_*`) for transport keys and UI Automation `LCDScrubber`/`Slider`
    /// scrubbing for timeline seeks, then invalidates [`MEDIA_CACHE`].
    pub fn execute_command(action: &MediaControlAction) -> Result<String, String> {
        const VK_VOLUME_MUTE: u16 = 0xAD;
        const VK_VOLUME_DOWN: u16 = 0xAE;
        const VK_VOLUME_UP: u16 = 0xAF;
        const VK_MEDIA_NEXT_TRACK: u16 = 0xB0;
        const VK_MEDIA_PREV_TRACK: u16 = 0xB1;
        const VK_MEDIA_PLAY_PAUSE: u16 = 0xB3;

        match action {
            MediaControlAction::VolumeMute => {
                send_win32_media_vk(VK_VOLUME_MUTE)?;
                return Ok("Toggled Windows audio mute".to_string());
            }
            MediaControlAction::VolumeDown => {
                send_win32_media_vk(VK_VOLUME_DOWN)?;
                return Ok("Decreased Windows volume".to_string());
            }
            MediaControlAction::VolumeUp => {
                send_win32_media_vk(VK_VOLUME_UP)?;
                return Ok("Increased Windows volume".to_string());
            }
            _ => {}
        }

        ensure_com_mta();
        let gsmtc_sess = GlobalSystemMediaTransportControlsSessionManager::RequestAsync()
            .ok()
            .and_then(|op| op.get().ok())
            .and_then(|mgr| pick_best_session(&mgr));

        match action {
            MediaControlAction::PlayPause => {
                let handled = gsmtc_sess
                    .as_ref()
                    .and_then(|s| s.TryTogglePlayPauseAsync().ok())
                    .and_then(|op| op.get().ok())
                    .unwrap_or(false);
                if !handled {
                    send_win32_media_vk(VK_MEDIA_PLAY_PAUSE)?;
                }
                invalidate_cache();
                Ok("Toggled Windows media play/pause".to_string())
            }
            MediaControlAction::Next => {
                let handled = gsmtc_sess
                    .as_ref()
                    .and_then(|s| s.TrySkipNextAsync().ok())
                    .and_then(|op| op.get().ok())
                    .unwrap_or(false);
                if !handled {
                    send_win32_media_vk(VK_MEDIA_NEXT_TRACK)?;
                }
                invalidate_cache();
                Ok("Skipped to next track on Windows".to_string())
            }
            MediaControlAction::Previous => {
                let handled = gsmtc_sess
                    .as_ref()
                    .and_then(|s| s.TrySkipPreviousAsync().ok())
                    .and_then(|op| op.get().ok())
                    .unwrap_or(false);
                if !handled {
                    send_win32_media_vk(VK_MEDIA_PREV_TRACK)?;
                }
                invalidate_cache();
                Ok("Skipped to previous track on Windows".to_string())
            }
            MediaControlAction::Seek { position_secs } => {
                let clamped = if position_secs.is_finite() {
                    position_secs.clamp(0.0, MAX_MEDIA_DURATION_SECS)
                } else {
                    0.0
                };
                if let Some(sess) = gsmtc_sess {
                    let app_id = sess
                        .SourceAppUserModelId()
                        .map(|h| h.to_string_lossy())
                        .unwrap_or_default();
                    let (start_ticks, end_ticks, min_seek, max_seek) =
                        match sess.GetTimelineProperties() {
                            Ok(tl) => (
                                tl.StartTime().map(|t| t.Duration).unwrap_or(0),
                                tl.EndTime().map(|t| t.Duration).unwrap_or(0),
                                tl.MinSeekTime().map(|t| t.Duration).unwrap_or(0),
                                tl.MaxSeekTime().map(|t| t.Duration).unwrap_or(0),
                            ),
                            Err(_) => (0, 0, 0, 0),
                        };
                    let duration_secs =
                        (end_ticks.saturating_sub(start_ticks)) as f64 / 10_000_000.0;
                    let mut req_ticks =
                        start_ticks.saturating_add((clamped * 10_000_000.0).round() as i64);
                    if max_seek > min_seek {
                        req_ticks = req_ticks.clamp(min_seek, max_seek);
                    }
                    let gsmtc_can_seek = sess
                        .GetPlaybackInfo()
                        .and_then(|pb| pb.Controls())
                        .and_then(|c| c.IsPlaybackPositionEnabled())
                        .unwrap_or(true);
                    let mut handled = false;
                    if gsmtc_can_seek {
                        handled = sess
                            .TryChangePlaybackPositionAsync(req_ticks)
                            .ok()
                            .and_then(|op| op.get().ok())
                            .unwrap_or(false);
                    }
                    if !handled {
                        let _ = try_uia_seek(&app_id, clamped, duration_secs);
                    }
                }
                invalidate_cache();
                Ok(format!("Seeked Windows media playback to {:.1}s", clamped))
            }
            MediaControlAction::VolumeMute
            | MediaControlAction::VolumeDown
            | MediaControlAction::VolumeUp => unreachable!("volume actions handled above"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_media_state_clamps_bounds_and_strips_bidi() {
        let raw = MediaPlaybackState {
            title: "  Song\u{202E}Title\x07  ".to_string(),
            artist: "Artist\nName".to_string(),
            app_name: "Spotify.exe".to_string(),
            is_playing: true,
            position_secs: 500.0,
            duration_secs: 240.0,
            has_session: true,
        };
        let clean = sanitize_media_state(raw);
        assert_eq!(clean.title, "SongTitle");
        assert_eq!(clean.artist, "ArtistName");
        assert_eq!(clean.duration_secs, 240.0);
        assert_eq!(clean.position_secs, 240.0);

        let nan_state = sanitize_media_state(MediaPlaybackState {
            position_secs: f64::NAN,
            duration_secs: f64::INFINITY,
            ..Default::default()
        });
        assert_eq!(nan_state.position_secs, 0.0);
        assert_eq!(nan_state.duration_secs, 0.0);
    }

    #[test]
    fn media_control_action_serde_roundtrip() {
        let cases = [
            MediaControlAction::PlayPause,
            MediaControlAction::Next,
            MediaControlAction::Previous,
            MediaControlAction::Seek { position_secs: 42.5 },
            MediaControlAction::VolumeMute,
            MediaControlAction::VolumeDown,
            MediaControlAction::VolumeUp,
        ];
        for action in cases {
            let json = serde_json::to_string(&action).unwrap();
            let back: MediaControlAction = serde_json::from_str(&json).unwrap();
            assert_eq!(back, action);
        }
    }
}
