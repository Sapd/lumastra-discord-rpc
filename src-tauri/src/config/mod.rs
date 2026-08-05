// SPDX-License-Identifier: MIT

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const CONFIG_FILE: &str = "config.json";

/// Disambiguates the temp file across concurrent `save` calls within this
/// process (the tray pause handler and the settings window can both write).
/// Combined with the process id, this keeps the temp path unique even across
/// processes, without needing a random source.
static TMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to write config: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to serialize config: {0}")]
    Serialize(#[from] serde_json::Error),
}

/// User settings. Contains **no secrets** — tokens live in the OS keychain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Config {
    /// Base URL of the Lumastra server, e.g. `https://media.example.com`.
    pub server_url: Option<String>,
    /// Global kill switch, toggled from the tray.
    pub paused: bool,
    pub enable_movies: bool,
    pub enable_series: bool,
    pub enable_music: bool,
    pub enable_audiobooks: bool,
    pub enable_livetv: bool,
    /// Attach a clickable link to the item. Off by default: it exposes the
    /// server hostname to anyone viewing the user's Discord profile.
    pub show_deep_links: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server_url: None,
            paused: false,
            enable_movies: true,
            enable_series: true,
            enable_music: true,
            enable_audiobooks: true,
            enable_livetv: true,
            show_deep_links: false,
        }
    }
}

impl Config {
    /// Is this session media type allowed to drive presence?
    ///
    /// The session vocabulary is deliberately wider than the public media-type
    /// table, so this matches the full set and returns `false` for anything
    /// unrecognized rather than guessing.
    pub fn is_type_enabled(&self, media_type: &str) -> bool {
        match media_type {
            "movie" => self.enable_movies,
            // `series` on the wire, `tv` in storage — both reach here.
            "series" | "tv" | "episode" | "season" => self.enable_series,
            "music" | "track" | "audio" => self.enable_music,
            "audiobook" => self.enable_audiobooks,
            // Live broadcasts share a toggle: both are open-ended streams with
            // no duration, and both render as an elapsed counter with no bar.
            "tvchannel" | "radio" => self.enable_livetv,
            _ => false,
        }
    }

    fn path(dir: &Path) -> PathBuf {
        dir.join(CONFIG_FILE)
    }

    /// Load settings, falling back to defaults for a missing or corrupt file.
    ///
    /// Never fails: a hand-edited config must not stop the app from starting.
    pub fn load(dir: &Path) -> Self {
        std::fs::read_to_string(Self::path(dir))
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default()
    }

    /// Write via a temp file + rename rather than truncating in place. The
    /// poller calls `load` every 15 seconds; a plain `fs::write` has a window
    /// where a concurrent read sees a truncated file, fails to parse, and
    /// silently falls back to defaults — clearing `server_url` and dropping
    /// presence for that tick. `rename` onto an existing path is atomic on
    /// both the platforms this app targets (POSIX rename(2); Windows
    /// `MoveFileEx` in the same volume), so a reader never observes a
    /// partial write.
    ///
    /// The temp filename is unique per call (process id + a monotonic
    /// counter): the tray pause handler and the settings window can both
    /// call `save`, and a fixed temp path would let their writes interleave
    /// through it. It stays in `dir` rather than the system temp dir —
    /// `rename` across filesystems/volumes fails, so the temp file must live
    /// on the same device as the target. On any failure the temp file is
    /// removed rather than left behind.
    pub fn save(&self, dir: &Path) -> Result<(), ConfigError> {
        std::fs::create_dir_all(dir)?;
        let contents = serde_json::to_string_pretty(self)?;

        let unique = TMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp_path = dir.join(format!("{CONFIG_FILE}.{}.{unique}.tmp", std::process::id()));

        let result = std::fs::write(&tmp_path, contents)
            .and_then(|()| std::fs::rename(&tmp_path, Self::path(dir)));

        if result.is_err() {
            let _ = std::fs::remove_file(&tmp_path);
        }

        Ok(result?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_enable_every_media_type_and_are_not_paused() {
        let config = Config::default();
        assert!(!config.paused);
        assert!(config.enable_movies);
        assert!(config.enable_series);
        assert!(config.enable_music);
        assert!(config.enable_audiobooks);
        assert!(config.enable_livetv);
        // Deep links leak the server hostname to profile viewers — opt-in only.
        assert!(!config.show_deep_links);
    }

    #[test]
    fn maps_every_session_media_type_to_its_toggle() {
        let config = Config { enable_series: false, ..Default::default() };

        // All three spellings reach the same toggle: the wire emits `series`,
        // storage uses `tv`, and episodes arrive as `episode`.
        assert!(!config.is_type_enabled("series"));
        assert!(!config.is_type_enabled("tv"));
        assert!(!config.is_type_enabled("episode"));
        assert!(config.is_type_enabled("movie"));
    }

    #[test]
    fn groups_live_broadcasts_under_the_livetv_toggle() {
        let config = Config { enable_livetv: false, ..Default::default() };
        assert!(!config.is_type_enabled("tvchannel"));
        assert!(!config.is_type_enabled("radio"));
    }

    #[test]
    fn treats_unknown_media_types_as_disabled() {
        let config = Config::default();
        assert!(!config.is_type_enabled("manga"));
        assert!(!config.is_type_enabled(""));
    }

    #[test]
    fn round_trips_through_disk() {
        let dir = std::env::temp_dir().join(format!("lrpc-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let config = Config {
            server_url: Some("https://media.example.com".into()),
            enable_music: false,
            ..Default::default()
        };
        config.save(&dir).unwrap();

        let loaded = Config::load(&dir);
        assert_eq!(loaded.server_url.as_deref(), Some("https://media.example.com"));
        assert!(!loaded.enable_music);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn falls_back_to_defaults_when_the_file_is_missing_or_corrupt() {
        let dir = std::env::temp_dir().join(format!("lrpc-missing-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        // Missing file.
        assert_eq!(Config::load(&dir).server_url, None);

        // Corrupt file must not panic — a hand-edited config should degrade to
        // defaults, not prevent the app from starting.
        std::fs::write(dir.join("config.json"), b"{ not json").unwrap();
        assert!(Config::load(&dir).enable_movies);

        std::fs::remove_dir_all(&dir).ok();
    }
}
