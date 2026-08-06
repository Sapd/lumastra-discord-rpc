// SPDX-License-Identifier: MIT
//
// Storage backend for OAuth tokens: OS keychain (release) vs. a file in the
// app config dir (debug). See the `debug_backend` module below for why the
// split exists and why it must never be collapsed.

use serde::{Deserialize, Serialize};

/// Keychain service name — the entry appears under this in Keychain Access
/// and Windows Credential Manager. Release builds only.
#[cfg(not(debug_assertions))]
const KEYCHAIN_SERVICE: &str = "org.lumastra.discord-rpc";
#[cfg(not(debug_assertions))]
const KEYCHAIN_USER: &str = "tokens";

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("network error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("invalid server URL: {0}")]
    Url(#[from] url::ParseError),
    #[error("keychain error: {0}")]
    Keyring(#[from] keyring::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    /// The user rejected the authorization request.
    #[error("authorization denied")]
    Denied,
    /// The device code expired before approval.
    #[error("device code expired")]
    Expired,
    /// The refresh token was rejected — re-login required. Never retried: the
    /// server revokes the whole device session on retired-token reuse, so a
    /// retry loop would be both futile and destructive.
    #[error("refresh rejected")]
    RefreshRejected,
    #[error("server returned {0}")]
    Status(u16),
    /// The `spawn_blocking` task running a keychain call panicked (or was
    /// cancelled by a runtime shutdown) before it could return. Never
    /// expected in practice — `store`/`load`/`clear` themselves don't panic
    /// — but the async wrappers must turn a `JoinError` into *some* result
    /// rather than propagating the panic into the poller.
    #[error("keychain task did not complete")]
    BlockingTaskFailed,
    /// Debug backend only: the dev token file could not be read, written, or
    /// removed (permissions, disk full, etc — anything other than "file
    /// doesn't exist", which is not an error).
    #[cfg(debug_assertions)]
    #[error("dev token file io error: {0}")]
    Io(#[from] std::io::Error),
    /// Debug backend only: the platform's governing environment variable
    /// (`HOME` on macOS/Linux, `APPDATA` on Windows) isn't set, so the dev
    /// token file's location can't be resolved.
    #[cfg(debug_assertions)]
    #[error("could not resolve app config directory")]
    NoConfigDir,
}

/// Token pair as returned by `/oauth/token`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: Option<u64>,
}

/// Whether a `store()` that reported success actually round-trips: compares
/// what was stored against what an immediate `load()` returns.
///
/// A store/load pair that disagree is exactly the ad-hoc-signature case
/// described below: macOS binds a Keychain ACL to the code signature, and an
/// ad-hoc signature is derived from the binary's own hash, so a `store()`
/// that reports success can still be unreadable (or resolve to a stale
/// value) on the very next `load()`. Kept as a pure comparison, separate
/// from the read-back call itself, so it's testable without touching the
/// real keychain — this crate deliberately has no keychain tests (the
/// "Always Allow" prompt they'd risk triggering can hang).
pub fn verify_round_trip(stored: &TokenResponse, loaded: Option<&TokenResponse>) -> bool {
    loaded == Some(stored)
}

#[cfg(not(debug_assertions))]
fn entry() -> Result<keyring::Entry, AuthError> {
    Ok(keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_USER)?)
}

/// Persist tokens to the OS keychain. Never write these to the config file.
#[cfg(not(debug_assertions))]
pub fn store(tokens: &TokenResponse) -> Result<(), AuthError> {
    entry()?.set_password(&serde_json::to_string(tokens)?)?;
    Ok(())
}

/// Read tokens, or `None` when absent or unreadable.
#[cfg(not(debug_assertions))]
pub fn load() -> Option<TokenResponse> {
    entry()
        .ok()?
        .get_password()
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
}

/// Remove stored tokens. Absent entries are not an error — this runs on logout
/// and on a rejected refresh, either of which may find nothing there.
#[cfg(not(debug_assertions))]
pub fn clear() -> Result<(), AuthError> {
    match entry()?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Debug-build stand-ins for `store`/`load`/`clear`, backed by
/// `debug_backend` instead of the OS keychain. See that module for why.
#[cfg(debug_assertions)]
pub fn store(tokens: &TokenResponse) -> Result<(), AuthError> {
    debug_backend::store(tokens)
}

#[cfg(debug_assertions)]
pub fn load() -> Option<TokenResponse> {
    debug_backend::load()
}

#[cfg(debug_assertions)]
pub fn clear() -> Result<(), AuthError> {
    debug_backend::clear()
}

// Debug builds are ad-hoc signed on macOS (`Signature=adhoc, linker-signed`),
// and an ad-hoc signature is derived from the binary's own hash. macOS ties a
// Keychain "Always Allow" grant to the app's code signature, so every
// `cargo build` produces what the OS considers a *different application* —
// the saved grant never matches, and the user is re-prompted on every
// launch (and that prompt has hung before, needing a kill). Release builds
// are properly signed with a stable identity across rebuilds, so they keep
// using the Keychain exactly as before, unmodified.
//
// Do not "simplify" this by pointing release at this module too — doing so
// puts long-lived OAuth tokens in a plaintext file instead of the Keychain
// for real users.
#[cfg(debug_assertions)]
mod debug_backend {
    use super::{AuthError, TokenResponse};
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    const TOKEN_FILE: &str = "dev-tokens.json";

    /// Matches the Tauri `identifier` in `tauri.conf.json`; used to build the
    /// OS-specific config directory below.
    const APP_IDENTIFIER: &str = "org.lumastra.discord-rpc";

    /// Disambiguates the temp file across concurrent writers within this
    /// process, same rationale as `Config::save`'s counter.
    static TMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

    /// Resolve the app's config directory, mirroring what Tauri's
    /// `app.path().app_config_dir()` returns **on each platform** — without
    /// adding a `directories` dependency. `config.json` already lives here.
    ///
    /// - **macOS:** `$HOME/Library/Application Support/<identifier>`
    /// - **Windows:** `%APPDATA%\<identifier>` — never falls back to `HOME`
    ///   (Git for Windows sets `HOME` too, but that is not where Tauri, or
    ///   any native Windows app, keeps per-user config)
    /// - **Linux:** `$XDG_CONFIG_HOME/<identifier>`, falling back to
    ///   `$HOME/.config/<identifier>` when `XDG_CONFIG_HOME` is unset *or
    ///   empty* (an empty value must be treated as unset per the XDG spec)
    ///
    /// Returns `None` when the platform's governing variable is unavailable;
    /// callers must treat that as "no store available" (`None` from `load`,
    /// an error from `store`/`clear`) rather than panicking.
    fn config_dir() -> Option<PathBuf> {
        config_dir_from(
            std::env::var_os("HOME"),
            std::env::var_os("APPDATA"),
            std::env::var_os("XDG_CONFIG_HOME"),
        )
    }

    /// Pure resolution logic behind [`config_dir`], parameterized over the
    /// relevant environment variables so it's testable without mutating
    /// global process state — env mutation is racy under the multi-threaded
    /// test runner, and `std::env::set_var` is `unsafe` in recent editions.
    fn config_dir_from(
        home: Option<OsString>,
        appdata: Option<OsString>,
        xdg_config_home: Option<OsString>,
    ) -> Option<PathBuf> {
        #[cfg(target_os = "macos")]
        {
            let _ = (&appdata, &xdg_config_home);
            Some(
                PathBuf::from(home?)
                    .join("Library")
                    .join("Application Support")
                    .join(APP_IDENTIFIER),
            )
        }

        #[cfg(target_os = "windows")]
        {
            let _ = (&home, &xdg_config_home);
            Some(PathBuf::from(appdata?).join(APP_IDENTIFIER))
        }

        #[cfg(all(unix, not(target_os = "macos")))]
        {
            let _ = &appdata;
            let base = match xdg_config_home {
                Some(value) if !value.is_empty() => PathBuf::from(value),
                _ => PathBuf::from(home?).join(".config"),
            };
            Some(base.join(APP_IDENTIFIER))
        }
    }

    fn token_path(dir: &Path) -> PathBuf {
        dir.join(TOKEN_FILE)
    }

    /// Explicitly restrict the file to owner-only access rather than relying
    /// on the process umask (which callers of this binary don't control).
    /// A no-op on non-Unix targets, where this backend still functions but
    /// without the permission hardening — this app currently only ships a
    /// macOS build.
    fn restrict_to_owner(path: &Path) -> std::io::Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(path)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(path, perms)?;
        }
        #[cfg(not(unix))]
        {
            let _ = path;
        }
        Ok(())
    }

    pub fn store(tokens: &TokenResponse) -> Result<(), AuthError> {
        let dir = config_dir().ok_or(AuthError::NoConfigDir)?;
        store_in(&dir, tokens)
    }

    pub fn load() -> Option<TokenResponse> {
        load_from(&config_dir()?)
    }

    pub fn clear() -> Result<(), AuthError> {
        match config_dir() {
            Some(dir) => clear_in(&dir),
            // No resolvable config dir means nothing could have been
            // written there either — same "absent is success" contract.
            None => Ok(()),
        }
    }

    /// Write via temp file + rename, matching `Config::save`'s pattern:
    /// atomic on POSIX `rename(2)`, and a concurrent `load` never observes a
    /// truncated file.
    fn store_in(dir: &Path, tokens: &TokenResponse) -> Result<(), AuthError> {
        std::fs::create_dir_all(dir)?;
        let contents = serde_json::to_string(tokens)?;

        let unique = TMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp_path = dir.join(format!("{TOKEN_FILE}.{}.{unique}.tmp", std::process::id()));

        let result = std::fs::write(&tmp_path, &contents)
            .and_then(|()| restrict_to_owner(&tmp_path))
            .and_then(|()| std::fs::rename(&tmp_path, token_path(dir)));

        if result.is_err() {
            let _ = std::fs::remove_file(&tmp_path);
        }

        Ok(result?)
    }

    fn load_from(dir: &Path) -> Option<TokenResponse> {
        std::fs::read_to_string(token_path(dir))
            .ok()
            .and_then(|raw| serde_json::from_str(&raw).ok())
    }

    fn clear_in(dir: &Path) -> Result<(), AuthError> {
        match std::fs::remove_file(token_path(dir)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn temp_dir(label: &str) -> PathBuf {
            let dir = std::env::temp_dir().join(format!(
                "lrpc-tokens-test-{label}-{}-{}",
                std::process::id(),
                TMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&dir).unwrap();
            dir
        }

        fn sample_tokens() -> TokenResponse {
            TokenResponse {
                access_token: "access-123".into(),
                refresh_token: Some("refresh-456".into()),
                expires_in: Some(3600),
            }
        }

        #[test]
        fn round_trips_a_token_response_through_store_and_load() {
            let dir = temp_dir("roundtrip");
            let tokens = sample_tokens();

            store_in(&dir, &tokens).unwrap();
            let loaded = load_from(&dir);

            assert_eq!(loaded, Some(tokens));
            std::fs::remove_dir_all(&dir).ok();
        }

        #[test]
        fn load_returns_none_when_the_file_is_absent() {
            let dir = temp_dir("missing");
            assert_eq!(load_from(&dir), None);
            std::fs::remove_dir_all(&dir).ok();
        }

        #[test]
        fn load_returns_none_for_a_corrupt_file_rather_than_panicking() {
            let dir = temp_dir("corrupt");
            std::fs::write(token_path(&dir), b"{ not json").unwrap();

            assert_eq!(load_from(&dir), None);
            std::fs::remove_dir_all(&dir).ok();
        }

        #[test]
        fn clear_removes_the_file_and_is_a_noop_when_already_gone() {
            let dir = temp_dir("clear");
            store_in(&dir, &sample_tokens()).unwrap();
            assert!(token_path(&dir).exists());

            clear_in(&dir).unwrap();
            assert!(!token_path(&dir).exists());

            // Second clear finds nothing there — still success.
            clear_in(&dir).unwrap();
            std::fs::remove_dir_all(&dir).ok();
        }

        #[test]
        #[cfg(unix)]
        fn the_created_file_is_owner_only() {
            use std::os::unix::fs::PermissionsExt;

            let dir = temp_dir("perms");
            store_in(&dir, &sample_tokens()).unwrap();

            let mode = std::fs::metadata(token_path(&dir)).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);

            std::fs::remove_dir_all(&dir).ok();
        }

        // `config_dir_from` is exercised directly (rather than through
        // `config_dir`, which reads real process env) so these tests never
        // mutate global env — see the doc comment on `config_dir_from`.

        #[cfg(target_os = "macos")]
        #[test]
        fn resolves_under_library_application_support_on_macos() {
            let dir = config_dir_from(Some(OsString::from("/Users/test")), None, None).unwrap();

            assert!(dir.ends_with(APP_IDENTIFIER));
            assert!(dir.to_string_lossy().contains("Library/Application Support"));
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn returns_none_without_home_on_macos() {
            assert_eq!(config_dir_from(None, None, None), None);
        }

        #[cfg(target_os = "windows")]
        #[test]
        fn resolves_under_appdata_on_windows() {
            let dir = config_dir_from(
                None,
                Some(OsString::from(r"C:\Users\test\AppData\Roaming")),
                None,
            )
            .unwrap();

            assert!(dir.ends_with(APP_IDENTIFIER));
            assert!(!dir.to_string_lossy().contains("Library/Application Support"));
        }

        #[cfg(target_os = "windows")]
        #[test]
        fn returns_none_without_appdata_on_windows_even_when_home_is_set() {
            // Git for Windows sets HOME; it must never be used as a
            // fallback for the Windows config directory.
            assert_eq!(
                config_dir_from(Some(OsString::from(r"C:\Users\test")), None, None),
                None
            );
        }

        #[cfg(all(unix, not(target_os = "macos")))]
        #[test]
        fn resolves_under_xdg_config_home_on_linux() {
            let dir = config_dir_from(
                Some(OsString::from("/home/test")),
                None,
                Some(OsString::from("/home/test/.config")),
            )
            .unwrap();

            assert!(dir.ends_with(APP_IDENTIFIER));
        }

        #[cfg(all(unix, not(target_os = "macos")))]
        #[test]
        fn falls_back_to_home_dot_config_when_xdg_config_home_is_unset_or_empty() {
            let via_unset =
                config_dir_from(Some(OsString::from("/home/test")), None, None).unwrap();
            assert!(via_unset.ends_with(APP_IDENTIFIER));
            assert!(via_unset.to_string_lossy().contains(".config"));

            let via_empty = config_dir_from(
                Some(OsString::from("/home/test")),
                None,
                Some(OsString::new()),
            )
            .unwrap();
            assert_eq!(via_unset, via_empty);
        }

        #[cfg(all(unix, not(target_os = "macos")))]
        #[test]
        fn returns_none_without_home_or_xdg_config_home_on_linux() {
            assert_eq!(config_dir_from(None, None, None), None);
        }
    }
}

/// Async wrapper: the underlying keyring call is blocking and can sit on a
/// modal OS auth prompt indefinitely, which would wedge a tokio worker.
pub async fn load_async() -> Option<TokenResponse> {
    tokio::task::spawn_blocking(load).await.ok().flatten()
}

/// Async wrapper around `store` — see `load_async`. Takes an owned
/// `TokenResponse` (rather than `&TokenResponse`) because it has to move
/// into the blocking task's `'static` closure.
pub async fn store_async(tokens: TokenResponse) -> Result<(), AuthError> {
    tokio::task::spawn_blocking(move || store(&tokens))
        .await
        .unwrap_or(Err(AuthError::BlockingTaskFailed))
}

/// Async wrapper around `clear` — see `load_async`.
pub async fn clear_async() -> Result<(), AuthError> {
    tokio::task::spawn_blocking(clear)
        .await
        .unwrap_or(Err(AuthError::BlockingTaskFailed))
}

/// Exchange a refresh token for a fresh pair.
///
/// The server **rotates** refresh tokens, so the returned `refresh_token` must
/// replace the stored one. Reusing a retired token revokes the device session.
pub async fn refresh(
    http: &reqwest::Client,
    base_url: &str,
    refresh_token: &str,
) -> Result<TokenResponse, AuthError> {
    let url = crate::urls::join_path(base_url, "oauth/token")?;

    let response = http
        .post(url)
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", super::device_flow::CLIENT_ID),
        ])
        .send()
        .await?;

    match response.status().as_u16() {
        200 => Ok(response.json().await?),
        400 | 401 => Err(AuthError::RefreshRejected),
        other => Err(AuthError::Status(other)),
    }
}

#[cfg(test)]
mod verify_round_trip_tests {
    use super::*;

    fn sample() -> TokenResponse {
        TokenResponse {
            access_token: "access-123".into(),
            refresh_token: Some("refresh-456".into()),
            expires_in: Some(3600),
        }
    }

    #[test]
    fn true_when_the_read_back_matches_what_was_stored() {
        let stored = sample();
        let loaded = sample();
        assert!(verify_round_trip(&stored, Some(&loaded)));
    }

    #[test]
    fn false_when_nothing_reads_back() {
        // The unsigned-build failure mode: `store()` reports `Ok`, but the
        // entry it wrote isn't readable under this process's signature.
        let stored = sample();
        assert!(!verify_round_trip(&stored, None));
    }

    #[test]
    fn false_when_the_read_back_is_a_stale_value() {
        // Not just "nothing there" — a signature mismatch can also resolve
        // to a leftover entry from a previous install/signature.
        let stored = sample();
        let stale = TokenResponse {
            access_token: "old-access".into(),
            ..sample()
        };
        assert!(!verify_round_trip(&stored, Some(&stale)));
    }
}
