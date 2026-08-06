// SPDX-License-Identifier: MIT

use crate::api::client::{fetch_sessions, fetch_username, ApiError};
use crate::auth::tokens::{self, AuthError};
use crate::config::Config;
use crate::mapper::{map_presence, PresenceKind, PresenceState};
use crate::presence::client::PresenceClient;
use crate::StatusHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tauri::Manager;

/// Poll cadence. Matches Discord's activity-update rate limit — polling faster
/// cannot produce a faster status change, only more load.
const POLL_INTERVAL: Duration = Duration::from_secs(15);

/// Backoff after a network failure, so an offline server is not hammered.
const ERROR_BACKOFF: Duration = Duration::from_secs(60);

/// Clear presence after this many consecutive failed polls. One transient
/// blip should not flicker the user's status; a server that has been down
/// for minutes should not leave a stale "watching" forever.
const MAX_FAILURES_BEFORE_CLEAR: u32 = 3;

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Update the tray's status line, if managed. Absent only in contexts that
/// never ran `main.rs`'s `setup` (there are none in this app today) — never
/// worth failing a poll cycle over.
fn set_status(app: &tauri::AppHandle, text: &str) {
    if let Some(status) = app.try_state::<StatusHandle>() {
        status.set(text);
    }
}

/// What the tray should say for a session that is actively broadcasting.
/// Falls back to "Discord not running" over the item's title when the last
/// send did not actually reach a connected client — otherwise the tray would
/// claim to be showing something Discord never received.
fn presence_status_text(presence: &PresenceClient, state: &PresenceState) -> String {
    if !presence.is_connected() {
        return "Discord not running".to_string();
    }
    match state.kind {
        PresenceKind::Watching => format!("Watching {}", state.details),
        PresenceKind::Listening => format!("Listening to {}", state.details),
    }
}

/// Start the background poll loop. Runs for the lifetime of the app.
pub fn spawn(app: tauri::AppHandle) {
    tauri::async_runtime::spawn(async move {
        let http = crate::http::http_client();
        let mut presence = PresenceClient::new();
        let mut current_id: Option<String> = None;
        // The caller's own username, fetched once and cached — it does not
        // change tick to tick. `None` means "not yet known", which forces a
        // (re-)fetch: on the first tick, and again after a sign-out/re-login
        // cycle clears it below.
        let mut current_username: Option<String> = None;
        // The token pair, read from the keychain once and cached — like
        // `current_username` above, re-reading it every tick was the whole
        // problem: each read is a keychain access check, and on macOS the
        // "Always Allow" grant is bound to the binary's code signature, so a
        // dev rebuild invalidates it and the user gets re-prompted. `None`
        // forces a (re-)read: on the first tick, and again after sign-out or
        // a rejected refresh clears it below.
        let mut cached_tokens: Option<tokens::TokenResponse> = None;
        let mut consecutive_failures: u32 = 0;

        loop {
            let delay = tick(
                &app,
                &http,
                &mut presence,
                &mut current_id,
                &mut current_username,
                &mut cached_tokens,
                &mut consecutive_failures,
            )
            .await;
            tokio::time::sleep(delay).await;
        }
    });
}

/// Record a failed poll. Once failures have piled up enough to indicate a
/// real outage rather than a transient blip, clear presence rather than
/// leaving a frozen status behind — the design intent: "keep last presence
/// briefly, then clear."
async fn note_failure(
    presence: &mut PresenceClient,
    current_id: &mut Option<String>,
    consecutive_failures: &mut u32,
) {
    *consecutive_failures = consecutive_failures.saturating_add(1);
    if *consecutive_failures >= MAX_FAILURES_BEFORE_CLEAR {
        presence.apply_async(None).await;
        *current_id = None;
    }
}

/// One poll cycle. Returns how long to wait before the next.
async fn tick(
    app: &tauri::AppHandle,
    http: &reqwest::Client,
    presence: &mut PresenceClient,
    current_id: &mut Option<String>,
    current_username: &mut Option<String>,
    cached_tokens: &mut Option<tokens::TokenResponse>,
    consecutive_failures: &mut u32,
) -> Duration {
    // `logout` and `begin_login` touch the keychain directly, without going
    // through this loop's cache, and set this flag when they do. Checking
    // (and clearing) it here — rather than reading the keychain every tick —
    // is what makes sign-out/sign-in take effect within one tick while
    // keeping the steady state at zero keychain reads. `crate::AuthDirty` is
    // `main.rs`'s managed state, mirrored on `StatusHandle`'s pattern above.
    if app
        .try_state::<crate::AuthDirty>()
        .map(|dirty| dirty.take())
        .unwrap_or(false)
    {
        *cached_tokens = None;
    }

    let config_dir = match app.path().app_config_dir() {
        Ok(dir) => dir,
        Err(_) => {
            note_failure(presence, current_id, consecutive_failures).await;
            return ERROR_BACKOFF;
        }
    };
    let config = Config::load(&config_dir);

    if config.paused {
        presence.apply_async(None).await;
        *current_id = None;
        *consecutive_failures = 0;
        set_status(app, "Paused");
        return POLL_INTERVAL;
    }

    let Some(base_url) = config.server_url.clone() else {
        presence.apply_async(None).await;
        *current_id = None;
        *current_username = None;
        *consecutive_failures = 0;
        set_status(app, "No server configured");
        return POLL_INTERVAL;
    };

    if cached_tokens.is_none() {
        *cached_tokens = tokens::load_async().await;
    }
    let Some(stored) = cached_tokens.clone() else {
        presence.apply_async(None).await;
        *current_id = None;
        *current_username = None;
        *consecutive_failures = 0;
        set_status(app, "Signed out");
        return POLL_INTERVAL;
    };

    let sessions = match fetch_sessions(http, &base_url, &stored.access_token).await {
        Ok(sessions) => sessions,

        // Access token expired — refresh once and retry on the next tick
        // rather than recursing here.
        Err(ApiError::Unauthorized) => {
            // Re-read the keychain here instead of trusting the cached pair
            // for the refresh decision below. `logout` (a Tauri command)
            // clears the keychain directly, without going through this
            // cache, so the cache can be stale precisely when it matters
            // most: if the still-cached refresh token were used as-is, a
            // still-valid-on-the-server refresh would succeed and silently
            // re-persist tokens the user just signed out of. Re-reading here
            // — on the request failure that this rare path already is,
            // rather than every tick — is what notices that keychain change.
            *cached_tokens = tokens::load_async().await;
            let Some(fresh_stored) = cached_tokens.clone() else {
                presence.apply_async(None).await;
                *current_id = None;
                *current_username = None;
                *consecutive_failures = 0;
                set_status(app, "Signed out");
                return POLL_INTERVAL;
            };

            let Some(refresh_token) = fresh_stored.refresh_token.as_deref() else {
                let _ = tokens::clear_async().await;
                *cached_tokens = None;
                presence.apply_async(None).await;
                *current_id = None;
                *current_username = None;
                *consecutive_failures = 0;
                set_status(app, "Signed out");
                return POLL_INTERVAL;
            };

            match tokens::refresh(http, &base_url, refresh_token).await {
                Ok(fresh) => {
                    let persisted = tokens::store_async(fresh.clone()).await.is_ok();
                    *cached_tokens = Some(fresh);

                    if !persisted {
                        // The refresh itself succeeded, so this session is
                        // still valid — keep using the fresh tokens from
                        // memory rather than treating this as a failed poll
                        // or signing the user out over a local write error.
                        // But the *next* 401 re-reads the keychain a few
                        // lines up (deliberately, to notice an external
                        // sign-out), and a persist that silently failed here
                        // means that re-read hands back this now-retired
                        // refresh token instead: the server rotates on every
                        // refresh and revokes the whole device session when
                        // a retired token is presented. A discarded `Err`
                        // used to hide exactly that setup — surface it in
                        // the tray instead.
                        set_status(app, "Sign-in not saved — will be needed again after restart");
                        return Duration::from_secs(1);
                    }

                    // A successful refresh still counts as a failed poll: if
                    // the server keeps returning 401 while refreshing keeps
                    // succeeding, this is the same fast-loop-burning-tokens
                    // shape already handled for 403, just arriving via 401.
                    // A genuinely-expired token recovers on the very next
                    // tick (consecutive_failures resets to 0 on success
                    // below), so a healthy flow never reaches the threshold.
                    note_failure(presence, current_id, consecutive_failures).await;
                    if *consecutive_failures < MAX_FAILURES_BEFORE_CLEAR {
                        // Come straight back rather than waiting a full interval.
                        return Duration::from_secs(1);
                    }

                    set_status(app, "Server unreachable");
                    return ERROR_BACKOFF;
                }
                // Refresh rejected: the device session is gone. Drop the
                // tokens and stop — retrying would be futile, and the server
                // revokes on retired-token reuse.
                Err(AuthError::RefreshRejected) => {
                    let _ = tokens::clear_async().await;
                    *cached_tokens = None;
                    presence.apply_async(None).await;
                    *current_id = None;
                    *current_username = None;
                    *consecutive_failures = 0;
                    set_status(app, "Signed out");
                    return POLL_INTERVAL;
                }
                Err(_) => {
                    set_status(app, "Server unreachable");
                    note_failure(presence, current_id, consecutive_failures).await;
                    return ERROR_BACKOFF;
                }
            }
        }

        // Permanently denied (revoked grant, disabled user, WAF rule) — not
        // refreshable. Refreshing here would burn a token rotation every
        // poll, forever. Back off instead; the tray status tells the user.
        Err(ApiError::Forbidden) => {
            set_status(app, "Server unreachable");
            note_failure(presence, current_id, consecutive_failures).await;
            return ERROR_BACKOFF;
        }

        // Server unreachable. Keep the last presence for a few cycles rather
        // than flickering the status on a transient blip, then clear it.
        Err(_) => {
            set_status(app, "Server unreachable");
            note_failure(presence, current_id, consecutive_failures).await;
            return ERROR_BACKOFF;
        }
    };

    *consecutive_failures = 0;

    // The username rarely changes and never within a session, so it is
    // fetched once and cached rather than on every tick — but it must be
    // known before anything is broadcast. With no identity to filter
    // against, every session in the response would look unowned, and the
    // safe behavior is no presence rather than guessing.
    if current_username.is_none() {
        match fetch_username(http, &base_url, &stored.access_token).await {
            Ok(username) => *current_username = Some(username),
            Err(_) => {
                set_status(app, "Server unreachable");
                note_failure(presence, current_id, consecutive_failures).await;
                return ERROR_BACKOFF;
            }
        }
    }
    let username = current_username
        .as_deref()
        .expect("just populated above when absent");

    // Attempt a connection before deriving the status text below, rather
    // than letting `is_connected()` infer liveness from send history.
    // `apply(None)` on the idle/nothing-playing path early-returns via
    // `needs_update` without ever trying to connect, which previously left
    // `is_connected()` false — and the tray reporting "Discord not running"
    // — on a fresh start with nothing playing, even with Discord running.
    presence.ensure_connected_async().await;

    match map_presence(&sessions, &config, now_unix(), current_id.as_deref(), username) {
        Some((id, state)) => {
            presence.apply_async(Some(state.clone())).await;
            set_status(app, &presence_status_text(presence, &state));
            *current_id = Some(id);
        }
        None => {
            presence.apply_async(None).await;
            *current_id = None;
            set_status(
                app,
                if presence.is_connected() {
                    "Nothing playing"
                } else {
                    "Discord not running"
                },
            );
        }
    }

    POLL_INTERVAL
}
