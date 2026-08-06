// SPDX-License-Identifier: MIT

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod api;
mod auth;
mod config;
mod http;
mod urls;
mod mapper;
mod poller;
mod presence;

use tauri::{
    menu::{CheckMenuItem, Menu, MenuItem},
    tray::TrayIconBuilder,
    Manager,
};

/// Cheap handle to the disabled status line at the top of the tray menu,
/// stashed in Tauri's managed state so the poller — which only has an
/// `AppHandle`, not this closure's captures — can update it. Mirrors how
/// `pause_handle` below updates the checkbox item directly; muda has no
/// higher-level way to do either.
///
/// This is the app's only failure feedback surface: several states (bad
/// server URL, signed out, server unreachable, Discord not running) were
/// previously silent forever. A logging framework is a separate decision;
/// this line is the cheap alternative that actually reaches the user.
pub struct StatusHandle(pub MenuItem<tauri::Wry>);

impl StatusHandle {
    pub fn set(&self, text: &str) {
        let _ = self.0.set_text(text);
    }
}

/// Set by `logout` and `begin_login` when they touch the keychain directly,
/// out from under the poller's cached token pair (see `poller.rs`). Mirrors
/// `StatusHandle` above: managed state the poller reads via its
/// `AppHandle`, since it has no other way to hear about a command run from
/// the settings window.
///
/// Without this, sign-out/sign-in would sit behind the poller's cache until
/// something else happened to force a re-read — for sign-out specifically,
/// that could be minutes away, during which the app keeps broadcasting a
/// presence the user just tried to end. A single atomic flag is enough:
/// no channel or mutex around the token pair is needed, since the poller
/// only ever needs to know "check the keychain again", not the new value.
pub struct AuthDirty(std::sync::atomic::AtomicBool);

impl AuthDirty {
    pub fn new() -> Self {
        Self(std::sync::atomic::AtomicBool::new(false))
    }

    /// Called by `logout`/`begin_login` after they touch the keychain.
    pub fn mark(&self) {
        self.0.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Called once per poll tick: reports whether the flag was set since the
    /// last check, clearing it atomically so it is only ever consumed once.
    pub fn take(&self) -> bool {
        self.0.swap(false, std::sync::atomic::Ordering::SeqCst)
    }
}

impl Default for AuthDirty {
    fn default() -> Self {
        Self::new()
    }
}

#[tauri::command]
fn get_config(app: tauri::AppHandle) -> Result<config::Config, String> {
    let dir = app.path().app_config_dir().map_err(|e| e.to_string())?;
    Ok(config::Config::load(&dir))
}

#[tauri::command]
fn save_config(app: tauri::AppHandle, config: config::Config) -> Result<(), String> {
    // A URL that fails to parse, or lacks a scheme `join_path` can build on
    // (`media.example.com` with no `https://`), fails every poll forever with
    // no feedback anywhere else in the app — reject it here instead, where
    // the settings page can show it immediately.
    if let Some(url) = &config.server_url {
        let parsed = url::Url::parse(url)
            .map_err(|_| "Server URL is not a valid URL".to_string())?;
        if parsed.scheme() != "http" && parsed.scheme() != "https" {
            return Err("Server URL must start with http:// or https://".to_string());
        }
    }

    let dir = app.path().app_config_dir().map_err(|e| e.to_string())?;
    config.save(&dir).map_err(|e| e.to_string())
}

#[tauri::command]
fn get_auth_status() -> bool {
    auth::tokens::load().is_some()
}

#[tauri::command]
fn logout(app: tauri::AppHandle) -> Result<(), String> {
    auth::tokens::clear().map_err(|e| e.to_string())?;
    // Tell the poller its cached token pair is stale so the broadcast stops
    // within one tick instead of continuing on the still-valid cached
    // access token until it happens to expire on its own.
    if let Some(dirty) = app.try_state::<AuthDirty>() {
        dirty.mark();
    }
    Ok(())
}

/// Where a successful `begin_login`'s tokens ended up, returned to the
/// settings UI so it can explain what's actually going on rather than a
/// flat yes/no — see the call site below.
///
/// - `Keychain`: stored in the OS keychain — the common case on a signed
///   release build (and the only state debug builds never report, since
///   they never touch the keychain at all). No message needed.
/// - `FileFallback`: the keychain write didn't round-trip (the
///   ad-hoc-signature symptom — see `auth::tokens`), so this run fell back
///   to the same `0600` file the debug backend already uses. The login is
///   still safely on disk; the UI should say so calmly, not raise an alarm.
/// - `NotPersisted`: neither backend could hold the tokens (a real keychain
///   error, or the fallback file write also failed). The sign-in itself
///   still worked for this run — the poller has the tokens in memory — it
///   just won't survive a restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
enum PersistOutcome {
    Keychain,
    FileFallback,
    NotPersisted,
}

/// Outcome of a successful `begin_login`, returned to the settings UI.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct LoginResult {
    user_code: String,
    persist: PersistOutcome,
}

/// Start the device flow: open the pre-filled verification URL in the user's
/// browser, then poll until approval.
///
/// Emits a `device-code` event as soon as the code is obtained and the
/// browser-open has been attempted — *before* polling, not after — so the UI
/// can show the code and URL immediately. If the browser fails to open, the
/// user would otherwise stare at "Waiting…" for the whole device-code
/// lifetime with nothing to act on; the old code returned `user_code` only
/// on success, by which point it was too late to be useful as a fallback.
#[tauri::command]
async fn begin_login(app: tauri::AppHandle, server_url: String) -> Result<LoginResult, String> {
    use tauri::Emitter;
    use tauri_plugin_opener::OpenerExt;

    let http = http::http_client();
    let device = auth::device_flow::start_device_flow(&http, &server_url)
        .await
        .map_err(|e| e.to_string())?;

    // Prefer the pre-filled URL so the user never types the code.
    let target = device
        .verification_uri_complete
        .clone()
        .unwrap_or_else(|| device.verification_uri.clone());
    let browser_opened = app.opener().open_url(target, None::<&str>).is_ok();

    let _ = app.emit(
        "device-code",
        serde_json::json!({
            "userCode": device.user_code,
            "verificationUri": device.verification_uri,
            "browserOpened": browser_opened,
        }),
    );

    // RFC 8628 §3.5: the server MAY omit `interval`; fall back to the spec default
    // rather than repeating the literal here.
    let interval = device
        .interval
        .unwrap_or(auth::device_flow::DEFAULT_INTERVAL_SECONDS);
    let tokens = auth::device_flow::poll_for_token(
        &http,
        &server_url,
        &device.device_code,
        interval,
        device.expires_in,
    )
    .await
    .map_err(|e| e.to_string())?;

    // `tokens::store` itself tries the keychain first and falls back to the
    // file backend when a round-trip proves the keychain entry it just
    // wrote isn't actually readable back — on macOS that's what an ad-hoc
    // (unsigned) code signature does, since the Keychain ACL is bound to
    // the signature. Rather than trusting a bare `Ok` (which the old
    // pre-fallback code did, silently losing the login), ask which backend
    // actually ended up holding the tokens so the UI can say so.
    let persist = match auth::tokens::store(&tokens) {
        Ok(()) if auth::tokens::keychain_active() => PersistOutcome::Keychain,
        Ok(()) => PersistOutcome::FileFallback,
        // Neither backend could hold the tokens. The sign-in itself still
        // worked for this run — the poller has the tokens in memory — so
        // this doesn't fail the command, same as the file-fallback case;
        // the UI just won't get to skip its restart warning.
        Err(_) => PersistOutcome::NotPersisted,
    };
    // Symmetric with `logout`: without this, a fresh sign-in would sit
    // behind the poller's cached `None` (or a stale pre-logout pair) until
    // something else forced a re-read, leaving the app idle after the user
    // just signed in.
    if let Some(dirty) = app.try_state::<AuthDirty>() {
        dirty.mark();
    }
    Ok(LoginResult { user_code: device.user_code, persist })
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            // A second launch surfaces the existing window instead of starting
            // a second tray icon and a second Discord IPC connection.
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
            }
        }))
        .setup(|app| {
            // Tray-only: no dock icon on macOS. Without this the app appears in
            // the dock and Cmd-Tab, which is wrong for a background bridge.
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);

            let config_dir = app.path().app_config_dir()?;
            let config = config::Config::load(&config_dir);

            // Disabled: it is a status display, not a clickable item.
            let status_item =
                MenuItem::with_id(app, "status", "Starting…", false, None::<&str>)?;
            app.manage(StatusHandle(status_item.clone()));
            app.manage(AuthDirty::new());

            let pause_item = CheckMenuItem::with_id(
                app,
                "pause",
                "Pause presence",
                true,
                config.paused,
                None::<&str>,
            )?;
            let settings_item =
                MenuItem::with_id(app, "settings", "Settings…", true, None::<&str>)?;
            let quit_item = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(
                app,
                &[&status_item, &pause_item, &settings_item, &quit_item],
            )?;

            // muda (the native menu backend) does not auto-toggle an
            // NSMenuItem's checkmark on click — clicking only fires the
            // event — so the handler below updates it explicitly via this
            // handle. `CheckMenuItem` is a cheap handle, safe to clone into
            // the closure.
            let pause_handle = pause_item.clone();

            TrayIconBuilder::new()
                .icon(app.default_window_icon().unwrap().clone())
                .menu(&menu)
                .show_menu_on_left_click(true)
                .on_menu_event(move |app, event| match event.id().as_ref() {
                    "pause" => {
                        if let Ok(dir) = app.path().app_config_dir() {
                            let mut config = config::Config::load(&dir);
                            config.paused = !config.paused;
                            let _ = config.save(&dir);
                            // muda does not toggle the native checkmark for us.
                            let _ = pause_handle.set_checked(config.paused);
                        }
                    }
                    "settings" => {
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                    "quit" => app.exit(0),
                    _ => {}
                })
                .build(app)?;

            // Start hidden. The tray is the entry point, not a window.
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.hide();
            }

            poller::spawn(app.handle().clone());

            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing the settings window hides it; quitting is a tray action.
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .invoke_handler(tauri::generate_handler![
            get_config,
            save_config,
            get_auth_status,
            logout,
            begin_login
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
