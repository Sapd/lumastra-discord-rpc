// SPDX-License-Identifier: MIT

use crate::mapper::{PresenceKind, PresenceState};
use discord_rich_presence::activity::{Activity, ActivityType, Assets, StatusDisplayType, Timestamps};
use discord_rich_presence::{DiscordIpc, DiscordIpcClient};

/// Discord application id. RPC client ids are public by design.
const DISCORD_APP_ID: &str = "1534510021772054598";

/// Build the Discord payload from our owned state.
///
/// Returns `Activity<'_>` borrowing from `state`: the crate's builders take
/// `Cow<'a, str>`, so the activity cannot outlive the state it describes. That
/// is exactly why the mapper produces an owned `PresenceState` — this borrow
/// happens at the last possible moment, immediately before sending.
pub fn build_activity(state: &PresenceState) -> Activity<'_> {
    let mut activity = Activity::new()
        .activity_type(match state.kind {
            PresenceKind::Watching => ActivityType::Watching,
            PresenceKind::Listening => ActivityType::Listening,
        })
        .name(&state.name)
        // Controls which field the member-list status text shows. `Details`
        // shows the item title there instead of falling back to the app
        // name, matching what the header line already shows.
        .status_display_type(StatusDisplayType::Details)
        .details(&state.details);

    if let Some(text) = &state.state {
        activity = activity.state(text);
    }

    if state.large_image.is_some() || state.large_text.is_some() {
        let mut assets = Assets::new();
        if let Some(image) = &state.large_image {
            assets = assets.large_image(image);
        }
        if let Some(text) = &state.large_text {
            assets = assets.large_text(text);
        }
        activity = activity.assets(assets);
    }

    if let Some(bounds) = state.timestamps {
        let mut timestamps = Timestamps::new().start(bounds.start);
        if let Some(end) = bounds.end {
            timestamps = timestamps.end(end);
        }
        activity = activity.timestamps(timestamps);
    }

    activity
}

/// Owns the Discord IPC connection and the last state sent. Driven by the
/// poller's `tick`.
pub struct PresenceClient {
    ipc: Option<DiscordIpcClient>,
    last_sent: Option<PresenceState>,
}

impl PresenceClient {
    pub fn new() -> Self {
        Self { ipc: None, last_sent: None }
    }

    /// Would sending `next` change anything?
    ///
    /// Discord rate-limits activity updates to roughly one per 15 seconds, and
    /// the poll runs at exactly that cadence — so re-sending an identical
    /// payload would spend the entire budget on no-ops.
    pub fn needs_update(&self, next: Option<&PresenceState>) -> bool {
        self.last_sent.as_ref() != next
    }

    /// Record what was sent. Separate from `needs_update` so both are testable
    /// without a Discord client running.
    pub fn remember(&mut self, sent: Option<PresenceState>) {
        self.last_sent = sent;
    }

    /// Is the IPC socket currently connected? Reflects the outcome of the
    /// most recent connection attempt, not a live probe — it is only as
    /// current as the last call to `apply` or `ensure_connected`.
    /// `ensure_connected` is what keeps it honest across a tick where
    /// nothing was sent; without a call to one of the two first, this can
    /// read `false` even while Discord is running (e.g. right after
    /// construction, before either has ever run). Used to drive the tray's
    /// "Discord not running" status.
    pub fn is_connected(&self) -> bool {
        self.ipc.is_some()
    }

    /// Attempt a connection if not currently connected, so `is_connected()`
    /// reflects Discord's actual availability rather than whether we happened
    /// to have something to send. Idempotent and cheap: a live connection
    /// returns immediately, and a failure just leaves us disconnected to retry
    /// on the next tick. Discord RPC connections are intended to be long-lived.
    pub fn ensure_connected(&mut self) {
        if self.ipc.is_some() {
            return;
        }
        let mut client = DiscordIpcClient::new(DISCORD_APP_ID);
        if client.connect().is_ok() {
            self.ipc = Some(client);
        }
    }

    /// Push `next` to Discord, connecting on demand.
    ///
    /// Every failure is non-fatal: Discord not running is the normal state for
    /// much of the day, and must never stop the poller. A failed send drops the
    /// connection so the next tick reconnects.
    pub fn apply(&mut self, next: Option<&PresenceState>) {
        if !self.needs_update(next) {
            return;
        }

        self.ensure_connected();

        let Some(client) = self.ipc.as_mut() else { return };

        let result = match next {
            Some(state) => client.set_activity(build_activity(state)),
            None => client.clear_activity(),
        };

        match result {
            Ok(()) => self.remember(next.cloned()),
            Err(_) => {
                // Broken pipe — Discord quit or restarted. Drop the connection
                // and forget what we sent, so the next tick reconnects and
                // re-sends rather than assuming Discord still shows it.
                self.ipc = None;
                self.last_sent = None;
            }
        }
    }

    /// Async wrapper: `apply` performs blocking socket I/O — including a
    /// handshake `read_exact` with no timeout — and a Discord client that
    /// accepts a connection and never replies would otherwise wedge a tokio
    /// worker indefinitely.
    ///
    /// Moves `self` onto a blocking thread for the call and puts it back
    /// afterward (via `std::mem::take`/`Default`, so `self` is never left
    /// empty for anyone observing it concurrently — there is no `.await`
    /// point where that could happen anyway, since this method owns the only
    /// reference). This is what keeps the same long-lived connection across
    /// ticks instead of reconnecting every time.
    ///
    /// `next` is owned rather than borrowed: the blocking closure must be
    /// `'static`, so a reference into the caller's stack cannot cross it.
    ///
    /// A panic inside the blocking task is treated the same as any other
    /// `apply` failure — `self` becomes a fresh, disconnected client rather
    /// than the panic propagating into the poller.
    pub async fn apply_async(&mut self, next: Option<PresenceState>) {
        let mut client = std::mem::take(self);
        *self = tokio::task::spawn_blocking(move || {
            client.apply(next.as_ref());
            client
        })
        .await
        .unwrap_or_default();
    }

    /// Async wrapper around `ensure_connected` — see `apply_async` for why
    /// and how.
    pub async fn ensure_connected_async(&mut self) {
        let mut client = std::mem::take(self);
        *self = tokio::task::spawn_blocking(move || {
            client.ensure_connected();
            client
        })
        .await
        .unwrap_or_default();
    }
}

impl Default for PresenceClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mapper::{PresenceKind, PresenceState, PresenceTimestamps};

    fn state() -> PresenceState {
        PresenceState {
            kind: PresenceKind::Watching,
            name: "Series".into(),
            details: "Lost".into(),
            state: Some("S04E05 · The Constant".into()),
            large_image: Some("https://image.tmdb.org/t/p/w500/lost.jpg".into()),
            large_text: Some("The Constant".into()),
            timestamps: Some(PresenceTimestamps { start: 100, end: Some(200) }),
        }
    }

    #[test]
    fn serializes_every_field_onto_the_activity() {
        let state = state();
        let activity = build_activity(&state);
        let json = serde_json::to_value(&activity).unwrap();

        // "name" and "status_display_type" both serialize under their Rust
        // field names — no `#[serde(rename = ...)]` on either in
        // discord_rich_presence::activity::Activity (verified against the
        // vendored crate source, ~/.cargo/registry/.../discord-rich-presence-1.1.0/src/activity.rs).
        assert_eq!(json["name"], "Series");
        assert_eq!(json["details"], "Lost");
        assert_eq!(json["state"], "S04E05 · The Constant");
        // The crate serializes `activity_type` under the wire key "type"
        // (`#[serde(rename = "type")]` in discord_rich_presence::activity::Activity).
        assert_eq!(json["type"], 3); // Watching
        // `StatusDisplayType::Details` = 2 — shows the item title (our
        // `details`) in the member-list status text instead of the app name.
        assert_eq!(json["status_display_type"], 2);
        assert_eq!(json["assets"]["large_image"], "https://image.tmdb.org/t/p/w500/lost.jpg");
        assert_eq!(json["assets"]["large_text"], "The Constant");
        assert_eq!(json["timestamps"]["start"], 100);
        assert_eq!(json["timestamps"]["end"], 200);
    }

    #[test]
    fn uses_discord_activity_type_two_for_listening() {
        let mut state = state();
        state.kind = PresenceKind::Listening;
        let json = serde_json::to_value(build_activity(&state)).unwrap();

        assert_eq!(json["type"], 2);
    }

    #[test]
    fn omits_timestamps_entirely_when_absent() {
        let mut state = state();
        state.timestamps = None;
        let json = serde_json::to_value(build_activity(&state)).unwrap();

        assert!(json.get("timestamps").is_none() || json["timestamps"].is_null());
    }

    #[test]
    fn reports_a_change_only_when_the_state_actually_differs() {
        let mut client = PresenceClient::new();

        assert!(client.needs_update(Some(&state())));
        client.remember(Some(state()));

        // Same content on the next poll — no Discord call. This is what keeps
        // us under the one-update-per-15s rate limit.
        assert!(!client.needs_update(Some(&state())));

        let mut moved = state();
        moved.state = Some("S04E06 · The Shape of Things to Come".into());
        assert!(client.needs_update(Some(&moved)));

        client.remember(None);
        assert!(!client.needs_update(None));
        assert!(client.needs_update(Some(&state())));
    }

    #[test]
    fn reports_disconnected_before_any_connection_attempt() {
        assert!(!PresenceClient::new().is_connected());
    }

    #[test]
    fn ensure_connected_does_not_disturb_an_already_connected_client() {
        let mut client = PresenceClient::new();
        // Simulate an already-connected state without a real Discord socket:
        // `DiscordIpcClient::new` performs no IO, it only stores the client
        // id, so this is safe in a suite that must not require a running
        // Discord.
        client.ipc = Some(DiscordIpcClient::new(DISCORD_APP_ID));

        client.ensure_connected();

        // The `self.ipc.is_some()` guard must return before ever attempting
        // another `connect()` — if it didn't, a real connect() with no
        // Discord running would fail and drop the (perfectly good)
        // connection this test set up.
        assert!(client.is_connected());
    }
}
