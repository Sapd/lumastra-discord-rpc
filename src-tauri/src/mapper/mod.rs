// SPDX-License-Identifier: MIT

pub mod types;

use crate::api::model::Session;
use crate::config::Config;
pub use types::{PresenceKind, PresenceState, PresenceTimestamps};

/// Discord asset key for the bundled logo, uploaded to the Discord application's
/// Rich Presence art assets. Used whenever no public image URL is available.
pub const FALLBACK_ASSET_KEY: &str = "lumastra";

/// Separator between the segments of the second line.
const SEP: &str = " · ";

/// Build the presence for the current session list.
///
/// Pure: `now_unix` is injected rather than read from the clock, so every case
/// below is deterministically testable.
///
/// `current_id` is the `__id` currently being broadcast, if any. It makes
/// selection sticky — see [`select`].
///
/// `username` is the authenticated caller's own username, from
/// `fetch_username`/`GET /api/v1/user/profile`. `GET /api/v1/sessions?scope=mine`
/// can return sessions belonging to other users (an admin, anyone with watch
/// permission, or public sessions), so this is the client-side backstop that
/// keeps another person's activity off the caller's Discord profile — see
/// [`select`]. Compared case-insensitively.
///
/// Returns the selected session's `__id` alongside its presence so the caller
/// can feed it back as `current_id` on the next tick.
pub fn map_presence(
    sessions: &[Session],
    config: &Config,
    now_unix: i64,
    current_id: Option<&str>,
    username: &str,
) -> Option<(String, PresenceState)> {
    if config.paused {
        return None;
    }

    let session = select(sessions, config, current_id, username)?;
    Some((session.id.clone(), build_state(session, now_unix)))
}

/// Pick the one session to broadcast.
///
/// 1. Stay on the session already being broadcast, if it is still eligible.
/// 2. Otherwise prefer a playing session over a paused one.
/// 3. Break remaining ties on `__id` lexicographically.
///
/// Step 1 exists because the payload carries no timestamp to order by, and step
/// 3 alone would let two equally-ranked sessions swap places on any poll where
/// the server changed their order. Stickiness removes that class of flapping
/// outright.
///
/// Eligibility folds in ownership alongside the media-type toggle — a session
/// that does not belong to `username` is never eligible, so it can never be
/// selected even when it is the only session playing. This has to live inside
/// the one eligibility predicate rather than as a separate pre-filter: two
/// notions of "eligible" drift apart over time, and drift here is exactly how
/// another user's session would end up on the caller's Discord profile.
fn select<'a>(
    sessions: &'a [Session],
    config: &Config,
    current_id: Option<&str>,
    username: &str,
) -> Option<&'a Session> {
    let eligible = || {
        sessions.iter().filter(|s| {
            config.is_type_enabled(&s.media_type) && s.username.eq_ignore_ascii_case(username)
        })
    };

    let is_playing = |s: &Session| s.play_is_playing.unwrap_or(false);

    // 1. Sticky — but only while the current session is still playing. A paused
    //    session must not pin the status when something else is actually on.
    if let Some(id) = current_id {
        if let Some(current) = eligible().find(|s| s.id == id) {
            if is_playing(current) || !eligible().any(is_playing) {
                return Some(current);
            }
        }
    }

    // 2 & 3. Playing first, then lexicographic by id.
    eligible().min_by(|a, b| {
        is_playing(b)
            .cmp(&is_playing(a))
            .then_with(|| a.id.cmp(&b.id))
    })
}

/// Discord rejects `details`/`state` longer than 128 characters, and an
/// oversized payload can blow the 64 KB IPC frame — after which the client
/// would re-send the same rejected payload every tick forever. Clamp on the
/// way in; the server's strings are untrusted input.
fn clamp(text: &str) -> String {
    const MAX: usize = 120;
    let cleaned: String = text
        .chars()
        // Strip Cc control characters plus the Cf format characters used for
        // bidi manipulation (RIGHT-TO-LEFT OVERRIDE and friends), zero-width
        // spaces/joiners, directional isolates, and the BOM. `is_control()`
        // alone only covers Cc — Cf format characters are a distinct
        // category and would otherwise pass through untouched, letting a
        // hostile or careless server render reversed text on the user's
        // public Discord profile.
        .filter(|c| {
            !c.is_control()
                && !matches!(c,
                    '\u{200B}'..='\u{200F}'
                    | '\u{202A}'..='\u{202E}'
                    | '\u{2066}'..='\u{2069}'
                    | '\u{FEFF}'
                )
        })
        .collect();
    match cleaned.char_indices().nth(MAX) {
        Some((byte_idx, _)) => format!("{}…", &cleaned[..byte_idx]),
        None => cleaned,
    }
}

/// Accept `artwork_public_url` only if it is something Discord's own
/// infrastructure can safely be pointed at: an `https://` URL, and short
/// enough that it cannot itself be an attempt to abuse the field. Anything
/// else falls back to the bundled asset key. This value comes straight from
/// the server and is untrusted input.
fn validate_artwork_url(url: &str) -> bool {
    url.starts_with("https://") && url.len() < 512
}

/// Render one session into a presence payload.
fn build_state(session: &Session, now_unix: i64) -> PresenceState {
    let playing = session.play_is_playing.unwrap_or(false);
    let (kind, name, details, state) = describe(session);

    // Paused: no moving bar, and say why the bar is gone. Clamp the base
    // state *before* appending the marker, not after — otherwise a state
    // line long enough to be truncated would silently drop the one thing
    // "· Paused" exists to communicate.
    let state = if playing {
        state.map(|s| clamp(&s))
    } else {
        Some(match state {
            Some(existing) => format!("{}{SEP}Paused", clamp(&existing)),
            None => "Paused".to_string(),
        })
    };

    let large_image = session
        .artwork_public_url
        .as_deref()
        .filter(|url| validate_artwork_url(url))
        .map(str::to_string)
        .unwrap_or_else(|| FALLBACK_ASSET_KEY.to_string());

    PresenceState {
        kind,
        name: name.to_string(),
        details: clamp(&details),
        state,
        large_image: Some(large_image),
        large_text: Some(clamp(&session.title)),
        timestamps: playing.then(|| timestamps(session, now_unix)),
    }
}

/// Per-media-type text. Returns `(kind, name, details, state)`.
///
/// `name` overrides the Discord application's default name in the header
/// ("Watching Lumastra"). It is a fixed noun per media type, not
/// server-supplied text, so it needs no clamping/sanitizing like `details`
/// and `state` do.
fn describe(session: &Session) -> (PresenceKind, &'static str, String, Option<String>) {
    match session.media_type.as_str() {
        "movie" => {
            let details = match session.year {
                Some(year) => format!("{} ({year})", session.title),
                None => session.title.clone(),
            };
            (PresenceKind::Watching, "Movie", details, None)
        }

        "series" | "tv" | "episode" | "season" => {
            let code = match (session.season_number, session.episode_number) {
                (Some(s), Some(e)) => Some(format!("S{s:02}E{e:02}")),
                _ => None,
            };
            match &session.series_name {
                // Series name known: it is the headline, the code and episode
                // title go below.
                Some(series) => {
                    let state = join(&[code.as_deref(), Some(session.title.as_str())]);
                    (PresenceKind::Watching, "Series", series.clone(), state)
                }
                // No series name: the episode title has to headline instead,
                // or the top line would be empty.
                None => (PresenceKind::Watching, "Series", session.title.clone(), code),
            }
        }

        "music" | "track" | "audio" => {
            let state = join(&[session.artist_name.as_deref(), session.album_name.as_deref()]);
            (PresenceKind::Listening, "Music", session.title.clone(), state)
        }

        "audiobook" => {
            let state = join(&[session.author.as_deref(), session.chapter.as_deref()]);
            (PresenceKind::Listening, "Audiobook", session.title.clone(), state)
        }

        "tvchannel" => (
            PresenceKind::Watching,
            "Live TV",
            session.title.clone(),
            session.live_tv_program_name.clone(),
        ),

        "radio" => {
            let state = join(&[
                session.now_playing_artist.as_deref(),
                session.now_playing_track.as_deref(),
            ]);
            (PresenceKind::Listening, "Radio", session.title.clone(), state)
        }

        // Unreachable: `select` only yields types `is_type_enabled` accepted.
        // Kept total rather than panicking — a new server media type should
        // degrade to a bare title, not crash the app. "Lumastra" mirrors
        // Discord's own default-name fallback for the (never-hit) case.
        _ => (PresenceKind::Watching, "Lumastra", session.title.clone(), None),
    }
}

/// Join present segments with the separator; `None` when nothing is present.
fn join(parts: &[Option<&str>]) -> Option<String> {
    let joined = parts
        .iter()
        .flatten()
        .filter(|part| !part.is_empty())
        .copied()
        .collect::<Vec<_>>()
        .join(SEP);

    (!joined.is_empty()).then_some(joined)
}

/// Anchor the progress bar to the reported position.
///
/// `start` is placed in the past by however far into the item we are, so
/// Discord's client-side animation lands on the right spot without needing
/// another update. `end` is omitted for open-ended streams and for a
/// non-positive duration, which would otherwise render a full bar.
///
/// Unix SECONDS, not milliseconds. The discord-rich-presence crate's Timestamps
/// doc comment says milliseconds, but that describes what Discord returns in its
/// responses — SET_ACTIVITY expects seconds on the way in. See discord/discord-rpc#231.
fn timestamps(session: &Session, now_unix: i64) -> PresenceTimestamps {
    let position = session.play_current_time.unwrap_or(0.0).max(0.0) as i64;
    let start = now_unix - position;

    // `play_item_duration` (playback block) is absent on some real sessions
    // even though the item plainly has a length, so fall back to `duration`
    // (identity block) — the server itself treats them as interchangeable
    // (`get-active-streams.tool.ts`: `s.playItemDuration ?? s.duration`).
    //
    // The `.filter(> 0.0)` on `play_item_duration` has to run *before* the
    // `.or`, not after: a present-but-zero `play_item_duration` is a
    // meaningless value, not an authoritative zero-length item, so it must
    // still fall through to `duration`. A bare `.or()` gets this wrong —
    // `Some(0.0).or(Some(3600.0))` evaluates to `Some(0.0)` and the bar is
    // lost even though `duration` had a perfectly good value.
    let end = session
        .play_item_duration
        .filter(|duration| *duration > 0.0)
        .or(session.duration)
        .filter(|duration| *duration > 0.0)
        .map(|duration| start + duration as i64);

    PresenceTimestamps { start, end }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::model::Session;
    use crate::config::Config;

    const NOW: i64 = 1_700_000_000;

    /// Minimal session; tests override only what they exercise. Owned by
    /// "denis" by default — the same username `map_presence` is called with
    /// unless a test overrides it.
    fn session(id: &str, media_type: &str, title: &str) -> Session {
        Session {
            id: id.into(),
            media_item_id: "media-uuid".into(),
            title: title.into(),
            media_type: media_type.into(),
            username: "denis".into(),
            year: None,
            season_number: None,
            episode_number: None,
            series_name: None,
            author: None,
            chapter: None,
            artist_name: None,
            album_name: None,
            live_tv_program_name: None,
            now_playing_track: None,
            now_playing_artist: None,
            artwork_public_url: None,
            play_is_playing: Some(true),
            play_current_time: Some(0.0),
            play_item_duration: Some(100.0),
            duration: None,
        }
    }

    // ── Empty and disabled ──────────────────────────────────────────────

    #[test]
    fn returns_none_for_an_empty_session_list() {
        assert!(map_presence(&[], &Config::default(), NOW, None, "denis").is_none());
    }

    #[test]
    fn returns_none_when_globally_paused() {
        let config = Config { paused: true, ..Default::default() };
        let sessions = vec![session("a", "movie", "Heat")];
        assert!(map_presence(&sessions, &config, NOW, None, "denis").is_none());
    }

    #[test]
    fn returns_none_when_the_media_type_is_disabled() {
        let config = Config { enable_movies: false, ..Default::default() };
        let sessions = vec![session("a", "movie", "Heat")];
        assert!(map_presence(&sessions, &config, NOW, None, "denis").is_none());
    }

    #[test]
    fn returns_none_for_an_unrecognized_media_type() {
        let sessions = vec![session("a", "manga", "Berserk")];
        assert!(map_presence(&sessions, &Config::default(), NOW, None, "denis").is_none());
    }

    // ── Per-type mapping ────────────────────────────────────────────────

    #[test]
    fn maps_a_movie_with_its_year() {
        let mut movie = session("a", "movie", "Heat");
        movie.year = Some(1995);
        let (_, state) = map_presence(&[movie], &Config::default(), NOW, None, "denis").unwrap();

        assert_eq!(state.kind, PresenceKind::Watching);
        assert_eq!(state.name, "Movie");
        assert_eq!(state.details, "Heat (1995)");
        assert_eq!(state.state, None);
    }

    #[test]
    fn maps_an_episode_to_series_plus_zero_padded_code() {
        let mut episode = session("a", "episode", "The Constant");
        episode.series_name = Some("Lost".into());
        episode.season_number = Some(4);
        episode.episode_number = Some(5);
        let (_, state) = map_presence(&[episode], &Config::default(), NOW, None, "denis").unwrap();

        assert_eq!(state.kind, PresenceKind::Watching);
        assert_eq!(state.details, "Lost");
        assert_eq!(state.state.as_deref(), Some("S04E05 · The Constant"));
    }

    #[test]
    fn falls_back_to_the_episode_title_when_the_series_name_is_missing() {
        let mut episode = session("a", "episode", "The Constant");
        episode.season_number = Some(4);
        episode.episode_number = Some(5);
        let (_, state) = map_presence(&[episode], &Config::default(), NOW, None, "denis").unwrap();

        assert_eq!(state.details, "The Constant");
        assert_eq!(state.state.as_deref(), Some("S04E05"));
    }

    #[test]
    fn maps_a_track_as_listening() {
        let mut track = session("a", "track", "Windowlicker");
        track.artist_name = Some("Aphex Twin".into());
        track.album_name = Some("Windowlicker".into());
        let (_, state) = map_presence(&[track], &Config::default(), NOW, None, "denis").unwrap();

        assert_eq!(state.kind, PresenceKind::Listening);
        assert_eq!(state.details, "Windowlicker");
        assert_eq!(state.state.as_deref(), Some("Aphex Twin · Windowlicker"));
    }

    #[test]
    fn maps_an_audiobook_to_author_and_chapter() {
        let mut book = session("a", "audiobook", "Dune");
        book.author = Some("Frank Herbert".into());
        book.chapter = Some("Chapter 12".into());
        let (_, state) = map_presence(&[book], &Config::default(), NOW, None, "denis").unwrap();

        assert_eq!(state.kind, PresenceKind::Listening);
        assert_eq!(state.details, "Dune");
        assert_eq!(state.state.as_deref(), Some("Frank Herbert · Chapter 12"));
    }

    #[test]
    fn maps_a_live_channel_with_its_programme_and_no_end_bound() {
        let mut channel = session("a", "tvchannel", "BBC One");
        channel.live_tv_program_name = Some("The News".into());
        channel.play_item_duration = None;
        let (_, state) = map_presence(&[channel], &Config::default(), NOW, None, "denis").unwrap();

        assert_eq!(state.kind, PresenceKind::Watching);
        assert_eq!(state.details, "BBC One");
        assert_eq!(state.state.as_deref(), Some("The News"));
        assert_eq!(state.timestamps.unwrap().end, None);
    }

    #[test]
    fn maps_radio_to_the_now_playing_track() {
        let mut radio = session("a", "radio", "NTS 1");
        radio.now_playing_track = Some("Aisha".into());
        radio.now_playing_artist = Some("Death in Vegas".into());
        radio.play_item_duration = None;
        let (_, state) = map_presence(&[radio], &Config::default(), NOW, None, "denis").unwrap();

        assert_eq!(state.kind, PresenceKind::Listening);
        assert_eq!(state.details, "NTS 1");
        assert_eq!(state.state.as_deref(), Some("Death in Vegas · Aisha"));
    }

    // ── Timestamps ──────────────────────────────────────────────────────

    #[test]
    fn anchors_the_progress_bar_to_the_current_position() {
        let mut movie = session("a", "movie", "Heat");
        movie.play_current_time = Some(600.0);
        movie.play_item_duration = Some(9000.0);
        let (_, state) = map_presence(&[movie], &Config::default(), NOW, None, "denis").unwrap();

        let timestamps = state.timestamps.unwrap();
        assert_eq!(timestamps.start, NOW - 600);
        assert_eq!(timestamps.end, Some(NOW - 600 + 9000));
    }

    #[test]
    fn omits_timestamps_while_paused_and_says_so() {
        let mut movie = session("a", "movie", "Heat");
        movie.play_is_playing = Some(false);
        let (_, state) = map_presence(&[movie], &Config::default(), NOW, None, "denis").unwrap();

        assert_eq!(state.timestamps, None);
        assert_eq!(state.state.as_deref(), Some("Paused"));
    }

    #[test]
    fn appends_paused_to_an_existing_state_line() {
        let mut track = session("a", "track", "Windowlicker");
        track.artist_name = Some("Aphex Twin".into());
        track.play_is_playing = Some(false);
        let (_, state) = map_presence(&[track], &Config::default(), NOW, None, "denis").unwrap();

        assert_eq!(state.state.as_deref(), Some("Aphex Twin · Paused"));
    }

    #[test]
    fn keeps_the_paused_marker_even_when_the_base_state_is_long_enough_to_truncate() {
        // The base state alone is well over the 120-char clamp limit. If the
        // marker were appended before clamping (the bug), it would be cut
        // off along with the tail of the state line, leaving the user with
        // no indication that playback is paused.
        let mut track = session("a", "track", "Windowlicker");
        track.artist_name = Some("a".repeat(200));
        track.play_is_playing = Some(false);
        let (_, state) = map_presence(&[track], &Config::default(), NOW, None, "denis").unwrap();

        assert!(state.state.as_deref().unwrap().ends_with(" · Paused"));
    }

    #[test]
    fn omits_the_end_bound_when_the_duration_is_missing() {
        let mut movie = session("a", "movie", "Heat");
        movie.play_item_duration = None;
        let (_, state) = map_presence(&[movie], &Config::default(), NOW, None, "denis").unwrap();

        assert_eq!(state.timestamps.unwrap().end, None);
    }

    #[test]
    fn omits_the_end_bound_when_the_duration_is_zero() {
        // A zero duration would make start == end and render a completed bar.
        let mut movie = session("a", "movie", "Heat");
        movie.play_item_duration = Some(0.0);
        let (_, state) = map_presence(&[movie], &Config::default(), NOW, None, "denis").unwrap();

        assert_eq!(state.timestamps.unwrap().end, None);
    }

    #[test]
    fn derives_the_end_bound_from_play_item_duration_when_present() {
        // Existing behavior preserved: the playback-block duration is used
        // when it is there.
        let mut movie = session("a", "movie", "Heat");
        movie.play_item_duration = Some(9000.0);
        movie.duration = Some(1234.0); // must be ignored in favor of the above
        let (_, state) = map_presence(&[movie], &Config::default(), NOW, None, "denis").unwrap();

        assert_eq!(state.timestamps.unwrap().end, Some(NOW + 9000));
    }

    #[test]
    fn falls_back_to_duration_when_play_item_duration_is_absent() {
        // Regression test for the reported bug: real sessions can carry
        // `duration` (identity block) without `playItemDuration` (playback
        // block), which used to silently drop the progress bar entirely.
        let mut movie = session("a", "movie", "Heat");
        movie.play_item_duration = None;
        movie.duration = Some(3600.0);
        let (_, state) = map_presence(&[movie], &Config::default(), NOW, None, "denis").unwrap();

        assert_eq!(state.timestamps.unwrap().end, Some(NOW + 3600));
    }

    #[test]
    fn omits_the_end_bound_when_both_durations_are_absent() {
        // Open-ended stream, e.g. live TV: start-only, no bar.
        let mut movie = session("a", "movie", "Heat");
        movie.play_item_duration = None;
        movie.duration = None;
        let (_, state) = map_presence(&[movie], &Config::default(), NOW, None, "denis").unwrap();

        assert_eq!(state.timestamps.unwrap().end, None);
    }

    #[test]
    fn falls_back_to_duration_when_play_item_duration_is_present_but_zero() {
        // A present `play_item_duration` of 0.0 is a meaningless value, not
        // an authoritative zero-length item, so this still falls through to
        // `duration` and keeps the progress bar. A bare `.or()` would get
        // this wrong: `Some(0.0).or(Some(3600.0))` evaluates to `Some(0.0)`,
        // losing the bar even though `duration` had a good value.
        let mut movie = session("a", "movie", "Heat");
        movie.play_item_duration = Some(0.0);
        movie.duration = Some(3600.0);
        let (_, state) = map_presence(&[movie], &Config::default(), NOW, None, "denis").unwrap();

        assert_eq!(state.timestamps.unwrap().end, Some(NOW + 3600));
    }

    // ── Artwork ─────────────────────────────────────────────────────────

    #[test]
    fn prefers_the_public_artwork_url() {
        let mut movie = session("a", "movie", "Heat");
        movie.artwork_public_url = Some("https://image.tmdb.org/t/p/w500/heat.jpg".into());
        let (_, state) = map_presence(&[movie], &Config::default(), NOW, None, "denis").unwrap();

        assert_eq!(
            state.large_image.as_deref(),
            Some("https://image.tmdb.org/t/p/w500/heat.jpg")
        );
    }

    #[test]
    fn falls_back_to_the_bundled_asset_key_without_a_public_url() {
        let (_, state) =
            map_presence(&[session("a", "movie", "Heat")], &Config::default(), NOW, None, "denis").unwrap();

        assert_eq!(state.large_image.as_deref(), Some(FALLBACK_ASSET_KEY));
    }

    #[test]
    fn falls_back_to_the_asset_key_when_the_artwork_url_is_not_https() {
        let mut movie = session("a", "movie", "Heat");
        movie.artwork_public_url = Some("http://image.tmdb.org/heat.jpg".into());
        let (_, state) = map_presence(&[movie], &Config::default(), NOW, None, "denis").unwrap();

        assert_eq!(state.large_image.as_deref(), Some(FALLBACK_ASSET_KEY));
    }

    #[test]
    fn falls_back_to_the_asset_key_when_the_artwork_url_is_oversized() {
        let mut movie = session("a", "movie", "Heat");
        let huge = format!("https://example.com/{}", "a".repeat(600));
        movie.artwork_public_url = Some(huge);
        let (_, state) = map_presence(&[movie], &Config::default(), NOW, None, "denis").unwrap();

        assert_eq!(state.large_image.as_deref(), Some(FALLBACK_ASSET_KEY));
    }

    // ── Untrusted-string hardening ─────────────────────────────────────────

    #[test]
    fn truncates_an_overlong_title_with_an_ellipsis_at_a_straddled_byte_boundary() {
        // Mixed widths so no byte offset in the naive `&cleaned[..120]` slice
        // this guards against can land on a character boundary by luck: a
        // single 1-byte ASCII char followed by 3-byte "日" characters means
        // byte offset 120 falls mid-character no matter how you count. (An
        // all-"日" title would NOT catch this — 3 divides 120 evenly, so a
        // naive byte slice lands exactly on a boundary and never panics.)
        let long_title = format!("a{}", "日".repeat(200));
        let movie = session("a", "movie", &long_title);
        let (_, state) = map_presence(&[movie], &Config::default(), NOW, None, "denis").unwrap();

        assert_eq!(state.details.chars().count(), 121); // 120 kept + the ellipsis
        assert!(state.details.ends_with('…'));
    }

    #[test]
    fn strips_control_characters_from_details() {
        let mut movie = session("a", "movie", "Heat");
        movie.title = "He\u{0000}at\n\r".into();
        let (_, state) = map_presence(&[movie], &Config::default(), NOW, None, "denis").unwrap();

        assert_eq!(state.details, "Heat");
    }

    #[test]
    fn strips_a_right_to_left_override_from_details() {
        // U+202E is category Cf (format), not Cc — `is_control()` alone does
        // not catch it. Left uncaught, a hostile or careless server could
        // make text render reversed on the user's public Discord profile.
        let mut movie = session("a", "movie", "Heat");
        movie.title = "He\u{202E}at".into();
        let (_, state) = map_presence(&[movie], &Config::default(), NOW, None, "denis").unwrap();

        assert_eq!(state.details, "Heat");
        assert!(!state.details.contains('\u{202E}'));
    }

    // ── Selection ───────────────────────────────────────────────────────

    #[test]
    fn prefers_a_playing_session_over_a_paused_one() {
        let mut paused = session("a-paused", "movie", "Heat");
        paused.play_is_playing = Some(false);
        let playing = session("b-playing", "movie", "Collateral");

        let (id, _) =
            map_presence(&[paused, playing], &Config::default(), NOW, None, "denis").unwrap();

        assert_eq!(id, "b-playing");
    }

    #[test]
    fn keeps_broadcasting_the_current_session_when_it_is_still_eligible() {
        // Both playing. Without stickiness the lexicographic tie-break would
        // switch to "a", flipping the user's status for no reason.
        let sessions = vec![
            session("a", "movie", "Heat"),
            session("z", "movie", "Collateral"),
        ];

        let (id, _) = map_presence(&sessions, &Config::default(), NOW, Some("z"), "denis").unwrap();
        assert_eq!(id, "z");
    }

    #[test]
    fn drops_stickiness_when_the_current_session_stops_playing() {
        let mut current = session("z", "movie", "Collateral");
        current.play_is_playing = Some(false);
        let sessions = vec![session("a", "movie", "Heat"), current];

        let (id, _) = map_presence(&sessions, &Config::default(), NOW, Some("z"), "denis").unwrap();
        assert_eq!(id, "a");
    }

    #[test]
    fn breaks_ties_lexicographically_so_the_result_never_flaps() {
        let sessions = vec![
            session("c", "movie", "Heat"),
            session("a", "movie", "Collateral"),
            session("b", "movie", "Thief"),
        ];

        let (id, _) = map_presence(&sessions, &Config::default(), NOW, None, "denis").unwrap();
        assert_eq!(id, "a");
    }

    #[test]
    fn ignores_disabled_types_when_selecting() {
        let config = Config { enable_movies: false, ..Default::default() };

        let sessions = vec![
            session("a", "movie", "Heat"),
            session("b", "track", "Windowlicker"),
        ];

        let (id, state) = map_presence(&sessions, &config, NOW, None, "denis").unwrap();
        assert_eq!(id, "b");
        assert_eq!(state.kind, PresenceKind::Listening);
    }

    // ── Ownership ───────────────────────────────────────────────────────
    // Regression coverage for the privacy bug: `scope=mine` can return
    // sessions the caller merely has permission to *see*, not just their own
    // (an admin, anyone with watch permission, or public sessions). These
    // pin down that an unowned session is never broadcast, however it is
    // dressed up.

    #[test]
    fn never_selects_another_users_session_even_when_it_is_the_only_one_playing() {
        let mut other = session("a", "movie", "The Mentalist");
        other.username = "someone-else".into();

        assert!(map_presence(&[other], &Config::default(), NOW, None, "denis").is_none());
    }

    #[test]
    fn matches_the_owning_username_case_insensitively() {
        let mut mine = session("a", "movie", "Heat");
        mine.username = "Denis".into();

        let (id, _) = map_presence(&[mine], &Config::default(), NOW, None, "denis").unwrap();
        assert_eq!(id, "a");
    }

    #[test]
    fn prefers_the_owned_session_even_when_the_tie_break_would_pick_the_other_users() {
        // Both playing, and "a-other" sorts before "z-own" lexicographically —
        // without the ownership filter, step 3 of `select` would pick the
        // other user's session outright.
        let mut mine = session("z-own", "movie", "Heat");
        mine.username = "denis".into();
        let mut other = session("a-other", "movie", "The Mentalist");
        other.username = "someone-else".into();

        let (id, _) =
            map_presence(&[other, mine], &Config::default(), NOW, None, "denis").unwrap();
        assert_eq!(id, "z-own");
    }

    #[test]
    fn still_excludes_an_owned_session_disabled_by_media_type() {
        let config = Config { enable_movies: false, ..Default::default() };
        let mut mine = session("a", "movie", "Heat");
        mine.username = "denis".into();

        assert!(map_presence(&[mine], &config, NOW, None, "denis").is_none());
    }
}
