// SPDX-License-Identifier: MIT

use serde::Deserialize;

/// One active play session.
///
/// Declares only the fields presence actually needs. `serde` ignores unknown
/// fields by default, which is the behavior we want: the server's session
/// schema is wide and grows, and an old client must keep working.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    /// Internal compound session id — the identity used for sticky selection.
    #[serde(rename = "__id")]
    pub id: String,
    pub media_item_id: String,
    pub title: String,
    /// Session media-type vocabulary: `movie`, `series`/`tv`, `episode`,
    /// `audiobook`, `track`, `music`, `tvchannel`, `radio`, and others.
    pub media_type: String,
    /// Owning user's login name. Always present server-side
    /// (`SessionUserSchema.username`). Used client-side to filter out
    /// sessions `scope=mine` returns that do not actually belong to the
    /// authenticated caller — see `mapper::select`.
    pub username: String,
    pub year: Option<u32>,

    // Episode / audiobook context
    pub season_number: Option<u32>,
    pub episode_number: Option<u32>,
    pub series_name: Option<String>,
    pub author: Option<String>,
    pub chapter: Option<String>,

    // Music
    pub artist_name: Option<String>,
    pub album_name: Option<String>,

    // Live TV / radio
    pub live_tv_program_name: Option<String>,
    pub now_playing_track: Option<String>,
    pub now_playing_artist: Option<String>,

    /// Public CDN artwork URL. Added by the server; absent when undecidable.
    pub artwork_public_url: Option<String>,

    // Playback state
    pub play_is_playing: Option<bool>,
    pub play_current_time: Option<f64>,
    /// Duration in seconds, from the playback block. Absent on some real
    /// sessions even while the item plainly has a length — see `duration`.
    pub play_item_duration: Option<f64>,
    /// Duration in seconds, from the identity block. A fallback for
    /// `play_item_duration` — the Lumastra server itself treats the two as
    /// interchangeable (`get-active-streams.tool.ts`:
    /// `s.playItemDuration ?? s.duration`), and the mapper does the same in
    /// `mapper::timestamps`.
    pub duration: Option<f64>,
}

/// Paginated envelope returned by `GET /api/v1/sessions`.
#[derive(Debug, Clone, Deserialize)]
pub struct SessionsResponse {
    pub items: Vec<Session>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../../tests/fixtures/sessions.json");

    #[test]
    fn parses_the_paginated_envelope() {
        let response: SessionsResponse = serde_json::from_str(FIXTURE).unwrap();
        assert_eq!(response.items.len(), 2);
    }

    #[test]
    fn maps_camel_case_and_the_double_underscore_id() {
        let response: SessionsResponse = serde_json::from_str(FIXTURE).unwrap();
        let episode = &response.items[0];

        assert_eq!(episode.id, "sess-episode-1");
        assert_eq!(episode.media_type, "episode");
        assert_eq!(episode.series_name.as_deref(), Some("Lost"));
        assert_eq!(episode.season_number, Some(4));
        assert_eq!(episode.episode_number, Some(5));
        assert_eq!(episode.play_is_playing, Some(true));
        assert_eq!(episode.play_current_time, Some(620.5));
        assert_eq!(
            episode.artwork_public_url.as_deref(),
            Some("https://image.tmdb.org/t/p/w500/lost.jpg")
        );
    }

    #[test]
    fn leaves_absent_optional_fields_as_none() {
        let response: SessionsResponse = serde_json::from_str(FIXTURE).unwrap();
        let track = &response.items[1];

        assert_eq!(track.artist_name.as_deref(), Some("Aphex Twin"));
        assert_eq!(track.series_name, None);
        assert_eq!(track.artwork_public_url, None);
    }

    #[test]
    fn tolerates_unknown_fields() {
        // The server adds fields freely; an old client must not break. The
        // fixture already carries playIsTranscoding, username and clientname,
        // none of which the model declares.
        let response: SessionsResponse = serde_json::from_str(FIXTURE).unwrap();
        assert_eq!(response.items[0].title, "The Constant");
    }
}
