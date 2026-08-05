// SPDX-License-Identifier: MIT

/// Which Discord activity verb to display.
///
/// Discord's numeric values are 0 Playing, 2 Listening, 3 Watching, 5 Competing.
/// Only the two we use are modelled — an unused variant is an untested variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresenceKind {
    Watching,
    Listening,
}

/// Unix-second bounds driving Discord's progress bar.
///
/// Discord animates between these client-side, so a 15-second poll still shows
/// a smooth, accurate bar. `end` is absent for open-ended streams (Live TV,
/// radio), which renders as an elapsed counter with no bar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PresenceTimestamps {
    pub start: i64,
    pub end: Option<i64>,
}

/// What to show on the user's profile — fully owned.
///
/// Owned rather than borrowed on purpose. `discord_rich_presence::activity::Activity<'a>`
/// holds `Cow<'a, str>`, so returning one would tie its lifetime to the input
/// session slice and make it impossible to keep as "the last thing we sent" for
/// change detection. `presence/client.rs` borrows from this to build the
/// `Activity` immediately before sending.
#[derive(Debug, Clone, PartialEq)]
pub struct PresenceState {
    pub kind: PresenceKind,
    /// Overrides the Discord application's default name in the header line
    /// ("Watching Lumastra" -> "Watching Movie"/"Watching Series"/etc). Discord
    /// always renders `<Verb> <name>`, so this is chosen per media type rather
    /// than left blank.
    pub name: String,
    /// Top line.
    pub details: String,
    /// Second line. `None` when there is nothing meaningful to say.
    pub state: Option<String>,
    /// Public image URL, or a Discord asset key for the bundled fallback.
    pub large_image: Option<String>,
    /// Hover text for the image.
    pub large_text: Option<String>,
    /// Absent while paused — a moving bar on paused content is wrong.
    pub timestamps: Option<PresenceTimestamps>,
}
