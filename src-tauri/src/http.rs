// SPDX-License-Identifier: MIT

//! Shared HTTP client construction.
//!
//! `reqwest::Client::new()` has no default timeout: a server that accepts the
//! connection and never responds wedges the caller forever. Every call site
//! that talks to the user's self-hosted server must use this instead.

use std::time::Duration;

/// Build the HTTP client used for every request to the Lumastra server.
///
/// The 15s overall timeout applies even to the login poll, which legitimately
/// runs for the device-code lifetime (minutes) as a *sequence* of individual
/// requests — each one of those requests must still fail fast rather than
/// hang, so the same client is correct there too.
pub fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .connect_timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}
