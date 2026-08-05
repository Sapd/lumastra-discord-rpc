// SPDX-License-Identifier: MIT

use super::tokens::{AuthError, TokenResponse};
use serde::Deserialize;
use std::time::{Duration, Instant};

/// OAuth client id for this application. Not a secret.
pub const CLIENT_ID: &str = "lumastra-discord-rpc";

/// Requested scope. Advisory only — the server fixes the device grant and
/// never issues admin on this path, regardless of what is asked for here.
const SCOPE: &str = "media";

/// Fallback poll interval when the server omits one (RFC 8628 §3.5).
pub const DEFAULT_INTERVAL_SECONDS: u64 = 5;

#[derive(Debug, Clone, Deserialize)]
pub struct DeviceCodeResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    /// Pre-filled URL. Present on this server; opening it means the user never
    /// has to type the code.
    pub verification_uri_complete: Option<String>,
    /// Lifetime of the device code in seconds (RFC 8628 §3.2). Used as a
    /// client-side deadline so polling terminates even if the server never
    /// sends `expired_token`.
    pub expires_in: u64,
    pub interval: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct OAuthErrorBody {
    error: String,
}

/// Begin device authorization.
pub async fn start_device_flow(
    http: &reqwest::Client,
    base_url: &str,
) -> Result<DeviceCodeResponse, AuthError> {
    let url = crate::urls::join_path(base_url, "oauth/device")?;

    let response = http
        .post(url)
        .form(&[
            ("client_id", CLIENT_ID),
            ("scope", SCOPE),
            ("device_name", "Lumastra Discord RPC"),
        ])
        .send()
        .await?;

    match response.status().as_u16() {
        200 => Ok(response.json().await?),
        other => Err(AuthError::Status(other)),
    }
}

/// Poll until the user approves, denies, or the code expires.
///
/// `interval_seconds` is the server-supplied cadence; tests pass 0. RFC 8628
/// `slow_down` increases it by 5 seconds, as the spec requires.
///
/// `expires_in_seconds` bounds the whole loop client-side (RFC 8628 §3.2): a
/// server that keeps answering `authorization_pending` and never sends
/// `expired_token` would otherwise poll forever.
pub async fn poll_for_token(
    http: &reqwest::Client,
    base_url: &str,
    device_code: &str,
    interval_seconds: u64,
    expires_in_seconds: u64,
) -> Result<TokenResponse, AuthError> {
    let url = crate::urls::join_path(base_url, "oauth/token")?;
    let mut interval = interval_seconds;
    let deadline = Instant::now() + Duration::from_secs(expires_in_seconds);

    loop {
        let response = http
            .post(url.clone())
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("device_code", device_code),
                ("client_id", CLIENT_ID),
            ])
            .send()
            .await?;

        if response.status().is_success() {
            return Ok(response.json().await?);
        }

        let body: OAuthErrorBody = response
            .json()
            .await
            .unwrap_or(OAuthErrorBody { error: "unknown".into() });

        match body.error.as_str() {
            // Expected for most of the flow — keep waiting.
            "authorization_pending" => {}
            // Server says we are polling too fast; back off permanently.
            "slow_down" => interval += 5,
            "access_denied" => return Err(AuthError::Denied),
            "expired_token" => return Err(AuthError::Expired),
            _ => return Err(AuthError::Status(400)),
        }

        // Do not sleep past the deadline and poll once more — a server that
        // never sends `expired_token` must still be bounded on our side.
        if Instant::now() >= deadline {
            return Err(AuthError::Expired);
        }

        tokio::time::sleep(Duration::from_secs(interval)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn requests_a_device_code_with_the_client_id_and_media_scope() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth/device"))
            .and(body_string_contains("client_id"))
            .and(body_string_contains("scope=media"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"device_code":"dc","user_code":"ABCD-EFGH",
                    "verification_uri":"https://s/device",
                    "verification_uri_complete":"https://s/device?code=ABCD-EFGH",
                    "expires_in":600,"interval":5}"#,
            ))
            .mount(&server)
            .await;

        let response = start_device_flow(&reqwest::Client::new(), &server.uri())
            .await
            .unwrap();

        assert_eq!(response.user_code, "ABCD-EFGH");
        assert_eq!(
            response.verification_uri_complete.as_deref(),
            Some("https://s/device?code=ABCD-EFGH")
        );
        assert_eq!(response.interval, Some(5));
    }

    #[tokio::test]
    async fn keeps_polling_while_the_user_has_not_approved_yet() {
        let server = MockServer::start().await;

        // authorization_pending is the normal state for most of the flow: it
        // must not be treated as a failure.
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(
                ResponseTemplate::new(400).set_body_string(r#"{"error":"authorization_pending"}"#),
            )
            .up_to_n_times(2)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"access_token":"at","refresh_token":"rt","expires_in":900}"#,
            ))
            .mount(&server)
            .await;

        let token = poll_for_token(&reqwest::Client::new(), &server.uri(), "dc", 0, 3600)
            .await
            .unwrap();

        assert_eq!(token.access_token, "at");
        assert_eq!(token.refresh_token.as_deref(), Some("rt"));
    }

    #[tokio::test]
    async fn gives_up_when_the_user_denies_the_request() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(400).set_body_string(r#"{"error":"access_denied"}"#))
            .mount(&server)
            .await;

        let error = poll_for_token(&reqwest::Client::new(), &server.uri(), "dc", 0, 3600)
            .await
            .unwrap_err();

        assert!(matches!(error, AuthError::Denied));
    }

    #[tokio::test]
    async fn gives_up_when_the_device_code_expires() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(ResponseTemplate::new(400).set_body_string(r#"{"error":"expired_token"}"#))
            .mount(&server)
            .await;

        let error = poll_for_token(&reqwest::Client::new(), &server.uri(), "dc", 0, 3600)
            .await
            .unwrap_err();

        assert!(matches!(error, AuthError::Expired));
    }

    #[tokio::test]
    async fn gives_up_once_the_client_side_deadline_passes_even_without_expired_token() {
        let server = MockServer::start().await;

        // The server keeps saying "not yet" and never sends `expired_token` —
        // proving the client enforces its own deadline rather than relying
        // on the server to say when to stop.
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .respond_with(
                ResponseTemplate::new(400).set_body_string(r#"{"error":"authorization_pending"}"#),
            )
            .mount(&server)
            .await;

        // expires_in_seconds: 0 means the deadline has already passed by the
        // time the first response is handled — no real sleep needed, so this
        // stays fast.
        let error = poll_for_token(&reqwest::Client::new(), &server.uri(), "dc", 0, 0)
            .await
            .unwrap_err();

        assert!(matches!(error, AuthError::Expired));
    }
}
