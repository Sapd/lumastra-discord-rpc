// SPDX-License-Identifier: MIT

use super::model::{Session, SessionsResponse};
use serde::Deserialize;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("network error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("invalid server URL: {0}")]
    Url(#[from] url::ParseError),
    /// The access token was rejected. The caller refreshes and retries once.
    #[error("unauthorized")]
    Unauthorized,
    /// Access permanently denied (revoked grant, disabled user, WAF rule) —
    /// distinct from `Unauthorized` because refreshing cannot fix it. A
    /// caller that refreshed on this would burn a refresh-token rotation
    /// every poll, forever.
    #[error("forbidden")]
    Forbidden,
    #[error("server returned {0}")]
    Status(u16),
}

/// Fetch the authenticated user's active sessions.
///
/// `scope=mine` is explicit even though it is the server default — the default
/// is not part of the contract we want to depend on.
pub async fn fetch_sessions(
    http: &reqwest::Client,
    base_url: &str,
    access_token: &str,
) -> Result<Vec<Session>, ApiError> {
    let url = crate::urls::join_path(base_url, "api/v1/sessions?scope=mine")?;

    let response = http
        .get(url)
        .bearer_auth(access_token)
        .header("Accept", "application/json")
        .send()
        .await?;

    match response.status().as_u16() {
        200 => Ok(response.json::<SessionsResponse>().await?.items),
        401 => Err(ApiError::Unauthorized),
        403 => Err(ApiError::Forbidden),
        other => Err(ApiError::Status(other)),
    }
}

/// Shape of `GET /api/v1/user/profile` this client cares about. The endpoint
/// also returns `profile` and `groups`, ignored here — `serde` drops unknown
/// fields by default.
#[derive(Debug, Deserialize)]
struct ProfileResponse {
    username: String,
}

/// Fetch the authenticated caller's own username.
///
/// `/user/profile` is self-scoped: it always returns the caller's own
/// identity, unlike `/sessions?scope=mine`, which can return sessions
/// belonging to other users (an admin, anyone with watch permission, or
/// public sessions). This is the anchor the mapper filters sessions against
/// so that whose activity reaches the caller's public Discord profile is
/// never delegated to the server's session-visibility rules.
pub async fn fetch_username(
    http: &reqwest::Client,
    base_url: &str,
    access_token: &str,
) -> Result<String, ApiError> {
    let url = crate::urls::join_path(base_url, "api/v1/user/profile")?;

    let response = http
        .get(url)
        .bearer_auth(access_token)
        .header("Accept", "application/json")
        .send()
        .await?;

    match response.status().as_u16() {
        200 => Ok(response.json::<ProfileResponse>().await?.username),
        401 => Err(ApiError::Unauthorized),
        403 => Err(ApiError::Forbidden),
        other => Err(ApiError::Status(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn sends_the_bearer_token_and_returns_items() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/sessions"))
            .and(query_param("scope", "mine"))
            .and(header("authorization", "Bearer tok-123"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"items":[{"__id":"a","id":"u","mediaItemId":"u","title":"T","mediaType":"movie","username":"denis"}],"page":{}}"#,
            ))
            .mount(&server)
            .await;

        let sessions = fetch_sessions(&reqwest::Client::new(), &server.uri(), "tok-123")
            .await
            .unwrap();

        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].title, "T");
    }

    #[tokio::test]
    async fn reports_401_as_unauthorized_so_the_caller_can_refresh() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;

        let error = fetch_sessions(&reqwest::Client::new(), &server.uri(), "stale")
            .await
            .unwrap_err();

        assert!(matches!(error, ApiError::Unauthorized));
    }

    #[tokio::test]
    async fn reports_403_as_forbidden_so_the_caller_does_not_refresh() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;

        let error = fetch_sessions(&reqwest::Client::new(), &server.uri(), "revoked")
            .await
            .unwrap_err();

        assert!(matches!(error, ApiError::Forbidden));
    }

    #[tokio::test]
    async fn preserves_a_subfolder_deployment_prefix() {
        // Regression test: `Url::join` with a leading-slash path replaces the
        // whole path, dropping a subfolder prefix like `/lumastra`. This
        // proves the request actually lands on `/lumastra/api/v1/sessions`.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/lumastra/api/v1/sessions"))
            .and(query_param("scope", "mine"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(r#"{"items":[],"page":{}}"#),
            )
            .mount(&server)
            .await;

        let base_url = format!("{}/lumastra", server.uri());
        let sessions = fetch_sessions(&reqwest::Client::new(), &base_url, "tok-123")
            .await
            .unwrap();

        assert_eq!(sessions.len(), 0);
    }

    #[tokio::test]
    async fn fetch_username_parses_the_profile_response() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/user/profile"))
            .and(header("authorization", "Bearer tok-123"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"username":"denis","profile":{"isAdmin":true,"hasWatchPermission":true},"groups":["staff"]}"#,
            ))
            .mount(&server)
            .await;

        let username = fetch_username(&reqwest::Client::new(), &server.uri(), "tok-123")
            .await
            .unwrap();

        assert_eq!(username, "denis");
    }

    #[tokio::test]
    async fn fetch_username_reports_401_as_unauthorized() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;

        let error = fetch_username(&reqwest::Client::new(), &server.uri(), "stale")
            .await
            .unwrap_err();

        assert!(matches!(error, ApiError::Unauthorized));
    }
}
