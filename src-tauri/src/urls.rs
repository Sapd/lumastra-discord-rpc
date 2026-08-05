// SPDX-License-Identifier: MIT

//! Shared URL construction.
//!
//! Lumastra supports subfolder deployment (e.g. `https://host/lumastra`), so
//! every request path must be appended to the configured base URL rather than
//! replacing it. `Url::join` with a leading-slash target replaces the whole
//! path, which silently drops the prefix — this helper exists so that mistake
//! is made in one place and fixed in one place.

/// Join an API path onto a user-configured base URL, preserving any subpath.
///
/// `path` must be relative (no leading slash).
pub fn join_path(base_url: &str, path: &str) -> Result<url::Url, url::ParseError> {
    // A base without a trailing slash loses its last segment on join, so add one.
    let base = if base_url.ends_with('/') {
        base_url.to_string()
    } else {
        format!("{base_url}/")
    };
    url::Url::parse(&base)?.join(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appends_to_an_origin_only_base() {
        assert_eq!(
            join_path("https://example.com", "api/v1/sessions?scope=mine").unwrap().as_str(),
            "https://example.com/api/v1/sessions?scope=mine"
        );
    }

    #[test]
    fn preserves_a_subpath_base() {
        assert_eq!(
            join_path("https://example.com/lumastra", "api/v1/sessions").unwrap().as_str(),
            "https://example.com/lumastra/api/v1/sessions"
        );
    }

    #[test]
    fn tolerates_a_trailing_slash_without_doubling_it() {
        assert_eq!(
            join_path("https://example.com/lumastra/", "api/v1/sessions").unwrap().as_str(),
            "https://example.com/lumastra/api/v1/sessions"
        );
    }

    #[test]
    fn rejects_a_url_it_cannot_parse() {
        assert!(join_path("not a url", "api/v1/sessions").is_err());
    }
}
