use ironclaw_host_api::action::{NetworkScheme, NetworkTarget};
use std::borrow::Cow;
use thiserror::Error;

use crate::error::NetworkHttpError;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum NetworkTargetUrlError {
    #[error("invalid URL: {0}")]
    Parse(String),
    #[error("URL userinfo is not allowed")]
    UserinfoDenied,
    #[error("unsupported URL scheme {0}")]
    UnsupportedScheme(String),
    #[error("URL host is required")]
    MissingHost,
}

pub fn network_target_for_url(raw: &str) -> Result<NetworkTarget, NetworkTargetUrlError> {
    network_target_for_url_inner(raw)
}

/// Parses a `wss://` URL into the policy target the WebSocket connector
/// authorizes. Plain `ws` and every HTTP scheme are rejected: an outbound
/// WebSocket is always TLS. Kept apart from [`network_target_for_url`] so every
/// existing HTTP-only caller keeps rejecting `wss`.
pub fn network_target_for_websocket_url(raw: &str) -> Result<NetworkTarget, NetworkTargetUrlError> {
    network_target_for_scheme_set(raw, UrlSchemeSet::WebSocket)
}

/// The ticket-free part of an outbound WebSocket URL, ready to dial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WebSocketEndpoint {
    pub(crate) target: NetworkTarget,
    /// Host as the URL spells it (lowercased; `host_str` keeps an IPv6
    /// literal's brackets).
    pub(crate) host: String,
    pub(crate) port: u16,
    /// Normalized absolute path.
    pub(crate) path: String,
}

/// Parses the endpoint part of a `wss://` URL: scheme, authority, and path,
/// with no query and no fragment. The caller splits the ticket-bearing query
/// off first, so nothing parsed here can hold the ticket.
pub(crate) fn websocket_endpoint(
    endpoint: &str,
) -> Result<WebSocketEndpoint, NetworkTargetUrlError> {
    let url = parse_target_url(endpoint)?;
    if url.query().is_some() || url.fragment().is_some() {
        return Err(NetworkTargetUrlError::Parse(
            "endpoint must not carry a query or fragment".to_string(),
        ));
    }
    let target = target_for_url(&url, UrlSchemeSet::WebSocket)?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| NetworkTargetUrlError::Parse("URL port is required".to_string()))?;
    Ok(WebSocketEndpoint {
        host: target.host.clone(),
        target,
        port,
        path: url.path().to_string(),
    })
}

pub fn is_rfc3986_unreserved_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment != "."
        && segment != ".."
        && segment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
}

/// Credential material substituted into one URL path segment: RFC 3986
/// unreserved characters plus `:` (legal raw in a path segment per the
/// `pchar` grammar, and real vendor tokens carry it — e.g. a
/// `<bot-id>:<secret>` token). Everything else stays rejected — no `%`
/// (validated material can never smuggle pre-encoded octets), no `/` (never
/// adds a segment), and no other sub-delims (nothing a naive server-side
/// parser could misread).
pub fn is_path_segment_credential_material(segment: &str) -> bool {
    !segment.is_empty()
        && segment != "."
        && segment != ".."
        && segment.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b':')
        })
}

pub fn percent_decode_url_component_lossy(input: &str) -> Cow<'_, str> {
    if !input.as_bytes().contains(&b'%') {
        Cow::Borrowed(input)
    } else {
        percent_encoding::percent_decode_str(input).decode_utf8_lossy()
    }
}

pub(crate) fn network_target_for_http_url(
    raw: &str,
    request_bytes: u64,
) -> Result<NetworkTarget, NetworkHttpError> {
    network_target_for_url_inner(raw).map_err(|error| NetworkHttpError::InvalidUrl {
        reason: error.to_string(),
        request_bytes,
        response_bytes: 0,
    })
}

/// Which URL schemes a caller of the shared target parser accepts. HTTP egress
/// and the WebSocket connector are disjoint on purpose: neither may authorize
/// the other's scheme.
#[derive(Clone, Copy)]
enum UrlSchemeSet {
    Http,
    WebSocket,
}

fn network_target_for_url_inner(raw: &str) -> Result<NetworkTarget, NetworkTargetUrlError> {
    network_target_for_scheme_set(raw, UrlSchemeSet::Http)
}

fn network_target_for_scheme_set(
    raw: &str,
    allowed: UrlSchemeSet,
) -> Result<NetworkTarget, NetworkTargetUrlError> {
    target_for_url(&parse_target_url(raw)?, allowed)
}

fn parse_target_url(raw: &str) -> Result<url::Url, NetworkTargetUrlError> {
    url::Url::parse(raw).map_err(|error| NetworkTargetUrlError::Parse(error.to_string()))
}

fn target_for_url(
    url: &url::Url,
    allowed: UrlSchemeSet,
) -> Result<NetworkTarget, NetworkTargetUrlError> {
    if !url.username().is_empty() || url.password().is_some() {
        return Err(NetworkTargetUrlError::UserinfoDenied);
    }
    let scheme = match (allowed, url.scheme()) {
        (UrlSchemeSet::Http, "http") => NetworkScheme::Http,
        (UrlSchemeSet::Http, "https") => NetworkScheme::Https,
        (UrlSchemeSet::WebSocket, "wss") => NetworkScheme::Wss,
        (_, other) => return Err(NetworkTargetUrlError::UnsupportedScheme(other.to_string())),
    };
    let host = url
        .host_str()
        .filter(|host| !host.trim().is_empty())
        .ok_or(NetworkTargetUrlError::MissingHost)?
        .to_ascii_lowercase();
    Ok(NetworkTarget {
        scheme,
        host,
        port: url.port_or_known_default(),
    })
}

pub(crate) fn default_port(scheme: NetworkScheme) -> u16 {
    match scheme {
        NetworkScheme::Http => 80,
        NetworkScheme::Https | NetworkScheme::Wss => 443,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        NetworkTargetUrlError, default_port, is_rfc3986_unreserved_segment,
        network_target_for_http_url, network_target_for_url, network_target_for_websocket_url,
        percent_decode_url_component_lossy,
    };
    use ironclaw_host_api::action::NetworkScheme;
    use std::borrow::Cow;

    #[test]
    fn websocket_target_accepts_only_wss_and_lowercases_host() {
        let target = network_target_for_websocket_url("wss://Gateway.Example.test/path?ticket=s")
            .expect("wss target");
        assert_eq!(target.scheme, NetworkScheme::Wss);
        assert_eq!(target.host, "gateway.example.test");
        assert_eq!(target.port, Some(443));
        let explicit = network_target_for_websocket_url("wss://gateway.example.test:8443/")
            .expect("wss target with port");
        assert_eq!(explicit.port, Some(8443));
        for rejected in [
            "ws://gateway.example.test/",
            "https://gateway.example.test/",
            "http://gateway.example.test/",
            "ftp://gateway.example.test/",
        ] {
            assert!(
                matches!(
                    network_target_for_websocket_url(rejected),
                    Err(NetworkTargetUrlError::UnsupportedScheme(_))
                ),
                "{rejected}"
            );
        }
        assert!(matches!(
            network_target_for_websocket_url("wss://user:pw@gateway.example.test/"),
            Err(NetworkTargetUrlError::UserinfoDenied)
        ));
    }

    #[test]
    fn websocket_endpoint_exposes_dial_parts_and_never_a_query() {
        let endpoint = super::websocket_endpoint("wss://Gateway.Example.test/a/./b c")
            .expect("endpoint parses");
        assert_eq!(endpoint.host, "gateway.example.test");
        assert_eq!(endpoint.port, 443);
        assert_eq!(endpoint.path, "/a/b%20c");
        assert_eq!(endpoint.target.host, "gateway.example.test");
        assert_eq!(endpoint.target.port, Some(443));

        let bare = super::websocket_endpoint("wss://gateway.example.test:8443")
            .expect("bare authority gets the root path");
        assert_eq!((bare.port, bare.path.as_str()), (8443, "/"));

        for rejected in [
            "ws://gateway.example.test/",
            "wss://user:pw@gateway.example.test/",
        ] {
            assert!(super::websocket_endpoint(rejected).is_err(), "{rejected}");
        }
        // A query or fragment means the caller did not split the ticket off.
        for leaked in [
            "wss://gateway.example.test/p?ticket=s",
            "wss://gateway.example.test/p#frag",
        ] {
            assert!(super::websocket_endpoint(leaked).is_err(), "{leaked}");
        }
    }

    #[test]
    fn http_target_parsing_still_rejects_wss_so_http_egress_is_unchanged() {
        assert!(matches!(
            network_target_for_url("wss://gateway.example.test/"),
            Err(NetworkTargetUrlError::UnsupportedScheme(_))
        ));
        assert!(network_target_for_http_url("wss://gateway.example.test/", 0).is_err());
    }

    #[test]
    fn default_port_for_wss_is_443() {
        assert_eq!(default_port(NetworkScheme::Wss), 443);
    }

    #[test]
    fn rfc3986_unreserved_segment_accepts_unreserved_path_parts() {
        for segment in ["abc", "ABC", "abc-._~", "a1_b2.c3~d4"] {
            assert!(is_rfc3986_unreserved_segment(segment), "{segment}");
        }
    }

    #[test]
    fn rfc3986_unreserved_segment_rejects_empty_dot_segments_and_reserved_chars() {
        for segment in ["", ".", "..", "/", "a/b", "?", "a?b", "#", "a#b", "%2f"] {
            assert!(!is_rfc3986_unreserved_segment(segment), "{segment}");
        }
    }

    #[test]
    fn percent_decode_url_component_lossy_borrows_unencoded_component() {
        assert!(matches!(
            percent_decode_url_component_lossy("plain/path"),
            Cow::Borrowed("plain/path")
        ));
    }

    #[test]
    fn percent_decode_url_component_lossy_decodes_encoded_component() {
        assert_eq!(
            percent_decode_url_component_lossy("token%20value").as_ref(),
            "token value"
        );
    }
}
