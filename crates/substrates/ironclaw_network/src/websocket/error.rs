use thiserror::Error;
use tokio_tungstenite::tungstenite;

use super::types::WebSocketLimits;

/// Stable, secret-free failure of an outbound WebSocket connection.
///
/// Reasons never carry the URL: a WebSocket URL routinely holds a connection
/// ticket in its query string. At most the host name may appear.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum WebSocketError {
    #[error("invalid websocket URL: {reason}")]
    InvalidUrl { reason: String },
    #[error("invalid websocket limits: {reason}")]
    InvalidLimits { reason: String },
    #[error("websocket policy denied connection: {reason}")]
    PolicyDenied { reason: String },
    #[error("websocket DNS resolution failed: {reason}")]
    Dns { reason: String },
    #[error("websocket connection failed: {reason}")]
    Connect { reason: String },
    #[error("websocket connection attempt timed out")]
    ConnectTimeout,
    #[error("websocket handshake rejected with HTTP status {status}")]
    HandshakeRejected { status: u16 },
    #[error("websocket handshake redirect (HTTP status {status}) is not followed")]
    RedirectRejected { status: u16 },
    #[error("websocket frame or message exceeds the {limit}-byte limit")]
    FrameTooLarge { limit: usize },
    #[error("websocket peer exceeded {limit} messages per second")]
    RateLimitExceeded { limit: u32 },
    #[error("websocket peer was idle past the idle timeout")]
    IdleTimeout,
    #[error("websocket send timed out")]
    SendTimeout,
    #[error("websocket protocol error: {reason}")]
    Protocol { reason: String },
    #[error("websocket connection is closed")]
    Closed,
}

impl WebSocketError {
    /// Maps a client-library error onto a stable, URL-free category.
    ///
    /// Variants whose library text can embed the request URL (`Url`,
    /// `Http`'s response, `HttpFormat`) are reduced to fixed text; the rest
    /// carry only static library diagnostics or I/O error kinds.
    pub(crate) fn from_tungstenite(error: tungstenite::Error, limits: &WebSocketLimits) -> Self {
        use tungstenite::Error as E;
        match error {
            E::ConnectionClosed | E::AlreadyClosed => Self::Closed,
            E::Io(error) => Self::Connect {
                reason: format!("i/o error ({:?})", error.kind()),
            },
            E::Tls(error) => Self::Connect {
                reason: format!("TLS error: {error}"),
            },
            E::Capacity(_) => Self::FrameTooLarge {
                limit: limits.max_frame_bytes.min(limits.max_message_bytes),
            },
            E::Protocol(error) => Self::Protocol {
                reason: error.to_string(),
            },
            E::WriteBufferFull(_) => Self::Protocol {
                reason: "write buffer is full".to_string(),
            },
            E::Utf8(_) => Self::Protocol {
                reason: "text frame is not valid UTF-8".to_string(),
            },
            E::AttackAttempt => Self::Protocol {
                reason: "attack attempt detected".to_string(),
            },
            E::Url(_) => Self::InvalidUrl {
                reason: "websocket client rejected the URL".to_string(),
            },
            E::Http(response) => {
                let status = response.status().as_u16();
                if (300..400).contains(&status) {
                    Self::RedirectRejected { status }
                } else {
                    Self::HandshakeRejected { status }
                }
            }
            E::HttpFormat(_) => Self::Protocol {
                reason: "malformed HTTP handshake".to_string(),
            },
        }
    }

    /// Stable machine-readable category for audit and status surfaces.
    pub fn stable_reason(&self) -> &'static str {
        match self {
            Self::InvalidUrl { .. } => "invalid_url",
            Self::InvalidLimits { .. } => "invalid_limits",
            Self::PolicyDenied { .. } => "policy_denied",
            Self::Dns { .. } => "dns_failed",
            Self::Connect { .. } => "connect_failed",
            Self::ConnectTimeout => "connect_timeout",
            Self::HandshakeRejected { .. } => "handshake_rejected",
            Self::RedirectRejected { .. } => "redirect_rejected",
            Self::FrameTooLarge { .. } => "frame_too_large",
            Self::RateLimitExceeded { .. } => "rate_limit_exceeded",
            Self::IdleTimeout => "idle_timeout",
            Self::SendTimeout => "send_timeout",
            Self::Protocol { .. } => "protocol_error",
            Self::Closed => "closed",
        }
    }
}
