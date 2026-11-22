use std::{fmt, net::IpAddr, time::Duration};

use ironclaw_host_api::{action::NetworkPolicy, resource::ResourceScope};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::error::WebSocketError;

/// Hard ceilings a caller-supplied [`WebSocketLimits`] may not exceed.
pub const MAX_FRAME_BYTES_CEILING: usize = 1024 * 1024;
pub const MAX_MESSAGE_BYTES_CEILING: usize = 4 * 1024 * 1024;
pub const MAX_MESSAGES_PER_SECOND_CEILING: u32 = 1000;

/// Per-connection resource limits enforced by the network boundary.
///
/// `max_messages_per_second` is a hard safety ceiling: a peer that exceeds it
/// is disconnected with [`WebSocketError::RateLimitExceeded`]. Callers that
/// want softer pacing (stop reading instead of failing) apply it above this
/// layer, below the ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebSocketLimits {
    pub max_frame_bytes: usize,
    pub max_message_bytes: usize,
    /// Covers TCP connect, TLS, and the HTTP upgrade together.
    pub connect_timeout: Duration,
    /// Maximum silence (no frame of any kind) before the peer is declared dead.
    pub idle_timeout: Duration,
    /// Keepalive ping cadence; must be shorter than `idle_timeout`.
    pub ping_interval: Duration,
    pub max_messages_per_second: u32,
}

impl Default for WebSocketLimits {
    fn default() -> Self {
        Self {
            max_frame_bytes: 64 * 1024,
            max_message_bytes: 256 * 1024,
            connect_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(150),
            ping_interval: Duration::from_secs(60),
            max_messages_per_second: 100,
        }
    }
}

impl WebSocketLimits {
    pub fn validate(&self) -> Result<(), WebSocketError> {
        let invalid = |reason: &str| {
            Err(WebSocketError::InvalidLimits {
                reason: reason.to_string(),
            })
        };
        if self.max_frame_bytes == 0 || self.max_frame_bytes > MAX_FRAME_BYTES_CEILING {
            return invalid("max_frame_bytes must be between 1 and the frame ceiling");
        }
        if self.max_message_bytes < self.max_frame_bytes
            || self.max_message_bytes > MAX_MESSAGE_BYTES_CEILING
        {
            return invalid(
                "max_message_bytes must be at least max_frame_bytes and within the message ceiling",
            );
        }
        if self.connect_timeout.is_zero() || self.idle_timeout.is_zero() {
            return invalid("timeouts must be non-zero");
        }
        if self.ping_interval.is_zero() || self.ping_interval >= self.idle_timeout {
            return invalid("ping_interval must be non-zero and shorter than idle_timeout");
        }
        if self.max_messages_per_second == 0
            || self.max_messages_per_second > MAX_MESSAGES_PER_SECOND_CEILING
        {
            return invalid("max_messages_per_second must be between 1 and the rate ceiling");
        }
        Ok(())
    }
}

/// One scoped request to open an outbound WebSocket.
///
/// `url` may carry a connection ticket in its query string, so the buffer is
/// scrubbed on drop and `Debug` never prints it.
#[derive(Clone)]
pub struct WebSocketConnectRequest {
    pub scope: ResourceScope,
    pub url: String,
    pub policy: NetworkPolicy,
    pub limits: WebSocketLimits,
}

impl Drop for WebSocketConnectRequest {
    fn drop(&mut self) {
        self.url.zeroize();
    }
}

impl ZeroizeOnDrop for WebSocketConnectRequest {}

impl fmt::Debug for WebSocketConnectRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebSocketConnectRequest")
            .field("scope", &self.scope)
            .field("url", &"<redacted>")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

/// Request handed to a [`super::WebSocketTransport`] after policy, URL, DNS,
/// and private-address checks succeed.
///
/// The endpoint (`host`, `port`, `path`) never carries the connection ticket;
/// only `query` does. The connector already evaluated policy and DNS on the
/// endpoint alone, so the ticket first appears here, at the handshake
/// boundary. The query buffer is scrubbed on drop and `Debug` never prints it.
#[derive(Clone)]
pub struct WebSocketTransportRequest {
    /// Host as it appears in the URL (an IPv6 literal keeps its brackets).
    pub host: String,
    pub port: u16,
    /// Absolute path, already normalized and percent-encoded.
    pub path: String,
    /// Query string without the leading `?`; may hold the ticket.
    pub query: Option<String>,
    pub resolved_ips: Vec<IpAddr>,
    /// Carried so the transport can re-check each candidate address and the
    /// connected peer address at dial time.
    pub deny_private_ip_ranges: bool,
    pub limits: WebSocketLimits,
}
impl Drop for WebSocketTransportRequest {
    fn drop(&mut self) {
        self.query.zeroize();
    }
}
impl ZeroizeOnDrop for WebSocketTransportRequest {}
impl fmt::Debug for WebSocketTransportRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebSocketTransportRequest")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("query", &self.query.as_ref().map(|_| "<redacted>"))
            .field("resolved_ips", &self.resolved_ips)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}
/// One application data message. Control frames never surface.
#[derive(Clone, PartialEq, Eq)]
pub enum WebSocketMessage {
    Text(String),
    Binary(Vec<u8>),
}

impl WebSocketMessage {
    pub fn len(&self) -> usize {
        match self {
            Self::Text(text) => text.len(),
            Self::Binary(bytes) => bytes.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl fmt::Debug for WebSocketMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::Text(_) => "Text",
            Self::Binary(_) => "Binary",
        };
        write!(f, "WebSocketMessage::{kind}({} bytes)", self.len())
    }
}
