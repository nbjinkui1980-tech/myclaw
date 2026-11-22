//! Policy-checked outbound WebSocket client.
//!
//! The one sanctioned WebSocket client in the workspace. A connection goes
//! through the same gates as outbound HTTP: scheme (`wss` only), exact
//! allow-listed host, DNS resolution with private/reserved address denial,
//! and a dial-time re-check of every candidate address and the connected
//! peer. Handshake redirects are never followed. Frame, message, timeout, and
//! rate limits are enforced here, and no error, `Debug` output, or log line
//! carries the URL (it can hold a connection ticket); only the host appears.
//!
//! TLS is the same rustls build (`ring` provider) and native root store
//! `reqwest` uses. The opening handshake is written in [`upgrade`] rather than
//! delegated to `tokio-tungstenite`, so the ticket in the URL's query is never
//! parsed into an unscrubbable `Uri`: policy and DNS see only the endpoint, and
//! the request line lives in a `Zeroizing` buffer. The unscrubbable remainder
//! is rustls's plaintext write buffer and the kernel socket buffers.
//! `tokio-tungstenite` carries frames after the upgrade.

mod connection;
mod connector;
mod error;
#[cfg(any(debug_assertions, feature = "test-support"))]
mod loopback;
mod transport;
mod types;
mod upgrade;

pub use connection::{WebSocketConnection, WebSocketReceiver, WebSocketSender};
pub use connector::{PolicyWebSocketConnector, WebSocketConnector, WebSocketTransport};
pub use error::WebSocketError;
#[cfg(any(debug_assertions, feature = "test-support"))]
pub use loopback::LoopbackWebSocketTransport;
pub use transport::TungsteniteWebSocketTransport;
pub use types::{
    MAX_FRAME_BYTES_CEILING, MAX_MESSAGE_BYTES_CEILING, MAX_MESSAGES_PER_SECOND_CEILING,
    WebSocketConnectRequest, WebSocketLimits, WebSocketMessage, WebSocketTransportRequest,
};
