//! Test-support seam: a [`WebSocketTransport`] that dials one loopback address
//! over plaintext `ws`.
//!
//! Everything above the dial still runs for real when this sits under
//! [`PolicyWebSocketConnector`](super::PolicyWebSocketConnector): URL parsing,
//! the `wss` allow-list, the resolver and private-address checks, and the
//! limits. Only the final TCP/TLS step is replaced, the same way
//! `RewriteNetworkTransport` redirects HTTP to a loopback fake vendor.
//!
//! Guard rails: the module is compiled only under `debug_assertions` or the
//! `test-support` feature (a shipped release binary has no such type), it is
//! constructor-only (no environment switch), and a non-loopback address is
//! refused at connect time.

use std::net::SocketAddr;

use async_trait::async_trait;
use tokio::net::TcpStream;
use tokio_tungstenite::MaybeTlsStream;

use super::{
    connection::WebSocketConnection,
    connector::WebSocketTransport,
    error::WebSocketError,
    transport::{open_websocket, within_connect_timeout},
    types::WebSocketTransportRequest,
};

#[derive(Debug, Clone, Copy)]
pub struct LoopbackWebSocketTransport {
    addr: SocketAddr,
}

impl LoopbackWebSocketTransport {
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }

    async fn dial(
        &self,
        request: &mut WebSocketTransportRequest,
    ) -> Result<WebSocketConnection, WebSocketError> {
        let limits = request.limits;
        if !self.addr.ip().is_loopback() {
            return Err(WebSocketError::Connect {
                reason: "loopback seam requires a loopback address".to_string(),
            });
        }
        let stream =
            TcpStream::connect(self.addr)
                .await
                .map_err(|error| WebSocketError::Connect {
                    reason: format!("TCP connect failed ({:?})", error.kind()),
                })?;
        let socket = open_websocket(MaybeTlsStream::Plain(stream), request).await?;
        Ok(WebSocketConnection::new(socket, limits))
    }
}

#[async_trait]
impl WebSocketTransport for LoopbackWebSocketTransport {
    async fn connect(
        &self,
        mut request: WebSocketTransportRequest,
    ) -> Result<WebSocketConnection, WebSocketError> {
        let limits = request.limits;
        within_connect_timeout(&limits, self.dial(&mut request)).await
    }
}
