use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use async_trait::async_trait;
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::ServerName;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream,
    tungstenite::protocol::{Role, WebSocketConfig},
};
use zeroize::Zeroizing;

use super::{
    connection::WebSocketConnection,
    connector::WebSocketTransport,
    error::WebSocketError,
    types::{WebSocketLimits, WebSocketTransportRequest},
    upgrade::{UpgradeRequest, client_upgrade},
};
use crate::policy::is_private_or_loopback_ip;

/// The production WebSocket transport.
///
/// It dials only the addresses the policy layer resolved and vetted (no second
/// DNS lookup), re-checks each candidate and the connected peer against the
/// private-address rule, never follows handshake redirects, and runs TLS
/// through the same rustls build and native roots as the `reqwest` transport.
/// The opening handshake is [`super::upgrade`]'s, so the ticket only ever sits
/// in scrubbed buffers; `tokio-tungstenite` carries the frames afterwards.
#[derive(Debug, Clone, Copy, Default)]
pub struct TungsteniteWebSocketTransport {
    _private: (),
}

impl TungsteniteWebSocketTransport {
    pub fn new() -> Self {
        Self { _private: () }
    }

    async fn dial(
        request: &mut WebSocketTransportRequest,
    ) -> Result<WebSocketConnection, WebSocketError> {
        let limits = request.limits;
        let stream = dial_vetted_addresses(
            &request.resolved_ips,
            request.port,
            request.deny_private_ip_ranges,
        )
        .await?;
        let stream = wrap_tls(stream, &request.host).await?;
        let socket = open_websocket(stream, request).await?;
        Ok(WebSocketConnection::new(socket, limits))
    }
}

#[async_trait]
impl WebSocketTransport for TungsteniteWebSocketTransport {
    async fn connect(
        &self,
        mut request: WebSocketTransportRequest,
    ) -> Result<WebSocketConnection, WebSocketError> {
        let limits = request.limits;
        within_connect_timeout(&limits, Self::dial(&mut request)).await
    }
}

/// Bounds TCP connect, TLS, and the HTTP upgrade together.
pub(super) async fn within_connect_timeout<F>(
    limits: &WebSocketLimits,
    attempt: F,
) -> Result<WebSocketConnection, WebSocketError>
where
    F: Future<Output = Result<WebSocketConnection, WebSocketError>>,
{
    match tokio::time::timeout(limits.connect_timeout, attempt).await {
        Ok(result) => result,
        Err(_elapsed) => Err(WebSocketError::ConnectTimeout),
    }
}

/// Runs the WebSocket upgrade over an established (and, for `wss`, already
/// TLS-wrapped) stream, then hands the stream to the frame layer together
/// with any bytes the server sent right behind its response head.
///
/// The ticket enters here: the query is moved into a `Zeroizing` owner, the
/// request is rendered into a scrubbed buffer, and both are overwritten before
/// this function returns on any path.
pub(super) async fn open_websocket<S>(
    mut stream: S,
    request: &mut WebSocketTransportRequest,
) -> Result<WebSocketStream<S>, WebSocketError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let limits = request.limits;
    let query = request.query.take().map(Zeroizing::new);
    let built = UpgradeRequest::build(
        &request.host,
        request.port,
        &request.path,
        query.as_ref().map(|query| query.as_str()),
    );
    drop(query);
    let mut upgrade = built?;
    let leftover = client_upgrade(&mut stream, &mut upgrade, limits.connect_timeout).await?;
    drop(upgrade);
    let config = WebSocketConfig::default()
        .max_frame_size(Some(limits.max_frame_bytes))
        .max_message_size(Some(limits.max_message_bytes));
    Ok(WebSocketStream::from_partially_read(stream, leftover, Role::Client, Some(config)).await)
}

/// TLS over the vetted TCP stream: rustls with the `ring` provider (the one
/// `reqwest` uses) and the platform's native roots. The provider is named
/// explicitly because the workspace also links `aws-lc-rs`, and rustls panics
/// when asked to pick a process default among several.
async fn wrap_tls(
    stream: TcpStream,
    host: &str,
) -> Result<MaybeTlsStream<TcpStream>, WebSocketError> {
    wrap_tls_with(tls_client_config()?, stream, host).await
}

async fn wrap_tls_with(
    config: Arc<ClientConfig>,
    stream: TcpStream,
    host: &str,
) -> Result<MaybeTlsStream<TcpStream>, WebSocketError> {
    let name = ServerName::try_from(host.trim_matches(['[', ']']).to_string()).map_err(
        |_invalid_dns_name| {
            // The rejected host is dropped on purpose: the error text is fixed.
            WebSocketError::InvalidUrl {
                reason: "host is not a valid TLS server name".to_string(),
            }
        },
    )?;
    let connected = tokio_rustls::TlsConnector::from(config)
        .connect(name, stream)
        .await
        .map_err(|error| WebSocketError::Connect {
            reason: format!("TLS handshake failed ({:?})", error.kind()),
        })?;
    Ok(MaybeTlsStream::Rustls(connected))
}

// Native roots are read from the OS store once per process; only a successful
// load is cached, so a failure is retried on the next dial.
static TLS_CONFIG: std::sync::OnceLock<Arc<ClientConfig>> = std::sync::OnceLock::new();

fn tls_client_config() -> Result<Arc<ClientConfig>, WebSocketError> {
    if let Some(cached) = TLS_CONFIG.get() {
        return Ok(Arc::clone(cached));
    }
    let config = build_tls_client_config()?;
    Ok(Arc::clone(TLS_CONFIG.get_or_init(|| config)))
}

fn build_tls_client_config() -> Result<Arc<ClientConfig>, WebSocketError> {
    let loaded = rustls_native_certs::load_native_certs();
    if !loaded.errors.is_empty() {
        tracing::warn!(
            target: "ironclaw_network::websocket",
            count = loaded.errors.len(),
            "some native root CA certificates could not be loaded"
        );
    }
    let mut roots = RootCertStore::empty();
    let (added, _ignored) = roots.add_parsable_certificates(loaded.certs);
    if added == 0 {
        return Err(WebSocketError::Connect {
            reason: "no native root CA certificates available".to_string(),
        });
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_unsupported_versions| WebSocketError::Connect {
            reason: "TLS protocol versions unavailable".to_string(),
        })?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// `TCP_NODELAY` is a latency optimisation; failing to set it must not abort
/// the dial. Returns whether it was applied.
fn note_nodelay(result: std::io::Result<()>) -> bool {
    match result {
        Ok(()) => true,
        Err(error) => {
            tracing::warn!(
                target: "ironclaw_network::websocket",
                kind = ?error.kind(),
                "TCP_NODELAY unavailable; continuing without it"
            );
            false
        }
    }
}

/// Dials the first reachable vetted address. Every candidate is re-checked
/// before any socket opens, and the connected peer address is checked again.
async fn dial_vetted_addresses(
    candidates: &[IpAddr],
    port: u16,
    deny_private: bool,
) -> Result<TcpStream, WebSocketError> {
    if candidates.is_empty() {
        return Err(WebSocketError::Dns {
            reason: "no resolved addresses to dial".to_string(),
        });
    }
    if deny_private && candidates.iter().copied().any(is_private_or_loopback_ip) {
        return Err(WebSocketError::PolicyDenied {
            reason: "network target resolves to a private or host-local IP".to_string(),
        });
    }
    let mut last_kind = None;
    for ip in candidates {
        match TcpStream::connect(SocketAddr::new(*ip, port)).await {
            Ok(stream) => {
                if deny_private {
                    let peer = stream
                        .peer_addr()
                        .map_err(|error| WebSocketError::Connect {
                            reason: format!("peer address unavailable ({:?})", error.kind()),
                        })?;
                    if is_private_or_loopback_ip(peer.ip()) {
                        return Err(WebSocketError::PolicyDenied {
                            reason: "connected peer is a private or host-local IP".to_string(),
                        });
                    }
                }
                note_nodelay(stream.set_nodelay(true));
                return Ok(stream);
            }
            Err(error) => last_kind = Some(error.kind()),
        }
    }
    Err(WebSocketError::Connect {
        reason: match last_kind {
            Some(kind) => format!("TCP connect failed ({kind:?})"),
            None => "TCP connect failed".to_string(),
        },
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_nodelay_failure_is_noted_and_does_not_fail_the_dial() {
        let failure = std::io::Error::from(std::io::ErrorKind::Unsupported);
        assert!(!super::note_nodelay(Err(failure)));
        assert!(super::note_nodelay(Ok(())));
    }
    use std::{net::Ipv4Addr, sync::Arc};

    use futures_util::{SinkExt, StreamExt};
    use rustls::{ClientConfig, RootCertStore, ServerConfig};
    use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::net::TcpListener;

    #[test]
    fn native_roots_are_loaded_once_and_shared_between_dials() {
        let Ok(first) = super::tls_client_config() else {
            return;
        };
        let second = super::tls_client_config().expect("cached");
        assert!(Arc::ptr_eq(&first, &second));
    }

    #[tokio::test]
    async fn dialed_sockets_disable_nagle_for_small_ack_frames() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let stream = super::dial_vetted_addresses(&[Ipv4Addr::LOCALHOST.into()], port, false)
            .await
            .expect("dial");
        assert!(stream.nodelay().expect("nodelay"), "TCP_NODELAY is set");
    }
    use tokio_tungstenite::tungstenite::Message;

    use super::{open_websocket, wrap_tls_with};
    use crate::websocket::types::{WebSocketLimits, WebSocketTransportRequest};

    const HOST: &str = "gateway.example.test";
    const TICKET: &str = "SECRET_TICKET_123";

    /// The production TLS path (explicit `ring` provider, hand-written upgrade
    /// over rustls) against an in-process TLS server with a throwaway
    /// certificate. A provider-selection panic or an upgrade that only works
    /// over plaintext fails here.
    // tungstenite fixes the handshake callback's signature, including its
    // large error type.
    #[allow(clippy::result_large_err)]
    #[tokio::test]
    async fn upgrade_and_frames_work_over_tls_with_the_ring_provider() {
        let certified = rcgen::generate_simple_self_signed(vec![HOST.to_string()])
            .expect("self-signed certificate");
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let server_config = ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .expect("server protocol versions")
            .with_no_client_auth()
            .with_single_cert(
                vec![certified.cert.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    certified.signing_key.serialize_der(),
                )),
            )
            .expect("server certificate");
        let mut roots = RootCertStore::empty();
        roots
            .add(certified.cert.der().clone())
            .expect("trust the test certificate");
        let client_config = Arc::new(
            ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .expect("client protocol versions")
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("accept");
            let tls = acceptor.accept(tcp).await.expect("server TLS");
            let mut socket = tokio_tungstenite::accept_hdr_async(
                tls,
                |request: &tokio_tungstenite::tungstenite::handshake::server::Request, response| {
                    assert_eq!(
                        request.uri().to_string(),
                        format!("/connect?ticket={TICKET}")
                    );
                    Ok(response)
                },
            )
            .await
            .expect("server upgrade");
            while let Some(Ok(message)) = socket.next().await {
                if message.is_text() && socket.send(message).await.is_err() {
                    return;
                }
            }
        });

        let tcp = tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .expect("connect");
        let tls = wrap_tls_with(client_config, tcp, HOST)
            .await
            .expect("client TLS");
        let mut request = WebSocketTransportRequest {
            host: HOST.to_string(),
            port,
            path: "/connect".to_string(),
            query: Some(format!("ticket={TICKET}")),
            resolved_ips: Vec::new(),
            deny_private_ip_ranges: true,
            limits: WebSocketLimits::default(),
        };
        let mut socket = open_websocket(tls, &mut request).await.expect("upgrade");
        assert!(
            request.query.is_none(),
            "the query moved into a scrubbed owner"
        );
        socket
            .send(Message::Text("over tls".into()))
            .await
            .expect("send");
        let echoed = socket.next().await.expect("open").expect("frame");
        assert_eq!(echoed, Message::Text("over tls".into()));
        drop(socket);
        server.abort();
    }
}
