//! Contract tests for the policy-checked outbound WebSocket client.
//!
//! A loopback fake gateway stands in for the remote peer. The connector under
//! test is the production `PolicyWebSocketConnector` (real URL parsing, policy,
//! resolver checks, limits, connection handling); only the final dial goes
//! through the compile-gated `LoopbackWebSocketTransport` seam to loopback
//! plaintext, the way `RewriteNetworkTransport` does for HTTP. The fake
//! resolver supplies a public-looking address so the policy path runs for
//! real. The production `TungsteniteWebSocketTransport` is covered by the
//! dial-time private-address re-check test (its TLS leg needs a real
//! certificate chain and is not exercised here).
#![cfg(any(debug_assertions, feature = "test-support"))]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use ironclaw_host_api::{
    action::{NetworkPolicy, NetworkScheme, NetworkTargetPattern},
    ids::{InvocationId, TenantId, UserId},
    resource::ResourceScope,
};
use ironclaw_network::{
    LoopbackWebSocketTransport, NetworkHttpError, NetworkResolver, PolicyWebSocketConnector,
    TungsteniteWebSocketTransport, WebSocketConnectRequest, WebSocketConnector, WebSocketError,
    WebSocketLimits, WebSocketMessage, WebSocketTransport, WebSocketTransportRequest,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_tungstenite::tungstenite::{
    self, Message,
    handshake::{
        derive_accept_key,
        server::{Callback, ErrorResponse, Request, Response},
    },
};

const SECRET: &str = "SECRET_TICKET_123";
const GATEWAY_HOST: &str = "gateway.example.test";

fn public_ip() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))
}

#[derive(Clone)]
struct FixedResolver(Vec<IpAddr>);

impl NetworkResolver for FixedResolver {
    fn resolve_ips(&self, _host: &str, _port: u16) -> Result<Vec<IpAddr>, NetworkHttpError> {
        Ok(self.0.clone())
    }
}

fn scope() -> ResourceScope {
    ResourceScope {
        tenant_id: TenantId::new("tenant1").unwrap(),
        user_id: UserId::new("user1").unwrap(),
        agent_id: None,
        project_id: None,
        mission_id: None,
        thread_id: None,
        invocation_id: InvocationId::new(),
    }
}

fn policy_for(host: &str) -> NetworkPolicy {
    NetworkPolicy {
        allowed_targets: vec![NetworkTargetPattern {
            scheme: Some(NetworkScheme::Wss),
            host_pattern: host.to_string(),
            port: None,
        }],
        deny_private_ip_ranges: true,
        max_egress_bytes: None,
    }
}

fn fast_limits() -> WebSocketLimits {
    WebSocketLimits {
        max_frame_bytes: 1024,
        max_message_bytes: 4096,
        connect_timeout: Duration::from_secs(2),
        idle_timeout: Duration::from_secs(5),
        ping_interval: Duration::from_secs(2),
        max_messages_per_second: 100,
    }
}

fn request(url: &str, policy: NetworkPolicy, limits: WebSocketLimits) -> WebSocketConnectRequest {
    WebSocketConnectRequest {
        scope: scope(),
        url: url.to_string(),
        policy,
        limits,
    }
}

fn gateway_url() -> String {
    format!("wss://{GATEWAY_HOST}/connect?ticket={SECRET}")
}

fn connector_to(
    addr: SocketAddr,
    resolved: Vec<IpAddr>,
) -> PolicyWebSocketConnector<LoopbackWebSocketTransport, FixedResolver> {
    PolicyWebSocketConnector::new_with_resolver(
        LoopbackWebSocketTransport::new(addr),
        FixedResolver(resolved),
    )
}

fn transport_request(resolved_ips: Vec<IpAddr>) -> WebSocketTransportRequest {
    WebSocketTransportRequest {
        host: GATEWAY_HOST.to_string(),
        port: 443,
        path: "/connect".to_string(),
        query: Some(format!("ticket={SECRET}")),
        resolved_ips,
        deny_private_ip_ranges: true,
        limits: fast_limits(),
    }
}
fn assert_no_secret(error: &WebSocketError) {
    let rendered = format!("{error} {error:?}");
    assert!(!rendered.contains(SECRET), "leaked ticket: {rendered}");
    assert!(!rendered.contains("ticket="), "leaked query: {rendered}");
}

/// Loopback fake gateway. Counts TCP accepts so tests can prove a denied
/// request never dialed.
struct Gateway {
    addr: SocketAddr,
    accepts: Arc<AtomicUsize>,
}

async fn bind() -> (TcpListener, SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    (listener, addr, Arc::new(AtomicUsize::new(0)))
}

struct UriRecorder(Option<tokio::sync::mpsc::UnboundedSender<String>>);

impl Callback for UriRecorder {
    // tungstenite fixes this signature, including the large error type.
    #[allow(clippy::result_large_err)]
    fn on_request(self, request: &Request, response: Response) -> Result<Response, ErrorResponse> {
        if let Some(uris) = &self.0 {
            let _ = uris.send(request.uri().to_string());
        }
        Ok(response)
    }
}

/// Echo gateway: records the upgrade request URI and echoes data frames.
async fn echo_gateway(uris: Option<tokio::sync::mpsc::UnboundedSender<String>>) -> Gateway {
    let (listener, addr, accepts) = bind().await;
    let counter = accepts.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            let uris = uris.clone();
            tokio::spawn(async move {
                let callback = UriRecorder(uris);
                let Ok(mut ws) = tokio_tungstenite::accept_hdr_async(stream, callback).await else {
                    return;
                };
                while let Some(Ok(message)) = ws.next().await {
                    if (message.is_text() || message.is_binary()) && ws.send(message).await.is_err()
                    {
                        return;
                    }
                }
            });
        }
    });
    Gateway { addr, accepts }
}

/// Scripted gateway: completes the upgrade, then runs `script` on the socket.
async fn scripted_gateway<F, Fut>(script: F) -> Gateway
where
    F: Fn(tokio_tungstenite::WebSocketStream<TcpStream>) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let (listener, addr, accepts) = bind().await;
    let counter = accepts.clone();
    let script = Arc::new(script);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            let script = script.clone();
            tokio::spawn(async move {
                if let Ok(ws) = tokio_tungstenite::accept_async(stream).await {
                    script(ws).await;
                }
            });
        }
    });
    Gateway { addr, accepts }
}

/// Raw gateway that answers the upgrade request by hand so a test controls
/// every byte (redirects, rejections, slow frames).
async fn raw_gateway<F, Fut>(handler: F) -> Gateway
where
    F: Fn(TcpStream, String) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let (listener, addr, accepts) = bind().await;
    let counter = accepts.clone();
    let handler = Arc::new(handler);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            let handler = handler.clone();
            tokio::spawn(async move {
                let mut buffer = Vec::new();
                let mut chunk = [0u8; 1024];
                while !buffer.windows(4).any(|window| window == b"\r\n\r\n") {
                    match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => buffer.extend_from_slice(&chunk[..read]),
                    }
                }
                let text = String::from_utf8_lossy(&buffer).to_string();
                let key = text
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("sec-websocket-key")
                            .then(|| value.trim().to_string())
                    })
                    .unwrap_or_default();
                handler(stream, key).await;
            });
        }
    });
    Gateway { addr, accepts }
}

async fn finish_upgrade(stream: &mut TcpStream, key: &str) {
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
        derive_accept_key(key.as_bytes())
    );
    stream.write_all(response.as_bytes()).await.unwrap();
}

#[tokio::test]
async fn connects_through_policy_and_exchanges_frames_with_the_fake_gateway() {
    let (tx, mut uris) = tokio::sync::mpsc::unbounded_channel();
    let gateway = echo_gateway(Some(tx)).await;
    let connector = connector_to(gateway.addr, vec![public_ip()]);

    let mut connection = connector
        .connect(request(
            &gateway_url(),
            policy_for(GATEWAY_HOST),
            fast_limits(),
        ))
        .await
        .expect("allow-listed public host connects");

    connection
        .send(WebSocketMessage::Text("hello".to_string()))
        .await
        .unwrap();
    assert_eq!(
        connection.recv().await.unwrap(),
        Some(WebSocketMessage::Text("hello".to_string()))
    );
    connection
        .send(WebSocketMessage::Binary(vec![1, 2, 3]))
        .await
        .unwrap();
    assert_eq!(
        connection.recv().await.unwrap(),
        Some(WebSocketMessage::Binary(vec![1, 2, 3]))
    );
    // The ticket reaches the peer in the upgrade request (it is the
    // protocol), so the connector must not have mangled the query.
    let uri = uris.recv().await.unwrap();
    assert_eq!(uri, format!("/connect?ticket={SECRET}"));
}

#[tokio::test]
async fn split_halves_send_while_receive_is_pending() {
    let gateway = echo_gateway(None).await;
    let connector = connector_to(gateway.addr, vec![public_ip()]);
    let connection = connector
        .connect(request(
            &gateway_url(),
            policy_for(GATEWAY_HOST),
            fast_limits(),
        ))
        .await
        .unwrap();
    let (sender, mut receiver) = connection.split();
    let reader = tokio::spawn(async move { receiver.recv().await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    sender
        .send(WebSocketMessage::Text("ack".to_string()))
        .await
        .unwrap();
    let received = tokio::time::timeout(Duration::from_secs(2), reader)
        .await
        .expect("receiver completes")
        .unwrap()
        .unwrap();
    assert_eq!(received, Some(WebSocketMessage::Text("ack".to_string())));
}

#[tokio::test]
async fn host_outside_the_allowlist_is_denied_without_dialing() {
    let gateway = echo_gateway(None).await;
    let connector = connector_to(gateway.addr, vec![public_ip()]);
    let error = connector
        .connect(request(
            &format!("wss://other.example.test/connect?ticket={SECRET}"),
            policy_for(GATEWAY_HOST),
            fast_limits(),
        ))
        .await
        .expect_err("non-allowlisted host must be denied");
    assert!(
        matches!(error, WebSocketError::PolicyDenied { .. }),
        "{error:?}"
    );
    assert_no_secret(&error);
    assert_eq!(gateway.accepts.load(Ordering::SeqCst), 0, "must not dial");
}

#[tokio::test]
async fn private_or_reserved_resolved_addresses_are_denied_without_dialing() {
    let gateway = echo_gateway(None).await;
    for resolved in [
        vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))],
        vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))],
        vec![IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))],
        vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        vec![IpAddr::V6(Ipv6Addr::LOCALHOST)],
        // One private address among public ones still denies the target.
        vec![public_ip(), IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))],
    ] {
        let connector = connector_to(gateway.addr, resolved.clone());
        let error = connector
            .connect(request(
                &gateway_url(),
                policy_for(GATEWAY_HOST),
                fast_limits(),
            ))
            .await
            .expect_err("private resolution must be denied");
        assert!(
            matches!(error, WebSocketError::PolicyDenied { .. }),
            "{resolved:?} -> {error:?}"
        );
        assert_no_secret(&error);
    }
    assert_eq!(gateway.accepts.load(Ordering::SeqCst), 0, "must not dial");
}

#[tokio::test]
async fn private_literal_ip_hosts_are_denied_even_when_allow_listed() {
    let gateway = echo_gateway(None).await;
    let connector = connector_to(gateway.addr, vec![public_ip()]);
    let error = connector
        .connect(request(
            &format!("wss://10.0.0.5/connect?ticket={SECRET}"),
            policy_for("10.0.0.5"),
            fast_limits(),
        ))
        .await
        .expect_err("private literal host must be denied");
    assert!(
        matches!(error, WebSocketError::PolicyDenied { .. }),
        "{error:?}"
    );
    assert_eq!(gateway.accepts.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn only_wss_urls_without_userinfo_are_accepted() {
    let gateway = echo_gateway(None).await;
    let connector = connector_to(gateway.addr, vec![public_ip()]);
    for url in [
        format!("ws://{GATEWAY_HOST}/connect?ticket={SECRET}"),
        format!("https://{GATEWAY_HOST}/connect?ticket={SECRET}"),
        format!("http://{GATEWAY_HOST}/connect?ticket={SECRET}"),
        format!("wss://user:pw@{GATEWAY_HOST}/connect?ticket={SECRET}"),
        "not a url".to_string(),
        // The ticket is never allowed to ride in a fragment or break the
        // request line.
        format!("wss://{GATEWAY_HOST}/connect?ticket={SECRET}#frag"),
        format!("wss://{GATEWAY_HOST}/connect?ticket={SECRET}\r\nX-Injected: 1"),
        format!("wss://{GATEWAY_HOST}/connect?ticket={SECRET} HTTP/1.1"),
    ] {
        let error = connector
            .connect(request(&url, policy_for(GATEWAY_HOST), fast_limits()))
            .await
            .expect_err("invalid url must be rejected");
        assert!(
            matches!(error, WebSocketError::InvalidUrl { .. }),
            "{url} -> {error:?}"
        );
        assert_no_secret(&error);
    }
    assert_eq!(gateway.accepts.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn policy_patterns_that_are_not_exact_wss_hosts_never_authorize() {
    let gateway = echo_gateway(None).await;
    let connector = connector_to(gateway.addr, vec![public_ip()]);
    let pattern = |scheme, host: &str, port| NetworkPolicy {
        allowed_targets: vec![NetworkTargetPattern {
            scheme,
            host_pattern: host.to_string(),
            port,
        }],
        deny_private_ip_ranges: true,
        max_egress_bytes: None,
    };
    for (label, policy) in [
        (
            "wildcard host",
            pattern(Some(NetworkScheme::Wss), "*.example.test", None),
        ),
        (
            "bare wildcard",
            pattern(Some(NetworkScheme::Wss), "*", None),
        ),
        ("any scheme", pattern(None, GATEWAY_HOST, None)),
        (
            "https only",
            pattern(Some(NetworkScheme::Https), GATEWAY_HOST, None),
        ),
        (
            "wrong port",
            pattern(Some(NetworkScheme::Wss), GATEWAY_HOST, Some(8443)),
        ),
        (
            "empty allowlist",
            NetworkPolicy {
                allowed_targets: Vec::new(),
                deny_private_ip_ranges: true,
                max_egress_bytes: None,
            },
        ),
    ] {
        let error = connector
            .connect(request(&gateway_url(), policy, fast_limits()))
            .await
            .expect_err(label);
        assert!(
            matches!(error, WebSocketError::PolicyDenied { .. }),
            "{label}: {error:?}"
        );
    }
    assert_eq!(gateway.accepts.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_pattern_without_a_port_means_443_only() {
    let gateway = echo_gateway(None).await;
    let connector = connector_to(gateway.addr, vec![public_ip()]);
    let error = connector
        .connect(request(
            &format!("wss://{GATEWAY_HOST}:8443/connect?ticket={SECRET}"),
            policy_for(GATEWAY_HOST),
            fast_limits(),
        ))
        .await
        .expect_err("non-443 port needs an explicit pattern port");
    assert!(
        matches!(error, WebSocketError::PolicyDenied { .. }),
        "{error:?}"
    );
    // An explicit pattern port authorizes exactly that port.
    let mut policy = policy_for(GATEWAY_HOST);
    policy.allowed_targets[0].port = Some(8443);
    connector
        .connect(request(
            &format!("wss://{GATEWAY_HOST}:8443/connect"),
            policy,
            fast_limits(),
        ))
        .await
        .expect("explicit port is authorized");
    assert_eq!(gateway.accepts.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn invalid_limits_are_rejected_before_any_dial() {
    let gateway = echo_gateway(None).await;
    let connector = connector_to(gateway.addr, vec![public_ip()]);
    let mut limits = fast_limits();
    limits.ping_interval = limits.idle_timeout;
    let error = connector
        .connect(request(&gateway_url(), policy_for(GATEWAY_HOST), limits))
        .await
        .expect_err("ping interval must be shorter than idle timeout");
    assert!(
        matches!(error, WebSocketError::InvalidLimits { .. }),
        "{error:?}"
    );
    assert_eq!(gateway.accepts.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn handshake_redirect_is_rejected_and_never_followed() {
    let target = echo_gateway(None).await;
    let redirect_to = format!("ws://{}/elsewhere", target.addr);
    let redirector = raw_gateway(move |mut stream, _key| {
        let location = redirect_to.clone();
        async move {
            let response =
                format!("HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\n\r\n");
            let _ = stream.write_all(response.as_bytes()).await;
        }
    })
    .await;
    let connector = connector_to(redirector.addr, vec![public_ip()]);
    let error = connector
        .connect(request(
            &gateway_url(),
            policy_for(GATEWAY_HOST),
            fast_limits(),
        ))
        .await
        .expect_err("redirect must not connect");
    assert_eq!(error, WebSocketError::RedirectRejected { status: 302 });
    assert_no_secret(&error);
    assert_eq!(
        target.accepts.load(Ordering::SeqCst),
        0,
        "redirect target must never be contacted"
    );
}

#[tokio::test]
async fn rejected_handshake_reports_status_without_the_query() {
    // 401 and 403 are what the supervisor sorts as an Auth failure (review #1);
    // they must survive the hand-written handshake as `HandshakeRejected`.
    for status in [401u16, 403, 503] {
        let gateway = raw_gateway(move |mut stream, _key| async move {
            let response = format!("HTTP/1.1 {status} Nope\r\nContent-Length: 0\r\n\r\n");
            let _ = stream.write_all(response.as_bytes()).await;
        })
        .await;
        let connector = connector_to(gateway.addr, vec![public_ip()]);
        let error = connector
            .connect(request(
                &gateway_url(),
                policy_for(GATEWAY_HOST),
                fast_limits(),
            ))
            .await
            .expect_err("rejected upgrade must fail");
        assert_eq!(error, WebSocketError::HandshakeRejected { status });
        assert_no_secret(&error);
    }
}
#[tokio::test]
async fn a_forged_or_over_negotiated_upgrade_response_is_refused_without_the_ticket() {
    let wrong_accept = raw_gateway(|mut stream, _key| async move {
        let _ = stream
            .write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: AAAAAAAAAAAAAAAAAAAAAAAAAAA=\r\n\r\n",
            )
            .await;
    })
    .await;
    let extension = raw_gateway(|mut stream, key| async move {
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n",
            derive_accept_key(key.as_bytes())
        );
        let _ = stream.write_all(response.as_bytes()).await;
    })
    .await;
    for gateway in [wrong_accept, extension] {
        let connector = connector_to(gateway.addr, vec![public_ip()]);
        let error = connector
            .connect(request(
                &gateway_url(),
                policy_for(GATEWAY_HOST),
                fast_limits(),
            ))
            .await
            .expect_err("forged upgrade must fail");
        assert!(
            matches!(error, WebSocketError::Protocol { .. }),
            "{error:?}"
        );
        assert_no_secret(&error);
    }
}
#[tokio::test]
async fn frames_sent_right_behind_the_upgrade_response_are_not_lost() {
    let gateway = raw_gateway(|mut stream, key| async move {
        let mut bytes = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
            derive_accept_key(key.as_bytes())
        )
        .into_bytes();
        bytes.extend_from_slice(&[0x81, 0x05, b'h', b'e', b'l', b'l', b'o']);
        let _ = stream.write_all(&bytes).await;
        tokio::time::sleep(Duration::from_secs(2)).await;
    })
    .await;
    let connector = connector_to(gateway.addr, vec![public_ip()]);
    let mut connection = connector
        .connect(request(
            &gateway_url(),
            policy_for(GATEWAY_HOST),
            fast_limits(),
        ))
        .await
        .expect("upgrade completes");
    let message = tokio::time::timeout(Duration::from_secs(1), connection.recv())
        .await
        .expect("first frame arrives")
        .expect("frame decodes")
        .expect("stream open");
    assert_eq!(message, WebSocketMessage::Text("hello".to_string()));
}
/// What the connector handed the transport.
#[derive(Clone)]
struct SeenRequest {
    host: String,
    port: u16,
    path: String,
    query: Option<String>,
    debug: String,
}
/// Records what the connector hands the transport.
#[derive(Clone, Default)]
struct RecordingTransport(Arc<std::sync::Mutex<Vec<SeenRequest>>>);
#[async_trait::async_trait]
impl WebSocketTransport for RecordingTransport {
    async fn connect(
        &self,
        request: WebSocketTransportRequest,
    ) -> Result<ironclaw_network::WebSocketConnection, WebSocketError> {
        self.0.lock().unwrap().push(SeenRequest {
            host: request.host.clone(),
            port: request.port,
            path: request.path.clone(),
            query: request.query.clone(),
            debug: format!("{request:?}"),
        });
        Err(WebSocketError::Connect {
            reason: "recorded".to_string(),
        })
    }
}
#[tokio::test]
async fn the_ticket_reaches_the_transport_only_as_the_query() {
    let transport = RecordingTransport::default();
    let connector = PolicyWebSocketConnector::new_with_resolver(
        transport.clone(),
        FixedResolver(vec![public_ip()]),
    );
    let _ = connector
        .connect(request(
            &format!("wss://{GATEWAY_HOST}/connect?ticket={SECRET}&a=b"),
            policy_for(GATEWAY_HOST),
            fast_limits(),
        ))
        .await;
    let seen = transport.0.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    let seen = &seen[0];
    assert_eq!(seen.host, GATEWAY_HOST);
    assert_eq!(seen.port, 443);
    assert_eq!(seen.path, "/connect", "the endpoint carries no ticket");
    assert_eq!(
        seen.query.as_deref(),
        Some(&*format!("ticket={SECRET}&a=b"))
    );
    assert!(!seen.debug.contains(SECRET), "{}", seen.debug);
}
#[tokio::test]
async fn silent_peer_hits_the_connect_timeout() {
    let gateway = raw_gateway(|stream, _key| async move {
        // Keep the socket open: an unused async-block capture would drop it.
        let _held = stream;
        tokio::time::sleep(Duration::from_secs(30)).await;
    })
    .await;
    let connector = connector_to(gateway.addr, vec![public_ip()]);
    let mut limits = fast_limits();
    limits.connect_timeout = Duration::from_millis(200);
    let error = connector
        .connect(request(&gateway_url(), policy_for(GATEWAY_HOST), limits))
        .await
        .expect_err("handshake that never completes must time out");
    assert_eq!(error, WebSocketError::ConnectTimeout);
    assert_no_secret(&error);
}

#[tokio::test]
async fn oversized_inbound_frame_is_rejected() {
    let gateway = scripted_gateway(|mut ws| async move {
        let _ = ws.send(Message::Text("x".repeat(8192).into())).await;
        tokio::time::sleep(Duration::from_secs(2)).await;
    })
    .await;
    let connector = connector_to(gateway.addr, vec![public_ip()]);
    let mut limits = fast_limits();
    limits.max_frame_bytes = 1024;
    limits.max_message_bytes = 2048;
    let mut connection = connector
        .connect(request(&gateway_url(), policy_for(GATEWAY_HOST), limits))
        .await
        .unwrap();
    let error = connection.recv().await.expect_err("oversized frame");
    assert!(
        matches!(error, WebSocketError::FrameTooLarge { .. }),
        "{error:?}"
    );
}

#[tokio::test]
async fn oversized_outbound_message_is_rejected_locally() {
    let gateway = echo_gateway(None).await;
    let connector = connector_to(gateway.addr, vec![public_ip()]);
    let mut limits = fast_limits();
    limits.max_frame_bytes = 1024;
    limits.max_message_bytes = 2048;
    let connection = connector
        .connect(request(&gateway_url(), policy_for(GATEWAY_HOST), limits))
        .await
        .unwrap();
    let error = connection
        .send(WebSocketMessage::Binary(vec![0; 4096]))
        .await
        .expect_err("outbound oversize");
    assert!(
        matches!(error, WebSocketError::FrameTooLarge { .. }),
        "{error:?}"
    );
}

#[tokio::test]
async fn silent_peer_is_dropped_at_the_idle_timeout() {
    let gateway = scripted_gateway(|ws| async move {
        // Hold the socket open without ever polling it: no pongs, no data.
        let _held = ws;
        tokio::time::sleep(Duration::from_secs(30)).await;
    })
    .await;
    let connector = connector_to(gateway.addr, vec![public_ip()]);
    let mut limits = fast_limits();
    limits.idle_timeout = Duration::from_millis(400);
    limits.ping_interval = Duration::from_millis(100);
    let mut connection = connector
        .connect(request(&gateway_url(), policy_for(GATEWAY_HOST), limits))
        .await
        .unwrap();
    let error = connection.recv().await.expect_err("idle peer");
    assert_eq!(error, WebSocketError::IdleTimeout);
}

#[tokio::test]
async fn slow_drip_frame_does_not_keep_the_connection_alive() {
    let gateway = raw_gateway(|mut stream, key| async move {
        finish_upgrade(&mut stream, &key).await;
        // Text frame header announcing 5 bytes, then one byte at a time.
        for byte in [0x81u8, 0x05, b'h', b'e', b'l', b'l'] {
            if stream.write_all(&[byte]).await.is_err() {
                return;
            }
            let _ = stream.flush().await;
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    })
    .await;
    let connector = connector_to(gateway.addr, vec![public_ip()]);
    let mut limits = fast_limits();
    limits.idle_timeout = Duration::from_millis(400);
    limits.ping_interval = Duration::from_millis(100);
    let mut connection = connector
        .connect(request(&gateway_url(), policy_for(GATEWAY_HOST), limits))
        .await
        .unwrap();
    let error = connection.recv().await.expect_err("slow drip");
    assert_eq!(error, WebSocketError::IdleTimeout);
}

#[tokio::test]
async fn graceful_server_close_ends_the_stream_after_pending_messages() {
    let gateway = scripted_gateway(|mut ws| async move {
        let _ = ws.send(Message::Text("last".into())).await;
        let _ = ws.close(None).await;
    })
    .await;
    let connector = connector_to(gateway.addr, vec![public_ip()]);
    let mut connection = connector
        .connect(request(
            &gateway_url(),
            policy_for(GATEWAY_HOST),
            fast_limits(),
        ))
        .await
        .unwrap();
    assert_eq!(
        connection.recv().await.unwrap(),
        Some(WebSocketMessage::Text("last".to_string()))
    );
    assert_eq!(connection.recv().await.unwrap(), None);
}

#[tokio::test]
async fn inbound_message_rate_above_the_ceiling_disconnects_the_peer() {
    let gateway = scripted_gateway(|mut ws| async move {
        for index in 0..50 {
            if ws
                .send(Message::Text(format!("m{index}").into()))
                .await
                .is_err()
            {
                return;
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    })
    .await;
    let connector = connector_to(gateway.addr, vec![public_ip()]);
    let mut limits = fast_limits();
    limits.max_messages_per_second = 5;
    let mut connection = connector
        .connect(request(&gateway_url(), policy_for(GATEWAY_HOST), limits))
        .await
        .unwrap();
    let mut received = 0;
    let error = loop {
        match connection.recv().await {
            Ok(Some(_)) => received += 1,
            Ok(None) => panic!("peer closed before the ceiling tripped"),
            Err(error) => break error,
        }
    };
    assert_eq!(error, WebSocketError::RateLimitExceeded { limit: 5 });
    assert_eq!(received, 5, "exactly the allowed messages are delivered");
}

#[tokio::test]
async fn keepalive_pings_are_sent_while_the_receiver_waits() {
    let (tx, mut pings) = tokio::sync::mpsc::unbounded_channel();
    let gateway = scripted_gateway(move |mut ws| {
        let tx = tx.clone();
        async move {
            while let Some(Ok(message)) = ws.next().await {
                if matches!(message, Message::Ping(_)) {
                    let _ = tx.send(());
                }
            }
        }
    })
    .await;
    let connector = connector_to(gateway.addr, vec![public_ip()]);
    let mut limits = fast_limits();
    limits.ping_interval = Duration::from_millis(100);
    limits.idle_timeout = Duration::from_secs(5);
    let mut connection = connector
        .connect(request(&gateway_url(), policy_for(GATEWAY_HOST), limits))
        .await
        .unwrap();
    let waiting = tokio::time::timeout(Duration::from_millis(800), connection.recv());
    let (outcome, ping) = tokio::join!(
        waiting,
        tokio::time::timeout(Duration::from_secs(2), pings.recv())
    );
    assert!(outcome.is_err(), "receiver should still be waiting");
    assert!(ping.unwrap().is_some(), "server must see a keepalive ping");
}

#[tokio::test]
async fn transport_rechecks_private_candidate_addresses_at_dial_time() {
    // The production transport (no loopback seam) must refuse to dial a
    // private candidate even if a caller hands one over after policy.
    let transport = TungsteniteWebSocketTransport::new();
    for ip in [
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ] {
        let error = transport
            .connect(transport_request(vec![ip]))
            .await
            .expect_err("private candidate must be refused");
        assert!(
            matches!(error, WebSocketError::PolicyDenied { .. }),
            "{ip}: {error:?}"
        );
        assert_no_secret(&error);
    }
    let error = transport
        .connect(transport_request(Vec::new()))
        .await
        .expect_err("no candidates");
    assert_no_secret(&error);
}

#[test]
fn debug_output_of_requests_and_messages_never_prints_secrets() {
    let connect = request(&gateway_url(), policy_for(GATEWAY_HOST), fast_limits());
    let rendered = format!("{connect:?}");
    assert!(!rendered.contains(SECRET), "{rendered}");
    let transport = transport_request(vec![public_ip()]);
    let rendered = format!("{transport:?}");
    assert!(!rendered.contains(SECRET), "{rendered}");
    assert!(!rendered.contains("ticket"), "{rendered}");
    let message = WebSocketMessage::Text("user private text".to_string());
    assert!(!format!("{message:?}").contains("private"));
    // Keep the tungstenite re-export in use so a feature change that drops it
    // fails here rather than in a distant crate.
    let _ = tungstenite::protocol::WebSocketConfig::default();
}
