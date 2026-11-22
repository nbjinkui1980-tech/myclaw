//! Reborn integration test: host-side token exchange (milestone 1b Task 11,
//! ADR 6.2 option B), through the composed runtime.
//!
//! The invented-vendor `acme-messenger-token` fixture installs and activates
//! through the production lifecycle tool; the stream connects as in
//! `extension_stream_ingress.rs`. Each delivered frame makes the fixture
//! adapter send one vendor message that NAMES the declared token handle, and
//! the host (not the adapter) exchanges the app credentials at the declared
//! token endpoint, caches the token in memory, refreshes it after a rejection,
//! and injects it as `x-acme-access-token`. Every assertion is made at the
//! egress seam (the recording network egress) plus what the adapter built and
//! received. The only substitutions are the fake vendor HTTP endpoints and the
//! loopback WebSocket transport.
//!
//! Not covered here (covered at host tier instead): refresh before expiry on a
//! paused clock. The composed harness runs libSQL and background tasks on the
//! real clock, so `tokio::time::advance(7200s)` would race those timers;
//! `channel_egress::token_exchange` tests pin the refresh timing with a paused
//! clock and `channel_token_exchange_contract` pins cache reuse through
//! `ExtensionHost`.
#[allow(dead_code)]
#[path = "support/mod.rs"]
mod reborn_support;
#[allow(dead_code)]
#[path = "../support/mod.rs"]
mod support;
use futures::{SinkExt, StreamExt};
use ironclaw_composition::RebornRuntime;
use ironclaw_extension_host::extension_ingress::{
    ChannelInboundSinkConfig, ChannelIngressDrain, ChannelIngressRegistration,
    ExtensionIngressParts, GenericChannelInboundSink, PostAdmissionObserver,
    StaticIngressConfiguration, StaticIngressSecrets, VerifiedEvidenceMint,
};
use ironclaw_extension_manager::extension_lifecycle_command::RebornExtensionLifecycleRuntime;
use ironclaw_host_api::product_adapter::{AuthRequirement, ProductAdapterId};
use ironclaw_network::{
    LoopbackWebSocketTransport, NetworkHttpError, NetworkResolver, PolicyWebSocketConnector,
    WebSocketConnector,
};
use ironclaw_product_contracts::inbound::{ProductInboundAck, ProductInboundEnvelope};
use ironclaw_product_contracts::surface::ChannelInboundProductSurface;
use reborn_support::builder::RebornIntegrationHarness;
use reborn_support::group::RebornIntegrationGroup;
use reborn_support::harness::profiles::extension::{
    ACME_STREAM_ACCEPTED_SECRET, ACME_TOKEN_APP_KEY, ACME_TOKEN_APP_SECRET, AcmeTokenFixture,
    AcmeTokenVendor,
};
use reborn_support::reply::RebornScriptedReply;
use serde_json::json;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
const EXTENSION: &str = "acme-messenger-token";
const TOKEN_PATH: &str = "/v1/oauth/token";
const SEND_PATH: &str = "/v1/messages";
const TOKEN_HEADER: &str = "x-acme-access-token";
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

async fn wait_until(mut condition: impl FnMut() -> bool, what: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while !condition() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

enum GatewayCmd {
    Send(String),
}

/// Loopback WebSocket server standing in for the vendor gateway. It records
/// every handshake URI (the ticket rides the query), every ACK frame the host
/// sends, and when each connection closes.
struct Gateway {
    addr: SocketAddr,
    accepts: Arc<AtomicUsize>,
    closed: Arc<AtomicUsize>,
    request_uris: Arc<Mutex<Vec<String>>>,
    connections: Arc<Mutex<Vec<mpsc::UnboundedSender<GatewayCmd>>>>,
    acks: Arc<Mutex<Vec<String>>>,
    /// When set, every upgrade is refused with this HTTP status.
    refuse_status: Arc<Mutex<Option<u16>>>,
    /// Upgrade requests seen, accepted or refused.
    handshakes: Arc<AtomicUsize>,
}

impl Gateway {
    // The handshake callback's `Err` type is fixed by tungstenite.
    #[allow(clippy::result_large_err)]
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let gateway = Self {
            addr: listener.local_addr().expect("addr"),
            accepts: Arc::default(),
            closed: Arc::default(),
            request_uris: Arc::default(),
            connections: Arc::default(),
            acks: Arc::default(),
            refuse_status: Arc::default(),
            handshakes: Arc::default(),
        };
        let refuse_status = Arc::clone(&gateway.refuse_status);
        let handshakes = Arc::clone(&gateway.handshakes);
        let accepts = Arc::clone(&gateway.accepts);
        let closed = Arc::clone(&gateway.closed);
        let uris = Arc::clone(&gateway.request_uris);
        let connections = Arc::clone(&gateway.connections);
        let acks = Arc::clone(&gateway.acks);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let uris = Arc::clone(&uris);
                let refuse = *lock(&refuse_status);
                let handshakes = Arc::clone(&handshakes);
                let callback =
                    move |request: &tokio_tungstenite::tungstenite::handshake::server::Request,
                          response| {
                        lock(&uris).push(request.uri().to_string());
                        handshakes.fetch_add(1, Ordering::SeqCst);
                        match refuse {
                            Some(status) => {
                                let mut refusal =
                                    tokio_tungstenite::tungstenite::handshake::server::ErrorResponse::new(None);
                                *refusal.status_mut() =
                                    tokio_tungstenite::tungstenite::http::StatusCode::from_u16(
                                        status,
                                    )
                                    .unwrap_or(
                                        tokio_tungstenite::tungstenite::http::StatusCode::FORBIDDEN,
                                    );
                                Err(refusal)
                            }
                            None => Ok(response),
                        }
                    };
                let Ok(socket) = tokio_tungstenite::accept_hdr_async(stream, callback).await else {
                    continue;
                };
                accepts.fetch_add(1, Ordering::SeqCst);
                let (mut write, mut read) = socket.split();
                let (tx, mut rx) = mpsc::unbounded_channel::<GatewayCmd>();
                lock(&connections).push(tx);
                let acks = Arc::clone(&acks);
                let closed = Arc::clone(&closed);
                tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            cmd = rx.recv() => match cmd {
                                Some(GatewayCmd::Send(text)) => {
                                    if write.send(Message::Text(text.into())).await.is_err() {
                                        break;
                                    }
                                }
                                None => break,
                            },
                            frame = read.next() => match frame {
                                Some(Ok(Message::Text(text))) => {
                                    let text = text.to_string();
                                    lock(&acks).push(text);
                                }
                                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                                Some(Ok(_)) => {}
                            },
                        }
                    }
                    closed.fetch_add(1, Ordering::SeqCst);
                });
            }
        });
        gateway
    }

    fn accepts(&self) -> usize {
        self.accepts.load(Ordering::SeqCst)
    }

    fn send(&self, frame: serde_json::Value) {
        let connections = lock(&self.connections);
        let latest = connections.last().expect("an open gateway connection");
        latest
            .send(GatewayCmd::Send(frame.to_string()))
            .expect("gateway connection task alive");
    }
}

/// Every declared host resolves to one public address; the loopback
/// transport then dials the fake gateway. The policy connector still runs its
/// declared-host, scheme, and private-address checks against this answer.
#[derive(Clone)]
struct PublicResolver;

impl NetworkResolver for PublicResolver {
    fn resolve_ips(&self, _host: &str, _port: u16) -> Result<Vec<IpAddr>, NetworkHttpError> {
        Ok(vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))])
    }
}

fn loopback_connector(gateway: SocketAddr) -> Arc<dyn WebSocketConnector> {
    Arc::new(PolicyWebSocketConnector::new_with_resolver(
        LoopbackWebSocketTransport::new(gateway),
        PublicResolver,
    ))
}

/// Records every post-admission workflow ack: `Accepted { submitted_run_id }`
/// is the proof the frame entered the binding + turn-submission pipeline.
#[derive(Default)]
struct RecordingAdmissionObserver {
    acks: Mutex<Vec<ProductInboundAck>>,
    errors: Mutex<Vec<String>>,
    evidence: Mutex<Vec<AuthRequirement>>,
    subjects: Mutex<Vec<String>>,
}

#[async_trait::async_trait]
impl PostAdmissionObserver for RecordingAdmissionObserver {
    async fn observe_ack(&self, envelope: ProductInboundEnvelope, ack: ProductInboundAck) {
        if let Some(claim) = envelope.auth_claim() {
            lock(&self.evidence).push(claim.requirement().clone());
            lock(&self.subjects).push(claim.subject().to_string());
        }
        lock(&self.acks).push(ack);
    }

    async fn observe_error(
        &self,
        _envelope: ProductInboundEnvelope,
        error: ironclaw_host_api::product_adapter::ProductAdapterError,
    ) {
        lock(&self.errors).push(format!("{error:?}"));
    }
}

struct StreamIngress {
    parts: ExtensionIngressParts,
}
impl StreamIngress {
    /// Register the fixture's inbound wiring (the generic sink over THIS
    /// thread harness's real workflow, minting stream evidence).
    fn register(parts: ExtensionIngressParts, harness: &RebornIntegrationHarness) -> Self {
        let observer = Arc::new(RecordingAdmissionObserver::default());
        let surface = harness.product_surface_for_test() as Arc<dyn ChannelInboundProductSurface>;
        let inner = Arc::new(GenericChannelInboundSink::new(ChannelInboundSinkConfig {
            adapter_id: ProductAdapterId::new(EXTENSION).expect("adapter id"),
            evidence: VerifiedEvidenceMint::AuthenticatedStream {
                connection_recipe:
                    ironclaw_extension_host::extension_ingress::STREAM_CONNECTION_RECIPE_LABEL
                        .to_string(),
            },
            surface,
            observer: Some(observer as Arc<dyn PostAdmissionObserver>),
        }));
        parts.registry.register(
            EXTENSION,
            ChannelIngressRegistration {
                secrets: Arc::new(StaticIngressSecrets::new(Vec::new())),
                configuration: Arc::new(StaticIngressConfiguration::new(vec![(
                    "acme_client_id".to_string(),
                    "itest-acme-client".to_string(),
                )])),
                sink: Arc::clone(&inner) as Arc<dyn ironclaw_extension_host::ingress::InboundSink>,
                drain: Some(inner as Arc<dyn ChannelIngressDrain>),
            },
        );
        Self { parts }
    }
    async fn drain(&self) {
        self.parts.registry.drain().await;
    }
}
fn reborn_services(group: &RebornIntegrationGroup) -> &RebornRuntime {
    group
        .capability_harness()
        .expect("host-runtime capability harness")
        .reborn_services_for_test()
        .expect("composed reborn services")
}
/// Bridge every channel-egress secret this fixture's host-side calls inject
/// (the stream connect secret and the two token-exchange app credentials).
fn bind_credentials(services: &RebornRuntime) {
    let entries = [
        ("acme_client_secret", ACME_STREAM_ACCEPTED_SECRET),
        ("acme_app_key", ACME_TOKEN_APP_KEY),
        ("acme_app_secret", ACME_TOKEN_APP_SECRET),
    ]
    .into_iter()
    .map(|(handle, value)| {
        (
            EXTENSION.to_string(),
            handle.to_string(),
            ironclaw_secrets::SecretMaterial::from(value.to_string()),
        )
    })
    .collect();
    assert!(
        services.register_static_channel_egress_credentials_for_test(entries),
        "the composed runtime must expose channel-egress credential bridging"
    );
}
async fn activate(group: &RebornIntegrationGroup) -> RebornIntegrationHarness {
    let harness = group
        .thread("conv-acme-token-install")
        .script([
            RebornScriptedReply::tool_call(
                "builtin.extension_install",
                json!({"extension_id": EXTENSION}),
            ),
            RebornScriptedReply::text("installed"),
        ])
        .build()
        .await
        .expect("lifecycle thread builds");
    harness
        .submit_turn("builtin.extension_install the acme token extension")
        .await
        .expect("lifecycle turn completes");
    harness
        .assert_tool_result_contains("\"phase\":\"active\"")
        .await
        .expect("install completed readiness and publication");
    harness
}
fn event_frame(n: usize) -> serde_json::Value {
    json!({
        "kind": "event",
        "frame_id": format!("F-{n}"),
        "payload": {
            "type": "message",
            "event_id": format!("Ev-acme-token-{n}"),
            "conversation": "C-ACME-TOKEN",
            "user": "U-ACME-1",
            "text": format!("hello {n}"),
        },
    })
}
fn requests_to(
    egress: &reborn_support::doubles::RecordingNetworkHttpEgress,
    path: &str,
) -> Vec<ironclaw_network::NetworkHttpRequest> {
    egress
        .requests()
        .into_iter()
        .filter(|request| request.url.ends_with(path))
        .collect()
}
fn header<'a>(request: &'a ironclaw_network::NetworkHttpRequest, name: &str) -> Option<&'a str> {
    request
        .headers
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}
async fn fixture_group() -> (
    RebornIntegrationGroup,
    Gateway,
    Arc<reborn_support::doubles::RecordingNetworkHttpEgress>,
    AcmeTokenFixture,
) {
    let gateway = Gateway::start().await;
    let (group, egress, fixture) = RebornIntegrationGroup::builder()
        .extension_runtime_acme_token(loopback_connector(gateway.addr))
        .await
        .expect("acme token group builds");
    (group, gateway, egress, fixture)
}
/// Wait for the adapter's nth send to be recorded.
async fn wait_for_sends(fixture: &AcmeTokenFixture, count: usize) {
    wait_until(
        || lock(&fixture.sends).len() >= count,
        &format!("the fixture adapter to record send #{count}"),
    )
    .await;
}
// ── TX-1, TX-2, TX-3, TX-6 ──────────────────────────────────────────────────
/// First send exchanges once and injects the declared header; a second send
/// reuses the token; a revoked token is refreshed once and the send retried
/// once; the token reaches no adapter-visible, status, or transcript surface.
#[tokio::test]
async fn the_host_exchanges_caches_refreshes_and_hides_the_token() {
    let (group, gateway, egress, fixture) = fixture_group().await;
    let services = reborn_services(&group);
    bind_credentials(services);
    let inbound = group
        .thread("conv-acme-token-inbound")
        .script([RebornScriptedReply::text("unused")])
        .build()
        .await
        .expect("inbound thread builds");
    let ingress = StreamIngress::register(
        services
            .extension_ingress_parts()
            .expect("composition built the generic ingress"),
        &inbound,
    );
    let lifecycle = activate(&group).await;
    wait_until(|| gateway.accepts() == 1, "the activation dial").await;
    let token1 = AcmeTokenVendor::token(1);
    let token2 = AcmeTokenVendor::token(2);

    // TX-1: one exchange, then one send carrying the injected header.
    gateway.send(event_frame(1));
    wait_for_sends(&fixture, 1).await;
    let exchanges = requests_to(&egress, TOKEN_PATH);
    assert_eq!(exchanges.len(), 1, "first send exchanges exactly once");
    assert_eq!(
        exchanges[0].url,
        format!("https://auth.acme.example{TOKEN_PATH}")
    );
    let exchange_body: serde_json::Value =
        serde_json::from_slice(&exchanges[0].body).expect("exchange body is JSON");
    assert_eq!(exchange_body["appKey"], ACME_TOKEN_APP_KEY);
    assert_eq!(exchange_body["appSecret"], ACME_TOKEN_APP_SECRET);
    let sends = requests_to(&egress, SEND_PATH);
    assert_eq!(sends.len(), 1);
    assert_eq!(header(&sends[0], TOKEN_HEADER), Some(token1.as_str()));
    {
        let records = lock(&fixture.sends);
        assert_eq!(records[0].outcome, Ok(200));
        assert!(
            records[0]
                .request
                .headers
                .iter()
                .all(|(name, _)| !name.eq_ignore_ascii_case(TOKEN_HEADER)),
            "the adapter never builds the token header"
        );
        let seen = format!("{records:?}");
        for secret in [token1.as_str(), ACME_TOKEN_APP_KEY, ACME_TOKEN_APP_SECRET] {
            assert!(!seen.contains(secret), "adapter saw {secret}");
        }
    }

    // TX-2: the cached token serves the next send.
    gateway.send(event_frame(2));
    wait_for_sends(&fixture, 2).await;
    assert_eq!(requests_to(&egress, TOKEN_PATH).len(), 1, "no new exchange");
    assert_eq!(requests_to(&egress, SEND_PATH).len(), 2);

    // TX-3: the vendor revokes token 1. The next send is rejected, the host
    // exchanges once more and resends once, and the adapter sees success.
    fixture.vendor.revoke(&token1);
    gateway.send(event_frame(3));
    wait_for_sends(&fixture, 3).await;
    assert_eq!(fixture.vendor.exchanges(), 2, "one replacement exchange");
    assert_eq!(requests_to(&egress, TOKEN_PATH).len(), 2);
    let sends = requests_to(&egress, SEND_PATH);
    assert_eq!(sends.len(), 4, "the rejected send plus exactly one resend");
    assert_eq!(header(&sends[2], TOKEN_HEADER), Some(token1.as_str()));
    assert_eq!(header(&sends[3], TOKEN_HEADER), Some(token2.as_str()));
    assert_eq!(lock(&fixture.sends)[2].outcome, Ok(200));

    // TX-6: no token or app secret on any surface the harness can read.
    ingress.drain().await;
    let status = format!(
        "{:?}",
        services
            .extension_management()
            .installation_stream_connections()
    );
    for secret in [
        token1.as_str(),
        token2.as_str(),
        ACME_TOKEN_APP_KEY,
        ACME_TOKEN_APP_SECRET,
    ] {
        assert!(!status.contains(secret), "status leaks {secret}: {status}");
        lifecycle
            .assert_conversation_history_lacks(secret)
            .await
            .expect("no token or app credential in the lifecycle transcript");
    }
}
// ── TX-4 ────────────────────────────────────────────────────────────────────
/// A transient token-endpoint failure surfaces to the adapter as a transient
/// transport failure with no vendor send, is not cached as a negative result,
/// and the next send exchanges again and succeeds.
#[tokio::test]
async fn a_token_endpoint_outage_sends_nothing_and_the_next_send_recovers() {
    let (group, gateway, egress, fixture) = fixture_group().await;
    let services = reborn_services(&group);
    bind_credentials(services);
    let inbound = group
        .thread("conv-acme-token-outage")
        .script([RebornScriptedReply::text("unused")])
        .build()
        .await
        .expect("inbound thread builds");
    let _ingress = StreamIngress::register(
        services
            .extension_ingress_parts()
            .expect("composition built the generic ingress"),
        &inbound,
    );
    fixture.vendor.fail_token_endpoint_with(503);
    activate(&group).await;
    wait_until(|| gateway.accepts() == 1, "the activation dial").await;
    gateway.send(event_frame(1));
    wait_for_sends(&fixture, 1).await;
    {
        let records = lock(&fixture.sends);
        let error = records[0].outcome.clone().expect_err("the send must fail");
        assert!(
            error.contains("token exchange unavailable"),
            "transient classification, static reason: {error}"
        );
    }
    assert_eq!(
        requests_to(&egress, TOKEN_PATH).len(),
        1,
        "exactly one exchange attempt per delivery attempt"
    );
    assert!(
        requests_to(&egress, SEND_PATH).is_empty(),
        "no vendor send without a token"
    );
    fixture.vendor.fail_token_endpoint_with(0);
    gateway.send(event_frame(2));
    wait_for_sends(&fixture, 2).await;
    assert_eq!(lock(&fixture.sends)[1].outcome, Ok(200));
    assert_eq!(requests_to(&egress, TOKEN_PATH).len(), 2);
    assert_eq!(requests_to(&egress, SEND_PATH).len(), 1);
}
// ── TX-5 ────────────────────────────────────────────────────────────────────
/// A vendor 5xx on the send is returned to the adapter and never resent, and
/// does not trigger a new exchange.
#[tokio::test]
async fn a_server_error_on_the_send_is_not_retried() {
    let (group, gateway, egress, fixture) = fixture_group().await;
    let services = reborn_services(&group);
    bind_credentials(services);
    let inbound = group
        .thread("conv-acme-token-5xx")
        .script([RebornScriptedReply::text("unused")])
        .build()
        .await
        .expect("inbound thread builds");
    let _ingress = StreamIngress::register(
        services
            .extension_ingress_parts()
            .expect("composition built the generic ingress"),
        &inbound,
    );
    fixture.vendor.fail_sends_with(500);
    activate(&group).await;
    wait_until(|| gateway.accepts() == 1, "the activation dial").await;
    gateway.send(event_frame(1));
    wait_for_sends(&fixture, 1).await;
    assert_eq!(lock(&fixture.sends)[0].outcome, Ok(500));
    assert_eq!(requests_to(&egress, SEND_PATH).len(), 1, "never resent");
    assert_eq!(
        requests_to(&egress, TOKEN_PATH).len(),
        1,
        "never re-exchanged"
    );
}
