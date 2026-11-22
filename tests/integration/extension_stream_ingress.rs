//! Reborn integration test: stream ingress (stream-ingress milestone one,
//! Task 10), the dial-out sibling of `extension_ingress.rs` (ING series).
//!
//! The invented-vendor `acme-messenger-stream` fixture installs and activates
//! through the production lifecycle tool. The composed runtime's REAL stream
//! supervisor (`RebornRuntime`'s, started by composition) runs the declared
//! connect call over the recording network egress (the client secret is
//! injected host-side from administrator configuration), then dials a
//! loopback fake gateway through the policy-checked WebSocket connector. The
//! only substitutions are that connector's transport (loopback) and the
//! vendor HTTP endpoint (recorded). Frames are decoded by the fixture's real
//! stream adapter and admitted through the shared admission pipeline into a
//! sink over the REAL `DefaultProductSurface` (idempotency ledger,
//! conversation binding, turn submission); the ACK frame is sent only after
//! that commit.
//!
//! Mirrors the ING series: connect after activation (ING-1), a
//! connection-time authentication failure is refused and never admits
//! (ING-3), persist-before-ACK with duplicate frames and a fresh-sink
//! "restart" replay admitted exactly once over libSQL and PostgreSQL (ING-8),
//! a frame enters a turn through the real workflow (ING-10), and deactivation
//! closes the connection without redialing.

#[allow(dead_code)]
#[path = "support/mod.rs"]
mod reborn_support;
#[allow(dead_code)]
#[path = "../support/mod.rs"]
mod support;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use ironclaw_composition::RebornRuntime;
use ironclaw_extension_host::extension_ingress::{
    ChannelInboundSinkConfig, ChannelIngressDrain, ChannelIngressRegistration,
    ExtensionIngressParts, GenericChannelInboundSink, PostAdmissionObserver,
    StaticIngressConfiguration, StaticIngressSecrets, VerifiedEvidenceMint,
};
use ironclaw_extension_host::ingress::{
    InboundAdmission, InboundAdmissionAck, InboundSink, InboundSinkError,
};
use ironclaw_host_api::product_adapter::{AuthRequirement, ProductAdapterId};
use ironclaw_network::{
    LoopbackWebSocketTransport, NetworkHttpError, NetworkResolver, PolicyWebSocketConnector,
    WebSocketConnector,
};
use ironclaw_product_contracts::inbound::{ProductInboundAck, ProductInboundEnvelope};
use ironclaw_product_contracts::lifecycle_service::ExtensionStreamState;
use ironclaw_product_contracts::surface::ChannelInboundProductSurface;
use reborn_support::builder::{RebornIntegrationHarness, StorageMode};
use reborn_support::group::RebornIntegrationGroup;
use reborn_support::harness::profiles::extension::{
    ACME_STREAM_ACCEPTED_SECRET, ACME_STREAM_TICKET,
};
use reborn_support::reply::RebornScriptedReply;
use rstest::rstest;
use serde_json::json;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

const EXTENSION: &str = "acme-messenger-stream";
const CONNECT_PATH: &str = "/v1/streams/open";

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

/// One ordered timeline both seams append to: `admitted:<event>` when the
/// durable admission commit returned, `ack:<frame>` when the gateway read the
/// host's ACK frame. Persist-before-ACK is an index comparison over it.
type Timeline = Arc<Mutex<Vec<String>>>;

// ── Fake gateway ────────────────────────────────────────────────────────────

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
    async fn start(timeline: Timeline) -> Self {
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
                let timeline = Arc::clone(&timeline);
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
                                    lock(&timeline).push(format!("ack:{text}"));
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

    fn closed(&self) -> usize {
        self.closed.load(Ordering::SeqCst)
    }

    fn send(&self, frame: serde_json::Value) {
        let connections = lock(&self.connections);
        let latest = connections.last().expect("an open gateway connection");
        latest
            .send(GatewayCmd::Send(frame.to_string()))
            .expect("gateway connection task alive");
    }

    fn acks_for(&self, frame_id: &str) -> usize {
        let expected = json!({ "ack": frame_id }).to_string();
        lock(&self.acks)
            .iter()
            .filter(|ack| **ack == expected)
            .count()
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

// ── Admission seams ─────────────────────────────────────────────────────────

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

/// Delays the sink for chosen frames so back-pressure and overlap are
/// observable through the real supervisor: while `held` matches an event id
/// prefix, that admission waits before reaching the real sink.
#[derive(Default)]
struct AdmissionHold {
    /// Event-id prefix to hold; `Some("")` holds every admission.
    held: Mutex<Option<String>>,
    /// Admissions that reached the sink (held or not).
    entered: AtomicUsize,
}
impl AdmissionHold {
    fn hold(&self, prefix: &str) {
        *lock(&self.held) = Some(prefix.to_string());
    }
    fn release(&self) {
        *lock(&self.held) = None;
    }
    fn is_held(&self, event: &str) -> bool {
        lock(&self.held)
            .as_deref()
            .is_some_and(|prefix| event.starts_with(prefix))
    }
}
/// The generic sink, plus a timeline entry once its durable commit returned.
struct TimelineSink {
    inner: Arc<GenericChannelInboundSink>,
    timeline: Timeline,
    hold: Arc<AdmissionHold>,
}

#[async_trait::async_trait]
impl InboundSink for TimelineSink {
    async fn admit(
        &self,
        admission: InboundAdmission,
    ) -> Result<InboundAdmissionAck, InboundSinkError> {
        let event = admission.message.event_id.as_str().to_string();
        self.hold.entered.fetch_add(1, Ordering::SeqCst);
        while self.hold.is_held(&event) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let ack = self.inner.admit(admission).await?;
        lock(&self.timeline).push(format!("admitted:{event}"));
        Ok(ack)
    }
}

struct StreamIngress {
    parts: ExtensionIngressParts,
    observer: Arc<RecordingAdmissionObserver>,
    hold: Arc<AdmissionHold>,
}

impl StreamIngress {
    /// Register the acme stream's inbound wiring (the generic sink over THIS
    /// thread harness's real workflow, minting stream evidence) as a
    /// lane-owned registration, exactly like the webhook ING template.
    /// Re-registering with a fresh sink over another workflow instance
    /// models a process restart over the same durable ledger.
    fn register(
        parts: ExtensionIngressParts,
        harness: &RebornIntegrationHarness,
        timeline: &Timeline,
    ) -> Self {
        let observer = Arc::new(RecordingAdmissionObserver::default());
        let hold = Arc::new(AdmissionHold::default());
        let surface = harness.product_surface_for_test() as Arc<dyn ChannelInboundProductSurface>;
        let inner = Arc::new(GenericChannelInboundSink::new(ChannelInboundSinkConfig {
            adapter_id: ProductAdapterId::new(EXTENSION).expect("adapter id"),
            evidence: VerifiedEvidenceMint::AuthenticatedStream {
                connection_recipe:
                    ironclaw_extension_host::extension_ingress::STREAM_CONNECTION_RECIPE_LABEL
                        .to_string(),
            },
            surface,
            observer: Some(Arc::clone(&observer) as Arc<dyn PostAdmissionObserver>),
        }));
        parts.registry.register(
            EXTENSION,
            ChannelIngressRegistration {
                // A stream mounts no route: nothing to verify per request.
                secrets: Arc::new(StaticIngressSecrets::new(Vec::new())),
                configuration: Arc::new(StaticIngressConfiguration::new(vec![(
                    "acme_client_id".to_string(),
                    "itest-acme-client".to_string(),
                )])),
                sink: Arc::new(TimelineSink {
                    inner: Arc::clone(&inner),
                    timeline: Arc::clone(timeline),
                    hold: Arc::clone(&hold),
                }),
                drain: Some(inner as Arc<dyn ChannelIngressDrain>),
            },
        );
        Self {
            parts,
            observer,
            hold,
        }
    }

    async fn drain(&self) {
        self.parts.registry.drain().await;
    }

    fn count(&self, accepted: bool) -> usize {
        lock(&self.observer.acks)
            .iter()
            .filter(|ack| match ack {
                ProductInboundAck::Accepted { .. } => accepted,
                ProductInboundAck::Duplicate { .. } => !accepted,
                _ => false,
            })
            .count()
    }

    fn errors(&self) -> Vec<String> {
        lock(&self.observer.errors).clone()
    }
}

// ── Lifecycle + frames ──────────────────────────────────────────────────────

fn reborn_services(group: &RebornIntegrationGroup) -> &RebornRuntime {
    group
        .capability_harness()
        .expect("host-runtime capability harness")
        .reborn_services_for_test()
        .expect("composed reborn services")
}

/// Bridge the channel-egress client secret the connect call injects into its
/// body (`[[channel.egress.body_credentials]]`), host-side only.
fn bind_client_secret(services: &RebornRuntime, secret: &str) {
    assert!(
        services.register_static_channel_egress_credentials_for_test(vec![(
            EXTENSION.to_string(),
            "acme_client_secret".to_string(),
            ironclaw_secrets::SecretMaterial::from(secret.to_string()),
        )]),
        "the composed runtime must expose channel-egress credential bridging"
    );
}

/// Drive one production lifecycle tool call on its own thread and return the
/// thread so the caller can inspect its transcript.
async fn lifecycle_turn(
    group: &RebornIntegrationGroup,
    thread: &str,
    tool: &str,
    reply: &str,
) -> RebornIntegrationHarness {
    let harness = group
        .thread(thread)
        .script([
            RebornScriptedReply::tool_call(tool, json!({"extension_id": EXTENSION})),
            RebornScriptedReply::text(reply),
        ])
        .build()
        .await
        .expect("lifecycle thread builds");
    harness
        .submit_turn(&format!("{tool} the acme stream extension"))
        .await
        .expect("lifecycle turn completes");
    harness
}

async fn activate_stream(group: &RebornIntegrationGroup) -> RebornIntegrationHarness {
    let lifecycle = lifecycle_turn(
        group,
        "conv-acme-stream-install",
        "builtin.extension_install",
        "installed",
    )
    .await;
    lifecycle
        .assert_tool_result_contains("\"phase\":\"active\"")
        .await
        .expect("install completed readiness and publication");
    lifecycle
}

/// The host's redacted connection state for every active stream extension:
/// the same projection the extensions page reads.
fn stream_connections(
    services: &RebornRuntime,
) -> std::collections::HashMap<
    ironclaw_host_api::ids::ExtensionId,
    ironclaw_product_contracts::lifecycle_service::ExtensionStreamConnection,
> {
    use ironclaw_extension_manager::extension_lifecycle_command::RebornExtensionLifecycleRuntime;
    services
        .extension_management()
        .installation_stream_connections()
}

fn stream_state(services: &RebornRuntime) -> Option<(ExtensionStreamState, Option<String>)> {
    stream_connections(services)
        .into_iter()
        .find(|(id, _)| id.as_str() == EXTENSION)
        .map(|(_, connection)| (connection.state, connection.last_error))
}

fn event_frame(frame_id: &str, event_id: &str, text: &str) -> serde_json::Value {
    conversation_frame("C-ACME-STREAM", frame_id, event_id, text)
}
fn conversation_frame(
    conversation: &str,
    frame_id: &str,
    event_id: &str,
    text: &str,
) -> serde_json::Value {
    json!({
        "kind": "event",
        "frame_id": frame_id,
        "payload": {
            "type": "message",
            "event_id": event_id,
            "conversation": conversation,
            "user": "U-ACME-1",
            "text": text,
        },
    })
}

fn position(timeline: &Timeline, entry: &str) -> usize {
    lock(timeline)
        .iter()
        .position(|candidate| candidate == entry)
        .unwrap_or_else(|| panic!("timeline lacks `{entry}`: {:?}", lock(timeline)))
}

fn ack_entry(frame_id: &str) -> String {
    format!("ack:{}", json!({ "ack": frame_id }))
}

fn connect_requests(
    egress: &reborn_support::doubles::RecordingNetworkHttpEgress,
) -> Vec<ironclaw_network::NetworkHttpRequest> {
    egress
        .requests()
        .into_iter()
        .filter(|request| request.url.ends_with(CONNECT_PATH))
        .collect()
}

/// Activation dials the declared gateway through the composed runtime's
/// supervisor (ING-1); a delivered frame is durably admitted through the real
/// workflow as a turn with stream evidence before its ACK leaves the host
/// (ING-8 ordering, ING-10); the ticket stays out of status and transcript;
/// deactivation closes the connection and the host never redials.
#[tokio::test]
async fn activated_stream_connects_admits_a_frame_into_a_turn_and_disconnects_on_deactivation() {
    let timeline: Timeline = Arc::default();
    let gateway = Gateway::start(Arc::clone(&timeline)).await;
    let (group, egress) = RebornIntegrationGroup::builder()
        .extension_runtime_acme_stream(loopback_connector(gateway.addr))
        .await
        .expect("acme stream group builds");
    let services = reborn_services(&group);
    bind_client_secret(services, ACME_STREAM_ACCEPTED_SECRET);
    let inbound = group
        .thread("conv-acme-stream-inbound")
        .script([RebornScriptedReply::text("unused")])
        .build()
        .await
        .expect("inbound thread builds");
    let ingress = StreamIngress::register(
        services
            .extension_ingress_parts()
            .expect("composition built the generic ingress"),
        &inbound,
        &timeline,
    );
    assert_eq!(gateway.accepts(), 0, "nothing dials before activation");

    let lifecycle = activate_stream(&group).await;
    wait_until(|| gateway.accepts() == 1, "the activation dial").await;
    wait_until(
        || {
            matches!(
                stream_state(services),
                Some((ExtensionStreamState::Connected, None))
            )
        },
        "the lifecycle projection to report Connected",
    )
    .await;

    // The connect call crossed the recorded wire to the declared egress host
    // with the client secret injected host-side and the subscriptions added.
    let connects = connect_requests(&egress);
    assert_eq!(connects.len(), 1, "one connect call per connection");
    assert_eq!(
        connects[0].url,
        format!("https://api.acme.example{CONNECT_PATH}")
    );
    let connect_body: serde_json::Value =
        serde_json::from_slice(&connects[0].body).expect("connect body is JSON");
    assert_eq!(connect_body["clientId"], "itest-acme-client");
    assert_eq!(connect_body["clientSecret"], ACME_STREAM_ACCEPTED_SECRET);
    // Review #12: the declared subscription array itself, never a literal
    // `{subscriptions}` placeholder string.
    assert_eq!(
        connect_body["subscriptions"],
        serde_json::json!([{ "type": "EVENT", "topic": "/v1/messages/get" }])
    );
    // The granted ticket rides only the dialed URL.
    let uris = lock(&gateway.request_uris).clone();
    assert_eq!(uris, vec![format!("/ws?ticket={ACME_STREAM_TICKET}")]);

    // A delivered event: admitted through the REAL workflow as a turn, with
    // connection evidence naming the owning installation, then acknowledged.
    gateway.send(event_frame(
        "F-1",
        "Ev-acme-stream-1",
        "hello over the stream",
    ));
    wait_until(|| gateway.acks_for("F-1") == 1, "the F-1 ACK").await;
    ingress.drain().await;
    assert_eq!(
        ingress.count(true),
        1,
        "the frame must be admitted as a turn (errors: {:?})",
        ingress.errors()
    );
    assert!(
        position(&timeline, "admitted:Ev-acme-stream-1") < position(&timeline, &ack_entry("F-1")),
        "the durable admission commit must precede the ACK: {:?}",
        lock(&timeline)
    );
    assert!(
        lock(&ingress.observer.acks).iter().any(|ack| matches!(
            ack,
            ProductInboundAck::Accepted {
                submission: Some(_),
                ..
            }
        )),
        "a fresh turn submission must back the acceptance"
    );
    assert_eq!(
        lock(&ingress.observer.evidence).clone(),
        vec![AuthRequirement::AuthenticatedStream {
            connection_recipe: "connect".to_string(),
        }]
    );
    assert_eq!(
        lock(&ingress.observer.subjects).clone(),
        vec![EXTENSION.to_string()]
    );

    // A keepalive frame is acknowledged and admits nothing.
    gateway.send(json!({"kind": "ping", "frame_id": "P-1"}));
    wait_until(|| gateway.acks_for("P-1") == 1, "the ping ACK").await;
    ingress.drain().await;
    assert_eq!(ingress.count(true), 1, "keepalive frames never admit");

    // Redaction: neither the ticket nor the client secret reaches the
    // connection status or the model-visible transcript.
    let status = format!("{:?}", stream_connections(services));
    assert!(
        !status.contains(ACME_STREAM_TICKET),
        "status leaks the ticket: {status}"
    );
    assert!(
        !status.contains(ACME_STREAM_ACCEPTED_SECRET),
        "status leaks the secret"
    );
    for secret in [ACME_STREAM_TICKET, ACME_STREAM_ACCEPTED_SECRET] {
        lifecycle
            .assert_conversation_history_lacks(secret)
            .await
            .expect("no connection secret in the transcript");
    }

    // Deactivation (removal unpublishes the extension) closes the socket and
    // the supervisor never redials.
    let remove = lifecycle_turn(
        &group,
        "conv-acme-stream-remove",
        "builtin.extension_remove",
        "removed",
    )
    .await;
    remove
        .assert_tool_result_contains("\"removed\":true")
        .await
        .expect("removal reported success");
    wait_until(|| gateway.closed() == 1, "the connection to close").await;
    assert!(
        stream_state(services).is_none(),
        "an inactive stream has no state"
    );
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(gateway.accepts(), 1, "no redial after deactivation");
    assert_eq!(
        connect_requests(&egress).len(),
        1,
        "no connect call after deactivation"
    );
}

/// ING-3 for a stream: the vendor refuses the connect call (wrong client
/// secret). No connection opens, nothing is admitted, and after the
/// configured number of consecutive refusals the host stops retrying and
/// reports a redacted "needs administrator" state.
#[tokio::test]
async fn connection_time_auth_failure_is_refused_and_never_admits() {
    let timeline: Timeline = Arc::default();
    let gateway = Gateway::start(Arc::clone(&timeline)).await;
    let (group, egress) = RebornIntegrationGroup::builder()
        .extension_runtime_acme_stream(loopback_connector(gateway.addr))
        .await
        .expect("acme stream group builds");
    let services = reborn_services(&group);
    let wrong_secret = "itest-acme-stream-wrong-secret";
    bind_client_secret(services, wrong_secret);
    let inbound = group
        .thread("conv-acme-stream-refused")
        .script([RebornScriptedReply::text("unused")])
        .build()
        .await
        .expect("inbound thread builds");
    let ingress = StreamIngress::register(
        services
            .extension_ingress_parts()
            .expect("composition built the generic ingress"),
        &inbound,
        &timeline,
    );

    activate_stream(&group).await;
    wait_until(
        || {
            matches!(
                stream_state(services),
                Some((ExtensionStreamState::NeedsAdministrator, Some(ref reason)))
                    if reason == "connect_unauthorized"
            )
        },
        "the refused connection to need an administrator",
    )
    .await;
    // Three refused connect calls (the default threshold), then no more.
    assert_eq!(connect_requests(&egress).len(), 3);
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(
        connect_requests(&egress).len(),
        3,
        "no retry after the threshold"
    );
    assert_eq!(
        gateway.accepts(),
        0,
        "a refused grant never dials the gateway"
    );
    ingress.drain().await;
    assert_eq!(ingress.count(true) + ingress.count(false), 0);
    assert!(
        lock(&timeline).is_empty(),
        "nothing admitted or acknowledged"
    );
    let status = format!("{:?}", stream_connections(services));
    assert!(
        !status.contains(wrong_secret),
        "status leaks the secret: {status}"
    );
}

/// ING-8 for a stream: a redelivered frame (same frame id) and a vendor
/// redelivery of the same event under a new frame id are both acknowledged
/// but admitted once; after a reconnect, a FRESH sink over a fresh workflow
/// sharing the same durable ledger (a process-restart stand-in) settles the
/// replay as Duplicate. Every ACK follows its durable commit. Matrixed over
/// libSQL and PostgreSQL (provisioning failure is a test failure, never a
/// skip).
#[rstest]
#[case(StorageMode::LibSql)]
#[case(StorageMode::Postgres)]
#[tokio::test]
async fn duplicate_frames_and_restart_replay_admit_exactly_once(#[case] storage: StorageMode) {
    let timeline: Timeline = Arc::default();
    let gateway = Gateway::start(Arc::clone(&timeline)).await;
    let (group, _egress) = RebornIntegrationGroup::builder()
        .storage(storage)
        .extension_runtime_acme_stream(loopback_connector(gateway.addr))
        .await
        .expect("acme stream group builds on this backend");
    let services = reborn_services(&group);
    bind_client_secret(services, ACME_STREAM_ACCEPTED_SECRET);
    let parts = services
        .extension_ingress_parts()
        .expect("composition built the generic ingress");
    let inbound = group
        .thread("conv-acme-stream-dedupe")
        .script([RebornScriptedReply::text("unused")])
        .build()
        .await
        .expect("inbound thread builds");
    let ingress = StreamIngress::register(parts.clone(), &inbound, &timeline);
    activate_stream(&group).await;
    wait_until(|| gateway.accepts() == 1, "the activation dial").await;

    let frame = event_frame("F-1", "Ev-acme-stream-dedupe", "deliver exactly once");
    gateway.send(frame.clone());
    wait_until(|| gateway.acks_for("F-1") == 1, "the first ACK").await;
    // The same frame again, then the same event under a new frame id.
    gateway.send(frame);
    gateway.send(event_frame(
        "F-2",
        "Ev-acme-stream-dedupe",
        "deliver exactly once",
    ));
    wait_until(
        || gateway.acks_for("F-1") == 2 && gateway.acks_for("F-2") == 1,
        "the redelivery ACKs",
    )
    .await;
    ingress.drain().await;
    assert_eq!(
        ingress.count(true),
        1,
        "duplicate frames must not admit twice (errors: {:?})",
        ingress.errors()
    );
    assert_eq!(
        ingress.count(false),
        2,
        "both redeliveries settle Duplicate"
    );
    assert!(
        position(&timeline, "admitted:Ev-acme-stream-dedupe")
            < position(&timeline, &ack_entry("F-1")),
        "the durable admission commit must precede the first ACK: {:?}",
        lock(&timeline)
    );

    // The vendor asks for a new connection; the host acknowledges and redials.
    gateway.send(json!({"kind": "reconnect", "frame_id": "R-1"}));
    wait_until(|| gateway.accepts() == 2, "the reconnect dial").await;
    assert_eq!(gateway.acks_for("R-1"), 1);

    // "Restart": a FRESH sink over a fresh workflow instance sharing the same
    // durable ledger; the replayed event on the new connection converges.
    let restarted_thread = group
        .thread("conv-acme-stream-dedupe-restart")
        .script([RebornScriptedReply::text("unused")])
        .build()
        .await
        .expect("restart thread builds");
    let restarted = StreamIngress::register(parts, &restarted_thread, &timeline);
    gateway.send(event_frame(
        "F-3",
        "Ev-acme-stream-dedupe",
        "deliver exactly once",
    ));
    wait_until(|| gateway.acks_for("F-3") == 1, "the replay ACK").await;
    restarted.drain().await;
    assert_eq!(
        restarted.count(true),
        0,
        "restart replay must not re-admit the settled event"
    );
    assert_eq!(
        restarted.count(false),
        1,
        "restart replay settles Duplicate from the durable ledger"
    );
}

/// A gateway that refuses the WebSocket upgrade (the ticket was rejected at
/// the handshake) is a permanent credential failure, exactly like a refused
/// connect call: after the threshold the host stops dialing and reports a
/// redacted "needs administrator" state.
#[tokio::test]
async fn a_refused_upgrade_ends_as_needs_administrator_and_stops_dialing() {
    let timeline: Timeline = Arc::default();
    let gateway = Gateway::start(Arc::clone(&timeline)).await;
    *lock(&gateway.refuse_status) = Some(403);
    let (group, egress) = RebornIntegrationGroup::builder()
        .extension_runtime_acme_stream(loopback_connector(gateway.addr))
        .await
        .expect("acme stream group builds");
    let services = reborn_services(&group);
    bind_client_secret(services, ACME_STREAM_ACCEPTED_SECRET);
    activate_stream(&group).await;
    wait_until(
        || {
            matches!(
                stream_state(services),
                Some((ExtensionStreamState::NeedsAdministrator, Some(ref reason)))
                    if reason == "handshake_unauthorized"
            )
        },
        "the refused upgrade to need an administrator",
    )
    .await;
    assert_eq!(connect_requests(&egress).len(), 3);
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(
        connect_requests(&egress).len(),
        3,
        "no retry after the threshold"
    );
    assert_eq!(
        gateway.handshakes.load(Ordering::SeqCst),
        3,
        "no further dials"
    );
    assert_eq!(gateway.accepts(), 0);
    let status = format!("{:?}", stream_connections(services));
    assert!(
        !status.contains(ACME_STREAM_TICKET),
        "status leaks the ticket: {status}"
    );
}

/// Frames of one conversation share a session key, so through the composed
/// supervisor they are admitted one at a time in arrival order, each ACK
/// following its own durable commit.
#[tokio::test]
async fn frames_of_one_conversation_are_admitted_and_acknowledged_in_arrival_order() {
    let timeline: Timeline = Arc::default();
    let gateway = Gateway::start(Arc::clone(&timeline)).await;
    let (group, _egress) = RebornIntegrationGroup::builder()
        .extension_runtime_acme_stream(loopback_connector(gateway.addr))
        .await
        .expect("acme stream group builds");
    let services = reborn_services(&group);
    bind_client_secret(services, ACME_STREAM_ACCEPTED_SECRET);
    let inbound = group
        .thread("conv-acme-stream-order")
        .script([RebornScriptedReply::text("unused")])
        .build()
        .await
        .expect("inbound thread builds");
    let ingress = StreamIngress::register(
        services
            .extension_ingress_parts()
            .expect("composition built the generic ingress"),
        &inbound,
        &timeline,
    );
    activate_stream(&group).await;
    wait_until(|| gateway.accepts() == 1, "the activation dial").await;
    for index in 1..=4 {
        gateway.send(event_frame(
            &format!("F-{index}"),
            &format!("Ev-order-{index}"),
            &format!("message {index}"),
        ));
    }
    wait_until(
        || (1..=4).all(|index| gateway.acks_for(&format!("F-{index}")) == 1),
        "every ACK",
    )
    .await;
    ingress.drain().await;
    // Later messages of a busy conversation settle as a queued or steered
    // submission rather than a fresh turn, so count every settled ack.
    assert_eq!(
        lock(&ingress.observer.acks).len(),
        4,
        "every frame reached the workflow (errors: {:?})",
        ingress.errors()
    );
    assert!(ingress.errors().is_empty());
    let admitted: Vec<usize> = (1..=4)
        .map(|index| position(&timeline, &format!("admitted:Ev-order-{index}")))
        .collect();
    let acked: Vec<usize> = (1..=4)
        .map(|index| position(&timeline, &ack_entry(&format!("F-{index}"))))
        .collect();
    assert!(
        admitted.windows(2).all(|pair| pair[0] < pair[1]),
        "{admitted:?}"
    );
    assert!(acked.windows(2).all(|pair| pair[0] < pair[1]), "{acked:?}");
    for (commit, ack) in admitted.iter().zip(&acked) {
        assert!(
            commit < ack,
            "each ACK follows its commit: {:?}",
            lock(&timeline)
        );
    }
}

/// Starts a stream group with a gateway and a registered ingress.
async fn stream_fixture(
    thread: &str,
) -> (
    RebornIntegrationGroup,
    Gateway,
    StreamIngress,
    Timeline,
    RebornIntegrationHarness,
) {
    let timeline: Timeline = Arc::default();
    let gateway = Gateway::start(Arc::clone(&timeline)).await;
    let (group, _egress) = RebornIntegrationGroup::builder()
        .extension_runtime_acme_stream(loopback_connector(gateway.addr))
        .await
        .expect("acme stream group builds");
    let services = reborn_services(&group);
    bind_client_secret(services, ACME_STREAM_ACCEPTED_SECRET);
    let inbound = group
        .thread(thread)
        .script([RebornScriptedReply::text("unused")])
        .build()
        .await
        .expect("inbound thread builds");
    let ingress = StreamIngress::register(
        services
            .extension_ingress_parts()
            .expect("composition built the generic ingress"),
        &inbound,
        &timeline,
    );
    activate_stream(&group).await;
    wait_until(|| gateway.accepts() == 1, "the activation dial").await;
    (group, gateway, ingress, timeline, inbound)
}

/// Back-pressure (ADR 5.3) through the real supervisor: with admission stalled,
/// a conversation admits one frame at a time; no frame is acknowledged before
/// its commit; once released every frame is admitted exactly once, in order,
/// and acknowledged. The queue bound itself (reader stops reading at the
/// limit) is asserted at the supervisor contract tier
/// (`stream_supervisor_contract.rs`), where the transport is observable; the
/// loopback socket here buffers unread frames invisibly, so this test does not
/// claim it.
#[tokio::test]
async fn a_stalled_admission_admits_one_frame_at_a_time_acknowledges_nothing_and_loses_no_frame() {
    const FRAMES: usize = 24;
    let (_group, gateway, ingress, timeline, _inbound) =
        stream_fixture("conv-acme-stream-backpressure").await;
    ingress.hold.hold("Ev-bp-");
    for index in 1..=FRAMES {
        gateway.send(event_frame(
            &format!("BP-{index}"),
            &format!("Ev-bp-{index:02}"),
            "burst",
        ));
    }
    wait_until(
        || ingress.hold.entered.load(Ordering::SeqCst) >= 1,
        "the first admission to start",
    )
    .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        ingress.hold.entered.load(Ordering::SeqCst) <= 1,
        "a conversation admits one frame at a time"
    );
    assert!(
        lock(&gateway.acks).is_empty(),
        "no ACK while the commit is pending: {:?}",
        lock(&gateway.acks)
    );
    ingress.hold.release();
    wait_until(
        || (1..=FRAMES).all(|index| gateway.acks_for(&format!("BP-{index}")) == 1),
        "every held frame to be acknowledged once",
    )
    .await;
    ingress.drain().await;
    assert_eq!(lock(&ingress.observer.acks).len(), FRAMES);
    assert!(ingress.errors().is_empty(), "{:?}", ingress.errors());
    let admitted: Vec<usize> = (1..=FRAMES)
        .map(|index| position(&timeline, &format!("admitted:Ev-bp-{index:02}")))
        .collect();
    assert!(
        admitted.windows(2).all(|pair| pair[0] < pair[1]),
        "{admitted:?}"
    );
    for index in 1..=FRAMES {
        assert!(
            position(&timeline, &format!("admitted:Ev-bp-{index:02}"))
                < position(&timeline, &ack_entry(&format!("BP-{index}"))),
            "frame {index}: commit before ACK"
        );
    }
}

/// Removal while admissions are saturated: the frame already inside the
/// pipeline finishes, queued frames are never admitted afterwards, the socket
/// closes and the host does not redial. (The `stop_timeout` bound on a stop
/// that never finishes is pinned at the host tier by
/// `a_stuck_stop_is_bounded_by_stop_timeout_...`; its default of 30 s is too
/// slow for this suite and no test-support seam may shorten it.)
#[tokio::test]
async fn removal_during_saturated_admission_closes_and_admits_nothing_afterwards() {
    let (group, gateway, ingress, timeline, _inbound) =
        stream_fixture("conv-acme-stream-saturated-close").await;
    let services = reborn_services(&group);
    ingress.hold.hold("Ev-sat-");
    for index in 1..=12 {
        gateway.send(event_frame(
            &format!("SAT-{index}"),
            &format!("Ev-sat-{index:02}"),
            "burst",
        ));
    }
    wait_until(
        || ingress.hold.entered.load(Ordering::SeqCst) == 1,
        "the first admission to stall",
    )
    .await;
    let remove = lifecycle_turn(
        &group,
        "conv-acme-stream-saturated-remove",
        "builtin.extension_remove",
        "removed",
    )
    .await;
    remove
        .assert_tool_result_contains("\"removed\":true")
        .await
        .expect("removal reported success");
    ingress.hold.release();
    wait_until(
        || gateway.closed() == 1,
        "the connection to close after the stalled frame finished",
    )
    .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        ingress.hold.entered.load(Ordering::SeqCst),
        1,
        "queued frames are never admitted after the stop: {:?}",
        lock(&timeline)
    );
    assert_eq!(gateway.accepts(), 1, "no redial");
    assert!(stream_state(services).is_none());
}

/// Two conversations on one connection: a stalled admission in one does not
/// hold up the other (they overlap), and each conversation's own frames stay
/// in arrival order.
#[tokio::test]
async fn two_conversations_on_one_connection_overlap_and_stay_ordered_each() {
    let (_group, gateway, ingress, timeline, _inbound) =
        stream_fixture("conv-acme-stream-sessions").await;
    ingress.hold.hold("Ev-a-");
    for index in 1..=3 {
        gateway.send(conversation_frame(
            "C-A",
            &format!("A-{index}"),
            &format!("Ev-a-{index}"),
            "a",
        ));
    }
    for index in 1..=3 {
        gateway.send(conversation_frame(
            "C-B",
            &format!("B-{index}"),
            &format!("Ev-b-{index}"),
            "b",
        ));
    }
    wait_until(
        || (1..=3).all(|index| gateway.acks_for(&format!("B-{index}")) == 1),
        "conversation B to finish while A is stalled",
    )
    .await;
    assert!(
        (1..=3).all(|index| gateway.acks_for(&format!("A-{index}")) == 0),
        "A is still stalled"
    );
    ingress.hold.release();
    wait_until(
        || (1..=3).all(|index| gateway.acks_for(&format!("A-{index}")) == 1),
        "conversation A to finish",
    )
    .await;
    ingress.drain().await;
    for prefix in ["a", "b"] {
        let admitted: Vec<usize> = (1..=3)
            .map(|index| position(&timeline, &format!("admitted:Ev-{prefix}-{index}")))
            .collect();
        assert!(
            admitted.windows(2).all(|pair| pair[0] < pair[1]),
            "{prefix}: {admitted:?}"
        );
    }
    assert!(
        position(&timeline, "admitted:Ev-b-3") < position(&timeline, "admitted:Ev-a-1"),
        "B committed while A was stalled: {:?}",
        lock(&timeline)
    );
    assert!(ingress.errors().is_empty(), "{:?}", ingress.errors());
}
