//! Shared fixtures for the stream-supervisor contract tests: a loopback fake
//! gateway, a scripted connect-call egress, a scripted acme-shaped adapter, a
//! recording admission sink, and a harness that wires them to the REAL
//! extension host snapshot, ingress router (shared admission pipeline), and
//! stream supervisor. Only the invented `acme` vendor appears here.
#![allow(dead_code, clippy::result_large_err)]

pub mod assembly;

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use ironclaw_extension_contracts::channel_adapter::{
    ChannelError, ChannelIngress, ChannelStreamControl, ChannelSurfaces, InboundOutcome,
    NormalizedInboundMessage, ProductTriggerReason, StreamFrameDecision, VerifiedInbound,
};
use ironclaw_extension_contracts::external::{
    ExternalActorRef, ExternalConversationRef, ExternalEventId,
};
use ironclaw_extension_contracts::state::InstallationState;
use ironclaw_extension_contracts::tool_adapter::{RestrictedEgressError, RestrictedEgressResponse};
use ironclaw_extension_host::egress::{ApprovedChannelEgress, ChannelEgressTransport};
use ironclaw_extension_host::ingress::{
    ExtensionIngressRouter, ExtensionIngressRouterDeps, InboundAdmission, InboundAdmissionAck,
    InboundSink, InboundSinkError, IngressConfigurationPort, IngressPortError, IngressRouterConfig,
    IngressSecretsPort, ReplyContextKey, ReplyContextStore, VerificationCandidate,
};
use ironclaw_extension_host::stream_supervisor::{
    BackoffPolicy, FanoutStreamAudit, StreamAuditEvent, StreamAuditKind, StreamAuditSink,
    StreamConnectionStatuses, StreamSupervisor, StreamSupervisorConfig, StreamSupervisorDeps,
};
use ironclaw_extension_host::test_support::{FakeChannelAdapter, resolve_manifest_toml};
use ironclaw_extension_host::{
    DeploymentChannelRegistry, ExtensionBindings, ExtensionEntrypoint, ExtensionHost,
    ExtensionHostDeps, ExtensionLoader, FilesystemInboundBatchStore, InstallationRecord,
    InstallationRecordStore, LoadContext, LoadedExtension, RehydratedInstallationRecordStore,
};
use ironclaw_filesystem::InMemoryBackend;
use ironclaw_host_api::action::NetworkPolicy;
use ironclaw_host_api::ids::{InvocationId, SecretHandle, TenantId, UserId};
use ironclaw_host_api::resource::ResourceScope;
use ironclaw_network::{
    LoopbackWebSocketTransport, NetworkHttpError, NetworkResolver, PolicyWebSocketConnector,
    WebSocketConnector,
};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

pub const EXTENSION_ID: &str = "acme-messenger-stream";
pub const INSTALLATION_ID: &str = "acme-stream-install-1";
pub const GATEWAY_HOST: &str = "gateway.acme.example";
pub const TICKET: &str = "TICKET-SECRET-1";

const MANIFEST: &str =
    include_str!("../../../../../tests/fixtures/extensions/acme-messenger-stream/manifest.toml");

/// The acme stream manifest with textual overrides applied.
pub fn manifest_with(replacements: &[(&str, &str)]) -> String {
    let mut manifest = MANIFEST.to_string();
    for (from, to) in replacements {
        assert!(manifest.contains(from), "fixture lacks `{from}`");
        manifest = manifest.replace(from, to);
    }
    manifest
}

pub fn wait_until_sync(mut condition: impl FnMut() -> bool, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

pub async fn wait_until(mut condition: impl FnMut() -> bool, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

pub type Log = Arc<Mutex<Vec<String>>>;

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

// ── Fake gateway ────────────────────────────────────────────────────────────

pub enum GatewayCmd {
    Send(String),
    Close,
}

/// Loopback WebSocket server standing in for the vendor gateway. Everything
/// it receives from the host is an ACK frame; each is logged as `ack:<text>`.
pub struct Gateway {
    pub addr: SocketAddr,
    pub accepts: Arc<AtomicUsize>,
    pub request_uris: Arc<Mutex<Vec<String>>>,
    connections: Arc<Mutex<Vec<mpsc::UnboundedSender<GatewayCmd>>>>,
    pub acks: Arc<Mutex<Vec<String>>>,
    pub closed: Arc<AtomicUsize>,
    /// When set, the upgrade is refused with this HTTP status.
    pub handshake_status: Arc<Mutex<Option<u16>>>,
    /// Every upgrade request seen, accepted or refused.
    pub handshakes: Arc<AtomicUsize>,
}

impl Gateway {
    pub async fn start(log: Log) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let gateway = Self {
            addr,
            accepts: Arc::new(AtomicUsize::new(0)),
            request_uris: Arc::default(),
            connections: Arc::default(),
            acks: Arc::default(),
            closed: Arc::new(AtomicUsize::new(0)),
            handshake_status: Arc::default(),
            handshakes: Arc::new(AtomicUsize::new(0)),
        };
        let handshake_status = Arc::clone(&gateway.handshake_status);
        let handshakes = Arc::clone(&gateway.handshakes);
        let accepts = Arc::clone(&gateway.accepts);
        let uris = Arc::clone(&gateway.request_uris);
        let connections = Arc::clone(&gateway.connections);
        let acks = Arc::clone(&gateway.acks);
        let closed = Arc::clone(&gateway.closed);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let uris = Arc::clone(&uris);
                let refuse = *lock(&handshake_status);
                let handshakes = Arc::clone(&handshakes);
                let callback = move |request: &tokio_tungstenite::tungstenite::handshake::server::Request,
                                     response: tokio_tungstenite::tungstenite::handshake::server::Response| {
                    lock(&uris).push(request.uri().to_string());
                    handshakes.fetch_add(1, Ordering::SeqCst);
                    match refuse {
                        Some(status) => {
                            let mut refusal =
                                tokio_tungstenite::tungstenite::handshake::server::ErrorResponse::new(None);
                            *refusal.status_mut() =
                                tokio_tungstenite::tungstenite::http::StatusCode::from_u16(status)
                                    .unwrap_or(tokio_tungstenite::tungstenite::http::StatusCode::FORBIDDEN);
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
                let log = Arc::clone(&log);
                let closed = Arc::clone(&closed);
                tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            cmd = rx.recv() => match cmd {
                                Some(GatewayCmd::Send(text)) => {
                                    if write.send(Message::Text(text.into())).await.is_err() { break; }
                                }
                                Some(GatewayCmd::Close) | None => {
                                    _ = write.close().await;
                                    break;
                                }
                            },
                            frame = read.next() => match frame {
                                Some(Ok(Message::Text(text))) => {
                                    let text = text.to_string();
                                    lock(&log).push(format!("ack:{text}"));
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

    pub fn send_to_latest(&self, text: impl Into<String>) {
        let connections = lock(&self.connections);
        if let Some(latest) = connections.last() {
            _ = latest.send(GatewayCmd::Send(text.into()));
        }
    }

    pub fn close_latest(&self) {
        if let Some(latest) = lock(&self.connections).last() {
            _ = latest.send(GatewayCmd::Close);
        }
    }

    pub fn ack_count(&self) -> usize {
        lock(&self.acks).len()
    }

    pub fn ack_texts(&self) -> Vec<String> {
        lock(&self.acks).clone()
    }
}

pub fn event_frame(frame_id: &str, event_id: &str, conversation: &str) -> String {
    serde_json::json!({
        "kind": "event",
        "frame_id": frame_id,
        "payload": {
            "type": "message",
            "event_id": event_id,
            "conversation": conversation,
            "user": "U-ACME-1",
            "text": format!("hello {event_id}"),
        },
    })
    .to_string()
}

pub fn ack_text(frame_id: &str) -> String {
    serde_json::json!({ "ack": frame_id }).to_string()
}

// ── Connect-call egress ─────────────────────────────────────────────────────

#[derive(Clone)]
pub enum ConnectScript {
    Grant,
    GrantEndpoint(&'static str),
    Status(u16),
    Error(RestrictedEgressError),
}

pub struct ConnectEgress {
    script: Mutex<VecDeque<ConnectScript>>,
    default: Mutex<ConnectScript>,
    pub calls: Mutex<Vec<(Instant, ApprovedChannelEgress)>>,
}

impl ConnectEgress {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            script: Mutex::default(),
            default: Mutex::new(ConnectScript::Grant),
            calls: Mutex::default(),
        })
    }

    pub fn push(&self, step: ConnectScript) {
        lock(&self.script).push_back(step);
    }

    pub fn set_default(&self, step: ConnectScript) {
        *lock(&self.default) = step;
    }

    pub fn call_count(&self) -> usize {
        lock(&self.calls).len()
    }

    pub fn call_times(&self) -> Vec<Instant> {
        lock(&self.calls).iter().map(|(at, _)| *at).collect()
    }
}

#[async_trait]
impl ChannelEgressTransport for ConnectEgress {
    async fn execute(
        &self,
        approved: ApprovedChannelEgress,
    ) -> Result<RestrictedEgressResponse, RestrictedEgressError> {
        lock(&self.calls).push((Instant::now(), approved));
        let step = lock(&self.script)
            .pop_front()
            .unwrap_or_else(|| lock(&self.default).clone());
        let grant = |endpoint: &str| RestrictedEgressResponse {
            status: 200,
            body: serde_json::json!({ "endpoint": endpoint, "ticket": TICKET })
                .to_string()
                .into_bytes(),
            retry_after: None,
        };
        match step {
            ConnectScript::Grant => Ok(grant(&format!("wss://{GATEWAY_HOST}/ws"))),
            ConnectScript::GrantEndpoint(endpoint) => Ok(grant(endpoint)),
            ConnectScript::Status(status) => Ok(RestrictedEgressResponse {
                status,
                body: b"{}".to_vec(),
                retry_after: None,
            }),
            ConnectScript::Error(error) => Err(error),
        }
    }
}

// ── Scripted adapter (ingress + frame control) ─────────────────────────────

#[derive(Default)]
pub struct ScriptedStreamAdapter {
    /// Frames the supervisor's reader has handed to `decode`.
    pub decoded: Arc<AtomicUsize>,
}

#[async_trait]
impl ChannelIngress for ScriptedStreamAdapter {
    async fn receive(
        &self,
        request: VerifiedInbound<'_>,
        _egress: &dyn ironclaw_extension_contracts::tool_adapter::RestrictedEgress,
    ) -> Result<InboundOutcome, ChannelError> {
        let parse = |reason: &str| ChannelError::Parse {
            reason: reason.to_string(),
        };
        let value: serde_json::Value =
            serde_json::from_slice(request.body).map_err(|_| parse("body is not JSON"))?;
        let field = |name: &str| {
            value
                .get(name)
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| parse("missing field"))
        };
        Ok(InboundOutcome::Messages(vec![NormalizedInboundMessage {
            actor: ExternalActorRef::new("acme_user", field("user")?, None::<&str>)
                .map_err(|e| parse(&e.to_string()))?,
            conversation: ExternalConversationRef::new(None, field("conversation")?, None, None)
                .map_err(|e| parse(&e.to_string()))?,
            event_id: ExternalEventId::new(field("event_id")?)
                .map_err(|e| parse(&e.to_string()))?,
            text: field("text")?,
            trigger: ProductTriggerReason::DirectChat,
            attachments: Vec::new(),
            conversation_context: None,
            reply_context: Some(b"acme-reply-route".to_vec()),
        }]))
    }
}

impl ChannelStreamControl for ScriptedStreamAdapter {
    fn decode(&self, frame: &[u8]) -> Result<StreamFrameDecision, ChannelError> {
        self.decoded.fetch_add(1, Ordering::SeqCst);
        let parse = |reason: &str| ChannelError::Parse {
            reason: reason.to_string(),
        };
        let value: serde_json::Value =
            serde_json::from_slice(frame).map_err(|_| parse("frame is not JSON"))?;
        if value.get("panic").and_then(serde_json::Value::as_str) == Some("decode") {
            panic!("scripted decode panic carrying SECRET-IN-PANIC");
        }
        let frame_id = value
            .get("frame_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| parse("missing frame_id"))?;
        let ack = match value.get("ack_pad").and_then(serde_json::Value::as_u64) {
            // A scripted oversize ACK: larger than the outbound frame bound.
            Some(pad) => serde_json::json!({
                "ack": frame_id,
                "pad": "x".repeat(usize::try_from(pad).unwrap_or(0)),
            })
            .to_string()
            .into_bytes(),
            None => ack_text(frame_id).into_bytes(),
        };
        match value.get("kind").and_then(serde_json::Value::as_str) {
            Some("event") => {
                let payload = value
                    .get("payload")
                    .ok_or_else(|| parse("missing payload"))?;
                let data = serde_json::to_vec(payload).map_err(|_| parse("payload"))?;
                Ok(StreamFrameDecision::Deliver { data, ack })
            }
            Some("ping") => Ok(StreamFrameDecision::Ack(ack)),
            Some("reconnect") => Ok(StreamFrameDecision::AckAndReconnect(ack)),
            _ => Ok(StreamFrameDecision::Drop { ack: None }),
        }
    }

    fn session_key(&self, data: &[u8]) -> Option<String> {
        let value = serde_json::from_slice::<serde_json::Value>(data).ok()?;
        if value.get("panic_key").is_some() {
            panic!("scripted session_key panic carrying SECRET-IN-PANIC");
        }
        value.get("conversation")?.as_str().map(str::to_string)
    }
}

// ── Recording sink (the durable-admission seam) ─────────────────────────────

#[derive(Default)]
pub struct SinkScript {
    /// event id -> remaining retryable failures before it is accepted.
    pub fail_retryable: HashMap<String, u32>,
    /// event ids rejected permanently.
    pub fail_permanent: Vec<String>,
    /// event id -> time the admit call takes.
    pub delay: HashMap<String, Duration>,
}

pub struct RecordingSink {
    pub log: Log,
    pub script: Mutex<SinkScript>,
    /// (event id, installation id) of each accepted admission, in order.
    pub admitted: Mutex<Vec<(String, String)>>,
    /// Every admit attempt, accepted or not.
    pub attempts: Mutex<Vec<String>>,
    pub in_flight: AtomicUsize,
    pub max_in_flight: AtomicUsize,
}

impl RecordingSink {
    pub fn new(log: Log) -> Arc<Self> {
        Arc::new(Self {
            log,
            script: Mutex::default(),
            admitted: Mutex::default(),
            attempts: Mutex::default(),
            in_flight: AtomicUsize::new(0),
            max_in_flight: AtomicUsize::new(0),
        })
    }

    pub fn admitted_events(&self) -> Vec<String> {
        lock(&self.admitted)
            .iter()
            .map(|(id, _)| id.clone())
            .collect()
    }
}

#[async_trait]
impl InboundSink for RecordingSink {
    async fn admit(
        &self,
        admission: InboundAdmission,
    ) -> Result<InboundAdmissionAck, InboundSinkError> {
        let event = admission.message.event_id.as_str().to_string();
        lock(&self.attempts).push(event.clone());
        let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_in_flight.fetch_max(now, Ordering::SeqCst);
        let delay = lock(&self.script).delay.get(&event).copied();
        if let Some(delay) = delay {
            tokio::time::sleep(delay).await;
        }
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
        let verdict = {
            let mut script = lock(&self.script);
            if script.fail_permanent.contains(&event) {
                Some(false)
            } else if let Some(remaining) = script.fail_retryable.get_mut(&event)
                && *remaining > 0
            {
                *remaining -= 1;
                Some(true)
            } else {
                None
            }
        };
        match verdict {
            Some(retryable) => Err(InboundSinkError {
                retryable,
                reason: "scripted failure".to_string(),
            }),
            None => {
                lock(&self.log).push(format!("admit:{event}"));
                lock(&self.admitted).push((event, admission.installation_id));
                Ok(InboundAdmissionAck::Accepted)
            }
        }
    }
}

// ── Router ports ────────────────────────────────────────────────────────────

struct NoSecrets;

#[async_trait]
impl IngressSecretsPort for NoSecrets {
    async fn verification_candidates(
        &self,
        _extension_id: &str,
        _installation_id: &str,
        _handle: Option<&SecretHandle>,
    ) -> Result<Vec<VerificationCandidate>, IngressPortError> {
        Ok(Vec::new())
    }
}

struct FixedConfiguration;

#[async_trait]
impl IngressConfigurationPort for FixedConfiguration {
    async fn non_secret_config(
        &self,
        _extension_id: &str,
        _installation_id: &str,
    ) -> Result<Vec<(String, String)>, IngressPortError> {
        Ok(vec![("acme_client_id".to_string(), "client-1".to_string())])
    }
}

#[derive(Default)]
struct MemoryReplyContexts {
    entries: Mutex<Vec<(ReplyContextKey, Vec<u8>)>>,
}

#[async_trait]
impl ReplyContextStore for MemoryReplyContexts {
    async fn put(&self, key: ReplyContextKey, context: Vec<u8>) -> Result<(), IngressPortError> {
        let mut entries = lock(&self.entries);
        entries.retain(|(existing, _)| existing != &key);
        entries.push((key, context));
        Ok(())
    }

    async fn get(&self, key: &ReplyContextKey) -> Result<Option<Vec<u8>>, IngressPortError> {
        Ok(lock(&self.entries)
            .iter()
            .find(|(existing, _)| existing == key)
            .map(|(_, value)| value.clone()))
    }
}

#[derive(Clone)]
pub struct PublicResolver;

impl NetworkResolver for PublicResolver {
    fn resolve_ips(&self, _host: &str, _port: u16) -> Result<Vec<IpAddr>, NetworkHttpError> {
        Ok(vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))])
    }
}

// ── Audit ───────────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct RecordingAudit {
    pub events: Mutex<Vec<StreamAuditEvent>>,
    /// Panic (after recording) when a `Connected` event arrives: a fault in
    /// the connection task outside the frame-control callbacks.
    pub panic_on_connected: std::sync::atomic::AtomicBool,
}

impl StreamAuditSink for RecordingAudit {
    fn record(&self, event: StreamAuditEvent) {
        let connected = event.kind == StreamAuditKind::Connected;
        lock(&self.events).push(event);
        if connected && self.panic_on_connected.load(Ordering::SeqCst) {
            panic!("scripted audit sink panic");
        }
    }
}

impl RecordingAudit {
    pub fn kinds(&self) -> Vec<StreamAuditKind> {
        lock(&self.events).iter().map(|e| e.kind.clone()).collect()
    }

    pub fn count(&self, kind: &StreamAuditKind) -> usize {
        self.kinds().iter().filter(|k| *k == kind).count()
    }

    pub fn rendered(&self) -> String {
        format!("{:?}", lock(&self.events))
    }
}

// ── Harness ─────────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct FixedLoader {
    pub decoded: Arc<AtomicUsize>,
}

#[async_trait]
impl ExtensionLoader for FixedLoader {
    async fn load(
        &self,
        _ctx: &LoadContext,
    ) -> Result<LoadedExtension, ironclaw_extension_host::BindError> {
        struct Entry(Arc<AtomicUsize>);
        impl ExtensionEntrypoint for Entry {
            fn bind(
                &self,
                _ctx: ironclaw_extension_host::BindContext,
            ) -> Result<ExtensionBindings, ironclaw_extension_host::BindError> {
                let adapter = Arc::new(ScriptedStreamAdapter {
                    decoded: Arc::clone(&self.0),
                });
                Ok(ExtensionBindings {
                    tools: None,
                    channel: ChannelSurfaces::default()
                        .with_ingress(adapter.clone())
                        .with_stream_control(adapter)
                        .with_reply(Arc::new(FakeChannelAdapter::default())),
                    device_link: None,
                })
            }
        }
        Ok(LoadedExtension::new(Box::new(Entry(Arc::clone(
            &self.decoded,
        )))))
    }
}

pub struct Harness {
    pub host: Arc<ExtensionHost>,
    pub gateway: Gateway,
    pub egress: Arc<ConnectEgress>,
    pub sink: Arc<RecordingSink>,
    pub audit: Arc<RecordingAudit>,
    /// The connection-state cache the lifecycle projection reads, fed by the
    /// same events as `audit` (as composition wires it).
    pub statuses: Arc<StreamConnectionStatuses>,
    pub log: Log,
    /// Frames the reader handed to the stream control's `decode`.
    pub decoded: Arc<AtomicUsize>,
    pub router: Arc<ExtensionIngressRouter>,
    pub supervisor: Option<Arc<StreamSupervisor>>,
    connector: Arc<PolicyWebSocketConnector<LoopbackWebSocketTransport, PublicResolver>>,
    deployment_channels: Arc<DeploymentChannelRegistry>,
    config: StreamSupervisorConfig,
    manifest: Arc<ironclaw_extension_registry::ResolvedExtensionManifest>,
}

pub struct HarnessOptions {
    pub manifest: String,
    pub config: StreamSupervisorConfig,
    /// Start the supervisor immediately (default). A test of boot restoration
    /// activates first and calls [`Harness::spawn_supervisor`] afterwards.
    pub start_supervisor: bool,
}

impl Default for HarnessOptions {
    fn default() -> Self {
        Self {
            manifest: manifest_with(&[]),
            start_supervisor: true,
            config: StreamSupervisorConfig {
                backoff: BackoffPolicy {
                    initial: Duration::from_millis(20),
                    max: Duration::from_millis(200),
                    jitter_fraction: 0.0,
                },
                ..StreamSupervisorConfig::default()
            },
        }
    }
}

fn scope() -> ResourceScope {
    ResourceScope {
        tenant_id: TenantId::new("tenant1").expect("tenant"),
        user_id: UserId::new("user1").expect("user"),
        agent_id: None,
        project_id: None,
        mission_id: None,
        thread_id: None,
        invocation_id: InvocationId::new(),
    }
}

impl Harness {
    /// Build everything and start the supervisor over an EMPTY snapshot; the
    /// installation is activated by [`Self::activate`].
    pub async fn start(options: HarnessOptions) -> Self {
        let log: Log = Arc::default();
        let gateway = Gateway::start(Arc::clone(&log)).await;
        let egress = ConnectEgress::new();
        let sink = RecordingSink::new(Arc::clone(&log));
        let audit = Arc::new(RecordingAudit::default());
        let store = Arc::new(RehydratedInstallationRecordStore::default());
        let decoded = Arc::new(AtomicUsize::new(0));
        let host = Arc::new(
            ExtensionHost::new(ExtensionHostDeps {
                store: Arc::clone(&store) as Arc<dyn InstallationRecordStore>,
                loader: Arc::new(FixedLoader {
                    decoded: Arc::clone(&decoded),
                }),
                drain: Arc::new(ironclaw_extension_host::test_support::RecordingDrain::default()),
                egress: Arc::new(ironclaw_extension_host::test_support::FakeEgressFactory),
                reserved_capability_ids: Default::default(),
                reserved_ingress_routes: Default::default(),
                hook_deadline: Duration::from_secs(5),
                linked_sessions: ironclaw_extension_host::LinkedSessionStore::unavailable(),
                linked_accounts: Arc::new(
                    ironclaw_extension_host::UnavailableLinkedAccountResolution,
                ),
                admin_secrets: None,
            })
            .await,
        );
        let router = Arc::new(ExtensionIngressRouter::new(
            host.snapshot_watch(),
            ExtensionIngressRouterDeps {
                secrets: Arc::new(NoSecrets),
                configuration: Arc::new(FixedConfiguration),
                sink: Arc::clone(&sink) as Arc<dyn InboundSink>,
                reply_context: Arc::new(MemoryReplyContexts::default()),
                inbound_batches: Arc::new(
                    FilesystemInboundBatchStore::new(
                        Arc::new(InMemoryBackend::new()),
                        TenantId::new("tenant-test").expect("tenant"),
                        UserId::new("user-test").expect("user"),
                    )
                    .expect("batch store"),
                ),
                channel_egress_transport: Some(
                    Arc::clone(&egress) as Arc<dyn ChannelEgressTransport>
                ),
            },
            IngressRouterConfig::default(),
        ));
        let connector = Arc::new(PolicyWebSocketConnector::new_with_resolver(
            LoopbackWebSocketTransport::new(gateway.addr),
            PublicResolver,
        ));
        let manifest = Arc::new(resolve_manifest_toml(&options.manifest));
        let mut harness = Self {
            host,
            gateway,
            egress,
            sink,
            audit,
            statuses: Arc::new(StreamConnectionStatuses::default()),
            log,
            decoded,
            router,
            supervisor: None,
            connector,
            deployment_channels: Arc::new(DeploymentChannelRegistry::default()),
            config: options.config,
            manifest,
        };
        if options.start_supervisor {
            harness.spawn_supervisor();
        }
        harness
    }

    pub fn spawn_supervisor(&mut self) {
        self.supervisor = Some(StreamSupervisor::start(
            StreamSupervisorDeps {
                watch: self.host.snapshot_watch(),
                deployment_channels: Arc::clone(&self.deployment_channels),
                admission: self.router.stream_admission(),
                connector: Arc::clone(&self.connector) as Arc<dyn WebSocketConnector>,
                scope: scope(),
                audit: Arc::new(FanoutStreamAudit::new(vec![
                    Arc::clone(&self.audit) as Arc<dyn StreamAuditSink>,
                    Arc::clone(&self.statuses) as Arc<dyn StreamAuditSink>,
                ])),
            },
            self.config.clone(),
        ));
    }

    pub async fn activate(&self) {
        self.host
            .install(InstallationRecord {
                extension_id: EXTENSION_ID.to_string(),
                installation_id: INSTALLATION_ID.to_string(),
                state: InstallationState::Installed,
                resolved: Arc::clone(&self.manifest),
                config: Vec::new(),
                last_error: None,
            })
            .await
            .expect("install");
        self.host.activate(EXTENSION_ID).await.expect("activate");
    }

    /// Install and activate a second acme stream extension under another id.
    pub async fn activate_other(&self, extension_id: &str) {
        let manifest = Arc::new(resolve_manifest_toml(&manifest_with(&[(
            "id = \"acme-messenger-stream\"",
            &format!("id = \"{extension_id}\""),
        )])));
        self.host
            .install(InstallationRecord {
                extension_id: extension_id.to_string(),
                installation_id: format!("{extension_id}-install"),
                state: InstallationState::Installed,
                resolved: manifest,
                config: Vec::new(),
                last_error: None,
            })
            .await
            .expect("install");
        self.host.activate(extension_id).await.expect("activate");
    }

    pub fn log_entries(&self) -> Vec<String> {
        lock(&self.log).clone()
    }
}

/// A policy value the tests never inspect but the connector API requires.
pub fn unused_policy() -> NetworkPolicy {
    NetworkPolicy {
        allowed_targets: Vec::new(),
        deny_private_ip_ranges: true,
        max_egress_bytes: None,
    }
}
