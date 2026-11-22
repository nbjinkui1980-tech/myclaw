//! Reborn integration test: the shipped DingTalk package (DingTalk plan,
//! Tasks 13–14) through the composed runtime.
//!
//! The real `crates/extensions/packages/dingtalk` manifest installs and
//! activates through the production lifecycle tool; the composed stream
//! supervisor runs the declared connect call (client id and secret injected
//! host-side) and dials a loopback fake gateway through the policy-checked
//! connector. The production channel-host assembly registers the package's
//! ingress with the generic pairing interceptor and connect-required driver.
//! Notices leave through the package's `ChannelDelivery` and the host-side
//! token exchange: every assertion about a send is made at the network-egress
//! seam (path, body, injected `x-acs-dingtalk-access-token`). The only
//! substitutions are the fake DingTalk OpenAPI and the loopback WebSocket
//! transport.
//!
//! Journey: an unpaired single-chat message gets the "connect first" notice
//! and admits no turn; the generated code sent as a single-chat message pairs
//! the sender (paired notice, connection state); the next message resolves to
//! the paired user's own thread and is admitted without a second nudge; a
//! sender from another organisation cannot pair with a live code.
//!
//! Single-chat journey (Task 16): a paired sender's frame runs a turn under
//! the paired user's own scope and the agent's terminal reply leaves through
//! the package's `ReplySink` as exactly one `batchSend` with the exchanged
//! token, and the coordinator records a Delivered attempt.
//!
//! Group journey (Task 17): two paired members @mention the robot in one
//! group; each message runs as that member's own identity and each reply
//! leaves on `groupMessages/send` for the group. A message that does not
//! @mention the robot admits no turn, and an unpaired member's @mention gets
//! the connect-required notice in their own single chat, not in the room.
//!
//! Push journey (Task 18): a paired user's `builtin.outbound_deliver` reaches
//! only their own single chat (the generic provider's own-DM target), asserted on
//! the wire; another person's DM and a group are refused with nothing sent.
//!
//! Stack: like the other composed-runtime targets in this tree, the journeys
//! assume the CI test environment's `RUST_MIN_STACK=67108864` (every CI test
//! job exports it); run it locally as
//! `RUST_MIN_STACK=67108864 cargo test -p ironclaw_integration_tests --test
//! reborn_integration_extension_dingtalk_pairing`.
//!
//! Determinism: no test sleeps for a fixed time. Every absence claim ("sent
//! exactly once", "no notice", "throttled") is made after a positive signal
//! that can only appear once the event under test has been fully processed: a
//! later frame's ACK followed by the ingress registry's post-admission drain,
//! the durable `Delivered` delivery attempt of a later send, or the fake
//! vendor's own counter.
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

use chrono::Utc;
use futures::{SinkExt, StreamExt};
use ironclaw_assistant::RunDeliverySettings;
use ironclaw_composition::{ChannelHostAssemblyTestWiring, RebornRuntime};
use ironclaw_extension_contracts::channel_adapter::{
    ChannelIngress, InboundOutcome, VerifiedInbound,
};
use ironclaw_extension_host::channel_host::{ChannelHostIdentity, GenericChannelHostAssembly};
use ironclaw_extension_host::extension_ingress::ExtensionIngressRegistry;
use ironclaw_host_api::product_adapter::auth::{AuthRequirement, ProtocolAuthEvidence};
use ironclaw_host_api::product_adapter::{AdapterInstallationId, ProductAdapterId};
use ironclaw_network::{
    LoopbackWebSocketTransport, NetworkHttpError, NetworkHttpRequest, NetworkResolver,
    PolicyWebSocketConnector, WebSocketConnector,
};
use ironclaw_product_contracts::binding::{ProductBindingResolver, ResolveBindingRequest};
use ironclaw_product_contracts::inbound::{
    ParsedProductInbound, ProductInboundEnvelope, ProductInboundPayload, UserMessagePayload,
};
use ironclaw_turns::TurnScope;
use reborn_support::assertions::ToolErrorClass;
use reborn_support::builder::RebornIntegrationHarness;
use reborn_support::group::RebornIntegrationGroup;
use reborn_support::harness::profiles::extension::{
    DINGTALK_CLIENT_ID, DINGTALK_CLIENT_SECRET, DINGTALK_TOKEN_PREFIX, DingTalkVendor,
};
use reborn_support::reply::RebornScriptedReply;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

const EXTENSION: &str = "dingtalk";
const INSTALLATION: &str = "dingtalk";
const DM_SEND_PATH: &str = "/v1.0/robot/oToMessages/batchSend";
const TOKEN_PATH: &str = "/v1.0/oauth2/accessToken";
const CORP: &str = "dingITEST_CORP";
const ROBOT_CODE: &str = "dingITEST_ROBOT";
const STAFF: &str = "itest-staff-1";
const DM_CONVERSATION: &str = "cidITEST_DM_1";
const CONNECT_REQUIRED: &str = "Connect this DingTalk account";
const PAIRED: &str = "DingTalk connected";
const GROUP_SEND_PATH: &str = "/v1.0/robot/groupMessages/send";
const GROUP_CONVERSATION: &str = "cidITEST_GROUP_1";

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

async fn wait_until(mut condition: impl FnMut() -> bool, what: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while !condition() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Poll `probe` until it yields a value; the same deadline and clock
/// (`tokio::time::Instant`) as [`wait_until`], so a paused clock treats both
/// alike.
async fn wait_for_some<T, Fut>(mut probe: impl FnMut() -> Fut, what: &str) -> T
where
    Fut: std::future::Future<Output = Option<T>>,
{
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(value) = probe().await {
            return value;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
/// Loopback WebSocket server standing in for the DingTalk gateway: records
/// every ACK frame the host sends back.
struct Gateway {
    addr: SocketAddr,
    accepts: Arc<AtomicUsize>,
    connections: Arc<Mutex<Vec<mpsc::UnboundedSender<String>>>>,
    acks: Arc<Mutex<Vec<String>>>,
}

impl Gateway {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let gateway = Self {
            addr: listener.local_addr().expect("addr"),
            accepts: Arc::default(),
            connections: Arc::default(),
            acks: Arc::default(),
        };
        let accepts = Arc::clone(&gateway.accepts);
        let connections = Arc::clone(&gateway.connections);
        let acks = Arc::clone(&gateway.acks);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let Ok(socket) = tokio_tungstenite::accept_async(stream).await else {
                    continue;
                };
                accepts.fetch_add(1, Ordering::SeqCst);
                let (mut write, mut read) = socket.split();
                let (tx, mut rx) = mpsc::unbounded_channel::<String>();
                lock(&connections).push(tx);
                let acks = Arc::clone(&acks);
                tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            text = rx.recv() => match text {
                                Some(text) => {
                                    if write.send(Message::Text(text.into())).await.is_err() {
                                        break;
                                    }
                                }
                                None => break,
                            },
                            frame = read.next() => match frame {
                                Some(Ok(Message::Text(text))) => lock(&acks).push(text.to_string()),
                                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                                Some(Ok(_)) => {}
                            },
                        }
                    }
                });
            }
        });
        gateway
    }

    fn accepts(&self) -> usize {
        self.accepts.load(Ordering::SeqCst)
    }

    fn send(&self, frame: Value) {
        let connections = lock(&self.connections);
        connections
            .last()
            .expect("an open gateway connection")
            .send(frame.to_string())
            .expect("gateway connection task alive");
    }

    fn acked(&self, message_id: &str) -> bool {
        lock(&self.acks).iter().any(|ack| {
            serde_json::from_str::<Value>(ack)
                .is_ok_and(|ack| ack["headers"]["messageId"] == message_id && ack["code"] == 200)
        })
    }
}

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

fn reborn_services(group: &RebornIntegrationGroup) -> &RebornRuntime {
    group
        .capability_harness()
        .expect("host-runtime capability harness")
        .reborn_services_for_test()
        .expect("composed reborn services")
}

/// The two administrator secrets every host-side DingTalk call injects (the
/// stream connect body and the token-exchange body).
fn bind_credentials(services: &RebornRuntime) {
    let entries = [
        ("dingtalk_client_id", DINGTALK_CLIENT_ID),
        ("dingtalk_client_secret", DINGTALK_CLIENT_SECRET),
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

/// One bot callback frame in the official SDK's shape (`data` is a JSON
/// string), single chat, text.
fn callback_data(
    msg_id: &str,
    sender_corp: &str,
    staff: &str,
    conversation: &str,
    text: &str,
) -> Value {
    json!({
        "conversationId": conversation,
        "conversationType": "1",
        "chatbotCorpId": CORP,
        "senderCorpId": sender_corp,
        "senderStaffId": staff,
        "senderNick": "Itest Sender",
        "msgId": msg_id,
        "msgtype": "text",
        "robotCode": ROBOT_CODE,
        "text": {"content": text},
    })
}

/// A group callback: `@robot` (or not) from one member.
fn group_callback_data(msg_id: &str, staff: &str, text: &str, at_robot: bool) -> Value {
    let mut data = callback_data(msg_id, CORP, staff, GROUP_CONVERSATION, text);
    data["conversationType"] = json!("2");
    data["isInAtList"] = json!(at_robot);
    data["atUsers"] = json!([{"dingtalkId": "itest-robot-dingtalk-id"}]);
    data
}
fn callback_frame(message_id: &str, data: &Value) -> Value {
    json!({
        "specVersion": "1.0",
        "type": "CALLBACK",
        "headers": {
            "messageId": message_id,
            "topic": "/v1.0/im/bot/messages/get",
            "contentType": "application/json",
        },
        "data": data.to_string(),
    })
}

fn requests_to(
    egress: &reborn_support::doubles::RecordingNetworkHttpEgress,
    path: &str,
) -> Vec<NetworkHttpRequest> {
    egress
        .requests()
        .into_iter()
        .filter(|request| request.url.ends_with(path))
        .collect()
}

fn header<'a>(request: &'a NetworkHttpRequest, name: &str) -> Option<&'a str> {
    request
        .headers
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

/// The decoded `msgParam.content` of a robot send.
fn sent_text(request: &NetworkHttpRequest) -> String {
    let body: Value = serde_json::from_slice(&request.body).expect("send body is JSON");
    let param: Value = serde_json::from_str(body["msgParam"].as_str().expect("msgParam string"))
        .expect("msgParam JSON");
    param["content"]
        .as_str()
        .expect("a robot send carries msgParam.content")
        .to_string()
}

fn dm_sends_containing(
    egress: &reborn_support::doubles::RecordingNetworkHttpEgress,
    needle: &str,
) -> Vec<NetworkHttpRequest> {
    requests_to(egress, DM_SEND_PATH)
        .into_iter()
        .filter(|request| sent_text(request).contains(needle))
        .collect()
}

/// Resolve the conversation binding the production sink will resolve for this
/// callback: parse it through the REAL adapter, assemble the verified
/// envelope like the generic sink does, and ask the production binding
/// service.
async fn resolve_turn_scope(
    binding_service: &Arc<dyn ProductBindingResolver>,
    data: &Value,
) -> (TurnScope, ironclaw_host_api::ids::UserId) {
    let egress = ironclaw_extension_contracts::test_support::conformance::ScriptedVendorServer::new(
        Arc::new(
            |_| ironclaw_extension_contracts::tool_adapter::RestrictedEgressResponse {
                retry_after: None,
                status: 503,
                body: Vec::new(),
            },
        ),
    );
    let body = data.to_string();
    let outcome = ironclaw_dingtalk_extension::DingTalkChannelAdapter::default()
        .receive(
            VerifiedInbound {
                extension_id: EXTENSION,
                installation_id: INSTALLATION,
                config: &[],
                body: body.as_bytes(),
                headers: &[],
                can_reply_in_threads: false,
            },
            &egress,
        )
        .await
        .expect("the callback parses through the real adapter");
    let InboundOutcome::Messages(messages) = outcome else {
        panic!("the callback must normalize to a message");
    };
    let message = messages.first().expect("one message");
    let evidence = ProtocolAuthEvidence::test_verified(
        AuthRequirement::AuthenticatedStream {
            connection_recipe:
                ironclaw_extension_host::extension_ingress::STREAM_CONNECTION_RECIPE_LABEL
                    .to_string(),
        },
        INSTALLATION,
    );
    let context =
        ironclaw_product_contracts::inbound::TrustedInboundContext::from_verified_evidence(
            ProductAdapterId::new(EXTENSION).expect("adapter id"),
            AdapterInstallationId::new(INSTALLATION).expect("installation id"),
            Utc::now(),
            &evidence,
        )
        .expect("trusted inbound context");
    let payload = ProductInboundPayload::UserMessage(
        UserMessagePayload::new(message.text.clone(), Vec::new(), message.trigger)
            .expect("user message payload"),
    );
    let parsed = ParsedProductInbound::new(
        message.event_id.clone(),
        message.actor.clone(),
        message.conversation.clone(),
        payload,
    )
    .expect("parsed inbound");
    let envelope =
        ProductInboundEnvelope::from_trusted_parse(context, parsed).expect("inbound envelope");
    let binding = binding_service
        .resolve_binding(ResolveBindingRequest::from_envelope(&envelope).expect("binding request"))
        .await
        .expect("the conversation binding resolves");
    (
        TurnScope::new_with_owner(
            binding.tenant_id.clone(),
            binding.agent_id.clone(),
            binding.project_id.clone(),
            binding.thread_id.clone(),
            Some(binding.actor_user_id.clone()),
        ),
        binding.actor_user_id,
    )
}

/// Scripted model for a paired user's DingTalk conversation. It answers with
/// `replies` in order (the last one repeats) and records every request it
/// receives, so a test can prove a run reached the model, count the runs, and
/// prove a message never did.
#[derive(Debug)]
struct RecordingReplyGateway {
    replies: Vec<&'static str>,
    requests: Mutex<Vec<String>>,
}
impl RecordingReplyGateway {
    fn new(replies: &[&'static str]) -> Arc<Self> {
        assert!(!replies.is_empty(), "a gateway needs at least one reply");
        Arc::new(Self {
            replies: replies.to_vec(),
            requests: Mutex::new(Vec::new()),
        })
    }
    fn calls(&self) -> usize {
        lock(&self.requests).len()
    }
    fn assert_saw(&self, needle: &str) {
        assert!(
            lock(&self.requests)
                .iter()
                .any(|request| request.contains(needle)),
            "no model request contained {needle:?}"
        );
    }
    /// Fails when nothing was captured, so it cannot pass vacuously.
    fn assert_excludes(&self, needle: &str) {
        let requests = lock(&self.requests);
        assert!(
            !requests.is_empty(),
            "vacuous exclusion: no model request was captured"
        );
        assert!(
            requests.iter().all(|request| !request.contains(needle)),
            "a model request unexpectedly contained {needle:?}"
        );
    }
}
#[async_trait::async_trait]
impl ironclaw_loop_host::HostManagedModelGateway for RecordingReplyGateway {
    async fn stream_model(
        &self,
        request: ironclaw_loop_host::HostManagedModelRequest,
    ) -> Result<
        ironclaw_loop_host::HostManagedModelResponse,
        ironclaw_loop_host::HostManagedModelError,
    > {
        let rendered = serde_json::to_string(&request).expect("model request serializes");
        let index = {
            let mut requests = lock(&self.requests);
            requests.push(rendered);
            requests.len() - 1
        };
        let reply = self.replies[index.min(self.replies.len() - 1)];
        Ok(ironclaw_loop_host::HostManagedModelResponse::assistant_reply(reply))
    }
}
fn dm_send_count(egress: &reborn_support::doubles::RecordingNetworkHttpEgress) -> usize {
    requests_to(egress, DM_SEND_PATH).len()
}
fn group_send_count(egress: &reborn_support::doubles::RecordingNetworkHttpEgress) -> usize {
    requests_to(egress, GROUP_SEND_PATH).len()
}
/// Everything the four journeys share, built in one fixed order: gateway,
/// group, credentials, inbound thread, install through the production
/// lifecycle tool, the runtime channel host's registration, then (when the
/// journey runs frames through a run world) the test channel-host assembly,
/// and finally the stream supervisor's dial.
/// How the journey's administrator secrets reach the host.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Credentials {
    /// The test injection point, before install (the pre-existing journeys).
    Bridged,
    /// Nothing at start; the test saves them through the administrator
    /// configuration capability, the service the WebUI save uses.
    AdministratorLater,
}
struct Journey {
    gateway: Gateway,
    group: RebornIntegrationGroup,
    egress: Arc<reborn_support::doubles::RecordingNetworkHttpEgress>,
    vendor: Arc<DingTalkVendor>,
    inbound: RebornIntegrationHarness,
    registry: Arc<ExtensionIngressRegistry>,
    /// Kept alive for the journey; `None` for a journey served by the
    /// runtime's own channel host.
    _assembly: Option<Arc<GenericChannelHostAssembly>>,
    binding_service: Option<Arc<dyn ProductBindingResolver>>,
}
impl Journey {
    async fn start(label: &str, with_assembly: bool) -> Self {
        Self::start_with(label, with_assembly, Credentials::Bridged).await
    }
    async fn start_with(label: &str, with_assembly: bool, credentials: Credentials) -> Self {
        let gateway = Gateway::start().await;
        let (group, egress, vendor) = RebornIntegrationGroup::builder()
            .extension_runtime_dingtalk(loopback_connector(gateway.addr))
            .await
            .expect("dingtalk group builds");
        let services = reborn_services(&group);
        if credentials == Credentials::Bridged {
            bind_credentials(services);
        }
        let inbound = group
            .thread(format!("conv-dingtalk-{label}-inbound"))
            .script([RebornScriptedReply::text("unused")])
            .build()
            .await
            .expect("inbound thread builds");
        let lifecycle = group
            .thread(format!("conv-dingtalk-{label}-install"))
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
        lifecycle
            .submit_turn("install the dingtalk extension")
            .await
            .expect("lifecycle turn completes");
        lifecycle
            .assert_tool_result_contains("\"phase\":\"active\"")
            .await
            .expect("dingtalk installs and activates");
        let registry = services
            .extension_ingress_parts()
            .expect("composition built the generic ingress")
            .registry;
        // The composed runtime runs its own channel host over the same
        // ingress registry. Starting the test assembly only after that host
        // registered makes the test assembly's registration the last one, so
        // stream frames are served by the assembly whose run world this
        // harness scripts (otherwise which host serves a frame is a race).
        wait_until(
            || registry.is_registered(EXTENSION),
            "the runtime channel host's registration",
        )
        .await;
        let (assembly, binding_service) = if with_assembly {
            let assembly = services
                .start_channel_host_assembly_for_test(ChannelHostAssemblyTestWiring {
                    thread_service: inbound
                        .thread_service_for_test()
                        .expect("group thread service"),
                    turn_coordinator: inbound.turn_coordinator_for_test(),
                    run_delivery_settings: RunDeliverySettings::default(),
                    reply_projection: inbound.reply_projection_for_test(),
                    identity: ChannelHostIdentity {
                        tenant_id: inbound.binding.tenant_id.clone(),
                        agent_id: inbound.binding.agent_id.clone().expect("binding agent id"),
                        project_id: inbound.binding.project_id.clone(),
                        operator_user_id: inbound.binding.actor_user_id.clone(),
                    },
                })
                .expect("the production channel host assembly starts");
            let binding_service = wait_for_some(
                || {
                    let assembly = &assembly;
                    async move { assembly.binding_service_for_extension_for_test(EXTENSION) }
                },
                "the production assembly's dingtalk binding service",
            )
            .await;
            (Some(assembly), Some(binding_service))
        } else {
            (None, None)
        };
        if credentials == Credentials::Bridged {
            wait_until(|| gateway.accepts() >= 1, "the stream supervisor's dial").await;
        }
        Self {
            gateway,
            group,
            egress,
            vendor,
            inbound,
            registry,
            _assembly: assembly,
            binding_service,
        }
    }
    fn services(&self) -> &RebornRuntime {
        reborn_services(&self.group)
    }
    fn binding_service(&self) -> &Arc<dyn ProductBindingResolver> {
        self.binding_service
            .as_ref()
            .expect("this journey started the channel host assembly")
    }
    /// The frame has been ACKed AND the post-admission work its admission
    /// spawned (nudges, notices) has finished: the point after which a
    /// request count can be compared without waiting for time to pass.
    async fn settle_frame(&self, message_id: &str) {
        wait_until(|| self.gateway.acked(message_id), "a frame's ACK").await;
        self.registry.drain().await;
    }
    /// Pair `staff` (in the single chat `conversation`) with `user`: issue a
    /// code, send it as the whole message, and wait for the paired notice.
    async fn pair(
        &self,
        user: &ironclaw_host_api::ids::UserId,
        staff: &str,
        conversation: &str,
        frame_id: &str,
    ) {
        let (code, _, _) = self
            .services()
            .pairing_issue_for_test(EXTENSION, user)
            .await
            .expect("a dingtalk pairing code issues");
        let before = dm_sends_containing(&self.egress, PAIRED).len();
        self.gateway.send(callback_frame(
            frame_id,
            &callback_data(&format!("{frame_id}-msg"), CORP, staff, conversation, &code),
        ));
        wait_until(
            || dm_sends_containing(&self.egress, PAIRED).len() > before,
            "the paired notice on batchSend",
        )
        .await;
    }
    /// Wait until the durable delivery attempts of `scope` hold at least
    /// `count` `Delivered` settlements.
    async fn wait_for_delivered(&self, scope: &TurnScope, count: usize) {
        let (outbound_store, _, _, _, _) = self
            .services()
            .outbound_delivery_stores_for_test()
            .expect("outbound stores");
        wait_for_some(
            || {
                let outbound_store = Arc::clone(&outbound_store);
                let scope = scope.clone();
                async move {
                    let attempts = outbound_store
                        .list_delivery_attempts(scope)
                        .await
                        .expect("list delivery attempts");
                    let delivered = attempts
                        .iter()
                        .filter(|attempt| {
                            attempt.status == ironclaw_outbound::OutboundDeliveryStatus::Delivered
                        })
                        .count();
                    (delivered >= count).then_some(())
                }
            },
            "durable Delivered settlements",
        )
        .await;
    }
    /// Resolve the scope of a callback through the production binding
    /// service and register `gateway` as that scope's scripted model.
    async fn script_model(
        &self,
        data: &Value,
        gateway: Arc<RecordingReplyGateway>,
    ) -> (TurnScope, ironclaw_host_api::ids::UserId) {
        let (scope, actor) = resolve_turn_scope(self.binding_service(), data).await;
        self.inbound
            .register_scope_gateway_for_test(scope.clone(), gateway);
        (scope, actor)
    }
}
/// Review #1: the connect call's credentials are injected into the BODY only.
/// The recorded request must carry no `Authorization` header and no header
/// value derived from either application credential.
fn assert_connect_request_carries_no_header_credential(request: &NetworkHttpRequest) {
    assert!(
        header(request, "authorization").is_none(),
        "the connect call must not carry an Authorization header; headers: {:?}",
        request
            .headers
            .iter()
            .map(|(name, _)| name)
            .collect::<Vec<_>>()
    );
    for (name, value) in &request.headers {
        for secret in [DINGTALK_CLIENT_SECRET, DINGTALK_CLIENT_ID] {
            assert!(
                !value.contains(secret),
                "the connect call's `{name}` header carries an application credential"
            );
        }
    }
}
/// TX-DT-1..4: connect-required notice, code pairing, paired admission into
/// the user's own thread (the run executes), and an external-organisation
/// sender refused.
#[tokio::test]
async fn dingtalk_code_pairing_binds_the_sender_and_notices_leave_through_the_token_exchange() {
    Box::pin(pairing_journey()).await;
}
const PAIRED_REPLY: &str = "You are connected, here is what I can do.";
async fn pairing_journey() {
    let journey = Box::pin(Journey::start("pairing", true)).await;
    let (gateway, egress) = (&journey.gateway, &journey.egress);
    // The connect call carried both admin secrets, injected host-side, in the
    // body and nowhere else.
    let connect = requests_to(egress, "/v1.0/gateway/connections/open");
    let connect = connect.last().expect("a connect call");
    let connect_body: Value = serde_json::from_slice(&connect.body).expect("JSON");
    assert_eq!(connect_body["clientId"], DINGTALK_CLIENT_ID);
    assert_eq!(connect_body["clientSecret"], DINGTALK_CLIENT_SECRET);
    assert_eq!(
        connect_body["subscriptions"],
        json!([{"type": "CALLBACK", "topic": "/v1.0/im/bot/messages/get"}])
    );
    assert_connect_request_carries_no_header_credential(connect);
    // 1. Unpaired single chat: the connect-required notice, no turn.
    let unpaired = "hello robot, are you there?";
    gateway.send(callback_frame(
        "M-1",
        &callback_data("msg-1", CORP, STAFF, DM_CONVERSATION, unpaired),
    ));
    wait_until(|| gateway.acked("M-1"), "the ACK for the unpaired frame").await;
    wait_until(
        || !dm_sends_containing(egress, CONNECT_REQUIRED).is_empty(),
        "the connect-required notice on batchSend",
    )
    .await;
    let nudge = dm_sends_containing(egress, CONNECT_REQUIRED)
        .into_iter()
        .next()
        .expect("nudge");
    assert_eq!(nudge.url, format!("https://api.dingtalk.com{DM_SEND_PATH}"));
    assert!(
        header(&nudge, "x-acs-dingtalk-access-token")
            .is_some_and(|token| token.starts_with(DINGTALK_TOKEN_PREFIX)),
        "the host injected the exchanged token"
    );
    let nudge_body: Value = serde_json::from_slice(&nudge.body).expect("JSON");
    assert_eq!(
        nudge_body["robotCode"], ROBOT_CODE,
        "robotCode comes from the callback"
    );
    assert_eq!(nudge_body["userIds"], json!([STAFF]));
    assert_eq!(nudge_body["msgKey"], "sampleText");
    let exchanges = requests_to(egress, TOKEN_PATH);
    assert_eq!(exchanges.len(), 1, "one token exchange so far");
    let exchange_body: Value = serde_json::from_slice(&exchanges[0].body).expect("JSON");
    assert_eq!(exchange_body["appKey"], DINGTALK_CLIENT_ID);
    assert_eq!(exchange_body["appSecret"], DINGTALK_CLIENT_SECRET);
    assert_eq!(journey.vendor.exchanges(), 1);
    // 2. A sender from ANOTHER organisation sending a live code is refused
    //    before pairing (stateless organisation rule): ACKed, and nothing is
    //    sent to the outsider or anywhere else.
    let paired_user = journey.inbound.binding.actor_user_id.clone();
    let (code, deep_link, _expires) = journey
        .services()
        .pairing_issue_for_test(EXTENSION, &paired_user)
        .await
        .expect("a dingtalk pairing code issues");
    assert!(deep_link.is_none(), "dingtalk declares no deep link");
    let dm_before = dm_send_count(egress);
    let group_before = group_send_count(egress);
    gateway.send(callback_frame(
        "M-2",
        &callback_data(
            "msg-2",
            "dingOTHER_ORG",
            "outsider-1",
            "cidITEST_DM_OUTSIDER",
            &code,
        ),
    ));
    journey.settle_frame("M-2").await;
    assert_eq!(
        dm_send_count(egress),
        dm_before,
        "the outsider received no notice of any kind"
    );
    assert_eq!(group_send_count(egress), group_before);
    let channel_connection = journey
        .group
        .channel_connection()
        .expect("the group composes production channel connection");
    assert!(
        !channel_connection
            .caller_channel_connected(EXTENSION, &paired_user)
            .await
            .expect("connection state reads"),
        "an external-organisation sender cannot consume the code"
    );
    // 3. The same in-org sender sends the code: paired notice + connected.
    let sends_before_pairing = dm_send_count(egress);
    gateway.send(callback_frame(
        "M-3",
        &callback_data("msg-3", CORP, STAFF, DM_CONVERSATION, &format!("  {code} ")),
    ));
    wait_until(|| gateway.acked("M-3"), "the ACK for the code frame").await;
    wait_until(
        || !dm_sends_containing(egress, PAIRED).is_empty(),
        "the paired notice on batchSend",
    )
    .await;
    assert!(
        channel_connection
            .caller_channel_connected(EXTENSION, &paired_user)
            .await
            .expect("connection state reads"),
        "the code pairs the DingTalk sender with the IronClaw user"
    );
    assert!(
        requests_to(egress, DM_SEND_PATH)
            .iter()
            .skip(sends_before_pairing)
            .all(|request| !sent_text(request).contains(&code)),
        "no send echoes the pairing code"
    );
    // 4. The next message resolves to the paired user's own thread and the
    //    run EXECUTES: the scripted model receives it and its reply leaves.
    let follow_up_text = "what can you do now that we are paired?";
    let follow_up = callback_data("msg-4", CORP, STAFF, DM_CONVERSATION, follow_up_text);
    let model = RecordingReplyGateway::new(&[PAIRED_REPLY]);
    let (scope, actor) = journey.script_model(&follow_up, Arc::clone(&model)).await;
    assert_eq!(
        actor, paired_user,
        "the binding resolves to the paired user"
    );
    assert_eq!(
        scope.explicit_owner_user_id(),
        Some(&paired_user),
        "post-pairing inbound is attributed to the paired user"
    );
    let nudges_before = dm_sends_containing(egress, CONNECT_REQUIRED).len();
    gateway.send(callback_frame("M-4", &follow_up));
    wait_until(|| gateway.acked("M-4"), "the ACK for the paired frame").await;
    wait_until(
        || !dm_sends_containing(egress, PAIRED_REPLY).is_empty(),
        "the paired sender's run reply on batchSend",
    )
    .await;
    journey.wait_for_delivered(&scope, 1).await;
    assert_eq!(model.calls(), 1, "the paired message ran exactly one turn");
    model.assert_saw(follow_up_text);
    assert_eq!(
        dm_sends_containing(egress, CONNECT_REQUIRED).len(),
        nudges_before,
        "a paired sender is admitted, not nudged again"
    );
    // The unpaired message never reached a model: the recorder holds the
    // paired run's request, so the exclusion is not vacuous.
    model.assert_excludes(unpaired);
    // Secrets stay host-side: no ACK frame carries them.
    for ack in lock(&gateway.acks).iter() {
        for secret in [DINGTALK_CLIENT_SECRET, DINGTALK_CLIENT_ID, ROBOT_CODE] {
            assert!(!ack.contains(secret), "an ACK frame leaked {secret}");
        }
    }
}
const JOURNEY_REPLY: &str = "Here is your DingTalk journey reply.";
const JOURNEY_SECOND_REPLY: &str = "Here is the second journey reply.";
/// TX-DT-5 (DingTalk plan, Task 16): the single-chat journey end to end. A
/// paired sender's frame arrives over the stream, runs a turn under the
/// paired user's own scope, and the agent's terminal reply leaves through the
/// package's `ReplySink` as exactly one `oToMessages/batchSend` carrying the
/// host-exchanged token, the callback robot code and the sender's staff id.
/// The same frame redelivered by DingTalk runs nothing and sends nothing.
#[tokio::test]
async fn dingtalk_single_chat_journey_replies_through_the_reply_sink() {
    Box::pin(single_chat_journey()).await;
}
async fn single_chat_journey() {
    let journey = Box::pin(Journey::start("journey", true)).await;
    let (gateway, egress) = (&journey.gateway, &journey.egress);
    let paired_user = journey.inbound.binding.actor_user_id.clone();
    journey
        .pair(&paired_user, STAFF, DM_CONVERSATION, "J-1")
        .await;
    // The paired sender's message resolves to the paired user's own scope;
    // register the scripted model there before the frame admits the turn.
    let question = "what is the status of my journey?";
    let data = callback_data("jmsg-2", CORP, STAFF, DM_CONVERSATION, question);
    let model = RecordingReplyGateway::new(&[JOURNEY_REPLY, JOURNEY_SECOND_REPLY]);
    let (scope, actor) = journey.script_model(&data, Arc::clone(&model)).await;
    assert_eq!(actor, paired_user, "the paired user acts");
    assert_eq!(scope.explicit_owner_user_id(), Some(&paired_user));
    gateway.send(callback_frame("J-2", &data));
    wait_until(|| gateway.acked("J-2"), "the ACK for the paired frame").await;
    // Seam: the reply leaves through the ReplySink on batchSend.
    wait_until(
        || !dm_sends_containing(egress, JOURNEY_REPLY).is_empty(),
        "the agent reply on batchSend",
    )
    .await;
    let reply = dm_sends_containing(egress, JOURNEY_REPLY)
        .into_iter()
        .next()
        .expect("reply send");
    assert_eq!(reply.url, format!("https://api.dingtalk.com{DM_SEND_PATH}"));
    assert!(
        header(&reply, "x-acs-dingtalk-access-token")
            .is_some_and(|token| token.starts_with(DINGTALK_TOKEN_PREFIX)),
        "the host injected the exchanged token on the reply"
    );
    let body: Value = serde_json::from_slice(&reply.body).expect("JSON");
    assert_eq!(body["robotCode"], ROBOT_CODE);
    assert_eq!(body["userIds"], json!([STAFF]));
    assert_eq!(body["msgKey"], "sampleText");
    assert_eq!(sent_text(&reply), JOURNEY_REPLY);
    // Durable evidence: the coordinator records a Delivered attempt for the
    // run's scope.
    journey.wait_for_delivered(&scope, 1).await;
    // Redelivery (review #17): DingTalk sends the SAME callback again under a
    // new frame id. The host's durable ledger settles it as a duplicate: it is
    // ACKed, starts no run and sends nothing. A later, different message then
    // runs; its Delivered settlement is the positive signal that the replay
    // (queued first on the same conversation) has been fully processed.
    gateway.send(callback_frame("J-2R", &data));
    journey.settle_frame("J-2R").await;
    let second = callback_data(
        "jmsg-3",
        CORP,
        STAFF,
        DM_CONVERSATION,
        "and one more thing?",
    );
    gateway.send(callback_frame("J-3", &second));
    wait_until(
        || !dm_sends_containing(egress, JOURNEY_SECOND_REPLY).is_empty(),
        "the second message's reply on batchSend",
    )
    .await;
    journey.wait_for_delivered(&scope, 2).await;
    assert_eq!(
        model.calls(),
        2,
        "two distinct messages ran two turns; the redelivered frame ran none"
    );
    assert_eq!(
        dm_sends_containing(egress, JOURNEY_REPLY).len(),
        1,
        "the terminal reply is sent exactly once"
    );
    assert_eq!(
        dm_sends_containing(egress, JOURNEY_SECOND_REPLY).len(),
        1,
        "the second reply is sent exactly once"
    );
    // The reply body never carries the application credentials.
    for secret in [DINGTALK_CLIENT_SECRET, DINGTALK_CLIENT_ID] {
        assert!(!String::from_utf8_lossy(&reply.body).contains(secret));
    }
}
const MEMBER_ONE: &str = "itest-member-1";
const MEMBER_TWO: &str = "itest-member-2";
const MEMBER_THREE: &str = "itest-member-3-unpaired";
const REPLY_ONE: &str = "Reply for member one.";
const REPLY_TWO: &str = "Reply for member two.";
fn group_sends_containing(
    egress: &reborn_support::doubles::RecordingNetworkHttpEgress,
    needle: &str,
) -> Vec<NetworkHttpRequest> {
    requests_to(egress, GROUP_SEND_PATH)
        .into_iter()
        .filter(|request| sent_text(request).contains(needle))
        .collect()
}
/// TX-DT-6 (DingTalk plan, Task 17): group @robot journey.
#[tokio::test]
async fn dingtalk_group_mentions_run_as_each_paired_member_and_reply_to_the_group() {
    Box::pin(group_journey()).await;
}
async fn group_journey() {
    let journey = Box::pin(Journey::start("group", true)).await;
    let (gateway, egress) = (&journey.gateway, &journey.egress);
    // Pair two members, each to its own IronClaw user, in single chats.
    let user_one = journey.inbound.binding.actor_user_id.clone();
    let user_two =
        ironclaw_host_api::ids::UserId::new("dingtalk-group-user-two").expect("second user id");
    let installation_store = journey
        .services()
        .extension_installation_store_for_test()
        .expect("the profile carries the lifecycle store");
    installation_store
        .activate_membership(
            &ironclaw_extension_registry::ExtensionInstallationId::new(INSTALLATION)
                .expect("installation id"),
            &user_two,
        )
        .await
        .expect("the second user joins the installation membership");
    for (index, (user, staff)) in [(&user_one, MEMBER_ONE), (&user_two, MEMBER_TWO)]
        .into_iter()
        .enumerate()
    {
        journey
            .pair(
                user,
                staff,
                &format!("cidITEST_DM_{staff}"),
                &format!("GP-{index}"),
            )
            .await;
    }
    // Each member's @mention resolves to that member's own identity.
    let question_one = data_for(MEMBER_ONE, "gmsg-1", "@Helper first question");
    let question_two = data_for(MEMBER_TWO, "gmsg-2", "@Helper second question");
    let model_one = RecordingReplyGateway::new(&[REPLY_ONE]);
    let model_two = RecordingReplyGateway::new(&[REPLY_TWO]);
    let (scope_one, actor_one) = journey
        .script_model(&question_one, Arc::clone(&model_one))
        .await;
    let (scope_two, actor_two) = journey
        .script_model(&question_two, Arc::clone(&model_two))
        .await;
    assert_eq!(actor_one, user_one);
    assert_eq!(actor_two, user_two);
    assert_eq!(scope_one.explicit_owner_user_id(), Some(&user_one));
    assert_eq!(scope_two.explicit_owner_user_id(), Some(&user_two));
    // Chatter that does not @mention the robot admits no turn and sends
    // nothing.
    let chatter_text = "just talking among ourselves";
    let chatter = group_callback_data("gmsg-0", MEMBER_ONE, chatter_text, false);
    gateway.send(callback_frame("G-0", &chatter));
    journey.settle_frame("G-0").await;
    gateway.send(callback_frame("G-1", &question_one));
    gateway.send(callback_frame("G-2", &question_two));
    for message_id in ["G-1", "G-2"] {
        wait_until(|| gateway.acked(message_id), "the ACK for a group frame").await;
    }
    for reply in [REPLY_ONE, REPLY_TWO] {
        wait_until(
            || !group_sends_containing(egress, reply).is_empty(),
            "the group reply on groupMessages/send",
        )
        .await;
    }
    journey.wait_for_delivered(&scope_one, 1).await;
    journey.wait_for_delivered(&scope_two, 1).await;
    for reply in [REPLY_ONE, REPLY_TWO] {
        let sends = group_sends_containing(egress, reply);
        assert_eq!(sends.len(), 1, "each reply is sent exactly once");
        let request = &sends[0];
        assert_eq!(
            request.url,
            format!("https://api.dingtalk.com{GROUP_SEND_PATH}")
        );
        assert!(
            header(request, "x-acs-dingtalk-access-token")
                .is_some_and(|token| token.starts_with(DINGTALK_TOKEN_PREFIX)),
            "the host injected the exchanged token on the group reply"
        );
        let body: Value = serde_json::from_slice(&request.body).expect("JSON");
        assert_eq!(body["openConversationId"], GROUP_CONVERSATION);
        assert_eq!(body["robotCode"], ROBOT_CODE);
        assert_eq!(body["msgKey"], "sampleText");
        assert!(body.get("userIds").is_none(), "a group send names no users");
    }
    let all_text: Vec<String> = requests_to(egress, GROUP_SEND_PATH)
        .iter()
        .map(sent_text)
        .collect();
    assert!(
        all_text
            .iter()
            .all(|text| !text.contains("second question") && !text.contains(chatter_text)),
        "no user text is echoed into the group"
    );
    // The unaddressed message admitted no turn: member one's model saw exactly
    // the addressed question (one run), never the chatter.
    assert_eq!(model_one.calls(), 1);
    model_one.assert_saw("first question");
    model_one.assert_excludes(chatter_text);
    assert_eq!(model_two.calls(), 1);
    // An unpaired member's @mention: the connect-required notice goes to
    // that member's own single chat (never the room), at most once per
    // conversation within the throttle window.
    let nudges_before = dm_sends_containing(egress, CONNECT_REQUIRED).len();
    let group_sends_before = group_send_count(egress);
    gateway.send(callback_frame(
        "G-3",
        &group_callback_data("gmsg-3", MEMBER_THREE, "@Helper hello", true),
    ));
    wait_until(
        || dm_sends_containing(egress, CONNECT_REQUIRED).len() > nudges_before,
        "the connect-required notice in the member's single chat",
    )
    .await;
    let nudge = dm_sends_containing(egress, CONNECT_REQUIRED)
        .into_iter()
        .last()
        .expect("nudge");
    let nudge_body: Value = serde_json::from_slice(&nudge.body).expect("JSON");
    assert_eq!(nudge_body["userIds"], json!([MEMBER_THREE]));
    // The throttle's reservation map is private to the generic observer, so
    // the repeat is judged after the observer work of its admission has
    // drained: a second nudge, if one were going to be sent, has been sent.
    gateway.send(callback_frame(
        "G-4",
        &group_callback_data("gmsg-4", MEMBER_THREE, "@Helper anyone there?", true),
    ));
    journey.settle_frame("G-4").await;
    assert_eq!(
        dm_sends_containing(egress, CONNECT_REQUIRED).len(),
        nudges_before + 1,
        "the nudge is throttled per conversation"
    );
    assert_eq!(
        group_send_count(egress),
        group_sends_before,
        "nothing about the unpaired member is posted into the group"
    );
}
fn data_for(staff: &str, msg_id: &str, text: &str) -> Value {
    group_callback_data(msg_id, staff, text, true)
}
const PUSH_TEXT: &str = "A proactive push for the paired user.";
const REFUSED_TEXT: &str = "This push must never leave.";
/// TX-DT-7 (DingTalk plan, Task 18): `builtin.outbound_deliver` to the
/// caller's own single chat succeeds on `oToMessages/batchSend`; targets
/// naming someone else's DM or a group are refused (the tool reports the
/// refusal) and send nothing.
#[tokio::test]
async fn dingtalk_push_reaches_only_the_callers_own_single_chat() {
    Box::pin(push_journey()).await;
}
async fn push_journey() {
    let journey = Box::pin(Journey::start("push", false)).await;
    let egress = &journey.egress;
    // Pair the sender in a single chat: this stores the conversation's reply
    // context (robot code) and provisions the user's DM target.
    let paired_user = journey.inbound.binding.actor_user_id.clone();
    journey
        .pair(&paired_user, STAFF, DM_CONVERSATION, "P-1")
        .await;
    let own_target = format!("dingtalk:personal-dm::{}", paired_user.as_str());
    let pusher = journey
        .group
        .thread("conv-dingtalk-push")
        .script([
            RebornScriptedReply::tool_call(
                "builtin.outbound_deliver",
                json!({"target_id": own_target, "content": PUSH_TEXT}),
            ),
            RebornScriptedReply::text("pushed"),
            RebornScriptedReply::tool_call(
                "builtin.outbound_deliver",
                json!({"target_id": "dingtalk:personal-dm::someone-else", "content": REFUSED_TEXT}),
            ),
            RebornScriptedReply::text("refused someone else"),
            RebornScriptedReply::tool_call(
                "builtin.outbound_deliver",
                json!({"target_id": format!("dingtalk:group:{GROUP_CONVERSATION}"), "content": REFUSED_TEXT}),
            ),
            RebornScriptedReply::text("refused the group"),
        ])
        .build()
        .await
        .expect("push thread builds");
    let (dm_before, group_before) = (dm_send_count(egress), group_send_count(egress));
    pusher
        .submit_turn("push a note to my dingtalk")
        .await
        .expect("the push turn completes");
    pusher
        .assert_tool_result_contains("\"delivered\":true")
        .await
        .expect("the tool reports the own-DM push as delivered");
    let sends = dm_sends_containing(egress, PUSH_TEXT);
    assert_eq!(sends.len(), 1, "the push is sent exactly once");
    let request = &sends[0];
    assert_eq!(
        request.url,
        format!("https://api.dingtalk.com{DM_SEND_PATH}")
    );
    assert!(
        header(request, "x-acs-dingtalk-access-token")
            .is_some_and(|token| token.starts_with(DINGTALK_TOKEN_PREFIX)),
        "the host injected the exchanged token on the push"
    );
    let body: Value = serde_json::from_slice(&request.body).expect("JSON");
    assert_eq!(body["userIds"], json!([STAFF]));
    assert_eq!(
        body["robotCode"], ROBOT_CODE,
        "robotCode comes from the DM conversation's stored reply context"
    );
    assert_eq!(body["msgKey"], "sampleText");
    assert_eq!(dm_send_count(egress), dm_before + 1);
    assert_eq!(group_send_count(egress), group_before);
    // Each refusal boundary: the tool reports the refusal (a model-visible
    // `input_encode` failure: the target does not validate), and the exact
    // request counts of both send endpoints stay where they were. The turn
    // completes only after the capability result is recorded, so the counts
    // are read after the refusal's own completion signal.
    let (dm_after_push, group_after_push) = (dm_send_count(egress), group_send_count(egress));
    for boundary in ["someone else's DM", "a group"] {
        let baseline = pusher.history_len().await.expect("history length");
        pusher
            .submit_turn(&format!("now try {boundary}"))
            .await
            .unwrap_or_else(|error| panic!("the refusal turn for {boundary} completes: {error}"));
        pusher
            .assert_tool_error_since(baseline, ToolErrorClass::Failed, "input_encode")
            .await
            .unwrap_or_else(|error| panic!("{boundary}: the tool reports a refusal: {error}"));
        assert_eq!(
            dm_send_count(egress),
            dm_after_push,
            "{boundary}: no single-chat send"
        );
        assert_eq!(
            group_send_count(egress),
            group_after_push,
            "{boundary}: no group send"
        );
    }
    assert!(
        dm_sends_containing(egress, REFUSED_TEXT).is_empty()
            && group_sends_containing(egress, REFUSED_TEXT).is_empty(),
        "a target that is not the caller's own single chat sends nothing"
    );
}

const UNCONFIRMED_REPLY: &str = "This reply meets a vendor server error.";
/// Review #10 (caller tier): DingTalk answers the reply's send with a 503. The
/// reply publication worker must not resend it: exactly one OpenAPI request is
/// made for the reply, and the durable record settles as unknown (never
/// delivered, never retried into a duplicate).
#[tokio::test]
async fn dingtalk_server_error_on_a_reply_is_sent_once_and_settles_unknown() {
    Box::pin(server_error_journey()).await;
}
async fn server_error_journey() {
    let journey = Box::pin(Journey::start("unverified", true)).await;
    let (gateway, egress) = (&journey.gateway, &journey.egress);
    let paired_user = journey.inbound.binding.actor_user_id.clone();
    journey
        .pair(&paired_user, STAFF, DM_CONVERSATION, "U-1")
        .await;
    let data = callback_data("umsg-2", CORP, STAFF, DM_CONVERSATION, "will this arrive?");
    let model = RecordingReplyGateway::new(&[UNCONFIRMED_REPLY]);
    let (scope, _) = journey.script_model(&data, Arc::clone(&model)).await;
    journey.vendor.script_send_failure(503);
    gateway.send(callback_frame("U-2", &data));
    wait_until(|| gateway.acked("U-2"), "the ACK for the frame").await;
    wait_until(
        || !dm_sends_containing(egress, UNCONFIRMED_REPLY).is_empty(),
        "the reply's send reaching the vendor",
    )
    .await;
    let (outbound_store, _, _, _, _) = journey
        .services()
        .outbound_delivery_stores_for_test()
        .expect("outbound stores");
    // Durable settlement: the attempt ends Unknown (unconfirmed), not
    // Delivered and not Failed/retried.
    let attempts = wait_for_some(
        || {
            let outbound_store = Arc::clone(&outbound_store);
            let scope = scope.clone();
            async move {
                let attempts = outbound_store
                    .list_delivery_attempts(scope)
                    .await
                    .expect("list delivery attempts");
                attempts
                    .iter()
                    .any(|attempt| {
                        attempt.status == ironclaw_outbound::OutboundDeliveryStatus::Unknown
                    })
                    .then_some(attempts)
            }
        },
        "an Unknown delivery settlement",
    )
    .await;
    assert!(
        attempts
            .iter()
            .all(|attempt| attempt.status != ironclaw_outbound::OutboundDeliveryStatus::Delivered),
        "an unconfirmed reply is never recorded as delivered"
    );
    assert_eq!(model.calls(), 1);
    journey.registry.drain().await;
    assert_eq!(
        dm_sends_containing(egress, UNCONFIRMED_REPLY).len(),
        1,
        "one OpenAPI request carried the reply (the run's separate working \
         indicator is a different message)"
    );
}

/// Save the DingTalk administrator secrets through `builtin.admin_configuration_replace`,
/// the capability the WebUI extension-configuration save invokes.
async fn configure_dingtalk_admin(group: &RebornIntegrationGroup, values: Value) {
    use ironclaw_host_api::{
        action::NetworkPolicy,
        capability::{CapabilityGrant, CapabilitySet, EffectKind, GrantConstraints},
        ids::{
            CapabilityGrantId, CapabilityId, CorrelationId, ExtensionId, InvocationId, ProductKind,
        },
        invocation::InvocationOrigin,
        mount::MountView,
        resource::{ResourceEstimate, ResourceScope},
        runtime::{RuntimeKind, TrustClass},
        scope::{ExecutionContext, Principal},
    };
    let operator = ironclaw_host_api::ids::UserId::new("reborn-e2e-extension-lifecycle-tools")
        .expect("operator user id");
    let capability_id = CapabilityId::new("builtin.admin_configuration_replace")
        .expect("admin configuration capability id");
    let product_ingress = ExtensionId::new("ironclaw_webui").expect("product ingress id");
    let invocation_id = InvocationId::new();
    let runtime_scope = &group.shared.product_harness.scope;
    let scope = ResourceScope {
        tenant_id: runtime_scope.tenant_id.clone(),
        user_id: operator.clone(),
        agent_id: Some(runtime_scope.agent_id.clone().expect("runtime agent id")),
        project_id: None,
        mission_id: None,
        thread_id: None,
        invocation_id,
    };
    let context = ExecutionContext {
        invocation_id,
        correlation_id: CorrelationId::new(),
        process_id: None,
        parent_process_id: None,
        tenant_id: scope.tenant_id.clone(),
        user_id: operator.clone(),
        authenticated_actor_user_id: Some(operator),
        agent_id: scope.agent_id.clone(),
        project_id: scope.project_id.clone(),
        mission_id: None,
        thread_id: None,
        run_id: None,
        origin: Some(InvocationOrigin::Product(
            ProductKind::new("webui").expect("product origin kind"),
        )),
        extension_id: product_ingress.clone(),
        runtime: RuntimeKind::FirstParty,
        trust: TrustClass::Sandbox,
        grants: CapabilitySet {
            grants: vec![CapabilityGrant {
                id: CapabilityGrantId::new(),
                capability: capability_id.clone(),
                grantee: Principal::Extension(product_ingress),
                issued_by: Principal::HostRuntime,
                constraints: GrantConstraints {
                    allowed_effects: vec![
                        EffectKind::ReadFilesystem,
                        EffectKind::WriteFilesystem,
                        EffectKind::DeleteFilesystem,
                        EffectKind::UseSecret,
                    ],
                    mounts: MountView::default(),
                    network: NetworkPolicy::default(),
                    secrets: Vec::new(),
                    resource_ceiling: None,
                    expires_at: None,
                    max_invocations: Some(1),
                },
            }],
        },
        mounts: MountView::default(),
        resource_scope: scope,
    };
    context
        .validate()
        .expect("admin capability context validates");
    let outcome = reborn_services(group)
        .host_runtime_for_test()
        .expect("host runtime")
        .invoke_capability((
            context,
            capability_id,
            ResourceEstimate::default(),
            json!({
                "group_id": "extension.dingtalk",
                "expected_revision": 0,
                "values": values,
            }),
        ))
        .await
        .expect("admin configuration dispatch completes");
    assert!(
        matches!(
            outcome,
            ironclaw_host_runtime::RuntimeCapabilityOutcome::Completed(_)
        ),
        "admin configuration must complete through the authorized runtime, got {outcome:?}"
    );
}

/// The host's redacted stream connection state for DingTalk, as the
/// extensions page reads it.
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
fn stream_state(
    services: &RebornRuntime,
) -> Option<(
    ironclaw_product_contracts::lifecycle_service::ExtensionStreamState,
    Option<String>,
)> {
    stream_connections(services)
        .into_iter()
        .find(|(id, _)| id.as_str() == EXTENSION)
        .map(|(_, connection)| (connection.state, connection.last_error))
}

/// Production path: the secrets are saved through the administrator
/// configuration capability after the connection stopped for missing
/// credentials. The deployment-sourced stream must reconnect, and the connect
/// body must carry the saved values, injected host-side.
#[tokio::test]
async fn dingtalk_administrator_saved_credentials_reach_the_connect_call_and_connect() {
    Box::pin(administrator_saved_credentials_journey()).await;
}
async fn administrator_saved_credentials_journey() {
    use ironclaw_product_contracts::lifecycle_service::ExtensionStreamState;
    let journey = Box::pin(Journey::start_with(
        "admin",
        false,
        Credentials::AdministratorLater,
    ))
    .await;
    let (gateway, egress) = (&journey.gateway, &journey.egress);
    let services = journey.services();
    wait_until(
        || {
            stream_state(services)
                == Some((
                    ExtensionStreamState::NeedsAdministrator,
                    Some("connect_credentials_missing".to_string()),
                ))
        },
        "the connection to stop for missing credentials",
    )
    .await;
    assert!(requests_to(egress, "/v1.0/gateway/connections/open").is_empty());
    assert_eq!(gateway.accepts(), 0);
    configure_dingtalk_admin(
        &journey.group,
        json!([
            {"handle": "dingtalk_client_id", "value": DINGTALK_CLIENT_ID},
            {"handle": "dingtalk_client_secret", "value": DINGTALK_CLIENT_SECRET},
        ]),
    )
    .await;
    wait_until(
        || gateway.accepts() >= 1,
        "the stream supervisor's dial after the administrator saved credentials",
    )
    .await;
    wait_until(
        || stream_state(services) == Some((ExtensionStreamState::Connected, None)),
        "the connection state to become connected",
    )
    .await;
    let connect = requests_to(egress, "/v1.0/gateway/connections/open");
    let connect = connect.last().expect("a connect call");
    let body: Value = serde_json::from_slice(&connect.body).expect("JSON");
    assert_eq!(body["clientId"], DINGTALK_CLIENT_ID);
    assert_eq!(body["clientSecret"], DINGTALK_CLIENT_SECRET);
    assert_connect_request_carries_no_header_credential(connect);
    let rendered = format!("{:?}", stream_connections(services));
    assert!(!rendered.contains(DINGTALK_CLIENT_SECRET));
    assert!(!rendered.contains(DINGTALK_CLIENT_ID));
}
