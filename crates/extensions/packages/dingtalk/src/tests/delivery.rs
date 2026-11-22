//! The send path: `ChannelDelivery::deliver` against a recording restricted
//! egress. Request shapes follow the official Go SDK
//! (`alibabacloud-go/dingtalk`, `robot_1_0/client.go`): `BatchSendOTO` posts
//! `{msgKey, msgParam, robotCode, userIds}` to `/v1.0/robot/oToMessages/batchSend`,
//! `OrgGroupSend` posts `{msgKey, msgParam, openConversationId, robotCode}` to
//! `/v1.0/robot/groupMessages/send`; both answer `processQueryKey`. The
//! access token is host-injected: the adapter only names its handle.
use std::sync::Mutex;

use crate::channel::{DINGTALK_ACCESS_TOKEN_HANDLE, DINGTALK_API_HOST, DingTalkChannelAdapter};
use crate::render::{MAX_CHUNK_CHARS, chunk_text, render_text_param};
use crate::reply_context::{DingTalkConversationKind, DingTalkReplyContext};
use ironclaw_extension_contracts::auth_prompt::AuthPromptView;
use ironclaw_extension_contracts::channel_adapter::{
    ChannelDelivery, ChannelError, OutboundEnvelope, OutboundPart, OutboundTarget,
    OutboundVisibility, PartDeliveryOutcome,
};
use ironclaw_extension_contracts::external::ExternalConversationRef;
use ironclaw_extension_contracts::tool_adapter::{
    RestrictedEgress, RestrictedEgressError, RestrictedEgressRequest, RestrictedEgressResponse,
};
use ironclaw_host_api::action::NetworkMethod;
use ironclaw_host_api::attachment::WorkspaceFile;
use serde_json::{Value, json};

type Script =
    Box<dyn Fn(usize) -> Result<RestrictedEgressResponse, RestrictedEgressError> + Send + Sync>;

struct Recorder {
    script: Script,
    requests: Mutex<Vec<RestrictedEgressRequest>>,
}

impl Recorder {
    fn new(script: Script) -> Self {
        Self {
            script,
            requests: Mutex::new(Vec::new()),
        }
    }
    fn ok(body: Value) -> Self {
        Self::new(Box::new(move |_| Ok(response(200, &body))))
    }
    fn requests(&self) -> Vec<RestrictedEgressRequest> {
        self.requests.lock().expect("lock").clone()
    }
}

#[async_trait::async_trait]
impl RestrictedEgress for Recorder {
    async fn send(
        &self,
        request: RestrictedEgressRequest,
    ) -> Result<RestrictedEgressResponse, RestrictedEgressError> {
        let index = {
            let mut requests = self.requests.lock().expect("lock");
            requests.push(request);
            requests.len() - 1
        };
        (self.script)(index)
    }
}

fn response(status: u16, body: &Value) -> RestrictedEgressResponse {
    RestrictedEgressResponse {
        status,
        body: body.to_string().into_bytes(),
        retry_after: None,
    }
}

const CONVERSATION: &str = "cidCONVERSATION";
const STAFF: &str = "staff-1";
const ROBOT: &str = "dingROBOT";

fn context(kind: DingTalkConversationKind, robot: Option<&str>) -> Vec<u8> {
    DingTalkReplyContext::new(kind, CONVERSATION, STAFF, robot.map(str::to_string))
        .encode()
        .expect("encodes")
}

fn envelope(parts: Vec<OutboundPart>, reply_context: Option<Vec<u8>>) -> OutboundEnvelope {
    OutboundEnvelope {
        target: OutboundTarget {
            conversation: ExternalConversationRef::new(None, CONVERSATION, None, None)
                .expect("conversation"),
            thread_anchor: None,
        },
        parts,
        reply_context,
        registrations: Vec::new(),
        visibility: OutboundVisibility::Public,
    }
}

fn dm_envelope(text: &str) -> OutboundEnvelope {
    envelope(
        vec![OutboundPart::Text(text.to_string())],
        Some(context(DingTalkConversationKind::Dm, Some(ROBOT))),
    )
}

fn body_of(request: &RestrictedEgressRequest) -> Value {
    serde_json::from_slice(request.body.as_deref().expect("body")).expect("JSON body")
}

async fn deliver(envelope: OutboundEnvelope, egress: &Recorder) -> Vec<PartDeliveryOutcome> {
    DingTalkChannelAdapter::default()
        .deliver(envelope, egress)
        .await
        .expect("deliver reports per part")
        .parts
}

#[tokio::test]
async fn dm_notice_posts_batch_send_with_the_callback_robot_code_and_token_handle() {
    let egress = Recorder::ok(json!({"processQueryKey": "pqk-1"}));
    let parts = deliver(dm_envelope("hello there"), &egress).await;
    assert!(matches!(
        parts.as_slice(),
        [PartDeliveryOutcome::Sent { vendor_message_ref: Some(key) }] if key == "pqk-1"
    ));
    let [request] = egress.requests().try_into().expect("exactly one request");
    assert_eq!(request.method, NetworkMethod::Post);
    assert_eq!(
        request.url,
        format!("https://{DINGTALK_API_HOST}/v1.0/robot/oToMessages/batchSend")
    );
    assert_eq!(
        request.credential.as_ref().map(|h| h.as_str()),
        Some(DINGTALK_ACCESS_TOKEN_HANDLE),
        "the adapter names the exchanged token; the host injects it"
    );
    assert!(request.body_credentials.is_empty());
    assert!(
        request
            .headers
            .iter()
            .all(|(name, _)| !name.eq_ignore_ascii_case("x-acs-dingtalk-access-token")),
        "the adapter never writes the token header itself"
    );
    let body = body_of(&request);
    assert_eq!(body["robotCode"], ROBOT);
    assert_eq!(body["userIds"], json!([STAFF]));
    assert_eq!(body["msgKey"], "sampleText");
    let param: Value = serde_json::from_str(
        body["msgParam"]
            .as_str()
            .expect("msgParam is a JSON string"),
    )
    .expect("msgParam JSON");
    assert_eq!(param, json!({"content": "hello there"}));
}

#[tokio::test]
async fn group_context_posts_group_messages_send() {
    let egress = Recorder::ok(json!({"processQueryKey": "pqk-g"}));
    let parts = deliver(
        envelope(
            vec![OutboundPart::Text("to the group".into())],
            Some(context(DingTalkConversationKind::Group, Some(ROBOT))),
        ),
        &egress,
    )
    .await;
    assert!(matches!(
        parts.as_slice(),
        [PartDeliveryOutcome::Sent { .. }]
    ));
    let [request] = egress.requests().try_into().expect("one request");
    assert_eq!(
        request.url,
        format!("https://{DINGTALK_API_HOST}/v1.0/robot/groupMessages/send")
    );
    let body = body_of(&request);
    assert_eq!(body["openConversationId"], CONVERSATION);
    assert_eq!(body["robotCode"], ROBOT);
    assert!(body.get("userIds").is_none());
}

#[tokio::test]
async fn an_ephemeral_group_notice_goes_to_that_member_alone_as_a_single_chat() {
    // DingTalk has no ephemeral group post. A notice meant for one member
    // (the connect-required nudge) must not land in the room, so it is sent
    // to that member's own single chat with the robot.
    let egress = Recorder::ok(json!({"processQueryKey": "pqk-e"}));
    let mut ephemeral = envelope(
        vec![OutboundPart::Text("connect first".into())],
        Some(context(DingTalkConversationKind::Group, Some(ROBOT))),
    );
    ephemeral.visibility = OutboundVisibility::EphemeralTo(
        ironclaw_extension_contracts::external::ExternalActorRef::new(
            crate::payload::DINGTALK_USER_ACTOR_KIND,
            "member-7",
            None::<String>,
        )
        .expect("actor"),
    );
    let parts = deliver(ephemeral, &egress).await;
    assert!(matches!(
        parts.as_slice(),
        [PartDeliveryOutcome::Sent { .. }]
    ));
    let [request] = egress.requests().try_into().expect("one request");
    assert_eq!(
        request.url,
        format!("https://{DINGTALK_API_HOST}/v1.0/robot/oToMessages/batchSend")
    );
    let body = body_of(&request);
    assert_eq!(body["userIds"], json!(["member-7"]));
    assert!(body.get("openConversationId").is_none());
    assert_eq!(body["robotCode"], ROBOT);
}

#[tokio::test]
async fn an_ephemeral_notice_for_a_foreign_actor_kind_is_refused_without_sending() {
    let egress = Recorder::ok(json!({"processQueryKey": "never"}));
    let mut ephemeral = envelope(
        vec![OutboundPart::Text("x".into())],
        Some(context(DingTalkConversationKind::Group, Some(ROBOT))),
    );
    ephemeral.visibility = OutboundVisibility::EphemeralTo(
        ironclaw_extension_contracts::external::ExternalActorRef::new(
            "slack_user",
            "U1",
            None::<String>,
        )
        .expect("actor"),
    );
    let parts = deliver(ephemeral, &egress).await;
    assert!(matches!(
        parts.as_slice(),
        [PartDeliveryOutcome::Permanent { .. }]
    ));
    assert!(egress.requests().is_empty());
}

#[tokio::test]
async fn a_missing_robot_code_or_context_fails_closed_without_sending() {
    for reply_context in [
        None,
        Some(context(DingTalkConversationKind::Dm, None)),
        Some(b"not json".to_vec()),
    ] {
        let egress = Recorder::ok(json!({"processQueryKey": "never"}));
        let parts = deliver(
            envelope(vec![OutboundPart::Text("x".into())], reply_context),
            &egress,
        )
        .await;
        assert!(
            matches!(parts.as_slice(), [PartDeliveryOutcome::Permanent { .. }]),
            "{parts:?}"
        );
        assert!(egress.requests().is_empty(), "nothing is sent");
    }
}

#[tokio::test]
async fn a_context_for_another_conversation_is_refused() {
    let other = DingTalkReplyContext::new(
        DingTalkConversationKind::Dm,
        "cidOTHER",
        STAFF,
        Some(ROBOT.to_string()),
    )
    .encode()
    .expect("encodes");
    let egress = Recorder::ok(json!({"processQueryKey": "never"}));
    let parts = deliver(
        envelope(vec![OutboundPart::Text("x".into())], Some(other)),
        &egress,
    )
    .await;
    assert!(matches!(
        parts.as_slice(),
        [PartDeliveryOutcome::Permanent { .. }]
    ));
    assert!(egress.requests().is_empty());
}

#[test]
fn chunks_split_on_character_boundaries() {
    let text = format!("{}{}", "字".repeat(MAX_CHUNK_CHARS), "é🙂x");
    let chunks = chunk_text(&text);
    assert_eq!(chunks.len(), 2);
    assert_eq!(chunks[0].chars().count(), MAX_CHUNK_CHARS);
    assert_eq!(chunks[1], "é🙂x");
    assert_eq!(chunks.concat(), text);
    assert_eq!(chunk_text("short"), vec!["short"]);
    assert!(chunk_text("").is_empty());
}

#[test]
fn renders_text_params_with_escaping() {
    let text: Value = serde_json::from_str(&render_text_param("a \"quoted\"\nline")).expect("json");
    assert_eq!(text, json!({"content": "a \"quoted\"\nline"}));
}

#[tokio::test]
async fn long_text_is_sent_as_ordered_chunks() {
    let egress = Recorder::new(Box::new(|i| {
        Ok(response(
            200,
            &json!({"processQueryKey": format!("pqk-{i}")}),
        ))
    }));
    let text = "あ".repeat(MAX_CHUNK_CHARS * 2 + 1);
    let parts = deliver(dm_envelope(&text), &egress).await;
    assert_eq!(parts.len(), 3);
    let sent: Vec<String> = egress
        .requests()
        .iter()
        .map(|request| {
            let param: Value =
                serde_json::from_str(body_of(request)["msgParam"].as_str().expect("param"))
                    .expect("json");
            param["content"].as_str().expect("content").to_string()
        })
        .collect();
    assert_eq!(sent.concat(), text);
}

#[tokio::test]
async fn auth_prompts_render_as_text() {
    let egress = Recorder::ok(json!({"processQueryKey": "pqk"}));
    let view: AuthPromptView = serde_json::from_value(json!({
        "turn_run_id": ironclaw_host_api::turn::TurnRunId::new(),
        "auth_request_ref": "auth-1",
        "headline": "Connect DingTalk",
        "body": "Open IronClaw to connect."
    }))
    .expect("view");
    let parts = deliver(
        envelope(
            vec![OutboundPart::AuthPrompt {
                view: Box::new(view),
                direct_message: true,
            }],
            Some(context(DingTalkConversationKind::Dm, Some(ROBOT))),
        ),
        &egress,
    )
    .await;
    assert!(matches!(
        parts.as_slice(),
        [PartDeliveryOutcome::Sent { .. }]
    ));
    let param: Value = serde_json::from_str(
        body_of(&egress.requests()[0])["msgParam"]
            .as_str()
            .expect("param"),
    )
    .expect("json");
    assert!(
        param["content"]
            .as_str()
            .expect("content")
            .contains("Connect DingTalk")
    );
}

async fn single_outcome(status: u16, body: Value) -> PartDeliveryOutcome {
    let egress = Recorder::new(Box::new(move |_| Ok(response(status, &body))));
    let mut parts = deliver(dm_envelope("x"), &egress).await;
    assert_eq!(egress.requests().len(), 1, "the adapter never re-sends");
    parts.remove(0)
}

#[tokio::test]
async fn vendor_errors_are_classified() {
    // 429 means DingTalk refused the request before processing it, so a later
    // attempt cannot duplicate a delivered message.
    assert!(
        matches!(
            single_outcome(429, json!({"code": "x"})).await,
            PartDeliveryOutcome::Retryable { .. }
        ),
        "429 is retryable"
    );
    // A 5xx gives no evidence either way: DingTalk may already have delivered
    // the message, so the send is unverified and never re-sent.
    for status in [500, 502, 503] {
        match single_outcome(status, json!({"code": "x"})).await {
            PartDeliveryOutcome::Ambiguous { reason } => {
                assert!(reason.contains("sent_unverified"), "{status}: {reason}")
            }
            other => panic!("{status} must be unverified, got {other:?}"),
        }
    }
    for status in [400, 403, 404] {
        assert!(
            matches!(
                single_outcome(status, json!({"code": "x"})).await,
                PartDeliveryOutcome::Permanent { .. }
            ),
            "{status} is permanent"
        );
    }
    // 401 reaches the adapter only after the host's single token refresh.
    assert!(matches!(
        single_outcome(401, json!({})).await,
        PartDeliveryOutcome::Unauthorized { .. }
    ));
}

#[tokio::test]
async fn per_recipient_lists_override_a_2xx() {
    assert!(matches!(
        single_outcome(
            200,
            json!({"processQueryKey": "k", "invalidStaffIdList": [STAFF]})
        )
        .await,
        PartDeliveryOutcome::Permanent { .. }
    ));
    assert!(matches!(
        single_outcome(
            200,
            json!({"processQueryKey": "k", "filteredStaffIdList": [STAFF]})
        )
        .await,
        PartDeliveryOutcome::Permanent { .. }
    ));
    assert!(matches!(
        single_outcome(
            200,
            json!({"processQueryKey": "k", "flowControlledStaffIdList": [STAFF]})
        )
        .await,
        PartDeliveryOutcome::Retryable { .. }
    ));
}

#[tokio::test]
async fn ambiguous_outcomes_are_marked_unverified_and_never_resent() {
    // 2xx without the evidence, 2xx that is not JSON, and a transport error
    // after the request may have left: all ambiguous, one request each.
    for script in [
        Box::new(|_| Ok(response(200, &json!({})))) as Script,
        Box::new(|_| {
            Ok(RestrictedEgressResponse {
                status: 200,
                body: b"<html>".to_vec(),
                retry_after: None,
            })
        }),
        Box::new(|_| {
            Err(RestrictedEgressError::Transport {
                reason: "connection reset".into(),
            })
        }),
    ] {
        let egress = Recorder::new(script);
        let parts = deliver(dm_envelope("x"), &egress).await;
        match parts.as_slice() {
            [PartDeliveryOutcome::Ambiguous { reason }] => {
                assert!(reason.contains("sent_unverified"), "{reason}")
            }
            other => panic!("expected ambiguous, got {other:?}"),
        }
        assert_eq!(egress.requests().len(), 1);
    }
}

#[tokio::test]
async fn a_failed_chunk_stops_the_rest() {
    let egress = Recorder::new(Box::new(|i| {
        if i == 0 {
            Ok(response(200, &json!({"processQueryKey": "first"})))
        } else {
            Ok(response(429, &json!({})))
        }
    }));
    let parts = deliver(dm_envelope(&"a".repeat(MAX_CHUNK_CHARS * 3)), &egress).await;
    assert_eq!(egress.requests().len(), 2, "stops after the failed chunk");
    assert!(matches!(parts[0], PartDeliveryOutcome::Sent { .. }));
    assert!(matches!(parts[1], PartDeliveryOutcome::Retryable { .. }));
}

#[tokio::test]
async fn a_server_error_after_an_accepted_chunk_is_unverified_and_stops_the_rest() {
    let egress = Recorder::new(Box::new(|i| {
        if i == 0 {
            Ok(response(200, &json!({"processQueryKey": "first"})))
        } else {
            Ok(response(503, &json!({})))
        }
    }));
    let parts = deliver(dm_envelope(&"a".repeat(MAX_CHUNK_CHARS * 3)), &egress).await;
    assert_eq!(egress.requests().len(), 2, "stops after the failed chunk");
    assert!(matches!(parts[0], PartDeliveryOutcome::Sent { .. }));
    assert!(matches!(parts[1], PartDeliveryOutcome::Ambiguous { .. }));
}

#[tokio::test]
async fn reasons_never_echo_vendor_bodies() {
    let marker = "VENDOR_ECHO_MARKER";
    let outcome = single_outcome(400, json!({"message": marker})).await;
    let PartDeliveryOutcome::Permanent { reason } = outcome else {
        panic!("permanent");
    };
    assert!(!reason.contains(marker));
    assert!(!reason.contains(ROBOT) && !reason.contains(STAFF));
}

#[tokio::test]
async fn files_and_reactions_are_unsupported_parts() {
    let egress = Recorder::ok(json!({"processQueryKey": "k"}));
    let file = OutboundPart::File(WorkspaceFile {
        path: ironclaw_host_api::path::ScopedPath::new("/workspace/report.pdf")
            .expect("workspace path"),
        filename: Some("report.pdf".to_string()),
        mime_type: "application/pdf".to_string(),
        bytes: b"%PDF".to_vec(),
    });
    let parts = deliver(
        envelope(
            vec![file],
            Some(context(DingTalkConversationKind::Dm, Some(ROBOT))),
        ),
        &egress,
    )
    .await;
    assert!(
        matches!(
            parts.as_slice(),
            [PartDeliveryOutcome::Permanent { reason }] if reason == "dingtalk channel does not send files"
        ),
        "{parts:?}"
    );
    let parts = deliver(
        envelope(
            vec![OutboundPart::Retract {
                vendor_message_ref: "k".into(),
            }],
            Some(context(DingTalkConversationKind::Dm, Some(ROBOT))),
        ),
        &egress,
    )
    .await;
    assert!(
        matches!(
            parts.as_slice(),
            [PartDeliveryOutcome::Permanent { reason }] if reason == "dingtalk channel does not retract or react"
        ),
        "{parts:?}"
    );
    assert!(egress.requests().is_empty());
}
/// An envelope with no parts is a render error, not an empty success.
#[tokio::test]
async fn an_envelope_without_parts_is_a_render_error_and_sends_nothing() {
    let egress = Recorder::ok(json!({"processQueryKey": "k"}));
    let error = DingTalkChannelAdapter::default()
        .deliver(
            envelope(
                Vec::new(),
                Some(context(DingTalkConversationKind::Dm, Some(ROBOT))),
            ),
            &egress,
        )
        .await
        .expect_err("an empty envelope is refused");
    assert!(matches!(error, ChannelError::Render { .. }), "{error:?}");
    assert!(egress.requests().is_empty());
}
