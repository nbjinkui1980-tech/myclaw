//! The outbound preference-target grammar (DingTalk plan, Task 18):
//! `dm:<staffId>:<conversationId>` and `group:<conversationId>`, strictly
//! parsed segment by segment. A stored ref is never trusted: anything that is
//! not exactly the canonical spelling decodes to nothing.
use crate::channel::DingTalkChannelAdapter;
use crate::preference_targets::DingTalkPreferenceTargetCodec;
use crate::reply_context::{DingTalkConversationKind, DingTalkReplyContext};
use ironclaw_extension_contracts::channel_adapter::{
    ChannelDelivery, OutboundEnvelope, OutboundPart, OutboundTarget, OutboundVisibility,
    PartDeliveryOutcome,
};
use ironclaw_extension_contracts::external::ExternalConversationRef;
use ironclaw_extension_contracts::preference_target::{
    PreferenceTargetCodec, PreferenceTargetEncodeRequest,
};
use ironclaw_extension_contracts::test_support::conformance::ScriptedVendorServer;
use ironclaw_extension_contracts::tool_adapter::RestrictedEgressResponse;
use ironclaw_host_api::ids::{AgentId, ProjectId};
use ironclaw_host_api::product_adapter::AdapterInstallationId;
use ironclaw_host_api::turn::ReplyTargetBindingRef;
use serde_json::Value;
use std::sync::Arc;

const STAFF: &str = "manager4220";
const CONVERSATION: &str = "cidAb+/c=d_E-f";

fn ids() -> (AdapterInstallationId, AgentId, ProjectId) {
    (
        AdapterInstallationId::new("dingtalk").expect("installation"),
        AgentId::new("agent:dingtalk").expect("agent"),
        ProjectId::new("project:dingtalk").expect("project"),
    )
}

fn conversation(id: &str) -> ExternalConversationRef {
    ExternalConversationRef::new(None, id, None, None).expect("conversation")
}

fn encode_dm(conversation_id: &str, actor: &str) -> Option<ReplyTargetBindingRef> {
    let (installation, agent, project) = ids();
    let conversation = conversation(conversation_id);
    DingTalkPreferenceTargetCodec.encode_personal_direct_message_target(
        PreferenceTargetEncodeRequest {
            installation_id: &installation,
            agent_id: &agent,
            project_id: Some(&project),
            conversation: &conversation,
        },
        actor,
    )
}

fn encode_group(conversation_id: &str) -> Option<ReplyTargetBindingRef> {
    let (installation, agent, project) = ids();
    let conversation = conversation(conversation_id);
    DingTalkPreferenceTargetCodec.encode_shared_conversation_target(PreferenceTargetEncodeRequest {
        installation_id: &installation,
        agent_id: &agent,
        project_id: Some(&project),
        conversation: &conversation,
    })
}

fn reference(value: &str) -> ReplyTargetBindingRef {
    ReplyTargetBindingRef::new(value).expect("a syntactically valid ref")
}

#[test]
fn a_personal_dm_round_trips_with_its_staff_id_and_conversation() {
    let target = encode_dm(CONVERSATION, STAFF).expect("encodes");
    assert_eq!(target.as_str(), format!("dm:{STAFF}:{CONVERSATION}"));
    let codec = DingTalkPreferenceTargetCodec;
    assert!(codec.is_personal_direct_message(&target));
    assert_eq!(
        codec.direct_message_actor_for_target(&target).as_deref(),
        Some(STAFF)
    );
    assert_eq!(
        codec
            .conversation_for_target(&target)
            .expect("decodes")
            .conversation_id(),
        CONVERSATION
    );
}

#[test]
fn a_group_round_trips_without_a_dm_actor() {
    let target = encode_group(CONVERSATION).expect("encodes");
    assert_eq!(target.as_str(), format!("group:{CONVERSATION}"));
    let codec = DingTalkPreferenceTargetCodec;
    assert!(!codec.is_personal_direct_message(&target));
    assert_eq!(codec.direct_message_actor_for_target(&target), None);
    assert_eq!(
        codec
            .conversation_for_target(&target)
            .expect("decodes")
            .conversation_id(),
        CONVERSATION
    );
}

#[test]
fn malformed_refs_decode_to_nothing() {
    let codec = DingTalkPreferenceTargetCodec;
    let too_long = format!("dm:{STAFF}:{}", "c".repeat(200));
    let long_staff = format!("dm:{}:{CONVERSATION}", "s".repeat(80));
    for bad in [
        "dm",
        "dm:",
        "dm::",
        "dm:staff",
        "dm:staff:",
        "dm::cid1",
        "dm:staff:cid1:extra",
        "group",
        "group:",
        "group:cid1:extra",
        "DM:staff:cid1",
        "tg:1:_:_",
        "dm:sta ff:cid1",
        "dm:staff:ci d1",
        "dm:staff:cid1\u{e9}",
        "dm:st\u{e9}:cid1",
        "dm:staff:cid1?x=1",
        "dm:staff:cid1/../x ",
        "dm:staff;x:cid1",
        too_long.as_str(),
        long_staff.as_str(),
    ] {
        let target = reference(bad);
        assert!(codec.conversation_for_target(&target).is_none(), "{bad}");
        assert!(!codec.is_personal_direct_message(&target), "{bad}");
        assert!(
            codec.direct_message_actor_for_target(&target).is_none(),
            "{bad}"
        );
    }
}

#[test]
fn encoding_refuses_unsafe_or_mismatched_inputs() {
    assert!(encode_dm(CONVERSATION, "").is_none());
    assert!(encode_dm(CONVERSATION, "a:b").is_none());
    assert!(encode_dm(CONVERSATION, "sta ff").is_none());
    assert!(encode_dm("cid:1", STAFF).is_none());
    assert!(encode_dm("cid 1", STAFF).is_none());
    assert!(encode_dm(&"c".repeat(200), STAFF).is_none());
    assert!(encode_group("cid:1").is_none());
    // A conversation carrying a space or topic is not a DingTalk conversation.
    let (installation, agent, project) = ids();
    let with_space = ExternalConversationRef::new(Some("team"), "cid1", None, None).expect("ref");
    let with_topic = ExternalConversationRef::new(None, "cid1", Some("t"), None).expect("ref");
    for conversation in [with_space, with_topic] {
        let request = PreferenceTargetEncodeRequest {
            installation_id: &installation,
            agent_id: &agent,
            project_id: Some(&project),
            conversation: &conversation,
        };
        assert!(
            DingTalkPreferenceTargetCodec
                .encode_personal_direct_message_target(request, STAFF)
                .is_none()
        );
        assert!(
            DingTalkPreferenceTargetCodec
                .encode_shared_conversation_target(request)
                .is_none()
        );
    }
}

// ---- push through the delivery path ----------------------------------------

fn context(robot: Option<&str>) -> Vec<u8> {
    DingTalkReplyContext::new(
        DingTalkConversationKind::Dm,
        CONVERSATION,
        STAFF,
        robot.map(str::to_string),
    )
    .encode()
    .expect("context")
}

/// What the coordinator hands the adapter for a push: the conversation the
/// codec decoded from the stored ref, plus the stored reply context.
async fn push(
    target: &ReplyTargetBindingRef,
    reply_context: Option<Vec<u8>>,
) -> (Vec<PartDeliveryOutcome>, Vec<Value>) {
    let conversation = DingTalkPreferenceTargetCodec
        .conversation_for_target(target)
        .expect("decodes");
    let bodies = Arc::new(std::sync::Mutex::new(Vec::<Value>::new()));
    let recorded = Arc::clone(&bodies);
    let egress = ScriptedVendorServer::new(Arc::new(move |request| {
        if let Some(body) = &request.body
            && let Ok(value) = serde_json::from_slice::<Value>(body)
        {
            recorded.lock().expect("lock").push(value);
        }
        RestrictedEgressResponse {
            retry_after: None,
            status: 200,
            body: br#"{"processQueryKey":"pqk-push"}"#.to_vec(),
        }
    }));
    let report = DingTalkChannelAdapter::default()
        .deliver(
            OutboundEnvelope {
                target: OutboundTarget {
                    conversation,
                    thread_anchor: None,
                },
                parts: vec![OutboundPart::Text("pushed".to_string())],
                reply_context,
                registrations: Vec::new(),
                visibility: OutboundVisibility::Public,
            },
            &egress,
        )
        .await
        .expect("reports per part");
    let sent = bodies.lock().expect("lock").clone();
    (report.parts, sent)
}

#[tokio::test]
async fn a_push_to_the_callers_own_dm_names_that_staff_id_and_the_context_robot_code() {
    let target = encode_dm(CONVERSATION, STAFF).expect("encodes");
    let (parts, sent) = push(&target, Some(context(Some("dingROBOT")))).await;
    assert!(matches!(
        parts.as_slice(),
        [PartDeliveryOutcome::Sent { .. }]
    ));
    let [body] = sent.as_slice() else {
        panic!("one request");
    };
    assert_eq!(body["userIds"], serde_json::json!([STAFF]));
    assert_eq!(body["robotCode"], "dingROBOT");
}

#[tokio::test]
async fn a_push_without_a_reply_context_or_robot_code_fails_closed() {
    let target = encode_dm(CONVERSATION, STAFF).expect("encodes");
    for reply_context in [None, Some(context(None))] {
        let (parts, sent) = push(&target, reply_context).await;
        assert!(
            matches!(parts.as_slice(), [PartDeliveryOutcome::Permanent { .. }]),
            "{parts:?}"
        );
        assert!(sent.is_empty(), "nothing leaves without a robot code");
    }
}

#[tokio::test]
async fn a_push_with_another_conversations_context_is_refused() {
    // The stored context of another conversation (a different person's DM)
    // never redirects a push.
    let target = encode_dm(CONVERSATION, STAFF).expect("encodes");
    let other = DingTalkReplyContext::new(
        DingTalkConversationKind::Dm,
        "cidSomeoneElse",
        "other-staff",
        Some("dingROBOT".to_string()),
    )
    .encode()
    .expect("context");
    let (parts, sent) = push(&target, Some(other)).await;
    assert!(matches!(
        parts.as_slice(),
        [PartDeliveryOutcome::Permanent { .. }]
    ));
    assert!(sent.is_empty());
}
