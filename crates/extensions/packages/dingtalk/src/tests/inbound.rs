//! Frame control and callback normalization against the constructed DingTalk
//! fixtures (`tests/fixtures/extensions/dingtalk-stream/`; see its README: the
//! frames follow the official SDK source, they are not real captures).
use std::path::PathBuf;
use std::sync::Arc;

use crate::channel::DingTalkChannelAdapter;
use crate::payload::{DINGTALK_USER_ACTOR_KIND, MAX_TEXT_BYTES};
use crate::reply_context::{DingTalkConversationKind, DingTalkReplyContext};
use crate::stream::{DINGTALK_BOT_CALLBACK_TOPIC, DingTalkStreamControl};
use ironclaw_extension_contracts::channel_adapter::{
    ChannelError, ChannelIngress, ChannelStreamControl, InboundOutcome, ProductTriggerReason,
    StreamFrameDecision, VerifiedInbound,
};
use ironclaw_extension_contracts::test_support::conformance::ScriptedVendorServer;
use ironclaw_extension_contracts::tool_adapter::RestrictedEgressResponse;
use serde_json::{Value, json};

fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../../tests/fixtures/extensions/dingtalk-stream")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

fn frame_data(name: &str) -> Value {
    let frame: Value = serde_json::from_slice(&fixture(name)).expect("fixture is JSON");
    serde_json::from_str(frame["data"].as_str().expect("data string")).expect("data is JSON")
}

fn ack_of(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).expect("ack is JSON")
}

async fn receive(data: &[u8]) -> Result<InboundOutcome, ChannelError> {
    let egress = ScriptedVendorServer::new(Arc::new(|_| RestrictedEgressResponse {
        retry_after: None,
        status: 500,
        body: Vec::new(),
    }));
    DingTalkChannelAdapter::default()
        .receive(
            VerifiedInbound {
                extension_id: "dingtalk",
                installation_id: "install_alpha",
                config: &[],
                body: data,
                headers: &[],
                can_reply_in_threads: false,
            },
            &egress,
        )
        .await
}

fn single_chat() -> Value {
    frame_data("callback_single_chat_text.json")
}

async fn expect_ignored(data: &Value) {
    match receive(data.to_string().as_bytes()).await {
        Ok(InboundOutcome::Ignore) => {}
        Ok(_) => panic!("expected the message to be ignored"),
        Err(error) => panic!("expected an authenticated no-op, got {error:?}"),
    }
}

// ---- frame control ---------------------------------------------------------

#[test]
fn callback_frame_delivers_its_data_and_acks_with_the_frame_message_id() {
    let decision = DingTalkStreamControl
        .decode(&fixture("callback_single_chat_text.json"))
        .expect("decodes");
    let StreamFrameDecision::Deliver { data, ack } = decision else {
        panic!("a bot callback must be delivered");
    };
    assert_eq!(
        serde_json::from_slice::<Value>(&data).expect("data is JSON"),
        single_chat()
    );
    let ack = ack_of(&ack);
    assert_eq!(ack["code"], 200);
    assert_eq!(ack["message"], "OK");
    assert_eq!(ack["headers"]["messageId"], "REDACTED_MESSAGE_ID_DM");
    assert_eq!(ack["headers"]["contentType"], "application/json");
    assert!(ack["data"].is_string(), "ACK data is a JSON string");
}

#[test]
fn disconnect_acks_then_reconnects() {
    let decision = DingTalkStreamControl
        .decode(&fixture("system_disconnect.json"))
        .expect("decodes");
    let StreamFrameDecision::AckAndReconnect(ack) = decision else {
        panic!("disconnect must reconnect");
    };
    assert_eq!(
        ack_of(&ack)["headers"]["messageId"],
        "REDACTED_MESSAGE_ID_DISCONNECT"
    );
}

#[test]
fn other_system_frames_are_acked_only() {
    // SDK behavior: every non-disconnect SYSTEM frame is answered 200 "OK".
    let decision = DingTalkStreamControl
        .decode(&fixture("system_ping.json"))
        .expect("decodes");
    let StreamFrameDecision::Ack(ack) = decision else {
        panic!("a ping-like system frame is acked, nothing delivered");
    };
    assert_eq!(ack_of(&ack)["code"], 200);
}

#[test]
fn unknown_topics_and_types_are_dropped_with_an_ack() {
    for frame in [
        json!({"type":"CALLBACK","headers":{"messageId":"M","topic":"/v1.0/other"},"data":"{}"}),
        json!({"type":"EVENT","headers":{"messageId":"M","topic":"x"},"data":"{}"}),
        json!({"type":"MYSTERY","headers":{"messageId":"M","topic":"x"},"data":"{}"}),
    ] {
        let decision = DingTalkStreamControl
            .decode(frame.to_string().as_bytes())
            .expect("decodes");
        let StreamFrameDecision::Drop { ack: Some(ack) } = decision else {
            panic!("unknown frames are dropped but still acknowledged");
        };
        assert_eq!(ack_of(&ack)["headers"]["messageId"], "M");
    }
}

#[test]
fn malformed_frames_are_parse_errors_not_panics() {
    let oversized_id = "x".repeat(300);
    let cases: Vec<Vec<u8>> = vec![
        b"".to_vec(),
        b"{".to_vec(),
        b"[]".to_vec(),
        b"\xff\xfe\x00".to_vec(),
        br#"{"type":"CALLBACK","headers":{"topic":"/v1.0/im/bot/messages/get"},"data":"{}"}"#
            .to_vec(),
        json!({"type":"CALLBACK","headers":{"messageId":oversized_id,"topic":DINGTALK_BOT_CALLBACK_TOPIC},"data":"{}"})
            .to_string()
            .into_bytes(),
        // A bot callback whose `data` is not a string.
        br#"{"type":"CALLBACK","headers":{"messageId":"M","topic":"/v1.0/im/bot/messages/get"},"data":{"a":1}}"#
            .to_vec(),
        br#"{"type":"SYSTEM","headers":{"topic":"disconnect"}}"#.to_vec(),
    ];
    for case in cases {
        assert!(
            matches!(
                DingTalkStreamControl.decode(&case),
                Err(ChannelError::Parse { .. })
            ),
            "{:?} must be a parse error",
            String::from_utf8_lossy(&case)
        );
    }
}

#[test]
fn session_key_is_the_bounded_conversation_id() {
    let data = single_chat().to_string();
    assert_eq!(
        DingTalkStreamControl
            .session_key(data.as_bytes())
            .as_deref(),
        Some("cidREDACTED_CONVERSATION_ID")
    );
    let long = json!({"conversationId": "c".repeat(400)}).to_string();
    assert_eq!(DingTalkStreamControl.session_key(long.as_bytes()), None);
    assert_eq!(DingTalkStreamControl.session_key(b"nope"), None);
}

// ---- single-chat normalization ---------------------------------------------

#[tokio::test]
async fn single_chat_text_normalizes_to_a_direct_message() {
    let outcome = receive(single_chat().to_string().as_bytes())
        .await
        .expect("parses");
    let InboundOutcome::Messages(messages) = outcome else {
        panic!("a same-organisation single chat is admitted");
    };
    let [message] = messages.as_slice() else {
        panic!("exactly one message");
    };
    message.validate().expect("within host bounds");
    assert_eq!(message.actor.kind(), DINGTALK_USER_ACTOR_KIND);
    assert_eq!(message.actor.id(), "REDACTED_STAFF_ID");
    assert_eq!(
        message.conversation.conversation_id(),
        "cidREDACTED_CONVERSATION_ID"
    );
    assert_eq!(message.event_id.as_str(), "msgREDACTED_MSG_ID");
    assert_eq!(message.text, "hello from a single chat");
    assert_eq!(message.trigger, ProductTriggerReason::DirectChat);
    assert!(message.attachments.is_empty());
    let context = DingTalkReplyContext::decode(message.reply_context.as_deref().expect("context"))
        .expect("reply context round-trips");
    assert_eq!(context.kind, DingTalkConversationKind::Dm);
    assert_eq!(context.recipient_staff_id, "REDACTED_STAFF_ID");
    assert_eq!(context.conversation_id, "cidREDACTED_CONVERSATION_ID");
    assert_eq!(
        context.robot_code.as_deref(),
        Some("REDACTED_ROBOT_CODE"),
        "sends name the callback's robot code (ADR 14.3)"
    );
}

#[tokio::test]
async fn dm_text_is_trimmed_and_empty_text_is_ignored() {
    let mut data = single_chat();
    data["text"]["content"] = json!("  spaced out \n");
    let InboundOutcome::Messages(messages) =
        receive(data.to_string().as_bytes()).await.expect("parses")
    else {
        panic!("admitted");
    };
    assert_eq!(messages[0].text, "spaced out");
    data["text"]["content"] = json!("   ");
    expect_ignored(&data).await;
}

#[tokio::test]
async fn corp_id_rule_is_stateless_and_fails_closed() {
    // Different organisation: the sender is not a member of the bot's org.
    let mut data = single_chat();
    data["senderCorpId"] = json!("dingOTHER_ORG");
    expect_ignored(&data).await;
    // Any of the two ids missing, null, or empty: refused.
    for field in ["chatbotCorpId", "senderCorpId"] {
        let mut missing = single_chat();
        missing.as_object_mut().expect("object").remove(field);
        expect_ignored(&missing).await;
        let mut null = single_chat();
        null[field] = Value::Null;
        expect_ignored(&null).await;
        let mut empty = single_chat();
        empty[field] = json!("");
        expect_ignored(&empty).await;
    }
    // The rule does not remember anything: an in-org message after refusals
    // is admitted again.
    assert!(matches!(
        receive(single_chat().to_string().as_bytes()).await,
        Ok(InboundOutcome::Messages(_))
    ));
}

#[tokio::test]
async fn sender_without_a_staff_id_is_ignored() {
    for staff in [None, Some(json!("")), Some(Value::Null)] {
        let mut data = single_chat();
        match staff {
            None => {
                data.as_object_mut()
                    .expect("object")
                    .remove("senderStaffId");
            }
            Some(value) => data["senderStaffId"] = value,
        }
        expect_ignored(&data).await;
    }
}

#[tokio::test]
async fn non_text_messages_are_ignored() {
    let mut data = single_chat();
    data["msgtype"] = json!("picture");
    expect_ignored(&data).await;
    let mut group = group_at();
    group["msgtype"] = json!("picture");
    expect_ignored(&group).await;
}

// ---- group chat (@robot) ---------------------------------------------------

fn group_at() -> Value {
    frame_data("callback_group_at_text.json")
}

async fn admitted(
    data: &Value,
) -> ironclaw_extension_contracts::channel_adapter::NormalizedInboundMessage {
    let InboundOutcome::Messages(mut messages) =
        receive(data.to_string().as_bytes()).await.expect("parses")
    else {
        panic!("expected the message to be admitted");
    };
    assert_eq!(messages.len(), 1);
    messages.remove(0)
}

#[tokio::test]
async fn an_at_mention_in_a_group_is_a_bot_mention_routed_to_the_group() {
    let message = admitted(&group_at()).await;
    message.validate().expect("within host bounds");
    assert_eq!(message.trigger, ProductTriggerReason::BotMention);
    assert_eq!(message.actor.kind(), DINGTALK_USER_ACTOR_KIND);
    assert_eq!(message.actor.id(), "REDACTED_STAFF_ID");
    assert_eq!(
        message.conversation.conversation_id(),
        "cidREDACTED_CONVERSATION_ID"
    );
    assert_eq!(message.event_id.as_str(), "msgREDACTED_MSG_ID");
    assert_eq!(message.text, "hello from a group");
    let context = DingTalkReplyContext::decode(message.reply_context.as_deref().expect("context"))
        .expect("reply context round-trips");
    assert_eq!(context.kind, DingTalkConversationKind::Group);
    assert_eq!(context.conversation_id, "cidREDACTED_CONVERSATION_ID");
    assert_eq!(context.recipient_staff_id, "REDACTED_STAFF_ID");
    assert_eq!(context.robot_code.as_deref(), Some("REDACTED_ROBOT_CODE"));
}

#[tokio::test]
async fn a_group_message_without_an_at_of_the_robot_is_ignored() {
    for in_at_list in [
        Some(json!(false)),
        Some(Value::Null),
        Some(json!("true")),
        None,
    ] {
        let mut data = group_at();
        match in_at_list {
            Some(value) => data["isInAtList"] = value,
            None => {
                data.as_object_mut().expect("object").remove("isInAtList");
            }
        }
        expect_ignored(&data).await;
    }
}

/// Review #4: whether DingTalk writes the robot's own `@name` into
/// `text.content` is unverified (plan Task 20), so no leading `@token` is ever
/// removed; a dropped `@Alice` would be lost user input.
/// `senderNick` becomes the actor's display name when the host's validator
/// accepts it; one it refuses (a control character) is dropped and the message
/// is still admitted, never failed (review #18).
#[tokio::test]
async fn sender_nick_passes_through_and_an_unacceptable_nick_is_dropped() {
    let mut data = single_chat();
    data["senderNick"] = json!("Itest Sender");
    assert_eq!(
        admitted(&data).await.actor.display_name(),
        Some("Itest Sender")
    );
    data["senderNick"] = json!("bad\u{0001}nick");
    let message = admitted(&data).await;
    assert_eq!(message.actor.display_name(), None);
    assert_eq!(
        message.actor.id(),
        data["senderStaffId"].as_str().expect("staff id")
    );
    data["senderNick"] = json!("");
    assert_eq!(admitted(&data).await.actor.display_name(), None);
    data.as_object_mut().expect("object").remove("senderNick");
    assert_eq!(admitted(&data).await.actor.display_name(), None);
}
#[tokio::test]
async fn a_leading_at_token_is_never_removed_from_the_text() {
    let mut data = group_at();
    // Exactly one @ target: the case the old stripping fired on.
    data["text"]["content"] = json!("@Alice 请看一下");
    assert_eq!(admitted(&data).await.text, "@Alice 请看一下");
    data["text"]["content"] = json!("@Helper  what is the weather?");
    assert_eq!(admitted(&data).await.text, "@Helper  what is the weather?");
    // A mention-only message is still non-empty text, handed on as typed.
    data["text"]["content"] = json!(" @Helper ");
    assert_eq!(admitted(&data).await.text, "@Helper");
    // Several @ targets and non-leading mentions are untouched as well.
    let mut many = group_at();
    many["atUsers"] = json!([{"dingtalkId": "a"}, {"dingtalkId": "b"}]);
    many["text"]["content"] = json!("@Alice please look at this");
    assert_eq!(admitted(&many).await.text, "@Alice please look at this");
    let mut inline = group_at();
    inline["text"]["content"] = json!("ask @Alice about it");
    assert_eq!(admitted(&inline).await.text, "ask @Alice about it");
}
#[tokio::test]
async fn two_members_of_one_group_are_two_actors_in_one_conversation() {
    let first = admitted(&group_at()).await;
    let mut other = group_at();
    other["senderStaffId"] = json!("OTHER_STAFF");
    other["msgId"] = json!("msgOTHER");
    let second = admitted(&other).await;
    assert_ne!(first.actor.id(), second.actor.id());
    assert_eq!(
        first.conversation.conversation_id(),
        second.conversation.conversation_id()
    );
    assert_ne!(first.event_id.as_str(), second.event_id.as_str());
}

/// msgId redelivery (plan Task 19): the event id derives from `msgId`, not
/// from the frame's message id or the arrival order, so a redelivery carries
/// the same id. That the host's ledger then settles it once is proven at the
/// integration tier (`dingtalk_single_chat_journey_replies_through_the_reply_sink`).
#[tokio::test]
async fn a_redelivered_callback_keeps_one_event_id_and_a_new_msg_id_gets_another() {
    let first = admitted(&single_chat()).await;
    let redelivered = admitted(&single_chat()).await;
    assert_eq!(first.event_id.as_str(), redelivered.event_id.as_str());
    let mut next = single_chat();
    next["msgId"] = json!("msgNEXT");
    let other = admitted(&next).await;
    assert_ne!(first.event_id.as_str(), other.event_id.as_str());
}
#[tokio::test]
async fn external_or_unidentified_group_members_are_never_admitted() {
    let mut outside = group_at();
    outside["senderCorpId"] = json!("dingOTHER_ORG");
    expect_ignored(&outside).await;
    let mut no_corp = group_at();
    no_corp
        .as_object_mut()
        .expect("object")
        .remove("senderCorpId");
    expect_ignored(&no_corp).await;
    let mut no_staff = group_at();
    no_staff
        .as_object_mut()
        .expect("object")
        .remove("senderStaffId");
    expect_ignored(&no_staff).await;
}

#[tokio::test]
async fn malformed_group_fields_are_ignored_or_parse_errors_never_panics() {
    let mut bad_at_users = group_at();
    bad_at_users["atUsers"] = json!("not a list");
    assert!(matches!(
        receive(bad_at_users.to_string().as_bytes()).await,
        Err(ChannelError::Parse { .. })
    ));
    let mut no_text = group_at();
    no_text.as_object_mut().expect("object").remove("text");
    expect_ignored(&no_text).await;
    let mut huge = group_at();
    huge["text"]["content"] = json!("é".repeat(MAX_TEXT_BYTES / 2 + 1));
    assert!(matches!(
        receive(huge.to_string().as_bytes()).await,
        Err(ChannelError::Parse { .. })
    ));
}

#[tokio::test]
#[tracing_test::traced_test]
async fn an_unaddressed_group_message_logs_a_fixed_reason_only() {
    let mut data = group_at();
    data["isInAtList"] = json!(false);
    expect_ignored(&data).await;
    assert!(logs_contain("group_message_not_addressed"));
    for secret in [
        "REDACTED_STAFF_ID",
        "cidREDACTED_CONVERSATION_ID",
        "hello from a group",
    ] {
        assert!(!logs_contain(secret), "{secret} leaked into a log line");
    }
}

#[tokio::test]
async fn malformed_callback_data_is_a_parse_error() {
    for body in [
        &b""[..],
        &b"{"[..],
        &b"[]"[..],
        &b"{\"unexpected\":true}"[..],
    ] {
        assert!(
            matches!(receive(body).await, Err(ChannelError::Parse { .. })),
            "{:?}",
            String::from_utf8_lossy(body)
        );
    }
    for field in ["msgId", "conversationId", "conversationType"] {
        let mut data = single_chat();
        data.as_object_mut().expect("object").remove(field);
        assert!(
            matches!(
                receive(data.to_string().as_bytes()).await,
                Err(ChannelError::Parse { .. })
            ),
            "missing {field} must be a parse error"
        );
    }
    let mut data = single_chat();
    data["conversationType"] = json!("9");
    assert!(matches!(
        receive(data.to_string().as_bytes()).await,
        Err(ChannelError::Parse { .. })
    ));
}

#[tokio::test]
async fn overlong_text_is_rejected_at_the_bound() {
    let mut data = single_chat();
    data["text"]["content"] = json!("é".repeat(MAX_TEXT_BYTES / 2));
    assert!(matches!(
        receive(data.to_string().as_bytes()).await,
        Ok(InboundOutcome::Messages(_))
    ));
    data["text"]["content"] = json!("é".repeat(MAX_TEXT_BYTES / 2 + 1));
    assert!(matches!(
        receive(data.to_string().as_bytes()).await,
        Err(ChannelError::Parse { .. })
    ));
}

#[tokio::test]
#[tracing_test::traced_test]
async fn refusals_log_a_fixed_reason_and_no_identifiers() {
    let mut data = single_chat();
    data["senderCorpId"] = json!("dingOTHER_ORG_SECRET_MARKER");
    expect_ignored(&data).await;
    let mut missing = single_chat();
    missing
        .as_object_mut()
        .expect("object")
        .remove("chatbotCorpId");
    expect_ignored(&missing).await;
    assert!(logs_contain("sender_outside_bot_org"));
    assert!(logs_contain("corp_id_missing"));
    for secret in [
        "dingOTHER_ORG_SECRET_MARKER",
        "dingREDACTED_CORP_ID",
        "REDACTED_STAFF_ID",
        "REDACTED_NICK",
        "hello from a single chat",
    ] {
        assert!(!logs_contain(secret), "{secret} leaked into a log line");
    }
}

#[tokio::test]
#[tracing_test::traced_test]
async fn robot_code_stability_is_recorded_as_booleans_only() {
    let adapter = DingTalkChannelAdapter::default();
    let egress = ScriptedVendorServer::new(Arc::new(|_| RestrictedEgressResponse {
        retry_after: None,
        status: 500,
        body: Vec::new(),
    }));
    for code in [
        "REDACTED_ROBOT_CODE",
        "REDACTED_ROBOT_CODE",
        "ANOTHER_BOT_CODE",
    ] {
        let mut data = single_chat();
        data["robotCode"] = json!(code);
        let body = data.to_string();
        adapter
            .receive(
                VerifiedInbound {
                    extension_id: "dingtalk",
                    installation_id: "install_alpha",
                    config: &[],
                    body: body.as_bytes(),
                    headers: &[],
                    can_reply_in_threads: false,
                },
                &egress,
            )
            .await
            .expect("parses");
    }
    assert!(logs_contain("robot_code_present=true"));
    assert!(logs_contain("observation=\"first_seen\""));
    assert!(logs_contain("observation=\"unchanged\""));
    assert!(logs_contain("observation=\"changed\""));
    assert!(!logs_contain("REDACTED_ROBOT_CODE"));
    assert!(!logs_contain("ANOTHER_BOT_CODE"));
}
/// Past the tracking cap the adapter says so once instead of going silent
/// (review #19), still without a value.
#[tokio::test]
#[tracing_test::traced_test]
async fn robot_code_tracking_saturation_is_logged_once() {
    let adapter = DingTalkChannelAdapter::default();
    let egress = ScriptedVendorServer::new(Arc::new(|_| RestrictedEgressResponse {
        retry_after: None,
        status: 500,
        body: Vec::new(),
    }));
    let body = single_chat().to_string();
    for index in 0..70 {
        let installation = format!("install_{index}");
        adapter
            .receive(
                VerifiedInbound {
                    extension_id: "dingtalk",
                    installation_id: &installation,
                    config: &[],
                    body: body.as_bytes(),
                    headers: &[],
                    can_reply_in_threads: false,
                },
                &egress,
            )
            .await
            .expect("parses");
    }
    logs_assert(|lines: &[&str]| {
        let full = lines
            .iter()
            .filter(|line| line.contains("robot code tracking is full"))
            .count();
        if full == 1 {
            Ok(())
        } else {
            Err(format!("expected exactly one saturation log, saw {full}"))
        }
    });
    assert!(!logs_contain("REDACTED_ROBOT_CODE"));
}

#[tokio::test]
async fn a_bare_pairing_code_in_a_single_chat_reaches_the_host_as_direct_chat_text() {
    // The host's pairing interceptor matches the whole trimmed text (no
    // inbound prefixes are declared), so the adapter must deliver it verbatim.
    let mut data = single_chat();
    data["text"]["content"] = json!("  ABCD2345 \n");
    let InboundOutcome::Messages(messages) =
        receive(data.to_string().as_bytes()).await.expect("parses")
    else {
        panic!("a code message is admitted to the host");
    };
    assert_eq!(messages[0].text, "ABCD2345");
    assert_eq!(messages[0].trigger, ProductTriggerReason::DirectChat);
    // The same code from another organisation never reaches the host.
    data["senderCorpId"] = json!("dingOTHER_ORG");
    expect_ignored(&data).await;
}
