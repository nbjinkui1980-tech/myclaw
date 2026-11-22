//! DingTalk bot callback parsing and the organisation rule.
//!
//! Field names come from the official Python SDK's `ChatbotMessage.from_dict`
//! (ADR §8 item 7a). Required-ness, length limits and value constraints are
//! unverified (item 7b), so every field is parsed as optional and the rules
//! below decide what is acceptable.
//!
//! **Organisation rule (stateless, fail closed).** An enterprise-internal
//! robot belongs to exactly one organisation, so `chatbotCorpId` is the
//! deployment's organisation. A message is admitted only when `chatbotCorpId`
//! and `senderCorpId` are both present, non-empty and equal; anything else is
//! refused and never reaches pairing or admission. Nothing is remembered
//! between messages. The meaning of both fields is unverified (ADR §8 item 9,
//! Task 20): if a same-organisation sender's frames carry no `senderCorpId`
//! this rule refuses every message, which is a visible failure.
use ironclaw_extension_contracts::channel_adapter::{
    ChannelError, NormalizedInboundMessage, ProductTriggerReason,
};
use ironclaw_extension_contracts::external::{
    ExternalActorRef, ExternalConversationRef, ExternalEventId,
};
use ironclaw_host_api::product_adapter_error::ProductAdapterError;
use serde::Deserialize;

use crate::reply_context::{DingTalkConversationKind, DingTalkReplyContext};

pub(crate) const DINGTALK_USER_ACTOR_KIND: &str = "dingtalk_user";
/// Largest accepted message text. A longer text is a deterministic parse
/// failure (acknowledged and discarded by the host), never truncated.
pub(crate) const MAX_TEXT_BYTES: usize = 20_000;

/// Why an authenticated callback is an acknowledged no-op. The code is the
/// only thing logged about a refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IgnoreReason {
    /// `chatbotCorpId` or `senderCorpId` is absent or empty.
    CorpIdMissing,
    /// The sender's organisation differs from the bot's.
    SenderOutsideBotOrg,
    /// The sender carries no `senderStaffId`.
    SenderStaffIdMissing,
    /// Not a plain text message.
    UnsupportedMessageType,
    /// A text message with nothing in it.
    EmptyText,
    /// A group message that does not @mention the robot.
    GroupMessageNotAddressed,
}

impl IgnoreReason {
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::CorpIdMissing => "corp_id_missing",
            Self::SenderOutsideBotOrg => "sender_outside_bot_org",
            Self::SenderStaffIdMissing => "sender_staff_id_missing",
            Self::UnsupportedMessageType => "unsupported_message_type",
            Self::EmptyText => "empty_text",
            Self::GroupMessageNotAddressed => "group_message_not_addressed",
        }
    }
}

/// A callback that passed the rules.
#[derive(Debug)]
pub(crate) struct AdmittedCallback {
    pub(crate) message: NormalizedInboundMessage,
    /// The callback's `robotCode`, for the booleans-only observation. Never
    /// logged or stored as a value.
    pub(crate) robot_code: Option<String>,
}

#[derive(Debug)]
pub(crate) enum CallbackOutcome {
    Admitted(Box<AdmittedCallback>),
    Ignored(IgnoreReason),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawCallback {
    conversation_id: Option<String>,
    conversation_type: Option<String>,
    msg_id: Option<String>,
    sender_staff_id: Option<String>,
    sender_corp_id: Option<String>,
    chatbot_corp_id: Option<String>,
    sender_nick: Option<String>,
    msgtype: Option<String>,
    robot_code: Option<String>,
    /// Kept as a raw value: only a JSON `true` counts as addressed, any other
    /// shape is "not addressed" rather than a parse failure.
    is_in_at_list: Option<serde_json::Value>,
    /// Not read since review #4, but still parsed for its shape: a malformed
    /// value stays a parse error, so no existing refusal is relaxed.
    #[serde(rename = "atUsers")]
    _at_users: Option<Vec<serde::de::IgnoredAny>>,
    text: Option<RawText>,
}

#[derive(Debug, Deserialize)]
struct RawText {
    content: Option<String>,
}

fn parse_error(reason: impl Into<String>) -> ChannelError {
    ChannelError::Parse {
        reason: reason.into(),
    }
}

/// An identifier the host's validators refuse. The validator's error carries
/// a fixed, value-free reason ("must not be empty", "must be at most N
/// bytes"), so it is kept in the returned error; the identifier never is.
fn invalid_identifier(field: &str, error: &ProductAdapterError) -> ChannelError {
    parse_error(format!("{field} is not an acceptable identifier ({error})"))
}
fn present(value: &Option<String>) -> Option<&str> {
    value.as_deref().filter(|text| !text.is_empty())
}

pub(crate) fn normalize_callback(data: &[u8]) -> Result<CallbackOutcome, ChannelError> {
    let raw: RawCallback = serde_json::from_slice(data).map_err(|error| {
        // Only the error category is kept: serde messages can quote values.
        parse_error(format!("malformed callback data ({:?})", error.classify()))
    })?;
    let msg_id = present(&raw.msg_id).ok_or_else(|| parse_error("callback has no msgId"))?;
    let conversation_id = present(&raw.conversation_id)
        .ok_or_else(|| parse_error("callback has no conversationId"))?;
    let conversation_type = match raw.conversation_type.as_deref() {
        Some("1") => DingTalkConversationKind::Dm,
        Some("2") => DingTalkConversationKind::Group,
        Some(_) => return Err(parse_error("callback has an unknown conversationType")),
        None => return Err(parse_error("callback has no conversationType")),
    };
    let (Some(bot_corp), Some(sender_corp)) =
        (present(&raw.chatbot_corp_id), present(&raw.sender_corp_id))
    else {
        return Ok(CallbackOutcome::Ignored(IgnoreReason::CorpIdMissing));
    };
    if bot_corp != sender_corp {
        return Ok(CallbackOutcome::Ignored(IgnoreReason::SenderOutsideBotOrg));
    }
    let Some(staff_id) = present(&raw.sender_staff_id) else {
        return Ok(CallbackOutcome::Ignored(IgnoreReason::SenderStaffIdMissing));
    };
    let addressed_in_group = raw.is_in_at_list == Some(serde_json::Value::Bool(true));
    if conversation_type == DingTalkConversationKind::Group && !addressed_in_group {
        return Ok(CallbackOutcome::Ignored(
            IgnoreReason::GroupMessageNotAddressed,
        ));
    }
    if raw.msgtype.as_deref() != Some("text") {
        return Ok(CallbackOutcome::Ignored(
            IgnoreReason::UnsupportedMessageType,
        ));
    }
    let content = raw
        .text
        .as_ref()
        .and_then(|text| text.content.as_deref())
        .unwrap_or_default();
    if content.len() > MAX_TEXT_BYTES {
        return Err(parse_error("message text exceeds the accepted size"));
    }
    // The text is handed to the model as typed. Whether DingTalk writes the
    // robot's own `@name` into `text.content` is unverified (Task 20), and a
    // leading `@Alice` may be user content, so nothing is removed (review #4).
    let text = content.trim();
    if text.is_empty() {
        return Ok(CallbackOutcome::Ignored(IgnoreReason::EmptyText));
    }
    let actor = ExternalActorRef::new(
        DINGTALK_USER_ACTOR_KIND,
        staff_id,
        raw.sender_nick.as_deref().filter(|nick| {
            ExternalActorRef::new(DINGTALK_USER_ACTOR_KIND, staff_id, Some(*nick)).is_ok()
        }),
    )
    .map_err(|error| invalid_identifier("senderStaffId", &error))?;
    let conversation = ExternalConversationRef::new(None, conversation_id, None, None)
        .map_err(|error| invalid_identifier("conversationId", &error))?;
    let event_id =
        ExternalEventId::new(msg_id).map_err(|error| invalid_identifier("msgId", &error))?;
    let reply_context = DingTalkReplyContext::new(
        conversation_type,
        conversation_id,
        staff_id,
        raw.robot_code.clone().filter(|code| !code.is_empty()),
    )
    .encode()
    .map_err(|error| {
        // Serialization of plain strings fails only on a host fault; keep the
        // error category, never the (identifier-bearing) message.
        tracing::debug!(category = ?error.classify(), "dingtalk reply context failed to serialize");
        parse_error("reply context could not be built")
    })?;
    Ok(CallbackOutcome::Admitted(Box::new(AdmittedCallback {
        message: NormalizedInboundMessage {
            actor,
            conversation,
            event_id,
            text: text.to_string(),
            trigger: match conversation_type {
                DingTalkConversationKind::Dm => ProductTriggerReason::DirectChat,
                DingTalkConversationKind::Group => ProductTriggerReason::BotMention,
            },
            attachments: Vec::new(),
            conversation_context: None,
            reply_context: Some(reply_context),
        },
        robot_code: raw.robot_code.filter(|code| !code.is_empty()),
    })))
}
