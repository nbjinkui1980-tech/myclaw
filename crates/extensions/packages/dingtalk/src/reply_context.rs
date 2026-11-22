//! The reply context ingress stamps on every message and delivery reads back.
//!
//! Opaque to the host (≤ 4 KiB). It carries only what routing a reply needs:
//! whether the conversation is a single chat or a group, the vendor
//! conversation id, and the staff id of the person to answer. It holds no
//! message text and no credentials.
use serde::{Deserialize, Serialize};

const CONTEXT_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DingTalkConversationKind {
    /// A single chat with the bot.
    Dm,
    /// A group chat the bot was @mentioned in.
    Group,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DingTalkReplyContext {
    kind_version: u8,
    pub(crate) kind: DingTalkConversationKind,
    pub(crate) conversation_id: String,
    pub(crate) recipient_staff_id: String,
    /// The callback's `robotCode`: the robot every send names. Not a secret,
    /// but never logged.
    pub(crate) robot_code: Option<String>,
}

/// A stored reply context that cannot be used. The reason is a fixed label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ReplyContextError {
    /// The serde error category only: its message may quote stored values.
    #[error("reply context is not valid JSON of the expected shape ({0:?})")]
    Malformed(serde_json::error::Category),
    #[error("reply context version is not supported")]
    UnsupportedVersion,
}

impl DingTalkReplyContext {
    pub(crate) fn new(
        kind: DingTalkConversationKind,
        conversation_id: impl Into<String>,
        recipient_staff_id: impl Into<String>,
        robot_code: Option<String>,
    ) -> Self {
        Self {
            kind_version: CONTEXT_VERSION,
            kind,
            conversation_id: conversation_id.into(),
            recipient_staff_id: recipient_staff_id.into(),
            robot_code,
        }
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, ReplyContextError> {
        let context: Self = serde_json::from_slice(bytes)
            .map_err(|error| ReplyContextError::Malformed(error.classify()))?;
        if context.kind_version != CONTEXT_VERSION {
            return Err(ReplyContextError::UnsupportedVersion);
        }
        Ok(context)
    }
}
