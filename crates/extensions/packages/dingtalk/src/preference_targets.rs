//! DingTalk preference targets for generic outbound delivery.
//!
//! Grammar (ADR 14.7), parsed strictly and never trusted:
//!
//! * `dm:<staffId>:<conversationId>`: a personal single chat. The
//!   conversation id is part of the ref because delivery reads the stored
//!   reply context (which carries the `robotCode`) by the conversation's
//!   fingerprint; a ref naming only the staff id would find no context.
//! * `group:<conversationId>`: a group the robot is in. Only the codec exists;
//!   the generic provider offers no shared-conversation targets, so nothing
//!   produces or resolves a group target yet (plan follow-up).
//!
//! Every segment is checked for prefix, segment count, character set and
//! length. No re-encode comparison is needed, and none is made: the character
//! sets exclude the `:` delimiter and the empty string, so `split(':')` and
//! `join(':')` are lossless and each valid ref has exactly one decoded form
//! (unlike Telegram's numeric ids, where `+42`, `042` and `42` collapse to one
//! integer). If a segment grammar is ever widened to admit `:` or an empty
//! segment, add a re-encode comparison in the same change.
//! The authorization policy (a caller pushes only to their own single chat)
//! is enforced by the generic provider, which offers only the caller's own
//! provisioned DM target.
use ironclaw_extension_contracts::external::ExternalConversationRef;
use ironclaw_extension_contracts::preference_target::{
    PreferenceTargetCodec, PreferenceTargetEncodeRequest,
};
use ironclaw_host_api::turn::ReplyTargetBindingRef;

const DM_PREFIX: &str = "dm";
const GROUP_PREFIX: &str = "group";
const MAX_STAFF_ID_BYTES: usize = 64;
const MAX_CONVERSATION_ID_BYTES: usize = 160;

/// A staff id: ASCII letters, digits, `_`, `-`, `.`.
fn valid_staff_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_STAFF_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

/// A conversation id: base64-like ASCII (letters, digits, `+ / = _ - .`). No
/// `:` (the delimiter), no whitespace, no control or non-ASCII characters.
fn valid_conversation_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_CONVERSATION_ID_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=' | b'_' | b'-' | b'.')
        })
}

#[derive(Debug, PartialEq, Eq)]
enum DecodedTarget<'a> {
    Dm {
        staff_id: &'a str,
        conversation_id: &'a str,
    },
    Group {
        conversation_id: &'a str,
    },
}

fn decode(target: &ReplyTargetBindingRef) -> Option<DecodedTarget<'_>> {
    let mut segments = target.as_str().split(':');
    let decoded = match segments.next()? {
        DM_PREFIX => {
            let staff_id = segments.next()?;
            let conversation_id = segments.next()?;
            (valid_staff_id(staff_id) && valid_conversation_id(conversation_id)).then_some(
                DecodedTarget::Dm {
                    staff_id,
                    conversation_id,
                },
            )?
        }
        GROUP_PREFIX => {
            let conversation_id = segments.next()?;
            valid_conversation_id(conversation_id)
                .then_some(DecodedTarget::Group { conversation_id })?
        }
        _ => return None,
    };
    // Any further segment makes the ref malformed.
    segments.next().is_none().then_some(decoded)
}

fn plain_conversation(conversation: &ExternalConversationRef) -> Option<&str> {
    // DingTalk conversations carry neither a space nor a topic.
    (conversation.space_id().is_none() && conversation.topic_id().is_none())
        .then(|| conversation.conversation_id())
}

/// DingTalk's vendor codec for stored outbound preference targets.
#[derive(Debug, Clone, Copy, Default)]
pub struct DingTalkPreferenceTargetCodec;

impl PreferenceTargetCodec for DingTalkPreferenceTargetCodec {
    fn conversation_for_target(
        &self,
        target: &ReplyTargetBindingRef,
    ) -> Option<ExternalConversationRef> {
        let conversation_id = match decode(target)? {
            DecodedTarget::Dm {
                conversation_id, ..
            }
            | DecodedTarget::Group { conversation_id } => conversation_id,
        };
        ExternalConversationRef::new(None, conversation_id, None, None).ok()
    }

    fn is_personal_direct_message(&self, target: &ReplyTargetBindingRef) -> bool {
        matches!(decode(target), Some(DecodedTarget::Dm { .. }))
    }

    fn direct_message_actor_for_target(&self, target: &ReplyTargetBindingRef) -> Option<String> {
        match decode(target)? {
            DecodedTarget::Dm { staff_id, .. } => Some(staff_id.to_string()),
            DecodedTarget::Group { .. } => None,
        }
    }

    fn encode_shared_conversation_target(
        &self,
        request: PreferenceTargetEncodeRequest<'_>,
    ) -> Option<ReplyTargetBindingRef> {
        let conversation_id = plain_conversation(request.conversation)?;
        if !valid_conversation_id(conversation_id) {
            return None;
        }
        ReplyTargetBindingRef::new(format!("{GROUP_PREFIX}:{conversation_id}")).ok()
    }

    fn encode_personal_direct_message_target(
        &self,
        request: PreferenceTargetEncodeRequest<'_>,
        external_actor_id: &str,
    ) -> Option<ReplyTargetBindingRef> {
        let conversation_id = plain_conversation(request.conversation)?;
        if !valid_staff_id(external_actor_id) || !valid_conversation_id(conversation_id) {
            return None;
        }
        ReplyTargetBindingRef::new(format!("{DM_PREFIX}:{external_actor_id}:{conversation_id}"))
            .ok()
    }
}

#[cfg(test)]
#[path = "tests/preference_targets.rs"]
mod tests;
