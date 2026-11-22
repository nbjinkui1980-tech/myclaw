//! The one send path for notices (and later replies): DingTalk robot OpenAPI
//! calls through host-mediated egress.
//!
//! Verified against the official Go SDK (`alibabacloud-go/dingtalk`,
//! `robot_1_0/client.go`, ADR §14.4):
//! * `POST /v1.0/robot/oToMessages/batchSend` — `{msgKey, msgParam, robotCode,
//!   userIds[]}`; response `{processQueryKey, invalidStaffIdList,
//!   filteredStaffIdList, flowControlledStaffIdList}`.
//! * `POST /v1.0/robot/groupMessages/send` — `{msgKey, msgParam,
//!   openConversationId, robotCode}`; response `{processQueryKey}`.
//! * Header `x-acs-dingtalk-access-token`, injected by the host from the
//!   exchanged token (`[channel.egress.credential_source]`); the adapter only
//!   names [`DINGTALK_ACCESS_TOKEN_HANDLE`].
//!
//! `robotCode` comes from the originating callback (stored in the reply
//! context), not from `dingtalk_client_id`: a `credential_source` target may
//! not also declare `body_credentials` (ADR §14.3). No context or no robot
//! code fails closed as `Permanent` before any request.
//!
//! Evidence: `processQueryKey` is the provider reference. A 2xx without it, a
//! non-JSON 2xx, a 5xx, or a transport failure after the request may have
//! left is `Ambiguous` ("sent_unverified") and is never re-sent here.
//!
//! A 429 or a per-recipient flow-control entry is `Retryable`. That rests on
//! the HTTP convention that 429 means the server did not process the request,
//! and it has NOT been verified against DingTalk's documentation or live
//! traffic (ADR 2026-11-22 revision, plan Task 20 checklist). If DingTalk can
//! rate-limit after accepting a message, a retry posts it twice; the choice
//! was made so that replies during rate limiting are not lost for good. Error
//! reasons are fixed strings: vendor bodies, ids and robot codes never appear
//! in them.
use ironclaw_extension_contracts::auth_prompt::render_channel_auth_prompt;
use ironclaw_extension_contracts::channel_adapter::{
    OutboundEnvelope, OutboundPart, OutboundVisibility, PartDeliveryOutcome,
};
use ironclaw_extension_contracts::tool_adapter::{
    RestrictedEgress, RestrictedEgressError, RestrictedEgressRequest, RestrictedEgressResponse,
};
use ironclaw_host_api::{action::NetworkMethod, ids::SecretHandle};
use serde::Deserialize;
use serde_json::json;

use crate::channel::{DINGTALK_ACCESS_TOKEN_HANDLE, DINGTALK_API_HOST};
use crate::payload::DINGTALK_USER_ACTOR_KIND;
use crate::render::{TEXT_MSG_KEY, chunk_text, render_text_param};
use crate::reply_context::{DingTalkConversationKind, DingTalkReplyContext};

pub(crate) const DM_SEND_PATH: &str = "/v1.0/robot/oToMessages/batchSend";
pub(crate) const GROUP_SEND_PATH: &str = "/v1.0/robot/groupMessages/send";

/// Where one send goes, resolved from the stored reply context.
pub(crate) struct SendTarget {
    kind: DingTalkConversationKind,
    conversation_id: String,
    staff_id: String,
    robot_code: String,
}

impl SendTarget {
    /// Resolve the target from an envelope, failing closed with a fixed
    /// reason.
    pub(crate) fn resolve(
        conversation_id: &str,
        reply_context: Option<&[u8]>,
        visibility: &OutboundVisibility,
    ) -> Result<Self, &'static str> {
        let bytes = reply_context.ok_or("dingtalk delivery has no reply context")?;
        let context = DingTalkReplyContext::decode(bytes).map_err(|error| {
            // The error names a category, never a stored value.
            tracing::debug!(%error, "dingtalk reply context is unusable");
            "dingtalk reply context is unusable"
        })?;
        if context.conversation_id != conversation_id {
            return Err("dingtalk reply context belongs to another conversation");
        }
        let robot_code = context
            .robot_code
            .filter(|code| !code.is_empty())
            .ok_or("dingtalk reply context has no robot code")?;
        let mut target = Self {
            kind: context.kind,
            conversation_id: context.conversation_id,
            staff_id: context.recipient_staff_id,
            robot_code,
        };
        // DingTalk has no ephemeral group post. A notice meant for one member
        // goes to that member's own single chat instead of the room.
        if let OutboundVisibility::EphemeralTo(actor) = visibility {
            if actor.kind() != DINGTALK_USER_ACTOR_KIND {
                return Err("dingtalk ephemeral notice names a foreign actor");
            }
            target.kind = DingTalkConversationKind::Dm;
            target.staff_id = actor.id().to_string();
        }
        Ok(target)
    }

    fn request(
        &self,
        msg_key: &str,
        msg_param: String,
    ) -> Result<RestrictedEgressRequest, &'static str> {
        let (path, body) = match self.kind {
            DingTalkConversationKind::Dm => (
                DM_SEND_PATH,
                json!({
                    "msgKey": msg_key,
                    "msgParam": msg_param,
                    "robotCode": self.robot_code,
                    "userIds": [self.staff_id],
                }),
            ),
            DingTalkConversationKind::Group => (
                GROUP_SEND_PATH,
                json!({
                    "msgKey": msg_key,
                    "msgParam": msg_param,
                    "openConversationId": self.conversation_id,
                    "robotCode": self.robot_code,
                }),
            ),
        };
        let credential = SecretHandle::new(DINGTALK_ACCESS_TOKEN_HANDLE).map_err(|error| {
            tracing::debug!(%error, "dingtalk access token handle is invalid");
            "dingtalk access token handle is invalid"
        })?;
        let body = serde_json::to_vec(&body).map_err(|error| {
            // Only the category: the serde message can quote body values.
            tracing::debug!(category = ?error.classify(), "dingtalk send body could not be built");
            "dingtalk send body could not be built"
        })?;
        Ok(RestrictedEgressRequest {
            method: NetworkMethod::Post,
            url: format!("https://{DINGTALK_API_HOST}{path}"),
            headers: vec![("content-type".to_string(), "application/json".to_string())],
            body: Some(body),
            credential: Some(credential),
            body_credentials: Vec::new(),
        })
    }

    /// Send one already-chunked text message.
    pub(crate) async fn send_text(
        &self,
        egress: &dyn RestrictedEgress,
        chunk: &str,
    ) -> PartDeliveryOutcome {
        let request = match self.request(TEXT_MSG_KEY, render_text_param(chunk)) {
            Ok(request) => request,
            Err(reason) => return permanent(reason),
        };
        match egress.send(request).await {
            Ok(response) => self.classify(&response),
            Err(error) => classify_egress_error(&error),
        }
    }

    fn classify(&self, response: &RestrictedEgressResponse) -> PartDeliveryOutcome {
        match response.status {
            200..=299 => {}
            // Assumed (unverified, see the module docs): DingTalk refused the
            // request before processing it, so a later attempt cannot
            // duplicate a delivered message.
            429 => {
                return PartDeliveryOutcome::Retryable {
                    reason: "dingtalk send returned status 429".to_string(),
                };
            }
            // No evidence either way: the message may already be delivered,
            // so retrying could post it twice.
            500..=599 => {
                return unverified("dingtalk send returned a server error");
            }
            401 => {
                return PartDeliveryOutcome::Unauthorized {
                    reason: "dingtalk rejected the access token".to_string(),
                };
            }
            status => {
                return PartDeliveryOutcome::Permanent {
                    reason: format!("dingtalk rejected the send (status {status})"),
                };
            }
        }
        let Ok(parsed) = serde_json::from_slice::<SendResponse>(&response.body) else {
            return unverified("dingtalk send response was not the expected JSON");
        };
        let names_recipient = |list: &Option<Vec<String>>| {
            self.kind == DingTalkConversationKind::Dm
                && list
                    .as_ref()
                    .is_some_and(|ids| ids.contains(&self.staff_id))
        };
        if names_recipient(&parsed.invalid_staff_id_list)
            || names_recipient(&parsed.filtered_staff_id_list)
        {
            return permanent("dingtalk refused the recipient");
        }
        if names_recipient(&parsed.flow_controlled_staff_id_list) {
            return PartDeliveryOutcome::Retryable {
                reason: "dingtalk flow-controlled the recipient".to_string(),
            };
        }
        match parsed.process_query_key.filter(|key| {
            !key.is_empty()
                && key.len() <= MAX_PROVIDER_REF_BYTES
                && !key.chars().any(char::is_control)
        }) {
            Some(key) => PartDeliveryOutcome::Sent {
                vendor_message_ref: Some(key),
            },
            None => unverified("dingtalk accepted the send without a processQueryKey"),
        }
    }
}

const MAX_PROVIDER_REF_BYTES: usize = 256;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SendResponse {
    process_query_key: Option<String>,
    invalid_staff_id_list: Option<Vec<String>>,
    filtered_staff_id_list: Option<Vec<String>>,
    flow_controlled_staff_id_list: Option<Vec<String>>,
}

fn permanent(reason: &str) -> PartDeliveryOutcome {
    PartDeliveryOutcome::Permanent {
        reason: reason.to_string(),
    }
}

fn unverified(reason: &str) -> PartDeliveryOutcome {
    PartDeliveryOutcome::Ambiguous {
        reason: format!("sent_unverified: {reason}"),
    }
}

fn classify_egress_error(error: &RestrictedEgressError) -> PartDeliveryOutcome {
    match error {
        RestrictedEgressError::Transport { .. } => {
            unverified("the request may have reached dingtalk but no response was read")
        }
        RestrictedEgressError::AuthRequired { .. } => PartDeliveryOutcome::Unauthorized {
            reason: "dingtalk access token is unavailable".to_string(),
        },
        RestrictedEgressError::UndeclaredHost { .. }
        | RestrictedEgressError::UndeclaredMethod
        | RestrictedEgressError::HostOwnedHeader { .. }
        | RestrictedEgressError::UndeclaredCredential { .. }
        | RestrictedEgressError::PolicyDenied
        | RestrictedEgressError::ResponseTooLarge => {
            permanent("dingtalk send refused by egress policy")
        }
    }
}

/// Send every part of an envelope in order, one outcome per message sent;
/// the first non-`Sent` outcome stops the rest (no partial re-send risk).
pub(crate) async fn send_parts(
    envelope: &OutboundEnvelope,
    egress: &dyn RestrictedEgress,
) -> Vec<PartDeliveryOutcome> {
    let target = match SendTarget::resolve(
        envelope.target.conversation.conversation_id(),
        envelope.reply_context.as_deref(),
        &envelope.visibility,
    ) {
        Ok(target) => target,
        Err(reason) => return vec![permanent(reason)],
    };
    let mut outcomes = Vec::new();
    for part in &envelope.parts {
        let text = match part {
            OutboundPart::Text(text) => text.clone(),
            OutboundPart::AuthPrompt {
                view,
                direct_message,
            } => render_channel_auth_prompt(view, *direct_message),
            OutboundPart::File(_) => {
                outcomes.push(permanent("dingtalk channel does not send files"));
                return outcomes;
            }
            OutboundPart::Retract { .. } | OutboundPart::React { .. } => {
                outcomes.push(permanent("dingtalk channel does not retract or react"));
                return outcomes;
            }
        };
        for chunk in chunk_text(&text) {
            let outcome = target.send_text(egress, chunk).await;
            let sent = matches!(outcome, PartDeliveryOutcome::Sent { .. });
            outcomes.push(outcome);
            if !sent {
                return outcomes;
            }
        }
    }
    outcomes
}

#[cfg(test)]
#[path = "tests/delivery.rs"]
mod tests;
