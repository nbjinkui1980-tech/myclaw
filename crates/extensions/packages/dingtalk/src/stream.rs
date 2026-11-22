//! Frame control for DingTalk Stream mode: pure functions over one frame.
//!
//! Frame shape (ADR §8 items 7a, 13, from the official Python SDK): JSON with
//! `type` (`SYSTEM`/`EVENT`/`CALLBACK`), `headers{messageId, topic, ..}` and a
//! `data` JSON string. Every frame is answered with
//! `{code, headers{messageId, contentType}, message, data}`.
//!
//! Unverified (Task 20): the `ack` for a bot callback carries `data = "{}"`
//! (the SDK serialises its own handler result there); whether DingTalk reads
//! it is unknown. A SYSTEM `ping` topic does not exist in the SDK source, so
//! all non-`disconnect` SYSTEM frames are acknowledged the way the SDK does.
use ironclaw_extension_contracts::channel_adapter::{
    ChannelError, ChannelStreamControl, StreamFrameDecision,
};
use serde::Deserialize;
use serde_json::json;

/// The robot-message callback topic subscribed at connect time.
pub(crate) const DINGTALK_BOT_CALLBACK_TOPIC: &str = "/v1.0/im/bot/messages/get";
const DISCONNECT_TOPIC: &str = "disconnect";
const MAX_MESSAGE_ID_BYTES: usize = 256;
const MAX_SESSION_KEY_BYTES: usize = 256;

/// DingTalk's frame protocol half.
#[derive(Debug, Default)]
pub struct DingTalkStreamControl;

#[derive(Deserialize)]
struct RawFrame {
    #[serde(rename = "type")]
    kind: Option<String>,
    headers: Option<RawHeaders>,
    data: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct RawHeaders {
    #[serde(rename = "messageId")]
    message_id: Option<String>,
    topic: Option<String>,
}

#[derive(Deserialize)]
struct SessionProbe {
    #[serde(rename = "conversationId")]
    conversation_id: Option<String>,
}

fn parse_error(reason: &str) -> ChannelError {
    ChannelError::Parse {
        reason: reason.to_string(),
    }
}

fn ack(message_id: &str) -> Result<Vec<u8>, ChannelError> {
    serde_json::to_vec(&json!({
        "code": 200,
        "headers": {"messageId": message_id, "contentType": "application/json"},
        "message": "OK",
        "data": "{}",
    }))
    .map_err(|error| {
        tracing::debug!(category = ?error.classify(), "dingtalk ack could not be built");
        parse_error("ack could not be built")
    })
}

impl ChannelStreamControl for DingTalkStreamControl {
    fn decode(&self, frame: &[u8]) -> Result<StreamFrameDecision, ChannelError> {
        let raw: RawFrame = serde_json::from_slice(frame)
            .map_err(|error| parse_error(&format!("malformed frame ({:?})", error.classify())))?;
        let headers = raw
            .headers
            .ok_or_else(|| parse_error("frame has no headers"))?;
        let message_id = headers
            .message_id
            .filter(|id| {
                !id.is_empty()
                    && id.len() <= MAX_MESSAGE_ID_BYTES
                    && !id.chars().any(char::is_control)
            })
            .ok_or_else(|| parse_error("frame has no usable messageId"))?;
        let topic = headers.topic.unwrap_or_default();
        match raw.kind.as_deref() {
            Some("SYSTEM") if topic == DISCONNECT_TOPIC => {
                Ok(StreamFrameDecision::AckAndReconnect(ack(&message_id)?))
            }
            Some("SYSTEM") => Ok(StreamFrameDecision::Ack(ack(&message_id)?)),
            Some("CALLBACK") if topic == DINGTALK_BOT_CALLBACK_TOPIC => {
                let Some(serde_json::Value::String(data)) = raw.data else {
                    return Err(parse_error("callback frame data is not a string"));
                };
                Ok(StreamFrameDecision::Deliver {
                    data: data.into_bytes(),
                    ack: ack(&message_id)?,
                })
            }
            // Unknown callback topics, EVENT frames (never subscribed) and
            // unknown frame types: acknowledged so DingTalk does not redeliver.
            _ => Ok(StreamFrameDecision::Drop {
                ack: Some(ack(&message_id)?),
            }),
        }
    }

    fn session_key(&self, data: &[u8]) -> Option<String> {
        let probe: SessionProbe = serde_json::from_slice(data).ok()?;
        probe.conversation_id.filter(|id| {
            !id.is_empty() && id.len() <= MAX_SESSION_KEY_BYTES && !id.chars().any(char::is_control)
        })
    }
}
