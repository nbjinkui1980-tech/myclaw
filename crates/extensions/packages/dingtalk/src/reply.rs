//! The DingTalk reply half: a [`ReplySink`] at `message` cadence
//! (`[channel.reply] transport = "message"`).
//!
//! The host asks a `message` sink to reconcile at exactly one point, the
//! terminal materialization. This sink renders the terminal document through
//! the same send path `deliver` uses ([`crate::send::send_parts`]): the answer
//! text split on character boundaries, or one short line for a failed or
//! cancelled run. Every other reconcile point is a no-op that hands the
//! incoming checkpoint back.
//!
//! Idempotency rides the checkpoint, never the revision number. A terminal
//! render DingTalk accepted in full is recorded as
//! `{ "terminal_applied": true, "message_refs": [ ... ] }` (the
//! `processQueryKey` of each accepted message) and a repeated terminal
//! reconcile carrying it answers `Applied` without a provider call. A partial
//! render records `terminal_applied: false` with the accepted refs and stays
//! `Permanent` afterwards: the send API has no idempotency key and no
//! read-back, so resuming would duplicate what the user already saw.
//!
//! Attachments are not sent: DingTalk file sending is out of scope for this
//! channel, so materialized attachments are dropped from the terminal render
//! (the answer text still ships).
use async_trait::async_trait;
use ironclaw_extension_contracts::channel_adapter::{
    ChannelError, OutboundEnvelope, OutboundPart, OutboundTarget, OutboundVisibility,
    PartDeliveryOutcome,
};
use ironclaw_extension_contracts::reply::{
    ReplyOutcome, ReplyOutcomeReason, ReplyProviderRef, ReplyReconcilePoint, ReplyReconcileRequest,
    ReplySink, ReplySinkCheckpoint, ReplySinkEvidence, ReplySinkOutcome, ReplySinkReport,
};
use ironclaw_extension_contracts::tool_adapter::RestrictedEgress;

use crate::channel::DingTalkChannelAdapter;

/// The checkpoint schema this sink writes and understands. A checkpoint of any
/// other version is ignored (see [`DingTalkReplyCheckpoint::decode`]).
pub(crate) const DINGTALK_REPLY_CHECKPOINT_VERSION: u32 = 1;

/// The one-line terminal message for a cancelled reply. Why the run stopped
/// stays in the web app.
pub(crate) const DINGTALK_REPLY_CANCELLED_TEXT: &str = "This reply was stopped before it finished.";

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct DingTalkReplyCheckpoint {
    /// True once the whole terminal render was accepted. False records a
    /// partial render: `message_refs` exist provider-side, the rest never
    /// shipped.
    terminal_applied: bool,
    /// `processQueryKey` of each accepted message, in send order.
    #[serde(default)]
    message_refs: Vec<String>,
}

impl DingTalkReplyCheckpoint {
    /// The previous checkpoint, or `None` when there is nothing this sink may
    /// act on. A checkpoint of another version, or one that does not decode,
    /// is deliberately "not applied": between a possible duplicate answer
    /// (visible, recoverable) and a never-delivered one (silent), the seam
    /// prefers the former.
    fn decode(checkpoint: Option<&ReplySinkCheckpoint>) -> Option<Self> {
        let checkpoint = checkpoint?;
        if checkpoint.version() != DINGTALK_REPLY_CHECKPOINT_VERSION {
            tracing::debug!(
                version = checkpoint.version(),
                "ignoring a dingtalk reply checkpoint of an unknown version"
            );
            return None;
        }
        match serde_json::from_str::<Self>(checkpoint.payload()) {
            Ok(decoded) => Some(decoded),
            Err(error) => {
                tracing::debug!(%error, "ignoring an undecodable dingtalk reply checkpoint");
                None
            }
        }
    }

    fn encode(&self) -> Result<ReplySinkCheckpoint, ChannelError> {
        let payload = serde_json::to_string(self).map_err(|error| ChannelError::Render {
            reason: format!("dingtalk reply checkpoint failed to serialize: {error}"),
        })?;
        ReplySinkCheckpoint::new(DINGTALK_REPLY_CHECKPOINT_VERSION, payload).map_err(|error| {
            ChannelError::Render {
                reason: format!("dingtalk reply checkpoint exceeds the host bound: {error}"),
            }
        })
    }

    /// The accepted refs as sink evidence. Never read back: no call fetches a
    /// sent message, so `read_back_verified` stays false.
    fn evidence(&self) -> ReplySinkEvidence {
        let mut evidence = ReplySinkEvidence::default();
        for reference in &self.message_refs {
            let reference = match ReplyProviderRef::new(reference.clone()) {
                Ok(reference) => reference,
                Err(error) => {
                    tracing::debug!(%error, "skipping a processQueryKey that is not a valid provider ref");
                    continue;
                }
            };
            if let Err(error) = evidence.provider_refs.push(reference) {
                // Past the host's per-report bound; the checkpoint still
                // holds every ref.
                tracing::debug!(%error, "dingtalk reply evidence reached the provider-ref bound");
                break;
            }
        }
        evidence
    }
}

#[async_trait]
impl ReplySink for DingTalkChannelAdapter {
    async fn reconcile(
        &self,
        request: ReplyReconcileRequest,
        egress: &dyn RestrictedEgress,
    ) -> Result<ReplySinkReport, ChannelError> {
        if !matches!(request.point, ReplyReconcilePoint::Terminal) {
            return Ok(ReplySinkReport::applied(
                request.checkpoint,
                ReplySinkEvidence::default(),
            ));
        }

        if let Some(prior) = DingTalkReplyCheckpoint::decode(request.checkpoint.as_ref()) {
            if prior.terminal_applied {
                return Ok(ReplySinkReport::applied(
                    Some(prior.encode()?),
                    prior.evidence(),
                ));
            }
            if !prior.message_refs.is_empty() {
                return Ok(ReplySinkReport {
                    outcome: ReplySinkOutcome::Permanent {
                        reason: ReplyOutcomeReason::new(format!(
                            "an earlier terminal render was partially accepted ({} message(s) \
                             already accepted); resending would duplicate them",
                            prior.message_refs.len()
                        )),
                    },
                    checkpoint: Some(prior.encode()?),
                    evidence: prior.evidence(),
                });
            }
        }

        let document = &request.revision.document;
        let Some(outcome) = document.outcome.as_ref() else {
            return Err(ChannelError::Render {
                reason: "terminal reply reconcile carries no terminal outcome".to_string(),
            });
        };
        let Some(conversation) = request.target.conversation.clone() else {
            return Ok(ReplySinkReport {
                outcome: ReplySinkOutcome::Permanent {
                    reason: ReplyOutcomeReason::new("reply target names no vendor conversation"),
                },
                checkpoint: None,
                evidence: ReplySinkEvidence::default(),
            });
        };

        let Some(text) = terminal_text(outcome, document.answer.text.as_str()) else {
            // A completed run with nothing to say: the desired state is
            // already reflected, and DingTalk rejects empty text.
            let checkpoint = DingTalkReplyCheckpoint {
                terminal_applied: true,
                message_refs: Vec::new(),
            };
            return Ok(ReplySinkReport::applied(
                Some(checkpoint.encode()?),
                ReplySinkEvidence::default(),
            ));
        };
        if !request.materialized_attachments.is_empty() {
            tracing::debug!(
                attachments = request.materialized_attachments.len(),
                "dingtalk reply drops attachments; the channel does not send files"
            );
        }

        let envelope = OutboundEnvelope {
            target: OutboundTarget {
                conversation,
                thread_anchor: None,
            },
            parts: vec![OutboundPart::Text(text)],
            reply_context: request
                .reply_context
                .map(|context| context.as_bytes().to_vec()),
            registrations: Vec::new(),
            visibility: OutboundVisibility::Public,
        };
        reply_report(crate::send::send_parts(&envelope, egress).await)
    }
}

/// The text a terminal document ships: the answer of a completed run (none
/// when blank), one line for a failed or cancelled run.
fn terminal_text(outcome: &ReplyOutcome, answer: &str) -> Option<String> {
    match outcome {
        ReplyOutcome::Completed => (!answer.trim().is_empty()).then(|| answer.to_string()),
        ReplyOutcome::Failed { summary } => Some(summary.as_str().to_string()),
        ReplyOutcome::Cancelled => Some(DINGTALK_REPLY_CANCELLED_TEXT.to_string()),
    }
}

/// Fold per-message send outcomes into one sink report.
///
/// Every message accepted ⇒ `Applied`. The first one not accepted decides the
/// outcome, except a retryable failure after at least one accepted message,
/// which is `Permanent`: retrying would re-send the accepted messages.
/// Accepted refs are checkpointed whenever there are any.
fn reply_report(parts: Vec<PartDeliveryOutcome>) -> Result<ReplySinkReport, ChannelError> {
    let first_failure = parts
        .iter()
        .position(|part| !matches!(part, PartDeliveryOutcome::Sent { .. }));
    let accepted_parts = first_failure.unwrap_or(parts.len());
    let message_refs: Vec<String> = parts
        .iter()
        .take(accepted_parts)
        .filter_map(|part| match part {
            PartDeliveryOutcome::Sent { vendor_message_ref } => vendor_message_ref.clone(),
            _ => None,
        })
        .collect();
    let outcome = match first_failure.and_then(|index| parts.get(index)) {
        None | Some(PartDeliveryOutcome::Sent { .. }) => ReplySinkOutcome::Applied,
        Some(PartDeliveryOutcome::Retryable { reason }) if accepted_parts > 0 => {
            ReplySinkOutcome::Permanent {
                reason: ReplyOutcomeReason::new(format!(
                    "{accepted_parts} message(s) already accepted before a retryable failure \
                     ({reason}); resending would duplicate them"
                )),
            }
        }
        Some(PartDeliveryOutcome::Retryable { reason }) => ReplySinkOutcome::Retryable {
            reason: ReplyOutcomeReason::new(reason),
            retry_after: None,
        },
        Some(PartDeliveryOutcome::Ambiguous { reason }) => ReplySinkOutcome::Ambiguous {
            reason: ReplyOutcomeReason::new(reason),
        },
        Some(PartDeliveryOutcome::Permanent { reason }) => ReplySinkOutcome::Permanent {
            reason: ReplyOutcomeReason::new(reason),
        },
        Some(PartDeliveryOutcome::Unauthorized { reason }) => ReplySinkOutcome::Unauthorized {
            reason: ReplyOutcomeReason::new(reason),
        },
    };
    let checkpoint = DingTalkReplyCheckpoint {
        terminal_applied: outcome.is_applied(),
        message_refs,
    };
    let evidence = checkpoint.evidence();
    // Nothing accepted means nothing to remember.
    let checkpoint = (accepted_parts > 0)
        .then(|| checkpoint.encode())
        .transpose()?;
    Ok(ReplySinkReport {
        outcome,
        checkpoint,
        evidence,
    })
}

#[cfg(test)]
#[path = "tests/reply.rs"]
mod tests;
