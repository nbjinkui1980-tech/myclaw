//! Transport-neutral admission pipeline shared by every inbound transport.
//!
//! Everything after the transport has verified the request and built the
//! [`VerifiedInbound`] lives here: the adapter `receive` call (panic-isolated,
//! error-classified), `InboundOutcome` handling, `message.validate()`,
//! `reply_context` storage, durable `sink.admit`, and provider-batch staging
//! and merging. Callers map the returned [`AdmissionDisposition`] onto their
//! own wire format (the webhook router maps it to HTTP responses).
use async_trait::async_trait;
use futures::FutureExt as _;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use chrono::Utc;
use ironclaw_extension_contracts::channel_adapter::{
    ChannelError, ChannelIngress, ImmediateResponse, InboundBatchFragment, InboundOutcome,
    NormalizedInboundMessage, VerifiedInbound,
};
use ironclaw_extension_contracts::tool_adapter::{
    RestrictedEgress, RestrictedEgressError, RestrictedEgressRequest, RestrictedEgressResponse,
};
use ironclaw_extension_registry::ResolvedExtensionManifest;
use sha2::{Digest, Sha256};

use crate::deployment_channels::DeploymentChannelRegistry;
use crate::egress::{ChannelEgressTransport, DeclaredChannelEgress, PolicyEnforcedChannelEgress};
use crate::inbound_batches::{
    ClaimedInboundBatch, InboundBatchKey, InboundBatchSchedule, InboundBatchStageOutcome,
    InboundBatchStageRequest,
};
use crate::lifecycle::SnapshotWatch;

use super::router::{
    ExtensionIngressRouterDeps, InboundAdmission, InboundAdmissionAck, IngressPortError,
    ReplyContextKey,
};

/// The transport-neutral result of the shared admission pipeline.
#[derive(Debug)]
pub enum AdmissionDisposition {
    /// Every message was durably admitted (duplicates count as admitted).
    Admitted,
    /// An authenticated no-op: nothing to admit.
    Ignored,
    /// A bounds-checked immediate response from the adapter.
    Respond(ImmediateResponse),
    /// A provider-batch fragment was durably staged.
    BatchStaged,
    /// A transient failure; the vendor's redelivery may succeed.
    Transient,
    /// A deterministic failure; redelivery would only re-fail, so the update
    /// is acknowledged and dropped (already warn-logged).
    DeterministicDiscard,
    /// The adapter violated a host bound (immediate response out of range).
    HostBoundViolation,
}

/// Invoke the adapter on an already verified request, with panic isolation
/// and transient-versus-deterministic error classification. `Err` carries the
/// disposition for a failed call.
pub(super) async fn receive_verified(
    channel: &dyn ChannelIngress,
    inbound: VerifiedInbound<'_>,
    egress: &dyn RestrictedEgress,
) -> Result<InboundOutcome, AdmissionDisposition> {
    let extension_id = inbound.extension_id;
    // `receive` is async now, so panic isolation wraps the FUTURE
    // rather than the call: a panic inside an awaited adapter parse
    // must still be a 503 for this request and never unwind the
    // ingress task. `AssertUnwindSafe` is sound here for the same
    // reason it was before — the adapter holds no host state that a
    // partial parse could leave observably broken.
    match AssertUnwindSafe(channel.receive(inbound, egress))
        .catch_unwind()
        .await
    {
        Ok(Ok(outcome)) => Ok(outcome),
        // Transient failures earn a 5xx so the vendor's redelivery
        // can succeed later. Every other adapter failure is
        // deterministic — redelivery replays the same bytes into the
        // same failure, and vendors with ordered webhook queues hold
        // every later update in the conversation behind a non-2xx'd
        // one — so the host acks and discards instead.
        Ok(Err(error)) if channel_error_is_transient(&error) => {
            tracing::debug!(
                extension_id = %extension_id,
                error = %error,
                "channel adapter failed transiently; vendor redelivery may succeed"
            );
            Err(AdmissionDisposition::Transient)
        }
        Ok(Err(error)) => {
            tracing::warn!(
                extension_id = %extension_id,
                error = %error,
                "acknowledging and discarding verified inbound update after a deterministic adapter failure"
            );
            Err(AdmissionDisposition::DeterministicDiscard)
        }
        Err(_) => {
            tracing::warn!(
                extension_id = %extension_id,
                "channel adapter panicked on verified inbound request"
            );
            Err(AdmissionDisposition::Transient)
        }
    }
}

/// Outcome handling. Admitted only after the outcome's durable boundary:
/// admission for ordinary messages, staging for provider batches.
/// `binding_fingerprint` is evaluated only for batch fragments.
pub(super) async fn dispose_outcome(
    processor: &InboundBatchProcessor,
    extension_id: &str,
    installation_id: &str,
    outcome: InboundOutcome,
    binding_fingerprint: impl FnOnce() -> Result<String, serde_json::Error>,
) -> AdmissionDisposition {
    match outcome {
        InboundOutcome::Ignore => AdmissionDisposition::Ignored,
        InboundOutcome::Respond(response) => {
            if response.validate().is_err() || !(200..=299).contains(&response.status) {
                tracing::warn!(
                    extension_id,
                    "channel adapter immediate response violated host bounds"
                );
                return AdmissionDisposition::HostBoundViolation;
            }
            AdmissionDisposition::Respond(response)
        }
        InboundOutcome::Messages(messages) => {
            admit_messages(&processor.deps, extension_id, installation_id, messages).await
        }
        InboundOutcome::BatchFragment(fragment) => {
            let binding_fingerprint = match binding_fingerprint() {
                Ok(fingerprint) => fingerprint,
                Err(error) => {
                    tracing::debug!(
                        extension_id,
                        error = %error,
                        "channel adapter binding fingerprint is unavailable"
                    );
                    return AdmissionDisposition::Transient;
                }
            };
            processor
                .stage_and_schedule(
                    extension_id,
                    installation_id,
                    binding_fingerprint,
                    *fragment,
                )
                .await
        }
    }
}

/// Transient failures may succeed on vendor redelivery; everything else is
/// deterministic and is acknowledged-and-discarded by ingress (see
/// [`AdmissionDisposition::DeterministicDiscard`]).
pub(super) fn channel_error_is_transient(error: &ChannelError) -> bool {
    matches!(
        error,
        ChannelError::Configuration { .. }
            | ChannelError::VendorWiring { .. }
            | ChannelError::AttachmentTransfer {
                retryable: true,
                ..
            }
    )
}

pub(super) async fn admit_messages(
    deps: &ExtensionIngressRouterDeps,
    extension_id: &str,
    installation_id: &str,
    messages: Vec<NormalizedInboundMessage>,
) -> AdmissionDisposition {
    if messages.is_empty() {
        return AdmissionDisposition::Ignored;
    }
    for message in messages {
        if let Err(error) = message.validate() {
            tracing::warn!(
                extension_id,
                error = %error,
                "acknowledging and discarding an out-of-bounds normalized message"
            );
            return AdmissionDisposition::DeterministicDiscard;
        }
        // reply_context is stored host-side, keyed to the conversation
        // source binding, before the admission commit — the delivery
        // coordinator reads it back for source-route replies.
        if let Some(context) = &message.reply_context {
            let key = ReplyContextKey {
                extension_id: extension_id.to_string(),
                installation_id: installation_id.to_string(),
                conversation: message.conversation.conversation_fingerprint(),
            };
            if let Err(error) = deps.reply_context.put(key, context.clone()).await {
                tracing::debug!(
                    extension_id,
                    error = %error,
                    "reply context store unavailable"
                );
                return AdmissionDisposition::Transient;
            }
        }
        // Durable dedupe + admission commit — before any ordinary-message
        // webhook 2xx and before a staged batch is marked complete.
        match deps
            .sink
            .admit(InboundAdmission {
                extension_id: extension_id.to_string(),
                installation_id: installation_id.to_string(),
                message,
            })
            .await
        {
            Ok(InboundAdmissionAck::Accepted) | Ok(InboundAdmissionAck::Duplicate) => {}
            Err(error) if error.retryable => {
                tracing::debug!(
                    extension_id,
                    error = %error,
                    "inbound admission failed retryably"
                );
                return AdmissionDisposition::Transient;
            }
            Err(error) => {
                // A permanent admission rejection is deterministic: the same
                // message re-fails on every redelivery, so a non-2xx would
                // wedge ordered vendors behind it. Acking drops a verified
                // user message — the loudest non-fatal log level it gets.
                tracing::warn!(
                    extension_id,
                    error = %error,
                    "acknowledging and discarding a message the admission sink permanently rejected"
                );
                return AdmissionDisposition::DeterministicDiscard;
            }
        }
    }
    AdmissionDisposition::Admitted
}

#[derive(Clone)]
pub(super) struct InboundBatchProcessor {
    pub(super) watch: SnapshotWatch,
    pub(super) deployment_channels: Arc<DeploymentChannelRegistry>,
    pub(super) deps: ExtensionIngressRouterDeps,
    pub(super) recovery_started: Arc<AtomicBool>,
    pub(super) admission_deadline: Duration,
}

impl InboundBatchProcessor {
    pub(super) async fn stage_and_schedule(
        &self,
        extension_id: &str,
        installation_id: &str,
        binding_fingerprint: String,
        fragment: InboundBatchFragment,
    ) -> AdmissionDisposition {
        if let Err(error) = fragment.validate() {
            tracing::warn!(
                extension_id,
                error = %error,
                "acknowledging and discarding an inbound batch fragment with invalid metadata"
            );
            return AdmissionDisposition::DeterministicDiscard;
        }
        let request = InboundBatchStageRequest {
            key: InboundBatchKey {
                extension_id: extension_id.to_string(),
                installation_id: installation_id.to_string(),
                batch_key: fragment.batch_key.clone(),
            },
            binding_fingerprint,
            fragment,
            staged_at: Utc::now(),
        };
        match self.deps.inbound_batches.stage(request).await {
            Ok(InboundBatchStageOutcome::Pending(schedule)) => {
                self.spawn_schedule(schedule);
                // The fragment itself is now durable. Providers that serialize
                // a logical batch may send the next webhook immediately.
                AdmissionDisposition::BatchStaged
            }
            Ok(InboundBatchStageOutcome::AlreadyCompleted) => AdmissionDisposition::BatchStaged,
            Ok(InboundBatchStageOutcome::Rejected) => {
                // The batch is durably tombstoned; redelivering the fragment
                // can only re-fail, so ack it away.
                tracing::warn!(
                    extension_id,
                    "acknowledging and discarding a fragment the staged batch rejected"
                );
                AdmissionDisposition::DeterministicDiscard
            }
            Err(error) if error.retryable => {
                tracing::debug!(
                    extension_id,
                    error = %error,
                    "inbound batch staging failed retryably"
                );
                AdmissionDisposition::Transient
            }
            Err(error) => {
                tracing::warn!(
                    extension_id,
                    error = %error,
                    "acknowledging and discarding a fragment inbound batch staging permanently rejected"
                );
                AdmissionDisposition::DeterministicDiscard
            }
        }
    }

    fn spawn_schedule(&self, schedule: InboundBatchSchedule) {
        let processor = self.clone();
        tokio::spawn(async move {
            processor.process_schedule(schedule).await;
        });
    }

    async fn process_schedule(&self, mut schedule: InboundBatchSchedule) {
        let mut retry_attempt = 0u32;
        loop {
            tokio::time::sleep(delay_until(schedule.due_at)).await;
            let claim = match self
                .deps
                .inbound_batches
                .claim_due(&schedule, Utc::now())
                .await
            {
                Ok(Some(claim)) => claim,
                Ok(None) => return,
                Err(error) => {
                    tracing::debug!(
                        extension_id = %schedule.key.extension_id,
                        error = %error,
                        "inbound batch claim is temporarily unavailable"
                    );
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };
            let response = match merge_batch_fragments(claim.fragments.clone()) {
                Ok(Some(message)) => match tokio::time::timeout(
                    self.admission_deadline,
                    admit_messages(
                        &self.deps,
                        &claim.schedule.key.extension_id,
                        &claim.schedule.key.installation_id,
                        vec![message],
                    ),
                )
                .await
                {
                    Ok(response) => response,
                    Err(_) => {
                        tracing::debug!(
                            extension_id = %claim.schedule.key.extension_id,
                            "inbound batch admission exceeded its bounded deadline"
                        );
                        AdmissionDisposition::Transient
                    }
                },
                Ok(None) => AdmissionDisposition::Ignored,
                Err(error) => {
                    tracing::debug!(
                        extension_id = %claim.schedule.key.extension_id,
                        error = %error,
                        "durably staged inbound batch fragments are inconsistent"
                    );
                    self.finish_claim(&claim, false).await;
                    return;
                }
            };
            match response {
                // An acknowledged discard is terminal but not a completion:
                // the merged message was consciously dropped, so the batch
                // record keeps the truthful `rejected` tombstone.
                AdmissionDisposition::DeterministicDiscard => {
                    self.finish_claim(&claim, false).await;
                    return;
                }
                AdmissionDisposition::Admitted
                | AdmissionDisposition::Ignored
                | AdmissionDisposition::BatchStaged => {
                    self.finish_claim(&claim, true).await;
                    return;
                }
                AdmissionDisposition::Respond(_) | AdmissionDisposition::HostBoundViolation => {
                    self.finish_claim(&claim, false).await;
                    return;
                }
                AdmissionDisposition::Transient => {}
            }

            retry_attempt = retry_attempt.saturating_add(1);
            let retry_after = Duration::from_secs(1u64 << retry_attempt.min(5));
            match self
                .deps
                .inbound_batches
                .release(&claim, Utc::now(), retry_after)
                .await
            {
                Ok(Some(next)) => schedule = next,
                Ok(None) => return,
                Err(error) => {
                    tracing::debug!(
                        extension_id = %claim.schedule.key.extension_id,
                        error = %error,
                        "inbound batch retry lease could not be released"
                    );
                    // The recovery sweep can reclaim this claim after the
                    // durable lease expires.
                    return;
                }
            }
        }
    }

    async fn finish_claim(&self, claim: &ClaimedInboundBatch, completed: bool) {
        let mut retry_attempt = 0u32;
        loop {
            let result = if completed {
                self.deps.inbound_batches.complete(claim, Utc::now()).await
            } else {
                self.deps.inbound_batches.reject(claim, Utc::now()).await
            };
            match result {
                Ok(true) | Ok(false) => return,
                Err(error) => {
                    tracing::debug!(
                        extension_id = %claim.schedule.key.extension_id,
                        error = %error,
                        "inbound batch terminal state could not be persisted"
                    );
                    retry_attempt = retry_attempt.saturating_add(1);
                    tokio::time::sleep(Duration::from_secs(1u64 << retry_attempt.min(5))).await;
                }
            }
        }
    }

    pub(super) fn start_recovery_sweep(&self) {
        if self.recovery_started.swap(true, Ordering::AcqRel) {
            return;
        }
        let processor = self.clone();
        tokio::spawn(async move {
            loop {
                processor.recover_pending().await;
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        });
    }

    async fn recover_pending(&self) {
        let schedules = match self.deps.inbound_batches.pending(Utc::now()).await {
            Ok(schedules) => schedules,
            Err(error) => {
                tracing::debug!(error = %error, "inbound batch recovery scan failed");
                return;
            }
        };
        for schedule in schedules {
            if !self.recovery_binding_matches(&schedule) {
                tracing::debug!(
                    extension_id = %schedule.key.extension_id,
                    "inbound batch recovery binding is unavailable or changed"
                );
                continue;
            }
            self.spawn_schedule(schedule);
        }
    }

    fn recovery_binding_matches(&self, schedule: &InboundBatchSchedule) -> bool {
        if let Some(binding) = self
            .deployment_channels
            .extension(&schedule.key.extension_id)
        {
            return resolved_binding_fingerprint("deployment", binding.resolved.as_ref())
                .is_ok_and(|fingerprint| fingerprint == schedule.binding_fingerprint)
                && binding.surfaces.ingress.is_some();
        }
        let Some(active) = self.watch.current().extension(&schedule.key.extension_id) else {
            return false;
        };
        resolved_binding_fingerprint("active", active.resolved.as_ref())
            .is_ok_and(|fingerprint| fingerprint == schedule.binding_fingerprint)
            && active.channel.ingress.is_some()
    }
}

fn delay_until(due_at: chrono::DateTime<Utc>) -> Duration {
    due_at
        .signed_duration_since(Utc::now())
        .to_std()
        .unwrap_or(Duration::ZERO)
}

pub(super) fn resolved_binding_fingerprint(
    kind: &str,
    resolved: &ResolvedExtensionManifest,
) -> Result<String, serde_json::Error> {
    let mut hasher = Sha256::new();
    hasher.update(kind.as_bytes());
    hasher.update([0]);
    hasher.update(serde_json::to_vec(resolved)?);
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn merge_batch_fragments(
    mut fragments: Vec<InboundBatchFragment>,
) -> Result<Option<NormalizedInboundMessage>, ChannelError> {
    fragments.sort_by(|left, right| {
        left.order
            .cmp(&right.order)
            .then_with(|| left.fragment_id.cmp(&right.fragment_id))
    });
    let Some(first) = fragments.first() else {
        return Err(ChannelError::Parse {
            reason: "inbound batch contained no fragments".to_string(),
        });
    };
    let triggered = fragments
        .iter()
        .filter(|fragment| fragment.triggered)
        .collect::<Vec<_>>();
    if triggered.is_empty() {
        return Ok(None);
    }
    for fragment in &fragments {
        if fragment.batch_key != first.batch_key
            || fragment.settle_millis != first.settle_millis
            || fragment.message.event_id != first.message.event_id
            || fragment.message.actor != first.message.actor
            || fragment.message.conversation != first.message.conversation
        {
            return Err(ChannelError::Parse {
                reason: "inbound batch fragments disagree on stable identity or timing".to_string(),
            });
        }
    }
    let canonical = triggered
        .iter()
        .rev()
        .find(|fragment| !fragment.message.text.is_empty())
        .copied()
        .unwrap_or(triggered[0]);
    if triggered
        .iter()
        .any(|fragment| fragment.message.trigger != canonical.message.trigger)
    {
        return Err(ChannelError::Parse {
            reason: "triggered inbound batch fragments disagree on trigger reason".to_string(),
        });
    }
    let mut message = canonical.message.clone();
    message.attachments = fragments
        .into_iter()
        .flat_map(|fragment| fragment.message.attachments)
        .collect();
    message.validate()?;
    Ok(Some(message))
}

/// Manifest-restricted egress for one verified installation, shared by every
/// transport so a channel's `receive` sees the same declared hosts whether the
/// request came over a webhook or a stream. Without a host egress transport
/// the egress fails closed (attachment-bearing messages become transient).
pub(super) fn channel_restricted_egress(
    transport: Option<&Arc<dyn ChannelEgressTransport>>,
    resolved: &ResolvedExtensionManifest,
    extension_id: &str,
    installation_id: &str,
) -> Arc<dyn RestrictedEgress> {
    let Some(transport) = transport else {
        return Arc::new(UnavailableRestrictedEgress);
    };
    let declared = resolved
        .channel
        .as_ref()
        .map(|channel| DeclaredChannelEgress::from_descriptors(&channel.egress))
        .unwrap_or_default();
    Arc::new(PolicyEnforcedChannelEgress::new(
        extension_id,
        installation_id,
        declared,
        Arc::clone(transport),
    ))
}

struct UnavailableRestrictedEgress;

#[async_trait]
impl RestrictedEgress for UnavailableRestrictedEgress {
    async fn send(
        &self,
        _request: RestrictedEgressRequest,
    ) -> Result<RestrictedEgressResponse, RestrictedEgressError> {
        Err(RestrictedEgressError::Transport {
            reason: "channel egress transport is unavailable".to_string(),
        })
    }
}

/// One frame's worth of verified stream input. The caller (the stream
/// supervisor) has already authenticated the connection; nothing here comes
/// from frame content except `body`.
pub struct StreamFrameInput<'a> {
    pub extension_id: &'a str,
    /// The installation that owns the connection, never read from the frame.
    pub installation_id: &'a str,
    pub resolved: &'a ResolvedExtensionManifest,
    /// `"deployment"` or `"active"`, matching the webhook router's binding
    /// fingerprint kinds so batch recovery sees the same fingerprint.
    pub binding_kind: &'static str,
    pub channel: &'a dyn ChannelIngress,
    pub config: &'a [(String, String)],
    pub body: &'a [u8],
}

/// The stream supervisor's door into the shared admission pipeline: the same
/// adapter call, validation, `reply_context` write, durable admit, and batch
/// staging the webhook router runs after verification.
#[derive(Clone)]
pub struct StreamAdmission {
    pub(super) processor: InboundBatchProcessor,
}

impl StreamAdmission {
    /// Manifest-declared non-secret configuration for one installation.
    pub async fn non_secret_config(
        &self,
        extension_id: &str,
        installation_id: &str,
    ) -> Result<Vec<(String, String)>, IngressPortError> {
        self.processor
            .deps
            .configuration
            .non_secret_config(extension_id, installation_id)
            .await
    }

    /// Manifest-restricted egress for the installation (connect call, and the
    /// adapter's own attachment fetches).
    pub fn restricted_egress(
        &self,
        resolved: &ResolvedExtensionManifest,
        extension_id: &str,
        installation_id: &str,
    ) -> Arc<dyn RestrictedEgress> {
        channel_restricted_egress(
            self.processor.deps.channel_egress_transport.as_ref(),
            resolved,
            extension_id,
            installation_id,
        )
    }

    /// Admit one delivered frame. `Transient` means the frame must NOT be
    /// acknowledged; every other disposition may be.
    pub async fn admit_frame(&self, frame: StreamFrameInput<'_>) -> AdmissionDisposition {
        let egress =
            self.restricted_egress(frame.resolved, frame.extension_id, frame.installation_id);
        let can_reply_in_threads = frame
            .resolved
            .channel
            .as_ref()
            .is_some_and(|channel| channel.presentation.can_reply_in_threads);
        let inbound = VerifiedInbound {
            extension_id: frame.extension_id,
            installation_id: frame.installation_id,
            config: frame.config,
            body: frame.body,
            headers: &[],
            can_reply_in_threads,
        };
        let outcome = match receive_verified(frame.channel, inbound, egress.as_ref()).await {
            Ok(outcome) => outcome,
            Err(disposition) => return disposition,
        };
        dispose_outcome(
            &self.processor,
            frame.extension_id,
            frame.installation_id,
            outcome,
            || resolved_binding_fingerprint(frame.binding_kind, frame.resolved),
        )
        .await
    }
}
