//! One connection's life: connect, read, pace, decode, admit, acknowledge.
//!
//! Order per delivered frame (ADR 4, 5.4): size and rate limits, then the
//! channel's pure `decode`, then the shared admission pipeline, and only after
//! that pipeline returns is the vendor's ACK sent. "Acknowledged" therefore
//! means "durably admitted (or consciously dropped)"; a transient failure
//! leaves the frame unacknowledged so the vendor redelivers it.
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use ironclaw_extension_contracts::channel::ChannelStreamDescriptor;
use ironclaw_extension_contracts::channel_adapter::{
    ChannelIngress, ChannelStreamControl, StreamFrameDecision,
};
use ironclaw_host_api::action::{NetworkPolicy, NetworkScheme, NetworkTargetPattern};
use ironclaw_host_api::resource::ResourceScope;
use ironclaw_network::{
    MAX_FRAME_BYTES_CEILING, MAX_MESSAGES_PER_SECOND_CEILING, WebSocketConnectRequest,
    WebSocketConnector, WebSocketError, WebSocketLimits, WebSocketMessage, WebSocketReceiver,
    WebSocketSender,
};

use crate::ingress::{AdmissionDisposition, StreamAdmission, StreamFrameInput};

use super::audit::{StreamAuditEvent, StreamAuditKind, StreamAuditSink};
use super::connect::{ConnectFailure, request_grant};
use super::rate::TokenBucket;
use super::session::{SessionKey, SessionQueues};
use super::source::StreamSource;
use super::{Cancel, StreamSupervisorConfig};

/// Everything one installation's connection task needs.
pub(super) struct ConnectionContext {
    pub source: StreamSource,
    pub admission: StreamAdmission,
    pub connector: Arc<dyn WebSocketConnector>,
    pub scope: ResourceScope,
    pub audit: Arc<dyn StreamAuditSink>,
    pub config: StreamSupervisorConfig,
    /// Admissions running at once across every connection of the supervisor.
    pub admissions: Arc<tokio::sync::Semaphore>,
}

impl ConnectionContext {
    pub(super) fn emit(&self, host: Option<&str>, kind: StreamAuditKind) {
        self.audit.record(StreamAuditEvent {
            extension_id: self.source.extension_id().to_string(),
            installation_id: self.source.installation_id().to_string(),
            host: host.map(str::to_string),
            kind,
        });
    }
}

/// Why an established connection ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EndReason {
    /// The supervisor stopped it.
    Stopped,
    /// The peer closed, or the transport failed.
    Ended(&'static str),
    /// The stream control asked for a fresh connection.
    ReconnectRequested,
}

pub(super) struct ConnectionEnd {
    pub reason: EndReason,
    /// At least one frame was accepted by the stream control and the
    /// connection did not end on a failed ACK. Only then does the reconnect
    /// backoff reset.
    pub healthy: bool,
}

pub(super) enum ConnectOutcome {
    Ran(ConnectionEnd),
    Failed(ConnectFailure),
}

/// Connect once and serve the connection until it ends.
pub(super) async fn run_connection(
    ctx: &Arc<ConnectionContext>,
    cancel: &mut Cancel,
) -> ConnectOutcome {
    let (Some(descriptor), Some(ingress), Some(control)) = (
        ctx.source.stream(),
        ctx.source.ingress(),
        ctx.source.control(),
    ) else {
        return ConnectOutcome::Failed(ConnectFailure {
            kind: super::connect::ConnectFailureKind::Rejected,
            reason: "stream_not_bound",
        });
    };
    let extension_id = ctx.source.extension_id();
    let installation_id = ctx.source.installation_id();
    let config = match ctx
        .admission
        .non_secret_config(extension_id, installation_id)
        .await
    {
        Ok(config) => config,
        Err(_unavailable) => {
            return ConnectOutcome::Failed(ConnectFailure {
                kind: super::connect::ConnectFailureKind::Transient,
                reason: "config_unavailable",
            });
        }
    };
    let egress =
        ctx.admission
            .restricted_egress(ctx.source.resolved(), extension_id, installation_id);
    let grant = match request_grant(
        descriptor,
        ctx.source.resolved(),
        &config,
        egress.as_ref(),
        ctx.config.connect_deadline,
    )
    .await
    {
        Ok(grant) => grant,
        Err(failure) => return ConnectOutcome::Failed(failure),
    };
    let host = grant.host.clone();
    let request = WebSocketConnectRequest {
        scope: ctx.scope.clone(),
        url: String::from(grant.url.as_str()),
        policy: NetworkPolicy {
            allowed_targets: vec![NetworkTargetPattern {
                scheme: Some(NetworkScheme::Wss),
                host_pattern: host.clone(),
                port: None,
            }],
            deny_private_ip_ranges: true,
            max_egress_bytes: None,
        },
        limits: limits_for(descriptor),
    };
    drop(grant);
    let connection = match ctx.connector.connect(request).await {
        Ok(connection) => connection,
        Err(error) => return ConnectOutcome::Failed(classify_dial_error(&error)),
    };
    // Frames are minted into verified inbound only from here on: the connect
    // call succeeded and the handshake completed for this installation.
    ctx.emit(Some(&host), StreamAuditKind::Connected);
    let (sender, receiver) = connection.split();
    let end = read_loop(
        ReadLoop {
            ctx: Arc::clone(ctx),
            descriptor,
            ingress: Arc::clone(ingress),
            control: Arc::clone(control),
            config: Arc::new(config),
            host: host.clone(),
            sender,
        },
        receiver,
        cancel,
    )
    .await;
    ctx.emit(
        Some(&host),
        StreamAuditKind::Disconnected {
            reason: match end.reason {
                EndReason::Stopped => "stopped",
                EndReason::Ended(reason) => reason,
                EndReason::ReconnectRequested => "reconnect_requested",
            },
        },
    );
    ConnectOutcome::Ran(end)
}

/// Sort a failed dial by its stable network category. A gateway refusing the
/// ticket at the upgrade (401/403) is a credential failure; a declaration the
/// dial policy or URL checks refuse can never succeed on retry. Both feed the
/// consecutive-refusal gate that ends in `NeedsAdministrator`. DNS, timeouts,
/// and transport trouble stay transient.
fn classify_dial_error(error: &WebSocketError) -> ConnectFailure {
    use super::connect::ConnectFailureKind;
    match error {
        WebSocketError::HandshakeRejected { status: 401 | 403 } => ConnectFailure {
            kind: ConnectFailureKind::Auth,
            reason: "handshake_unauthorized",
        },
        WebSocketError::PolicyDenied { .. }
        | WebSocketError::InvalidUrl { .. }
        | WebSocketError::InvalidLimits { .. }
        | WebSocketError::RedirectRejected { .. } => ConnectFailure {
            kind: ConnectFailureKind::Rejected,
            reason: error.stable_reason(),
        },
        _ => ConnectFailure {
            kind: ConnectFailureKind::Transient,
            reason: error.stable_reason(),
        },
    }
}

/// Network-layer limits for one declared stream. The network boundary is the
/// hard cap (it disconnects a peer that exceeds it); pacing below it is the
/// supervisor's soft limit, so the hard rate cap is twice the declared rate.
fn limits_for(descriptor: &ChannelStreamDescriptor) -> WebSocketLimits {
    let frame = usize::try_from(descriptor.max_frame_bytes)
        .unwrap_or(MAX_FRAME_BYTES_CEILING)
        .min(MAX_FRAME_BYTES_CEILING);
    let ping = Duration::from_secs(u64::from(descriptor.keepalive.ping_interval_secs));
    let pong = Duration::from_secs(u64::from(descriptor.keepalive.pong_timeout_secs));
    WebSocketLimits {
        max_frame_bytes: frame,
        max_message_bytes: frame,
        connect_timeout: Duration::from_secs(10),
        idle_timeout: ping.saturating_add(pong),
        ping_interval: ping,
        max_messages_per_second: descriptor
            .max_frames_per_second
            .saturating_mul(2)
            .min(MAX_MESSAGES_PER_SECOND_CEILING),
    }
}

/// One connection's borrowed and shared inputs.
struct ReadLoop<'a> {
    ctx: Arc<ConnectionContext>,
    descriptor: &'a ChannelStreamDescriptor,
    ingress: Arc<dyn ChannelIngress>,
    control: Arc<dyn ChannelStreamControl>,
    config: Arc<Vec<(String, String)>>,
    host: String,
    sender: WebSocketSender,
}

/// A delivered frame waiting for, or in, admission.
struct FrameJob {
    data: Vec<u8>,
    ack: Vec<u8>,
    received_at: Instant,
}

/// What the per-session runners need; the connection loop keeps no state the
/// runners write.
struct FrameExecutor {
    ctx: Arc<ConnectionContext>,
    ingress: Arc<dyn ChannelIngress>,
    config: Arc<Vec<(String, String)>>,
    host: String,
    sender: WebSocketSender,
    /// Cleared the moment the connection ends. A queued frame that has not
    /// started admission by then is skipped (unacknowledged, so the vendor
    /// redelivers) and no evidence is minted for it.
    open: Arc<AtomicBool>,
    /// Set when the ACK of an admitted frame could not be sent. The read loop
    /// ends the connection on it, so a write half that stopped working is not
    /// reported as a healthy connection.
    ack_failed: tokio::sync::watch::Sender<bool>,
}
impl FrameExecutor {
    async fn run(self: Arc<Self>, job: FrameJob) {
        if !self.open.load(Ordering::SeqCst) {
            return;
        }
        let Ok(_slot) = Arc::clone(&self.ctx.admissions).acquire_owned().await else {
            return;
        };
        if !self.open.load(Ordering::SeqCst) {
            return;
        }
        if admit(&self.ctx, self.ingress.as_ref(), &self.config, &job.data)
            .await
            .is_none()
        {
            return;
        }
        let elapsed = job.received_at.elapsed();
        if elapsed >= self.ctx.config.ack_latency_warn {
            self.ctx.emit(
                Some(&self.host),
                StreamAuditKind::SlowAck {
                    millis: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
                },
            );
        }
        // The frame is durable whatever happens next; a failed ACK ends the
        // connection (a fresh grant follows) and the vendor's redelivery is
        // absorbed by dedupe.
        if send_ack(&self.sender, job.ack).await.is_err() {
            self.ack_failed.send_replace(true);
        }
    }
}

async fn read_loop(
    input: ReadLoop<'_>,
    mut receiver: WebSocketReceiver,
    cancel: &mut Cancel,
) -> ConnectionEnd {
    let ReadLoop {
        ctx,
        descriptor,
        ingress,
        control,
        config,
        host,
        sender,
    } = input;
    let open = Arc::new(AtomicBool::new(true));
    // Cleared when this function ends or is aborted (a forced stop): frames
    // still queued must not start admission against a connection that is gone.
    let _open_guard = OpenGuard(Arc::clone(&open));
    let (ack_failed, mut ack_failure) = tokio::sync::watch::channel(false);
    let executor = Arc::new(FrameExecutor {
        ctx: Arc::clone(&ctx),
        ingress,
        config,
        host: host.clone(),
        sender: sender.clone(),
        open: Arc::clone(&open),
        ack_failed,
    });
    let queues = {
        let executor = Arc::clone(&executor);
        SessionQueues::new(
            ctx.config.max_pending_frames,
            ctx.config.max_pending_per_session,
            move |job: FrameJob| Box::pin(Arc::clone(&executor).run(job)),
        )
    };
    let mut bucket = TokenBucket::new(descriptor.max_frames_per_second);
    let mut healthy = false;
    let reason = loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => break EndReason::Stopped,
            _ = ack_failure.wait_for(|failed| *failed) => break EndReason::Ended("send_failed"),
            () = bucket.acquire() => {}
        }
        let message = tokio::select! {
            biased;
            () = cancel.cancelled() => break EndReason::Stopped,
            _ = ack_failure.wait_for(|failed| *failed) => break EndReason::Ended("send_failed"),
            received = receiver.recv() => received,
        };
        let frame = match message {
            Ok(Some(message)) => frame_bytes(message),
            Ok(None) => break EndReason::Ended("peer_closed"),
            Err(error) => {
                if matches!(
                    error,
                    WebSocketError::FrameTooLarge { .. } | WebSocketError::RateLimitExceeded { .. }
                ) {
                    ctx.emit(
                        Some(&host),
                        StreamAuditKind::FrameRejected {
                            reason: error.stable_reason(),
                        },
                    );
                }
                break EndReason::Ended(error.stable_reason());
            }
        };
        let received_at = Instant::now();
        // Package code: a panic here must not unwind the connection task.
        // The reason is a fixed code; the panic payload is never read.
        let Some(decoded) = contained(|| control.decode(&frame)) else {
            ctx.emit(
                Some(&host),
                StreamAuditKind::FrameRejected {
                    reason: CONTROL_PANICKED,
                },
            );
            break EndReason::Ended(CONTROL_PANICKED);
        };
        let decision = match decoded {
            Ok(decision) => decision,
            Err(_undecodable) => {
                ctx.emit(
                    Some(&host),
                    StreamAuditKind::FrameRejected {
                        reason: "decode_failed",
                    },
                );
                continue;
            }
        };
        healthy = true;
        match decision {
            StreamFrameDecision::Ack(ack) => {
                if send_ack(&sender, ack).await.is_err() {
                    break EndReason::Ended("send_failed");
                }
            }
            StreamFrameDecision::AckAndReconnect(ack) => {
                // Best effort: the connection is being replaced either way.
                _ = send_ack(&sender, ack).await;
                _ = sender.close().await;
                break EndReason::ReconnectRequested;
            }
            StreamFrameDecision::Drop { ack } => {
                if let Some(ack) = ack
                    && send_ack(&sender, ack).await.is_err()
                {
                    break EndReason::Ended("send_failed");
                }
            }
            StreamFrameDecision::Deliver { data, ack } => {
                let Some(key) = contained(|| session_key(control.as_ref(), &data)) else {
                    ctx.emit(
                        Some(&host),
                        StreamAuditKind::FrameRejected {
                            reason: CONTROL_PANICKED,
                        },
                    );
                    break EndReason::Ended(CONTROL_PANICKED);
                };
                // Waits while the session or connection is full: reading stops.
                let enqueue = queues.enqueue(
                    key,
                    FrameJob {
                        data,
                        ack,
                        received_at,
                    },
                );
                tokio::select! {
                    biased;
                    () = cancel.cancelled() => break EndReason::Stopped,
                    _ = ack_failure.wait_for(|failed| *failed) => break EndReason::Ended("send_failed"),
                    () = enqueue => {}
                }
            }
        }
    };
    // No new admission may start; frames already inside the pipeline finish.
    open.store(false, Ordering::SeqCst);
    queues.wait_idle().await;
    if matches!(reason, EndReason::Stopped | EndReason::Ended("send_failed")) {
        _ = sender.close().await;
    }
    // A connection that ends because an ACK could not be sent is not healthy,
    // however many frames decoded: a persistent ACK failure must keep
    // escalating the reconnect delay instead of resetting it.
    let healthy = healthy && !matches!(reason, EndReason::Ended("send_failed"));
    ConnectionEnd { reason, healthy }
}

struct OpenGuard(Arc<AtomicBool>);

impl Drop for OpenGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// Fixed reason for a frame-control callback that panicked.
const CONTROL_PANICKED: &str = "control_panicked";

/// Run package-supplied frame control, turning a panic into `None`.
/// `AssertUnwindSafe` is sound: the control is `&self` and the closure only
/// borrows the frame; nothing host-owned is left half-updated by an unwind.
fn contained<T>(call: impl FnOnce() -> T) -> Option<T> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(call)).ok()
}

/// Longest session key honored; a longer one is treated as absent (the frame
/// joins the default queue) rather than truncated into a collision.
const MAX_SESSION_KEY_BYTES: usize = 256;

fn session_key(control: &dyn ChannelStreamControl, data: &[u8]) -> SessionKey {
    control
        .session_key(data)
        .filter(|key| !key.is_empty() && key.len() <= MAX_SESSION_KEY_BYTES)
}

/// Run the shared admission pipeline. `Some(())` means "acknowledge this
/// frame"; `None` means leave it unacknowledged.
async fn admit(
    ctx: &ConnectionContext,
    ingress: &dyn ChannelIngress,
    config: &[(String, String)],
    data: &[u8],
) -> Option<()> {
    let input = StreamFrameInput {
        extension_id: ctx.source.extension_id(),
        installation_id: ctx.source.installation_id(),
        resolved: ctx.source.resolved(),
        binding_kind: ctx.source.binding_kind(),
        channel: ingress,
        config,
        body: data,
    };
    let disposition = match tokio::time::timeout(
        ctx.config.admission_deadline,
        ctx.admission.admit_frame(input),
    )
    .await
    {
        Ok(disposition) => disposition,
        Err(_elapsed) => return None,
    };
    match disposition {
        AdmissionDisposition::Transient => None,
        AdmissionDisposition::DeterministicDiscard => {
            ctx.emit(
                None,
                StreamAuditKind::FrameDiscarded {
                    reason: "deterministic_failure",
                },
            );
            Some(())
        }
        AdmissionDisposition::HostBoundViolation => {
            ctx.emit(
                None,
                StreamAuditKind::FrameDiscarded {
                    reason: "adapter_bound_violation",
                },
            );
            Some(())
        }
        // A stream has no synchronous response; the adapter's body is dropped.
        AdmissionDisposition::Admitted
        | AdmissionDisposition::Ignored
        | AdmissionDisposition::BatchStaged
        | AdmissionDisposition::Respond(_) => Some(()),
    }
}

fn frame_bytes(message: WebSocketMessage) -> Vec<u8> {
    match message {
        WebSocketMessage::Text(text) => text.into_bytes(),
        WebSocketMessage::Binary(bytes) => bytes,
    }
}

async fn send_ack(sender: &WebSocketSender, ack: Vec<u8>) -> Result<(), WebSocketError> {
    let message = match String::from_utf8(ack) {
        Ok(text) => WebSocketMessage::Text(text),
        Err(error) => WebSocketMessage::Binary(error.into_bytes()),
    };
    sender.send(message).await
}

#[cfg(test)]
mod tests {
    use super::super::connect::ConnectFailureKind;
    use super::*;
    use ironclaw_extension_contracts::channel::{
        MAX_STREAM_FRAME_BYTES, MAX_STREAM_FRAMES_PER_SECOND,
    };

    /// Review #2/#11: the manifest's declared maxima and the network layer's
    /// hard ceilings are one contract. The contract crate cannot depend on the
    /// network crate, so this is the test that sees both.
    #[test]
    fn declared_stream_maxima_agree_with_the_network_ceilings() {
        assert_eq!(
            usize::try_from(MAX_STREAM_FRAME_BYTES).ok(),
            Some(MAX_FRAME_BYTES_CEILING),
            "a declared frame limit must be exactly what the network layer enforces"
        );
        assert!(
            u64::from(MAX_STREAM_FRAMES_PER_SECOND) * 2
                <= u64::from(MAX_MESSAGES_PER_SECOND_CEILING),
            "the 2x hard-cap headroom must hold across the whole legal declared range"
        );
    }

    #[test]
    fn dial_failures_are_sorted_by_their_stable_category() {
        let kind = |error: WebSocketError| classify_dial_error(&error).kind;
        assert_eq!(
            kind(WebSocketError::HandshakeRejected { status: 401 }),
            ConnectFailureKind::Auth
        );
        assert_eq!(
            kind(WebSocketError::HandshakeRejected { status: 403 }),
            ConnectFailureKind::Auth
        );
        for rejected in [
            WebSocketError::PolicyDenied {
                reason: String::new(),
            },
            WebSocketError::InvalidUrl {
                reason: String::new(),
            },
            WebSocketError::InvalidLimits {
                reason: String::new(),
            },
            WebSocketError::RedirectRejected { status: 302 },
        ] {
            assert_eq!(kind(rejected), ConnectFailureKind::Rejected);
        }
        for transient in [
            WebSocketError::Dns {
                reason: String::new(),
            },
            WebSocketError::ConnectTimeout,
            WebSocketError::Closed,
            WebSocketError::HandshakeRejected { status: 503 },
            WebSocketError::HandshakeRejected { status: 429 },
        ] {
            assert_eq!(kind(transient), ConnectFailureKind::Transient);
        }
    }
}
