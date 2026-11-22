//! Stream-connection audit events.
//!
//! The webhook path's only operational record is structured `tracing`, so the
//! stream path emits the same: one stable event per connection transition or
//! rejected frame. Events carry the extension, the installation, and (once
//! known) the gateway **host name**, never the endpoint's query, the ticket,
//! the client secret, or frame content. Reasons are fixed `&'static str`
//! codes, so no vendor or transport text can reach an event.
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamAuditKind {
    /// The connect call succeeded and the WebSocket handshake completed.
    Connected,
    /// An established connection ended.
    Disconnected { reason: &'static str },
    /// A connection attempt failed before any frame (not an auth rejection).
    ConnectFailed { reason: &'static str },
    /// The connect call was refused for credentials; `consecutive` counts
    /// uninterrupted refusals.
    AuthFailed { consecutive: u32 },
    /// A frame was refused (oversize, over rate, undecodable).
    FrameRejected { reason: &'static str },
    /// A verified frame was acknowledged and dropped without admission.
    FrameDiscarded { reason: &'static str },
    /// Retrying stopped; an administrator has to act (credentials, limits).
    NeedsAdministrator { reason: &'static str },
    /// A frame took at least the configured threshold from receipt to ACK.
    /// The vendor's real ACK window is unverified (ADR 5.4); this is a signal
    /// to look, not a promise about redelivery.
    SlowAck { millis: u64 },
    /// The supervisor stopped this connection on purpose.
    Stopped,
    /// A stop exceeded the stop timeout and the connection task was aborted.
    /// Followed by `Stopped`.
    StopForced,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamAuditEvent {
    pub extension_id: String,
    pub installation_id: String,
    /// Gateway host name only, once a connect response named one.
    pub host: Option<String>,
    pub kind: StreamAuditKind,
}

pub trait StreamAuditSink: Send + Sync {
    fn record(&self, event: StreamAuditEvent);
}

/// Default sink: structured `tracing`, matching the webhook router's levels
/// (debug for routine transitions, warn for refusals and drops).
#[derive(Debug, Clone, Copy, Default)]
pub struct TracingStreamAudit;

impl StreamAuditSink for TracingStreamAudit {
    fn record(&self, event: StreamAuditEvent) {
        let host = event.host.as_deref().unwrap_or("");
        match &event.kind {
            StreamAuditKind::Connected | StreamAuditKind::Stopped => tracing::debug!(
                target: "ironclaw_extension_host::stream",
                extension_id = %event.extension_id,
                installation_id = %event.installation_id,
                host,
                kind = ?event.kind,
                "stream connection event"
            ),
            kind => tracing::warn!(
                target: "ironclaw_extension_host::stream",
                extension_id = %event.extension_id,
                installation_id = %event.installation_id,
                host,
                kind = ?kind,
                "stream connection event"
            ),
        }
    }
}

/// Sends every event to each sink in order.
#[derive(Clone, Default)]
pub struct FanoutStreamAudit {
    sinks: Vec<Arc<dyn StreamAuditSink>>,
}

impl FanoutStreamAudit {
    pub fn new(sinks: Vec<Arc<dyn StreamAuditSink>>) -> Self {
        Self { sinks }
    }
}

impl StreamAuditSink for FanoutStreamAudit {
    fn record(&self, event: StreamAuditEvent) {
        for sink in &self.sinks {
            sink.record(event.clone());
        }
    }
}
