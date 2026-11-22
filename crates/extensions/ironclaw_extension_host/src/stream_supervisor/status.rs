//! In-memory connection state, derived from the supervisor's audit events.
//!
//! Connection state is a process fact (it is rebuilt by reconnecting after a
//! restart), so it is a cache fed by the same events that go to the audit log,
//! not a durable record. The lifecycle projection reads it; transports and the
//! browser never infer state. It stores fixed reason codes only: no host, URL,
//! ticket, credential, or frame content.
use std::collections::HashMap;
use std::sync::Mutex;

use chrono::{DateTime, Utc};

use super::audit::{StreamAuditEvent, StreamAuditKind, StreamAuditSink};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamConnectionState {
    Connected,
    Reconnecting,
    NeedsAdministrator,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamConnectionStatus {
    pub state: StreamConnectionState,
    pub last_error: Option<&'static str>,
    pub last_error_at: Option<DateTime<Utc>>,
}

/// Latest state per extension id. A stopped connection has no entry.
#[derive(Debug, Default)]
pub struct StreamConnectionStatuses {
    by_extension: Mutex<HashMap<String, StreamConnectionStatus>>,
}

impl StreamConnectionStatuses {
    pub fn get(&self, extension_id: &str) -> Option<StreamConnectionStatus> {
        self.lock().get(extension_id).cloned()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, StreamConnectionStatus>> {
        self.by_extension
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl StreamAuditSink for StreamConnectionStatuses {
    fn record(&self, event: StreamAuditEvent) {
        let mut statuses = self.lock();
        let entry = statuses.get(&event.extension_id).cloned();
        let now = Utc::now();
        let failed = |state, reason: &'static str| StreamConnectionStatus {
            state,
            last_error: Some(reason),
            last_error_at: Some(now),
        };
        let next = match event.kind {
            StreamAuditKind::Connected => Some(StreamConnectionStatus {
                state: StreamConnectionState::Connected,
                last_error: entry.as_ref().and_then(|status| status.last_error),
                last_error_at: entry.as_ref().and_then(|status| status.last_error_at),
            }),
            StreamAuditKind::Disconnected { reason } => Some(match reason {
                // Deliberate ends are not errors.
                "stopped" | "reconnect_requested" | "peer_closed" => StreamConnectionStatus {
                    state: StreamConnectionState::Reconnecting,
                    last_error: entry.as_ref().and_then(|status| status.last_error),
                    last_error_at: entry.as_ref().and_then(|status| status.last_error_at),
                },
                reason => failed(StreamConnectionState::Reconnecting, reason),
            }),
            StreamAuditKind::ConnectFailed { reason } => {
                Some(failed(StreamConnectionState::Reconnecting, reason))
            }
            StreamAuditKind::AuthFailed { .. } => Some(failed(
                StreamConnectionState::Reconnecting,
                "credentials_refused",
            )),
            StreamAuditKind::NeedsAdministrator { reason } => {
                Some(failed(StreamConnectionState::NeedsAdministrator, reason))
            }
            StreamAuditKind::Stopped => {
                statuses.remove(&event.extension_id);
                None
            }
            // Frame-level events do not change connection state.
            StreamAuditKind::FrameRejected { .. }
            | StreamAuditKind::FrameDiscarded { .. }
            | StreamAuditKind::SlowAck { .. }
            | StreamAuditKind::StopForced => None,
        };
        if let Some(next) = next {
            statuses.insert(event.extension_id, next);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(kind: StreamAuditKind) -> StreamAuditEvent {
        StreamAuditEvent {
            extension_id: "acme".to_string(),
            installation_id: "install".to_string(),
            host: Some("gateway.acme.example".to_string()),
            kind,
        }
    }

    #[test]
    fn events_drive_the_state_and_a_stopped_connection_has_none() {
        let statuses = StreamConnectionStatuses::default();
        assert_eq!(statuses.get("acme"), None);

        statuses.record(event(StreamAuditKind::Connected));
        assert_eq!(
            statuses.get("acme").map(|s| s.state),
            Some(StreamConnectionState::Connected)
        );

        // A deliberate end is "reconnecting" without an error.
        statuses.record(event(StreamAuditKind::Disconnected {
            reason: "peer_closed",
        }));
        let status = statuses.get("acme").expect("status");
        assert_eq!(status.state, StreamConnectionState::Reconnecting);
        assert_eq!(status.last_error, None);

        // A failed attempt records its fixed reason code and time.
        statuses.record(event(StreamAuditKind::ConnectFailed {
            reason: "connect_unavailable",
        }));
        let status = statuses.get("acme").expect("status");
        assert_eq!(status.state, StreamConnectionState::Reconnecting);
        assert_eq!(status.last_error, Some("connect_unavailable"));
        assert!(status.last_error_at.is_some());

        // A later connection keeps the last error for context.
        statuses.record(event(StreamAuditKind::Connected));
        let status = statuses.get("acme").expect("status");
        assert_eq!(status.state, StreamConnectionState::Connected);
        assert_eq!(status.last_error, Some("connect_unavailable"));

        statuses.record(event(StreamAuditKind::AuthFailed { consecutive: 1 }));
        assert_eq!(
            statuses.get("acme").and_then(|s| s.last_error),
            Some("credentials_refused")
        );
        statuses.record(event(StreamAuditKind::NeedsAdministrator {
            reason: "connect_unauthorized",
        }));
        let status = statuses.get("acme").expect("status");
        assert_eq!(status.state, StreamConnectionState::NeedsAdministrator);
        assert_eq!(status.last_error, Some("connect_unauthorized"));

        // Frame-level events never change connection state.
        statuses.record(event(StreamAuditKind::FrameRejected {
            reason: "decode_failed",
        }));
        statuses.record(event(StreamAuditKind::SlowAck { millis: 9000 }));
        assert_eq!(
            statuses.get("acme").map(|s| s.state),
            Some(StreamConnectionState::NeedsAdministrator)
        );

        statuses.record(event(StreamAuditKind::Stopped));
        assert_eq!(statuses.get("acme"), None);
    }

    #[test]
    fn the_cache_holds_reason_codes_only() {
        let statuses = StreamConnectionStatuses::default();
        statuses.record(event(StreamAuditKind::Connected));
        let rendered = format!("{:?}", statuses.get("acme"));
        assert!(!rendered.contains("gateway.acme.example"), "{rendered}");
        assert!(!rendered.contains("install"), "{rendered}");
    }
}
