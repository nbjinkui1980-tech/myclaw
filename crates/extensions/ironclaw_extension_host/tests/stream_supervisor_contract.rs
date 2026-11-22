//! Stream supervisor contract tests (stream-ingress milestone one).
//!
//! Drives the REAL extension host snapshot, the REAL ingress router's shared
//! admission pipeline, and the REAL stream supervisor and network connector
//! (policy, resolver, limits, handshake) against a loopback fake gateway. The
//! admission sink and the connect-call egress are the recorded seams, so each
//! test asserts what crossed them and in what order. Only the invented `acme`
//! vendor appears.
mod stream_support;

use std::time::{Duration, Instant};

use ironclaw_extension_contracts::tool_adapter::RestrictedEgressError;
use ironclaw_extension_host::stream_supervisor::{
    BackoffPolicy, StreamAuditKind, StreamConnectionState, StreamSupervisorConfig,
};
use stream_support::*;

async fn started_and_active(options: HarnessOptions) -> Harness {
    let harness = Harness::start(options).await;
    harness.activate().await;
    harness
}

fn has_connect_failure(harness: &Harness, reason: &'static str) -> bool {
    harness
        .audit
        .kinds()
        .contains(&StreamAuditKind::ConnectFailed { reason })
}

#[tokio::test]
async fn a_delivered_frame_is_admitted_before_it_is_acknowledged() {
    let harness = started_and_active(HarnessOptions::default()).await;
    wait_until(
        || harness.audit.count(&StreamAuditKind::Connected) == 1,
        "connection",
    )
    .await;

    harness
        .gateway
        .send_to_latest(event_frame("F-1", "Ev-1", "C-1"));
    wait_until(|| harness.gateway.ack_count() == 1, "the ACK").await;

    // Seam order: the durable admission commit precedes the ACK on the wire.
    assert_eq!(
        harness.log_entries(),
        vec!["admit:Ev-1".to_string(), format!("ack:{}", ack_text("F-1"))]
    );
    // The installation comes from the connection's owner, never the frame.
    assert_eq!(
        *harness.sink.admitted.lock().expect("admitted"),
        vec![("Ev-1".to_string(), INSTALLATION_ID.to_string())]
    );
}

#[tokio::test]
async fn the_connect_call_carries_declared_secrets_only_by_reference_and_no_secret_is_reported() {
    let harness = started_and_active(HarnessOptions::default()).await;
    wait_until(
        || harness.audit.count(&StreamAuditKind::Connected) == 1,
        "connection",
    )
    .await;
    harness
        .gateway
        .send_to_latest(event_frame("F-1", "Ev-1", "C-1"));
    wait_until(|| harness.gateway.ack_count() == 1, "the ACK").await;

    let calls = harness.egress.calls.lock().expect("calls");
    assert_eq!(calls.len(), 1);
    let approved = &calls[0].1;
    assert_eq!(approved.url, "https://api.acme.example/v1/streams/open");
    let body = String::from_utf8(approved.body.clone()).expect("utf8 body");
    assert!(body.contains("\"clientId\":\"client-1\""), "{body}");
    assert!(body.contains("\"subscriptions\""), "{body}");
    assert!(body.contains("/v1/messages/get"), "{body}");
    assert!(
        !body.contains("clientSecret"),
        "secret slot is host-injected: {body}"
    );
    assert_eq!(approved.body_credentials.len(), 1);
    assert_eq!(
        approved.body_credentials[0].handle.as_str(),
        "acme_client_secret"
    );
    drop(calls);

    // The ticket rode the dial URL (percent-encoded) and nowhere else.
    let uris = harness.gateway.request_uris.lock().expect("uris");
    assert_eq!(uris.len(), 1);
    assert!(uris[0].contains(&format!("ticket={TICKET}")), "{}", uris[0]);
    let audit = harness.audit.rendered();
    assert!(
        !audit.contains("TICKET"),
        "audit leaked the ticket: {audit}"
    );
    assert!(!audit.contains("ticket="), "audit leaked a query: {audit}");
    assert!(audit.contains(GATEWAY_HOST), "host name is reported");
}

#[tokio::test]
async fn an_unauthorized_connect_call_fails_closed_without_dialing() {
    let harness = Harness::start(HarnessOptions::default()).await;
    harness.egress.set_default(ConnectScript::Status(401));
    harness.activate().await;

    wait_until(
        || {
            harness
                .audit
                .kinds()
                .contains(&StreamAuditKind::AuthFailed { consecutive: 1 })
        },
        "the refusal",
    )
    .await;
    assert_eq!(
        harness
            .gateway
            .accepts
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    assert!(harness.sink.attempts.lock().expect("attempts").is_empty());
}

#[tokio::test]
async fn a_missing_credential_is_reported_as_a_refusal_not_a_transport_error() {
    let harness = Harness::start(HarnessOptions::default()).await;
    harness
        .egress
        .set_default(ConnectScript::Error(RestrictedEgressError::AuthRequired {
            required_secrets: Vec::new(),
            credential_requirements: Vec::new(),
        }));
    harness.activate().await;

    wait_until(
        || {
            harness
                .audit
                .kinds()
                .contains(&StreamAuditKind::AuthFailed { consecutive: 1 })
        },
        "the refusal",
    )
    .await;
    assert_eq!(
        harness
            .gateway
            .accepts
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
}

#[tokio::test]
async fn an_endpoint_outside_the_declared_hosts_is_never_dialed() {
    for endpoint in [
        "wss://evil.example/ws",
        "wss://127.0.0.1/ws",
        "ws://gateway.acme.example/ws",
        "wss://gateway.acme.example:8443/ws",
        "wss://gateway.acme.example/ws?leak=1",
        "wss://user:pw@gateway.acme.example/ws",
        "not a url",
    ] {
        let harness = Harness::start(HarnessOptions::default()).await;
        harness
            .egress
            .set_default(ConnectScript::GrantEndpoint(endpoint));
        harness.activate().await;

        wait_until(
            || has_connect_failure(&harness, "endpoint_host_not_declared"),
            endpoint,
        )
        .await;
        assert_eq!(
            harness
                .gateway
                .accepts
                .load(std::sync::atomic::Ordering::SeqCst),
            0,
            "{endpoint} must not be dialed"
        );
        let audit = harness.audit.rendered();
        assert!(
            !audit.contains("leak=1") && !audit.contains("pw@"),
            "{audit}"
        );
    }
}

#[tokio::test]
async fn an_oversize_frame_ends_the_connection_and_admits_nothing() {
    let harness = started_and_active(HarnessOptions {
        manifest: manifest_with(&[("max_frame_bytes = 262144", "max_frame_bytes = 1024")]),
        ..HarnessOptions::default()
    })
    .await;
    wait_until(
        || harness.audit.count(&StreamAuditKind::Connected) == 1,
        "connection",
    )
    .await;

    harness.gateway.send_to_latest("x".repeat(4096));
    wait_until(
        || {
            harness.audit.count(&StreamAuditKind::FrameRejected {
                reason: "frame_too_large",
            }) == 1
        },
        "the oversize rejection",
    )
    .await;
    assert!(harness.sink.attempts.lock().expect("attempts").is_empty());
    assert_eq!(harness.gateway.ack_count(), 0);
}

#[tokio::test]
async fn pacing_slows_a_fast_peer_without_dropping_a_frame() {
    let harness = started_and_active(HarnessOptions {
        manifest: manifest_with(&[("max_frames_per_second = 50", "max_frames_per_second = 5")]),
        ..HarnessOptions::default()
    })
    .await;
    wait_until(
        || harness.audit.count(&StreamAuditKind::Connected) == 1,
        "connection",
    )
    .await;

    let started = Instant::now();
    for index in 0..8 {
        harness.gateway.send_to_latest(event_frame(
            &format!("F-{index}"),
            &format!("Ev-{index}"),
            "C-1",
        ));
    }
    wait_until(|| harness.gateway.ack_count() == 8, "all eight ACKs").await;

    assert!(
        started.elapsed() >= Duration::from_millis(400),
        "5/s with a 5-frame burst must delay the last 3: {:?}",
        started.elapsed()
    );
    assert_eq!(
        harness.sink.admitted_events().len(),
        8,
        "nothing was dropped"
    );
}

#[tokio::test]
async fn an_undecodable_frame_is_rejected_and_the_connection_keeps_serving() {
    let harness = started_and_active(HarnessOptions::default()).await;
    wait_until(
        || harness.audit.count(&StreamAuditKind::Connected) == 1,
        "connection",
    )
    .await;

    harness.gateway.send_to_latest("not json at all");
    harness
        .gateway
        .send_to_latest(event_frame("F-1", "Ev-1", "C-1"));
    wait_until(|| harness.gateway.ack_count() == 1, "the valid frame's ACK").await;

    assert_eq!(
        harness.audit.count(&StreamAuditKind::FrameRejected {
            reason: "decode_failed"
        }),
        1
    );
    assert_eq!(harness.sink.admitted_events(), vec!["Ev-1".to_string()]);
}

#[tokio::test]
async fn a_transient_admission_failure_is_not_acknowledged() {
    let harness = started_and_active(HarnessOptions::default()).await;
    harness
        .sink
        .script
        .lock()
        .expect("script")
        .fail_retryable
        .insert("Ev-1".to_string(), 1);
    wait_until(
        || harness.audit.count(&StreamAuditKind::Connected) == 1,
        "connection",
    )
    .await;

    harness
        .gateway
        .send_to_latest(event_frame("F-1", "Ev-1", "C-1"));
    harness
        .gateway
        .send_to_latest(event_frame("F-2", "Ev-2", "C-2"));
    wait_until(
        || harness.gateway.ack_count() == 1,
        "the second frame's ACK",
    )
    .await;

    assert_eq!(harness.gateway.ack_texts(), vec![ack_text("F-2")]);
    assert_eq!(harness.sink.admitted_events(), vec!["Ev-2".to_string()]);
}

#[tokio::test]
async fn a_permanently_rejected_frame_is_acknowledged_and_audited_as_discarded() {
    let harness = started_and_active(HarnessOptions::default()).await;
    harness
        .sink
        .script
        .lock()
        .expect("script")
        .fail_permanent
        .push("Ev-1".to_string());
    wait_until(
        || harness.audit.count(&StreamAuditKind::Connected) == 1,
        "connection",
    )
    .await;

    harness
        .gateway
        .send_to_latest(event_frame("F-1", "Ev-1", "C-1"));
    wait_until(|| harness.gateway.ack_count() == 1, "the ACK").await;

    assert!(harness.sink.admitted_events().is_empty());
    assert_eq!(
        harness.audit.count(&StreamAuditKind::FrameDiscarded {
            reason: "deterministic_failure"
        }),
        1
    );
}

// ── Task 7: ACK timing, ordering, back-pressure, reconnect ─────────────────

fn config_with(edit: impl FnOnce(&mut StreamSupervisorConfig)) -> StreamSupervisorConfig {
    let mut config = HarnessOptions::default().config;
    edit(&mut config);
    config
}

async fn connected(harness: &Harness, connections: usize) {
    wait_until(
        || harness.audit.count(&StreamAuditKind::Connected) == connections,
        "connection",
    )
    .await;
}

#[tokio::test]
async fn frames_of_one_session_are_admitted_and_acknowledged_in_arrival_order() {
    let harness = started_and_active(HarnessOptions::default()).await;
    harness
        .sink
        .script
        .lock()
        .expect("script")
        .delay
        .insert("Ev-1".to_string(), Duration::from_millis(250));
    connected(&harness, 1).await;

    for (frame, event) in [("F-1", "Ev-1"), ("F-2", "Ev-2"), ("F-3", "Ev-3")] {
        harness
            .gateway
            .send_to_latest(event_frame(frame, event, "C-1"));
    }
    wait_until(|| harness.gateway.ack_count() == 3, "three ACKs").await;

    assert_eq!(
        harness.sink.admitted_events(),
        vec!["Ev-1", "Ev-2", "Ev-3"],
        "the slow first frame does not let later frames of its session pass"
    );
    assert_eq!(
        harness.gateway.ack_texts(),
        vec![ack_text("F-1"), ack_text("F-2"), ack_text("F-3")]
    );
    assert_eq!(
        harness
            .sink
            .max_in_flight
            .load(std::sync::atomic::Ordering::SeqCst),
        1,
        "one session never admits concurrently"
    );
}

#[tokio::test]
async fn a_slow_session_does_not_block_another_session() {
    let harness = started_and_active(HarnessOptions::default()).await;
    harness
        .sink
        .script
        .lock()
        .expect("script")
        .delay
        .insert("Ev-slow".to_string(), Duration::from_millis(400));
    connected(&harness, 1).await;

    harness
        .gateway
        .send_to_latest(event_frame("F-1", "Ev-slow", "C-1"));
    harness
        .gateway
        .send_to_latest(event_frame("F-2", "Ev-fast", "C-2"));
    wait_until(|| harness.gateway.ack_count() == 2, "both ACKs").await;

    assert_eq!(harness.sink.admitted_events(), vec!["Ev-fast", "Ev-slow"]);
}

#[tokio::test]
async fn total_admission_concurrency_is_bounded() {
    let harness = started_and_active(HarnessOptions {
        config: config_with(|config| config.max_concurrent_admissions = 2),
        ..HarnessOptions::default()
    })
    .await;
    {
        let mut script = harness.sink.script.lock().expect("script");
        for index in 0..5 {
            script
                .delay
                .insert(format!("Ev-{index}"), Duration::from_millis(120));
        }
    }
    connected(&harness, 1).await;

    for index in 0..5 {
        harness.gateway.send_to_latest(event_frame(
            &format!("F-{index}"),
            &format!("Ev-{index}"),
            &format!("C-{index}"),
        ));
    }
    wait_until(|| harness.gateway.ack_count() == 5, "five ACKs").await;

    assert_eq!(
        harness
            .sink
            .max_in_flight
            .load(std::sync::atomic::Ordering::SeqCst),
        2
    );
}

#[tokio::test]
async fn a_redelivered_frame_is_acknowledged_once_it_is_admitted() {
    let harness = started_and_active(HarnessOptions::default()).await;
    harness
        .sink
        .script
        .lock()
        .expect("script")
        .fail_retryable
        .insert("Ev-1".to_string(), 1);
    connected(&harness, 1).await;

    harness
        .gateway
        .send_to_latest(event_frame("F-1", "Ev-1", "C-1"));
    wait_until(
        || harness.sink.attempts.lock().expect("attempts").len() == 1,
        "first attempt",
    )
    .await;
    assert_eq!(
        harness.gateway.ack_count(),
        0,
        "a failed admission is never ACKed"
    );

    // The vendor redelivers the same frame.
    harness
        .gateway
        .send_to_latest(event_frame("F-1", "Ev-1", "C-1"));
    wait_until(|| harness.gateway.ack_count() == 1, "the ACK after success").await;
    assert_eq!(
        harness.log_entries(),
        vec!["admit:Ev-1".to_string(), format!("ack:{}", ack_text("F-1")),]
    );
}

#[tokio::test]
async fn a_disconnect_frame_is_acknowledged_then_a_new_connection_is_made_with_a_new_grant() {
    let harness = started_and_active(HarnessOptions::default()).await;
    connected(&harness, 1).await;

    harness
        .gateway
        .send_to_latest(serde_json::json!({"kind": "reconnect", "frame_id": "F-9"}).to_string());
    connected(&harness, 2).await;

    assert_eq!(harness.gateway.ack_texts(), vec![ack_text("F-9")]);
    assert_eq!(
        harness.egress.call_count(),
        2,
        "every connection asks for a fresh grant"
    );
    harness
        .gateway
        .send_to_latest(event_frame("F-1", "Ev-1", "C-1"));
    wait_until(
        || harness.gateway.ack_count() == 2,
        "service on the new connection",
    )
    .await;
    assert_eq!(harness.sink.admitted_events(), vec!["Ev-1"]);
}

#[tokio::test]
async fn a_server_close_reconnects_automatically() {
    let harness = started_and_active(HarnessOptions::default()).await;
    connected(&harness, 1).await;

    harness.gateway.close_latest();
    connected(&harness, 2).await;

    harness
        .gateway
        .send_to_latest(event_frame("F-1", "Ev-1", "C-1"));
    wait_until(|| harness.gateway.ack_count() == 1, "the ACK").await;
    assert_eq!(
        harness
            .gateway
            .accepts
            .load(std::sync::atomic::Ordering::SeqCst),
        2
    );
}

#[tokio::test]
async fn reconnect_delays_grow_exponentially_up_to_the_cap() {
    let harness = Harness::start(HarnessOptions::default()).await;
    harness.egress.set_default(ConnectScript::Status(503));
    harness.activate().await;

    wait_until(|| harness.egress.call_count() >= 7, "seven attempts").await;
    let times = harness.egress.call_times();
    let gaps: Vec<u128> = times
        .windows(2)
        .map(|w| (w[1] - w[0]).as_millis())
        .collect();
    // initial 20ms doubling to the 200ms cap: 20, 40, 80, 160, 200, 200.
    for (gap, floor) in gaps.iter().zip([20u128, 40, 80, 160, 200, 200]) {
        assert!(*gap >= floor, "gap {gap}ms < {floor}ms: {gaps:?}");
    }
    assert!(gaps[5] < 400, "capped near 200ms: {gaps:?}");
}

#[tokio::test]
async fn backoff_resets_only_after_a_frame_the_stream_control_accepted() {
    let harness = Harness::start(HarnessOptions {
        config: config_with(|config| {
            config.backoff = BackoffPolicy {
                initial: Duration::from_millis(100),
                max: Duration::from_millis(800),
                jitter_fraction: 0.0,
            };
        }),
        ..HarnessOptions::default()
    })
    .await;
    harness.activate().await;
    connected(&harness, 1).await;

    // Connect-and-drop with no accepted frame: delays keep growing.
    harness.gateway.close_latest();
    connected(&harness, 2).await;
    harness.gateway.close_latest();
    connected(&harness, 3).await;
    let times = harness.egress.call_times();
    let first = (times[1] - times[0]).as_millis();
    let second = (times[2] - times[1]).as_millis();
    assert!(
        second >= first + 80,
        "no healthy frame, no reset: {first}ms then {second}ms"
    );

    // One accepted frame resets the delay to the initial value.
    harness
        .gateway
        .send_to_latest(event_frame("F-1", "Ev-1", "C-1"));
    wait_until(|| harness.gateway.ack_count() == 1, "the ACK").await;
    harness.gateway.close_latest();
    connected(&harness, 4).await;
    let times = harness.egress.call_times();
    let after_reset = (times[3] - times[2]).as_millis();
    assert!(after_reset < second, "reset: {after_reset}ms vs {second}ms");
}

#[tokio::test]
async fn repeated_credential_refusals_stop_the_retrying_and_flag_the_administrator() {
    let harness = Harness::start(HarnessOptions::default()).await;
    harness.egress.set_default(ConnectScript::Status(401));
    harness.activate().await;

    wait_until(
        || {
            harness.audit.count(&StreamAuditKind::NeedsAdministrator {
                reason: "connect_unauthorized",
            }) == 1
        },
        "the administrator flag",
    )
    .await;
    assert_eq!(
        harness.egress.call_count(),
        3,
        "threshold of three refusals"
    );
    for consecutive in 1..=3 {
        assert_eq!(
            harness
                .audit
                .count(&StreamAuditKind::AuthFailed { consecutive }),
            1
        );
    }
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(harness.egress.call_count(), 3, "no further attempts");
}

#[tokio::test]
async fn a_refused_upgrade_is_a_credential_failure_that_stops_the_retrying() {
    // Review #1: a gateway refusing the ticket at the upgrade (HTTP 403) is a
    // permanent credential failure, not a transient dial error.
    let harness = Harness::start(HarnessOptions::default()).await;
    *harness.gateway.handshake_status.lock().expect("status") = Some(403);
    harness.activate().await;
    wait_until(
        || {
            harness.audit.count(&StreamAuditKind::NeedsAdministrator {
                reason: "handshake_unauthorized",
            }) == 1
        },
        "the administrator flag",
    )
    .await;
    assert_eq!(
        harness.egress.call_count(),
        3,
        "threshold of three refusals"
    );
    for consecutive in 1..=3 {
        assert_eq!(
            harness
                .audit
                .count(&StreamAuditKind::AuthFailed { consecutive }),
            1
        );
    }
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(harness.egress.call_count(), 3, "no further connect calls");
    assert_eq!(
        harness
            .gateway
            .handshakes
            .load(std::sync::atomic::Ordering::SeqCst),
        3,
        "no further dials"
    );
}

#[tokio::test]
async fn a_transient_connect_failure_between_refusals_resets_the_refusal_count() {
    let harness = Harness::start(HarnessOptions::default()).await;
    for step in [
        ConnectScript::Status(401),
        ConnectScript::Status(401),
        ConnectScript::Status(503),
        ConnectScript::Status(401),
        ConnectScript::Status(401),
    ] {
        harness.egress.push(step);
    }
    harness.egress.set_default(ConnectScript::Grant);
    harness.activate().await;

    connected(&harness, 1).await;
    assert_eq!(
        harness.audit.count(&StreamAuditKind::NeedsAdministrator {
            reason: "connect_unauthorized"
        }),
        0
    );
}

#[tokio::test]
async fn frames_queued_when_the_connection_ends_are_not_admitted_afterwards() {
    let harness = started_and_active(HarnessOptions {
        config: config_with(|config| {
            config.backoff.initial = Duration::from_secs(5);
            config.backoff.max = Duration::from_secs(5);
        }),
        ..HarnessOptions::default()
    })
    .await;
    harness
        .sink
        .script
        .lock()
        .expect("script")
        .delay
        .insert("Ev-1".to_string(), Duration::from_millis(300));
    connected(&harness, 1).await;

    harness
        .gateway
        .send_to_latest(event_frame("F-1", "Ev-1", "C-1"));
    harness
        .gateway
        .send_to_latest(event_frame("F-2", "Ev-2", "C-1"));
    wait_until(
        || harness.sink.attempts.lock().expect("attempts").len() == 1,
        "Ev-1 in flight",
    )
    .await;
    harness.gateway.close_latest();
    tokio::time::sleep(Duration::from_millis(600)).await;

    assert_eq!(
        *harness.sink.attempts.lock().expect("attempts"),
        vec!["Ev-1".to_string()],
        "Ev-2 was queued behind Ev-1 when the connection ended: it is never admitted for a dead connection"
    );
    assert_eq!(
        harness.gateway.ack_count(),
        0,
        "neither frame was acknowledged"
    );
}

#[tokio::test]
async fn a_slow_acknowledgement_raises_an_audit_signal() {
    let harness = started_and_active(HarnessOptions {
        config: config_with(|config| config.ack_latency_warn = Duration::from_millis(50)),
        ..HarnessOptions::default()
    })
    .await;
    harness
        .sink
        .script
        .lock()
        .expect("script")
        .delay
        .insert("Ev-1".to_string(), Duration::from_millis(150));
    connected(&harness, 1).await;

    harness
        .gateway
        .send_to_latest(event_frame("F-1", "Ev-1", "C-1"));
    wait_until(|| harness.gateway.ack_count() == 1, "the ACK").await;

    assert!(
        harness
            .audit
            .kinds()
            .iter()
            .any(|kind| matches!(kind, StreamAuditKind::SlowAck { millis } if *millis >= 50))
    );
}

#[tokio::test]
async fn a_failed_acknowledgement_after_admission_reconnects_without_a_second_admission() {
    // Review #3: the ACK exceeds the outbound frame bound, so it cannot be
    // sent after the durable commit. The connection must not stay "healthy".
    let harness = started_and_active(HarnessOptions {
        manifest: manifest_with(&[("max_frame_bytes = 262144", "max_frame_bytes = 1024")]),
        ..HarnessOptions::default()
    })
    .await;
    connected(&harness, 1).await;
    let mut frame: serde_json::Value =
        serde_json::from_str(&event_frame("F-1", "Ev-1", "C-1")).expect("frame");
    frame["ack_pad"] = serde_json::json!(4096);
    harness.gateway.send_to_latest(frame.to_string());
    connected(&harness, 2).await;
    assert_eq!(harness.sink.admitted_events(), vec!["Ev-1"]);
    assert_eq!(
        harness.sink.attempts.lock().expect("attempts").len(),
        1,
        "the committed admission is not repeated"
    );
    assert_eq!(harness.gateway.ack_count(), 0);
    assert!(
        harness
            .audit
            .kinds()
            .contains(&StreamAuditKind::Disconnected {
                reason: "send_failed"
            })
    );
    assert_eq!(
        harness.egress.call_count(),
        2,
        "a fresh grant per connection"
    );
}

#[tokio::test]
async fn a_persistent_acknowledgement_failure_keeps_escalating_the_reconnect_delay() {
    // Review (ACK failure resets backoff): a frame that decodes but whose ACK
    // cannot be sent is not a healthy connection, so the delay must not reset.
    let harness = started_and_active(HarnessOptions {
        manifest: manifest_with(&[("max_frame_bytes = 262144", "max_frame_bytes = 1024")]),
        config: config_with(|config| {
            config.backoff = BackoffPolicy {
                initial: Duration::from_millis(100),
                max: Duration::from_millis(800),
                jitter_fraction: 0.0,
            };
        }),
        ..HarnessOptions::default()
    })
    .await;
    connected(&harness, 1).await;
    for (round, n) in [(2usize, 1usize), (3, 2), (4, 3)] {
        let mut frame: serde_json::Value =
            serde_json::from_str(&event_frame(&format!("F-{n}"), &format!("Ev-{n}"), "C-1"))
                .expect("frame");
        frame["ack_pad"] = serde_json::json!(4096);
        harness.gateway.send_to_latest(frame.to_string());
        connected(&harness, round).await;
    }
    let times = harness.egress.call_times();
    let gaps: Vec<u128> = times
        .windows(2)
        .map(|w| (w[1] - w[0]).as_millis())
        .collect();
    assert!(
        gaps[2] >= gaps[0] + 80,
        "ACK failures keep escalating the delay: {gaps:?}"
    );
}
async fn assert_control_panic_is_contained(frame: serde_json::Value) {
    let harness = started_and_active(HarnessOptions::default()).await;
    connected(&harness, 1).await;
    harness.gateway.send_to_latest(frame.to_string());
    // The connection ends with a fixed reason and a new one is made.
    connected(&harness, 2).await;
    let kinds = harness.audit.kinds();
    assert!(kinds.contains(&StreamAuditKind::FrameRejected {
        reason: "control_panicked"
    }));
    assert!(kinds.contains(&StreamAuditKind::Disconnected {
        reason: "control_panicked"
    }));
    let status = harness.statuses.get(EXTENSION_ID).expect("status");
    assert_eq!(status.last_error, Some("control_panicked"));
    assert!(
        !harness.audit.rendered().contains("SECRET-IN-PANIC"),
        "no panic text reaches the audit"
    );
    assert_eq!(harness.sink.attempts.lock().expect("attempts").len(), 0);
}

#[tokio::test]
async fn a_panicking_decode_ends_the_connection_with_a_fixed_reason_and_reconnects() {
    // Review #4.
    assert_control_panic_is_contained(serde_json::json!({
        "kind": "event", "frame_id": "F-1", "panic": "decode",
    }))
    .await;
}

#[tokio::test]
async fn a_panicking_session_key_ends_the_connection_with_a_fixed_reason_and_reconnects() {
    // Review #4.
    let mut frame: serde_json::Value =
        serde_json::from_str(&event_frame("F-1", "Ev-1", "C-1")).expect("frame");
    frame["payload"]["panic_key"] = serde_json::json!(true);
    assert_control_panic_is_contained(frame).await;
}

#[tokio::test]
async fn a_connection_task_that_dies_is_reported_and_does_not_hold_a_false_connected_state() {
    // Review #4: a fault outside the frame-control callbacks (here a panicking
    // audit sink) must not leave the last projected state at `Connected`.
    let mut harness = Harness::start(HarnessOptions {
        start_supervisor: false,
        ..HarnessOptions::default()
    })
    .await;
    harness
        .audit
        .panic_on_connected
        .store(true, std::sync::atomic::Ordering::SeqCst);
    harness.spawn_supervisor();
    harness.activate().await;
    wait_until(
        || {
            harness.audit.count(&StreamAuditKind::NeedsAdministrator {
                reason: "connection_task_panicked",
            }) == 1
        },
        "the task failure report",
    )
    .await;
    assert_eq!(
        harness.statuses.get(EXTENSION_ID).map(|s| s.state),
        Some(StreamConnectionState::NeedsAdministrator)
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        harness
            .gateway
            .accepts
            .load(std::sync::atomic::Ordering::SeqCst),
        1,
        "a faulted task is not respawned in a loop"
    );
}

/// Two frames fit the connection (executing + queued); the reader decodes one
/// more and then waits for room, so a stalled admission stops the socket reads.
async fn saturated_connection() -> Harness {
    let harness = started_and_active(HarnessOptions {
        config: config_with(|config| {
            config.max_pending_frames = 2;
            config.max_pending_per_session = 2;
        }),
        ..HarnessOptions::default()
    })
    .await;
    harness
        .sink
        .script
        .lock()
        .expect("script")
        .delay
        .insert("Ev-1".to_string(), Duration::from_millis(1500));
    connected(&harness, 1).await;
    for index in 1..=6 {
        harness.gateway.send_to_latest(event_frame(
            &format!("F-{index}"),
            &format!("Ev-{index}"),
            "C-1",
        ));
    }
    wait_until(
        || harness.sink.attempts.lock().expect("attempts").len() == 1,
        "the first admission to stall",
    )
    .await;
    harness
}

#[tokio::test]
async fn a_full_connection_stops_reading_and_every_frame_is_still_admitted_in_order() {
    // Back-pressure at the host layer: the reader waits instead of buffering
    // or dropping, then resumes when the stalled admission completes.
    let harness = saturated_connection().await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        harness.decoded.load(std::sync::atomic::Ordering::SeqCst),
        3,
        "two frames pending plus the one the reader holds; the rest stay in the socket"
    );
    wait_until(|| harness.gateway.ack_count() == 6, "six ACKs").await;
    assert_eq!(
        harness.sink.admitted_events(),
        vec!["Ev-1", "Ev-2", "Ev-3", "Ev-4", "Ev-5", "Ev-6"]
    );
    assert_eq!(
        harness.gateway.ack_texts(),
        (1..=6)
            .map(|index| ack_text(&format!("F-{index}")))
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn closing_a_saturated_connection_finishes_the_in_flight_frame_and_leaves_the_rest_unacknowledged()
 {
    let harness = saturated_connection().await;
    // The reader is parked waiting for room; the stop must reach it there.
    let started = Instant::now();
    harness
        .supervisor
        .as_ref()
        .expect("supervisor")
        .shutdown()
        .await;
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "shutdown is not held up by the full queue: {:?}",
        started.elapsed()
    );
    assert_eq!(harness.sink.admitted_events(), vec!["Ev-1"]);
    wait_until(
        || {
            harness
                .gateway
                .closed
                .load(std::sync::atomic::Ordering::SeqCst)
                == 1
        },
        "the socket to close",
    )
    .await;
    assert_eq!(
        harness.gateway.ack_texts(),
        vec![ack_text("F-1")],
        "queued frames were never admitted, so none is acknowledged"
    );
}
