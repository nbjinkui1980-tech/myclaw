//! Stream supervisor lifecycle contract tests (stream-ingress Task 8).
//!
//! Connections follow the extension's activation: activate starts one,
//! deactivate/remove stops it, a re-activation (what a credential change
//! triggers) replaces it, boot restoration reconnects an already-active
//! installation, and the connection cap and graceful shutdown are bounded.
//! The second half goes through the REAL `GenericChannelHostAssembly`, so the
//! stream channel's sealed evidence and admission graph are the production
//! ones, with only product admission recorded.
mod stream_support;

use std::sync::atomic::Ordering;
use std::time::Duration;

use ironclaw_extension_host::stream_supervisor::{
    StreamAuditKind, StreamConnectionState, StreamSupervisorConfig,
};
use stream_support::assembly::AssemblyHarness;
use stream_support::*;

async fn connected(harness: &Harness, connections: usize) {
    wait_until(
        || harness.audit.count(&StreamAuditKind::Connected) == connections,
        "connection",
    )
    .await;
}

fn fast_config() -> StreamSupervisorConfig {
    HarnessOptions::default().config
}

#[tokio::test]
async fn activation_starts_a_connection_and_deactivation_closes_it_for_good() {
    let harness = Harness::start(HarnessOptions::default()).await;
    assert_eq!(
        harness.gateway.accepts.load(Ordering::SeqCst),
        0,
        "nothing active, nothing dialed"
    );

    harness.activate().await;
    connected(&harness, 1).await;

    harness
        .host
        .deactivate(EXTENSION_ID)
        .await
        .expect("deactivate");
    wait_until(
        || harness.gateway.closed.load(Ordering::SeqCst) == 1,
        "the socket to close",
    )
    .await;
    assert_eq!(harness.audit.count(&StreamAuditKind::Stopped), 1);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        harness.gateway.accepts.load(Ordering::SeqCst),
        1,
        "a deactivated installation is never redialed"
    );
}

#[tokio::test]
async fn reactivation_replaces_the_connection_and_asks_for_a_fresh_grant() {
    let harness = Harness::start(HarnessOptions::default()).await;
    harness.activate().await;
    connected(&harness, 1).await;

    // What `ChannelConfigService::save` triggers after a credential change.
    harness
        .host
        .deactivate(EXTENSION_ID)
        .await
        .expect("deactivate");
    harness.host.activate(EXTENSION_ID).await.expect("activate");
    connected(&harness, 2).await;

    assert_eq!(
        harness.egress.call_count(),
        2,
        "the new connection asked for its own grant"
    );
    wait_until(
        || harness.gateway.closed.load(Ordering::SeqCst) == 1,
        "the old socket to close",
    )
    .await;
    harness
        .gateway
        .send_to_latest(event_frame("F-1", "Ev-1", "C-1"));
    wait_until(
        || harness.gateway.ack_count() == 1,
        "service on the new connection",
    )
    .await;
}

#[tokio::test]
async fn an_installation_active_before_the_supervisor_starts_is_connected_at_boot() {
    let mut harness = Harness::start(HarnessOptions {
        start_supervisor: false,
        ..HarnessOptions::default()
    })
    .await;
    harness.activate().await;
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(harness.gateway.accepts.load(Ordering::SeqCst), 0);

    harness.spawn_supervisor();
    connected(&harness, 1).await;
    harness
        .gateway
        .send_to_latest(event_frame("F-1", "Ev-1", "C-1"));
    wait_until(|| harness.gateway.ack_count() == 1, "the ACK").await;
}

#[tokio::test]
async fn a_new_activation_after_the_administrator_flag_connects_again() {
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

    // The administrator fixes the credential: save -> reactivation.
    harness.egress.set_default(ConnectScript::Grant);
    harness
        .host
        .deactivate(EXTENSION_ID)
        .await
        .expect("deactivate");
    harness.host.activate(EXTENSION_ID).await.expect("activate");
    connected(&harness, 1).await;
}

/// A deployment-bound channel keeps one source for the process, so a
/// republished snapshot never restarts it: only the administrator
/// configuration signal does.
#[tokio::test]
async fn a_configuration_change_restarts_a_deployment_stream_that_needs_an_administrator() {
    let harness = Harness::start(HarnessOptions {
        deployment: true,
        ..HarnessOptions::default()
    })
    .await;
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
    // The working credential alone restarts nothing: a later reconcile pass
    // (the fence) leaves the stopped connection stopped.
    harness.egress.set_default(ConnectScript::Grant);
    let refusals = harness.egress.call_count();
    reconcile_fence(&harness, "acme-fence-one").await;
    assert_eq!(
        harness
            .audit
            .count_for(EXTENSION_ID, &StreamAuditKind::Connected),
        0,
        "without the signal the stopped connection stays stopped"
    );
    assert_eq!(
        harness.egress.call_count(),
        refusals + 1,
        "only the fence dialed"
    );

    // The administrator saves the credential: the save signals the change.
    harness.changes.notify(EXTENSION_ID);
    wait_until(
        || {
            harness
                .audit
                .count_for(EXTENSION_ID, &StreamAuditKind::Connected)
                == 1
        },
        "the restarted connection",
    )
    .await;
    harness
        .gateway
        .send_to_latest(event_frame("F-1", "Ev-1", "C-1"));
    wait_until(|| harness.gateway.ack_count() == 1, "the ACK").await;
}

/// Activates another stream extension and waits for its connection. The
/// supervisor serializes reconcile passes, and the pass that dials the new
/// extension checks every running connection against the current
/// configuration generation first, so a change signalled before the fence
/// has been acted on once the fence connects.
async fn reconcile_fence(harness: &Harness, fence_id: &str) {
    harness.activate_other(fence_id).await;
    wait_until(
        || {
            harness
                .audit
                .count_for(fence_id, &StreamAuditKind::Connected)
                == 1
        },
        "the fence connection",
    )
    .await;
}

/// An active-sourced stream already restarts with the re-published snapshot;
/// the signal must not restart it a second time.
#[tokio::test]
async fn a_configuration_change_does_not_restart_an_active_stream_twice() {
    let harness = Harness::start(HarnessOptions::default()).await;
    harness.activate().await;
    connected(&harness, 1).await;
    harness.changes.notify(EXTENSION_ID);
    reconcile_fence(&harness, "acme-fence-one").await;

    assert_eq!(
        harness
            .audit
            .count_for(EXTENSION_ID, &StreamAuditKind::Connected),
        1,
        "the signal did not reconnect the active-sourced stream"
    );
    assert_eq!(
        harness.audit.count(&StreamAuditKind::Stopped),
        0,
        "nothing was stopped"
    );
    assert_eq!(
        harness.gateway.closed.load(Ordering::SeqCst),
        0,
        "no socket closed"
    );
    assert_eq!(harness.egress.call_count(), 2, "one grant per extension");
}

#[tokio::test]
async fn the_connection_limit_holds_and_a_freed_slot_is_used() {
    let harness = Harness::start(HarnessOptions {
        config: StreamSupervisorConfig {
            max_connections: 1,
            ..fast_config()
        },
        ..HarnessOptions::default()
    })
    .await;
    harness.activate().await;
    connected(&harness, 1).await;
    harness.activate_other("acme-two").await;

    wait_until(
        || {
            harness.audit.count(&StreamAuditKind::NeedsAdministrator {
                reason: "connection_limit",
            }) == 1
        },
        "the limit report",
    )
    .await;
    assert_eq!(
        harness.gateway.accepts.load(Ordering::SeqCst),
        1,
        "only one live connection"
    );

    // Freeing the slot lets the waiting installation connect on the next reconcile.
    harness
        .host
        .deactivate(EXTENSION_ID)
        .await
        .expect("deactivate");
    connected(&harness, 2).await;
    assert_eq!(harness.gateway.accepts.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn shutdown_lets_an_in_flight_frame_finish_and_closes_the_connection() {
    let harness = Harness::start(HarnessOptions::default()).await;
    harness
        .sink
        .script
        .lock()
        .expect("script")
        .delay
        .insert("Ev-1".to_string(), Duration::from_millis(250));
    harness.activate().await;
    connected(&harness, 1).await;
    harness
        .gateway
        .send_to_latest(event_frame("F-1", "Ev-1", "C-1"));
    wait_until(
        || harness.sink.attempts.lock().expect("attempts").len() == 1,
        "the frame to be in the pipeline",
    )
    .await;

    harness
        .supervisor
        .as_ref()
        .expect("supervisor")
        .shutdown()
        .await;

    assert_eq!(
        harness.sink.admitted_events(),
        vec!["Ev-1".to_string()],
        "the frame already inside the pipeline committed before shutdown returned"
    );
    wait_until(
        || harness.gateway.closed.load(Ordering::SeqCst) == 1,
        "the socket to close",
    )
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        harness.gateway.accepts.load(Ordering::SeqCst),
        1,
        "no reconnect after shutdown"
    );
}

// ── Through the real channel host assembly ──────────────────────────────────

#[tokio::test]
async fn an_activated_stream_channel_reaches_product_admission_with_stream_evidence() {
    let harness = AssemblyHarness::start(fast_config()).await;
    harness.activate().await;
    wait_until(
        || harness.audit.count(&StreamAuditKind::Connected) == 1,
        "connection",
    )
    .await;
    assert!(
        harness.ingress.registry.is_registered(EXTENSION_ID),
        "the assembly registered the stream channel's graph"
    );

    harness
        .gateway
        .send_to_latest(event_frame("F-1", "Ev-1", "C-1"));
    wait_until(|| harness.gateway.ack_count() == 1, "the ACK").await;

    // Persist-before-ACK at the product-admission seam.
    assert_eq!(
        *harness.log.lock().expect("log"),
        vec![
            "surface:Ev-1".to_string(),
            format!("ack:{}", ack_text("F-1"))
        ]
    );
    let contexts = harness.surface.contexts.lock().expect("contexts");
    assert_eq!(contexts.len(), 1);
    // The sealed claim describes connection-level authentication; its subject
    // and the admission's installation are the connection owner's.
    assert!(
        contexts[0].contains("AuthenticatedStream"),
        "{}",
        contexts[0]
    );
    assert!(contexts[0].contains("connect"), "{}", contexts[0]);
    assert!(contexts[0].contains(INSTALLATION_ID), "{}", contexts[0]);
    assert!(
        !contexts[0].contains(TICKET),
        "no ticket in evidence: {}",
        contexts[0]
    );
    assert_eq!(
        *harness.surface.installations.lock().expect("installations"),
        vec![INSTALLATION_ID.to_string()]
    );
}

#[tokio::test]
async fn saving_channel_config_reactivates_and_reconnects_through_the_host() {
    let harness = AssemblyHarness::start(fast_config()).await;
    harness.activate().await;
    wait_until(
        || harness.audit.count(&StreamAuditKind::Connected) == 1,
        "connection",
    )
    .await;

    // The real configure service: a changed secret reactivates the extension.
    harness
        .channel_config
        .save(
            &ironclaw_host_api::ids::ExtensionId::new(EXTENSION_ID).expect("id"),
            vec![("acme_client_secret".to_string(), "secret-2".to_string())],
        )
        .await
        .expect("save");
    wait_until(
        || harness.audit.count(&StreamAuditKind::Connected) == 2,
        "reconnection",
    )
    .await;

    assert_eq!(harness.egress.call_count(), 2);
    harness
        .gateway
        .send_to_latest(event_frame("F-1", "Ev-1", "C-1"));
    wait_until(
        || harness.gateway.ack_count() == 1,
        "the ACK on the new connection",
    )
    .await;
}

#[tokio::test]
async fn deactivating_unregisters_the_graph_and_stops_the_connection() {
    let harness = AssemblyHarness::start(fast_config()).await;
    harness.activate().await;
    wait_until(
        || harness.audit.count(&StreamAuditKind::Connected) == 1,
        "connection",
    )
    .await;

    harness
        .host
        .deactivate(EXTENSION_ID)
        .await
        .expect("deactivate");

    wait_until(
        || harness.gateway.closed.load(Ordering::SeqCst) == 1,
        "the socket to close",
    )
    .await;
    wait_until(
        || !harness.ingress.registry.is_registered(EXTENSION_ID),
        "the registration to be removed",
    )
    .await;
}

// ── Task 9: connection state for the lifecycle projection ───────────────────

#[tokio::test]
async fn connection_state_follows_the_real_supervisor_and_clears_when_stopped() {
    let harness = Harness::start(HarnessOptions {
        // Slow the retry so the reconnecting state is observable.
        config: StreamSupervisorConfig {
            backoff: ironclaw_extension_host::stream_supervisor::BackoffPolicy {
                initial: Duration::from_millis(600),
                max: Duration::from_millis(600),
                jitter_fraction: 0.0,
            },
            ..fast_config()
        },
        ..HarnessOptions::default()
    })
    .await;
    harness.activate().await;
    connected(&harness, 1).await;
    let status = harness.statuses.get(EXTENSION_ID).expect("status");
    assert_eq!(status.state, StreamConnectionState::Connected);
    assert_eq!(status.last_error, None);

    harness.gateway.close_latest();
    wait_until(
        || {
            harness
                .statuses
                .get(EXTENSION_ID)
                .is_some_and(|s| s.state == StreamConnectionState::Reconnecting)
        },
        "the reconnecting state",
    )
    .await;
    connected(&harness, 2).await;
    assert_eq!(
        harness.statuses.get(EXTENSION_ID).map(|s| s.state),
        Some(StreamConnectionState::Connected)
    );

    harness
        .host
        .deactivate(EXTENSION_ID)
        .await
        .expect("deactivate");
    wait_until(
        || harness.statuses.get(EXTENSION_ID).is_none(),
        "the entry to clear",
    )
    .await;
}

#[tokio::test]
async fn refused_credentials_end_as_needs_administrator_with_a_redacted_reason() {
    let harness = Harness::start(HarnessOptions::default()).await;
    harness.egress.set_default(ConnectScript::Status(401));
    harness.activate().await;

    wait_until(
        || {
            harness
                .statuses
                .get(EXTENSION_ID)
                .is_some_and(|s| s.state == StreamConnectionState::NeedsAdministrator)
        },
        "the administrator state",
    )
    .await;
    let status = harness.statuses.get(EXTENSION_ID).expect("status");
    assert_eq!(status.last_error, Some("connect_unauthorized"));
    assert!(status.last_error_at.is_some());
    let rendered = format!("{status:?}");
    for forbidden in ["TICKET", "ticket=", "wss://", GATEWAY_HOST, "secret"] {
        assert!(!rendered.contains(forbidden), "{forbidden} in {rendered}");
    }
}

// ── Review #5: bounded, concurrent stops ────────────────────────────────────

/// Two active installations; the first is stuck in a slow admission.
async fn one_stuck_one_idle(stop_timeout: Duration) -> Harness {
    let harness = Harness::start(HarnessOptions {
        config: StreamSupervisorConfig {
            stop_timeout,
            ..fast_config()
        },
        ..HarnessOptions::default()
    })
    .await;
    harness
        .sink
        .script
        .lock()
        .expect("script")
        .delay
        .insert("Ev-1".to_string(), Duration::from_secs(8));
    harness.activate().await;
    connected(&harness, 1).await;
    harness
        .gateway
        .send_to_latest(event_frame("F-1", "Ev-1", "C-1"));
    wait_until(
        || harness.sink.attempts.lock().expect("attempts").len() == 1,
        "the frame to be stuck in the pipeline",
    )
    .await;
    harness.activate_other("acme-two").await;
    connected(&harness, 2).await;
    harness
}

fn stopped(harness: &Harness, extension_id: &str) -> bool {
    harness
        .audit
        .events
        .lock()
        .expect("events")
        .iter()
        .any(|e| e.extension_id == extension_id && e.kind == StreamAuditKind::Stopped)
}

#[tokio::test]
async fn a_stuck_connection_neither_delays_another_stop_nor_outlives_the_stop_timeout() {
    let harness = one_stuck_one_idle(Duration::from_millis(900)).await;
    let supervisor = std::sync::Arc::clone(harness.supervisor.as_ref().expect("supervisor"));
    let started = std::time::Instant::now();
    let shutdown = tokio::spawn(async move { supervisor.shutdown().await });
    // The idle connection stops right away; it is not queued behind the stuck one.
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(
        stopped(&harness, "acme-two"),
        "the idle connection was stopped while the stuck one was still draining"
    );
    assert!(
        !stopped(&harness, EXTENSION_ID),
        "the stuck one is still draining"
    );
    shutdown.await.expect("shutdown");
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "shutdown is bounded by the stop timeout, not the 8 s admission: {:?}",
        started.elapsed()
    );
    assert!(stopped(&harness, EXTENSION_ID));
    assert_eq!(harness.audit.count(&StreamAuditKind::StopForced), 1);
    assert_eq!(harness.statuses.get(EXTENSION_ID), None);
}

#[tokio::test]
async fn a_stuck_stop_is_bounded_by_stop_timeout_and_never_blocks_an_unrelated_activation_forever()
{
    let harness = one_stuck_one_idle(Duration::from_millis(500)).await;
    harness
        .host
        .deactivate(EXTENSION_ID)
        .await
        .expect("deactivate");
    harness.activate_other("acme-three").await;
    tokio::time::timeout(Duration::from_secs(3), connected(&harness, 3))
        .await
        .expect("the unrelated activation connected within the stop timeout");
    assert_eq!(harness.audit.count(&StreamAuditKind::StopForced), 1);
}

#[tokio::test]
async fn a_dropped_supervisor_leaves_no_connected_state_behind() {
    // Review #6: the status cache outlives the supervisor, so dropping one
    // without `shutdown` must not leave its last `Connected` entry.
    let mut harness = Harness::start(HarnessOptions::default()).await;
    harness.activate().await;
    connected(&harness, 1).await;
    assert_eq!(
        harness.statuses.get(EXTENSION_ID).map(|s| s.state),
        Some(StreamConnectionState::Connected)
    );
    drop(harness.supervisor.take());
    assert_eq!(harness.statuses.get(EXTENSION_ID), None);
    assert!(stopped(&harness, EXTENSION_ID));
}

#[tokio::test]
async fn a_connection_that_gives_up_frees_its_slot_for_a_queued_installation_without_a_publication()
{
    // Review #10: the first installation exits on its own (credentials refused
    // three times in a row); nothing is published, yet the installation parked
    // by the connection limit must connect.
    let harness = Harness::start(HarnessOptions {
        config: StreamSupervisorConfig {
            max_connections: 1,
            ..fast_config()
        },
        ..HarnessOptions::default()
    })
    .await;
    harness.activate().await;
    connected(&harness, 1).await;
    harness.activate_other("acme-two").await;
    wait_until(
        || {
            harness.audit.count(&StreamAuditKind::NeedsAdministrator {
                reason: "connection_limit",
            }) == 1
        },
        "the limit report",
    )
    .await;
    // From here on no lifecycle change happens. The next three connect calls
    // are refused, which ends the first installation's task.
    for _ in 0..3 {
        harness.egress.push(ConnectScript::Status(401));
    }
    harness.gateway.close_latest();
    wait_until(
        || {
            harness.audit.count(&StreamAuditKind::NeedsAdministrator {
                reason: "connect_unauthorized",
            }) == 1
        },
        "the first installation to give up",
    )
    .await;
    connected(&harness, 2).await;
    assert_eq!(
        harness.statuses.get("acme-two").map(|s| s.state),
        Some(StreamConnectionState::Connected)
    );
}
