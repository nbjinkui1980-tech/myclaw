//! The generic stream-ingress supervisor.
//!
//! For every active installation whose channel declares
//! `[channel.ingress.stream]`, the supervisor keeps one outbound connection:
//! it runs the declared connect call through the channel's restricted egress,
//! dials the granted endpoint through the policy-checked network connector,
//! reads vendor frames, and hands each delivered frame to the same shared
//! admission pipeline webhook requests use. Nothing here names a vendor; the
//! frame protocol is the bound [`ChannelStreamControl`], and the evidence the
//! admitted frame carries is minted by the host's single
//! `ChannelIngressVerifier` for the installation that owns the connection.
//!
//! [`ChannelStreamControl`]: ironclaw_extension_contracts::channel_adapter::ChannelStreamControl
mod audit;
mod changes;
mod connect;
mod connection;
mod rate;
mod session;
mod source;
mod status;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use ironclaw_host_api::resource::ResourceScope;
use ironclaw_network::WebSocketConnector;
use tokio::sync::watch;

pub use audit::{
    FanoutStreamAudit, StreamAuditEvent, StreamAuditKind, StreamAuditSink, TracingStreamAudit,
};
pub use changes::{StreamConfigurationChanges, StreamRestartingReactivation};
pub use rate::BackoffPolicy;
pub use status::{StreamConnectionState, StreamConnectionStatus, StreamConnectionStatuses};

use crate::active::ActiveSnapshot;
use crate::deployment_channels::DeploymentChannelRegistry;
use crate::ingress::StreamAdmission;
use crate::lifecycle::SnapshotWatch;

use connect::ConnectFailureKind;
use connection::{ConnectOutcome, ConnectionContext, EndReason, run_connection};
use rate::Backoff;
use source::StreamSource;

/// Bounds and timings of the supervisor. Defaults are the ADR's conservative
/// choices; the vendor's real ACK window and redelivery policy are unverified
/// (ADR 5.4, 8 items 2-3), so none of these is a vendor promise.
#[derive(Debug, Clone)]
pub struct StreamSupervisorConfig {
    /// Budget for the connect call (not the WebSocket dial).
    pub connect_deadline: Duration,
    /// Budget for one frame's trip through the shared admission pipeline.
    pub admission_deadline: Duration,
    /// Reconnect delay: exponential with jitter, reset only after a frame the
    /// stream control accepted.
    pub backoff: BackoffPolicy,
    /// Consecutive credential refusals (or declaration/endpoint rejections)
    /// after which retrying stops and an administrator has to act. A changed
    /// credential starts a fresh connection (a re-activation for an active
    /// source, a configuration-change signal for a deployment source).
    pub auth_failure_threshold: u32,
    /// Live connections the supervisor keeps at once. An installation over the
    /// limit is reported as `NeedsAdministrator` and retried as soon as a
    /// slot frees (a stopped connection, or one that gave up).
    pub max_connections: usize,
    /// Admissions running at once across every connection.
    pub max_concurrent_admissions: usize,
    /// Frames queued or executing on one connection; when full the reader
    /// stops reading from the socket.
    pub max_pending_frames: usize,
    /// Frames queued behind one session key; kept below `max_pending_frames`
    /// so one slow session cannot occupy the whole connection.
    pub max_pending_per_session: usize,
    /// How long stopping one connection may take (it lets an in-flight frame
    /// finish) before the task is aborted and the stop is reported as forced.
    pub stop_timeout: Duration,
    /// Receipt-to-ACK time that raises a `SlowAck` event. Provisional and well
    /// under the 10 s HTTP timeout the vendor's own SDK uses; the vendor's real
    /// ACK window is unverified (ADR 5.4).
    pub ack_latency_warn: Duration,
}

impl Default for StreamSupervisorConfig {
    fn default() -> Self {
        Self {
            connect_deadline: Duration::from_secs(15),
            admission_deadline: Duration::from_secs(20),
            backoff: BackoffPolicy::default(),
            auth_failure_threshold: 3,
            max_connections: 16,
            max_concurrent_admissions: 8,
            max_pending_frames: 64,
            max_pending_per_session: 8,
            stop_timeout: Duration::from_secs(30),
            ack_latency_warn: Duration::from_secs(5),
        }
    }
}

/// Everything the supervisor is composed from.
pub struct StreamSupervisorDeps {
    pub watch: SnapshotWatch,
    pub deployment_channels: Arc<DeploymentChannelRegistry>,
    /// The shared admission pipeline, taken from the ingress router so both
    /// transports admit through one implementation.
    pub admission: StreamAdmission,
    /// The one policy-checked WebSocket port (production:
    /// `PolicyWebSocketConnector<TungsteniteWebSocketTransport>`).
    pub connector: Arc<dyn WebSocketConnector>,
    pub scope: ResourceScope,
    pub audit: Arc<dyn StreamAuditSink>,
    /// Administrator configuration changes; a change restarts the extension's
    /// deployment-sourced connection (an active-sourced one restarts with the
    /// re-published snapshot).
    pub configuration_changes: Arc<StreamConfigurationChanges>,
}

/// Cooperative stop signal shared with a connection task.
#[derive(Clone)]
pub(crate) struct Cancel(watch::Receiver<bool>);

impl Cancel {
    pub(crate) fn is_cancelled(&self) -> bool {
        *self.0.borrow()
    }

    pub(crate) async fn cancelled(&mut self) {
        // A dropped sender also means "stop".
        _ = self.0.wait_for(|stopped| *stopped).await;
    }
}

struct RunningConnection {
    source: StreamSource,
    /// The extension's configuration generation when the task started.
    generation: u64,
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
    /// Set by the task just before it signals `task_ended`, so the pass that
    /// signal triggers never sees the slot as still taken while the task is
    /// only moments from finishing.
    ended: Arc<AtomicBool>,
}

impl RunningConnection {
    fn is_live(&self) -> bool {
        !self.ended.load(Ordering::SeqCst) && !self.task.is_finished()
    }
}

/// Owns one reconcile loop and the connection tasks it starts.
pub struct StreamSupervisor {
    deps: StreamSupervisorDeps,
    config: StreamSupervisorConfig,
    admissions: Arc<tokio::sync::Semaphore>,
    running: tokio::sync::Mutex<HashMap<String, RunningConnection>>,
    /// Sources already reported as over the connection limit, so a retry on
    /// every publication does not repeat the event.
    limited: StdMutex<HashMap<String, StreamSource>>,
    reconcile_loop: StdMutex<Option<tokio::task::JoinHandle<()>>>,
    /// Held for one whole reconcile pass, so `shutdown` can wait for a pass
    /// that already took connections out of `running` to finish stopping them
    /// instead of aborting it and orphaning them.
    reconcile_gate: tokio::sync::Mutex<()>,
    /// Set by `shutdown`; a pass that starts afterwards does nothing.
    closing: AtomicBool,
    /// Signalled whenever a connection task ends, so a slot it frees (an
    /// installation that gave up) reaches the sources parked by the connection
    /// limit without waiting for an unrelated publication.
    task_ended: Arc<tokio::sync::Notify>,
}

impl StreamSupervisor {
    /// Reconcile the current snapshot, then keep reconciling on every
    /// publication. The loop holds only a weak handle: dropping the returned
    /// `Arc` ends it.
    pub fn start(deps: StreamSupervisorDeps, config: StreamSupervisorConfig) -> Arc<Self> {
        let mut subscription = deps.watch.subscribe();
        let mut changes = deps.configuration_changes.subscribe();
        let supervisor = Arc::new(Self {
            deps,
            admissions: Arc::new(tokio::sync::Semaphore::new(
                config.max_concurrent_admissions.max(1),
            )),
            config,
            running: tokio::sync::Mutex::new(HashMap::new()),
            limited: StdMutex::new(HashMap::new()),
            reconcile_loop: StdMutex::new(None),
            reconcile_gate: tokio::sync::Mutex::new(()),
            closing: AtomicBool::new(false),
            task_ended: Arc::new(tokio::sync::Notify::new()),
        });
        let task_ended = Arc::clone(&supervisor.task_ended);
        let weak = Arc::downgrade(&supervisor);
        let handle = tokio::spawn(async move {
            loop {
                {
                    let Some(supervisor) = weak.upgrade() else {
                        break;
                    };
                    supervisor.reconcile().await;
                }
                tokio::select! {
                    changed = subscription.changed() => {
                        if changed.is_err() {
                            break;
                        }
                    }
                    changed = changes.changed() => {
                        if changed.is_err() {
                            break;
                        }
                    }
                    () = task_ended.notified() => {}
                }
            }
        });
        if let Ok(mut slot) = supervisor.reconcile_loop.lock() {
            *slot = Some(handle);
        }
        supervisor
    }

    fn desired(&self) -> HashMap<String, StreamSource> {
        let mut desired = HashMap::new();
        for extension_id in self.deps.deployment_channels.extension_ids() {
            if let Some(binding) = self.deps.deployment_channels.extension(&extension_id) {
                desired.insert(extension_id, StreamSource::Deployment(binding));
            }
        }
        let snapshot: Arc<ActiveSnapshot> = self.deps.watch.current();
        for extension_id in snapshot.extension_ids() {
            if let Some(active) = snapshot.extension(&extension_id) {
                // Deployment bindings win for the same extension id, exactly
                // as for webhook ingress.
                desired
                    .entry(extension_id)
                    .or_insert(StreamSource::Active(active));
            }
        }
        desired.retain(|_, source| source.stream().is_some());
        desired
    }

    async fn reconcile(&self) {
        let _pass = self.reconcile_gate.lock().await;
        if self.closing.load(Ordering::SeqCst) {
            return;
        }
        let desired = self.desired();
        // Take stale connections out under the lock and stop them after it is
        // released: a connection draining a slow frame must not hold up the
        // map, or the other stops.
        let stale_connections = {
            let mut running = self.running.lock().await;
            let stale: Vec<String> = running
                .iter()
                .filter(|(id, current)| {
                    desired.get(*id).is_none_or(|wanted| {
                        !wanted.same_source(&current.source)
                            || (wanted.is_deployment()
                                && current.generation
                                    != self.deps.configuration_changes.generation(id))
                    })
                })
                .map(|(id, _)| id.clone())
                .collect();
            stale
                .into_iter()
                .filter_map(|id| running.remove(&id))
                .collect::<Vec<_>>()
        };
        self.limited
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .retain(|id, source| {
                desired
                    .get(id)
                    .is_some_and(|wanted| wanted.same_source(source))
            });
        stop_all(&self.deps, self.config.stop_timeout, stale_connections).await;
        let mut running = self.running.lock().await;
        for (id, source) in desired {
            if running.contains_key(&id) {
                continue;
            }
            // A connection whose task ended (administrator needed) holds no
            // live socket, so only live tasks count against the limit.
            let live = running
                .values()
                .filter(|connection| connection.is_live())
                .count();
            if live >= self.config.max_connections {
                let mut limited = self
                    .limited
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if limited
                    .get(&id)
                    .is_none_or(|reported| !reported.same_source(&source))
                {
                    self.deps.audit.record(StreamAuditEvent {
                        extension_id: source.extension_id().to_string(),
                        installation_id: source.installation_id().to_string(),
                        host: None,
                        kind: StreamAuditKind::NeedsAdministrator {
                            reason: "connection_limit",
                        },
                    });
                    limited.insert(id, source);
                }
                continue;
            }
            self.limited
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remove(&id);
            let generation = self.deps.configuration_changes.generation(&id);
            let (stop, stopped) = watch::channel(false);
            let ctx = Arc::new(ConnectionContext {
                source: source.clone(),
                admission: self.deps.admission.clone(),
                connector: Arc::clone(&self.deps.connector),
                scope: self.deps.scope.clone(),
                audit: Arc::clone(&self.deps.audit),
                config: self.config.clone(),
                admissions: Arc::clone(&self.admissions),
            });
            let ended = Arc::new(AtomicBool::new(false));
            let task = tokio::spawn(supervised_task(
                ctx,
                Cancel(stopped),
                Arc::clone(&ended),
                Arc::clone(&self.task_ended),
            ));
            running.insert(
                id,
                RunningConnection {
                    source,
                    generation,
                    stop,
                    task,
                    ended,
                },
            );
        }
    }
}
impl StreamSupervisor {
    /// Stop reconciling and close every connection. Frames already inside the
    /// admission pipeline finish first; queued frames are left unacknowledged
    /// for the vendor to redeliver. The channel host assembly drains each
    /// registration's post-admission observers when it unregisters the sink.
    pub async fn shutdown(&self) {
        self.closing.store(true, Ordering::SeqCst);
        // Wait for a pass in progress: it finishes stopping what it took.
        let _pass = self.reconcile_gate.lock().await;
        let handle = self
            .reconcile_loop
            .lock()
            .ok()
            .and_then(|mut slot| slot.take());
        if let Some(handle) = handle {
            handle.abort();
            _ = handle.await; // silent-ok: an aborted join is Cancelled.
        }
        let mut running = self.running.lock().await;
        let connections: Vec<RunningConnection> = running.drain().map(|(_, c)| c).collect();
        drop(running);
        stop_all(&self.deps, self.config.stop_timeout, connections).await;
    }
}
impl Drop for StreamSupervisor {
    fn drop(&mut self) {
        if let Ok(mut slot) = self.reconcile_loop.lock()
            && let Some(handle) = slot.take()
        {
            handle.abort();
        }
        // The state cache outlives the supervisor and is fed only by audit
        // events, so each aborted connection reports the same `Stopped` event
        // an orderly stop does; the cache then clears its own entry and the
        // projection never keeps a `Connected` for a connection that is gone.
        // `get_mut` needs no lock: `&mut self` means no one else holds it.
        for (_, connection) in self.running.get_mut().drain() {
            connection.task.abort();
            self.deps.audit.record(StreamAuditEvent {
                extension_id: connection.source.extension_id().to_string(),
                installation_id: connection.source.installation_id().to_string(),
                host: None,
                kind: StreamAuditKind::Stopped,
            });
        }
    }
}

/// Stop connections concurrently, each bounded by `timeout`.
async fn stop_all(
    deps: &StreamSupervisorDeps,
    timeout: Duration,
    connections: Vec<RunningConnection>,
) {
    futures::future::join_all(
        connections
            .into_iter()
            .map(|connection| stop_connection(deps, timeout, connection)),
    )
    .await;
}

async fn stop_connection(
    deps: &StreamSupervisorDeps,
    timeout: Duration,
    connection: RunningConnection,
) {
    let RunningConnection {
        source,
        stop,
        mut task,
        ..
    } = connection;
    _ = stop.send(true);
    // The task finishes its in-flight frame (if any) and closes the socket.
    // A task that does not within the timeout is aborted; its queued frames
    // stay unacknowledged for the vendor to redeliver.
    if tokio::time::timeout(timeout, &mut task).await.is_err() {
        task.abort();
        _ = task.await; // silent-ok: an aborted join is Cancelled.
        deps.audit.record(StreamAuditEvent {
            extension_id: source.extension_id().to_string(),
            installation_id: source.installation_id().to_string(),
            host: None,
            kind: StreamAuditKind::StopForced,
        });
    }
    deps.audit.record(StreamAuditEvent {
        extension_id: source.extension_id().to_string(),
        installation_id: source.installation_id().to_string(),
        host: None,
        kind: StreamAuditKind::Stopped,
    });
}

/// Runs [`connection_task`] and reports a panic that escaped it. A task that
/// dies outside the frame-control callbacks (which are contained themselves)
/// would otherwise leave the last projected state at `Connected` and a dead
/// handle in the source's slot. The failure is terminal until the source
/// changes, like a refused credential: respawning on every panic would loop.
async fn supervised_task(
    ctx: Arc<ConnectionContext>,
    cancel: Cancel,
    ended: Arc<AtomicBool>,
    task_ended: Arc<tokio::sync::Notify>,
) {
    use futures::FutureExt as _;
    let outcome = std::panic::AssertUnwindSafe(connection_task(Arc::clone(&ctx), cancel))
        .catch_unwind()
        .await;
    if outcome.is_err() {
        ctx.emit(
            None,
            StreamAuditKind::NeedsAdministrator {
                reason: "connection_task_panicked",
            },
        );
    }
    ended.store(true, Ordering::SeqCst);
    // A stored permit, so an exit during a reconcile pass is not missed.
    task_ended.notify_one();
}

/// One installation's connection until it is stopped: connect, serve, and on
/// any end reconnect after a backoff delay. Repeated credential refusals stop
/// the retrying (the extension then needs an administrator); a re-activation
/// or configuration change with new credentials replaces this task.
async fn connection_task(ctx: Arc<ConnectionContext>, mut cancel: Cancel) {
    let mut backoff = Backoff::new(ctx.config.backoff);
    let mut refusals = 0u32;
    while !cancel.is_cancelled() {
        match run_connection(&ctx, &mut cancel).await {
            ConnectOutcome::Ran(end) => {
                refusals = 0;
                if end.healthy {
                    backoff.reset();
                }
                if end.reason == EndReason::Stopped {
                    return;
                }
            }
            ConnectOutcome::Failed(failure) => match failure.kind {
                ConnectFailureKind::Transient => {
                    refusals = 0;
                    ctx.emit(
                        None,
                        StreamAuditKind::ConnectFailed {
                            reason: failure.reason,
                        },
                    );
                }
                ConnectFailureKind::Auth | ConnectFailureKind::Rejected => {
                    refusals = refusals.saturating_add(1);
                    ctx.emit(
                        None,
                        if failure.kind == ConnectFailureKind::Auth {
                            StreamAuditKind::AuthFailed {
                                consecutive: refusals,
                            }
                        } else {
                            StreamAuditKind::ConnectFailed {
                                reason: failure.reason,
                            }
                        },
                    );
                    if refusals >= ctx.config.auth_failure_threshold {
                        ctx.emit(
                            None,
                            StreamAuditKind::NeedsAdministrator {
                                reason: failure.reason,
                            },
                        );
                        return;
                    }
                }
            },
        }
        tokio::select! {
            () = cancel.cancelled() => return,
            () = tokio::time::sleep(backoff.next_delay()) => {}
        }
    }
}
