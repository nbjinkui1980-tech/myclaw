//! Per-session ordered execution with bounded queues.
//!
//! Frames that share a session key run one at a time, in arrival order;
//! different keys run concurrently (the executor bounds total concurrency).
//! Every queue is bounded: [`SessionQueues::enqueue`] does not return until the
//! frame has a slot, so the reader that awaits it stops reading from the
//! socket and TCP back-pressure slows the peer. Nothing is dropped and nothing
//! grows without bound. The key only orders delivery; it grants no identity.
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use futures::future::BoxFuture;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};

pub(super) type SessionKey = Option<String>;

type Run<J> = Arc<dyn Fn(J) -> BoxFuture<'static, ()> + Send + Sync>;
type Queue<J> = VecDeque<(J, OwnedSemaphorePermit)>;

struct Inner<J> {
    /// A key is present exactly while a runner owns it. The runner removes the
    /// key under this lock when its queue is empty, which makes "append to the
    /// existing queue" and "start a runner" mutually exclusive.
    sessions: Mutex<HashMap<SessionKey, Queue<J>>>,
    /// Signalled whenever a queue slot frees.
    space: Notify,
    /// Signalled when the last runner exits.
    idle: Notify,
    runners: AtomicUsize,
    /// Frames queued or executing on this connection.
    pending: Arc<Semaphore>,
    per_session_cap: usize,
    run: Run<J>,
}

pub(super) struct SessionQueues<J> {
    inner: Arc<Inner<J>>,
}

impl<J: Send + 'static> SessionQueues<J> {
    pub fn new(
        max_pending: usize,
        per_session_cap: usize,
        run: impl Fn(J) -> BoxFuture<'static, ()> + Send + Sync + 'static,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                sessions: Mutex::new(HashMap::new()),
                space: Notify::new(),
                idle: Notify::new(),
                runners: AtomicUsize::new(0),
                pending: Arc::new(Semaphore::new(max_pending.max(1))),
                per_session_cap: per_session_cap.max(1),
                run: Arc::new(run),
            }),
        }
    }

    /// Queue one frame behind its session's earlier frames. Waits (so the
    /// caller stops reading) while the connection or the session is full.
    pub async fn enqueue(&self, key: SessionKey, job: J) {
        let inner = &self.inner;
        let Ok(permit) = Arc::clone(&inner.pending).acquire_owned().await else {
            return; // the semaphore is never closed; defensive
        };
        let mut item = Some((job, permit));
        loop {
            let notified = inner.space.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut sessions = lock(&inner.sessions);
                match sessions.get_mut(&key) {
                    Some(queue) if queue.len() >= inner.per_session_cap => {}
                    Some(queue) => {
                        if let Some(item) = item.take() {
                            queue.push_back(item);
                        }
                        return;
                    }
                    None => {
                        if let Some(item) = item.take() {
                            sessions.insert(key.clone(), VecDeque::from([item]));
                            inner.runners.fetch_add(1, Ordering::SeqCst);
                            tokio::spawn(run_session(Arc::clone(inner), key));
                        }
                        return;
                    }
                }
            }
            notified.await;
        }
    }

    /// Resolves once no runner is active (every queued frame has been run or
    /// skipped by the executor).
    pub async fn wait_idle(&self) {
        loop {
            let notified = self.inner.idle.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.inner.runners.load(Ordering::SeqCst) == 0 {
                return;
            }
            notified.await;
        }
    }
}

async fn run_session<J: Send + 'static>(inner: Arc<Inner<J>>, key: SessionKey) {
    loop {
        let next = {
            let mut sessions = lock(&inner.sessions);
            match sessions.get_mut(&key).and_then(VecDeque::pop_front) {
                Some(item) => Some(item),
                None => {
                    sessions.remove(&key);
                    None
                }
            }
        };
        let Some((job, _permit)) = next else {
            break;
        };
        inner.space.notify_waiters();
        (inner.run)(job).await;
    }
    if inner.runners.fetch_sub(1, Ordering::SeqCst) == 1 {
        inner.idle.notify_waiters();
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;
    use std::time::Duration;

    use super::*;

    fn key(name: &str) -> SessionKey {
        Some(name.to_string())
    }

    #[tokio::test]
    async fn a_full_session_queue_makes_the_reader_wait_and_nothing_is_dropped() {
        let gate = Arc::new(Semaphore::new(0));
        let ran = Arc::new(Mutex::new(Vec::<u32>::new()));
        let queues = {
            let (gate, ran) = (Arc::clone(&gate), Arc::clone(&ran));
            SessionQueues::new(16, 2, move |job: u32| {
                let (gate, ran) = (Arc::clone(&gate), Arc::clone(&ran));
                Box::pin(async move {
                    // Every job waits for a release permit.
                    if let Ok(permit) = gate.acquire().await {
                        permit.forget();
                    }
                    lock(&ran).push(job);
                })
            })
        };
        // Job 1 starts executing (blocked); jobs 2 and 3 fill the queue of 2.
        queues.enqueue(key("s"), 1).await;
        tokio::time::sleep(Duration::from_millis(30)).await;
        queues.enqueue(key("s"), 2).await;
        queues.enqueue(key("s"), 3).await;
        // The fourth cannot get a slot: the reader would be waiting.
        let blocked = tokio::time::timeout(Duration::from_millis(100), queues.enqueue(key("s"), 4));
        assert!(
            blocked.await.is_err(),
            "queue of 2 is full while job 1 runs"
        );

        gate.add_permits(16);
        queues.enqueue(key("s"), 4).await;
        queues.wait_idle().await;
        assert_eq!(*lock(&ran), vec![1, 2, 3, 4], "arrival order, none dropped");
    }

    #[tokio::test]
    async fn the_connection_wide_bound_applies_across_sessions() {
        let gate = Arc::new(Semaphore::new(0));
        let queues = {
            let gate = Arc::clone(&gate);
            SessionQueues::new(2, 8, move |_job: u32| {
                let gate = Arc::clone(&gate);
                Box::pin(async move {
                    if let Ok(permit) = gate.acquire().await {
                        permit.forget();
                    }
                })
            })
        };
        queues.enqueue(key("a"), 1).await;
        queues.enqueue(key("b"), 2).await;
        let blocked = tokio::time::timeout(Duration::from_millis(100), queues.enqueue(key("c"), 3));
        assert!(blocked.await.is_err(), "two frames pending connection-wide");
        gate.add_permits(8);
        queues.wait_idle().await;
    }

    #[tokio::test]
    async fn different_sessions_overlap_while_one_session_never_does() {
        let running = Arc::new(Mutex::new(HashMap::<&'static str, usize>::new()));
        let cross_overlap = Arc::new(AtomicBool::new(false));
        let same_overlap = Arc::new(AtomicBool::new(false));
        let queues = {
            let (running, cross, same) = (
                Arc::clone(&running),
                Arc::clone(&cross_overlap),
                Arc::clone(&same_overlap),
            );
            SessionQueues::new(16, 8, move |session: &'static str| {
                let (running, cross, same) =
                    (Arc::clone(&running), Arc::clone(&cross), Arc::clone(&same));
                Box::pin(async move {
                    {
                        let mut running = lock(&running);
                        let here = running.entry(session).or_insert(0);
                        *here += 1;
                        if *here > 1 {
                            same.store(true, Ordering::SeqCst);
                        }
                        if running.values().sum::<usize>() > 1 {
                            cross.store(true, Ordering::SeqCst);
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(40)).await;
                    if let Some(count) = lock(&running).get_mut(session) {
                        *count -= 1;
                    }
                })
            })
        };
        queues.enqueue(key("x"), "x").await;
        queues.enqueue(key("y"), "y").await;
        queues.enqueue(key("x"), "x").await;
        queues.wait_idle().await;
        assert!(cross_overlap.load(Ordering::SeqCst), "x and y overlapped");
        assert!(
            !same_overlap.load(Ordering::SeqCst),
            "x never overlapped itself"
        );
    }
}
