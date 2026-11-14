//! Core hears a sandbox's events in the order they happened.
//!
//! The dashboard orders a session by when Core stored each event, so the
//! order Core receives them is the order a person sees. Some events are sent
//! in the background so the sandbox is never held for Core (a response's
//! completed span and the end of its activity, the tools its reply opens),
//! and the next request's verdict could otherwise overtake them.
//!
//! Each sandbox has one queue. Background work joins it as it happens, and a
//! verdict takes a [`Turn`]: it waits until everything queued before it has
//! been sent, and holds the queue while it talks to Core. One queue per
//! replica: a sandbox's traffic reaches one replica at a time in practice,
//! and the shared store, not this queue, keeps replicas consistent.
//!
//! A sandbox's background work is bounded ([`MAX_BACKLOG`] jobs): when Core
//! falls that far behind, further background records for the sandbox are
//! dropped and counted, rather than held in memory until the process is
//! killed. Verdicts are never dropped.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};

use crate::telemetry;

type Job = Pin<Box<dyn Future<Output = ()> + Send>>;

/// The job, taking itself off the queue's count when it finishes.
fn counted(job: Job, depth: &Arc<AtomicUsize>) -> Job {
    let depth = Arc::clone(depth);
    Box::pin(async move {
        job.await;
        depth.fetch_sub(1, Ordering::Relaxed);
    })
}

/// How long a sandbox's queue waits for work before it is put away.
const IDLE: Duration = Duration::from_secs(10 * 60);
/// Most background jobs a sandbox's queue holds while Core catches up.
pub const MAX_BACKLOG: usize = 1000;

struct Queue {
    sender: mpsc::UnboundedSender<Job>,
    /// Jobs queued and not yet finished.
    depth: Arc<AtomicUsize>,
}

pub struct Sequencer {
    queues: Mutex<HashMap<String, Queue>>,
    /// Most a background job may take, so a hung Core call cannot stall the
    /// sandbox's queue.
    job_timeout: Duration,
    max_backlog: usize,
}

/// A verdict's place in its sandbox's queue: everything queued before it has
/// been sent, and nothing queued after it runs until the turn is dropped.
pub struct Turn {
    _release: oneshot::Sender<()>,
}

impl Sequencer {
    pub fn new(job_timeout: Duration) -> Arc<Self> {
        Self::with_backlog(job_timeout, MAX_BACKLOG)
    }

    pub fn with_backlog(job_timeout: Duration, max_backlog: usize) -> Arc<Self> {
        Arc::new(Self {
            queues: Mutex::new(HashMap::new()),
            job_timeout,
            max_backlog: max_backlog.max(1),
        })
    }

    /// Queues background work for a sandbox, after everything already
    /// queued. Returns false, and drops the job, when the sandbox already has
    /// `max_backlog` jobs waiting.
    pub fn push(
        self: &Arc<Self>,
        sandbox_id: &str,
        job: impl Future<Output = ()> + Send + 'static,
    ) -> bool {
        if self.depth(sandbox_id) >= self.max_backlog {
            return false;
        }
        let timeout = self.job_timeout;
        let sandbox = sandbox_id.to_owned();
        self.enqueue(
            sandbox_id,
            Box::pin(async move {
                if tokio::time::timeout(timeout, job).await.is_err() {
                    eprintln!(
                        "openbox: a Core call for sandbox_id={sandbox} took over {} s; moving on",
                        timeout.as_secs()
                    );
                }
            }),
        );
        true
    }

    /// Jobs queued for a sandbox and not yet finished.
    pub fn depth(&self, sandbox_id: &str) -> usize {
        self.queues
            .lock()
            .expect("sequencer lock")
            .get(sandbox_id)
            .map_or(0, |queue| queue.depth.load(Ordering::Relaxed))
    }

    /// Waits for the sandbox's queue to reach this caller, then holds it. The
    /// wait is an `openbox.queue_wait` span under the current one.
    pub async fn turn(self: &Arc<Self>, sandbox_id: &str) -> Turn {
        let (ready, reached) = oneshot::channel();
        let (release, released) = oneshot::channel::<()>();
        self.enqueue(
            sandbox_id,
            Box::pin(async move {
                if ready.send(()).is_ok() {
                    let _ = released.await;
                }
            }),
        );
        let _ = telemetry::within(
            "openbox.queue_wait",
            vec![telemetry::sandbox(sandbox_id)],
            reached,
        )
        .await;
        Turn { _release: release }
    }

    /// Waits, up to `limit`, until everything queued so far has been sent,
    /// for every sandbox. For shutdown: work still queued when the process
    /// exits is lost. Returns whether it all went out in time.
    pub async fn drain(self: &Arc<Self>, limit: Duration) -> bool {
        let sandboxes: Vec<String> = self
            .queues
            .lock()
            .expect("sequencer lock")
            .keys()
            .cloned()
            .collect();
        let mut done = Vec::new();
        for sandbox_id in sandboxes {
            let (sent, reached) = oneshot::channel::<()>();
            self.enqueue(
                &sandbox_id,
                Box::pin(async move {
                    let _ = sent.send(());
                }),
            );
            done.push(reached);
        }
        tokio::time::timeout(limit, async {
            for reached in done {
                let _ = reached.await;
            }
        })
        .await
        .is_ok()
    }

    fn enqueue(self: &Arc<Self>, sandbox_id: &str, job: Job) {
        let mut queues = self.queues.lock().expect("sequencer lock");
        if let Some(queue) = queues.get(sandbox_id) {
            // A queue is put away (its receiver dropped) only under this
            // lock, so an open sender here stays open for this send.
            if !queue.sender.is_closed() {
                queue.depth.fetch_add(1, Ordering::Relaxed);
                let _ = queue.sender.send(counted(job, &queue.depth));
                return;
            }
            queues.remove(sandbox_id);
        }
        let (sender, receiver) = mpsc::unbounded_channel();
        let depth = Arc::new(AtomicUsize::new(1));
        let _ = sender.send(counted(job, &depth));
        queues.insert(sandbox_id.to_owned(), Queue { sender, depth });
        tokio::spawn(Arc::clone(self).run(sandbox_id.to_owned(), receiver));
    }

    async fn run(self: Arc<Self>, sandbox_id: String, mut receiver: mpsc::UnboundedReceiver<Job>) {
        loop {
            match tokio::time::timeout(IDLE, receiver.recv()).await {
                Ok(Some(job)) => job.await,
                Ok(None) => return,
                Err(_) => {
                    // Work is only queued under this lock, so an empty queue
                    // here stays empty once removed.
                    let mut queues = self.queues.lock().expect("sequencer lock");
                    if receiver.is_empty() {
                        queues.remove(&sandbox_id);
                        return;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    #[tokio::test]
    async fn a_turn_waits_for_earlier_work_and_holds_later_work() {
        let sequencer = Sequencer::new(Duration::from_secs(5));
        let log = Arc::new(StdMutex::new(Vec::new()));
        let write = |entry: &'static str| {
            let log = Arc::clone(&log);
            async move {
                tokio::time::sleep(Duration::from_millis(20)).await;
                log.lock().unwrap().push(entry);
            }
        };
        sequencer.push("sbx", write("completed span"));
        sequencer.push("sbx", write("activity completed"));
        let turn = sequencer.turn("sbx").await;
        log.lock().unwrap().push("verdict");
        sequencer.push("sbx", write("after the verdict"));
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(
            *log.lock().unwrap(),
            vec!["completed span", "activity completed", "verdict"]
        );
        drop(turn);
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(log.lock().unwrap().last(), Some(&"after the verdict"));
    }

    #[tokio::test]
    async fn sandboxes_do_not_wait_for_each_other_and_a_hung_job_is_dropped() {
        let sequencer = Sequencer::new(Duration::from_millis(50));
        sequencer.push("slow", std::future::pending());
        let started = std::time::Instant::now();
        drop(sequencer.turn("fast").await);
        assert!(started.elapsed() < Duration::from_millis(40));
        drop(sequencer.turn("slow").await);
        assert!(started.elapsed() >= Duration::from_millis(50));
    }

    #[tokio::test]
    async fn drain_waits_for_queued_work_up_to_a_limit() {
        let sequencer = Sequencer::new(Duration::from_secs(5));
        let sent = Arc::new(StdMutex::new(Vec::new()));
        for sandbox in ["a", "b"] {
            let sent = Arc::clone(&sent);
            sequencer.push(sandbox, async move {
                tokio::time::sleep(Duration::from_millis(30)).await;
                sent.lock().unwrap().push(sandbox);
            });
        }
        assert!(sequencer.drain(Duration::from_secs(1)).await);
        assert_eq!(sent.lock().unwrap().len(), 2);
        sequencer.push("c", std::future::pending());
        assert!(!sequencer.drain(Duration::from_millis(20)).await);
    }

    #[tokio::test]
    async fn background_work_is_bounded_per_sandbox_and_verdicts_still_run() {
        let sequencer = Sequencer::with_backlog(Duration::from_secs(5), 3);
        let (open, gate) = tokio::sync::watch::channel(false);
        let held = |gate: tokio::sync::watch::Receiver<bool>| async move {
            let mut gate = gate;
            let _ = gate.wait_for(|open| *open).await;
        };
        assert!(sequencer.push("sbx", held(gate.clone())));
        assert!(sequencer.push("sbx", held(gate.clone())));
        assert!(sequencer.push("sbx", held(gate.clone())));
        assert!(
            !sequencer.push("sbx", held(gate.clone())),
            "the fourth is dropped"
        );
        assert!(
            sequencer.push("other", async {}),
            "other sandboxes are not affected"
        );
        assert_eq!(sequencer.depth("sbx"), 3);
        let _ = open.send(true);
        drop(sequencer.turn("sbx").await);
        // the released turn leaves the count once the queue moves on
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(sequencer.depth("sbx"), 0, "finished jobs leave the count");
        assert!(sequencer.push("sbx", async {}));
    }
}
