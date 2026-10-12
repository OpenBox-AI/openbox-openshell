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

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};

type Job = Pin<Box<dyn Future<Output = ()> + Send>>;

/// How long a sandbox's queue waits for work before it is put away.
const IDLE: Duration = Duration::from_secs(10 * 60);

pub struct Sequencer {
    queues: Mutex<HashMap<String, mpsc::UnboundedSender<Job>>>,
    /// Most a background job may take, so a hung Core call cannot stall the
    /// sandbox's queue.
    job_timeout: Duration,
}

/// A verdict's place in its sandbox's queue: everything queued before it has
/// been sent, and nothing queued after it runs until the turn is dropped.
pub struct Turn {
    _release: oneshot::Sender<()>,
}

impl Sequencer {
    pub fn new(job_timeout: Duration) -> Arc<Self> {
        Arc::new(Self {
            queues: Mutex::new(HashMap::new()),
            job_timeout,
        })
    }

    /// Queues background work for a sandbox, after everything already queued.
    pub fn push(
        self: &Arc<Self>,
        sandbox_id: &str,
        job: impl Future<Output = ()> + Send + 'static,
    ) {
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
    }

    /// Waits for the sandbox's queue to reach this caller, then holds it.
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
        let _ = reached.await;
        Turn { _release: release }
    }

    fn enqueue(self: &Arc<Self>, sandbox_id: &str, job: Job) {
        let mut queues = self.queues.lock().expect("sequencer lock");
        if let Some(queue) = queues.get(sandbox_id) {
            match queue.send(job) {
                Ok(()) => return,
                Err(mpsc::error::SendError(job)) => {
                    queues.remove(sandbox_id);
                    return self.start(&mut queues, sandbox_id, job);
                }
            }
        }
        self.start(&mut queues, sandbox_id, job);
    }

    fn start(
        self: &Arc<Self>,
        queues: &mut HashMap<String, mpsc::UnboundedSender<Job>>,
        sandbox_id: &str,
        job: Job,
    ) {
        let (sender, receiver) = mpsc::unbounded_channel();
        let _ = sender.send(job);
        queues.insert(sandbox_id.to_owned(), sender);
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
}
