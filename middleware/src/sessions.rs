//! Sandbox sessions in `OpenBox` Core, opened on create and closed on delete.
//!
//! Each `OpenShell` sandbox is one Core session. The front desk opens it when
//! the gateway creates the sandbox and closes it when the gateway deletes it,
//! so a session has a start, every governed request in between, and an end
//! Core can seal.
//!
//! The verdict middleware still opens the session on a sandbox's first
//! request, so a missed create costs nothing: `WorkflowStarted` is
//! idempotent and whichever arrives second is replayed. A missed delete
//! leaves the session open, as before this module existed.
//!
//! The session's input is the sandbox as created (name, image, policy
//! version, labels); its duration comes from the start time the front desk
//! keeps in the shared store, so any replica can close it.
//!
//! The door guard sends a request's completion (its span and the end of its
//! activity) in the background, and a sandbox is often deleted right after its
//! last response. So on delete the session waits, bounded, until the door
//! guard has sent every completion it still owes ([`pending_key`]); otherwise
//! Core hears the session end first and the last activity stays open.
//!
//! On shutdown ([`SessionLifecycle::shutdown`]) that wait is cut to a short
//! grace and every session still ending is ended before the process exits,
//! so a sandbox deleted just before a restart still gets its end.
//!
//! A session end Core does not accept (Core down, slow or unreachable) is
//! retried with backoff for [`END_RETRY_FOR`]. Until Core accepts it, the end
//! is kept as owed in the shared store; [`SessionLifecycle::sweep_owed`],
//! which the front desk runs at start and every [`END_SWEEP_EVERY`], takes up
//! any owed end nobody has tried for [`END_STALE`], so an end survives a
//! restart and any replica can finish it. Core keys the end by sandbox, so an
//! end sent twice is recorded once.
//!
//! A tool the model asked for that never got its result back (the sandbox
//! went away mid-tool) is closed before the session, so no activity is left
//! open.
//!
//! Like the inventory, this runs in `post_commit` and is best effort. Core
//! calls run in the background so a slow Core never holds up the gateway.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::{Notify, watch};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::core_client::{Activity, CoreClient, Outcome};
use crate::guard::activity_from;
use crate::interceptor::{Inventory, InventoryEvent};
use crate::inventory::RuntimeEnvironment;
use crate::store::{
    SharedStore, end_owed_key, ends_owed_key, open_tools_key, pending_key, session_key, tool_key,
};
use crate::telemetry;

/// Most a deleted sandbox's session waits for the door guard's completions:
/// one slow Core call. The wait is in the background; nothing is held for it.
const PENDING_WAIT: Duration = Duration::from_secs(30);
const PENDING_POLL: Duration = Duration::from_millis(250);
/// Once shutting down, how much longer a session waits for the door guard,
/// which is draining its own queue at the same time.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);
/// How long a session end Core does not accept is retried before it is left
/// to the sweep: long enough to ride out a Core restart.
const END_RETRY_FOR: Duration = Duration::from_secs(300);
/// The first wait between session end attempts; it doubles up to
/// [`END_BACKOFF_MAX`].
const END_BACKOFF: Duration = Duration::from_secs(1);
const END_BACKOFF_MAX: Duration = Duration::from_secs(30);
/// An owed end nobody has tried for this long is taken up by the sweep. More
/// than the longest backoff plus one Core call (29 s at most), so an end still
/// being retried is left to its replica.
const END_STALE: Duration = Duration::from_secs(90);
/// The longest an owed end is kept.
const END_OWED_TTL: Duration = Duration::from_secs(24 * 60 * 60);
/// How often the front desk sweeps for owed session ends.
pub const END_SWEEP_EVERY: Duration = Duration::from_secs(60);

/// The two Core calls a sandbox's lifecycle needs.
#[tonic::async_trait]
pub trait SessionGovernance: Send + Sync + 'static {
    async fn start(
        &self,
        sandbox_id: &str,
        sandbox_name: &str,
        input: &Value,
    ) -> Result<(), String>;
    async fn end(&self, sandbox_id: &str, duration_ms: Option<u64>) -> Result<(), String>;
    /// Closes a tool left open, opening it first when Core never heard of
    /// it.
    async fn close_tool(
        &self,
        sandbox_id: &str,
        tool: &Activity,
        opened: bool,
    ) -> Result<(), String>;
}

#[tonic::async_trait]
impl SessionGovernance for CoreClient {
    async fn start(
        &self,
        sandbox_id: &str,
        sandbox_name: &str,
        input: &Value,
    ) -> Result<(), String> {
        self.start_session_with(sandbox_id, sandbox_name, Some(input))
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    async fn end(&self, sandbox_id: &str, duration_ms: Option<u64>) -> Result<(), String> {
        self.end_session(sandbox_id, duration_ms)
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    async fn close_tool(
        &self,
        sandbox_id: &str,
        tool: &Activity,
        opened: bool,
    ) -> Result<(), String> {
        if !opened {
            self.open_activity(sandbox_id, tool)
                .await
                .map_err(|error| error.to_string())?;
        }
        let outcome = Outcome {
            output: Some(json!({"reason": "sandbox deleted"})),
            ..Outcome::default()
        };
        self.close_activity(sandbox_id, tool, &outcome)
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
}

/// Opens and closes Core sessions on the way to the inventory, which still
/// receives every event.
pub struct SessionLifecycle {
    inventory: Arc<dyn Inventory>,
    core: Arc<dyn SessionGovernance>,
    store: Arc<dyn SharedStore>,
    gateway: Option<String>,
    pending_wait: Duration,
    retry: EndRetry,
    ending: Arc<Ending>,
}

/// How a session end is retried.
#[derive(Clone, Copy)]
struct EndRetry {
    /// Retry for this long after the first attempt.
    within: Duration,
    /// The first wait between attempts.
    backoff: Duration,
    /// An owed end untried for this long is taken up by the sweep.
    stale: Duration,
}

/// A session end Core has not accepted yet, as kept in the shared store.
#[derive(Serialize, Deserialize)]
struct Owed {
    duration_ms: Option<u64>,
    /// When it was last tried, in Unix milliseconds.
    attempted: u64,
}

/// How a session end finished.
enum Ended {
    /// Core accepted it, after this many attempts.
    Accepted(u32),
    /// Another front desk ended it while this one was waiting to retry.
    Elsewhere,
}

/// The sessions being ended in the background, so shutdown can finish them.
struct Ending {
    count: Mutex<usize>,
    idle: Notify,
    /// Set on shutdown: the latest a session waits for the door guard.
    cutoff: watch::Sender<Option<Instant>>,
}

impl Ending {
    fn begin(&self) {
        *self.count.lock().expect("ending lock") += 1;
    }

    fn end(&self) {
        let mut count = self.count.lock().expect("ending lock");
        *count -= 1;
        if *count == 0 {
            self.idle.notify_waiters();
        }
    }
}
impl SessionLifecycle {
    pub fn new(
        inventory: Arc<dyn Inventory>,
        core: Arc<dyn SessionGovernance>,
        store: Arc<dyn SharedStore>,
        gateway: Option<String>,
    ) -> Self {
        Self {
            inventory,
            core,
            store,
            gateway,
            pending_wait: PENDING_WAIT,
            retry: EndRetry {
                within: END_RETRY_FOR,
                backoff: END_BACKOFF,
                stale: END_STALE,
            },
            ending: Arc::new(Ending {
                count: Mutex::new(0),
                idle: Notify::new(),
                cutoff: watch::Sender::new(None),
            }),
        }
    }

    /// Ends every session still waiting for the door guard, giving it
    /// [`SHUTDOWN_GRACE`] more (at most half of `limit`), and returns once they are all sent or
    /// `limit` passes. Returns whether they all went out.
    pub async fn shutdown(&self, limit: Duration) -> bool {
        self.ending
            .cutoff
            .send_replace(Some(Instant::now() + SHUTDOWN_GRACE.min(limit / 2)));
        tokio::time::timeout(limit, async {
            loop {
                let idle = self.ending.idle.notified();
                if *self.ending.count.lock().expect("ending lock") == 0 {
                    return;
                }
                idle.await;
            }
        })
        .await
        .is_ok()
    }

    /// Replaces [`PENDING_WAIT`].
    #[must_use]
    pub const fn with_pending_wait(mut self, wait: Duration) -> Self {
        self.pending_wait = wait;
        self
    }

    /// Replaces [`END_RETRY_FOR`], [`END_BACKOFF`] and [`END_STALE`].
    #[must_use]
    pub const fn with_end_retry(
        mut self,
        within: Duration,
        backoff: Duration,
        stale: Duration,
    ) -> Self {
        self.retry = EndRetry {
            within,
            backoff,
            stale,
        };
        self
    }

    /// Takes up the session ends still owed to Core that nobody has tried for
    /// [`END_STALE`]: ones whose retries ran out, or whose front desk stopped.
    /// Returns how many it took up.
    pub async fn sweep_owed(&self) -> usize {
        let ids = match self.store.members(&ends_owed_key()).await {
            Ok(ids) => ids,
            Err(error) => {
                eprintln!("openbox: owed session ends unknown: {error}");
                return 0;
            }
        };
        let stale = u64::try_from(self.retry.stale.as_millis()).unwrap_or(u64::MAX);
        let mut taken = 0;
        for id in ids {
            let owed = match self.store.get(&end_owed_key(&id)).await {
                Ok(Some(text)) => serde_json::from_str::<Owed>(&text).ok(),
                // Ended, or kept past END_OWED_TTL.
                Ok(None) => None,
                Err(_) => continue,
            };
            let Some(owed) = owed else {
                let _ = self.store.remove_member(&ends_owed_key(), &id).await;
                continue;
            };
            if unix_millis().saturating_sub(owed.attempted) < stale {
                continue;
            }
            eprintln!("openbox: retrying the owed session end sandbox_id={id}");
            self.spawn_end(id, owed.duration_ms, Duration::ZERO);
            taken += 1;
        }
        taken
    }

    /// Ends the sandbox's session in the background: after the door guard's
    /// completions (at most `wait`) and its open tools, retried until Core
    /// accepts it and kept as owed until then.
    fn spawn_end(&self, id: String, duration: Option<u64>, wait: Duration) {
        let core = Arc::clone(&self.core);
        let store = Arc::clone(&self.store);
        let retry = self.retry;
        let ending = Arc::clone(&self.ending);
        let cutoff = ending.cutoff.subscribe();
        ending.begin();
        let attributes = vec![telemetry::sandbox(&id)];
        tokio::spawn(telemetry::job(
            "openbox.session.end",
            attributes,
            async move {
                // Owed from the start, so a restart during the wait keeps it.
                owe(store.as_ref(), &id, duration).await;
                let left = await_pending(store.as_ref(), &id, wait, cutoff.clone()).await;
                if left > 0 {
                    eprintln!(
                        "openbox: ending session sandbox_id={id} with {left} completion(s) not sent after {} s",
                        wait.as_secs()
                    );
                }
                // After the wait: the door guard may still have been
                // opening the tools the last reply asked for.
                for (tool, opened) in open_tools(store.as_ref(), &id).await {
                    let closed = core.close_tool(&id, &tool, opened);
                    if let Err(error) =
                        telemetry::call("openbox.core.close_tool", Vec::new(), closed).await
                    {
                        eprintln!(
                            "openbox: tool activity {} left open sandbox_id={id}: {error}",
                            tool.id
                        );
                    }
                }
                match end_with_retry(core.as_ref(), store.as_ref(), &id, duration, retry, cutoff)
                    .await
                {
                    Ok(Ended::Accepted(attempts)) => {
                        settle(store.as_ref(), &id).await;
                        if attempts > 1 {
                            eprintln!(
                                "openbox: session completed sandbox_id={id} after {attempts} attempts"
                            );
                        } else {
                            eprintln!("openbox: session completed sandbox_id={id}");
                        }
                    }
                    Ok(Ended::Elsewhere) => {
                        eprintln!(
                            "openbox: session end sandbox_id={id} was completed by another front desk"
                        );
                    }
                    Err((attempts, error)) => {
                        eprintln!(
                            "openbox: session end failed sandbox_id={id} after {attempts} attempt(s), kept for a later sweep: {error}"
                        );
                    }
                }
                ending.end();
            },
        ));
    }
}

/// Keeps the sandbox's session end as owed, tried now.
async fn owe(store: &dyn SharedStore, sandbox_id: &str, duration_ms: Option<u64>) -> bool {
    let owed = Owed {
        duration_ms,
        attempted: unix_millis(),
    };
    let text = serde_json::to_string(&owed).expect("owed end serializes");
    let kept = match store
        .set(&end_owed_key(sandbox_id), &text, Some(END_OWED_TTL))
        .await
    {
        Ok(()) => {
            store
                .add_member(&ends_owed_key(), sandbox_id, END_OWED_TTL)
                .await
        }
        Err(error) => Err(error),
    };
    if let Err(error) = &kept {
        eprintln!(
            "openbox: session end for sandbox_id={sandbox_id} not kept as owed, a restart before Core accepts it loses it: {error}"
        );
    }
    kept.is_ok()
}

/// Forgets the sandbox's owed session end: Core accepted it.
async fn settle(store: &dyn SharedStore, sandbox_id: &str) {
    let _ = store.delete(&end_owed_key(sandbox_id)).await;
    let _ = store.remove_member(&ends_owed_key(), sandbox_id).await;
}

/// Sends the session end until Core accepts it, waiting `retry.backoff`
/// (doubling, at most [`END_BACKOFF_MAX`]) between attempts, for at most
/// `retry.within`, or until the shutdown cutoff. Stops early when another
/// front desk has ended it. On failure, returns the attempts and the last error.
async fn end_with_retry(
    core: &dyn SessionGovernance,
    store: &dyn SharedStore,
    sandbox_id: &str,
    duration_ms: Option<u64>,
    retry: EndRetry,
    mut cutoff: watch::Receiver<Option<Instant>>,
) -> Result<Ended, (u32, String)> {
    let until = Instant::now() + retry.within;
    let mut backoff = retry.backoff;
    let mut attempt = 0;
    let mut owed = false;
    loop {
        attempt += 1;
        if attempt > 1 {
            // Kept as owed by the last attempt and gone now: ended elsewhere.
            if owed && matches!(store.get(&end_owed_key(sandbox_id)).await, Ok(None)) {
                return Ok(Ended::Elsewhere);
            }
            owed = owe(store, sandbox_id, duration_ms).await;
        } else {
            owed = store
                .get(&end_owed_key(sandbox_id))
                .await
                .is_ok_and(|kept| kept.is_some());
        }
        let ended = core.end(sandbox_id, duration_ms);
        match telemetry::call("openbox.core.session_end", Vec::new(), ended).await {
            Ok(()) => return Ok(Ended::Accepted(attempt)),
            Err(error) => {
                let until = cutoff.borrow().map_or(until, |cutoff| cutoff.min(until));
                if Instant::now() + backoff > until {
                    return Err((attempt, error));
                }
                eprintln!(
                    "openbox: session end attempt {attempt} failed sandbox_id={sandbox_id}, retrying in {} ms: {error}",
                    backoff.as_millis()
                );
                tokio::select! {
                    () = tokio::time::sleep(backoff) => {}
                    _ = cutoff.changed() => {}
                }
                backoff = (backoff * 2).min(END_BACKOFF_MAX);
            }
        }
    }
}

/// Waits until the door guard has sent every completion it owes the sandbox,
/// or `limit` passes, or the shutdown cutoff. Returns how many it gave up on.
async fn await_pending(
    store: &dyn SharedStore,
    sandbox_id: &str,
    limit: Duration,
    mut cutoff: watch::Receiver<Option<Instant>>,
) -> u64 {
    let deadline = Instant::now() + limit;
    loop {
        let deadline = cutoff
            .borrow()
            .map_or(deadline, |cutoff| cutoff.min(deadline));
        let pending = match store.count_members(&pending_key(sandbox_id)).await {
            Ok(pending) => pending,
            Err(error) => {
                eprintln!(
                    "openbox: pending completions for sandbox_id={sandbox_id} unknown, ending its session now: {error}"
                );
                return 0;
            }
        };
        if pending == 0 || Instant::now() >= deadline {
            return pending;
        }
        tokio::select! {
            () = tokio::time::sleep(PENDING_POLL) => {}
            _ = cutoff.changed() => {}
        }
    }
}

/// Takes the sandbox's tools that are still open, marking them closed.
async fn open_tools(store: &dyn SharedStore, sandbox_id: &str) -> Vec<(Activity, bool)> {
    let ids: Vec<String> = store
        .take(&open_tools_key(sandbox_id))
        .await
        .ok()
        .flatten()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default();
    let mut tools = Vec::new();
    for call_id in ids {
        let Some(entry) = store
            .take(&tool_key(sandbox_id, &call_id))
            .await
            .ok()
            .flatten()
            .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        else {
            continue;
        };
        let state = entry.get("state").and_then(Value::as_str);
        let activity = entry.get("activity").and_then(activity_from);
        if let (Some("open" | "opened"), Some(activity)) = (state, activity) {
            tools.push((activity, state == Some("opened")));
        }
    }
    tools
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

#[tonic::async_trait]
impl Inventory for SessionLifecycle {
    async fn record(&self, event: InventoryEvent) -> Result<(), String> {
        match &event {
            InventoryEvent::Created { sandbox } => {
                let id = text(sandbox, "/sandbox/metadata/id");
                if !id.is_empty() {
                    let name = text(sandbox, "/sandbox/metadata/name");
                    let mut input =
                        RuntimeEnvironment::from_create_response(sandbox, self.gateway.as_deref())
                            .and_then(|environment| serde_json::to_value(environment).ok())
                            .unwrap_or_else(|| json!({}));
                    input["sandboxId"] = json!(id);
                    if let Err(error) = self
                        .store
                        .set(&session_key(&id), &unix_millis().to_string(), None)
                        .await
                    {
                        eprintln!(
                            "openbox: session start time for sandbox_id={id} not kept, its end carries no duration: {error}"
                        );
                    }
                    let core = Arc::clone(&self.core);
                    let attributes = vec![telemetry::sandbox(&id)];
                    tokio::spawn(telemetry::job(
                        "openbox.session.start",
                        attributes,
                        async move {
                            let started = core.start(&id, &name, &input);
                            match telemetry::call("openbox.core.session_start", Vec::new(), started)
                                .await
                            {
                                Ok(()) => eprintln!("openbox: session started sandbox_id={id}"),
                                Err(error) => {
                                    eprintln!(
                                        "openbox: session start failed sandbox_id={id}: {error}"
                                    );
                                }
                            }
                        },
                    ));
                }
            }
            // Empty for ALREADY_ABSENT: nothing was deleted by this call.
            InventoryEvent::Deleted { response } => {
                let id = text(response, "/sandboxId");
                if !id.is_empty() {
                    let duration = self
                        .store
                        .take(&session_key(&id))
                        .await
                        .unwrap_or_default()
                        .and_then(|started| started.parse::<u64>().ok())
                        .map(|started| unix_millis().saturating_sub(started));
                    self.spawn_end(id, duration, self.pending_wait);
                }
            }
            InventoryEvent::PolicyChanged { .. } => {}
        }
        self.inventory.record(event).await
    }
}

fn text(value: &Value, pointer: &str) -> String {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemoryStore;
    use std::sync::atomic::{AtomicU32, Ordering};
    use tokio::sync::mpsc;

    /// Records every call; fails the next `failures` of them (`u32::MAX`: all).
    struct FakeCore {
        calls: mpsc::UnboundedSender<String>,
        failures: AtomicU32,
    }

    impl FakeCore {
        fn new(calls: mpsc::UnboundedSender<String>, failures: u32) -> Self {
            Self {
                calls,
                failures: AtomicU32::new(failures),
            }
        }

        fn result(&self) -> Result<(), String> {
            let failed = self
                .failures
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| match left {
                    0 => None,
                    u32::MAX => Some(u32::MAX),
                    left => Some(left - 1),
                })
                .is_ok();
            if failed {
                Err("down".to_owned())
            } else {
                Ok(())
            }
        }
    }

    #[tonic::async_trait]
    impl SessionGovernance for FakeCore {
        async fn start(
            &self,
            sandbox_id: &str,
            sandbox_name: &str,
            input: &Value,
        ) -> Result<(), String> {
            self.calls
                .send(format!(
                    "start {sandbox_id} {sandbox_name} image={}",
                    input["image"].as_str().unwrap_or("-")
                ))
                .unwrap();
            self.result()
        }

        async fn end(&self, sandbox_id: &str, duration_ms: Option<u64>) -> Result<(), String> {
            self.calls
                .send(format!("end {sandbox_id} timed={}", duration_ms.is_some()))
                .unwrap();
            self.result()
        }

        async fn close_tool(
            &self,
            sandbox_id: &str,
            tool: &Activity,
            opened: bool,
        ) -> Result<(), String> {
            self.calls
                .send(format!(
                    "close-tool {sandbox_id} {} {} opened={opened}",
                    tool.id, tool.kind
                ))
                .unwrap();
            Ok(())
        }
    }

    #[tokio::test]
    async fn delete_closes_tools_left_open_before_the_session() {
        let (calls, mut received) = mpsc::unbounded_channel();
        let store: Arc<dyn SharedStore> = Arc::new(MemoryStore::default());
        let tool = |state: &str, id: &str| {
            json!({"activity": {"id": format!("oshx-tool-{id}"), "kind": "fetch", "input": [{}]}, "state": state})
                .to_string()
        };
        store
            .set(&tool_key("sbx-1", "a"), &tool("opened", "a"), None)
            .await
            .unwrap();
        store
            .set(&tool_key("sbx-1", "b"), &tool("open", "b"), None)
            .await
            .unwrap();
        store
            .set(&tool_key("sbx-1", "c"), &tool("closed", "c"), None)
            .await
            .unwrap();
        store
            .set(
                &open_tools_key("sbx-1"),
                &json!(["a", "b", "c"]).to_string(),
                None,
            )
            .await
            .unwrap();
        let sessions = SessionLifecycle::new(
            Arc::new(FakeInventory::default()),
            Arc::new(FakeCore::new(calls, 0)),
            Arc::clone(&store),
            None,
        );
        sessions
            .record(InventoryEvent::Deleted {
                response: json!({"sandboxId": "sbx-1"}),
            })
            .await
            .unwrap();
        assert_eq!(
            next(&mut received).await.as_deref(),
            Some("close-tool sbx-1 oshx-tool-a fetch opened=true")
        );
        assert_eq!(
            next(&mut received).await.as_deref(),
            Some("close-tool sbx-1 oshx-tool-b fetch opened=false")
        );
        assert_eq!(
            next(&mut received).await.as_deref(),
            Some("end sbx-1 timed=false")
        );
        assert!(store.get(&open_tools_key("sbx-1")).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn delete_ends_the_session_after_the_door_guards_pending_completions() {
        let (calls, mut received) = mpsc::unbounded_channel();
        let store: Arc<dyn SharedStore> = Arc::new(MemoryStore::default());
        store
            .add_member(&pending_key("sbx-1"), "req-1", Duration::from_secs(60))
            .await
            .unwrap();
        let sessions = SessionLifecycle::new(
            Arc::new(FakeInventory::default()),
            Arc::new(FakeCore::new(calls, 0)),
            Arc::clone(&store),
            None,
        );
        sessions
            .record(InventoryEvent::Deleted {
                response: json!({"sandboxId": "sbx-1"}),
            })
            .await
            .unwrap();
        // The door guard has not sent req-1's completion yet: no end.
        assert_eq!(next(&mut received).await, None);
        // Meanwhile its reply opened a tool, which the end must close.
        store
            .set(
                &tool_key("sbx-1", "a"),
                &json!({"activity": {"id": "oshx-tool-a", "kind": "fetch", "input": []}, "state": "opened"})
                    .to_string(),
                None,
            )
            .await
            .unwrap();
        store
            .set(&open_tools_key("sbx-1"), &json!(["a"]).to_string(), None)
            .await
            .unwrap();
        store
            .remove_member(&pending_key("sbx-1"), "req-1")
            .await
            .unwrap();
        assert_eq!(
            next(&mut received).await.as_deref(),
            Some("close-tool sbx-1 oshx-tool-a fetch opened=true")
        );
        assert_eq!(
            next(&mut received).await.as_deref(),
            Some("end sbx-1 timed=false")
        );
    }

    #[tokio::test]
    async fn delete_ends_the_session_anyway_once_the_wait_runs_out() {
        let (calls, mut received) = mpsc::unbounded_channel();
        let store: Arc<dyn SharedStore> = Arc::new(MemoryStore::default());
        store
            .add_member(&pending_key("sbx-1"), "lost", Duration::from_secs(60))
            .await
            .unwrap();
        let sessions = SessionLifecycle::new(
            Arc::new(FakeInventory::default()),
            Arc::new(FakeCore::new(calls, 0)),
            store,
            None,
        )
        .with_pending_wait(Duration::from_millis(300));
        sessions
            .record(InventoryEvent::Deleted {
                response: json!({"sandboxId": "sbx-1"}),
            })
            .await
            .unwrap();
        assert_eq!(
            next(&mut received).await.as_deref(),
            Some("end sbx-1 timed=false")
        );
    }

    #[tokio::test]
    async fn shutdown_ends_a_session_still_waiting_for_the_door_guard() {
        let (calls, mut received) = mpsc::unbounded_channel();
        let store: Arc<dyn SharedStore> = Arc::new(MemoryStore::default());
        store
            .add_member(&pending_key("sbx-1"), "req-1", Duration::from_secs(60))
            .await
            .unwrap();
        let sessions = SessionLifecycle::new(
            Arc::new(FakeInventory::default()),
            Arc::new(FakeCore::new(calls, 0)),
            store,
            None,
        );
        sessions
            .record(InventoryEvent::Deleted {
                response: json!({"sandboxId": "sbx-1"}),
            })
            .await
            .unwrap();
        // The default wait is 30 s; shutdown cuts it to the grace, here half
        // the 300 ms limit, and still sends the end.
        let started = Instant::now();
        assert!(sessions.shutdown(Duration::from_millis(300)).await);
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(
            next(&mut received).await.as_deref(),
            Some("end sbx-1 timed=false")
        );
        // Nothing left to end: returns at once.
        assert!(sessions.shutdown(Duration::from_millis(1)).await);
    }

    #[derive(Default)]
    struct FakeInventory(Mutex<Vec<InventoryEvent>>);

    #[tonic::async_trait]
    impl Inventory for FakeInventory {
        async fn record(&self, event: InventoryEvent) -> Result<(), String> {
            self.0.lock().unwrap().push(event);
            Ok(())
        }
    }

    fn lifecycle(
        fail: bool,
    ) -> (
        SessionLifecycle,
        Arc<FakeInventory>,
        mpsc::UnboundedReceiver<String>,
    ) {
        let (calls, received) = mpsc::unbounded_channel();
        let inventory = Arc::new(FakeInventory::default());
        let sink: Arc<dyn Inventory> = inventory.clone();
        let sessions = SessionLifecycle::new(
            sink,
            Arc::new(FakeCore::new(calls, if fail { u32::MAX } else { 0 })),
            Arc::new(MemoryStore::default()),
            Some("gw-1".to_owned()),
        );
        (sessions, inventory, received)
    }

    async fn next(received: &mut mpsc::UnboundedReceiver<String>) -> Option<String> {
        tokio::time::timeout(Duration::from_secs(1), received.recv())
            .await
            .ok()
            .flatten()
    }

    #[tokio::test]
    async fn create_opens_and_delete_closes_the_session() {
        let (sessions, inventory, mut received) = lifecycle(false);
        let created = InventoryEvent::Created {
            sandbox: json!({"sandbox": {
                "metadata": {"id": "sbx-1", "name": "research"},
                "spec": {"template": {"image": "ubuntu:24.04"}},
            }}),
        };
        let deleted = InventoryEvent::Deleted {
            response: json!({"sandboxId": "sbx-1"}),
        };
        sessions.record(created.clone()).await.unwrap();
        assert_eq!(
            next(&mut received).await.as_deref(),
            Some("start sbx-1 research image=ubuntu:24.04")
        );
        sessions.record(deleted.clone()).await.unwrap();
        assert_eq!(
            next(&mut received).await.as_deref(),
            Some("end sbx-1 timed=true"),
            "the end carries the time since the create"
        );
        assert_eq!(*inventory.0.lock().unwrap(), [created, deleted]);
    }

    #[tokio::test]
    async fn no_id_means_no_core_call() {
        let (sessions, inventory, mut received) = lifecycle(false);
        // ALREADY_ABSENT delete, and a create result without an id.
        sessions
            .record(InventoryEvent::Deleted {
                response: json!({"sandboxId": ""}),
            })
            .await
            .unwrap();
        sessions
            .record(InventoryEvent::Created { sandbox: json!({}) })
            .await
            .unwrap();
        sessions
            .record(InventoryEvent::PolicyChanged {
                request: json!({"version": 2}),
            })
            .await
            .unwrap();
        assert_eq!(next(&mut received).await, None);
        assert_eq!(inventory.0.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn a_core_failure_still_reaches_the_inventory() {
        let (sessions, inventory, mut received) = lifecycle(true);
        sessions
            .record(InventoryEvent::Deleted {
                response: json!({"sandboxId": "sbx-2"}),
            })
            .await
            .unwrap();
        assert_eq!(
            next(&mut received).await.as_deref(),
            Some("end sbx-2 timed=false")
        );
        assert_eq!(inventory.0.lock().unwrap().len(), 1);
    }

    /// Fast retries for tests: 20 ms apart, for `within`, stale after `stale`.
    fn retrying(
        core: FakeCore,
        store: &Arc<dyn SharedStore>,
        within: Duration,
        stale: Duration,
    ) -> SessionLifecycle {
        SessionLifecycle::new(
            Arc::new(FakeInventory::default()),
            Arc::new(core),
            Arc::clone(store),
            None,
        )
        .with_end_retry(within, Duration::from_millis(20), stale)
    }

    async fn owed(store: &Arc<dyn SharedStore>) -> Vec<String> {
        store.members(&ends_owed_key()).await.unwrap()
    }

    async fn delete(sessions: &SessionLifecycle, id: &str) {
        sessions
            .record(InventoryEvent::Deleted {
                response: json!({"sandboxId": id}),
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_failed_end_is_retried_until_core_accepts_it() {
        let (calls, mut received) = mpsc::unbounded_channel();
        let store: Arc<dyn SharedStore> = Arc::new(MemoryStore::default());
        let sessions = retrying(
            FakeCore::new(calls, 2),
            &store,
            Duration::from_secs(5),
            Duration::from_secs(60),
        );
        delete(&sessions, "sbx-1").await;
        for _ in 0..3 {
            assert_eq!(
                next(&mut received).await.as_deref(),
                Some("end sbx-1 timed=false")
            );
        }
        // Accepted on the third: no fourth, and nothing left owed.
        assert_eq!(next(&mut received).await, None);
        assert!(sessions.shutdown(Duration::from_secs(1)).await);
        assert!(owed(&store).await.is_empty());
        assert!(store.get(&end_owed_key("sbx-1")).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn an_end_core_never_accepts_stays_owed_and_the_sweep_finishes_it() {
        let (calls, mut received) = mpsc::unbounded_channel();
        let store: Arc<dyn SharedStore> = Arc::new(MemoryStore::default());
        let down = retrying(
            FakeCore::new(calls, u32::MAX),
            &store,
            Duration::from_millis(100),
            Duration::ZERO,
        );
        delete(&down, "sbx-1").await;
        // Retries run out; the end is kept with its duration slot.
        assert!(down.shutdown(Duration::from_secs(2)).await);
        let mut attempts = 0;
        while let Ok(Some(call)) =
            tokio::time::timeout(Duration::from_millis(50), received.recv()).await
        {
            assert_eq!(call, "end sbx-1 timed=false");
            attempts += 1;
        }
        assert!(attempts > 1, "retried, got {attempts} attempt(s)");
        assert_eq!(owed(&store).await, ["sbx-1"]);

        // A later front desk (after a restart, or another replica) with Core
        // back takes it up and settles it.
        let (calls, mut received) = mpsc::unbounded_channel();
        let up = retrying(
            FakeCore::new(calls, 0),
            &store,
            Duration::from_secs(5),
            Duration::ZERO,
        );
        assert_eq!(up.sweep_owed().await, 1);
        assert_eq!(
            next(&mut received).await.as_deref(),
            Some("end sbx-1 timed=false")
        );
        assert!(up.shutdown(Duration::from_secs(1)).await);
        assert!(owed(&store).await.is_empty());
        assert_eq!(up.sweep_owed().await, 0);
    }

    #[tokio::test]
    async fn the_sweep_leaves_an_end_still_being_retried() {
        let (calls, mut received) = mpsc::unbounded_channel();
        let store: Arc<dyn SharedStore> = Arc::new(MemoryStore::default());
        assert!(owe(store.as_ref(), "sbx-1", Some(42)).await);
        let sessions = retrying(
            FakeCore::new(calls, 0),
            &store,
            Duration::from_secs(5),
            Duration::from_secs(60),
        );
        // Tried just now by someone: not stale, not taken up.
        assert_eq!(sessions.sweep_owed().await, 0);
        assert_eq!(next(&mut received).await, None);
        assert_eq!(owed(&store).await, ["sbx-1"]);
    }

    #[tokio::test]
    async fn a_retry_stops_once_another_front_desk_has_ended_it() {
        let (calls, mut received) = mpsc::unbounded_channel();
        let store: Arc<dyn SharedStore> = Arc::new(MemoryStore::default());
        let sessions = SessionLifecycle::new(
            Arc::new(FakeInventory::default()),
            Arc::new(FakeCore::new(calls, u32::MAX)),
            Arc::clone(&store),
            None,
        )
        .with_end_retry(
            Duration::from_secs(5),
            Duration::from_millis(200),
            Duration::from_secs(60),
        );
        delete(&sessions, "sbx-1").await;
        assert_eq!(
            next(&mut received).await.as_deref(),
            Some("end sbx-1 timed=false")
        );
        // Another replica's end went through and settled it.
        settle(store.as_ref(), "sbx-1").await;
        assert!(sessions.shutdown(Duration::from_secs(2)).await);
        assert_eq!(next(&mut received).await, None);
        assert!(owed(&store).await.is_empty());
    }

    #[tokio::test]
    async fn the_sweep_drops_an_owed_id_whose_entry_is_gone() {
        let (calls, mut received) = mpsc::unbounded_channel();
        let store: Arc<dyn SharedStore> = Arc::new(MemoryStore::default());
        store
            .add_member(&ends_owed_key(), "sbx-gone", END_OWED_TTL)
            .await
            .unwrap();
        let sessions = retrying(
            FakeCore::new(calls, 0),
            &store,
            Duration::from_secs(5),
            Duration::ZERO,
        );
        assert_eq!(sessions.sweep_owed().await, 0);
        assert_eq!(next(&mut received).await, None);
        assert!(owed(&store).await.is_empty());
    }
}
