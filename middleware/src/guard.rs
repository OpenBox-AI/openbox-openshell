//! The decision engine: one `OpenBox` verdict per evaluated request, mapped
//! onto `OpenShell`'s allow/deny result.
//!
//! | Core verdict      | Result for this request                                  |
//! |-------------------|----------------------------------------------------------|
//! | allow             | allow                                                    |
//! | `constrain`       | allow; the action already runs in a sandbox (see below)  |
//! | `require_approval`| deny `openbox_approval_required`; retry after approval   |
//! | block             | deny `openbox_blocked`                                   |
//! | halt              | deny `openbox_halted`, stop the sandbox, deny all after  |
//!
//! CONSTRAIN in `OpenBox` means "run this in a sandbox". Traffic reaching this
//! middleware already comes from inside an `OpenShell` sandbox under policy, so
//! the constraint is met and the request proceeds, with a finding recording it.
//!
//! Each request is its own Core activity (`oshx-<request id>`), and its
//! response closes it ([`Guard::complete`]).
//!
//! Approvals are deny-then-retry, because `OpenShell` has no way to hold a
//! request. When Core requires approval, the guard records `sandbox + action
//! fingerprint → activity id` in the shared store. The identical retry, on any
//! replica, finds that activity and asks Core about it: approved lets it be
//! scored under that activity and through (where Core's grant matches), still
//! pending denies it without re-scoring, and a human rejection (which Core
//! reports as halt) stops the sandbox. Without an entry, or when the store is
//! unreachable, the retry is a new activity and is scored afresh, so a lost
//! entry can cost a second approval but never skips one.
//!
//! Every failure to get a verdict is an explicit deny with
//! `openbox_unavailable`, never an allow.
//!
//! Core runs policy, guardrails and behaviour rules in full on every call,
//! so a verdict can take seconds. All Core calls for one request (session
//! start, approval check, evaluation) share one budget, [`DEFAULT_CORE_BUDGET`]
//! unless configured. It must end before `OpenShell`'s middleware timeout
//! (30 s, the most `OpenShell` allows) so the sandbox gets our explicit deny
//! rather than the gateway's generic failure.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use openshell_core::proto::{Decision, Finding, HttpRequestResult};
use serde_json::{Value, json};

use crate::action::Action;
use crate::core_client::{
    ApprovalState, Completion, CoreDecision, CoreError, Verdict, activity_name, request_activity_id,
};
use crate::metrics::{CoreCall, Metrics};
use crate::store::{MemoryStore, SharedStore, approval_key, request_key};

/// How long an approval can be matched by its retry, unless configured.
pub const DEFAULT_APPROVAL_TTL: Duration = Duration::from_secs(15 * 60);
/// How long a request waits for its response to complete its activity.
const REQUEST_TTL: Duration = Duration::from_secs(60 * 60);

pub const REASON_APPROVAL_REQUIRED: &str = "openbox_approval_required";
pub const REASON_BLOCKED: &str = "openbox_blocked";
pub const REASON_HALTED: &str = "openbox_halted";
pub const REASON_UNAVAILABLE: &str = "openbox_unavailable";

const MAX_REASON_BYTES: usize = 4 * 1024;

/// Time allowed for all Core calls behind one verdict: 1 s under the 30 s
/// middleware timeout the gateway registration uses.
pub const DEFAULT_CORE_BUDGET: Duration = Duration::from_secs(29);

/// Core's governance API, as the guard uses it.
#[tonic::async_trait]
pub trait Governance: Send + Sync + 'static {
    async fn start_session(
        &self,
        sandbox_id: &str,
        sandbox_name: &str,
    ) -> Result<CoreDecision, CoreError>;
    async fn evaluate_action(
        &self,
        action: &Action,
        activity_id: &str,
    ) -> Result<CoreDecision, CoreError>;
    async fn approval_state(
        &self,
        action: &Action,
        activity_id: &str,
    ) -> Result<ApprovalState, CoreError>;
    async fn complete_activity(&self, completion: &Completion) -> Result<CoreDecision, CoreError>;
}

#[tonic::async_trait]
impl Governance for crate::core_client::CoreClient {
    async fn start_session(
        &self,
        sandbox_id: &str,
        sandbox_name: &str,
    ) -> Result<CoreDecision, CoreError> {
        Self::start_session(self, sandbox_id, sandbox_name).await
    }
    async fn evaluate_action(
        &self,
        action: &Action,
        activity_id: &str,
    ) -> Result<CoreDecision, CoreError> {
        Self::evaluate_action(self, action, activity_id).await
    }
    async fn approval_state(
        &self,
        action: &Action,
        activity_id: &str,
    ) -> Result<ApprovalState, CoreError> {
        Self::approval_state(self, action, activity_id).await
    }
    async fn complete_activity(&self, completion: &Completion) -> Result<CoreDecision, CoreError> {
        Self::complete_activity(self, completion).await
    }
}

/// A response `OpenShell` is about to return, as the response hook sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponseSeen {
    pub sandbox_id: String,
    pub request_id: String,
    pub method: String,
    pub url: String,
    pub host: String,
    pub status_code: u32,
}

/// Stops a sandbox after a HALT. Called in the background; the triggering
/// request is denied without waiting for it.
#[tonic::async_trait]
pub trait SandboxStopper: Send + Sync + 'static {
    async fn stop(
        &self,
        sandbox_id: &str,
        sandbox_name: &str,
        workspace: &str,
    ) -> Result<(), String>;
}

/// Per-binding behaviour selected by the sandbox policy's middleware config.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ApprovalMode {
    /// Deny, and let the identical retry through once a human approves.
    #[default]
    Queue,
    /// Treat `REQUIRE_APPROVAL` as a block.
    Deny,
}

pub struct Guard<G, S: ?Sized> {
    governance: Arc<G>,
    stopper: Arc<S>,
    store: Arc<dyn SharedStore>,
    approval_ttl: Duration,
    sessions: Mutex<HashSet<String>>,
    /// Local cache only: Core latches a halted session, so a replica that
    /// missed the halt still gets `halt` for the sandbox's next request.
    halted: Arc<Mutex<HashSet<String>>>,
    metrics: Arc<Metrics>,
    core_budget: Duration,
}

impl<G: Governance, S: SandboxStopper + ?Sized> Guard<G, S> {
    /// One replica: approvals and requests are remembered in process.
    pub fn new(governance: Arc<G>, stopper: Arc<S>) -> Self {
        Self::with_store(
            governance,
            stopper,
            Arc::new(MemoryStore::default()),
            DEFAULT_APPROVAL_TTL,
        )
    }

    pub fn with_store(
        governance: Arc<G>,
        stopper: Arc<S>,
        store: Arc<dyn SharedStore>,
        approval_ttl: Duration,
    ) -> Self {
        Self {
            governance,
            stopper,
            store,
            approval_ttl,
            sessions: Mutex::new(HashSet::new()),
            halted: Arc::new(Mutex::new(HashSet::new())),
            metrics: Arc::new(Metrics::default()),
            core_budget: DEFAULT_CORE_BUDGET,
        }
    }

    /// Replaces [`DEFAULT_CORE_BUDGET`].
    #[must_use]
    pub fn with_core_budget(mut self, budget: Duration) -> Self {
        self.core_budget = budget;
        self
    }

    pub fn metrics(&self) -> Arc<Metrics> {
        Arc::clone(&self.metrics)
    }

    /// Evaluates one request and records its result. The log line carries
    /// identifiers and the outcome only, never request content.
    pub async fn evaluate(&self, action: &Action, mode: ApprovalMode) -> HttpRequestResult {
        let started = std::time::Instant::now();
        let result = self.decide(action, mode).await;
        let elapsed = started.elapsed();
        let allowed = result.decision == Decision::Allow as i32;
        self.metrics
            .record_result(allowed, &result.reason_code, elapsed);
        eprintln!(
            "openbox: eval request_id={} sandbox_id={} decision={} reason_code={} ms={}",
            action.request_id,
            action.sandbox_id,
            if allowed { "allow" } else { "deny" },
            if result.reason_code.is_empty() {
                "-"
            } else {
                &result.reason_code
            },
            elapsed.as_millis()
        );
        result
    }

    async fn timed<T>(
        &self,
        call: CoreCall,
        future: impl Future<Output = Result<T, CoreError>>,
    ) -> Result<T, CoreError> {
        let started = std::time::Instant::now();
        let outcome = future.await;
        self.metrics
            .record_core(call, outcome.is_ok(), started.elapsed());
        outcome
    }

    async fn decide(&self, action: &Action, mode: ApprovalMode) -> HttpRequestResult {
        if action.sandbox_id.is_empty() {
            return deny(REASON_UNAVAILABLE, "request carried no sandbox id", None);
        }
        if self.is_halted(&action.sandbox_id) {
            return deny(REASON_HALTED, "sandbox was halted by OpenBox", None);
        }
        tokio::time::timeout(self.core_budget, self.decide_with_core(action, mode))
            .await
            .unwrap_or_else(|_| {
                deny(
                    REASON_UNAVAILABLE,
                    &format!(
                        "OpenBox did not return a verdict within {} ms",
                        self.core_budget.as_millis()
                    ),
                    None,
                )
            })
    }

    async fn decide_with_core(&self, action: &Action, mode: ApprovalMode) -> HttpRequestResult {
        if let Some(result) = self.ensure_session(action).await {
            return result;
        }
        let approval = approval_key(&action.sandbox_id, &action.fingerprint);
        let mut activity_id = request_activity_id(&action.request_id);
        if mode == ApprovalMode::Queue {
            match self.store.get(&approval).await {
                Ok(Some(held)) => match self
                    .timed(
                        CoreCall::Approval,
                        self.governance.approval_state(action, &held),
                    )
                    .await
                {
                    Ok(ApprovalState::Pending { .. }) => {
                        return deny(REASON_APPROVAL_REQUIRED, "awaiting human approval", None);
                    }
                    Ok(ApprovalState::Approved) => activity_id = held,
                    Ok(ApprovalState::Gone) => {
                        let _ = self.store.delete(&approval).await;
                    }
                    Ok(ApprovalState::Rejected(verdict)) => {
                        let decision = CoreDecision {
                            verdict,
                            reason: Some("approval was rejected".to_owned()),
                            governance_event_id: None,
                            risk_score: None,
                            approval_expires_at: None,
                            policy_id: None,
                        };
                        return self.apply(action, mode, &decision);
                    }
                    Err(error) => return deny(REASON_UNAVAILABLE, &error.to_string(), None),
                },
                Ok(None) => {}
                Err(error) => eprintln!(
                    "openbox: approval lookup unavailable, scoring request_id={} as a new activity: {error}",
                    action.request_id
                ),
            }
        }
        let decision = match self
            .timed(
                CoreCall::Evaluate,
                self.governance.evaluate_action(action, &activity_id),
            )
            .await
        {
            Ok(decision) => decision,
            Err(error) => return deny(REASON_UNAVAILABLE, &error.to_string(), None),
        };
        if mode == ApprovalMode::Queue
            && decision.verdict == Verdict::RequireApproval
            && let Err(error) = self
                .store
                .set(&approval, &activity_id, Some(self.approval_ttl))
                .await
        {
            eprintln!(
                "openbox: approval for request_id={} not recorded, its retry will be scored again: {error}",
                action.request_id
            );
        }
        let result = self.apply(action, mode, &decision);
        if result.decision == Decision::Allow as i32 {
            let record = json!({
                "activity_id": activity_id,
                "activity_type": activity_name(action),
                "started_ms": unix_millis(),
            });
            if let Err(error) = self
                .store
                .set(
                    &request_key(&action.request_id),
                    &record.to_string(),
                    Some(REQUEST_TTL),
                )
                .await
            {
                eprintln!(
                    "openbox: request_id={} not recorded, its completion carries no duration: {error}",
                    action.request_id
                );
            }
        }
        result
    }

    /// Closes the activity a response belongs to. Runs in the background: the
    /// response is not held for Core.
    pub async fn complete(&self, response: ResponseSeen) {
        let record = self
            .store
            .take(&request_key(&response.request_id))
            .await
            .unwrap_or_default()
            .and_then(|text| serde_json::from_str::<Value>(&text).ok());
        let field = |name: &str| {
            record
                .as_ref()
                .and_then(|record| record.get(name))
                .and_then(Value::as_str)
                .map(str::to_owned)
        };
        let completion = Completion {
            activity_id: field("activity_id")
                .unwrap_or_else(|| request_activity_id(&response.request_id)),
            activity_type: field("activity_type")
                .unwrap_or_else(|| format!("{} {}", response.method, response.host)),
            duration_ms: record
                .as_ref()
                .and_then(|record| record.get("started_ms"))
                .and_then(Value::as_u64)
                .map(|started| unix_millis().saturating_sub(started)),
            sandbox_id: response.sandbox_id,
            request_id: response.request_id,
            method: response.method,
            url: response.url,
            status_code: response.status_code,
        };
        let governance = Arc::clone(&self.governance);
        tokio::spawn(async move {
            match governance.complete_activity(&completion).await {
                Ok(_) => eprintln!(
                    "openbox: completed request_id={} activity_id={} status={}",
                    completion.request_id, completion.activity_id, completion.status_code
                ),
                Err(error) => eprintln!(
                    "openbox: completion for request_id={} failed: {error}",
                    completion.request_id
                ),
            }
        });
    }

    async fn ensure_session(&self, action: &Action) -> Option<HttpRequestResult> {
        if self.lock_sessions().contains(&action.sandbox_id) {
            return None;
        }
        match self
            .timed(
                CoreCall::Session,
                self.governance
                    .start_session(&action.sandbox_id, &action.sandbox_name),
            )
            .await
        {
            Ok(decision) if decision.verdict == Verdict::Halt => {
                Some(self.halt(action, decision.reason.as_deref(), &decision))
            }
            Ok(_) => {
                self.lock_sessions().insert(action.sandbox_id.clone());
                None
            }
            Err(error) => Some(deny(REASON_UNAVAILABLE, &error.to_string(), None)),
        }
    }

    fn apply(
        &self,
        action: &Action,
        mode: ApprovalMode,
        decision: &CoreDecision,
    ) -> HttpRequestResult {
        match decision.verdict {
            Verdict::Allow => allow(decision, "allow"),
            Verdict::Constrain => allow(decision, "constrain_met_by_sandbox"),
            Verdict::RequireApproval if mode == ApprovalMode::Queue => deny(
                REASON_APPROVAL_REQUIRED,
                decision
                    .reason
                    .as_deref()
                    .unwrap_or("human approval required"),
                Some(decision),
            ),
            Verdict::RequireApproval | Verdict::Block => deny(
                REASON_BLOCKED,
                decision
                    .reason
                    .as_deref()
                    .unwrap_or("blocked by OpenBox policy"),
                Some(decision),
            ),
            Verdict::Halt => self.halt(action, decision.reason.as_deref(), decision),
        }
    }

    fn halt(
        &self,
        action: &Action,
        reason: Option<&str>,
        decision: &CoreDecision,
    ) -> HttpRequestResult {
        let first = self
            .halted
            .lock()
            .expect("halted set lock")
            .insert(action.sandbox_id.clone());
        if first {
            let stopper = Arc::clone(&self.stopper);
            let (sandbox_id, sandbox_name, workspace) = (
                action.sandbox_id.clone(),
                action.sandbox_name.clone(),
                action.workspace.clone(),
            );
            tokio::spawn(async move {
                match stopper.stop(&sandbox_id, &sandbox_name, &workspace).await {
                    Ok(()) => eprintln!("openbox: halted sandbox {sandbox_id} stopped"),
                    Err(error) => eprintln!(
                        "openbox: halted sandbox {sandbox_id} could not be stopped: {error}"
                    ),
                }
            });
        }
        deny(
            REASON_HALTED,
            reason.unwrap_or("halted by OpenBox"),
            Some(decision),
        )
    }

    fn is_halted(&self, sandbox_id: &str) -> bool {
        self.halted
            .lock()
            .expect("halted set lock")
            .contains(sandbox_id)
    }

    fn lock_sessions(&self) -> std::sync::MutexGuard<'_, HashSet<String>> {
        self.sessions.lock().expect("session set lock")
    }
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

fn allow(decision: &CoreDecision, label: &str) -> HttpRequestResult {
    HttpRequestResult {
        decision: Decision::Allow as i32,
        findings: vec![finding(label, "info")],
        metadata: metadata(Some(decision)),
        ..HttpRequestResult::default()
    }
}

fn deny(reason_code: &str, reason: &str, decision: Option<&CoreDecision>) -> HttpRequestResult {
    let severity = match reason_code {
        REASON_HALTED => "critical",
        REASON_BLOCKED => "high",
        _ => "medium",
    };
    HttpRequestResult {
        decision: Decision::Deny as i32,
        reason: truncate(reason, MAX_REASON_BYTES),
        reason_code: reason_code.to_owned(),
        findings: vec![finding(
            reason_code.trim_start_matches("openbox_"),
            severity,
        )],
        metadata: metadata(decision),
        ..HttpRequestResult::default()
    }
}

fn finding(label: &str, severity: &str) -> Finding {
    Finding {
        r#type: "openbox.verdict".to_owned(),
        label: label.to_owned(),
        count: 1,
        confidence: "certain".to_owned(),
        severity: severity.to_owned(),
    }
}

fn metadata(decision: Option<&CoreDecision>) -> HashMap<String, String> {
    let mut metadata = HashMap::new();
    if let Some(decision) = decision {
        if let Some(id) = &decision.governance_event_id {
            metadata.insert("openbox.governance_event_id".to_owned(), id.clone());
        }
        if let Some(score) = decision.risk_score {
            metadata.insert("openbox.risk_score".to_owned(), format!("{score:.3}"));
        }
        if let Some(policy) = &decision.policy_id {
            metadata.insert("openbox.policy_id".to_owned(), policy.clone());
        }
    }
    metadata
}

fn truncate(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_owned();
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::action::tests::evaluation;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    pub struct FakeCore {
        pub session: Mutex<VecDeque<Result<Verdict, ()>>>,
        pub verdicts: Mutex<VecDeque<Result<Verdict, ()>>>,
        pub approvals: Mutex<VecDeque<Result<ApprovalState, ()>>>,
        pub session_calls: AtomicUsize,
        pub evaluate_calls: AtomicUsize,
        pub approval_calls: AtomicUsize,
        /// How long every call takes.
        pub delay: Duration,
        /// Activity ids, in call order, of evaluations and approval polls.
        pub evaluated: Mutex<Vec<String>>,
        pub polled: Mutex<Vec<String>>,
        pub completions: Mutex<Vec<Completion>>,
    }

    fn decision(verdict: Verdict) -> CoreDecision {
        CoreDecision {
            verdict,
            reason: Some(format!("{verdict:?} by test policy")),
            governance_event_id: Some("evt-1".to_owned()),
            risk_score: Some(0.5),
            approval_expires_at: None,
            policy_id: None,
        }
    }

    impl FakeCore {
        pub fn with_verdicts(verdicts: &[Verdict]) -> Self {
            let fake = Self::default();
            fake.verdicts
                .lock()
                .unwrap()
                .extend(verdicts.iter().copied().map(Ok));
            fake
        }
    }

    #[tonic::async_trait]
    impl Governance for FakeCore {
        async fn start_session(&self, _: &str, _: &str) -> Result<CoreDecision, CoreError> {
            tokio::time::sleep(self.delay).await;
            self.session_calls.fetch_add(1, Ordering::SeqCst);
            let next = self
                .session
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(Ok(Verdict::Allow));
            match next {
                Ok(verdict) => Ok(decision(verdict)),
                Err(()) => Err(CoreError::Transport),
            }
        }
        async fn evaluate_action(
            &self,
            _: &Action,
            activity_id: &str,
        ) -> Result<CoreDecision, CoreError> {
            tokio::time::sleep(self.delay).await;
            self.evaluate_calls.fetch_add(1, Ordering::SeqCst);
            self.evaluated.lock().unwrap().push(activity_id.to_owned());
            let next = self
                .verdicts
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected evaluation");
            match next {
                Ok(verdict) => Ok(decision(verdict)),
                Err(()) => Err(CoreError::Status(500)),
            }
        }
        async fn approval_state(
            &self,
            _: &Action,
            activity_id: &str,
        ) -> Result<ApprovalState, CoreError> {
            tokio::time::sleep(self.delay).await;
            self.approval_calls.fetch_add(1, Ordering::SeqCst);
            self.polled.lock().unwrap().push(activity_id.to_owned());
            self.approvals
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(Ok(ApprovalState::Gone))
                .map_err(|()| CoreError::Transport)
        }
        async fn complete_activity(
            &self,
            completion: &Completion,
        ) -> Result<CoreDecision, CoreError> {
            self.completions.lock().unwrap().push(completion.clone());
            Ok(decision(Verdict::Allow))
        }
    }

    /// A store that is always down.
    struct DownStore;

    #[tonic::async_trait]
    impl SharedStore for DownStore {
        async fn get(&self, _: &str) -> Result<Option<String>, String> {
            Err("down".to_owned())
        }
        async fn set(&self, _: &str, _: &str, _: Option<Duration>) -> Result<(), String> {
            Err("down".to_owned())
        }
        async fn take(&self, _: &str) -> Result<Option<String>, String> {
            Err("down".to_owned())
        }
        async fn delete(&self, _: &str) -> Result<(), String> {
            Err("down".to_owned())
        }
    }

    #[derive(Default)]
    pub struct FakeStopper {
        pub stopped: Mutex<Vec<(String, String)>>,
    }

    #[tonic::async_trait]
    impl SandboxStopper for FakeStopper {
        async fn stop(&self, sandbox_id: &str, sandbox_name: &str, _: &str) -> Result<(), String> {
            self.stopped
                .lock()
                .unwrap()
                .push((sandbox_id.to_owned(), sandbox_name.to_owned()));
            Ok(())
        }
    }

    fn guard(
        core: FakeCore,
    ) -> (
        Guard<FakeCore, FakeStopper>,
        Arc<FakeCore>,
        Arc<FakeStopper>,
    ) {
        let core = Arc::new(core);
        let stopper = Arc::new(FakeStopper::default());
        (
            Guard::new(Arc::clone(&core), Arc::clone(&stopper)),
            core,
            stopper,
        )
    }

    fn action() -> Action {
        request("req-1")
    }

    /// The same action, sent as a new request (a retry).
    fn request(request_id: &str) -> Action {
        let mut evaluation = evaluation(
            "POST",
            "/mcp",
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"pay","arguments":{"amount":10}}}"#,
        );
        evaluation.context.as_mut().unwrap().request_id = request_id.to_owned();
        Action::from_evaluation(&evaluation)
    }

    fn is_allow(result: &HttpRequestResult) -> bool {
        result.decision == Decision::Allow as i32
    }

    #[tokio::test]
    async fn allow_and_constrain_let_the_request_through() {
        let (guard, core, _) = guard(FakeCore::with_verdicts(&[
            Verdict::Allow,
            Verdict::Constrain,
        ]));
        let first = guard.evaluate(&action(), ApprovalMode::Queue).await;
        assert!(is_allow(&first));
        assert_eq!(first.metadata["openbox.governance_event_id"], "evt-1");
        let second = guard.evaluate(&action(), ApprovalMode::Queue).await;
        assert!(is_allow(&second));
        assert_eq!(second.findings[0].label, "constrain_met_by_sandbox");
        assert_eq!(
            core.session_calls.load(Ordering::SeqCst),
            1,
            "one session per sandbox"
        );
    }

    #[tokio::test]
    async fn block_denies_with_a_stable_reason_code() {
        let (guard, _, stopper) = guard(FakeCore::with_verdicts(&[Verdict::Block]));
        let result = guard.evaluate(&action(), ApprovalMode::Queue).await;
        assert_eq!(result.decision, Decision::Deny as i32);
        assert_eq!(result.reason_code, REASON_BLOCKED);
        assert!(stopper.stopped.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn every_request_is_its_own_activity() {
        let (guard, core, _) = guard(FakeCore::with_verdicts(&[Verdict::Allow, Verdict::Allow]));
        guard.evaluate(&request("req-1"), ApprovalMode::Queue).await;
        guard.evaluate(&request("req-2"), ApprovalMode::Queue).await;
        assert_eq!(
            *core.evaluated.lock().unwrap(),
            ["oshx-req-1", "oshx-req-2"]
        );
        assert_eq!(
            core.approval_calls.load(Ordering::SeqCst),
            0,
            "no approval poll without a held approval"
        );
    }

    #[tokio::test]
    async fn approval_is_denied_then_released_on_the_approved_retry() {
        let (guard, core, _) = guard(FakeCore::with_verdicts(&[
            Verdict::RequireApproval,
            Verdict::Allow,
        ]));
        core.approvals.lock().unwrap().extend([
            Ok(ApprovalState::Pending { expires_at: None }),
            Ok(ApprovalState::Approved),
        ]);
        let first = guard.evaluate(&request("req-1"), ApprovalMode::Queue).await;
        assert_eq!(first.reason_code, REASON_APPROVAL_REQUIRED);
        let still_pending = guard.evaluate(&request("req-2"), ApprovalMode::Queue).await;
        assert_eq!(still_pending.reason_code, REASON_APPROVAL_REQUIRED);
        assert_eq!(
            core.evaluate_calls.load(Ordering::SeqCst),
            1,
            "pending retries are not re-scored"
        );
        let approved = guard.evaluate(&request("req-3"), ApprovalMode::Queue).await;
        assert!(is_allow(&approved));
        assert_eq!(
            *core.polled.lock().unwrap(),
            ["oshx-req-1", "oshx-req-1"],
            "retries ask about the activity holding the approval"
        );
        assert_eq!(
            *core.evaluated.lock().unwrap(),
            ["oshx-req-1", "oshx-req-1"],
            "the approved retry is scored under that activity, where Core's grant matches"
        );
    }

    #[tokio::test]
    async fn a_replica_that_missed_the_first_attempt_honours_the_approval() {
        // Regression: a replica with no memory of the first attempt used to
        // re-score the retry, which made Core write a fresh pending verdict
        // over the human's approval. The shared store is that memory.
        let store: Arc<dyn SharedStore> = Arc::new(MemoryStore::default());
        let core = Arc::new(FakeCore::with_verdicts(&[
            Verdict::RequireApproval,
            Verdict::Allow,
        ]));
        core.approvals.lock().unwrap().extend([
            Ok(ApprovalState::Pending { expires_at: None }),
            Ok(ApprovalState::Approved),
        ]);
        let replica = |store: &Arc<dyn SharedStore>| {
            Guard::with_store(
                Arc::clone(&core),
                Arc::new(FakeStopper::default()),
                Arc::clone(store),
                DEFAULT_APPROVAL_TTL,
            )
        };
        let (first, second) = (replica(&store), replica(&store));
        first.evaluate(&request("req-1"), ApprovalMode::Queue).await;
        let pending = second
            .evaluate(&request("req-2"), ApprovalMode::Queue)
            .await;
        assert_eq!(pending.reason_code, REASON_APPROVAL_REQUIRED);
        assert_eq!(
            core.evaluate_calls.load(Ordering::SeqCst),
            1,
            "a pending action is never re-scored"
        );
        let approved = second
            .evaluate(&request("req-3"), ApprovalMode::Queue)
            .await;
        assert!(is_allow(&approved));
        assert_eq!(core.evaluated.lock().unwrap()[1], "oshx-req-1");
    }

    #[tokio::test]
    async fn without_the_store_a_retry_is_scored_again_never_released() {
        let core = Arc::new(FakeCore::with_verdicts(&[
            Verdict::RequireApproval,
            Verdict::RequireApproval,
        ]));
        let guard = Guard::with_store(
            Arc::clone(&core),
            Arc::new(FakeStopper::default()),
            Arc::new(DownStore),
            DEFAULT_APPROVAL_TTL,
        );
        let first = guard.evaluate(&request("req-1"), ApprovalMode::Queue).await;
        let retry = guard.evaluate(&request("req-2"), ApprovalMode::Queue).await;
        assert_eq!(first.reason_code, REASON_APPROVAL_REQUIRED);
        assert_eq!(retry.reason_code, REASON_APPROVAL_REQUIRED);
        assert_eq!(
            *core.evaluated.lock().unwrap(),
            ["oshx-req-1", "oshx-req-2"]
        );
        assert_eq!(core.approval_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_response_completes_its_requests_activity() {
        let (guard, core, _) = guard(FakeCore::with_verdicts(&[Verdict::Allow]));
        guard.evaluate(&request("req-1"), ApprovalMode::Queue).await;
        let seen = |request_id: &str, status_code| ResponseSeen {
            sandbox_id: "sbx-id-1".to_owned(),
            request_id: request_id.to_owned(),
            method: "POST".to_owned(),
            url: "https://mcp.example.com/mcp".to_owned(),
            host: "mcp.example.com".to_owned(),
            status_code,
        };
        guard.complete(seen("req-1", 200)).await;
        // A response for a request this replica never recorded still closes
        // the request's own activity, without a duration.
        guard.complete(seen("req-9", 503)).await;
        for _ in 0..50 {
            if core.completions.lock().unwrap().len() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let completions = core.completions.lock().unwrap();
        let first = completions
            .iter()
            .find(|c| c.request_id == "req-1")
            .unwrap();
        assert_eq!(first.activity_id, "oshx-req-1");
        assert_eq!(first.activity_type, "MCP pay");
        assert!(first.duration_ms.is_some());
        let other = completions
            .iter()
            .find(|c| c.request_id == "req-9")
            .unwrap();
        assert_eq!(other.activity_id, "oshx-req-9");
        assert_eq!(other.activity_type, "POST mcp.example.com");
        assert_eq!(other.duration_ms, None);
    }

    #[tokio::test]
    async fn a_modified_retry_is_scored_afresh() {
        let (guard, core, _) = guard(FakeCore::with_verdicts(&[
            Verdict::RequireApproval,
            Verdict::Block,
        ]));
        guard.evaluate(&action(), ApprovalMode::Queue).await;
        let modified = Action::from_evaluation(&evaluation(
            "POST",
            "/mcp",
            br#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"pay","arguments":{"amount":99999}}}"#,
        ));
        let result = guard.evaluate(&modified, ApprovalMode::Queue).await;
        assert_eq!(result.reason_code, REASON_BLOCKED);
        assert_eq!(core.evaluate_calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_rejected_approval_halts_the_sandbox() {
        let (guard, core, stopper) = guard(FakeCore::with_verdicts(&[Verdict::RequireApproval]));
        core.approvals
            .lock()
            .unwrap()
            .push_back(Ok(ApprovalState::Rejected(Verdict::Halt)));
        guard.evaluate(&action(), ApprovalMode::Queue).await;
        let result = guard.evaluate(&action(), ApprovalMode::Queue).await;
        assert_eq!(result.reason_code, REASON_HALTED);
        tokio::task::yield_now().await;
        assert_eq!(stopper.stopped.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn deny_mode_treats_approval_as_a_block() {
        let (guard, _, _) = guard(FakeCore::with_verdicts(&[Verdict::RequireApproval]));
        let result = guard.evaluate(&action(), ApprovalMode::Deny).await;
        assert_eq!(result.reason_code, REASON_BLOCKED);
    }

    #[tokio::test]
    async fn halt_stops_once_and_denies_everything_after_without_asking_core() {
        let (guard, core, stopper) = guard(FakeCore::with_verdicts(&[Verdict::Halt]));
        let result = guard.evaluate(&action(), ApprovalMode::Queue).await;
        assert_eq!(result.reason_code, REASON_HALTED);
        let other = Action::from_evaluation(&evaluation("GET", "/anything", b""));
        let after = guard.evaluate(&other, ApprovalMode::Queue).await;
        assert_eq!(after.reason_code, REASON_HALTED);
        assert_eq!(core.evaluate_calls.load(Ordering::SeqCst), 1);
        tokio::task::yield_now().await;
        assert_eq!(
            *stopper.stopped.lock().unwrap(),
            [("sbx-id-1".to_owned(), "sbx-name".to_owned())]
        );
    }

    #[tokio::test]
    async fn a_halted_session_at_start_halts_the_sandbox() {
        let core = FakeCore::default();
        core.session.lock().unwrap().push_back(Ok(Verdict::Halt));
        let (guard, core, _) = guard(core);
        let result = guard.evaluate(&action(), ApprovalMode::Queue).await;
        assert_eq!(result.reason_code, REASON_HALTED);
        assert_eq!(core.evaluate_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn every_core_failure_is_an_explicit_deny() {
        let core = FakeCore::default();
        core.session.lock().unwrap().push_back(Err(()));
        let (guard, core, _) = guard(core);
        assert_eq!(
            guard
                .evaluate(&action(), ApprovalMode::Queue)
                .await
                .reason_code,
            REASON_UNAVAILABLE,
            "session start failure"
        );
        core.verdicts.lock().unwrap().push_back(Err(()));
        assert_eq!(
            guard
                .evaluate(&action(), ApprovalMode::Queue)
                .await
                .reason_code,
            REASON_UNAVAILABLE,
            "evaluation failure"
        );
        core.verdicts
            .lock()
            .unwrap()
            .push_back(Ok(Verdict::RequireApproval));
        guard.evaluate(&action(), ApprovalMode::Queue).await;
        core.approvals.lock().unwrap().push_back(Err(()));
        assert_eq!(
            guard
                .evaluate(&action(), ApprovalMode::Queue)
                .await
                .reason_code,
            REASON_UNAVAILABLE,
            "approval poll failure"
        );
    }

    fn slow_core(delay: Duration, verdicts: &[Verdict]) -> FakeCore {
        FakeCore {
            delay,
            ..FakeCore::with_verdicts(verdicts)
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_verdict_that_takes_seconds_still_arrives() {
        // Full policy, guardrails and behaviour rules: slow, but inside budget.
        let (guard, _, _) = guard(slow_core(Duration::from_secs(9), &[Verdict::Allow]));
        let started = tokio::time::Instant::now();
        let result = guard.evaluate(&action(), ApprovalMode::Queue).await;
        assert!(is_allow(&result), "{result:?}");
        // Session start and evaluation: two calls. (The approval check only
        // runs for a retry of an action holding an approval.)
        assert_eq!(started.elapsed(), Duration::from_secs(18));
    }

    #[tokio::test(start_paused = true)]
    async fn the_budget_covers_every_core_call_for_the_request() {
        // Each call is inside the budget; the two together are not.
        let (guard, core, _) = guard(slow_core(Duration::from_secs(15), &[Verdict::Allow]));
        let started = tokio::time::Instant::now();
        let result = guard.evaluate(&action(), ApprovalMode::Queue).await;
        assert_eq!(result.reason_code, REASON_UNAVAILABLE);
        assert!(result.reason.contains("29000 ms"), "{}", result.reason);
        assert_eq!(started.elapsed(), DEFAULT_CORE_BUDGET);
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "before the gateway gives up"
        );
        // Session (15 s) finished; evaluation was cut off at 29 s.
        assert_eq!(core.session_calls.load(Ordering::SeqCst), 1);
        assert_eq!(core.approval_calls.load(Ordering::SeqCst), 0);
        assert_eq!(core.evaluate_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn the_budget_is_configurable() {
        let (guard, _, _) = guard(slow_core(Duration::from_millis(300), &[Verdict::Allow]));
        let guard = guard.with_core_budget(Duration::from_millis(500));
        let result = guard.evaluate(&action(), ApprovalMode::Queue).await;
        assert_eq!(result.reason_code, REASON_UNAVAILABLE);
    }

    #[tokio::test]
    async fn a_request_without_a_sandbox_id_is_denied() {
        let (guard, core, _) = guard(FakeCore::default());
        let mut evaluation = evaluation("GET", "/", b"");
        evaluation.context.as_mut().unwrap().sandbox_id.clear();
        let result = guard
            .evaluate(&Action::from_evaluation(&evaluation), ApprovalMode::Queue)
            .await;
        assert_eq!(result.reason_code, REASON_UNAVAILABLE);
        assert_eq!(core.session_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn reasons_are_bounded_on_a_char_boundary() {
        let long = "é".repeat(MAX_REASON_BYTES);
        let result = deny(REASON_BLOCKED, &long, None);
        assert!(result.reason.len() <= MAX_REASON_BYTES);
        assert!(result.reason.chars().all(|c| c == 'é'));
    }
}
