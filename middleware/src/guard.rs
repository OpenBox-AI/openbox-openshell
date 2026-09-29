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
//! Approvals are deny-then-retry, because `OpenShell` has no way to hold a
//! request. The first attempt is denied with a stable reason code and
//! remembered by fingerprint. When the identical action comes back, the
//! approval is read from Core: approved lets it through, still pending denies
//! it again, and a human rejection (which Core reports as halt) stops the
//! sandbox. Losing this memory on restart is safe: the retry is evaluated
//! afresh and, at worst, asks for approval again.
//!
//! Every failure to get a verdict is an explicit deny with
//! `openbox_unavailable`, never an allow.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use openshell_core::proto::{Decision, Finding, HttpRequestResult};

use crate::action::Action;
use crate::core_client::{ApprovalState, CoreDecision, CoreError, Verdict, unix_now};

pub const REASON_APPROVAL_REQUIRED: &str = "openbox_approval_required";
pub const REASON_BLOCKED: &str = "openbox_blocked";
pub const REASON_HALTED: &str = "openbox_halted";
pub const REASON_UNAVAILABLE: &str = "openbox_unavailable";

const MAX_REASON_BYTES: usize = 4 * 1024;
/// Fallback lifetime of a remembered approval when Core gives no expiry.
const DEFAULT_APPROVAL_SECS: i64 = 30 * 60;

/// Core's governance API, as the guard uses it.
#[tonic::async_trait]
pub trait Governance: Send + Sync + 'static {
    async fn start_session(
        &self,
        sandbox_id: &str,
        sandbox_name: &str,
    ) -> Result<CoreDecision, CoreError>;
    async fn evaluate_action(&self, action: &Action) -> Result<CoreDecision, CoreError>;
    async fn approval_state(&self, action: &Action) -> Result<ApprovalState, CoreError>;
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
    async fn evaluate_action(&self, action: &Action) -> Result<CoreDecision, CoreError> {
        Self::evaluate_action(self, action).await
    }
    async fn approval_state(&self, action: &Action) -> Result<ApprovalState, CoreError> {
        Self::approval_state(self, action).await
    }
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
    /// Deny, remember the action, and let the approved retry through.
    #[default]
    Queue,
    /// Treat `REQUIRE_APPROVAL` as a block.
    Deny,
}

pub struct Guard<G, S: ?Sized> {
    governance: Arc<G>,
    stopper: Arc<S>,
    sessions: Mutex<HashSet<String>>,
    halted: Arc<Mutex<HashSet<String>>>,
    /// (sandbox id, fingerprint) → Unix-seconds expiry of a pending approval.
    pending: Mutex<HashMap<(String, String), i64>>,
}

impl<G: Governance, S: SandboxStopper + ?Sized> Guard<G, S> {
    pub fn new(governance: Arc<G>, stopper: Arc<S>) -> Self {
        Self {
            governance,
            stopper,
            sessions: Mutex::new(HashSet::new()),
            halted: Arc::new(Mutex::new(HashSet::new())),
            pending: Mutex::new(HashMap::new()),
        }
    }

    pub async fn evaluate(&self, action: &Action, mode: ApprovalMode) -> HttpRequestResult {
        if action.sandbox_id.is_empty() {
            return deny(REASON_UNAVAILABLE, "request carried no sandbox id", None);
        }
        if self.is_halted(&action.sandbox_id) {
            return deny(REASON_HALTED, "sandbox was halted by OpenBox", None);
        }
        if let Some(result) = self.ensure_session(action).await {
            return result;
        }
        let key = (action.sandbox_id.clone(), action.fingerprint.clone());
        if self.pending_expiry(&key).is_some() {
            match self.governance.approval_state(action).await {
                Ok(ApprovalState::Pending { .. }) => {
                    return deny(REASON_APPROVAL_REQUIRED, "awaiting human approval", None);
                }
                Ok(ApprovalState::Approved | ApprovalState::Gone) => self.forget(&key),
                Ok(ApprovalState::Rejected(verdict)) => {
                    self.forget(&key);
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
            }
        }
        match self.governance.evaluate_action(action).await {
            Ok(decision) => self.apply(action, mode, &decision),
            Err(error) => deny(REASON_UNAVAILABLE, &error.to_string(), None),
        }
    }

    async fn ensure_session(&self, action: &Action) -> Option<HttpRequestResult> {
        if self.lock_sessions().contains(&action.sandbox_id) {
            return None;
        }
        match self
            .governance
            .start_session(&action.sandbox_id, &action.sandbox_name)
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
            Verdict::RequireApproval if mode == ApprovalMode::Queue => {
                let expires_at = decision
                    .approval_expires_at
                    .unwrap_or_else(|| unix_now() + DEFAULT_APPROVAL_SECS);
                self.remember(
                    (action.sandbox_id.clone(), action.fingerprint.clone()),
                    expires_at,
                );
                deny(
                    REASON_APPROVAL_REQUIRED,
                    decision
                        .reason
                        .as_deref()
                        .unwrap_or("human approval required"),
                    Some(decision),
                )
            }
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

    fn pending_expiry(&self, key: &(String, String)) -> Option<i64> {
        let mut pending = self.pending.lock().expect("pending lock");
        let now = unix_now();
        pending.retain(|_, expires_at| *expires_at > now);
        pending.get(key).copied()
    }

    fn remember(&self, key: (String, String), expires_at: i64) {
        self.pending
            .lock()
            .expect("pending lock")
            .insert(key, expires_at);
    }

    fn forget(&self, key: &(String, String)) {
        self.pending.lock().expect("pending lock").remove(key);
    }
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
        async fn evaluate_action(&self, _: &Action) -> Result<CoreDecision, CoreError> {
            self.evaluate_calls.fetch_add(1, Ordering::SeqCst);
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
        async fn approval_state(&self, _: &Action) -> Result<ApprovalState, CoreError> {
            self.approval_calls.fetch_add(1, Ordering::SeqCst);
            self.approvals
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected approval poll")
                .map_err(|()| CoreError::Transport)
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
        Action::from_evaluation(&evaluation(
            "POST",
            "/mcp",
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"pay","arguments":{"amount":10}}}"#,
        ))
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
    async fn approval_is_denied_then_released_on_the_approved_retry() {
        let (guard, core, _) = guard(FakeCore::with_verdicts(&[
            Verdict::RequireApproval,
            Verdict::Allow,
        ]));
        core.approvals.lock().unwrap().extend([
            Ok(ApprovalState::Pending { expires_at: None }),
            Ok(ApprovalState::Approved),
        ]);
        let first = guard.evaluate(&action(), ApprovalMode::Queue).await;
        assert_eq!(first.reason_code, REASON_APPROVAL_REQUIRED);
        let still_pending = guard.evaluate(&action(), ApprovalMode::Queue).await;
        assert_eq!(still_pending.reason_code, REASON_APPROVAL_REQUIRED);
        assert_eq!(
            core.evaluate_calls.load(Ordering::SeqCst),
            1,
            "pending retries are not re-scored"
        );
        let approved = guard.evaluate(&action(), ApprovalMode::Queue).await;
        assert!(is_allow(&approved));
        assert_eq!(core.approval_calls.load(Ordering::SeqCst), 2);
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
        assert_eq!(core.approval_calls.load(Ordering::SeqCst), 0);
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
