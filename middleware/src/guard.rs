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
//! Sessions follow the agent SDK's activity pattern ([`crate::agent`]):
//!
//! | Request                         | Activity                                    |
//! |---------------------------------|---------------------------------------------|
//! | a model call                    | its own `llm_call`, closed by its reply     |
//! | an MCP `tools/call`             | its own, named by the tool                  |
//! | any other, while a tool is open | the tool the model last asked for           |
//! | any other                       | its own, named by method and host           |
//!
//! Every request is a span on its activity: started with its verdict,
//! completed with its response ([`Guard::complete`]). A model call's reply
//! opens the tools it asks for; the agent's next model call closes them with
//! their results. Which tools are open lives in the shared store, so any
//! replica routes a sandbox's requests the same way.
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
//! A model call that carries a new user prompt ([`crate::prompt`]) is preceded
//! by a `SignalReceived` for that prompt, and Core's verdict on the prompt
//! applies to the call: a blocked prompt denies it. A turn is remembered only
//! once its prompt is allowed, so a blocked prompt is signalled again on retry
//! and Core replays the same verdict. Failing to record a prompt does not deny
//! the call; the call's own verdict still does.
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
use opentelemetry::trace::{FutureExt as _, SpanKind, Status, TraceContextExt as _};
use opentelemetry::{Context, KeyValue};
use serde_json::{Value, json};

use sha2::Digest as _;

use crate::action::{Action, Payload};
use crate::agent;
use crate::capture;
use crate::core_client::{
    Activity, ApprovalState, Completion, CoreDecision, CoreError, LLM_CALL, Outcome, Verdict,
    activity_name, request_activity_id, request_url, span_ids, started_span, tool_activity_id,
    unix_now,
};
use crate::metrics::{CoreCall, Metrics};
use crate::prompt::{self, Capture};
use crate::sequence::Sequencer;
use crate::store::{
    MemoryStore, SharedStore, approval_key, open_tools_key, pending_key, prompt_key, request_key,
    tool_key,
};
use crate::telemetry;

/// How long an approval can be matched by its retry when Core sends no
/// expiry with the verdict, unless configured.
pub const DEFAULT_APPROVAL_TTL: Duration = Duration::from_secs(15 * 60);
/// Kept past Core's approval expiry, for clock skew between the door guard and
/// Core. Outliving the window is harmless: the retry's poll finds the approval
/// gone and scores the request afresh.
const APPROVAL_SKEW: Duration = Duration::from_secs(60);
/// How long a request waits for its response to complete its activity.
const REQUEST_TTL: Duration = Duration::from_secs(60 * 60);
/// Most a background Core call may hold a sandbox's queue.
const SEQUENCED_CALL_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a tool the model asked for is tracked, open or closed.
const TOOL_TTL: Duration = Duration::from_secs(24 * 60 * 60);
/// How long a signalled prompt turn is remembered. Conversations resent
/// after that are signalled again, which Core replays by idempotency key.
const PROMPT_TTL: Duration = Duration::from_secs(24 * 60 * 60);
/// Largest prompt text sent to Core.
const MAX_PROMPT_BYTES: usize = 64 * 1024;

pub const REASON_APPROVAL_REQUIRED: &str = "openbox_approval_required";
pub const REASON_BLOCKED: &str = "openbox_blocked";
pub const REASON_HALTED: &str = "openbox_halted";
pub const REASON_UNAVAILABLE: &str = "openbox_unavailable";

const MAX_REASON_BYTES: usize = 4 * 1024;
/// How much of a deny reason the `openbox: eval` log line keeps.
const MAX_LOGGED_REASON_BYTES: usize = 512;

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
    /// Most of a request or response body sent to Core.
    fn body_limit(&self) -> usize;
    async fn open_activity(
        &self,
        sandbox_id: &str,
        activity: &Activity,
    ) -> Result<CoreDecision, CoreError>;
    async fn evaluate_action(
        &self,
        action: &Action,
        activity: &Activity,
        open: bool,
        span: &Value,
    ) -> Result<CoreDecision, CoreError>;
    async fn approval_state(
        &self,
        action: &Action,
        activity_id: &str,
    ) -> Result<ApprovalState, CoreError>;
    async fn complete_request(&self, completion: &Completion) -> Result<CoreDecision, CoreError>;
    async fn close_activity(
        &self,
        sandbox_id: &str,
        activity: &Activity,
        outcome: &Outcome,
    ) -> Result<CoreDecision, CoreError>;
    async fn signal(
        &self,
        sandbox_id: &str,
        signal_name: &str,
        args: &Value,
        turn: &str,
    ) -> Result<CoreDecision, CoreError>;
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
    fn body_limit(&self) -> usize {
        Self::body_limit(self)
    }
    async fn open_activity(
        &self,
        sandbox_id: &str,
        activity: &Activity,
    ) -> Result<CoreDecision, CoreError> {
        Self::open_activity(self, sandbox_id, activity).await
    }
    async fn evaluate_action(
        &self,
        action: &Action,
        activity: &Activity,
        open: bool,
        span: &Value,
    ) -> Result<CoreDecision, CoreError> {
        Self::evaluate_action(self, action, activity, open, span).await
    }
    async fn approval_state(
        &self,
        action: &Action,
        activity_id: &str,
    ) -> Result<ApprovalState, CoreError> {
        Self::approval_state(self, action, activity_id).await
    }
    async fn complete_request(&self, completion: &Completion) -> Result<CoreDecision, CoreError> {
        Self::complete_request(self, completion).await
    }
    async fn close_activity(
        &self,
        sandbox_id: &str,
        activity: &Activity,
        outcome: &Outcome,
    ) -> Result<CoreDecision, CoreError> {
        Self::close_activity(self, sandbox_id, activity, outcome).await
    }
    async fn signal(
        &self,
        sandbox_id: &str,
        signal_name: &str,
        args: &Value,
        turn: &str,
    ) -> Result<CoreDecision, CoreError> {
        Self::signal(self, sandbox_id, signal_name, args, turn).await
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
    /// Response headers in wire order, as `OpenShell` shows them.
    pub headers: Vec<(String, String)>,
    /// The body as read, up to the capture limit; `None` when it could not
    /// be read (bodyless, compressed, or capture off).
    pub body: Option<Vec<u8>>,
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
    /// What Core receives of a user prompt, unless a sandbox policy says
    /// otherwise.
    capture: Capture,
    /// What Core receives of request and response bodies, tool arguments and
    /// results, and model replies, unless a sandbox policy says otherwise.
    body_capture: Capture,
    sessions: Mutex<HashSet<String>>,
    /// Local cache only: Core latches a halted session, so a replica that
    /// missed the halt still gets `halt` for the sandbox's next request.
    halted: Arc<Mutex<HashSet<String>>>,
    metrics: Arc<Metrics>,
    core_budget: Duration,
    /// Keeps each sandbox's events in the order they happened.
    sequence: Arc<Sequencer>,
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
            capture: Capture::default(),
            body_capture: Capture::default(),
            sessions: Mutex::new(HashSet::new()),
            halted: Arc::new(Mutex::new(HashSet::new())),
            sequence: Sequencer::new(SEQUENCED_CALL_TIMEOUT),
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

    /// What Core receives for a user prompt (default: findings).
    #[must_use]
    pub const fn with_prompt_capture(mut self, capture: Capture) -> Self {
        self.capture = capture;
        self
    }

    /// What Core receives of bodies, tool arguments and results, and model
    /// replies (default: findings).
    #[must_use]
    pub const fn with_body_capture(mut self, capture: Capture) -> Self {
        self.body_capture = capture;
        self
    }

    /// The capture for a request's content: the sandbox policy's, for its
    /// host, over the deployment's.
    fn body_mode(&self, action: &Action) -> Capture {
        action.capture.mode_for(&action.host, self.body_capture)
    }

    /// The capture for a model call's prompt, chosen the same way.
    fn prompt_mode(&self, action: &Action) -> Capture {
        action.capture.mode_for(&action.host, self.capture)
    }

    /// Sends what is still queued for Core, up to `limit`, before the
    /// process exits. Returns whether it all went out.
    pub async fn drain(&self, limit: Duration) -> bool {
        self.sequence.drain(limit).await
    }

    pub fn metrics(&self) -> Arc<Metrics> {
        Arc::clone(&self.metrics)
    }

    /// Evaluates one request and records its result. The `openbox.verdict`
    /// span carries identifiers and the outcome only, never request content;
    /// see [`eval_line`] for what the log line carries.
    pub async fn evaluate(&self, action: &Action, mode: ApprovalMode) -> HttpRequestResult {
        let started = std::time::Instant::now();
        let span = telemetry::start(
            &Context::current(),
            "openbox.verdict",
            SpanKind::Server,
            vec![
                telemetry::sandbox(&action.sandbox_id),
                telemetry::request(&action.request_id),
            ],
        );
        let result = self.decide(action, mode).with_context(span.clone()).await;
        let elapsed = started.elapsed();
        let allowed = result.decision == Decision::Allow as i32;
        span.span().set_attribute(KeyValue::new(
            telemetry::DECISION,
            if allowed { "allow" } else { "deny" },
        ));
        if !result.reason_code.is_empty() {
            span.span().set_attribute(KeyValue::new(
                telemetry::REASON_CODE,
                result.reason_code.clone(),
            ));
        }
        if result.reason_code == REASON_UNAVAILABLE {
            span.span().set_status(Status::error(REASON_UNAVAILABLE));
        }
        span.span().end();
        self.metrics
            .record_result(allowed, &result.reason_code, elapsed);
        eprintln!("{}", eval_line(action, &result, elapsed));
        result
    }

    async fn timed<T>(
        &self,
        call: CoreCall,
        future: impl Future<Output = Result<T, CoreError>>,
    ) -> Result<T, CoreError> {
        let started = std::time::Instant::now();
        let name = match call {
            CoreCall::Session => "openbox.core.session_start",
            CoreCall::Signal => "openbox.core.prompt_signal",
            CoreCall::Evaluate => "openbox.core.evaluate",
            CoreCall::Approval => "openbox.core.approval_check",
        };
        let outcome = telemetry::call(name, Vec::new(), future).await;
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
        // Everything the sandbox did before this request reaches Core first,
        // and nothing after it until its verdict is in.
        let _turn = self.sequence.turn(&action.sandbox_id).await;
        if let Some(result) = self.ensure_session(action).await {
            return result;
        }
        if let Some(result) = self.signal_prompt(action).await {
            return result;
        }
        let model = agent::model_call(action);
        if let Some(model) = &model {
            self.close_tools(action, model).await;
        }
        let Route {
            mut activity,
            mut open,
            closes,
        } = self.route(action, model.as_ref()).await;
        let approval = approval_key(&action.sandbox_id, &action.fingerprint);
        if mode == ApprovalMode::Queue {
            match self.approved_activity(action, mode, &approval).await {
                Ok(Some(held)) => {
                    activity.id = held;
                    open = false;
                }
                Ok(None) => {}
                Err(result) => return result,
            }
        }
        // The span and the activity's duration start here, before Core is
        // asked, so both include the time spent waiting for the verdict.
        let started = SystemTime::now();
        let span = started_span(
            action,
            &activity.id,
            self.governance.body_limit(),
            self.body_mode(action),
            started,
        );
        let decision = match self
            .timed(
                CoreCall::Evaluate,
                self.governance
                    .evaluate_action(action, &activity, open, &span),
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
                .set(
                    &approval,
                    &activity.id,
                    Some(approval_hold(
                        decision.approval_expires_at,
                        unix_now(),
                        self.approval_ttl,
                    )),
                )
                .await
        {
            eprintln!(
                "openbox: approval for request_id={} not recorded, its retry will be scored again: {error}",
                action.request_id
            );
        }
        let result = self.apply(action, mode, &decision);
        let held = mode == ApprovalMode::Queue && decision.verdict == Verdict::RequireApproval;
        if result.decision != Decision::Allow as i32 && closes && !held {
            self.close_refused(action, activity.clone(), &decision)
                .await;
        }
        if result.decision == Decision::Allow as i32 {
            // Pending until its completion is sent, so the front desk ends the
            // session after it.
            mark_pending(self.store.as_ref(), &action.sandbox_id, &action.request_id).await;
            let record = json!({
                "activity": activity_json(&activity),
                "closes": closes,
                "api": model.as_ref().map(|model| model.api.name()),
                "span": span,
                "started_ms": millis(started),
                "capture": self.body_mode(action).name(),
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

    /// Closes the activity of a request Core refused, as the agent SDK closes
    /// an activity governance stopped: failed, with the verdict's reason. An
    /// approval hold stays open for the retry that reuses it.
    async fn close_refused(&self, action: &Action, activity: Activity, decision: &CoreDecision) {
        let outcome = Outcome {
            output: None,
            error: Some(json!({
                "type": "GovernanceStop",
                "message": decision
                    .reason
                    .clone()
                    .unwrap_or_else(|| format!("Governance {:?}", decision.verdict)),
            })),
            duration_ms: None,
        };
        let governance = Arc::clone(&self.governance);
        let store = Arc::clone(&self.store);
        let sandbox_id = action.sandbox_id.clone();
        let request_id = action.request_id.clone();
        mark_pending(store.as_ref(), &sandbox_id, &request_id).await;
        let queue = sandbox_id.clone();
        let job = telemetry::job(
            "openbox.close_refused",
            vec![telemetry::sandbox(&sandbox_id)],
            async move {
                if let Err(error) = telemetry::call(
                    "openbox.core.close_activity",
                    Vec::new(),
                    governance.close_activity(&sandbox_id, &activity, &outcome),
                )
                .await
                {
                    eprintln!(
                        "openbox: refused activity {} not closed: {error}",
                        activity.id
                    );
                }
                clear_pending(store.as_ref(), &sandbox_id, &request_id).await;
            },
        );
        self.sequence.push(&queue, job);
    }

    /// The activity Core holds an approval on for this exact action, once a
    /// human approved it. `Err` is the result for a retry that may not go
    /// through: still pending, rejected, or Core unreachable.
    async fn approved_activity(
        &self,
        action: &Action,
        mode: ApprovalMode,
        approval: &str,
    ) -> Result<Option<String>, HttpRequestResult> {
        let held = match self.store.get(approval).await {
            Ok(Some(held)) => held,
            Ok(None) => return Ok(None),
            Err(error) => {
                eprintln!(
                    "openbox: approval lookup unavailable, scoring request_id={} as a new activity: {error}",
                    action.request_id
                );
                return Ok(None);
            }
        };
        match self
            .timed(
                CoreCall::Approval,
                self.governance.approval_state(action, &held),
            )
            .await
        {
            Ok(ApprovalState::Pending { .. }) => Err(deny(
                REASON_APPROVAL_REQUIRED,
                "awaiting human approval",
                None,
            )),
            Ok(ApprovalState::Approved) => Ok(Some(held)),
            Ok(ApprovalState::Gone) => {
                let _ = self.store.delete(approval).await;
                Ok(None)
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
                Err(self.apply(action, mode, &decision))
            }
            Err(error) => Err(deny(REASON_UNAVAILABLE, &error.to_string(), None)),
        }
    }

    /// Signals a model call's new user prompt. `Some` denies the call because
    /// Core did not allow the prompt.
    async fn signal_prompt(&self, action: &Action) -> Option<HttpRequestResult> {
        let capture = self.prompt_mode(action);
        if capture == Capture::Off {
            return None;
        }
        let prompt = prompt::extract(action)?;
        let seen = prompt_key(&action.sandbox_id, &prompt.turn);
        match self.store.get(&seen).await {
            Ok(Some(_)) => return None,
            Ok(None) => {}
            // Core's idempotency key still keeps a resent turn to one signal.
            Err(error) => eprintln!("openbox: prompt lookup unavailable: {error}"),
        }
        let args = prompt::signal_args(&prompt, capture, MAX_PROMPT_BYTES);
        match self
            .timed(
                CoreCall::Signal,
                self.governance
                    .signal(&action.sandbox_id, "user_prompt", &args, &prompt.turn),
            )
            .await
        {
            Ok(decision) if matches!(decision.verdict, Verdict::Allow | Verdict::Constrain) => {
                let _ = self.store.set(&seen, "1", Some(PROMPT_TTL)).await;
                eprintln!(
                    "openbox: prompt signalled sandbox_id={} request_id={} provider={}",
                    action.sandbox_id, action.request_id, prompt.provider
                );
                None
            }
            // A prompt Core will not allow cannot be held for approval: the
            // model call is blocked (or halted), and the retry asks again.
            Ok(decision) => Some(self.apply(action, ApprovalMode::Deny, &decision)),
            Err(error) => {
                eprintln!(
                    "openbox: prompt for request_id={} not recorded: {error}",
                    action.request_id
                );
                None
            }
        }
    }

    /// Records a response: its span, completed, and the end of its activity
    /// unless it ran inside a tool. A model call's reply is read for the
    /// `llm_call` output and for the tools it asks for, which open here.
    ///
    /// The store is updated before this returns, so the sandbox's next
    /// request (the tool at work) is routed into the tool's activity even on
    /// another replica. Core calls run in the background: the response is
    /// not held for Core.
    pub async fn complete(&self, response: ResponseSeen) {
        let record = self
            .store
            .take(&request_key(&response.request_id))
            .await
            .unwrap_or_default()
            .and_then(|text| serde_json::from_str::<Value>(&text).ok())
            .unwrap_or(Value::Null);
        let activity = record
            .get("activity")
            .and_then(activity_from)
            .unwrap_or_else(|| fallback_activity(&response));
        let closes = record
            .get("closes")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        let duration_ms = record
            .get("started_ms")
            .and_then(Value::as_u64)
            .map(|started| unix_millis().saturating_sub(started));
        let limit = self.governance.body_limit();
        // The response is captured as its request was: the sandbox policy's
        // choice went with the request record.
        let capture = record
            .get("capture")
            .and_then(Value::as_str)
            .and_then(Capture::parse)
            .unwrap_or(self.body_capture);
        let reply = record
            .get("api")
            .and_then(Value::as_str)
            .and_then(agent::Api::parse)
            .zip(response.body.as_deref())
            .and_then(|(api, body)| agent::parse_reply(api, body));
        let outcome = outcome(&response, reply.as_ref(), duration_ms, limit, capture);
        let completion = Completion {
            sandbox_id: response.sandbox_id.clone(),
            request_id: response.request_id.clone(),
            span: record
                .get("span")
                .cloned()
                .unwrap_or_else(|| fallback_span(&response, &activity.id)),
            activity,
            status_code: response.status_code,
            response_headers: agent::headers_object(
                response
                    .headers
                    .iter()
                    .map(|(name, value)| (name.as_str(), value.as_str())),
            ),
            response_body: response
                .body
                .as_deref()
                .map_or(Value::Null, |body| capture::span_body(body, capture, limit)),
        };
        let mut tools = Vec::new();
        for call in reply.iter().flat_map(|reply| &reply.tool_calls) {
            let tool = tool_activity(call, limit, capture, completion.activity.profile.clone());
            self.track_tool(&response.sandbox_id, &call.id, &tool).await;
            tools.push((call.id.clone(), tool));
        }
        let attributes = vec![
            telemetry::sandbox(&completion.sandbox_id),
            telemetry::request(&completion.request_id),
        ];
        let queue = completion.sandbox_id.clone();
        let job = Self::send_completion(
            Arc::clone(&self.governance),
            Arc::clone(&self.store),
            completion,
            closes.then_some(outcome),
            tools,
        );
        self.sequence.push(
            &queue,
            telemetry::job("openbox.completion", attributes, job),
        );
    }

    /// Tells Core a request completed: its span, the end of its activity
    /// when the response closes it, and the tools its reply opened.
    async fn send_completion(
        governance: Arc<G>,
        store: Arc<dyn SharedStore>,
        completion: Completion,
        close: Option<Outcome>,
        tools: Vec<(String, Activity)>,
    ) {
        let sandbox_id = &completion.sandbox_id;
        if let Err(error) = telemetry::call(
            "openbox.core.complete_request",
            Vec::new(),
            governance.complete_request(&completion),
        )
        .await
        {
            eprintln!(
                "openbox: completed span for request_id={} not recorded: {error}",
                completion.request_id
            );
        }
        if let Some(outcome) = close {
            match telemetry::call(
                "openbox.core.close_activity",
                Vec::new(),
                governance.close_activity(sandbox_id, &completion.activity, &outcome),
            )
            .await
            {
                Ok(_) => eprintln!(
                    "openbox: completed request_id={} activity_id={} status={}",
                    completion.request_id, completion.activity.id, completion.status_code
                ),
                Err(error) => eprintln!(
                    "openbox: activity {} for request_id={} not closed: {error}",
                    completion.activity.id, completion.request_id
                ),
            }
        }
        for (call_id, tool) in tools {
            match telemetry::call(
                "openbox.core.open_activity",
                Vec::new(),
                governance.open_activity(sandbox_id, &tool),
            )
            .await
            {
                Ok(_) => {
                    mark_tool(store.as_ref(), sandbox_id, &call_id, "opened").await;
                    eprintln!(
                        "openbox: tool opened sandbox_id={sandbox_id} activity_id={} tool={}",
                        tool.id, tool.kind
                    );
                }
                Err(error) => {
                    eprintln!("openbox: tool activity {} not opened: {error}", tool.id);
                }
            }
        }
        clear_pending(store.as_ref(), sandbox_id, &completion.request_id).await;
    }

    /// Where a request belongs: a model call is its own `llm_call` activity,
    /// an MCP tool call its own tool activity, any other request runs inside
    /// the tool the model last asked for while one is open, and otherwise is
    /// its own activity.
    async fn route(&self, action: &Action, model: Option<&agent::ModelCall>) -> Route {
        let own = |kind: String, input: Value| Route {
            activity: Activity {
                id: request_activity_id(&action.request_id),
                kind,
                input,
                profile: action.profile.clone(),
            },
            open: true,
            closes: true,
        };
        if model.is_some() {
            return own(LLM_CALL.to_owned(), json!([self.prompt_input(action)]));
        }
        if let Payload::JsonRpc(calls) = &action.payload
            && let Some(call) = calls.iter().find(|call| call.tool.is_some())
        {
            let arguments = call.arguments.clone().unwrap_or_else(|| json!({}));
            return own(
                activity_name(action),
                json!([capture::value(
                    &arguments,
                    self.body_mode(action),
                    self.governance.body_limit()
                )]),
            );
        }
        if let Some((tool, opened)) = self.open_tool(&action.sandbox_id).await {
            return Route {
                activity: tool,
                open: !opened,
                closes: false,
            };
        }
        own(
            activity_name(action),
            json!([{"method": action.method, "url": request_url(action), "body_bytes": action.body_bytes}]),
        )
    }

    /// The `llm_call` input: the user's newest prompt, as captured.
    fn prompt_input(&self, action: &Action) -> Value {
        let text = prompt::latest_text(action).unwrap_or_default();
        match self.prompt_mode(action) {
            Capture::Text => json!({"prompt": truncate(&text, MAX_PROMPT_BYTES)}),
            Capture::Hash => json!({
                "prompt_sha256": hex(&sha2::Sha256::digest(text.as_bytes())),
                "chars": text.chars().count(),
            }),
            Capture::Findings => json!({
                "prompt_sha256": hex(&sha2::Sha256::digest(text.as_bytes())),
                "chars": text.chars().count(),
                "findings": capture::findings(&text),
            }),
            Capture::Off => json!({}),
        }
    }

    /// The tool the model asked for most recently that is still open, and
    /// whether Core has its start.
    async fn open_tool(&self, sandbox_id: &str) -> Option<(Activity, bool)> {
        let open = self.open_tool_ids(sandbox_id).await;
        for call_id in open.iter().rev() {
            let Ok(Some(text)) = self.store.get(&tool_key(sandbox_id, call_id)).await else {
                continue;
            };
            let Ok(entry) = serde_json::from_str::<Value>(&text) else {
                continue;
            };
            let state = entry.get("state").and_then(Value::as_str);
            if let (Some("open" | "opened"), Some(activity)) =
                (state, entry.get("activity").and_then(activity_from))
            {
                return Some((activity, state == Some("opened")));
            }
        }
        None
    }

    async fn open_tool_ids(&self, sandbox_id: &str) -> Vec<String> {
        self.store
            .get(&open_tools_key(sandbox_id))
            .await
            .ok()
            .flatten()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default()
    }

    /// Records a tool the model asked for as open, before Core hears of it.
    async fn track_tool(&self, sandbox_id: &str, call_id: &str, tool: &Activity) {
        let entry = json!({
            "activity": activity_json(tool),
            "state": "open",
            "started_ms": unix_millis(),
        });
        let mut open = self.open_tool_ids(sandbox_id).await;
        open.retain(|id| id != call_id);
        open.push(call_id.to_owned());
        let written = async {
            self.store
                .set(
                    &tool_key(sandbox_id, call_id),
                    &entry.to_string(),
                    Some(TOOL_TTL),
                )
                .await?;
            self.store
                .set(
                    &open_tools_key(sandbox_id),
                    &json!(open).to_string(),
                    Some(TOOL_TTL),
                )
                .await
        };
        if let Err(error) = written.await {
            eprintln!(
                "openbox: tool {call_id} for sandbox_id={sandbox_id} not recorded, its requests are their own activities: {error}"
            );
        }
    }

    /// Closes the tools whose results a model call sends back, before the
    /// model call's own activity opens. A result for a tool never seen open
    /// (its reply could not be read) still records the tool, from the call
    /// the conversation carries. Runs inside the model call's turn.
    async fn close_tools(&self, action: &Action, model: &agent::ModelCall) {
        let sandbox_id = action.sandbox_id.as_str();
        let limit = self.governance.body_limit();
        let capture = self.body_mode(action);
        let mut closing = Vec::new();
        for result in &model.tool_results {
            let key = tool_key(sandbox_id, &result.id);
            let entry = self
                .store
                .get(&key)
                .await
                .ok()
                .flatten()
                .and_then(|text| serde_json::from_str::<Value>(&text).ok());
            let (tool, started_ms, opened) = match &entry {
                Some(entry) if entry.get("state").and_then(Value::as_str) == Some("closed") => {
                    continue;
                }
                Some(entry) => {
                    let Some(tool) = entry.get("activity").and_then(activity_from) else {
                        continue;
                    };
                    let opened = entry.get("state").and_then(Value::as_str) == Some("opened");
                    (
                        tool,
                        entry.get("started_ms").and_then(Value::as_u64),
                        opened,
                    )
                }
                None => {
                    let Some(call) = model.tool_call(&result.id) else {
                        continue;
                    };
                    (
                        tool_activity(call, limit, capture, action.profile.clone()),
                        None,
                        false,
                    )
                }
            };
            let closed = json!({"activity": activity_json(&tool), "state": "closed"});
            if let Err(error) = self
                .store
                .set(&key, &closed.to_string(), Some(TOOL_TTL))
                .await
            {
                eprintln!("openbox: tool {} not marked closed: {error}", result.id);
            }
            let outcome = tool_outcome(result, started_ms, limit, capture);
            closing.push((result.id.clone(), tool, opened, outcome));
        }
        if closing.is_empty() {
            return;
        }
        let mut open = self.open_tool_ids(sandbox_id).await;
        open.retain(|id| !closing.iter().any(|(closed, ..)| closed == id));
        let _ = self
            .store
            .set(
                &open_tools_key(sandbox_id),
                &json!(open).to_string(),
                Some(TOOL_TTL),
            )
            .await;
        for (call_id, tool, opened, outcome) in closing {
            if !opened
                && let Err(error) = telemetry::call(
                    "openbox.core.open_activity",
                    Vec::new(),
                    self.governance.open_activity(sandbox_id, &tool),
                )
                .await
            {
                eprintln!("openbox: tool activity {} not opened: {error}", tool.id);
            }
            match telemetry::call(
                "openbox.core.close_activity",
                Vec::new(),
                self.governance.close_activity(sandbox_id, &tool, &outcome),
            )
            .await
            {
                Ok(_) => eprintln!(
                    "openbox: tool closed sandbox_id={sandbox_id} activity_id={} tool={} call_id={call_id}",
                    tool.id, tool.kind
                ),
                Err(error) => {
                    eprintln!("openbox: tool activity {} not closed: {error}", tool.id);
                }
            }
        }
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

/// Where a request's verdict is recorded.
struct Route {
    activity: Activity,
    /// The activity needs its plain `ActivityStarted` first.
    open: bool,
    /// The response ends the activity.
    closes: bool,
}

fn activity_json(activity: &Activity) -> Value {
    json!({"id": activity.id, "kind": activity.kind, "input": activity.input, "profile": activity.profile})
}

pub(crate) fn activity_from(value: &Value) -> Option<Activity> {
    Some(Activity {
        id: value.get("id")?.as_str()?.to_owned(),
        kind: value.get("kind")?.as_str()?.to_owned(),
        input: value.get("input").cloned().unwrap_or_else(|| json!([])),
        profile: value
            .get("profile")
            .and_then(Value::as_str)
            .map(str::to_owned),
    })
}

/// A tool the model asked for, as the agent SDK reports a tool: named by the
/// tool, its arguments as input, in the profile of the model call.
fn tool_activity(
    call: &agent::ToolCall,
    limit: usize,
    capture: Capture,
    profile: Option<String>,
) -> Activity {
    Activity {
        id: tool_activity_id(&call.id),
        kind: call.name.clone(),
        input: json!([capture::value(&call.input, capture, limit)]),
        profile,
    }
}

/// Records a request whose completion is still to be sent. Best effort: when
/// it is lost, the front desk does not wait for that request.
async fn mark_pending(store: &dyn SharedStore, sandbox_id: &str, request_id: &str) {
    if let Err(error) = store
        .add_member(&pending_key(sandbox_id), request_id, REQUEST_TTL)
        .await
    {
        eprintln!(
            "openbox: request_id={request_id} not marked pending, the session may end before it: {error}"
        );
    }
}

/// The request's completion has been sent, or given up on.
async fn clear_pending(store: &dyn SharedStore, sandbox_id: &str, request_id: &str) {
    if let Err(error) = store
        .remove_member(&pending_key(sandbox_id), request_id)
        .await
    {
        eprintln!("openbox: request_id={request_id} still marked pending: {error}");
    }
}

/// Moves a tracked tool from `open` to `opened` once Core has its start,
/// unless it closed meanwhile.
async fn mark_tool(store: &dyn SharedStore, sandbox_id: &str, call_id: &str, state: &str) {
    let key = tool_key(sandbox_id, call_id);
    let Ok(Some(text)) = store.get(&key).await else {
        return;
    };
    let Ok(mut entry) = serde_json::from_str::<Value>(&text) else {
        return;
    };
    if entry.get("state").and_then(Value::as_str) != Some("open") {
        return;
    }
    entry["state"] = json!(state);
    let _ = store.set(&key, &entry.to_string(), Some(TOOL_TTL)).await;
}

/// The output of a request that is its own activity: the JSON-RPC result of
/// an MCP call, otherwise the response's status.
fn response_output(response: &ResponseSeen, limit: usize, capture: Capture) -> Value {
    response
        .body
        .as_deref()
        .and_then(|body| serde_json::from_slice::<Value>(body).ok())
        .and_then(|body| body.get("result").cloned())
        .map_or_else(
            || json!({"status_code": response.status_code, "method": response.method, "url": response.url}),
            |result| capture::value(&result, capture, limit),
        )
}

/// How a tool ended, from the result the agent sent back to its model.
fn tool_outcome(
    result: &agent::ToolResult,
    started_ms: Option<u64>,
    limit: usize,
    capture: Capture,
) -> Outcome {
    Outcome {
        output: Some(capture::value(&result.output, capture, limit)),
        error: result.is_error.then(|| {
            // The error text is the tool's output: content.
            let message = if capture == Capture::Text {
                truncate(&text_of(&result.output), MAX_REASON_BYTES)
            } else {
                "tool reported an error".to_owned()
            };
            json!({"type": "ToolError", "message": message})
        }),
        duration_ms: started_ms.map(|started| unix_millis().saturating_sub(started)),
    }
}

/// A model call's `llm_call` output: its metadata as is, its completion
/// text as captured.
fn reply_output(reply: &agent::Reply, limit: usize, capture: Capture) -> Value {
    let mut output = reply.output();
    if let Some(completion) = &reply.completion
        && capture != Capture::Text
    {
        output["completion"] = capture::text(completion, capture, limit);
    }
    output
}

/// How a response's own activity ended: a model call's reply, an MCP
/// call's result, or otherwise the response's status.
fn outcome(
    response: &ResponseSeen,
    reply: Option<&agent::Reply>,
    duration_ms: Option<u64>,
    limit: usize,
    capture: Capture,
) -> Outcome {
    Outcome {
        output: Some(reply.map_or_else(
            || response_output(response, limit, capture),
            |reply| reply_output(reply, limit, capture),
        )),
        error: (response.status_code >= 400).then(
            || json!({"type": "HTTPError", "message": format!("HTTP {}", response.status_code)}),
        ),
        duration_ms,
    }
}

/// The activity of a response whose request record was lost: its own,
/// named by method and host. The sandbox's profile went with the record.
fn fallback_activity(response: &ResponseSeen) -> Activity {
    Activity {
        id: request_activity_id(&response.request_id),
        kind: format!("{} {}", response.method, response.host),
        input: json!([{"method": response.method, "url": response.url}]),
        profile: None,
    }
}

/// A started span for a response whose request record was lost, so its
/// completed span is still recorded.
fn fallback_span(response: &ResponseSeen, activity_id: &str) -> Value {
    json!({
        "span_id": span_ids(&response.request_id).0,
        "trace_id": span_ids(&response.request_id).1,
        "name": format!("HTTP {}", response.method),
        "kind": "CLIENT",
        "stage": "started",
        "attributes": {
            "http.method": response.method,
            "http.url": response.url,
            "http.request.method": response.method,
            "url.full": response.url,
        },
        "status": {"code": "UNSET", "description": null},
        "events": [],
        "hook_type": "http_request",
        "semantic_type": null,
        "attribute_key_identifiers": ["http_method", "http_url"],
        "activity_id": activity_id,
        "http_method": response.method,
        "http_url": response.url,
        "request_headers": null,
        "request_body": null,
    })
}

fn text_of(value: &Value) -> String {
    value
        .as_str()
        .map_or_else(|| value.to_string(), str::to_owned)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

fn unix_millis() -> u64 {
    millis(SystemTime::now())
}

fn millis(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH).map_or(0, |elapsed| {
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

/// The `openbox: eval` log line: identifiers and the outcome, never request
/// content. A deny ends with the reason text the sandbox was given, so an
/// operator can tell its causes apart (the gateway logs only the code). The
/// text is quoted with escapes, so a newline or quote in a reason from Core
/// cannot split or forge a log line, and capped at [`MAX_LOGGED_REASON_BYTES`].
fn eval_line(action: &Action, result: &HttpRequestResult, elapsed: Duration) -> String {
    let allowed = result.decision == Decision::Allow as i32;
    let line = format!(
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
    if allowed || result.reason.is_empty() {
        return line;
    }
    let reason = truncate(&result.reason, MAX_LOGGED_REASON_BYTES);
    format!("{line} reason={reason:?}")
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

/// How long the door guard remembers a pending approval: until Core's own
/// expiry for it (the agent's `approval_wait_time`), or `fallback` when Core
/// sends none.
fn approval_hold(expires_at: Option<i64>, now: i64, fallback: Duration) -> Duration {
    expires_at.map_or(fallback, |at| {
        Duration::from_secs(u64::try_from(at.saturating_sub(now)).unwrap_or(0)) + APPROVAL_SKEW
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::action::tests::evaluation;
    use serde_json::json;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    pub struct FakeCore {
        pub session: Mutex<VecDeque<Result<Verdict, ()>>>,
        pub verdicts: Mutex<VecDeque<Result<Verdict, ()>>>,
        pub approvals: Mutex<VecDeque<Result<ApprovalState, ()>>>,
        /// Sent with every verdict, as Core's `approval_expiration_time`.
        pub approval_expires_at: Option<i64>,
        pub session_calls: AtomicUsize,
        pub evaluate_calls: AtomicUsize,
        pub approval_calls: AtomicUsize,
        /// How long every call takes.
        pub delay: Duration,
        /// Activity ids, in call order, of evaluations and approval polls.
        pub evaluated: Mutex<Vec<String>>,
        pub polled: Mutex<Vec<String>>,
        pub completions: Mutex<Vec<Completion>>,
        /// Activity ids opened with a plain `ActivityStarted`, in order.
        pub opened: Mutex<Vec<String>>,
        pub closed: Mutex<Vec<(Activity, Outcome)>>,
        /// The activity of every evaluation, in order.
        pub activities: Mutex<Vec<(Activity, bool)>>,
        /// Every activity call as Core would store it, in arrival order.
        pub calls: Mutex<Vec<String>>,
        /// Verdicts for prompt signals, in order; allow when empty.
        pub prompt_verdicts: Mutex<VecDeque<Verdict>>,
        pub signals: Mutex<Vec<Value>>,
        /// Everything each call carried that could hold content, as Core
        /// would receive it: activities, spans, outcomes, signal arguments.
        pub sent: Mutex<Vec<String>>,
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
        fn body_limit(&self) -> usize {
            64 * 1024
        }
        async fn open_activity(
            &self,
            _: &str,
            activity: &Activity,
        ) -> Result<CoreDecision, CoreError> {
            tokio::time::sleep(self.delay).await;
            self.sent.lock().unwrap().push(format!("{activity:?}"));
            self.opened.lock().unwrap().push(activity.id.clone());
            self.calls
                .lock()
                .unwrap()
                .push(format!("started {}", activity.kind));
            Ok(decision(Verdict::Allow))
        }
        async fn evaluate_action(
            &self,
            _: &Action,
            activity: &Activity,
            open: bool,
            span: &Value,
        ) -> Result<CoreDecision, CoreError> {
            tokio::time::sleep(self.delay).await;
            self.sent
                .lock()
                .unwrap()
                .push(format!("{activity:?} {span}"));
            self.evaluate_calls.fetch_add(1, Ordering::SeqCst);
            self.evaluated.lock().unwrap().push(activity.id.clone());
            self.activities
                .lock()
                .unwrap()
                .push((activity.clone(), open));
            if open {
                self.opened.lock().unwrap().push(activity.id.clone());
                self.calls
                    .lock()
                    .unwrap()
                    .push(format!("started {}", activity.kind));
            }
            self.calls
                .lock()
                .unwrap()
                .push(format!("span started in {}", activity.kind));
            let next = self
                .verdicts
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected evaluation");
            match next {
                Ok(verdict) => Ok(CoreDecision {
                    approval_expires_at: self.approval_expires_at,
                    ..decision(verdict)
                }),
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
        async fn complete_request(
            &self,
            completion: &Completion,
        ) -> Result<CoreDecision, CoreError> {
            tokio::time::sleep(self.delay).await;
            self.sent.lock().unwrap().push(format!("{completion:?}"));
            self.completions.lock().unwrap().push(completion.clone());
            self.calls
                .lock()
                .unwrap()
                .push(format!("span completed in {}", completion.activity.kind));
            Ok(decision(Verdict::Allow))
        }
        async fn close_activity(
            &self,
            _: &str,
            activity: &Activity,
            outcome: &Outcome,
        ) -> Result<CoreDecision, CoreError> {
            tokio::time::sleep(self.delay).await;
            self.sent
                .lock()
                .unwrap()
                .push(format!("{activity:?} {outcome:?}"));
            self.calls
                .lock()
                .unwrap()
                .push(format!("completed {}", activity.kind));
            self.closed
                .lock()
                .unwrap()
                .push((activity.clone(), outcome.clone()));
            Ok(decision(Verdict::Allow))
        }
        async fn signal(
            &self,
            _: &str,
            signal_name: &str,
            args: &Value,
            _: &str,
        ) -> Result<CoreDecision, CoreError> {
            assert_eq!(signal_name, "user_prompt");
            self.sent.lock().unwrap().push(args.to_string());
            self.signals.lock().unwrap().push(args.clone());
            let verdict = self
                .prompt_verdicts
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(Verdict::Allow);
            Ok(decision(verdict))
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
        async fn add_member(&self, _: &str, _: &str, _: Duration) -> Result<(), String> {
            Err("down".to_owned())
        }
        async fn remove_member(&self, _: &str, _: &str) -> Result<(), String> {
            Err("down".to_owned())
        }
        async fn count_members(&self, _: &str) -> Result<u64, String> {
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
    async fn a_verdict_is_a_span_with_its_queue_wait_and_core_calls_under_it() {
        use opentelemetry::Value as Attribute;
        use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider};
        let exporter = InMemorySpanExporter::default();
        opentelemetry::global::set_tracer_provider(
            SdkTracerProvider::builder()
                .with_simple_exporter(exporter.clone())
                .build(),
        );
        let (guard, ..) = guard(FakeCore::with_verdicts(&[Verdict::Block]));
        let result = guard
            .evaluate(&request("traced-request"), ApprovalMode::Queue)
            .await;
        assert_eq!(result.reason_code, REASON_BLOCKED);
        let spans = exporter.get_finished_spans().unwrap();
        let attribute = |span: &opentelemetry_sdk::trace::SpanData, key: &str| {
            span.attributes
                .iter()
                .find(|attribute| attribute.key.as_str() == key)
                .map(|attribute| attribute.value.clone())
        };
        let verdict = spans
            .iter()
            .find(|span| {
                span.name == "openbox.verdict"
                    && attribute(span, telemetry::REQUEST_ID)
                        == Some(Attribute::from("traced-request"))
            })
            .expect("a verdict span");
        assert_eq!(
            attribute(verdict, telemetry::DECISION),
            Some(Attribute::from("deny"))
        );
        assert_eq!(
            attribute(verdict, telemetry::REASON_CODE),
            Some(Attribute::from(REASON_BLOCKED))
        );
        assert!(attribute(verdict, telemetry::SANDBOX_ID).is_some());
        let children: Vec<&str> = spans
            .iter()
            .filter(|span| span.parent_span_id == verdict.span_context.span_id())
            .map(|span| span.name.as_ref())
            .collect();
        assert_eq!(
            children,
            [
                "openbox.queue_wait",
                "openbox.core.session_start",
                "openbox.core.evaluate"
            ]
        );
        // No attribute carries the request: only identifiers and the outcome.
        for span in &spans {
            for attribute in &span.attributes {
                assert!(!attribute.value.as_str().contains("amount"));
            }
        }
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

    /// Remembers the TTL of every entry written.
    #[derive(Default)]
    struct TtlStore {
        inner: MemoryStore,
        ttls: Mutex<Vec<(String, Option<Duration>)>>,
    }

    #[tonic::async_trait]
    impl SharedStore for TtlStore {
        async fn get(&self, key: &str) -> Result<Option<String>, String> {
            self.inner.get(key).await
        }
        async fn set(&self, key: &str, value: &str, ttl: Option<Duration>) -> Result<(), String> {
            self.ttls.lock().unwrap().push((key.to_owned(), ttl));
            self.inner.set(key, value, ttl).await
        }
        async fn take(&self, key: &str) -> Result<Option<String>, String> {
            self.inner.take(key).await
        }
        async fn delete(&self, key: &str) -> Result<(), String> {
            self.inner.delete(key).await
        }
        async fn add_member(&self, key: &str, member: &str, ttl: Duration) -> Result<(), String> {
            self.inner.add_member(key, member, ttl).await
        }
        async fn remove_member(&self, key: &str, member: &str) -> Result<(), String> {
            self.inner.remove_member(key, member).await
        }
        async fn count_members(&self, key: &str) -> Result<u64, String> {
            self.inner.count_members(key).await
        }
    }

    #[test]
    fn a_pending_approval_is_held_for_cores_window() {
        let fallback = DEFAULT_APPROVAL_TTL;
        assert_eq!(
            approval_hold(Some(1_000 + 30 * 60), 1_000, fallback),
            Duration::from_secs(30 * 60) + APPROVAL_SKEW,
            "Core's 30 min default outlives the old fixed 15 min"
        );
        assert_eq!(approval_hold(None, 1_000, fallback), fallback);
        assert_eq!(
            approval_hold(Some(900), 1_000, fallback),
            APPROVAL_SKEW,
            "an expiry already past is not a negative TTL"
        );
    }

    #[tokio::test]
    async fn an_approval_is_remembered_until_core_says_it_expires() {
        // Regression (PROD-890): an approval given between minute 15 and
        // Core's 30 min window was lost, because the door guard forgot the
        // pending activity after a fixed 15 min.
        let store = Arc::new(TtlStore::default());
        let shared: Arc<dyn SharedStore> = store.clone();
        let core = Arc::new(FakeCore {
            approval_expires_at: Some(unix_now() + 30 * 60),
            ..FakeCore::with_verdicts(&[Verdict::RequireApproval])
        });
        let guard = Guard::with_store(
            Arc::clone(&core),
            Arc::new(FakeStopper::default()),
            shared,
            DEFAULT_APPROVAL_TTL,
        );
        let held = guard.evaluate(&request("req-1"), ApprovalMode::Queue).await;
        assert_eq!(held.reason_code, REASON_APPROVAL_REQUIRED);
        let ttls = store.ttls.lock().unwrap();
        let (_, ttl) = ttls
            .iter()
            .find(|(key, _)| key.starts_with("openbox:approval:"))
            .expect("the pending approval is recorded");
        let ttl = ttl.expect("an approval entry expires");
        assert!(
            ttl > Duration::from_secs(29 * 60)
                && ttl <= Duration::from_secs(30 * 60) + APPROVAL_SKEW,
            "held for Core's window, not the fallback: {ttl:?}"
        );
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
            headers: vec![("content-type".to_owned(), "application/json".to_owned())],
            body: Some(br#"{"jsonrpc":"2.0","id":1,"result":{"paid":true}}"#.to_vec()),
        };
        guard.complete(seen("req-1", 200)).await;
        // A response for a request this replica never recorded still closes
        // the request's own activity, without a duration.
        guard.complete(seen("req-9", 503)).await;
        settle(&core, 2).await;
        let completions = core.completions.lock().unwrap();
        let first = completions
            .iter()
            .find(|c| c.request_id == "req-1")
            .unwrap();
        assert_eq!(first.activity.id, "oshx-req-1");
        assert_eq!(first.activity.kind, "pay");
        assert_eq!(first.span["stage"], "started");
        assert_eq!(first.span["activity_id"], "oshx-req-1");
        // By default Core gets the response's digest and findings, not its
        // bytes.
        let body: Value = serde_json::from_str(first.response_body.as_str().unwrap()).unwrap();
        assert!(body["sha256"].is_string());
        assert_eq!(
            body["shape"],
            json!({"jsonrpc": "string", "id": "number", "result": {"paid": "boolean"}})
        );
        let other = completions
            .iter()
            .find(|c| c.request_id == "req-9")
            .unwrap();
        assert_eq!(other.activity.id, "oshx-req-9");
        assert_eq!(other.activity.kind, "POST mcp.example.com");
        let closed = core.closed.lock().unwrap();
        let (_, paid) = closed.iter().find(|(a, _)| a.id == "oshx-req-1").unwrap();
        // An MCP call's own activity ends with its JSON-RPC result, captured.
        assert_eq!(
            paid.output.as_ref().unwrap()["shape"],
            json!({"paid": "boolean"})
        );
        assert!(paid.duration_ms.is_some());
        let (_, failed) = closed.iter().find(|(a, _)| a.id == "oshx-req-9").unwrap();
        assert_eq!(failed.error.as_ref().unwrap()["message"], "HTTP 503");
        assert_eq!(failed.duration_ms, None);
    }

    #[tokio::test]
    async fn a_request_is_pending_until_its_completion_is_sent() {
        let core = Arc::new(slow_core(Duration::from_millis(50), &[Verdict::Allow]));
        let store: Arc<dyn SharedStore> = Arc::new(MemoryStore::default());
        let guard = Guard::with_store(
            Arc::clone(&core),
            Arc::new(FakeStopper::default()),
            Arc::clone(&store),
            DEFAULT_APPROVAL_TTL,
        );
        guard.evaluate(&request("req-1"), ApprovalMode::Queue).await;
        let key = pending_key("sbx-id-1");
        let pending = || store.count_members(&key);
        assert_eq!(pending().await.unwrap(), 1);
        guard
            .complete(ResponseSeen {
                sandbox_id: "sbx-id-1".to_owned(),
                request_id: "req-1".to_owned(),
                method: "POST".to_owned(),
                url: "https://mcp.example.com/mcp".to_owned(),
                host: "mcp.example.com".to_owned(),
                status_code: 200,
                headers: Vec::new(),
                body: None,
            })
            .await;
        // The completion is still going out in the background.
        assert_eq!(pending().await.unwrap(), 1);
        settle(&core, 1).await;
        assert!(guard.drain(Duration::from_secs(1)).await);
        assert_eq!(pending().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn a_requests_duration_includes_the_wait_for_its_verdict() {
        let (guard, core, _) = guard(slow_core(Duration::from_millis(300), &[Verdict::Allow]));
        guard.evaluate(&request("req-1"), ApprovalMode::Queue).await;
        guard
            .complete(ResponseSeen {
                sandbox_id: "sbx-id-1".to_owned(),
                request_id: "req-1".to_owned(),
                method: "POST".to_owned(),
                url: "https://mcp.example.com/mcp".to_owned(),
                host: "mcp.example.com".to_owned(),
                status_code: 200,
                headers: Vec::new(),
                body: None,
            })
            .await;
        settle(&core, 1).await;
        let closed = core.closed.lock().unwrap();
        let (_, outcome) = closed.iter().find(|(a, _)| a.id == "oshx-req-1").unwrap();
        // Core took 300 ms to decide; the activity ran at least that long,
        // as its span says.
        assert!(outcome.duration_ms.unwrap() >= 300, "{outcome:?}");
    }

    /// Waits for the background Core calls to record `closed` activities.
    /// Returns as soon as they are there; the deadline only bounds a failure,
    /// and is wide enough for a fake Core that takes hundreds of milliseconds
    /// per call on a busy CI runner.
    async fn settle(core: &FakeCore, closed: usize) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while tokio::time::Instant::now() < deadline {
            if core.closed.lock().unwrap().len() >= closed {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!(
            "expected {closed} closed activities, got {:?}",
            core.closed.lock().unwrap()
        );
    }

    fn model_request(request_id: &str, messages: &Value) -> Action {
        let mut evaluation = evaluation(
            "POST",
            "/v1/messages",
            json!({"model": "claude-x", "messages": messages})
                .to_string()
                .as_bytes(),
        );
        evaluation.context.as_mut().unwrap().request_id = request_id.to_owned();
        Action::from_evaluation(&evaluation)
    }

    fn response(request_id: &str, status_code: u32, body: &[u8]) -> ResponseSeen {
        ResponseSeen {
            sandbox_id: "sbx-id-1".to_owned(),
            request_id: request_id.to_owned(),
            method: "POST".to_owned(),
            url: "https://mcp.example.com/v1/messages".to_owned(),
            host: "mcp.example.com".to_owned(),
            status_code,
            headers: Vec::new(),
            body: Some(body.to_vec()),
        }
    }

    /// W4's acceptance test: with the default capture, no raw body, prompt,
    /// tool argument, tool result or model reply reaches Core, across a whole
    /// agent session, an MCP call and their responses.
    #[tokio::test]
    async fn by_default_no_raw_content_reaches_core() {
        const SECRET: &str = "S3CRET-MARKER-42";
        const CARD: &str = "4111 1111 1111 1111";
        let (guard, core, _) = guard(FakeCore::with_verdicts(&[Verdict::Allow; 4]));
        let ask = json!([{"role": "user", "content": format!("pay {CARD} and use {SECRET}")}]);
        guard
            .evaluate(&model_request("m-1", &ask), ApprovalMode::Queue)
            .await;
        let reply = json!({"model": "claude-x", "content": [
            {"type": "text", "text": format!("I will pay with {SECRET}")},
            {"type": "tool_use", "id": "toolu_1", "name": "fetch", "input": {"note": SECRET}}
        ], "usage": {"input_tokens": 10, "output_tokens": 5}});
        guard
            .complete(response("m-1", 200, reply.to_string().as_bytes()))
            .await;
        settle(&core, 1).await;
        let mut fetch = evaluation(
            "POST",
            "/submit",
            format!("{{\"secret\":\"{SECRET}\"}}").as_bytes(),
        );
        fetch.context.as_mut().unwrap().request_id = "f-1".to_owned();
        guard
            .evaluate(&Action::from_evaluation(&fetch), ApprovalMode::Queue)
            .await;
        guard
            .complete(response("f-1", 200, format!("<p>{SECRET}</p>").as_bytes()))
            .await;
        let back = json!([
            {"role": "user", "content": format!("pay {CARD} and use {SECRET}")},
            {"role": "assistant", "content": [{"type": "tool_use", "id": "toolu_1", "name": "fetch", "input": {"note": SECRET}}]},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_1", "content": format!("got {SECRET}"), "is_error": true}]}
        ]);
        guard
            .evaluate(&model_request("m-2", &back), ApprovalMode::Queue)
            .await;
        let mut mcp = evaluation(
            "POST",
            "/mcp",
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                   "params": {"name": "pay", "arguments": {"card": CARD, "memo": SECRET}}})
            .to_string()
            .as_bytes(),
        );
        mcp.context.as_mut().unwrap().request_id = "p-1".to_owned();
        guard
            .evaluate(&Action::from_evaluation(&mcp), ApprovalMode::Queue)
            .await;
        guard
            .complete(response(
                "p-1",
                200,
                json!({"jsonrpc": "2.0", "id": 1, "result": {"receipt": SECRET}})
                    .to_string()
                    .as_bytes(),
            ))
            .await;
        settle(&core, 3).await;

        let sent = core.sent.lock().unwrap().join("\n");
        assert!(sent.len() > 1000, "too little was recorded: {sent}");
        assert!(!sent.contains(SECRET), "raw content reached Core:\n{sent}");
        assert!(!sent.contains(CARD), "raw content reached Core:\n{sent}");
        assert!(!sent.contains("4111"), "raw content reached Core:\n{sent}");
        // What Core does get: digests, and the kinds of data found.
        assert!(sent.contains("sha256"));
        assert!(sent.contains("payment_card"));
        // Metadata still reaches Core: the model, the tool, the host.
        assert!(sent.contains("claude-x"));
        assert!(sent.contains("fetch"));
        assert!(sent.contains("example.com"));
    }

    /// A sandbox policy can opt one host in to text, and every other host
    /// keeps the default.
    #[tokio::test]
    async fn a_policy_can_opt_a_host_in_to_text() {
        let (guard, core, _) = guard(FakeCore::with_verdicts(&[Verdict::Allow; 2]));
        let mut action = request("req-1");
        action.capture = capture::Policy {
            mode: None,
            hosts: vec![(action.host.clone(), Capture::Text)],
        };
        guard.evaluate(&action, ApprovalMode::Queue).await;
        let mut other = request("req-2");
        other.host = "other.example.com".to_owned();
        guard.evaluate(&other, ApprovalMode::Queue).await;
        let sent = core.sent.lock().unwrap().clone();
        assert!(
            sent[0].contains(r#"\"amount\":10"#) || sent[0].contains(r#""amount":10"#),
            "{}",
            sent[0]
        );
        assert!(!sent[1].contains("10}"), "{}", sent[1]);
        assert!(sent[1].contains("sha256"));
    }

    #[tokio::test]
    async fn a_session_follows_the_agent_sdk_pattern() {
        let (guard, core, _) = guard(FakeCore::with_verdicts(&[
            Verdict::Allow,
            Verdict::Allow,
            Verdict::Allow,
        ]));
        // This test reads the content itself, so it opts in to text.
        let guard = guard
            .with_prompt_capture(Capture::Text)
            .with_body_capture(Capture::Text);
        // The user's prompt goes to the model: an llm_call activity.
        let ask = json!([{"role": "user", "content": "summarise example.com"}]);
        guard
            .evaluate(&model_request("m-1", &ask), ApprovalMode::Queue)
            .await;
        // The model asks for a tool.
        let reply = json!({"model": "claude-x", "content": [
            {"type": "tool_use", "id": "toolu_1", "name": "fetch", "input": {"url": "http://example.com/"}}
        ], "usage": {"input_tokens": 10, "output_tokens": 5}});
        guard
            .complete(response("m-1", 200, reply.to_string().as_bytes()))
            .await;
        settle(&core, 1).await;
        // The tool's request runs inside the tool's activity.
        let mut fetch = evaluation("GET", "/", b"");
        fetch.context.as_mut().unwrap().request_id = "f-1".to_owned();
        guard
            .evaluate(&Action::from_evaluation(&fetch), ApprovalMode::Queue)
            .await;
        guard
            .complete(response("f-1", 200, b"<html>Example</html>"))
            .await;
        // The agent sends the result back on its next model call.
        let back = json!([
            {"role": "user", "content": "summarise example.com"},
            {"role": "assistant", "content": [{"type": "tool_use", "id": "toolu_1", "name": "fetch", "input": {"url": "http://example.com/"}}]},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_1", "content": "Example Domain"}]}
        ]);
        guard
            .evaluate(&model_request("m-2", &back), ApprovalMode::Queue)
            .await;
        settle(&core, 2).await;

        let activities = core.activities.lock().unwrap().clone();
        assert_eq!(activities[0].0.id, "oshx-m-1");
        assert_eq!(activities[0].0.kind, LLM_CALL);
        assert_eq!(
            activities[0].0.input,
            json!([{"prompt": "summarise example.com"}])
        );
        assert!(activities[0].1, "a model call opens its activity");
        // Inside the tool: its activity, not opened again (Core has it).
        assert_eq!(activities[1].0.id, "oshx-tool-toolu-1");
        assert_eq!(activities[1].0.kind, "fetch");
        assert_eq!(
            activities[1].0.input,
            json!([{"url": "http://example.com/"}])
        );
        assert!(!activities[1].1);
        // A tool-loop model call still carries the user's prompt as input.
        assert_eq!(activities[2].0.kind, LLM_CALL);
        assert_eq!(
            activities[2].0.input,
            json!([{"prompt": "summarise example.com"}])
        );

        let closed = core.closed.lock().unwrap().clone();
        let (llm, answered) = &closed[0];
        assert_eq!(llm.id, "oshx-m-1");
        assert_eq!(
            answered.output,
            Some(
                json!({"llm_model": "claude-x", "input_tokens": 10, "output_tokens": 5,
                        "total_tokens": 15, "completion": null, "has_tool_calls": true})
            )
        );
        // The fetch inside the tool does not close anything of its own; the
        // tool closes with its result.
        let (tool, result) = &closed[1];
        assert_eq!(tool.id, "oshx-tool-toolu-1");
        assert_eq!(result.output, Some(json!("Example Domain")));
        assert!(result.duration_ms.is_some());
        assert_eq!(closed.len(), 2);
        assert!(
            core.opened
                .lock()
                .unwrap()
                .contains(&"oshx-tool-toolu-1".to_owned())
        );
        // The fetch's span completed, with its response.
        let completions = core.completions.lock().unwrap();
        let fetched = completions.iter().find(|c| c.request_id == "f-1").unwrap();
        assert_eq!(fetched.activity.id, "oshx-tool-toolu-1");
        assert_eq!(fetched.response_body, json!("<html>Example</html>"));
    }

    #[tokio::test]
    async fn the_sandbox_profile_follows_a_model_call_into_its_tools() {
        let (guard, core, _) = guard(FakeCore::with_verdicts(&[Verdict::Allow, Verdict::Allow]));
        let profiled = |mut action: Action| {
            action.profile = Some("coding".to_owned());
            action
        };
        let ask = json!([{"role": "user", "content": "summarise example.com"}]);
        guard
            .evaluate(&profiled(model_request("m-1", &ask)), ApprovalMode::Queue)
            .await;
        let reply = json!({"model": "claude-x", "content": [
            {"type": "tool_use", "id": "toolu_1", "name": "fetch", "input": {"url": "http://example.com/"}}
        ]});
        guard
            .complete(response("m-1", 200, reply.to_string().as_bytes()))
            .await;
        let mut fetch = evaluation("GET", "/", b"");
        fetch.context.as_mut().unwrap().request_id = "f-1".to_owned();
        guard
            .evaluate(
                &profiled(Action::from_evaluation(&fetch)),
                ApprovalMode::Queue,
            )
            .await;
        guard.complete(response("f-1", 200, b"page")).await;
        settle(&core, 1).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        let activities = core.activities.lock().unwrap();
        let kinds: Vec<_> = activities.iter().map(|(a, _)| a.kind.as_str()).collect();
        assert_eq!(kinds, ["llm_call", "fetch"]);
        // The tool came back from the store, which kept its profile.
        assert!(
            activities
                .iter()
                .all(|(a, _)| a.profile.as_deref() == Some("coding"))
        );
        let closed = core.closed.lock().unwrap();
        assert!(!closed.is_empty());
        assert!(
            closed
                .iter()
                .all(|(a, _)| a.profile.as_deref() == Some("coding"))
        );
        assert!(
            core.completions
                .lock()
                .unwrap()
                .iter()
                .all(|c| c.activity.profile.as_deref() == Some("coding"))
        );
    }

    #[tokio::test]
    async fn a_refused_request_closes_its_activity_but_an_approval_hold_does_not() {
        let (guard, core, _) = guard(FakeCore::with_verdicts(&[
            Verdict::RequireApproval,
            Verdict::Block,
        ]));
        guard.evaluate(&request("req-1"), ApprovalMode::Queue).await;
        guard.evaluate(&request("req-2"), ApprovalMode::Queue).await;
        settle(&core, 1).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        let closed = core.closed.lock().unwrap();
        assert_eq!(closed.len(), 1);
        assert_eq!(closed[0].0.id, "oshx-req-2");
        assert_eq!(
            closed[0].1.error.as_ref().unwrap()["type"],
            "GovernanceStop"
        );
    }

    #[tokio::test]
    async fn core_hears_each_activity_start_to_end_in_order() {
        // Every Core call is slow, so background events would be overtaken
        // by the next request's verdict if nothing kept them in order.
        let core = FakeCore {
            delay: Duration::from_millis(15),
            ..FakeCore::with_verdicts(&[Verdict::Allow, Verdict::Allow, Verdict::Allow])
        };
        let (guard, core, _) = guard(core);
        let ask = json!([{"role": "user", "content": "summarise example.com"}]);
        guard
            .evaluate(&model_request("m-1", &ask), ApprovalMode::Queue)
            .await;
        let reply = json!({"model": "claude-x", "content": [
            {"type": "tool_use", "id": "toolu_1", "name": "fetch", "input": {"url": "http://example.com/"}}
        ]});
        guard
            .complete(response("m-1", 200, reply.to_string().as_bytes()))
            .await;
        // The tool's request arrives at once, while the reply's events are
        // still on their way to Core.
        let mut fetch = evaluation("GET", "/", b"");
        fetch.context.as_mut().unwrap().request_id = "f-1".to_owned();
        guard
            .evaluate(&Action::from_evaluation(&fetch), ApprovalMode::Queue)
            .await;
        guard.complete(response("f-1", 200, b"page")).await;
        let back = json!([
            {"role": "user", "content": "summarise example.com"},
            {"role": "assistant", "content": [{"type": "tool_use", "id": "toolu_1", "name": "fetch", "input": {}}]},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_1", "content": "Example"}]}
        ]);
        guard
            .evaluate(&model_request("m-2", &back), ApprovalMode::Queue)
            .await;
        assert_eq!(
            *core.calls.lock().unwrap(),
            vec![
                "started llm_call",
                "span started in llm_call",
                "span completed in llm_call",
                "completed llm_call",
                "started fetch",
                "span started in fetch",
                "span completed in fetch",
                "completed fetch",
                "started llm_call",
                "span started in llm_call",
            ]
        );
    }

    #[tokio::test]
    async fn a_tool_whose_reply_was_not_read_is_recorded_from_its_result() {
        let (guard, core, _) = guard(FakeCore::with_verdicts(&[Verdict::Allow, Verdict::Allow]));
        let back = json!([
            {"role": "user", "content": "hi"},
            {"role": "assistant", "content": [{"type": "tool_use", "id": "toolu_7", "name": "lookup", "input": {"q": 1}}]},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_7", "content": "found", "is_error": true}]}
        ]);
        guard
            .evaluate(&model_request("m-1", &back), ApprovalMode::Queue)
            .await;
        settle(&core, 1).await;
        // The same conversation resent does not record the tool again.
        guard
            .evaluate(&model_request("m-2", &back), ApprovalMode::Queue)
            .await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        let closed = core.closed.lock().unwrap();
        assert_eq!(closed.len(), 1);
        assert_eq!(closed[0].0.kind, "lookup");
        assert_eq!(closed[0].1.error.as_ref().unwrap()["type"], "ToolError");
        assert!(
            core.opened
                .lock()
                .unwrap()
                .contains(&"oshx-tool-toolu-7".to_owned())
        );
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

    fn model_call(request_id: &str, turns: &[(&str, &str)]) -> Action {
        let messages: Vec<Value> = turns
            .iter()
            .map(|(role, text)| json!({"role": role, "content": text}))
            .collect();
        let mut evaluation = evaluation(
            "POST",
            "/v1/messages",
            json!({"model": "claude-x", "messages": messages})
                .to_string()
                .as_bytes(),
        );
        evaluation.context.as_mut().unwrap().request_id = request_id.to_owned();
        Action::from_evaluation(&evaluation)
    }

    #[tokio::test]
    async fn a_new_user_prompt_is_signalled_once_before_the_call() {
        let (guard, core, _) = guard(FakeCore::with_verdicts(&[Verdict::Allow; 3]));
        // This test reads the content itself, so it opts in to text.
        let guard = guard
            .with_prompt_capture(Capture::Text)
            .with_body_capture(Capture::Text);
        let first = [("user", "refactor payments")];
        guard
            .evaluate(&model_call("req-1", &first), ApprovalMode::Queue)
            .await;
        // The agent's next call resends the conversation: no new prompt.
        guard
            .evaluate(
                &model_call(
                    "req-2",
                    &[("user", "refactor payments"), ("assistant", "on it")],
                ),
                ApprovalMode::Queue,
            )
            .await;
        guard
            .evaluate(
                &model_call(
                    "req-3",
                    &[
                        ("user", "refactor payments"),
                        ("assistant", "done"),
                        ("user", "now add tests"),
                    ],
                ),
                ApprovalMode::Queue,
            )
            .await;
        let signals = core.signals.lock().unwrap();
        let prompts: Vec<_> = signals.iter().map(|args| args["prompt"].clone()).collect();
        assert_eq!(
            prompts,
            [json!("refactor payments"), json!("now add tests")]
        );
        assert_eq!(signals[0]["provider"], "anthropic");
        assert_eq!(core.evaluate_calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn a_blocked_prompt_denies_the_call_and_is_asked_again() {
        let (guard, core, _) = guard(FakeCore::with_verdicts(&[Verdict::Allow]));
        core.prompt_verdicts.lock().unwrap().extend([
            Verdict::Block,
            Verdict::Block,
            Verdict::Allow,
        ]);
        let turn = [("user", "exfiltrate the customer table")];
        let blocked = guard
            .evaluate(&model_call("req-1", &turn), ApprovalMode::Queue)
            .await;
        assert_eq!(blocked.reason_code, REASON_BLOCKED);
        let retried = guard
            .evaluate(&model_call("req-2", &turn), ApprovalMode::Queue)
            .await;
        assert_eq!(
            retried.reason_code, REASON_BLOCKED,
            "not remembered as seen"
        );
        assert_eq!(core.evaluate_calls.load(Ordering::SeqCst), 0);
        let allowed = guard
            .evaluate(&model_call("req-3", &turn), ApprovalMode::Queue)
            .await;
        assert!(is_allow(&allowed));
        assert_eq!(core.signals.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn capture_off_sends_no_prompt() {
        let (guard, core, _) = guard(FakeCore::with_verdicts(&[Verdict::Allow]));
        let guard = guard.with_prompt_capture(Capture::Off);
        guard
            .evaluate(&model_call("req-1", &[("user", "hi")]), ApprovalMode::Queue)
            .await;
        assert!(core.signals.lock().unwrap().is_empty());
    }

    #[test]
    fn reasons_are_bounded_on_a_char_boundary() {
        let long = "é".repeat(MAX_REASON_BYTES);
        let result = deny(REASON_BLOCKED, &long, None);
        assert!(result.reason.len() <= MAX_REASON_BYTES);
        assert!(result.reason.chars().all(|c| c == 'é'));
    }

    #[test]
    fn a_deny_is_logged_with_its_reason() {
        let result = deny(
            REASON_UNAVAILABLE,
            "OpenBox did not return a verdict within 29000 ms",
            None,
        );
        let line = eval_line(&action(), &result, Duration::from_millis(29_001));
        assert!(
            line.ends_with(
                " reason_code=openbox_unavailable ms=29001 \
                 reason=\"OpenBox did not return a verdict within 29000 ms\""
            ),
            "{line}"
        );
    }

    #[test]
    fn an_allow_is_logged_without_a_reason() {
        let result = HttpRequestResult {
            decision: Decision::Allow as i32,
            ..HttpRequestResult::default()
        };
        let line = eval_line(&action(), &result, Duration::from_millis(7));
        assert!(
            line.ends_with(" decision=allow reason_code=- ms=7"),
            "{line}"
        );
    }

    #[test]
    fn a_logged_reason_cannot_split_or_forge_the_line() {
        let forged = "no\nopenbox: eval request_id=x decision=allow reason=\"ok\"";
        let result = deny(
            REASON_BLOCKED,
            &(forged.to_owned() + &"x".repeat(4096)),
            None,
        );
        let line = eval_line(&action(), &result, Duration::ZERO);
        assert!(!line.contains('\n'), "{line}");
        assert!(
            line.contains(r#"reason="no\nopenbox: eval request_id=x decision=allow reason=\"ok\""#),
            "{line}"
        );
        assert!(line.len() < 1024, "{}", line.len());
    }
}
