//! Client for `OpenBox` Core's governance API.
//!
//! Each `OpenShell` sandbox is one Core session: `workflow_id` and `run_id`
//! are the sandbox id, announced once with `WorkflowStarted`. Every evaluated
//! request is an `ActivityStarted` hook event carrying one span that describes
//! the HTTP or MCP call, so policy, guardrails and behavioral rules see it the
//! same way they see SDK-instrumented traffic, and its response closes it with
//! `ActivityCompleted` under the same `activity_id`. Each request is its own
//! activity (`oshx-<request id>`); an approval retry reuses the activity Core
//! holds the approval on, which the guard looks up by the action fingerprint.
//!
//! Requests are sent as exact bytes so the optional Ed25519 request signature
//! (`X-OpenBox-Agent-*`, required for agents with signed requests on) covers
//! what Core receives.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use ring::signature::{Ed25519KeyPair, RSA_PKCS1_SHA256, RsaKeyPair};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tokio::sync::Mutex;

use crate::action::{Action, Payload};

const EVALUATE_PATH: &str = "/api/v1/governance/evaluate";
const APPROVAL_PATH: &str = "/api/v1/governance/approval";
const V3_EVALUATE_PATH: &str = "/api/v3/governance/evaluate";
const V3_APPROVAL_PATH: &str = "/api/v3/governance/approval";
const V3_BOOTSTRAP_PATH: &str = "/api/v3/auth/bootstrap";
/// Refresh a workload token this long before Keycloak says it expires.
const TOKEN_REFRESH_MARGIN: Duration = Duration::from_secs(60);
const WORKFLOW_TYPE: &str = "openshell.sandbox";
const TASK_QUEUE: &str = "openshell";
const SDK_IDENTIFIER: &str = concat!("openshell-middleware/rust/", env!("CARGO_PKG_VERSION"));

/// A verdict as Core states it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Verdict {
    Allow,
    Constrain,
    RequireApproval,
    Block,
    Halt,
}

impl Verdict {
    /// Parses Core's wire string, including the legacy aliases Core accepts.
    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "allow" | "continue" => Some(Self::Allow),
            "constrain" => Some(Self::Constrain),
            "require_approval" | "require-approval" => Some(Self::RequireApproval),
            "block" => Some(Self::Block),
            "halt" | "stop" => Some(Self::Halt),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct CoreDecision {
    pub verdict: Verdict,
    pub reason: Option<String>,
    pub governance_event_id: Option<String>,
    pub risk_score: Option<f64>,
    /// Unix seconds after which a pending approval lapses.
    pub approval_expires_at: Option<i64>,
    pub policy_id: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalState {
    Approved,
    Pending {
        expires_at: Option<i64>,
    },
    Rejected(Verdict),
    /// Core no longer knows the approval (404) or it has expired.
    Gone,
}

#[derive(Debug)]
pub enum CoreError {
    Transport,
    Status(u16),
    Malformed,
}

impl core::fmt::Display for CoreError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Transport => formatter.write_str("core unreachable or timed out"),
            Self::Status(code) => write!(formatter, "core returned HTTP {code}"),
            Self::Malformed => formatter.write_str("core response was malformed"),
        }
    }
}

impl std::error::Error for CoreError {}

/// Everything Core needs to attribute events to one `OpenBox` agent.
pub struct CoreConfig {
    pub base_url: String,
    pub api_key: String,
    /// Ed25519 request signing, for v1 agents with "Require signed requests".
    pub signer: Option<AgentSigner>,
    /// Keycloak workload identity. Agents created in an organization with an
    /// identity provider generation use it, and must call the v3 API.
    pub workload: Option<WorkloadIdentity>,
    pub timeout: Duration,
    /// Request bodies larger than this are sent to Core truncated.
    pub body_limit_bytes: usize,
}

pub struct AgentSigner {
    did: String,
    key: Ed25519KeyPair,
}

impl AgentSigner {
    /// `seed_b64` is the agent's raw 32-byte Ed25519 seed, base64 encoded, as
    /// issued at agent registration.
    pub fn new(did: impl Into<String>, seed_b64: &str) -> Result<Self, CoreError> {
        let seed = base64::engine::general_purpose::STANDARD
            .decode(seed_b64.trim())
            .map_err(|_| CoreError::Malformed)?;
        let key = Ed25519KeyPair::from_seed_unchecked(&seed).map_err(|_| CoreError::Malformed)?;
        let did = did.into();
        if !did.starts_with("did:aip:") {
            return Err(CoreError::Malformed);
        }
        Ok(Self { did, key })
    }

    fn headers(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        now: SystemTime,
    ) -> Vec<(&'static str, String)> {
        let body_sha256 = hex(&Sha256::digest(body));
        let timestamp = rfc3339_micros(now);
        let nonce = random_token();
        let canonical = [
            method.to_ascii_uppercase().as_str(),
            path,
            &timestamp,
            &nonce,
            &body_sha256,
        ]
        .join("\n");
        let signature = base64::engine::general_purpose::STANDARD
            .encode(self.key.sign(canonical.as_bytes()).as_ref());
        vec![
            ("X-OpenBox-Agent-DID", self.did.clone()),
            ("X-OpenBox-Agent-Timestamp", timestamp),
            ("X-OpenBox-Agent-Nonce", nonce),
            ("X-OpenBox-Agent-Signature", signature),
            ("X-OpenBox-Body-SHA256", body_sha256),
        ]
    }
}

/// The agent's workload service-account key.
///
/// Core's v3 API wants the agent
/// API key plus a Keycloak access token obtained with a signed RS256 client
/// assertion (private-key JWT). Tokens are cached and refreshed ahead of
/// expiry, so the assertion round trip is not on the per-request path.
pub struct WorkloadIdentity {
    key: RsaKeyPair,
    kid: String,
    cache: Mutex<Option<CachedToken>>,
}

struct CachedToken {
    token: String,
    refresh_at: std::time::Instant,
}

impl WorkloadIdentity {
    /// `pem` is the RSA private key registered with the agent, as PKCS#8
    /// (`BEGIN PRIVATE KEY`) or PKCS#1 (`BEGIN RSA PRIVATE KEY`).
    pub fn from_pem(pem: &str, kid: impl Into<String>) -> Result<Self, CoreError> {
        let pkcs1 = pem.contains("BEGIN RSA PRIVATE KEY");
        let body: String = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .map(str::trim)
            .collect();
        let der = base64::engine::general_purpose::STANDARD
            .decode(body)
            .map_err(|_| CoreError::Malformed)?;
        let key = if pkcs1 {
            RsaKeyPair::from_der(&der)
        } else {
            RsaKeyPair::from_pkcs8(&der)
        }
        .map_err(|_| CoreError::Malformed)?;
        let kid = kid.into();
        if kid.is_empty() {
            return Err(CoreError::Malformed);
        }
        Ok(Self {
            key,
            kid,
            cache: Mutex::new(None),
        })
    }

    fn assertion(
        &self,
        token_endpoint: &str,
        client_id: &str,
        now: i64,
    ) -> Result<String, CoreError> {
        let encode = |value: &Value| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value.to_string())
        };
        let signed = format!(
            "{}.{}",
            encode(&json!({"alg": "RS256", "kid": self.kid, "typ": "JWT"})),
            encode(&json!({
                "aud": token_endpoint,
                "iss": client_id,
                "sub": client_id,
                "iat": now,
                "exp": now + 60,
                "jti": random_hex(16),
            }))
        );
        let mut signature = vec![0_u8; self.key.public().modulus_len()];
        self.key
            .sign(
                &RSA_PKCS1_SHA256,
                &ring::rand::SystemRandom::new(),
                signed.as_bytes(),
                &mut signature,
            )
            .map_err(|_| CoreError::Malformed)?;
        Ok(format!(
            "{signed}.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature)
        ))
    }
}

#[derive(Deserialize)]
struct Bootstrap {
    token_endpoint: String,
    client_id: String,
    kid: Option<String>,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: Option<u64>,
}

pub struct CoreClient {
    config: CoreConfig,
    http: reqwest::Client,
}

impl CoreClient {
    pub fn new(config: CoreConfig) -> Result<Self, CoreError> {
        let http = reqwest::Client::builder()
            .timeout(config.timeout)
            .https_only(!config.base_url.starts_with("http://"))
            .build()
            .map_err(|_| CoreError::Transport)?;
        Ok(Self { config, http })
    }

    /// Opens the Core session for a sandbox. Safe to repeat: Core returns the
    /// stored result for a duplicate `WorkflowStarted`.
    pub async fn start_session(
        &self,
        sandbox_id: &str,
        sandbox_name: &str,
    ) -> Result<CoreDecision, CoreError> {
        self.start_session_with(sandbox_id, sandbox_name, None)
            .await
    }

    /// [`Self::start_session`] with the sandbox's description as the session's
    /// input. The front desk sends it at create, before the sandbox can make
    /// a request, so it is the `WorkflowStarted` Core keeps.
    pub async fn start_session_with(
        &self,
        sandbox_id: &str,
        sandbox_name: &str,
        input: Option<&Value>,
    ) -> Result<CoreDecision, CoreError> {
        let payload = session_event(sandbox_id, sandbox_name, input, SystemTime::now());
        let key = format!("wfs-{sandbox_id}");
        self.evaluate(&payload, &key).await
    }

    /// Closes the Core session for a deleted sandbox, so Core marks it
    /// completed and seals it. Safe to repeat, like [`Self::start_session`].
    pub async fn end_session(
        &self,
        sandbox_id: &str,
        duration_ms: Option<u64>,
    ) -> Result<CoreDecision, CoreError> {
        let payload = session_end_event(sandbox_id, duration_ms, SystemTime::now());
        let key = format!("wfc-{sandbox_id}");
        self.evaluate(&payload, &key).await
    }

    /// Asks Core for a verdict on one action.
    pub async fn evaluate_action(
        &self,
        action: &Action,
        activity_id: &str,
    ) -> Result<CoreDecision, CoreError> {
        let payload = action_event(
            action,
            activity_id,
            self.config.body_limit_bytes,
            SystemTime::now(),
        );
        let key = format!("act-{}-{}", action.sandbox_id, action.request_id);
        self.evaluate(&payload, &idempotency_key(&key)).await
    }

    /// Closes an activity when its response comes back. A notification: the
    /// response is already on its way to the sandbox.
    pub async fn complete_activity(
        &self,
        completion: &Completion,
    ) -> Result<CoreDecision, CoreError> {
        let payload = completion_event(completion, SystemTime::now());
        let key = format!("acd-{}-{}", completion.sandbox_id, completion.request_id);
        self.evaluate(&payload, &idempotency_key(&key)).await
    }

    /// Reads the state of an approval Core is holding for an action. Polling
    /// also makes Core issue the short-lived grant that lets the approved
    /// action's retry through.
    pub async fn approval_state(
        &self,
        action: &Action,
        activity_id: &str,
    ) -> Result<ApprovalState, CoreError> {
        let body = serde_json::to_vec(&json!({
            "workflow_id": action.sandbox_id,
            "run_id": action.sandbox_id,
            "activity_id": activity_id,
        }))
        .map_err(|_| CoreError::Malformed)?;
        let path = if self.config.workload.is_some() {
            V3_APPROVAL_PATH
        } else {
            APPROVAL_PATH
        };
        let response = self.post(path, body, None).await?;
        let status = response.status().as_u16();
        if status == 404 {
            return Ok(ApprovalState::Gone);
        }
        if !(200..300).contains(&status) {
            return Err(CoreError::Status(status));
        }
        let parsed: ApprovalResponse = response.json().await.map_err(|_| CoreError::Malformed)?;
        let expires_at = parsed
            .approval_expiration_time
            .as_deref()
            .and_then(parse_rfc3339);
        Ok(
            match parsed
                .action
                .as_deref()
                .and_then(Verdict::parse)
                .ok_or(CoreError::Malformed)?
            {
                Verdict::Allow => ApprovalState::Approved,
                Verdict::RequireApproval => {
                    if expires_at.is_some_and(|at| at <= unix_now()) {
                        ApprovalState::Gone
                    } else {
                        ApprovalState::Pending { expires_at }
                    }
                }
                other => ApprovalState::Rejected(other),
            },
        )
    }

    async fn evaluate(
        &self,
        payload: &Value,
        idempotency_key: &str,
    ) -> Result<CoreDecision, CoreError> {
        let body = serde_json::to_vec(payload).map_err(|_| CoreError::Malformed)?;
        let path = if self.config.workload.is_some() {
            V3_EVALUATE_PATH
        } else {
            EVALUATE_PATH
        };
        let response = self.post(path, body, Some(idempotency_key)).await?;
        let status = response.status().as_u16();
        if !(200..300).contains(&status) {
            return Err(CoreError::Status(status));
        }
        let parsed: EvaluateResponse = response.json().await.map_err(|_| CoreError::Malformed)?;
        parsed.into_decision()
    }

    async fn post(
        &self,
        path: &str,
        body: Vec<u8>,
        idempotency_key: Option<&str>,
    ) -> Result<reqwest::Response, CoreError> {
        let url = format!("{}{path}", self.config.base_url.trim_end_matches('/'));
        let mut request = self
            .http
            .post(url)
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .header("Content-Type", "application/json")
            .header("User-Agent", format!("OpenBox-SDK/{SDK_IDENTIFIER}"))
            .header("X-OpenBox-SDK-Version", SDK_IDENTIFIER);
        if let Some(key) = idempotency_key {
            request = request.header("Idempotency-Key", key);
        }
        if let Some(signer) = &self.config.signer {
            for (name, value) in signer.headers("POST", path, &body, SystemTime::now()) {
                request = request.header(name, value);
            }
        }
        if let Some(workload) = &self.config.workload {
            request = request.header(
                "X-OpenBox-Workload-Token",
                self.workload_token(workload).await?,
            );
        }
        let response = request
            .body(body)
            .send()
            .await
            .map_err(|_| CoreError::Transport)?;
        if response.status().as_u16() == 401
            && let Some(workload) = &self.config.workload
        {
            // A revoked or rotated token: fetch a fresh one on the next call.
            *workload.cache.lock().await = None;
        }
        Ok(response)
    }

    /// The agent's current Keycloak workload token, for other `OpenBox` APIs
    /// that take the same identity (the backend's runtime-environment routes).
    /// `None` when the agent has no workload identity configured.
    pub async fn current_workload_token(&self) -> Option<Result<String, CoreError>> {
        let workload = self.config.workload.as_ref()?;
        Some(self.workload_token(workload).await)
    }

    /// Drops the cached workload token after a caller saw it rejected.
    pub async fn forget_workload_token(&self) {
        if let Some(workload) = &self.config.workload {
            *workload.cache.lock().await = None;
        }
    }

    async fn workload_token(&self, workload: &WorkloadIdentity) -> Result<String, CoreError> {
        let mut cache = workload.cache.lock().await;
        if let Some(cached) = cache.as_ref()
            && std::time::Instant::now() < cached.refresh_at
        {
            return Ok(cached.token.clone());
        }
        let base = self.config.base_url.trim_end_matches('/');
        let bootstrap: Bootstrap = self
            .http
            .get(format!("{base}{V3_BOOTSTRAP_PATH}"))
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .send()
            .await
            .map_err(|_| CoreError::Transport)?
            .error_for_status()
            .map_err(|error| CoreError::Status(error.status().map_or(0, |s| s.as_u16())))?
            .json()
            .await
            .map_err(|_| CoreError::Malformed)?;
        if bootstrap
            .kid
            .as_deref()
            .is_some_and(|kid| kid != workload.kid)
        {
            return Err(CoreError::Malformed);
        }
        let assertion =
            workload.assertion(&bootstrap.token_endpoint, &bootstrap.client_id, unix_now())?;
        let form = form_encode(&[
            ("grant_type", "client_credentials"),
            ("client_id", &bootstrap.client_id),
            (
                "client_assertion_type",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            ),
            ("client_assertion", &assertion),
        ]);
        let token: TokenResponse = self
            .http
            .post(&bootstrap.token_endpoint)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(form)
            .send()
            .await
            .map_err(|_| CoreError::Transport)?
            .error_for_status()
            .map_err(|error| CoreError::Status(error.status().map_or(0, |s| s.as_u16())))?
            .json()
            .await
            .map_err(|_| CoreError::Malformed)?;
        let lifetime = Duration::from_secs(token.expires_in.unwrap_or(300));
        *cache = Some(CachedToken {
            token: token.access_token.clone(),
            refresh_at: std::time::Instant::now() + lifetime.saturating_sub(TOKEN_REFRESH_MARGIN),
        });
        Ok(token.access_token)
    }
}

#[derive(Deserialize)]
struct EvaluateResponse {
    verdict: Option<String>,
    action: Option<String>,
    reason: Option<String>,
    governance_event_id: Option<String>,
    risk_score: Option<f64>,
    approval_expiration_time: Option<String>,
    policy_id: Option<String>,
}

impl EvaluateResponse {
    fn into_decision(self) -> Result<CoreDecision, CoreError> {
        let verdict = self.verdict.as_deref().and_then(Verdict::parse);
        let action = self.action.as_deref().and_then(Verdict::parse);
        // Like the SDK, refuse a response whose verdict and action disagree.
        let verdict = match (verdict, action) {
            (Some(verdict), Some(action)) if verdict != action => return Err(CoreError::Malformed),
            (Some(verdict), _) | (None, Some(verdict)) => verdict,
            (None, None) => return Err(CoreError::Malformed),
        };
        Ok(CoreDecision {
            verdict,
            reason: self.reason.filter(|reason| !reason.is_empty()),
            governance_event_id: self.governance_event_id.filter(|id| !id.is_empty()),
            risk_score: self.risk_score,
            approval_expires_at: self
                .approval_expiration_time
                .as_deref()
                .and_then(parse_rfc3339),
            policy_id: self.policy_id.filter(|id| !id.is_empty()),
        })
    }
}

#[derive(Deserialize)]
struct ApprovalResponse {
    action: Option<String>,
    approval_expiration_time: Option<String>,
}

/// A request's own activity id. Request ids are `OpenShell`'s, so trim them to
/// what Core accepts rather than trust them.
pub fn request_activity_id(request_id: &str) -> String {
    let id: String = request_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .take(59)
        .collect();
    format!("oshx-{id}")
}

/// What the dashboard shows for an activity: the MCP tool for a tool call,
/// otherwise the method and host. Policy and behaviour rules key on the span's
/// semantic type, not on this.
pub fn activity_name(action: &Action) -> String {
    action.tools().first().map_or_else(
        || format!("{} {}", action.method, action.host),
        |tool| format!("MCP {tool}"),
    )
}

/// A response that closes an activity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Completion {
    pub sandbox_id: String,
    pub request_id: String,
    pub activity_id: String,
    pub activity_type: String,
    pub method: String,
    pub url: String,
    pub status_code: u32,
    pub duration_ms: Option<u64>,
}

fn form_encode(fields: &[(&str, &str)]) -> String {
    let escape = |value: &str| {
        value.bytes().fold(String::new(), |mut out, byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
                out.push(char::from(byte));
            } else {
                use std::fmt::Write as _;
                let _ = write!(out, "%{byte:02X}");
            }
            out
        })
    };
    fields
        .iter()
        .map(|(key, value)| format!("{}={}", escape(key), escape(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn idempotency_key(raw: &str) -> String {
    raw.chars()
        .filter(|c| !c.is_whitespace() && !c.is_control())
        .take(200)
        .collect()
}

fn session_event(
    sandbox_id: &str,
    sandbox_name: &str,
    input: Option<&Value>,
    now: SystemTime,
) -> Value {
    let mut event = json!({
        "source": "workflow-telemetry",
        "event_type": "WorkflowStarted",
        "workflow_id": sandbox_id,
        "run_id": sandbox_id,
        "workflow_type": WORKFLOW_TYPE,
        "task_queue": TASK_QUEUE,
        "timestamp": rfc3339_micros(now),
        "span_count": 0,
        "spans": [],
        "hook_trigger": false,
        "metadata": {"openshell": {"sandbox_id": sandbox_id, "sandbox": sandbox_name}},
    });
    if let Some(input) = input {
        event["activity_input"] = json!([input]);
    }
    event
}

fn session_end_event(sandbox_id: &str, duration_ms: Option<u64>, now: SystemTime) -> Value {
    let mut event = json!({
        "source": "workflow-telemetry",
        "event_type": "WorkflowCompleted",
        "workflow_id": sandbox_id,
        "run_id": sandbox_id,
        "workflow_type": WORKFLOW_TYPE,
        "task_queue": TASK_QUEUE,
        "timestamp": rfc3339_micros(now),
        "status": "completed",
        "activity_output": [{"reason": "sandbox deleted"}],
        "span_count": 0,
        "spans": [],
        "hook_trigger": false,
        "metadata": {"openshell": {"sandbox_id": sandbox_id}},
    });
    if let Some(duration) = duration_ms {
        #[allow(clippy::cast_precision_loss)]
        let duration = duration as f64;
        event["duration_ms"] = json!(duration);
    }
    event
}

fn completion_event(completion: &Completion, now: SystemTime) -> Value {
    let mut event = json!({
        "source": "workflow-telemetry",
        "event_type": "ActivityCompleted",
        "workflow_id": completion.sandbox_id,
        "run_id": completion.sandbox_id,
        "workflow_type": WORKFLOW_TYPE,
        "task_queue": TASK_QUEUE,
        "activity_id": completion.activity_id,
        "activity_type": completion.activity_type,
        "attempt": 1,
        "activity_output": [{
            "status_code": completion.status_code,
            "method": completion.method,
            "url": completion.url,
        }],
        "status": if completion.status_code >= 500 { "failed" } else { "completed" },
        "timestamp": rfc3339_micros(now),
        "hook_trigger": false,
        "span_count": 0,
        "spans": [],
        "metadata": {"openshell": {
            "sandbox_id": completion.sandbox_id,
            "request_id": completion.request_id,
        }},
    });
    if let Some(duration) = completion.duration_ms {
        #[allow(clippy::cast_precision_loss)]
        let duration = duration as f64;
        event["duration_ms"] = json!(duration);
    }
    event
}

fn action_event(action: &Action, activity_id: &str, body_limit: usize, now: SystemTime) -> Value {
    let is_mcp = !action.tools().is_empty();
    let url = request_url(action);
    let started_ns = now.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos());
    let mut attributes = json!({
        "http.request.method": action.method,
        "url.full": url,
        "server.address": action.host,
        "server.port": action.port,
        "openshell.sandbox_id": action.sandbox_id,
        "openshell.request_id": action.request_id,
    });
    if let Some(binary) = &action.process_binary {
        attributes["process.executable.path"] = json!(binary);
    }
    if let Payload::JsonRpc(calls) = &action.payload
        && let Some(call) = calls
            .iter()
            .find(|call| call.tool.is_some())
            .or_else(|| calls.first())
    {
        attributes["rpc.method"] = json!(call.method);
        if let Some(tool) = &call.tool {
            attributes["mcp.method"] = json!("callTool");
            attributes["mcp.server_id"] = json!(action.host);
            attributes["mcp.operation"] = json!(tool);
            attributes["mcp.input"] = json!(
                call.arguments
                    .as_ref()
                    .map_or_else(String::new, Value::to_string)
            );
        }
    }
    let span = json!({
        "span_id": random_hex(8),
        "trace_id": random_hex(16),
        "name": format!("HTTP {}", action.method),
        "kind": "CLIENT",
        "stage": "started",
        "start_time": u64::try_from(started_ns).unwrap_or(u64::MAX),
        "end_time": null,
        "attributes": attributes,
        "status": {"code": "UNSET"},
        "events": [],
        "hook_type": if is_mcp { "mcp" } else { "http_request" },
        "http_method": action.method,
        "http_url": url,
        "request_headers": {},
        "request_body": body_text(&action.body, body_limit),
        "http_status_code": null,
    });
    json!({
        "source": "workflow-telemetry",
        "event_type": "ActivityStarted",
        "workflow_id": action.sandbox_id,
        "run_id": action.sandbox_id,
        "workflow_type": WORKFLOW_TYPE,
        "task_queue": TASK_QUEUE,
        "activity_id": activity_id,
        "activity_type": activity_name(action),
        "attempt": 1,
        "activity_input": [{
            "method": action.method,
            "url": url,
            "tools": action.tools(),
            "body_bytes": action.body_bytes,
        }],
        "timestamp": rfc3339_micros(now),
        "hook_trigger": true,
        "span_count": 1,
        "spans": [span],
        "metadata": {"openshell": {
            "sandbox_id": action.sandbox_id,
            "sandbox": action.sandbox_name,
            "request_id": action.request_id,
            "process": action.process_binary,
            "ancestors": action.process_ancestors,
        }},
    })
}

pub fn request_url(action: &Action) -> String {
    target_url(
        &action.scheme,
        &action.host,
        action.port,
        &action.path,
        &action.query,
    )
}

/// `scheme://host[:port]path[?query]`, omitting the scheme's default port.
pub fn target_url(scheme: &str, host: &str, port: u32, path: &str, query: &str) -> String {
    let default_port = matches!((scheme, port), ("https" | "wss", 443) | ("http" | "ws", 80));
    let authority = if default_port {
        host.to_owned()
    } else {
        format!("{host}:{port}")
    };
    let query = if query.is_empty() {
        String::new()
    } else {
        format!("?{query}")
    };
    format!("{scheme}://{authority}{path}{query}")
}

fn body_text(body: &[u8], limit: usize) -> Value {
    if body.is_empty() {
        return Value::Null;
    }
    let slice = &body[..body.len().min(limit)];
    Value::String(String::from_utf8_lossy(slice).into_owned())
}

fn random_hex(bytes: usize) -> String {
    let mut buffer = vec![0_u8; bytes];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut buffer)
        .expect("system randomness is available");
    hex(&buffer)
}

fn random_token() -> String {
    let mut buffer = [0_u8; 24];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut buffer)
        .expect("system randomness is available");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buffer)
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            use std::fmt::Write as _;
            let _ = write!(out, "{byte:02x}");
            out
        })
}

pub(crate) fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// `YYYY-MM-DDTHH:MM:SS.ffffff+00:00`, the form the Python SDK signs.
fn rfc3339_micros(time: SystemTime) -> String {
    let since = time.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = i64::try_from(since.as_secs()).unwrap_or(i64::MAX);
    let (year, month, day) = civil_from_days(secs.div_euclid(86_400));
    let rem = secs.rem_euclid(86_400);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:06}+00:00",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60,
        since.subsec_micros()
    )
}

/// Parses the RFC 3339 timestamps Core emits into Unix seconds (UTC offsets
/// honoured, fractional seconds ignored).
fn parse_rfc3339(value: &str) -> Option<i64> {
    let bytes = value.as_bytes();
    if bytes.len() < 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !matches!(bytes[10], b'T' | b't' | b' ')
    {
        return None;
    }
    let number = |range: core::ops::Range<usize>| value.get(range)?.parse::<i64>().ok();
    let (year, month, day) = (number(0..4)?, number(5..7)?, number(8..10)?);
    let (hour, minute, second) = (number(11..13)?, number(14..16)?, number(17..19)?);
    let mut rest = &value[19..];
    if let Some(fraction) = rest.strip_prefix('.') {
        let digits = fraction.bytes().take_while(u8::is_ascii_digit).count();
        rest = &fraction[digits..];
    }
    let offset = match rest {
        "Z" | "z" => 0,
        _ if rest.len() == 6
            && matches!(rest.as_bytes()[0], b'+' | b'-')
            && rest.as_bytes()[3] == b':' =>
        {
            let sign = if rest.starts_with('-') { -1 } else { 1 };
            sign * (rest[1..3].parse::<i64>().ok()? * 3600 + rest[4..6].parse::<i64>().ok()? * 60)
        }
        _ => return None,
    };
    let days = days_from_civil(year, month, day);
    Some(days * 86_400 + hour * 3600 + minute * 60 + second - offset)
}

// Howard Hinnant's civil calendar conversions.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let yoe = year - era * 400;
    let doy = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(month <= 2), month, day)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::tests::evaluation;

    #[test]
    fn parses_verdicts_and_legacy_aliases() {
        assert_eq!(Verdict::parse("allow"), Some(Verdict::Allow));
        assert_eq!(Verdict::parse("CONTINUE"), Some(Verdict::Allow));
        assert_eq!(
            Verdict::parse("require-approval"),
            Some(Verdict::RequireApproval)
        );
        assert_eq!(Verdict::parse("stop"), Some(Verdict::Halt));
        assert_eq!(Verdict::parse("maybe"), None);
    }

    #[test]
    fn refuses_disagreeing_verdict_and_action() {
        let response = EvaluateResponse {
            verdict: Some("allow".to_owned()),
            action: Some("block".to_owned()),
            reason: None,
            governance_event_id: None,
            risk_score: None,
            approval_expiration_time: None,
            policy_id: None,
        };
        assert!(matches!(
            response.into_decision(),
            Err(CoreError::Malformed)
        ));
    }

    #[test]
    fn formats_and_parses_timestamps() {
        let time = UNIX_EPOCH + Duration::new(1_790_674_275, 359_123_000);
        assert_eq!(rfc3339_micros(time), "2026-09-29T09:31:15.359123+00:00");
        assert_eq!(
            parse_rfc3339("2026-09-29T09:31:15.359123+00:00"),
            Some(1_790_674_275)
        );
        assert_eq!(parse_rfc3339("2026-09-29T09:31:15Z"), Some(1_790_674_275));
        assert_eq!(
            parse_rfc3339("2026-09-29T16:31:15+07:00"),
            Some(1_790_674_275)
        );
        assert_eq!(parse_rfc3339("2000-02-29T00:00:00Z"), Some(951_782_400));
        assert_eq!(parse_rfc3339("yesterday"), None);
    }

    #[test]
    fn an_mcp_tool_call_becomes_an_mcp_hook_span() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_database","arguments":{"name":"prod"}}}"#;
        let action = Action::from_evaluation(&evaluation("POST", "/mcp", body));
        let event = action_event(
            &action,
            "oshx-req-1",
            1024,
            UNIX_EPOCH + Duration::from_secs(1_790_674_275),
        );
        assert_eq!(event["event_type"], "ActivityStarted");
        assert_eq!(event["hook_trigger"], true);
        assert_eq!(event["workflow_id"], "sbx-id-1");
        assert_eq!(event["run_id"], "sbx-id-1");
        assert_eq!(event["activity_type"], "MCP delete_database");
        assert_eq!(event["activity_id"], "oshx-req-1");
        let span = &event["spans"][0];
        assert_eq!(span["hook_type"], "mcp");
        assert_eq!(span["stage"], "started");
        assert_eq!(span["http_url"], "https://mcp.example.com/mcp");
        assert_eq!(span["attributes"]["mcp.method"], "callTool");
        assert_eq!(span["attributes"]["mcp.operation"], "delete_database");
        assert_eq!(span["attributes"]["mcp.input"], r#"{"name":"prod"}"#);
        assert_eq!(span["span_id"].as_str().unwrap().len(), 16);
        assert_eq!(span["trace_id"].as_str().unwrap().len(), 32);
    }

    #[test]
    fn a_plain_request_becomes_an_http_hook_span_with_a_bounded_body() {
        let mut evaluation = evaluation("POST", "/v1/charge", b"0123456789");
        let target = evaluation.target.as_mut().unwrap();
        target.port = 8443;
        target.query = "dry_run=1".to_owned();
        let action = Action::from_evaluation(&evaluation);
        let event = action_event(&action, "oshx-req-1", 4, UNIX_EPOCH);
        let span = &event["spans"][0];
        assert_eq!(event["activity_type"], "POST mcp.example.com");
        assert_eq!(span["hook_type"], "http_request");
        assert_eq!(
            span["http_url"],
            "https://mcp.example.com:8443/v1/charge?dry_run=1"
        );
        assert_eq!(span["request_body"], "0123");
    }

    #[test]
    fn request_activity_ids_are_bounded_and_clean() {
        assert_eq!(request_activity_id("4751e07a-e1a0"), "oshx-4751e07a-e1a0");
        let id = request_activity_id(&format!("{}/../\n", "a".repeat(200)));
        assert!(id.len() <= 64);
        assert!(id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
    }

    #[test]
    fn a_response_completes_its_activity() {
        let completion = Completion {
            sandbox_id: "sbx-id-1".to_owned(),
            request_id: "req-1".to_owned(),
            activity_id: "oshx-req-1".to_owned(),
            activity_type: "GET example.com".to_owned(),
            method: "GET".to_owned(),
            url: "http://example.com/".to_owned(),
            status_code: 200,
            duration_ms: Some(12),
        };
        let event = completion_event(&completion, UNIX_EPOCH);
        assert_eq!(event["event_type"], "ActivityCompleted");
        assert_eq!(event["activity_id"], "oshx-req-1");
        assert_eq!(event["activity_type"], "GET example.com");
        assert_eq!(event["status"], "completed");
        assert_eq!(event["duration_ms"], 12.0);
        assert_eq!(event["activity_output"][0]["status_code"], 200);
        let failed = completion_event(
            &Completion {
                status_code: 502,
                duration_ms: None,
                ..completion
            },
            UNIX_EPOCH,
        );
        assert_eq!(failed["status"], "failed");
        assert!(failed.get("duration_ms").is_none());
    }

    #[test]
    fn signed_headers_follow_the_core_canonical_string() {
        use ring::signature::{ED25519, KeyPair as _, UnparsedPublicKey};
        let seed = [7_u8; 32];
        let signer = AgentSigner::new(
            "did:aip:00000000-0000-5000-8000-000000000000",
            &base64::engine::general_purpose::STANDARD.encode(seed),
        )
        .unwrap();
        let body = br#"{"a":1}"#;
        let headers = signer.headers(
            "post",
            EVALUATE_PATH,
            body,
            UNIX_EPOCH + Duration::from_secs(1_790_674_275),
        );
        let get = |name: &str| {
            headers
                .iter()
                .find(|(key, _)| *key == name)
                .unwrap()
                .1
                .clone()
        };
        assert_eq!(
            get("X-OpenBox-Agent-Timestamp"),
            "2026-09-29T09:31:15.000000+00:00"
        );
        assert_eq!(get("X-OpenBox-Body-SHA256"), hex(&Sha256::digest(body)));
        let canonical = [
            "POST",
            EVALUATE_PATH,
            &get("X-OpenBox-Agent-Timestamp"),
            &get("X-OpenBox-Agent-Nonce"),
            &get("X-OpenBox-Body-SHA256"),
        ]
        .join("\n");
        let signature = base64::engine::general_purpose::STANDARD
            .decode(get("X-OpenBox-Agent-Signature"))
            .unwrap();
        let public = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
        UnparsedPublicKey::new(&ED25519, public.public_key().as_ref())
            .verify(canonical.as_bytes(), &signature)
            .unwrap();
    }

    #[test]
    fn rejects_bad_signer_material() {
        assert!(AgentSigner::new("did:aip:x", "not-base64!").is_err());
        assert!(
            AgentSigner::new(
                "did:web:x",
                &base64::engine::general_purpose::STANDARD.encode([1_u8; 32])
            )
            .is_err()
        );
    }

    #[test]
    fn form_values_are_percent_encoded() {
        assert_eq!(
            form_encode(&[("a", "x y"), ("t", "urn:ietf:x"), ("j", "a.b-c_d")]),
            "a=x%20y&t=urn%3Aietf%3Ax&j=a.b-c_d"
        );
    }

    #[test]
    fn rejects_bad_workload_keys() {
        assert!(
            WorkloadIdentity::from_pem(
                "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----",
                "wk1"
            )
            .is_err()
        );
    }

    #[test]
    fn idempotency_keys_are_bounded_and_clean() {
        let key = idempotency_key(&format!("act- {}\n{}", "a".repeat(300), "\t"));
        assert!(key.len() <= 200);
        assert!(!key.chars().any(char::is_whitespace));
    }
}
