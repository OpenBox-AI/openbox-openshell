//! Fleet governance: `OpenBox` judges sandbox creation, policy changes and
//! agent-authored policy proposals as a whole fleet (OB-OSHELL-SPEC-002 W8,
//! R8.1 risk budgets and R8.2 proposal scoring).
//!
//! The front desk scores how much a policy opens up ([`policy_risk`]) and
//! sends Core the operation as an activity on the gateway's fleet session
//! (`openshell-fleet-<gateway id>`), with the score and the fleet's totals
//! before and after. Core judges it with the organisation's ordinary policy
//! rules, so a budget is a rule on those fields, for example
//! `activity_type == "openshell.create_sandbox"` and
//! `activity_input.fleet.risk_after > 60` gives BLOCK, and a proposal that
//! needs a person is `activity_type == "openshell.policy_proposal"` and
//! `activity_input.risk >= 5` giving `REQUIRE_APPROVAL`, which lands in the
//! `OpenBox` approval queue like any other.
//!
//! | Core says | The operation |
//! |-----------|---------------|
//! | allow, constrain | goes ahead |
//! | block, halt | is refused with Core's reason |
//! | require approval | is refused until someone approves it in `OpenBox`; the same operation asked again then goes ahead |
//!
//! An operation is identified by a hash of what was scored, so asking again
//! finds the same approval. Content never leaves the front desk: Core gets
//! the score, its factors, the sandbox and rule names, and the hosts.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Mutex;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::OnceCell;

use crate::core_client::{Activity, ApprovalState, CoreClient, CoreError, Verdict};
use crate::front_desk::{
    endpoints, field, is_tls_skip, network_policies, sends_uninspected_credentials,
};

/// How much a policy, or one proposed rule, opens up. Higher is wider.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Risk {
    pub score: u32,
    /// Factor → points, for the reason shown to people.
    pub factors: BTreeMap<&'static str, u32>,
    pub hosts: Vec<String>,
}

impl Risk {
    fn add(&mut self, factor: &'static str, points: u32) {
        self.score += points;
        *self.factors.entry(factor).or_default() += points;
    }
}

/// The points one endpoint adds:
///
/// | Factor | Points |
/// |--------|--------|
/// | `endpoint` (each one) | 1 |
/// | `wildcard_host` (`*.example.com`) | 3 |
/// | `any_host` (`*`, `**`) | 5 |
/// | `tls_skip` (not inspected) | 3 |
/// | `uninspected_credentials` | 5 |
/// | `full_access` / `read_write_access` preset | 2 / 1 |
/// | `many_ports` (more than 3, or any port) | 1 |
fn score_endpoint(endpoint: &Value, risk: &mut Risk) {
    risk.add("endpoint", 1);
    let host = endpoint.get("host").and_then(Value::as_str).unwrap_or("");
    if !host.is_empty() {
        risk.hosts.push(host.to_ascii_lowercase());
    }
    if host == "*" || host == "**" {
        risk.add("any_host", 5);
    } else if host.contains('*') {
        risk.add("wildcard_host", 3);
    }
    if is_tls_skip(endpoint) {
        risk.add("tls_skip", 3);
    }
    if sends_uninspected_credentials(endpoint) {
        risk.add("uninspected_credentials", 5);
    }
    match endpoint.get("access") {
        Some(Value::String(preset)) if preset.ends_with("FULL") || preset == "full" => {
            risk.add("full_access", 2);
        }
        Some(Value::Number(preset)) if preset.as_i64() == Some(3) => risk.add("full_access", 2),
        Some(Value::String(preset)) if preset.ends_with("READ_WRITE") || preset == "read-write" => {
            risk.add("read_write_access", 1);
        }
        Some(Value::Number(preset)) if preset.as_i64() == Some(2) => {
            risk.add("read_write_access", 1);
        }
        _ => {}
    }
    let ports = endpoint
        .get("ports")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let port = endpoint.get("port").and_then(Value::as_u64).unwrap_or(0);
    if ports > 3 || (ports == 0 && port == 0) {
        risk.add("many_ports", 1);
    }
}

/// Scores one network policy rule (a proposal's `proposed_rule`).
pub fn rule_risk(rule: &Value) -> Risk {
    let mut risk = Risk::default();
    for endpoint in endpoints(rule) {
        score_endpoint(endpoint, &mut risk);
    }
    risk.hosts.sort();
    risk.hosts.dedup();
    risk
}

/// Scores a sandbox policy: the sum over its network policy rules.
pub fn policy_risk(policy: &Value) -> Risk {
    let mut risk = Risk::default();
    for rule in network_policies(policy) {
        for endpoint in endpoints(rule) {
            score_endpoint(endpoint, &mut risk);
        }
    }
    risk.hosts.sort();
    risk.hosts.dedup();
    risk
}

/// One operation the fleet check judges.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Operation {
    CreateSandbox {
        sandbox: String,
        policy: Value,
    },
    UpdatePolicy {
        sandbox: String,
        policy: Value,
    },
    Proposal {
        sandbox: String,
        chunk_id: String,
        rule_name: String,
        rule: Value,
    },
}

impl Operation {
    fn kind(&self) -> &'static str {
        match self {
            Self::CreateSandbox { .. } => "openshell.create_sandbox",
            Self::UpdatePolicy { .. } => "openshell.policy_change",
            Self::Proposal { .. } => "openshell.policy_proposal",
        }
    }

    fn sandbox(&self) -> &str {
        match self {
            Self::CreateSandbox { sandbox, .. }
            | Self::UpdatePolicy { sandbox, .. }
            | Self::Proposal { sandbox, .. } => sandbox,
        }
    }

    fn risk(&self) -> Risk {
        match self {
            Self::CreateSandbox { policy, .. } | Self::UpdatePolicy { policy, .. } => {
                policy_risk(policy)
            }
            Self::Proposal { rule, .. } => rule_risk(rule),
        }
    }

    /// Stable for the same operation, so asking again finds its approval.
    fn activity_id(&self) -> String {
        let scored = match self {
            Self::CreateSandbox { policy, .. } | Self::UpdatePolicy { policy, .. } => policy,
            Self::Proposal { rule, .. } => rule,
        };
        let digest = Sha256::digest(format!("{}\n{}\n{scored}", self.kind(), self.sandbox()));
        let hex = digest.iter().take(12).fold(String::new(), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        });
        format!("ofl-{hex}")
    }
}

/// The fleet's sandboxes and the risk of each, kept from what the front desk
/// sees (creates, policy changes, deletes) and refreshed by the inventory
/// reconcile.
#[derive(Default)]
pub struct FleetState {
    sandboxes: Mutex<BTreeMap<String, u32>>,
}

impl FleetState {
    pub fn set(&self, sandbox: &str, risk: u32) {
        self.sandboxes
            .lock()
            .expect("fleet lock")
            .insert(sandbox.to_owned(), risk);
    }

    pub fn remove(&self, sandbox: &str) {
        self.sandboxes.lock().expect("fleet lock").remove(sandbox);
    }

    /// Replaces the whole view with what the gateway lists.
    pub fn replace(&self, sandboxes: BTreeMap<String, u32>) {
        *self.sandboxes.lock().expect("fleet lock") = sandboxes;
    }

    /// (sandboxes, total risk), leaving one sandbox out.
    fn totals_without(&self, sandbox: &str) -> (usize, u32) {
        let sandboxes = self.sandboxes.lock().expect("fleet lock");
        sandboxes
            .iter()
            .filter(|(name, _)| name.as_str() != sandbox)
            .fold((0, 0), |(count, risk), (_, each)| (count + 1, risk + each))
    }
}

/// Why an operation may not go ahead, for the gateway to show.
#[derive(Debug, PartialEq, Eq)]
pub struct FleetRefusal(pub String);

/// What the fleet check needs from Core; a trait so it can be tested.
#[tonic::async_trait]
pub trait FleetCore: Send + Sync + 'static {
    async fn start(&self, session: &str) -> Result<(), CoreError>;
    async fn approval(&self, session: &str, activity_id: &str) -> Result<ApprovalState, CoreError>;
    async fn judge(
        &self,
        session: &str,
        activity: &Activity,
    ) -> Result<(Verdict, Option<String>), CoreError>;
}

#[tonic::async_trait]
impl FleetCore for CoreClient {
    async fn start(&self, session: &str) -> Result<(), CoreError> {
        self.start_session(session, "openshell-fleet")
            .await
            .map(|_| ())
    }
    async fn approval(&self, session: &str, activity_id: &str) -> Result<ApprovalState, CoreError> {
        self.approval_state_for(session, activity_id).await
    }
    async fn judge(
        &self,
        session: &str,
        activity: &Activity,
    ) -> Result<(Verdict, Option<String>), CoreError> {
        self.open_activity(session, activity)
            .await
            .map(|decision| (decision.verdict, decision.reason))
    }
}

/// The fleet check.
pub struct FleetGovernance<C: ?Sized> {
    core: std::sync::Arc<C>,
    session: String,
    started: OnceCell<()>,
    pub state: FleetState,
}

impl<C: FleetCore + ?Sized> FleetGovernance<C> {
    pub fn new(core: std::sync::Arc<C>, gateway_id: &str) -> Self {
        Self {
            core,
            session: format!("openshell-fleet-{gateway_id}"),
            started: OnceCell::new(),
            state: FleetState::default(),
        }
    }

    /// Asks `OpenBox` whether an operation may go ahead. Core unreachable or
    /// failing is a refusal: the front desk fails closed.
    pub async fn check(&self, operation: &Operation) -> Result<u32, FleetRefusal> {
        let unavailable = |error: CoreError| {
            FleetRefusal(format!(
                "OpenBox could not check this change ({error:?}); try again"
            ))
        };
        self.started
            .get_or_try_init(|| async { self.core.start(&self.session).await })
            .await
            .map_err(unavailable)?;
        let risk = operation.risk();
        let activity_id = operation.activity_id();
        match self.core.approval(&self.session, &activity_id).await {
            Ok(ApprovalState::Approved(_)) => return Ok(risk.score),
            Ok(ApprovalState::Pending { .. }) => {
                return Err(FleetRefusal(format!(
                    "waiting for approval in OpenBox ({}, risk {}); ask again once it is approved",
                    operation.kind(),
                    risk.score
                )));
            }
            Ok(ApprovalState::Rejected(_)) => {
                return Err(FleetRefusal(format!(
                    "refused in OpenBox ({}, risk {})",
                    operation.kind(),
                    risk.score
                )));
            }
            // Core has not seen it, or the approval lapsed: judge it now.
            Ok(ApprovalState::Gone) => {}
            Err(error) => return Err(unavailable(error)),
        }
        let (count, total) = self.state.totals_without(operation.sandbox());
        let mut input = json!({
            "operation": operation.kind(),
            "sandbox": operation.sandbox(),
            "risk": risk.score,
            "factors": risk.factors,
            "hosts": risk.hosts,
            "fleet": {
                "sandboxes": count,
                "risk": total,
                "sandboxes_after": count + 1,
                "risk_after": total + risk.score,
            },
        });
        if let Operation::Proposal {
            chunk_id,
            rule_name,
            ..
        } = operation
        {
            input["chunk_id"] = json!(chunk_id);
            input["rule_name"] = json!(rule_name);
        }
        let activity = Activity {
            id: activity_id,
            kind: operation.kind().to_owned(),
            input: json!([input]),
            profile: None,
        };
        let (verdict, reason) = self
            .core
            .judge(&self.session, &activity)
            .await
            .map_err(unavailable)?;
        let because = reason.map_or_else(String::new, |reason| format!(": {reason}"));
        match verdict {
            Verdict::Allow | Verdict::Constrain => Ok(risk.score),
            Verdict::RequireApproval => Err(FleetRefusal(format!(
                "needs approval in OpenBox ({}, risk {}){because}; ask again once it is approved",
                operation.kind(),
                risk.score
            ))),
            Verdict::Block | Verdict::Halt => Err(FleetRefusal(format!(
                "refused by OpenBox governance ({}, risk {}){because}",
                operation.kind(),
                risk.score
            ))),
        }
    }
}

/// The fleet operation in a `CreateSandbox` request.
pub fn create_sandbox_operation(operation: &Value) -> Operation {
    let sandbox = operation
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
        .or_else(|| operation.pointer("/metadata/name").and_then(Value::as_str))
        .unwrap_or("")
        .to_owned();
    Operation::CreateSandbox {
        sandbox,
        policy: operation
            .pointer("/spec/policy")
            .cloned()
            .unwrap_or(Value::Null),
    }
}

/// The fleet operation in an `UpdateConfig` request, when it changes network
/// access: a new policy, or rules added by merge. A global update is judged
/// as the sandbox `*`.
pub fn update_config_operation(operation: &Value) -> Option<Operation> {
    let sandbox = operation
        .get("sandbox")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
        .unwrap_or("*")
        .to_owned();
    if let Some(policy) = operation.get("policy").filter(|policy| !policy.is_null()) {
        return Some(Operation::UpdatePolicy {
            sandbox,
            policy: policy.clone(),
        });
    }
    let added: serde_json::Map<String, Value> =
        field(operation, "mergeOperations", "merge_operations")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|merge| field(merge, "addRule", "add_rule"))
            .enumerate()
            .filter_map(|(index, add)| Some((format!("added-{index}"), add.get("rule")?.clone())))
            .collect();
    (!added.is_empty()).then(|| Operation::UpdatePolicy {
        sandbox,
        policy: json!({ "network_policies": added }),
    })
}

/// Reads an agent's pending policy proposals from the gateway.
#[tonic::async_trait]
pub trait DraftReader: Send + Sync + 'static {
    /// The sandbox's pending chunks, as `PolicyChunk` JSON (snake case).
    async fn pending_chunks(&self, sandbox: &str) -> Result<Vec<Value>, String>;
}

/// The proposal operations an approval would apply: one chunk, or every
/// pending chunk (`chunk_ids` empty), leaving out chunks with security notes
/// unless `include_flagged`.
pub fn proposal_operations(
    sandbox: &str,
    chunks: &[Value],
    chunk_ids: &[String],
    include_flagged: bool,
) -> Vec<Operation> {
    chunks
        .iter()
        .filter(|chunk| {
            let id = chunk.get("id").and_then(Value::as_str).unwrap_or("");
            if chunk_ids.is_empty() {
                include_flagged
                    || chunk
                        .get("security_notes")
                        .and_then(Value::as_str)
                        .is_none_or(str::is_empty)
            } else {
                chunk_ids.iter().any(|wanted| wanted == id)
            }
        })
        .map(|chunk| Operation::Proposal {
            sandbox: sandbox.to_owned(),
            chunk_id: chunk
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned(),
            rule_name: chunk
                .get("rule_name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned(),
            rule: chunk.get("proposed_rule").cloned().unwrap_or(Value::Null),
        })
        .collect()
}

/// The fields [`policy_risk`] reads, from a listed sandbox's policy.
fn proto_policy_json(policy: &openshell_core::proto::SandboxPolicy) -> Value {
    let rules: serde_json::Map<String, Value> = policy
        .network_policies
        .iter()
        .map(|(name, rule)| (name.clone(), proto_rule_json(rule)))
        .collect();
    json!({ "network_policies": rules })
}

/// The fields [`rule_risk`] reads, from a proto network policy rule.
pub fn proto_rule_json(rule: &openshell_core::proto::NetworkPolicyRule) -> Value {
    let endpoints: Vec<Value> = rule
        .endpoints
        .iter()
        .map(|endpoint| {
            json!({
                "host": endpoint.host,
                "port": endpoint.port,
                "ports": endpoint.ports,
                "tls": endpoint.tls,
                "access": endpoint.access,
                "allow_uninspected_credentials": endpoint.allow_uninspected_credentials,
            })
        })
        .collect();
    json!({ "name": rule.name, "endpoints": endpoints })
}

/// Each listed sandbox's risk, by name, from its policy.
pub fn sandbox_risks(sandboxes: &[openshell_core::proto::Sandbox]) -> BTreeMap<String, u32> {
    sandboxes
        .iter()
        .filter_map(|sandbox| {
            let name = sandbox.metadata.as_ref()?.name.clone();
            let policy = sandbox.spec.as_ref()?.policy.as_ref()?;
            Some((name, policy_risk(&proto_policy_json(policy)).score))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn policy_risk_adds_up_what_a_policy_opens() {
        let policy = json!({"network_policies": {
            "api": {"endpoints": [
                {"host": "api.example.com", "port": 443},
                {"host": "*.example.com", "port": 443, "tls": "NETWORK_TLS_MODE_SKIP"},
            ]},
            "any": {"endpoints": [
                {"host": "**", "ports": [1, 2, 3, 4], "allowUninspectedCredentials": true, "access": "NETWORK_ACCESS_PRESET_FULL"},
            ]},
        }});
        let risk = policy_risk(&policy);
        // 3 endpoints + wildcard 3 + tls skip 3 + any host 5 + credentials 5 + full 2 + ports 1
        assert_eq!(risk.score, 22);
        assert_eq!(risk.factors["any_host"], 5);
        assert_eq!(risk.hosts, ["**", "*.example.com", "api.example.com"]);
        assert_eq!(policy_risk(&json!({})).score, 0);
        // proto JSON (numbers for enums) scores the same
        let numeric = json!({"network_policies": {"a": {"endpoints": [{"host": "x", "port": 443, "tls": 1, "access": 2}]}}});
        assert_eq!(policy_risk(&numeric).score, 1 + 3 + 1);
    }

    #[derive(Default)]
    struct FakeCore {
        approval: Mutex<Option<ApprovalState>>,
        verdict: Mutex<Option<Verdict>>,
        judged: Mutex<Vec<Activity>>,
        down: bool,
    }

    #[tonic::async_trait]
    impl FleetCore for FakeCore {
        async fn start(&self, _: &str) -> Result<(), CoreError> {
            if self.down {
                Err(CoreError::Transport)
            } else {
                Ok(())
            }
        }
        async fn approval(&self, _: &str, _: &str) -> Result<ApprovalState, CoreError> {
            Ok(self
                .approval
                .lock()
                .unwrap()
                .clone()
                .unwrap_or(ApprovalState::Gone))
        }
        async fn judge(
            &self,
            _: &str,
            activity: &Activity,
        ) -> Result<(Verdict, Option<String>), CoreError> {
            self.judged.lock().unwrap().push(activity.clone());
            Ok((
                self.verdict.lock().unwrap().unwrap_or(Verdict::Allow),
                Some("budget".to_owned()),
            ))
        }
    }

    fn create(name: &str, host: &str) -> Operation {
        Operation::CreateSandbox {
            sandbox: name.to_owned(),
            policy: json!({"network_policies": {"a": {"endpoints": [{"host": host, "port": 443}]}}}),
        }
    }

    #[tokio::test]
    async fn the_check_sends_the_score_and_the_fleet_and_follows_core() {
        let core = Arc::new(FakeCore::default());
        let fleet = FleetGovernance::new(Arc::clone(&core), "gw-1");
        fleet.state.set("old-1", 4);
        fleet.state.set("old-2", 6);
        assert_eq!(fleet.check(&create("new", "*.example.com")).await, Ok(4));
        let judged = core.judged.lock().unwrap().pop().unwrap();
        assert_eq!(judged.kind, "openshell.create_sandbox");
        assert_eq!(
            judged.input[0]["fleet"],
            json!({"sandboxes": 2, "risk": 10, "sandboxes_after": 3, "risk_after": 14})
        );
        assert_eq!(judged.input[0]["risk"], 4);

        *core.verdict.lock().unwrap() = Some(Verdict::Block);
        let refused = fleet
            .check(&create("new", "a.example.com"))
            .await
            .unwrap_err();
        assert!(
            refused.0.contains("refused by OpenBox governance") && refused.0.contains("budget"),
            "{}",
            refused.0
        );

        *core.verdict.lock().unwrap() = Some(Verdict::RequireApproval);
        assert!(
            fleet
                .check(&create("new", "b.example.com"))
                .await
                .unwrap_err()
                .0
                .contains("needs approval")
        );
        *core.approval.lock().unwrap() = Some(ApprovalState::Approved(
            crate::core_client::ApprovalScope::default(),
        ));
        assert_eq!(
            fleet.check(&create("new", "b.example.com")).await,
            Ok(1),
            "approved: goes ahead without asking again"
        );
    }

    #[test]
    fn operations_are_read_from_gateway_requests() {
        let create = create_sandbox_operation(
            &json!({"name": "box", "spec": {"policy": {"network_policies": {}}}}),
        );
        assert_eq!(create.sandbox(), "box");
        let update = update_config_operation(&json!({"sandbox": "box", "mergeOperations": [
            {"addRule": {"rule": {"endpoints": [{"host": "*.x.test", "port": 443}]}}},
            {"removeRule": {"name": "old"}},
        ]}))
        .unwrap();
        assert_eq!(update.risk().score, 4);
        assert!(update_config_operation(&json!({"sandbox": "box", "settingKey": "k"})).is_none());
        let global =
            update_config_operation(&json!({"global": true, "policy": {"network_policies": {}}}))
                .unwrap();
        assert_eq!(global.sandbox(), "*");

        let chunks = [
            json!({"id": "c1", "rule_name": "r1", "proposed_rule": {"endpoints": [{"host": "a.test", "port": 443}]}}),
            json!({"id": "c2", "rule_name": "r2", "security_notes": "wildcard", "proposed_rule": {"endpoints": [{"host": "*", "port": 0}]}}),
        ];
        assert_eq!(
            proposal_operations("box", &chunks, &["c2".to_owned()], false).len(),
            1
        );
        assert_eq!(
            proposal_operations("box", &chunks, &[], false).len(),
            1,
            "flagged chunks need include_flagged"
        );
        let all = proposal_operations("box", &chunks, &[], true);
        assert_eq!(all.len(), 2);
        assert_eq!(all[1].risk().score, 1 + 5 + 1);
    }

    #[tokio::test]
    async fn the_same_operation_has_the_same_id_and_core_down_refuses() {
        assert_eq!(
            create("s", "x").activity_id(),
            create("s", "x").activity_id()
        );
        assert_ne!(
            create("s", "x").activity_id(),
            create("s", "y").activity_id()
        );
        let fleet = FleetGovernance::new(
            Arc::new(FakeCore {
                down: true,
                ..FakeCore::default()
            }),
            "gw",
        );
        assert!(
            fleet
                .check(&create("s", "x"))
                .await
                .unwrap_err()
                .0
                .contains("could not check")
        );
    }
}
