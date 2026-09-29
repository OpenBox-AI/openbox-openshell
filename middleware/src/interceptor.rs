//! The front desk's `openshell.gateway_interceptor.v1.GatewayInterceptor`
//! gRPC service.
//!
//! Policy rules live in [`crate::front_desk`]; this module handles the
//! protocol, authentication and the inventory hooks.
//!
//! Stamping and checking (`modify_operation`, `validate`) fail closed.
//! Inventory updates run in `post_commit`, which `OpenShell` requires to be
//! `fail_open` because the operation has already happened; a missed update is
//! caught by periodic reconciliation, not by blocking the fleet.
//!
//! `OpenShell` allows one binding per RPC in a manifest and a binding's
//! phases share one failure policy, so the two concerns are served as two
//! registrations with their own manifests: [`Role::Govern`] and
//! [`Role::Inventory`].

use std::collections::HashMap;
use std::sync::Arc;

use openshell_core::extension_protocol::{
    ExtensionFamily, extension_metadata, validate_gateway_metadata,
};
use openshell_core::proto::gateway_interceptor::v1::gateway_interceptor_server::GatewayInterceptor;
use openshell_core::proto::gateway_interceptor::v1::{
    DescribeRequest, GatewayInterceptorPhase, InterceptorBinding, InterceptorEvaluation,
    InterceptorManifest, InterceptorResult, InterceptorSelector, JsonPatch,
    ProviderProfileSnapshot, ProviderProfileSnapshotRequest, interceptor_evaluation,
};
use prost_types::value::Kind;
use prost_types::{ListValue, Struct};
use serde_json::Value;
use tonic::{Request, Response, Status};

use crate::core_client::unix_now;
use crate::front_desk::{self, Refusal};
use crate::token::{Caller, TokenVerifier};

pub const MANIFEST_NAME: &str = "openbox/governance-interceptor";
const SERVICE: &str = "openshell.v1.OpenShell";

/// What happened to a sandbox, for the AI Inventory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InventoryEvent {
    Created { sandbox: Value },
    PolicyChanged { request: Value },
    Deleted { response: Value },
}

/// Where the front desk records sandboxes. Best effort by design: it runs
/// after the gateway has committed the change.
#[tonic::async_trait]
pub trait Inventory: Send + Sync + 'static {
    async fn record(&self, event: InventoryEvent) -> Result<(), String>;
}

/// Records inventory events in the service log only.
pub struct LogInventory;

#[tonic::async_trait]
impl Inventory for LogInventory {
    async fn record(&self, event: InventoryEvent) -> Result<(), String> {
        match &event {
            InventoryEvent::Created { sandbox } => eprintln!(
                "openbox: inventory created sandbox={} id={}",
                sandbox_name(sandbox),
                sandbox
                    .pointer("/sandbox/metadata/id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
            ),
            // UpdateConfigResponse carries the new revision, not the sandbox.
            InventoryEvent::PolicyChanged { request } => eprintln!(
                "openbox: inventory policy_changed version={} policy_hash={}",
                request
                    .get("version")
                    .map_or_else(String::new, ToString::to_string),
                request
                    .get("policyHash")
                    .and_then(Value::as_str)
                    .unwrap_or("")
            ),
            InventoryEvent::Deleted { response } => eprintln!(
                "openbox: inventory deleted id={}",
                response
                    .get("sandboxId")
                    .and_then(Value::as_str)
                    .unwrap_or("")
            ),
        }
        Ok(())
    }
}

fn sandbox_name(sandbox: &Value) -> String {
    sandbox
        .pointer("/sandbox/metadata/name")
        .or_else(|| sandbox.pointer("/metadata/name"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned()
}

/// Which registration a listener serves.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    /// `modify_operation` and `validate`, fail closed.
    Govern,
    /// `post_commit` inventory updates, fail open.
    Inventory,
}

pub struct FrontDesk<I: ?Sized> {
    role: Role,
    verifier: Option<TokenVerifier>,
    inventory: Arc<I>,
}

impl<I: Inventory + ?Sized> FrontDesk<I> {
    pub fn new(role: Role, verifier: Option<TokenVerifier>, inventory: Arc<I>) -> Self {
        Self {
            role,
            verifier,
            inventory,
        }
    }

    fn authenticate<T>(&self, request: &Request<T>) -> Result<(), Status> {
        let Some(verifier) = &self.verifier else {
            return Ok(());
        };
        let token = request
            .metadata()
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .ok_or_else(|| Status::unauthenticated("missing extension token"))?;
        match verifier.verify(token, unix_now()) {
            Ok(Caller::Gateway) => Ok(()),
            Ok(Caller::Supervisor { .. }) => Err(Status::permission_denied(
                "interceptor calls must come from the gateway",
            )),
            Err(error) => Err(Status::unauthenticated(error.to_string())),
        }
    }
}

fn binding(
    id: &str,
    method: &str,
    phases: &[GatewayInterceptorPhase],
    failure: &str,
) -> InterceptorBinding {
    InterceptorBinding {
        id: id.to_owned(),
        selector: Some(InterceptorSelector {
            rpc: format!("{SERVICE}/{method}"),
            ..InterceptorSelector::default()
        }),
        phases: phases.iter().map(|phase| *phase as i32).collect(),
        failure_policy: failure.to_owned(),
    }
}

fn allow() -> InterceptorResult {
    InterceptorResult {
        allowed: true,
        ..InterceptorResult::default()
    }
}

fn refuse(refusal: &Refusal) -> InterceptorResult {
    InterceptorResult {
        allowed: false,
        reason: refusal.0.clone(),
        status_code: "PERMISSION_DENIED".to_owned(),
        log_annotations: HashMap::from([("openbox.decision".to_owned(), "denied".to_owned())]),
        ..InterceptorResult::default()
    }
}

#[tonic::async_trait]
impl<I: Inventory + ?Sized> GatewayInterceptor for FrontDesk<I> {
    async fn describe(
        &self,
        request: Request<DescribeRequest>,
    ) -> Result<Response<InterceptorManifest>, Status> {
        use GatewayInterceptorPhase::{ModifyOperation, PostCommit, Validate};
        self.authenticate(&request)?;
        let manifest = InterceptorManifest {
            name: MANIFEST_NAME.to_owned(),
            bindings: match self.role {
                Role::Govern => vec![
                    binding(
                        "create-sandbox",
                        "CreateSandbox",
                        &[ModifyOperation, Validate],
                        "fail_closed",
                    ),
                    binding("update-config", "UpdateConfig", &[Validate], "fail_closed"),
                ],
                Role::Inventory => vec![
                    binding(
                        "create-sandbox",
                        "CreateSandbox",
                        &[PostCommit],
                        "fail_open",
                    ),
                    binding("update-config", "UpdateConfig", &[PostCommit], "fail_open"),
                    binding(
                        "delete-sandbox",
                        "DeleteSandbox",
                        &[PostCommit],
                        "fail_open",
                    ),
                ],
            },
            failure_policy: match self.role {
                Role::Govern => "fail_closed",
                Role::Inventory => "fail_open",
            }
            .to_owned(),
            provider_profiles: false,
            expected_audience: self
                .verifier
                .as_ref()
                .map_or_else(String::new, |verifier| verifier.audience().to_owned()),
            extension: Some(extension_metadata(
                ExtensionFamily::GatewayInterceptor,
                MANIFEST_NAME,
                env!("CARGO_PKG_VERSION"),
                [],
            )),
        };
        validate_gateway_metadata(
            ExtensionFamily::GatewayInterceptor,
            MANIFEST_NAME,
            manifest.extension.as_ref(),
            request.into_inner().gateway,
        )
        .map_err(|error| Status::failed_precondition(error.to_string()))?;
        Ok(Response::new(manifest))
    }

    async fn snapshot_provider_profiles(
        &self,
        _: Request<ProviderProfileSnapshotRequest>,
    ) -> Result<Response<ProviderProfileSnapshot>, Status> {
        Err(Status::unimplemented(
            "OpenBox does not vend provider profiles",
        ))
    }

    async fn evaluate(
        &self,
        request: Request<InterceptorEvaluation>,
    ) -> Result<Response<InterceptorResult>, Status> {
        self.authenticate(&request)?;
        let evaluation = request.into_inner();
        if evaluation.service != SERVICE {
            return Ok(Response::new(allow()));
        }
        let result = match (evaluation.method.as_str(), evaluation.phase) {
            ("CreateSandbox", Some(interceptor_evaluation::Phase::ModifyOperation(phase))) => {
                let operation = struct_to_json(phase.proposed_operation.as_ref());
                match front_desk::modify_create_sandbox(&operation) {
                    Ok(patches) => {
                        let mut result = allow();
                        let excluded = operation
                            .pointer("/spec/policy")
                            .map(front_desk::uninspectable_hosts)
                            .unwrap_or_default();
                        if !excluded.is_empty() {
                            result
                                .log_annotations
                                .insert("openbox.uninspected_hosts".to_owned(), excluded.join(","));
                        }
                        result.patches = patches
                            .into_iter()
                            .map(|patch| JsonPatch {
                                op: patch.op.to_owned(),
                                path: patch.path,
                                value: Some(json_to_value(&patch.value)),
                                from: String::new(),
                            })
                            .collect();
                        result
                    }
                    Err(refusal) => refuse(&refusal),
                }
            }
            ("CreateSandbox", Some(interceptor_evaluation::Phase::Validate(phase))) => {
                let operation = struct_to_json(phase.proposed_operation.as_ref());
                front_desk::validate_create_sandbox(&operation)
                    .map_or_else(|refusal| refuse(&refusal), |()| allow())
            }
            ("UpdateConfig", Some(interceptor_evaluation::Phase::Validate(phase))) => {
                let operation = struct_to_json(phase.proposed_operation.as_ref());
                front_desk::validate_update_config(&operation)
                    .map_or_else(|refusal| refuse(&refusal), |()| allow())
            }
            (method, Some(interceptor_evaluation::Phase::PostCommit(phase))) => {
                let committed = struct_to_json(phase.committed_response.as_ref());
                let event = match method {
                    "CreateSandbox" => Some(InventoryEvent::Created { sandbox: committed }),
                    "UpdateConfig" => Some(InventoryEvent::PolicyChanged { request: committed }),
                    "DeleteSandbox" => Some(InventoryEvent::Deleted {
                        response: committed,
                    }),
                    _ => None,
                };
                if let Some(event) = event
                    && let Err(error) = self.inventory.record(event).await
                {
                    eprintln!("openbox: inventory update failed ({method}): {error}");
                }
                allow()
            }
            _ => allow(),
        };
        eprintln!(
            "openbox: intercept {} allowed={} patches={} reason={}",
            evaluation.method,
            result.allowed,
            result.patches.len(),
            if result.reason.is_empty() {
                "-"
            } else {
                &result.reason
            }
        );
        Ok(Response::new(result))
    }
}

pub fn struct_to_json(value: Option<&Struct>) -> Value {
    value.map_or(Value::Null, |value| {
        Value::Object(
            value
                .fields
                .iter()
                .map(|(key, value)| (key.clone(), value_to_json(value)))
                .collect(),
        )
    })
}

fn value_to_json(value: &prost_types::Value) -> Value {
    match &value.kind {
        None | Some(Kind::NullValue(_)) => Value::Null,
        Some(Kind::BoolValue(flag)) => Value::Bool(*flag),
        Some(Kind::NumberValue(number)) => {
            // ProtoJSON numbers arrive as doubles; keep integers integral.
            #[allow(clippy::cast_possible_truncation, clippy::float_cmp)]
            if number.fract() == 0.0 && number.abs() < 9.0e15 {
                Value::from(*number as i64)
            } else {
                serde_json::Number::from_f64(*number).map_or(Value::Null, Value::Number)
            }
        }
        Some(Kind::StringValue(text)) => Value::String(text.clone()),
        Some(Kind::StructValue(inner)) => struct_to_json(Some(inner)),
        Some(Kind::ListValue(list)) => {
            Value::Array(list.values.iter().map(value_to_json).collect())
        }
    }
}

pub fn json_to_value(value: &Value) -> prost_types::Value {
    let kind = match value {
        Value::Null => Kind::NullValue(0),
        Value::Bool(flag) => Kind::BoolValue(*flag),
        #[allow(clippy::cast_precision_loss)]
        Value::Number(number) => Kind::NumberValue(number.as_f64().unwrap_or_default()),
        Value::String(text) => Kind::StringValue(text.clone()),
        Value::Array(items) => Kind::ListValue(ListValue {
            values: items.iter().map(json_to_value).collect(),
        }),
        Value::Object(object) => Kind::StructValue(Struct {
            fields: object
                .iter()
                .map(|(key, value)| (key.clone(), json_to_value(value)))
                .collect(),
        }),
    };
    prost_types::Value { kind: Some(kind) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::tests::TestSigner;
    use openshell_core::proto::gateway_interceptor::v1::{
        ModifyOperationEvaluation, PostCommitEvaluation, ValidateEvaluation,
    };
    use serde_json::json;
    use std::sync::Mutex;

    const AUDIENCE: &str = "urn:openshell:extension:interceptor:openbox";

    #[derive(Default)]
    struct RecordingInventory(Mutex<Vec<InventoryEvent>>);

    #[tonic::async_trait]
    impl Inventory for RecordingInventory {
        async fn record(&self, event: InventoryEvent) -> Result<(), String> {
            self.0.lock().unwrap().push(event);
            Err("inventory is down".to_owned())
        }
    }

    fn gateway_token(signer: &TestSigner) -> String {
        signer.sign(
            &json!({"typ": "openshell-ext+jwt", "alg": "EdDSA"}),
            &json!({"iss": "openshell-gateway:gw-1", "aud": AUDIENCE, "exp": unix_now() + 60, "caller_kind": "gateway"}),
        )
    }

    fn service_as(
        role: Role,
        signer: &TestSigner,
    ) -> (FrontDesk<RecordingInventory>, Arc<RecordingInventory>) {
        let inventory = Arc::new(RecordingInventory::default());
        let verifier = TokenVerifier::from_pem(&signer.public_pem(), "gw-1", AUDIENCE).unwrap();
        (
            FrontDesk::new(role, Some(verifier), Arc::clone(&inventory)),
            inventory,
        )
    }

    fn service(signer: &TestSigner) -> (FrontDesk<RecordingInventory>, Arc<RecordingInventory>) {
        service_as(Role::Govern, signer)
    }

    fn authed<T>(message: T, token: &str) -> Request<T> {
        let mut request = Request::new(message);
        request
            .metadata_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
        request
    }

    fn operation() -> Value {
        json!({"name": "sbx", "spec": {"policy": {"version": 1, "networkPolicies": {"api": {
            "endpoints": [{"host": "api.example.com", "port": 443}]
        }}}}})
    }

    fn to_struct(value: &Value) -> Struct {
        match json_to_value(value).kind {
            Some(Kind::StructValue(inner)) => inner,
            _ => unreachable!(),
        }
    }

    #[test]
    fn json_round_trips_through_protobuf_struct() {
        let value = json!({"a": 1, "b": [true, null, "x", 1.5], "c": {"d": "e"}});
        assert_eq!(struct_to_json(Some(&to_struct(&value))), value);
    }

    #[tokio::test]
    async fn each_role_declares_one_binding_per_rpc_with_the_right_failure_policy() {
        let signer = TestSigner::new();
        for role in [Role::Govern, Role::Inventory] {
            let (service, _) = service_as(role, &signer);
            let gateway = extension_metadata(
                ExtensionFamily::GatewayInterceptor,
                "openshell/gateway",
                "0.1.2",
                [],
            );
            let manifest = service
                .describe(authed(
                    DescribeRequest {
                        gateway: Some(gateway),
                    },
                    &gateway_token(&signer),
                ))
                .await
                .unwrap()
                .into_inner();
            assert_eq!(manifest.expected_audience, AUDIENCE);
            let mut rpcs: Vec<_> = manifest
                .bindings
                .iter()
                .map(|binding| binding.selector.as_ref().unwrap().rpc.clone())
                .collect();
            let count = rpcs.len();
            rpcs.dedup();
            assert_eq!(rpcs.len(), count, "one binding per RPC");
            for binding in &manifest.bindings {
                let post_commit = binding
                    .phases
                    .contains(&(GatewayInterceptorPhase::PostCommit as i32));
                assert_eq!(post_commit, role == Role::Inventory, "{}", binding.id);
                assert_eq!(
                    binding.failure_policy == "fail_open",
                    post_commit,
                    "{}",
                    binding.id
                );
            }
        }
    }

    #[tokio::test]
    async fn modify_returns_patches_and_validate_refuses_a_weakened_policy() {
        let signer = TestSigner::new();
        let (service, _) = service(&signer);
        let token = gateway_token(&signer);
        let modify = service
            .evaluate(authed(
                InterceptorEvaluation {
                    service: SERVICE.to_owned(),
                    method: "CreateSandbox".to_owned(),
                    phase: Some(interceptor_evaluation::Phase::ModifyOperation(
                        ModifyOperationEvaluation {
                            proposed_operation: Some(to_struct(&operation())),
                        },
                    )),
                    ..InterceptorEvaluation::default()
                },
                &token,
            ))
            .await
            .unwrap()
            .into_inner();
        assert!(modify.allowed);
        assert!(
            modify
                .patches
                .iter()
                .any(|patch| patch.path == "/spec/policy/networkMiddlewares")
        );

        let validate = service
            .evaluate(authed(
                InterceptorEvaluation {
                    service: SERVICE.to_owned(),
                    method: "UpdateConfig".to_owned(),
                    phase: Some(interceptor_evaluation::Phase::Validate(
                        ValidateEvaluation {
                            proposed_operation: Some(to_struct(
                                &json!({"sandbox": "sbx", "policy": operation()["spec"]["policy"]}),
                            )),
                            current_state: None,
                        },
                    )),
                    ..InterceptorEvaluation::default()
                },
                &token,
            ))
            .await
            .unwrap()
            .into_inner();
        assert!(!validate.allowed);
        assert_eq!(validate.status_code, "PERMISSION_DENIED");
    }

    #[tokio::test]
    async fn post_commit_always_allows_even_when_the_inventory_fails() {
        let signer = TestSigner::new();
        let (service, inventory) = service(&signer);
        let result = service
            .evaluate(authed(
                InterceptorEvaluation {
                    service: SERVICE.to_owned(),
                    method: "DeleteSandbox".to_owned(),
                    phase: Some(interceptor_evaluation::Phase::PostCommit(
                        PostCommitEvaluation {
                            committed_response: Some(to_struct(&json!({"sandboxId": "id-1"}))),
                        },
                    )),
                    ..InterceptorEvaluation::default()
                },
                &gateway_token(&signer),
            ))
            .await
            .unwrap()
            .into_inner();
        assert!(result.allowed);
        assert_eq!(inventory.0.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn supervisor_tokens_and_missing_tokens_are_refused() {
        let signer = TestSigner::new();
        let (service, _) = service(&signer);
        let request = InterceptorEvaluation::default();
        assert_eq!(
            service
                .evaluate(Request::new(request.clone()))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Unauthenticated
        );
        let supervisor = signer.sign(
            &json!({"typ": "openshell-ext+jwt", "alg": "EdDSA"}),
            &json!({"iss": "openshell-gateway:gw-1", "aud": AUDIENCE, "exp": unix_now() + 60, "caller_kind": "supervisor", "sandbox_id": "s"}),
        );
        assert_eq!(
            service
                .evaluate(authed(request, &supervisor))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
    }
}
