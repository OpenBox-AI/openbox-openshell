//! The `openshell.middleware.v1.SupervisorMiddleware` gRPC service.
//!
//! Every call is authenticated with `OpenShell`'s extension token unless the
//! operator explicitly runs without authentication (local development only).
//! A supervisor may only evaluate traffic for the sandbox its token names, so
//! one sandbox cannot spend another's approvals or trip another's halt.
//!
//! The same service also answers `HttpResponsePreReturn`: it never inspects
//! or changes a response (skip), it only closes the request's Core activity.

use std::sync::Arc;
use std::time::Duration;

use openshell_core::extension_protocol::{
    ExtensionFamily, extension_metadata, validate_gateway_metadata,
};
use openshell_core::middleware::{HttpResponseResultStream, WebSocketResponseStream};
use openshell_core::proto::middleware::v1::http_response_pre_return_server::HttpResponsePreReturn;
use openshell_core::proto::middleware::v1::supervisor_middleware_server::SupervisorMiddleware;
use openshell_core::proto::{
    Finding, HttpRequestEvaluation, HttpRequestResult, HttpResponseEvent, HttpResponseEventResult,
    HttpResponsePreflight, HttpResponsePreflightResult, HttpResponsePreflightSkip,
    MiddlewareBinding, MiddlewareDescribeRequest, MiddlewareManifest,
    SupervisorMiddlewareOperation, SupervisorMiddlewarePhase, ValidateConfigRequest,
    ValidateConfigResponse, WebSocketPreflightAction, WebSocketPreflightDecision,
    WebSocketSessionEvent, WebSocketSessionEventResult, http_response_event,
    http_response_event_result, http_response_preflight_result, web_socket_session_event,
    web_socket_session_event_result,
};
use prost_types::Struct;
use prost_types::value::Kind;
use tokio_stream::StreamExt as _;
use tonic::{Request, Response, Status};

use crate::action::Action;
use crate::core_client::{target_url, unix_now};
use crate::guard::{ApprovalMode, Governance, Guard, ResponseSeen, SandboxStopper};
use crate::token::{Caller, TokenVerifier};

pub const MANIFEST_NAME: &str = "openbox/verdict-middleware";

pub struct VerdictMiddleware<G, S: ?Sized> {
    guard: Arc<Guard<G, S>>,
    verifier: Option<TokenVerifier>,
    max_payload_bytes: u64,
    request_timeout: Option<Duration>,
}

impl<G: Governance, S: SandboxStopper + ?Sized> VerdictMiddleware<G, S> {
    /// `verifier` is `None` only when the operator chose to run without
    /// authentication.
    pub fn new(
        guard: Arc<Guard<G, S>>,
        verifier: Option<TokenVerifier>,
        max_payload_bytes: u64,
        request_timeout: Option<Duration>,
    ) -> Self {
        Self {
            guard,
            verifier,
            max_payload_bytes,
            request_timeout,
        }
    }

    fn caller<T>(&self, request: &Request<T>) -> Result<Option<Caller>, Status> {
        let Some(verifier) = &self.verifier else {
            return Ok(None);
        };
        let token = request
            .metadata()
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .ok_or_else(|| Status::unauthenticated("missing extension token"))?;
        verifier
            .verify(token, unix_now())
            .map(Some)
            .map_err(|error| Status::unauthenticated(error.to_string()))
    }

    /// A supervisor token may only act for the sandbox it names.
    fn check_sandbox(caller: Option<&Caller>, sandbox_id: &str) -> Result<(), Status> {
        match caller {
            None => Ok(()),
            Some(Caller::Supervisor {
                sandbox_id: token_sandbox,
            }) if token_sandbox == sandbox_id => Ok(()),
            Some(_) => Err(Status::permission_denied(
                "token does not authorize evaluation for this sandbox",
            )),
        }
    }
}

/// What a response preflight says about the request it answers.
fn response_seen(preflight: &HttpResponsePreflight) -> ResponseSeen {
    let context = preflight.context.clone().unwrap_or_default();
    let target = preflight.target.clone().unwrap_or_default();
    ResponseSeen {
        sandbox_id: context.sandbox_id,
        request_id: context.request_id,
        url: target_url(
            &target.scheme,
            &target.host,
            target.port,
            &target.path,
            &target.query,
        ),
        method: target.method,
        host: target.host,
        status_code: preflight.status_code,
    }
}

fn skip_response() -> HttpResponseEventResult {
    HttpResponseEventResult {
        result: Some(http_response_event_result::Result::PreflightResult(
            HttpResponsePreflightResult {
                action: Some(http_response_preflight_result::Action::Skip(
                    HttpResponsePreflightSkip {},
                )),
                ..HttpResponsePreflightResult::default()
            },
        )),
    }
}

/// Parses the policy-supplied middleware config. Only known keys are accepted
/// so a typo fails at policy load instead of silently changing behaviour.
pub fn parse_config(config: Option<&Struct>) -> Result<ApprovalMode, String> {
    let Some(config) = config else {
        return Ok(ApprovalMode::default());
    };
    let mut mode = ApprovalMode::default();
    for (key, value) in &config.fields {
        match key.as_str() {
            "approval_mode" => {
                mode = match value.kind.as_ref() {
                    Some(Kind::StringValue(text)) if text == "queue" => ApprovalMode::Queue,
                    Some(Kind::StringValue(text)) if text == "deny" => ApprovalMode::Deny,
                    _ => return Err("approval_mode must be \"queue\" or \"deny\"".to_owned()),
                };
            }
            other => {
                return Err(format!(
                    "unknown config key {other:?}; supported: approval_mode"
                ));
            }
        }
    }
    Ok(mode)
}

#[tonic::async_trait]
impl<G: Governance, S: SandboxStopper + ?Sized> SupervisorMiddleware for VerdictMiddleware<G, S> {
    type EvaluateWebSocketSessionStream = WebSocketResponseStream;

    async fn describe(
        &self,
        request: Request<MiddlewareDescribeRequest>,
    ) -> Result<Response<MiddlewareManifest>, Status> {
        self.caller(&request)?;
        let binding = |operation: SupervisorMiddlewareOperation| MiddlewareBinding {
            operation: operation as i32,
            phase: if operation == SupervisorMiddlewareOperation::HttpResponse {
                SupervisorMiddlewarePhase::PreReturn as i32
            } else {
                SupervisorMiddlewarePhase::PreCredentials as i32
            },
            max_payload_bytes: self.max_payload_bytes,
            request_timeout: self
                .request_timeout
                .and_then(|timeout| prost_types::Duration::try_from(timeout).ok()),
        };
        let manifest = MiddlewareManifest {
            name: MANIFEST_NAME.to_owned(),
            service_version: env!("CARGO_PKG_VERSION").to_owned(),
            bindings: vec![
                binding(SupervisorMiddlewareOperation::HttpRequest),
                binding(SupervisorMiddlewareOperation::HttpResponse),
                binding(SupervisorMiddlewareOperation::WebsocketMessage),
            ],
            expected_audience: self
                .verifier
                .as_ref()
                .map_or_else(String::new, |verifier| verifier.audience().to_owned()),
            extension: Some(extension_metadata(
                ExtensionFamily::SupervisorMiddleware,
                MANIFEST_NAME,
                env!("CARGO_PKG_VERSION"),
                [],
            )),
        };
        validate_gateway_metadata(
            ExtensionFamily::SupervisorMiddleware,
            MANIFEST_NAME,
            manifest.extension.as_ref(),
            request.into_inner().gateway,
        )
        .map_err(|error| Status::failed_precondition(error.to_string()))?;
        Ok(Response::new(manifest))
    }

    async fn validate_config(
        &self,
        request: Request<ValidateConfigRequest>,
    ) -> Result<Response<ValidateConfigResponse>, Status> {
        self.caller(&request)?;
        Ok(Response::new(
            match parse_config(request.get_ref().config.as_ref()) {
                Ok(_) => ValidateConfigResponse {
                    valid: true,
                    reason: String::new(),
                },
                Err(reason) => ValidateConfigResponse {
                    valid: false,
                    reason,
                },
            },
        ))
    }

    async fn evaluate_http_request(
        &self,
        request: Request<HttpRequestEvaluation>,
    ) -> Result<Response<HttpRequestResult>, Status> {
        let caller = self.caller(&request)?;
        let evaluation = request.into_inner();
        if evaluation.phase != SupervisorMiddlewarePhase::PreCredentials as i32 {
            return Err(Status::invalid_argument(
                "only PRE_CREDENTIALS is supported",
            ));
        }
        let sandbox_id = evaluation
            .context
            .as_ref()
            .map_or("", |context| context.sandbox_id.as_str());
        Self::check_sandbox(caller.as_ref(), sandbox_id)?;
        let mode = parse_config(evaluation.config.as_ref()).map_err(Status::invalid_argument)?;
        let action = Action::from_evaluation(&evaluation);
        Ok(Response::new(self.guard.evaluate(&action, mode).await))
    }

    async fn evaluate_web_socket_session(
        &self,
        request: Request<tonic::Streaming<WebSocketSessionEvent>>,
    ) -> Result<Response<Self::EvaluateWebSocketSessionStream>, Status> {
        self.caller(&request)?;
        let mut inbound = request.into_inner();
        let (sender, receiver) = tokio::sync::mpsc::channel(4);
        tokio::spawn(async move {
            // v1 declines to inspect WebSocket sessions. SKIP is a successful
            // decision, recorded as a finding so the coverage gap is visible
            // in the evidence rather than silent.
            while let Some(Ok(event)) = inbound.next().await {
                if let Some(web_socket_session_event::Event::Preflight(_)) = event.event {
                    let decision = WebSocketSessionEventResult {
                        result: Some(web_socket_session_event_result::Result::PreflightDecision(
                            WebSocketPreflightDecision {
                                action: WebSocketPreflightAction::Skip as i32,
                                reason: "OpenBox does not inspect WebSocket sessions in v1"
                                    .to_owned(),
                                findings: vec![Finding {
                                    r#type: "openbox.coverage".to_owned(),
                                    label: "websocket_not_inspected".to_owned(),
                                    count: 1,
                                    confidence: "certain".to_owned(),
                                    severity: "low".to_owned(),
                                }],
                                ..WebSocketPreflightDecision::default()
                            },
                        )),
                    };
                    if sender.send(Ok(decision)).await.is_err() {
                        break;
                    }
                }
            }
        });
        Ok(Response::new(Box::pin(
            tokio_stream::wrappers::ReceiverStream::new(receiver),
        )))
    }
}

#[tonic::async_trait]
impl<G: Governance, S: SandboxStopper + ?Sized> HttpResponsePreReturn for VerdictMiddleware<G, S> {
    type EvaluateStream = HttpResponseResultStream;

    async fn evaluate(
        &self,
        request: Request<tonic::Streaming<HttpResponseEvent>>,
    ) -> Result<Response<Self::EvaluateStream>, Status> {
        let caller = self.caller(&request)?;
        let mut inbound = request.into_inner();
        let guard = Arc::clone(&self.guard);
        let (sender, receiver) = tokio::sync::mpsc::channel(4);
        tokio::spawn(async move {
            // Skip ends this stage after preflight, so no body or trailers
            // follow; anything else ends the stream.
            while let Some(Ok(event)) = inbound.next().await {
                let Some(http_response_event::Event::Preflight(preflight)) = event.event else {
                    break;
                };
                let seen = response_seen(&preflight);
                let result = match Self::check_sandbox(caller.as_ref(), &seen.sandbox_id) {
                    Ok(()) => {
                        guard.complete(seen).await;
                        Ok(skip_response())
                    }
                    Err(status) => Err(status),
                };
                let failed = result.is_err();
                if sender.send(result).await.is_err() || failed {
                    break;
                }
            }
        });
        Ok(Response::new(Box::pin(
            tokio_stream::wrappers::ReceiverStream::new(receiver),
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::tests::evaluation;
    use crate::core_client::Verdict;
    use crate::guard::tests::{FakeCore, FakeStopper};
    use crate::guard::{REASON_BLOCKED, REASON_UNAVAILABLE};
    use crate::token::tests::{AUDIENCE, TestSigner};
    use openshell_core::proto::Decision;
    use prost_types::Value;

    fn service(
        core: FakeCore,
        signer: Option<&TestSigner>,
    ) -> VerdictMiddleware<FakeCore, FakeStopper> {
        let guard = Arc::new(Guard::new(Arc::new(core), Arc::new(FakeStopper::default())));
        let verifier = signer
            .map(|signer| TokenVerifier::from_pem(&signer.public_pem(), "gw-1", AUDIENCE).unwrap());
        VerdictMiddleware::new(guard, verifier, 1024 * 1024, None)
    }

    fn with_token<T>(message: T, token: &str) -> Request<T> {
        let mut request = Request::new(message);
        request
            .metadata_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
        request
    }

    fn phased(mut evaluation: HttpRequestEvaluation) -> HttpRequestEvaluation {
        evaluation.phase = SupervisorMiddlewarePhase::PreCredentials as i32;
        evaluation
    }

    fn config(entries: &[(&str, &str)]) -> Struct {
        Struct {
            fields: entries
                .iter()
                .map(|(key, value)| {
                    (
                        (*key).to_owned(),
                        Value {
                            kind: Some(Kind::StringValue((*value).to_owned())),
                        },
                    )
                })
                .collect(),
        }
    }

    #[test]
    fn config_accepts_only_known_keys() {
        assert_eq!(parse_config(None), Ok(ApprovalMode::Queue));
        assert_eq!(
            parse_config(Some(&config(&[("approval_mode", "deny")]))),
            Ok(ApprovalMode::Deny)
        );
        assert!(parse_config(Some(&config(&[("approval_mode", "later")]))).is_err());
        assert!(parse_config(Some(&config(&[("approvl_mode", "queue")]))).is_err());
    }

    #[tokio::test]
    async fn describe_advertises_the_bindings_and_audience() {
        let signer = TestSigner::new();
        let service = service(FakeCore::default(), Some(&signer));
        let gateway = extension_metadata(
            ExtensionFamily::SupervisorMiddleware,
            "openshell/gateway",
            "0.1.2",
            [],
        );
        let token = signer.sign(
            &serde_json::json!({"typ": "openshell-ext+jwt", "alg": "EdDSA"}),
            &serde_json::json!({"iss": "openshell-gateway:gw-1", "aud": AUDIENCE, "exp": unix_now() + 60, "caller_kind": "gateway"}),
        );
        let manifest = service
            .describe(with_token(
                MiddlewareDescribeRequest {
                    gateway: Some(gateway),
                },
                &token,
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(manifest.expected_audience, AUDIENCE);
        let bound: Vec<_> = manifest
            .bindings
            .iter()
            .map(|binding| (binding.operation, binding.phase))
            .collect();
        assert_eq!(
            bound,
            [
                (
                    SupervisorMiddlewareOperation::HttpRequest as i32,
                    SupervisorMiddlewarePhase::PreCredentials as i32
                ),
                (
                    SupervisorMiddlewareOperation::HttpResponse as i32,
                    SupervisorMiddlewarePhase::PreReturn as i32
                ),
                (
                    SupervisorMiddlewareOperation::WebsocketMessage as i32,
                    SupervisorMiddlewarePhase::PreCredentials as i32
                ),
            ]
        );
        assert!(
            manifest
                .bindings
                .iter()
                .all(|binding| binding.max_payload_bytes == 1024 * 1024)
        );
    }

    #[tokio::test]
    async fn describe_rejects_a_gateway_without_protocol_metadata() {
        let service = service(FakeCore::default(), None);
        let error = service
            .describe(Request::new(MiddlewareDescribeRequest { gateway: None }))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn evaluation_requires_a_token_for_the_same_sandbox() {
        let signer = TestSigner::new();
        let service = service(FakeCore::with_verdicts(&[Verdict::Block]), Some(&signer));
        let request = phased(evaluation("POST", "/", b""));

        let missing = service
            .evaluate_http_request(Request::new(request.clone()))
            .await
            .unwrap_err();
        assert_eq!(missing.code(), tonic::Code::Unauthenticated);

        let other = signer.supervisor_token("sbx-other", unix_now() + 60);
        let wrong = service
            .evaluate_http_request(with_token(request.clone(), &other))
            .await
            .unwrap_err();
        assert_eq!(wrong.code(), tonic::Code::PermissionDenied);

        let token = signer.supervisor_token("sbx-id-1", unix_now() + 60);
        let result = service
            .evaluate_http_request(with_token(request, &token))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(result.decision, Decision::Deny as i32);
        assert_eq!(result.reason_code, REASON_BLOCKED);
    }

    #[tokio::test]
    async fn evaluation_rejects_other_phases() {
        let service = service(FakeCore::default(), None);
        let mut request = evaluation("GET", "/", b"");
        request.phase = SupervisorMiddlewarePhase::PreReturn as i32;
        assert_eq!(
            service
                .evaluate_http_request(Request::new(request))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
    }

    #[tokio::test]
    async fn an_unreachable_core_is_an_explicit_deny_not_an_rpc_error() {
        let core = FakeCore::default();
        core.session.lock().unwrap().push_back(Err(()));
        let service = service(core, None);
        let result = service
            .evaluate_http_request(Request::new(phased(evaluation("GET", "/", b""))))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(result.decision, Decision::Deny as i32);
        assert_eq!(result.reason_code, REASON_UNAVAILABLE);
    }
}
