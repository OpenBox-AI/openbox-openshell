//! The `openshell.middleware.v1.SupervisorMiddleware` gRPC service.
//!
//! Every call is authenticated with `OpenShell`'s extension token unless the
//! operator explicitly runs without authentication (local development only).
//! A supervisor may only evaluate traffic for the sandbox its token names, so
//! one sandbox cannot spend another's approvals or trip another's halt.
//!
//! The same service also answers `HttpResponsePreReturn`: it never changes
//! or holds a response. Where `OpenShell` allows it, the body is read as it
//! streams (every unit passed through unchanged, a bounded copy kept) so the
//! request's completed span carries it and a model call's reply can be read;
//! otherwise the response is skipped and completes without a body.

use std::sync::Arc;
use std::time::Duration;

use openshell_core::extension_protocol::{
    ExtensionFamily, extension_metadata, validate_gateway_metadata,
};
use openshell_core::middleware::{HttpResponseResultStream, WebSocketResponseStream};
use openshell_core::proto::middleware::v1::http_response_pre_return_server::HttpResponsePreReturn;
use openshell_core::proto::middleware::v1::supervisor_middleware_server::SupervisorMiddleware;
use openshell_core::proto::{
    Finding, HttpRequestEvaluation, HttpRequestResult, HttpResponseBodyMode,
    HttpResponseBodyPassThrough, HttpResponseBodyResult, HttpResponseEvent,
    HttpResponseEventResult, HttpResponsePreflight, HttpResponsePreflightInspect,
    HttpResponsePreflightResult, HttpResponsePreflightSkip, HttpResponseTrailersResult,
    MiddlewareBinding, MiddlewareDescribeRequest, MiddlewareManifest,
    SupervisorMiddlewareOperation, SupervisorMiddlewarePhase, ValidateConfigRequest,
    ValidateConfigResponse, WebSocketPreflightAction, WebSocketPreflightDecision,
    WebSocketSessionEvent, WebSocketSessionEventResult, http_response_body_result,
    http_response_body_unit, http_response_event, http_response_event_result,
    http_response_preflight_result, web_socket_session_event, web_socket_session_event_result,
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
/// Most of a response body kept for its activity. The rest still streams
/// through to the sandbox; only the copy stops.
const RESPONSE_CAPTURE_BYTES: usize = 4 * 1024 * 1024;

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

/// Answers one response's stage stream: preflight, then (when streaming)
/// body units ending in `end_of_stream`, then trailers. The response
/// completes when its body ends, or with what arrived if the stream stops
/// first.
async fn answer_response<G, S>(
    guard: Arc<Guard<G, S>>,
    caller: Option<Caller>,
    mut inbound: impl tokio_stream::Stream<Item = Result<HttpResponseEvent, Status>> + Unpin,
    sender: tokio::sync::mpsc::Sender<Result<HttpResponseEventResult, Status>>,
) where
    G: Governance,
    S: SandboxStopper + ?Sized,
{
    let mut pending: Option<ResponseSeen> = None;
    let mut body = Vec::new();
    while let Some(Ok(event)) = inbound.next().await {
        let result = match event.event {
            Some(http_response_event::Event::Preflight(preflight)) => {
                let seen = response_seen(&preflight);
                if let Err(status) =
                    VerdictMiddleware::<G, S>::check_sandbox(caller.as_ref(), &seen.sandbox_id)
                {
                    let _ = sender.send(Err(status)).await;
                    break;
                }
                if preflight
                    .permitted_body_modes
                    .contains(&(HttpResponseBodyMode::StreamBytes as i32))
                {
                    pending = Some(seen);
                    stream_response()
                } else {
                    guard.complete(seen).await;
                    skip_response()
                }
            }
            Some(http_response_event::Event::Body(unit)) => {
                if let Some(http_response_body_unit::Payload::Data(data)) = &unit.payload {
                    let room = RESPONSE_CAPTURE_BYTES.saturating_sub(body.len());
                    body.extend_from_slice(&data[..data.len().min(room)]);
                }
                // Recorded before the last unit goes out, so the
                // sandbox's next request finds any tool it opened.
                if unit.end_of_stream
                    && let Some(mut seen) = pending.take()
                {
                    seen.body = Some(std::mem::take(&mut body));
                    guard.complete(seen).await;
                }
                pass_through(unit.sequence)
            }
            Some(http_response_event::Event::Trailers(_)) => keep_trailers(),
            Some(http_response_event::Event::SessionEnd(_)) | None => break,
        };
        if sender.send(Ok(result)).await.is_err() {
            break;
        }
    }
    if let Some(mut seen) = pending.take() {
        seen.body = Some(body);
        guard.complete(seen).await;
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
        headers: preflight
            .headers
            .iter()
            .map(|header| (header.name.clone(), header.value.clone()))
            .collect(),
        body: None,
    }
}

/// Reads the body as it streams, when `OpenShell` offers that for this
/// response: compressed, partial and bodyless responses are headers only.
fn stream_response() -> HttpResponseEventResult {
    HttpResponseEventResult {
        result: Some(http_response_event_result::Result::PreflightResult(
            HttpResponsePreflightResult {
                action: Some(http_response_preflight_result::Action::Inspect(
                    HttpResponsePreflightInspect {
                        body_mode: HttpResponseBodyMode::StreamBytes as i32,
                        header_mutations: Vec::new(),
                    },
                )),
                ..HttpResponsePreflightResult::default()
            },
        )),
    }
}

fn pass_through(sequence: u64) -> HttpResponseEventResult {
    HttpResponseEventResult {
        result: Some(http_response_event_result::Result::BodyResult(
            HttpResponseBodyResult {
                sequence,
                action: Some(http_response_body_result::Action::PassThrough(
                    HttpResponseBodyPassThrough {},
                )),
                ..HttpResponseBodyResult::default()
            },
        )),
    }
}

fn keep_trailers() -> HttpResponseEventResult {
    HttpResponseEventResult {
        result: Some(http_response_event_result::Result::TrailersResult(
            HttpResponseTrailersResult::default(),
        )),
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

/// The longest `profile` accepted; Core stores it with every activity.
const MAX_PROFILE_BYTES: usize = 128;

/// The middleware config a sandbox's policy sets for the door guard.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MiddlewareConfig {
    pub approval_mode: ApprovalMode,
    /// The sandbox's profile, sent to Core as `profile_id` so a policy can
    /// tell one kind of sandbox from another under the same agent.
    pub profile: Option<String>,
}

/// Parses the policy-supplied middleware config. Only known keys are accepted
/// so a typo fails at policy load instead of silently changing behaviour.
pub fn parse_config(config: Option<&Struct>) -> Result<MiddlewareConfig, String> {
    let mut parsed = MiddlewareConfig::default();
    let Some(config) = config else {
        return Ok(parsed);
    };
    for (key, value) in &config.fields {
        match key.as_str() {
            "approval_mode" => {
                parsed.approval_mode = match value.kind.as_ref() {
                    Some(Kind::StringValue(text)) if text == "queue" => ApprovalMode::Queue,
                    Some(Kind::StringValue(text)) if text == "deny" => ApprovalMode::Deny,
                    _ => return Err("approval_mode must be \"queue\" or \"deny\"".to_owned()),
                };
            }
            "profile" => {
                parsed.profile = match value.kind.as_ref() {
                    Some(Kind::StringValue(text))
                        if !text.trim().is_empty()
                            && text.len() <= MAX_PROFILE_BYTES
                            && !text.chars().any(char::is_control) =>
                    {
                        Some(text.clone())
                    }
                    _ => {
                        return Err(format!(
                            "profile must be a non-empty string of at most {MAX_PROFILE_BYTES} bytes"
                        ));
                    }
                };
            }
            other => {
                return Err(format!(
                    "unknown config key {other:?}; supported: approval_mode, profile"
                ));
            }
        }
    }
    Ok(parsed)
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
        let config = parse_config(evaluation.config.as_ref()).map_err(Status::invalid_argument)?;
        let mut action = Action::from_evaluation(&evaluation);
        action.profile = config.profile;
        Ok(Response::new(
            self.guard.evaluate(&action, config.approval_mode).await,
        ))
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
        let inbound = request.into_inner();
        let guard = Arc::clone(&self.guard);
        let (sender, receiver) = tokio::sync::mpsc::channel(4);
        tokio::spawn(answer_response(guard, caller, inbound, sender));
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

    fn response_events(
        modes: &[HttpResponseBodyMode],
        units: &[(&[u8], bool)],
    ) -> Vec<HttpResponseEvent> {
        use openshell_core::proto::{
            HttpRequestTarget, HttpResponseBodyUnit, HttpResponseTrailers, RequestContext,
        };
        let mut events = vec![HttpResponseEvent {
            event: Some(http_response_event::Event::Preflight(
                HttpResponsePreflight {
                    context: Some(RequestContext {
                        request_id: "req-1".to_owned(),
                        sandbox_id: "sbx-id-1".to_owned(),
                        ..RequestContext::default()
                    }),
                    target: Some(HttpRequestTarget {
                        scheme: "https".to_owned(),
                        host: "mcp.example.com".to_owned(),
                        port: 443,
                        method: "POST".to_owned(),
                        path: "/mcp".to_owned(),
                        query: String::new(),
                    }),
                    status_code: 200,
                    permitted_body_modes: modes.iter().map(|mode| *mode as i32).collect(),
                    ..HttpResponsePreflight::default()
                },
            )),
        }];
        for (sequence, (data, last)) in (1_u64..).zip(units) {
            events.push(HttpResponseEvent {
                event: Some(http_response_event::Event::Body(HttpResponseBodyUnit {
                    sequence,
                    payload: Some(http_response_body_unit::Payload::Data(data.to_vec())),
                    end_of_stream: *last,
                })),
            });
        }
        if !units.is_empty() {
            events.push(HttpResponseEvent {
                event: Some(http_response_event::Event::Trailers(
                    HttpResponseTrailers::default(),
                )),
            });
        }
        events
    }

    async fn answer(
        core: &Arc<FakeCore>,
        events: Vec<HttpResponseEvent>,
    ) -> Vec<HttpResponseEventResult> {
        let guard = Arc::new(Guard::new(
            Arc::clone(core),
            Arc::new(FakeStopper::default()),
        ));
        let (sender, mut receiver) = tokio::sync::mpsc::channel(16);
        answer_response(
            guard,
            None,
            tokio_stream::iter(events.into_iter().map(Ok)),
            sender,
        )
        .await;
        let mut results = Vec::new();
        while let Ok(result) = receiver.try_recv() {
            results.push(result.unwrap());
        }
        results
    }

    async fn completed(core: &FakeCore) -> crate::core_client::Completion {
        for _ in 0..100 {
            if let Some(completion) = core.completions.lock().unwrap().first() {
                return completion.clone();
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("the response was never completed");
    }

    #[tokio::test]
    async fn a_streamed_response_passes_through_and_its_body_is_kept() {
        let core = Arc::new(FakeCore::default());
        let events = response_events(
            &[
                HttpResponseBodyMode::HeadersOnly,
                HttpResponseBodyMode::StreamBytes,
            ],
            &[
                (br#"{"jsonrpc":"2.0","#, false),
                (br#""id":1,"result":{}}"#, false),
                (b"", true),
            ],
        );
        let results = answer(&core, events).await;
        let kinds: Vec<String> = results
            .iter()
            .map(|result| match &result.result {
                Some(http_response_event_result::Result::PreflightResult(preflight)) => {
                    match &preflight.action {
                        Some(http_response_preflight_result::Action::Inspect(inspect)) => {
                            format!("inspect {}", inspect.body_mode)
                        }
                        other => format!("{other:?}"),
                    }
                }
                Some(http_response_event_result::Result::BodyResult(body)) => match body.action {
                    Some(http_response_body_result::Action::PassThrough(_)) => {
                        format!("pass {}", body.sequence)
                    }
                    ref other => format!("{other:?}"),
                },
                Some(http_response_event_result::Result::TrailersResult(trailers)) => {
                    format!("trailers {}", trailers.trailer_mutations.len())
                }
                None => "none".to_owned(),
            })
            .collect();
        assert_eq!(
            kinds,
            vec![
                format!("inspect {}", HttpResponseBodyMode::StreamBytes as i32),
                "pass 1".to_owned(),
                "pass 2".to_owned(),
                "pass 3".to_owned(),
                "trailers 0".to_owned(),
            ]
        );
        let completion = completed(&core).await;
        assert_eq!(completion.request_id, "req-1");
        assert_eq!(
            completion.response_body.as_deref(),
            Some(r#"{"jsonrpc":"2.0","id":1,"result":{}}"#)
        );
    }

    #[tokio::test]
    async fn a_response_offered_headers_only_is_skipped_and_completes_without_a_body() {
        let core = Arc::new(FakeCore::default());
        let results = answer(
            &core,
            response_events(&[HttpResponseBodyMode::HeadersOnly], &[]),
        )
        .await;
        assert_eq!(results.len(), 1);
        assert!(matches!(
            &results[0].result,
            Some(http_response_event_result::Result::PreflightResult(preflight))
                if matches!(preflight.action, Some(http_response_preflight_result::Action::Skip(_)))
        ));
        assert_eq!(completed(&core).await.response_body, None);
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
        assert_eq!(parse_config(None), Ok(MiddlewareConfig::default()));
        assert_eq!(
            MiddlewareConfig::default().approval_mode,
            ApprovalMode::Queue
        );
        assert_eq!(
            parse_config(Some(&config(&[("approval_mode", "deny")]))),
            Ok(MiddlewareConfig {
                approval_mode: ApprovalMode::Deny,
                profile: None,
            })
        );
        assert_eq!(
            parse_config(Some(&config(&[
                ("profile", "coding"),
                ("approval_mode", "queue")
            ]))),
            Ok(MiddlewareConfig {
                approval_mode: ApprovalMode::Queue,
                profile: Some("coding".to_owned()),
            })
        );
        assert!(parse_config(Some(&config(&[("profile", " ")]))).is_err());
        assert!(parse_config(Some(&config(&[("profile", "a\nb")]))).is_err());
        assert!(parse_config(Some(&config(&[("profile", &"p".repeat(129))]))).is_err());
        assert!(parse_config(Some(&config(&[("tenant", "acme")]))).is_err());
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
