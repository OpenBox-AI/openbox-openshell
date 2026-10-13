//! `OpenTelemetry` traces, exported over OTLP/gRPC when the operator asks for
//! them with the standard variables:
//!
//!   `OTEL_EXPORTER_OTLP_ENDPOINT`     collector, e.g. <http://collector:4317>;
//!                                     `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` wins
//!   `OTEL_SERVICE_NAME`               default: the binary's name
//!   `OTEL_RESOURCE_ATTRIBUTES`, `OTEL_EXPORTER_OTLP_HEADERS`,
//!   `OTEL_EXPORTER_OTLP_TIMEOUT`, `OTEL_TRACES_SAMPLER`, `OTEL_BSP_*`
//!                                     as the `OpenTelemetry` SDK reads them
//!   `OTEL_SDK_DISABLED=true`          off, even with an endpoint
//!
//! Without an endpoint nothing is installed: spans go to `OpenTelemetry`'s
//! no-op tracer, with no exporter, no background thread and no network.
//!
//! Spans carry identifiers, verdicts and reason codes only: never request or
//! response bodies, prompts, headers or credentials.

use std::fmt::Display;

use opentelemetry::trace::{FutureExt as _, SpanKind, Status, TraceContextExt as _, Tracer as _};
use opentelemetry::{Context, KeyValue, global};
use opentelemetry_otlp::tonic_types::transport::ClientTlsConfig;
use opentelemetry_otlp::{SpanExporter, WithTonicConfig as _};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::trace::SdkTracerProvider;

const TRACER: &str = "openbox";

pub const SANDBOX_ID: &str = "openbox.sandbox.id";
pub const REQUEST_ID: &str = "openbox.request.id";
pub const DECISION: &str = "openbox.decision";
pub const REASON_CODE: &str = "openbox.reason_code";

/// The installed exporter. Shut it down once the server has stopped, so the
/// last spans are sent.
pub struct Telemetry {
    provider: SdkTracerProvider,
}

impl Telemetry {
    /// Sends what is buffered and stops the exporter. Blocks while it sends.
    pub fn shutdown(self) {
        if let Err(error) = self.provider.shutdown() {
            eprintln!("openbox: trace export did not shut down cleanly: {error}");
        }
    }
}

/// Installs the OTLP exporter as the global tracer provider when an endpoint
/// is configured. Must run inside the Tokio runtime: the gRPC client lives
/// there.
pub fn init(service: &str) -> Result<Option<Telemetry>, String> {
    init_with(
        |key| {
            std::env::var(key)
                .ok()
                .filter(|value| !value.trim().is_empty())
        },
        service,
    )
}

fn init_with(
    env: impl Fn(&str) -> Option<String>,
    service: &str,
) -> Result<Option<Telemetry>, String> {
    let Some(endpoint) =
        env("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT").or_else(|| env("OTEL_EXPORTER_OTLP_ENDPOINT"))
    else {
        return Ok(None);
    };
    if env("OTEL_SDK_DISABLED").is_some_and(|value| value.eq_ignore_ascii_case("true")) {
        return Ok(None);
    }
    if let Some(protocol) = env("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL")
        .or_else(|| env("OTEL_EXPORTER_OTLP_PROTOCOL"))
        .filter(|protocol| protocol != "grpc")
    {
        return Err(format!(
            "OTEL_EXPORTER_OTLP_PROTOCOL={protocol} is not supported; traces are sent over grpc"
        ));
    }
    let mut exporter = SpanExporter::builder().with_tonic();
    if endpoint.starts_with("https://") {
        exporter = exporter.with_tls_config(ClientTlsConfig::new().with_native_roots());
    }
    let exporter = exporter
        .build()
        .map_err(|error| format!("OTEL_EXPORTER_OTLP_ENDPOINT: {error}"))?;
    let mut resource = Resource::builder();
    if env("OTEL_SERVICE_NAME").is_none() {
        resource = resource.with_service_name(service.to_owned());
    }
    let provider = SdkTracerProvider::builder()
        .with_resource(resource.build())
        .with_batch_exporter(exporter)
        .build();
    global::set_tracer_provider(provider.clone());
    eprintln!("{service}: exporting traces to {endpoint}");
    Ok(Some(Telemetry { provider }))
}

/// Starts a span under `parent`. Callers end it; otherwise it ends when the
/// last clone of the returned context is dropped.
pub fn start(
    parent: &Context,
    name: &'static str,
    kind: SpanKind,
    attributes: Vec<KeyValue>,
) -> Context {
    let tracer = global::tracer(TRACER);
    let span = tracer
        .span_builder(name)
        .with_kind(kind)
        .with_attributes(attributes)
        .start_with_context(&tracer, parent);
    parent.with_span(span)
}

/// Runs a call to another service in a client span under the current one,
/// marked failed when the call fails. The error must not carry content.
pub async fn call<T, E: Display>(
    name: &'static str,
    attributes: Vec<KeyValue>,
    work: impl Future<Output = Result<T, E>>,
) -> Result<T, E> {
    let cx = start(&Context::current(), name, SpanKind::Client, attributes);
    let outcome = work.with_context(cx.clone()).await;
    if let Err(error) = &outcome {
        cx.span().set_status(Status::error(error.to_string()));
    }
    cx.span().end();
    outcome
}

/// Runs `work` in a span under the current one.
pub async fn within<T>(
    name: &'static str,
    attributes: Vec<KeyValue>,
    work: impl Future<Output = T>,
) -> T {
    let cx = start(&Context::current(), name, SpanKind::Internal, attributes);
    let output = work.with_context(cx.clone()).await;
    cx.span().end();
    output
}

/// Background work, traced from when it runs: under the span current where
/// it was created, which has usually ended by then.
pub fn job<F: Future>(
    name: &'static str,
    attributes: Vec<KeyValue>,
    work: F,
) -> impl Future<Output = F::Output> {
    let parent = Context::current();
    async move {
        let cx = start(&parent, name, SpanKind::Internal, attributes);
        let output = work.with_context(cx.clone()).await;
        cx.span().end();
        output
    }
}

pub fn sandbox(sandbox_id: &str) -> KeyValue {
    KeyValue::new(SANDBOX_ID, sandbox_id.to_owned())
}

pub fn request(request_id: &str) -> KeyValue {
    KeyValue::new(REQUEST_ID, request_id.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn without_an_endpoint_nothing_is_installed() {
        assert!(init_with(|_| None, "test").unwrap().is_none());
        let disabled = |key: &str| match key {
            "OTEL_EXPORTER_OTLP_ENDPOINT" => Some("http://127.0.0.1:4317".to_owned()),
            "OTEL_SDK_DISABLED" => Some("true".to_owned()),
            _ => None,
        };
        assert!(init_with(disabled, "test").unwrap().is_none());
    }

    #[test]
    fn only_grpc_is_accepted() {
        let http = |key: &str| match key {
            "OTEL_EXPORTER_OTLP_ENDPOINT" => Some("http://127.0.0.1:4318".to_owned()),
            "OTEL_EXPORTER_OTLP_PROTOCOL" => Some("http/protobuf".to_owned()),
            _ => None,
        };
        assert!(init_with(http, "test").is_err());
    }
}
