//! `openbox-verdict-middleware`: serves `OpenBox` verdicts to `OpenShell`
//! supervisors. Configuration comes from the environment; secrets are read
//! from files so they never appear in process listings.
//!
//! Required:
//!   `OPENBOX_URL`                     Core base URL, e.g. <https://core.example>
//!   `OPENBOX_API_KEY_FILE`            file holding the agent's `obx_` API key
//!   `OPENBOX_MW_TLS_CERT` / `_KEY`    server certificate and key (PEM)
//!   `OPENBOX_MW_GATEWAY_ID`           gateway id; tokens must come from
//!                                     `openshell-gateway:<id>`
//!   `OPENBOX_MW_GATEWAY_PUBLIC_KEY`   gateway JWT public key (PEM)
//!
//! Optional:
//!   `OPENBOX_MW_LISTEN`               default `127.0.0.1:50051`
//!   `OPENBOX_MW_ADMIN_LISTEN`         `/healthz`, `/readyz`, `/metrics`; default
//!                                     `127.0.0.1:9464`
//!   `OPENBOX_MW_AUDIENCE`             default `urn:openshell:extension:middleware:openbox`
//!   `OPENBOX_AGENT_DID`, `OPENBOX_AGENT_KEY_FILE`   sign requests (agents with
//!                                     "Require signed requests" on)
//!   `OPENBOX_WORKLOAD_KEY_FILE`, `OPENBOX_WORKLOAD_KID`   Keycloak workload
//!                                     identity: the RSA key registered with the
//!                                     agent; switches Core calls to the v3 API
//!   `OPENBOX_CORE_TIMEOUT_MS`         time for all Core calls behind one verdict,
//!                                     default 29000: under the 30 s middleware
//!                                     timeout the gateway registration must set,
//!                                     so a slow Core yields an explicit deny
//!   `OPENBOX_MW_MAX_PAYLOAD_BYTES`    default 1 MiB
//!   `OPENBOX_CORE_BODY_LIMIT_BYTES`   request body sent to Core, default 64 KiB
//!   `OPENBOX_GATEWAY_ENDPOINT`, `OPENBOX_GATEWAY_MTLS_DIR`   enable stopping
//!                                     halted sandboxes
//!   `OPENBOX_MW_INSECURE=1`           plaintext, no token checks: local dev only
//!   `OPENBOX_REDIS_URL`               `redis://[:password@]host[:port][/db]`, shared
//!                                     by every replica: approval retries and
//!                                     response completions are matched through
//!                                     it. Without it they are matched in process,
//!                                     which is only correct for one replica.
//!   `OPENBOX_APPROVAL_TTL_SECS`       how long an approval's retry can match it,
//!                                     default 900
//!   `OPENBOX_PROMPT_CAPTURE`          what Core receives for a user prompt read
//!                                     from a model call: `text` (default),
//!                                     `hash` (SHA-256 and length), `off`

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use openbox_verdict_middleware::core_client::{
    AgentSigner, CoreClient, CoreConfig, WorkloadIdentity,
};
use openbox_verdict_middleware::guard::{
    DEFAULT_APPROVAL_TTL, DEFAULT_CORE_BUDGET, Guard, SandboxStopper,
};
use openbox_verdict_middleware::halt::{DenyOnlyStopper, GatewayStopper};
use openbox_verdict_middleware::metrics::serve_admin;
use openbox_verdict_middleware::prompt::Capture;
use openbox_verdict_middleware::service::VerdictMiddleware;
use openbox_verdict_middleware::store::{MemoryStore, RedisStore, SharedStore};
use openbox_verdict_middleware::token::TokenVerifier;
use openshell_core::proto::middleware::v1::http_response_pre_return_server::HttpResponsePreReturnServer;
use openshell_core::proto::middleware::v1::supervisor_middleware_server::SupervisorMiddlewareServer;
use tonic::transport::{Identity, Server, ServerTlsConfig};

const DEFAULT_AUDIENCE: &str = "urn:openshell:extension:middleware:openbox";
/// `OpenShell` sends bodies up to 4 MiB plus a protobuf envelope (it asks
/// services to accept at least 4 MiB + 293 KiB); tonic defaults to 4 MiB.
const MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024 + 512 * 1024;

fn env(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn required(key: &str) -> Result<String, String> {
    env(key).ok_or_else(|| format!("{key} is required"))
}

fn read_secret(key: &str) -> Result<String, String> {
    let path = required(key)?;
    std::fs::read_to_string(&path)
        .map(|text| text.trim().to_owned())
        .map_err(|error| format!("{key}: cannot read {path}: {error}"))
}

fn core_budget() -> Result<Duration, String> {
    let default = u64::try_from(DEFAULT_CORE_BUDGET.as_millis()).unwrap_or(u64::MAX);
    Ok(Duration::from_millis(number(
        "OPENBOX_CORE_TIMEOUT_MS",
        default,
    )?))
}

fn number<T: std::str::FromStr>(key: &str, default: T) -> Result<T, String> {
    env(key).map_or(Ok(default), |value| {
        value.parse().map_err(|_| format!("{key} must be a number"))
    })
}

#[tokio::main]
async fn main() -> ExitCode {
    // openshell-core enables aws-lc-rs next to our ring; choose explicitly.
    let _ = rustls::crypto::ring::default_provider().install_default();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("openbox-verdict-middleware: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Builds the Core client: API key, plus either v1 request signing or a v3
/// workload identity.
fn core_from_env() -> Result<CoreClient, String> {
    let signer = match (env("OPENBOX_AGENT_DID"), env("OPENBOX_AGENT_KEY_FILE")) {
        (Some(did), Some(_)) => Some(
            AgentSigner::new(did, &read_secret("OPENBOX_AGENT_KEY_FILE")?)
                .map_err(|_| "OPENBOX_AGENT_DID / OPENBOX_AGENT_KEY_FILE are invalid".to_owned())?,
        ),
        (None, None) => None,
        _ => {
            return Err(
                "set both OPENBOX_AGENT_DID and OPENBOX_AGENT_KEY_FILE, or neither".to_owned(),
            );
        }
    };
    let workload = match (
        env("OPENBOX_WORKLOAD_KEY_FILE"),
        env("OPENBOX_WORKLOAD_KID"),
    ) {
        (Some(_), Some(kid)) => Some(
            WorkloadIdentity::from_pem(&read_secret("OPENBOX_WORKLOAD_KEY_FILE")?, kid)
                .map_err(|_| "OPENBOX_WORKLOAD_KEY_FILE is not an RSA private key".to_owned())?,
        ),
        (None, None) => None,
        _ => {
            return Err(
                "set both OPENBOX_WORKLOAD_KEY_FILE and OPENBOX_WORKLOAD_KID, or neither"
                    .to_owned(),
            );
        }
    };
    if workload.is_some() && signer.is_some() {
        return Err(
            "use either request signing (v1) or a workload identity (v3), not both".to_owned(),
        );
    }
    CoreClient::new(CoreConfig {
        base_url: required("OPENBOX_URL")?,
        api_key: read_secret("OPENBOX_API_KEY_FILE")?,
        signer,
        workload,
        timeout: core_budget()?,
        body_limit_bytes: number("OPENBOX_CORE_BODY_LIMIT_BYTES", 64 * 1024)?,
    })
    .map_err(|error| error.to_string())
}

/// The gRPC server, with TLS unless the operator chose plaintext.
fn server_from_env(insecure: bool) -> Result<Server, String> {
    let server = Server::builder();
    if insecure {
        return Ok(server);
    }
    let cert = std::fs::read(required("OPENBOX_MW_TLS_CERT")?)
        .map_err(|error| format!("OPENBOX_MW_TLS_CERT: {error}"))?;
    let key = std::fs::read(required("OPENBOX_MW_TLS_KEY")?)
        .map_err(|error| format!("OPENBOX_MW_TLS_KEY: {error}"))?;
    server
        .tls_config(ServerTlsConfig::new().identity(Identity::from_pem(cert, key)))
        .map_err(|error| format!("server TLS: {error}"))
}

/// Where approvals and completions are matched, and for how long.
fn store_from_env() -> Result<(Arc<dyn SharedStore>, Duration), String> {
    let store: Arc<dyn SharedStore> = if let Some(url) = env("OPENBOX_REDIS_URL") {
        Arc::new(RedisStore::from_url(&url, Duration::from_millis(200))?)
    } else {
        eprintln!(
            "openbox-verdict-middleware: no OPENBOX_REDIS_URL; approvals and completions are matched in this process only (one replica)"
        );
        Arc::new(MemoryStore::default())
    };
    let approval_ttl =
        env("OPENBOX_APPROVAL_TTL_SECS").map_or(Ok(DEFAULT_APPROVAL_TTL), |value| {
            value
                .parse()
                .ok()
                .filter(|seconds| *seconds > 0)
                .map(Duration::from_secs)
                .ok_or_else(|| "OPENBOX_APPROVAL_TTL_SECS must be a positive number".to_owned())
        })?;
    Ok((store, approval_ttl))
}

async fn run() -> Result<(), String> {
    let insecure = env("OPENBOX_MW_INSECURE").as_deref() == Some("1");
    let listen: SocketAddr = env("OPENBOX_MW_LISTEN")
        .unwrap_or_else(|| "127.0.0.1:50051".to_owned())
        .parse()
        .map_err(|_| "OPENBOX_MW_LISTEN must be host:port".to_owned())?;

    let core = core_from_env()?;

    let stopper: Arc<dyn SandboxStopper> = match (
        env("OPENBOX_GATEWAY_ENDPOINT"),
        env("OPENBOX_GATEWAY_MTLS_DIR"),
    ) {
        (Some(endpoint), Some(dir)) => Arc::new(GatewayStopper::connect_lazy(
            &endpoint,
            &PathBuf::from(dir),
        )?),
        (None, None) => {
            eprintln!(
                "openbox-verdict-middleware: no gateway credential; HALT denies traffic but cannot stop sandboxes"
            );
            Arc::new(DenyOnlyStopper)
        }
        _ => {
            return Err(
                "set both OPENBOX_GATEWAY_ENDPOINT and OPENBOX_GATEWAY_MTLS_DIR, or neither"
                    .to_owned(),
            );
        }
    };

    let verifier = if insecure {
        eprintln!(
            "openbox-verdict-middleware: OPENBOX_MW_INSECURE=1, accepting unauthenticated plaintext calls"
        );
        None
    } else {
        let pem = std::fs::read_to_string(required("OPENBOX_MW_GATEWAY_PUBLIC_KEY")?)
            .map_err(|error| format!("OPENBOX_MW_GATEWAY_PUBLIC_KEY: {error}"))?;
        Some(
            TokenVerifier::from_pem(
                &pem,
                &required("OPENBOX_MW_GATEWAY_ID")?,
                env("OPENBOX_MW_AUDIENCE").unwrap_or_else(|| DEFAULT_AUDIENCE.to_owned()),
            )
            .map_err(|error| format!("gateway public key: {error}"))?,
        )
    };

    let (store, approval_ttl) = store_from_env()?;
    let capture = env("OPENBOX_PROMPT_CAPTURE").map_or(Ok(Capture::Text), |value| {
        Capture::parse(&value)
            .ok_or_else(|| "OPENBOX_PROMPT_CAPTURE must be text, hash or off".to_owned())
    })?;
    let guard = Arc::new(
        Guard::with_store(Arc::new(core), stopper, store, approval_ttl)
            .with_core_budget(core_budget()?)
            .with_prompt_capture(capture),
    );
    let metrics = guard.metrics();
    let admin: SocketAddr = env("OPENBOX_MW_ADMIN_LISTEN")
        .unwrap_or_else(|| "127.0.0.1:9464".to_owned())
        .parse()
        .map_err(|_| "OPENBOX_MW_ADMIN_LISTEN must be host:port".to_owned())?;
    let admin = tokio::net::TcpListener::bind(admin)
        .await
        .map_err(|error| format!("admin listener {admin}: {error}"))?;
    tokio::spawn(serve_admin(admin, Arc::clone(&metrics)));
    let service = Arc::new(VerdictMiddleware::new(
        guard,
        verifier,
        number("OPENBOX_MW_MAX_PAYLOAD_BYTES", 1024 * 1024)?,
        None,
    ));

    let mut server = server_from_env(insecure)?;
    eprintln!(
        "openbox-verdict-middleware: listening on {}://{listen}",
        if insecure { "http" } else { "https" }
    );
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .map_err(|error| format!("listener {listen}: {error}"))?;
    metrics.set_ready();
    server
        .add_service(
            SupervisorMiddlewareServer::from_arc(Arc::clone(&service))
                .max_decoding_message_size(MAX_MESSAGE_BYTES),
        )
        .add_service(
            HttpResponsePreReturnServer::from_arc(service)
                .max_decoding_message_size(MAX_MESSAGE_BYTES),
        )
        .serve_with_incoming_shutdown(
            tokio_stream::wrappers::TcpListenerStream::new(listener),
            shutdown_signal(),
        )
        .await
        .map_err(|error| format!("server: {error}"))
}

/// Kubernetes sends SIGTERM; a terminal sends SIGINT. In-flight evaluations
/// finish before the server exits.
async fn shutdown_signal() {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = terminate.recv() => {}
    }
    eprintln!("openbox-verdict-middleware: shutting down");
}
