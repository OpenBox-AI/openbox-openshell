//! `openbox-governance-interceptor`: the front desk. Stamps the `OpenBox`
//! verdict middleware onto every new `OpenShell` sandbox, refuses policy
//! changes that weaken it, and records sandboxes for the AI Inventory.
//!
//! Required (unless `OPENBOX_FD_INSECURE=1`, local development only):
//!   `OPENBOX_FD_TLS_CERT` / `_KEY`    server certificate and key (PEM)
//!   `OPENBOX_FD_GATEWAY_ID`           tokens must come from `openshell-gateway:<id>`
//!   `OPENBOX_FD_GATEWAY_PUBLIC_KEY`   gateway JWT public key (PEM)
//!
//! Optional:
//!   `OPENBOX_FD_LISTEN`               governing registration (fail closed),
//!                                     default `127.0.0.1:50061`
//!   `OPENBOX_FD_INVENTORY_LISTEN`     inventory registration (fail open),
//!                                     default `127.0.0.1:50062`
//!   `OPENBOX_FD_AUDIENCE`             default `urn:openshell:extension:interceptor:openbox`
//!   `OPENBOX_FD_INVENTORY_AUDIENCE`   default
//!                                     `urn:openshell:extension:interceptor:openbox-inventory`
//!
//! AI Inventory (without `OPENBOX_BACKEND_URL`, inventory events are only
//! logged):
//!   `OPENBOX_BACKEND_URL`             backend base URL; sandboxes are recorded
//!                                     with the agent's workload token
//!   `OPENBOX_URL`, `OPENBOX_API_KEY_FILE`   Core, for the workload bootstrap
//!   `OPENBOX_WORKLOAD_KEY_FILE`, `OPENBOX_WORKLOAD_KID`   the RSA key
//!                                     registered with the agent
//!   `OPENBOX_GATEWAY_ENDPOINT`, `OPENBOX_GATEWAY_MTLS_DIR`   gateway API
//!                                     credential; enables reconciliation
//!   `OPENBOX_FD_RECONCILE_SECS`       reconciliation interval, default 60
//!
//! Sandbox sessions: with `OPENBOX_URL` and the workload identity above, the
//! front desk opens each sandbox's Core session on create and completes it on
//! delete (best effort, like the inventory). Without them it does neither.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use openbox_verdict_middleware::core_client::{CoreClient, CoreConfig, WorkloadIdentity};
use openbox_verdict_middleware::interceptor::{FrontDesk, Inventory, LogInventory, Role};
use openbox_verdict_middleware::inventory::{
    BackendInventory, GatewayLister, HttpInventory, SandboxLister,
};
use openbox_verdict_middleware::sessions::SessionLifecycle;
use openbox_verdict_middleware::token::TokenVerifier;
use openshell_core::proto::gateway_interceptor::v1::gateway_interceptor_server::GatewayInterceptorServer;
use tonic::transport::{Identity, Server, ServerTlsConfig};

const DEFAULT_AUDIENCE: &str = "urn:openshell:extension:interceptor:openbox";
const DEFAULT_INVENTORY_AUDIENCE: &str = "urn:openshell:extension:interceptor:openbox-inventory";

fn env(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn required(key: &str) -> Result<String, String> {
    env(key).ok_or_else(|| format!("{key} is required"))
}

#[tokio::main]
async fn main() -> ExitCode {
    // openshell-core enables aws-lc-rs next to our ring; choose explicitly.
    let _ = rustls::crypto::ring::default_provider().install_default();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("openbox-governance-interceptor: {error}");
            ExitCode::FAILURE
        }
    }
}

fn read_secret(key: &str) -> Result<String, String> {
    let path = required(key)?;
    std::fs::read_to_string(&path)
        .map(|text| text.trim().to_owned())
        .map_err(|error| format!("{key}: cannot read {path}: {error}"))
}

/// Core, for the workload token and sandbox sessions: set when `OPENBOX_URL`
/// is, and then the workload identity is required.
fn core_from_env() -> Result<Option<Arc<CoreClient>>, String> {
    let Some(base_url) = env("OPENBOX_URL") else {
        return Ok(None);
    };
    let workload = WorkloadIdentity::from_pem(
        &read_secret("OPENBOX_WORKLOAD_KEY_FILE")?,
        required("OPENBOX_WORKLOAD_KID")?,
    )
    .map_err(|_| "OPENBOX_WORKLOAD_KEY_FILE is not an RSA private key".to_owned())?;
    CoreClient::new(CoreConfig {
        base_url,
        api_key: read_secret("OPENBOX_API_KEY_FILE")?,
        signer: None,
        workload: Some(workload),
        timeout: Duration::from_secs(10),
        body_limit_bytes: 0,
    })
    .map(|core| Some(Arc::new(core)))
    .map_err(|error| error.to_string())
}

/// The inventory the front desk writes to: the backend when configured,
/// otherwise the service log.
fn inventory_from_env(
    gateway: Option<String>,
    core: Option<Arc<CoreClient>>,
) -> Result<Arc<dyn Inventory>, String> {
    let Some(backend_url) = env("OPENBOX_BACKEND_URL") else {
        eprintln!(
            "openbox-governance-interceptor: no OPENBOX_BACKEND_URL; inventory events are only logged"
        );
        return Ok(Arc::new(LogInventory));
    };
    let tokens = core.ok_or("OPENBOX_BACKEND_URL needs OPENBOX_URL for the workload token")?;
    let backend = BackendInventory::new(&backend_url, tokens)?;
    let lister: Option<Arc<dyn SandboxLister>> = match (
        env("OPENBOX_GATEWAY_ENDPOINT"),
        env("OPENBOX_GATEWAY_MTLS_DIR"),
    ) {
        (Some(endpoint), Some(dir)) => Some(Arc::new(GatewayLister::connect_lazy(
            &endpoint,
            &PathBuf::from(dir),
        )?)),
        (None, None) => {
            eprintln!(
                "openbox-governance-interceptor: no gateway credential; inventory is not reconciled, missed events stay missed"
            );
            None
        }
        _ => {
            return Err(
                "set both OPENBOX_GATEWAY_ENDPOINT and OPENBOX_GATEWAY_MTLS_DIR, or neither"
                    .to_owned(),
            );
        }
    };
    let interval: u64 = env("OPENBOX_FD_RECONCILE_SECS").map_or(Ok(60), |value| {
        value
            .parse()
            .ok()
            .filter(|seconds| *seconds > 0)
            .ok_or_else(|| "OPENBOX_FD_RECONCILE_SECS must be a positive number".to_owned())
    })?;
    Ok(Arc::new(HttpInventory::spawn(
        Arc::new(backend),
        lister,
        gateway,
        Duration::from_secs(interval),
    )))
}

fn address(key: &str, default: &str) -> Result<SocketAddr, String> {
    env(key)
        .unwrap_or_else(|| default.to_owned())
        .parse()
        .map_err(|_| format!("{key} must be host:port"))
}

fn verifier(
    insecure: bool,
    audience_key: &str,
    default_audience: &str,
) -> Result<Option<TokenVerifier>, String> {
    if insecure {
        return Ok(None);
    }
    let pem = std::fs::read_to_string(required("OPENBOX_FD_GATEWAY_PUBLIC_KEY")?)
        .map_err(|error| format!("OPENBOX_FD_GATEWAY_PUBLIC_KEY: {error}"))?;
    TokenVerifier::from_pem(
        &pem,
        &required("OPENBOX_FD_GATEWAY_ID")?,
        env(audience_key).unwrap_or_else(|| default_audience.to_owned()),
    )
    .map(Some)
    .map_err(|error| format!("gateway public key: {error}"))
}

fn tls(insecure: bool) -> Result<Option<ServerTlsConfig>, String> {
    if insecure {
        return Ok(None);
    }
    let cert = std::fs::read(required("OPENBOX_FD_TLS_CERT")?)
        .map_err(|error| format!("OPENBOX_FD_TLS_CERT: {error}"))?;
    let key = std::fs::read(required("OPENBOX_FD_TLS_KEY")?)
        .map_err(|error| format!("OPENBOX_FD_TLS_KEY: {error}"))?;
    Ok(Some(
        ServerTlsConfig::new().identity(Identity::from_pem(cert, key)),
    ))
}

async fn serve(
    role: Role,
    listen: SocketAddr,
    verifier: Option<TokenVerifier>,
    tls: Option<ServerTlsConfig>,
    inventory: Arc<dyn Inventory>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<(), String> {
    let mut server = Server::builder();
    if let Some(tls) = tls {
        server = server
            .tls_config(tls)
            .map_err(|error| format!("server TLS: {error}"))?;
    }
    eprintln!(
        "openbox-governance-interceptor: {role:?} registration on {}://{listen}",
        if verifier.is_some() { "https" } else { "http" }
    );
    let service = FrontDesk::new(role, verifier, inventory);
    server
        .add_service(GatewayInterceptorServer::new(service))
        .serve_with_shutdown(listen, async move {
            let _ = shutdown.changed().await;
        })
        .await
        .map_err(|error| format!("{role:?} server: {error}"))
}

async fn run() -> Result<(), String> {
    let insecure = env("OPENBOX_FD_INSECURE").as_deref() == Some("1");
    if insecure {
        eprintln!(
            "openbox-governance-interceptor: OPENBOX_FD_INSECURE=1, accepting unauthenticated plaintext calls"
        );
    }
    let govern = address("OPENBOX_FD_LISTEN", "127.0.0.1:50061")?;
    let inventory = address("OPENBOX_FD_INVENTORY_LISTEN", "127.0.0.1:50062")?;
    let govern_verifier = verifier(insecure, "OPENBOX_FD_AUDIENCE", DEFAULT_AUDIENCE)?;
    let inventory_verifier = verifier(
        insecure,
        "OPENBOX_FD_INVENTORY_AUDIENCE",
        DEFAULT_INVENTORY_AUDIENCE,
    )?;
    let core = core_from_env()?;
    let mut inventory_sink = inventory_from_env(env("OPENBOX_FD_GATEWAY_ID"), core.clone())?;
    if let Some(core) = core {
        inventory_sink = Arc::new(SessionLifecycle::new(inventory_sink, core));
    } else {
        eprintln!(
            "openbox-governance-interceptor: no OPENBOX_URL; sandbox sessions are not opened or closed"
        );
    }
    let (stop, stopped) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
        let _ = stop.send(true);
    });
    tokio::try_join!(
        serve(
            Role::Govern,
            govern,
            govern_verifier,
            tls(insecure)?,
            Arc::new(LogInventory),
            stopped.clone()
        ),
        serve(
            Role::Inventory,
            inventory,
            inventory_verifier,
            tls(insecure)?,
            inventory_sink,
            stopped
        ),
    )
    .map(|_| ())
}
