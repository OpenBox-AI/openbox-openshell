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

use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;

use openbox_verdict_middleware::interceptor::{FrontDesk, LogInventory, Role};
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
    let service = FrontDesk::new(role, verifier, Arc::new(LogInventory));
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
            stopped.clone()
        ),
        serve(
            Role::Inventory,
            inventory,
            inventory_verifier,
            tls(insecure)?,
            stopped
        ),
    )
    .map(|_| ())
}
