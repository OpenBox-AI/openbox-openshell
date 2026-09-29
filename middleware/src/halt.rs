//! Stops a halted sandbox through the `OpenShell` gateway API.
//!
//! HALT stops rather than deletes: the sandbox can be inspected and restarted,
//! and its security log survives for the evidence pipeline. `StopSandbox`
//! addresses a sandbox by name, and names can be reused, so the name is first
//! resolved and checked against the sandbox id from the evaluated request.

use std::path::Path;
use std::time::Duration;

use openshell_core::proto::open_shell_client::OpenShellClient;
use openshell_core::proto::{GetSandboxRequest, StopSandboxRequest, workspace_selector};
use openshell_core::{ObjectId as _, ObjectName as _};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

use crate::guard::SandboxStopper;

const STOP_TIMEOUT: Duration = Duration::from_secs(5);

/// Gateway client for sandbox stops. Uses a least-privileged mTLS identity
/// dedicated to `OpenBox` (see the bundle docs).
pub struct GatewayStopper {
    channel: Channel,
}

impl GatewayStopper {
    /// `mtls_dir` holds `ca.crt`, `tls.crt` and `tls.key`.
    pub fn connect_lazy(endpoint: &str, mtls_dir: &Path) -> Result<Self, String> {
        let read = |name: &str| {
            std::fs::read(mtls_dir.join(name))
                .map_err(|error| format!("cannot read {name}: {error}"))
        };
        let tls = ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(read("ca.crt")?))
            .identity(Identity::from_pem(read("tls.crt")?, read("tls.key")?));
        let channel = Endpoint::from_shared(endpoint.to_owned())
            .map_err(|error| format!("invalid gateway endpoint: {error}"))?
            .connect_timeout(STOP_TIMEOUT)
            .timeout(STOP_TIMEOUT)
            .tls_config(tls)
            .map_err(|error| format!("invalid gateway TLS config: {error}"))?
            .connect_lazy();
        Ok(Self { channel })
    }
}

#[tonic::async_trait]
impl SandboxStopper for GatewayStopper {
    async fn stop(
        &self,
        sandbox_id: &str,
        sandbox_name: &str,
        workspace: &str,
    ) -> Result<(), String> {
        let workspace = if workspace.is_empty() {
            "default"
        } else {
            workspace
        };
        let mut client = OpenShellClient::new(self.channel.clone());
        let current = client
            .get_sandbox(GetSandboxRequest {
                name: sandbox_name.to_owned(),
                workspace_scope: Some(workspace_selector(workspace)),
            })
            .await
            .map_err(|status| format!("lookup failed: {}", status.code()))?
            .into_inner()
            .sandbox
            .ok_or("lookup returned no sandbox")?;
        if current.object_id() != sandbox_id || current.object_name() != sandbox_name {
            return Err("name now refers to a different sandbox; not stopping it".to_owned());
        }
        client
            .stop_sandbox(StopSandboxRequest {
                name: sandbox_name.to_owned(),
                workspace_scope: Some(workspace_selector(workspace)),
                ..StopSandboxRequest::default()
            })
            .await
            .map(|_| ())
            .map_err(|status| format!("stop failed: {}", status.code()))
    }
}

/// Used when no gateway credential is configured: a halted sandbox is still
/// cut off, because every later request from it is denied.
pub struct DenyOnlyStopper;

#[tonic::async_trait]
impl SandboxStopper for DenyOnlyStopper {
    async fn stop(&self, _: &str, _: &str, _: &str) -> Result<(), String> {
        Err(
            "no gateway credential configured; halt is enforced by denying all further traffic"
                .to_owned(),
        )
    }
}
