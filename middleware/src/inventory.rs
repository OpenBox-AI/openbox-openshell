//! Keeps the `OpenBox` AI Inventory in step with the sandboxes on a gateway.
//!
//! Every sandbox is one row in the backend's `agent_runtime_environments`,
//! written with the agent's Keycloak workload token. Two paths feed it:
//!
//! - **Events.** The front desk's `post_commit` hooks hand `CreateSandbox`
//!   and `DeleteSandbox` results to [`HttpInventory`], which queues them for
//!   one worker, so the gateway never waits on the backend and events keep
//!   their order.
//! - **Reconciliation.** `post_commit` is best effort and fail open, so a
//!   worker pass also lists the gateway's sandboxes, writes each one, and
//!   deletes rows whose sandbox is gone. `UpdateConfig` results carry no
//!   sandbox id, so a policy change triggers a pass instead of a write.
//!
//! A failed gateway listing deletes nothing: an empty list must never be
//! read as "every sandbox is gone".

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use openshell_core::proto::open_shell_client::OpenShellClient;
use openshell_core::proto::{ListSandboxesRequest, Sandbox, all_workspaces_selector};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::mpsc;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

use crate::core_client::CoreClient;
use crate::interceptor::{Inventory, InventoryEvent};

const RUNTIME_ENVIRONMENTS_PATH: &str = "/api/v3/runtime-environments";
const WORKLOAD_TOKEN_HEADER: &str = "X-OpenBox-Workload-Token";
const BACKEND_TIMEOUT: Duration = Duration::from_secs(10);
const GATEWAY_TIMEOUT: Duration = Duration::from_secs(10);
const LIST_PAGE_SIZE: i32 = 500;
/// Events waiting for the worker. A full queue drops the event; the next
/// reconciliation pass repairs it.
const QUEUE_DEPTH: usize = 1024;

/// One sandbox as the backend stores it.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeEnvironment {
    #[serde(skip)]
    pub external_id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<u64>,
    pub labels: BTreeMap<String, String>,
}

impl RuntimeEnvironment {
    /// From a `CreateSandboxResponse` as `post_commit` delivers it (`ProtoJSON`).
    pub fn from_create_response(response: &Value, gateway: Option<&str>) -> Option<Self> {
        let sandbox = response.get("sandbox")?;
        let text = |pointer: &str| {
            sandbox
                .pointer(pointer)
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
        };
        let external_id = text("/metadata/id")?;
        let labels = sandbox
            .pointer("/metadata/labels")
            .and_then(Value::as_object)
            .map(|labels| {
                labels
                    .iter()
                    .filter_map(|(key, value)| Some((key.clone(), value.as_str()?.to_owned())))
                    .collect()
            })
            .unwrap_or_default();
        Some(Self {
            name: text("/metadata/name").unwrap_or_else(|| external_id.clone()),
            external_id,
            gateway: gateway.map(str::to_owned),
            image: text("/spec/template/image"),
            policy_version: sandbox
                .pointer("/status/currentPolicyVersion")
                .and_then(Value::as_u64)
                .filter(|version| *version > 0),
            labels,
        })
    }

    /// From a sandbox the gateway lists.
    pub fn from_sandbox(sandbox: &Sandbox, gateway: Option<&str>) -> Option<Self> {
        let metadata = sandbox.metadata.as_ref()?;
        if metadata.id.is_empty() {
            return None;
        }
        Some(Self {
            external_id: metadata.id.clone(),
            name: if metadata.name.is_empty() {
                metadata.id.clone()
            } else {
                metadata.name.clone()
            },
            gateway: gateway.map(str::to_owned),
            image: sandbox
                .spec
                .as_ref()
                .and_then(|spec| spec.template.as_ref())
                .map(|template| template.image.clone())
                .filter(|image| !image.is_empty()),
            policy_version: sandbox
                .status
                .as_ref()
                .map(|status| u64::from(status.current_policy_version))
                .filter(|version| *version > 0),
            labels: metadata
                .labels
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
        })
    }
}

/// Where runtime environments are stored.
#[tonic::async_trait]
pub trait InventoryBackend: Send + Sync + 'static {
    async fn upsert(&self, environment: &RuntimeEnvironment) -> Result<(), String>;
    async fn delete(&self, external_id: &str) -> Result<(), String>;
    /// Ids of the rows this workload currently has active.
    async fn list_active(&self) -> Result<Vec<String>, String>;
}

/// Where the sandboxes really are.
#[tonic::async_trait]
pub trait SandboxLister: Send + Sync + 'static {
    async fn list(&self) -> Result<Vec<Sandbox>, String>;
}

/// The backend's runtime-environment API, authenticated with the agent's
/// workload token from [`CoreClient`].
pub struct BackendInventory {
    http: reqwest::Client,
    base_url: String,
    tokens: Arc<CoreClient>,
}

impl BackendInventory {
    pub fn new(base_url: &str, tokens: Arc<CoreClient>) -> Result<Self, String> {
        let base_url = base_url.trim_end_matches('/').to_owned();
        let http = reqwest::Client::builder()
            .timeout(BACKEND_TIMEOUT)
            .https_only(!base_url.starts_with("http://"))
            .build()
            .map_err(|error| format!("backend client: {error}"))?;
        Ok(Self {
            http,
            base_url,
            tokens,
        })
    }

    async fn send(&self, request: reqwest::RequestBuilder) -> Result<reqwest::Response, String> {
        let token = self
            .tokens
            .current_workload_token()
            .await
            .ok_or("no workload identity configured")?
            .map_err(|error| format!("workload token: {error}"))?;
        let response = request
            .header(WORKLOAD_TOKEN_HEADER, token)
            .send()
            .await
            .map_err(|_| "backend unreachable or timed out".to_owned())?;
        let status = response.status();
        if status.as_u16() == 401 {
            // Rotated or revoked identity: fetch a fresh token next time.
            self.tokens.forget_workload_token().await;
        }
        if status.is_success() {
            Ok(response)
        } else {
            Err(format!("backend returned HTTP {}", status.as_u16()))
        }
    }

    fn url(&self, external_id: &str) -> String {
        format!(
            "{}{RUNTIME_ENVIRONMENTS_PATH}/{}",
            self.base_url,
            percent_encode(external_id)
        )
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
struct ActiveRow {
    external_id: String,
}

/// The backend wraps every response as `{"status": 200, "data": ...}`.
#[derive(Deserialize)]
struct Envelope<T> {
    data: T,
}

/// External ids from a `GET` of the runtime environments; the backend
/// already filters to active rows.
fn parse_active_list(body: &[u8]) -> Result<Vec<String>, String> {
    let envelope: Envelope<Vec<ActiveRow>> =
        serde_json::from_slice(body).map_err(|_| "backend list was malformed".to_owned())?;
    Ok(envelope
        .data
        .into_iter()
        .map(|row| row.external_id)
        .collect())
}

#[tonic::async_trait]
impl InventoryBackend for BackendInventory {
    async fn upsert(&self, environment: &RuntimeEnvironment) -> Result<(), String> {
        self.send(
            self.http
                .put(self.url(&environment.external_id))
                .json(environment),
        )
        .await
        .map(|_| ())
    }

    async fn delete(&self, external_id: &str) -> Result<(), String> {
        self.send(self.http.delete(self.url(external_id)))
            .await
            .map(|_| ())
    }

    async fn list_active(&self) -> Result<Vec<String>, String> {
        let body = self
            .send(
                self.http
                    .get(format!("{}{RUNTIME_ENVIRONMENTS_PATH}", self.base_url)),
            )
            .await?
            .bytes()
            .await
            .map_err(|_| "backend list was malformed".to_owned())?;
        parse_active_list(&body)
    }
}

/// Lists sandboxes over the gateway API with an mTLS identity, the same kind
/// the door guard uses to stop halted sandboxes.
pub struct GatewayLister {
    channel: Channel,
}

impl GatewayLister {
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
            .connect_timeout(GATEWAY_TIMEOUT)
            .timeout(GATEWAY_TIMEOUT)
            .tls_config(tls)
            .map_err(|error| format!("invalid gateway TLS config: {error}"))?
            .connect_lazy();
        Ok(Self { channel })
    }
}

#[tonic::async_trait]
impl SandboxLister for GatewayLister {
    async fn list(&self) -> Result<Vec<Sandbox>, String> {
        let mut client = OpenShellClient::new(self.channel.clone());
        let mut sandboxes = Vec::new();
        let mut page_token = String::new();
        loop {
            let page = client
                .list_sandboxes(ListSandboxesRequest {
                    workspace_scope: Some(all_workspaces_selector()),
                    page_size: LIST_PAGE_SIZE,
                    page_token: page_token.clone(),
                    label_selector: String::new(),
                })
                .await
                .map_err(|status| format!("gateway list failed: {}", status.code()))?
                .into_inner();
            sandboxes.extend(page.sandboxes);
            if page.next_page_token.is_empty() {
                return Ok(sandboxes);
            }
            page_token = page.next_page_token;
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReconcileStats {
    pub written: usize,
    pub deleted: usize,
    pub failed: usize,
}

/// One pass: write every sandbox the gateway has, then delete the rows whose
/// sandbox is gone. Nothing is deleted unless both lists were read.
pub async fn reconcile(
    backend: &dyn InventoryBackend,
    lister: &dyn SandboxLister,
    gateway: Option<&str>,
) -> Result<ReconcileStats, String> {
    let sandboxes = lister.list().await?;
    let mut stats = ReconcileStats::default();
    let mut present = BTreeSet::new();
    for sandbox in &sandboxes {
        let Some(environment) = RuntimeEnvironment::from_sandbox(sandbox, gateway) else {
            continue;
        };
        present.insert(environment.external_id.clone());
        match backend.upsert(&environment).await {
            Ok(()) => stats.written += 1,
            Err(error) => {
                stats.failed += 1;
                eprintln!(
                    "openbox: inventory reconcile write failed id={}: {error}",
                    environment.external_id
                );
            }
        }
    }
    for external_id in backend.list_active().await? {
        if present.contains(&external_id) {
            continue;
        }
        match backend.delete(&external_id).await {
            Ok(()) => stats.deleted += 1,
            Err(error) => {
                stats.failed += 1;
                eprintln!("openbox: inventory reconcile delete failed id={external_id}: {error}");
            }
        }
    }
    Ok(stats)
}

enum Command {
    Upsert(RuntimeEnvironment),
    Delete(String),
    Reconcile,
}

/// The front desk's [`Inventory`] when a backend is configured.
pub struct HttpInventory {
    queue: mpsc::Sender<Command>,
    gateway: Option<String>,
}

impl HttpInventory {
    /// Starts the worker. With a `lister`, it also reconciles once at start
    /// and then every `interval`.
    pub fn spawn(
        backend: Arc<dyn InventoryBackend>,
        lister: Option<Arc<dyn SandboxLister>>,
        gateway: Option<String>,
        interval: Duration,
    ) -> Self {
        let (queue, mut commands) = mpsc::channel(QUEUE_DEPTH);
        let worker_gateway = gateway.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                let command = tokio::select! {
                    command = commands.recv() => match command {
                        Some(command) => command,
                        None => return,
                    },
                    _ = ticker.tick(), if lister.is_some() => Command::Reconcile,
                };
                run(
                    command,
                    backend.as_ref(),
                    lister.as_deref(),
                    worker_gateway.as_deref(),
                )
                .await;
            }
        });
        Self { queue, gateway }
    }

    fn enqueue(&self, command: Command) -> Result<(), String> {
        self.queue
            .try_send(command)
            .map_err(|_| "inventory queue full; the next reconciliation repairs it".to_owned())
    }
}

async fn run(
    command: Command,
    backend: &dyn InventoryBackend,
    lister: Option<&dyn SandboxLister>,
    gateway: Option<&str>,
) {
    match command {
        Command::Upsert(environment) => match backend.upsert(&environment).await {
            Ok(()) => eprintln!(
                "openbox: inventory recorded sandbox={} id={}",
                environment.name, environment.external_id
            ),
            Err(error) => eprintln!(
                "openbox: inventory write failed id={}: {error}",
                environment.external_id
            ),
        },
        Command::Delete(external_id) => match backend.delete(&external_id).await {
            Ok(()) => eprintln!("openbox: inventory deleted id={external_id}"),
            Err(error) => eprintln!("openbox: inventory delete failed id={external_id}: {error}"),
        },
        Command::Reconcile => {
            let Some(lister) = lister else { return };
            match reconcile(backend, lister, gateway).await {
                Ok(stats) => eprintln!(
                    "openbox: inventory reconciled written={} deleted={} failed={}",
                    stats.written, stats.deleted, stats.failed
                ),
                Err(error) => eprintln!("openbox: inventory reconcile skipped: {error}"),
            }
        }
    }
}

#[tonic::async_trait]
impl Inventory for HttpInventory {
    async fn record(&self, event: InventoryEvent) -> Result<(), String> {
        match event {
            InventoryEvent::Created { sandbox } => {
                let environment =
                    RuntimeEnvironment::from_create_response(&sandbox, self.gateway.as_deref())
                        .ok_or("CreateSandbox result carries no sandbox id")?;
                self.enqueue(Command::Upsert(environment))
            }
            // UpdateConfigResponse names no sandbox: re-read them all.
            InventoryEvent::PolicyChanged { .. } => self.enqueue(Command::Reconcile),
            InventoryEvent::Deleted { response } => {
                // Empty for ALREADY_ABSENT: nothing was deleted by this call.
                match response.get("sandboxId").and_then(Value::as_str) {
                    Some(id) if !id.is_empty() => self.enqueue(Command::Delete(id.to_owned())),
                    _ => Ok(()),
                }
            }
        }
    }
}

/// Encodes a path segment. Sandbox ids are plain, but never trust that.
fn percent_encode(segment: &str) -> String {
    segment
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                char::from(byte).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::datamodel::v1::ObjectMeta;
    use openshell_core::proto::{SandboxSpec, SandboxStatus, SandboxTemplate};
    use serde_json::json;
    use std::sync::Mutex;

    #[derive(Default)]
    struct FakeBackend {
        rows: Mutex<BTreeMap<String, RuntimeEnvironment>>,
        calls: Mutex<Vec<String>>,
        fail_list: bool,
        fail_writes: bool,
    }

    #[tonic::async_trait]
    impl InventoryBackend for FakeBackend {
        async fn upsert(&self, environment: &RuntimeEnvironment) -> Result<(), String> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("put {}", environment.external_id));
            if self.fail_writes {
                return Err("down".to_owned());
            }
            self.rows
                .lock()
                .unwrap()
                .insert(environment.external_id.clone(), environment.clone());
            Ok(())
        }

        async fn delete(&self, external_id: &str) -> Result<(), String> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("delete {external_id}"));
            self.rows.lock().unwrap().remove(external_id);
            Ok(())
        }

        async fn list_active(&self) -> Result<Vec<String>, String> {
            if self.fail_list {
                return Err("down".to_owned());
            }
            Ok(self.rows.lock().unwrap().keys().cloned().collect())
        }
    }

    struct FakeLister(Result<Vec<Sandbox>, String>);

    #[tonic::async_trait]
    impl SandboxLister for FakeLister {
        async fn list(&self) -> Result<Vec<Sandbox>, String> {
            self.0.clone()
        }
    }

    fn sandbox(id: &str, name: &str, version: u32) -> Sandbox {
        Sandbox {
            metadata: Some(ObjectMeta {
                id: id.to_owned(),
                name: name.to_owned(),
                labels: [("openbox.ai/governed".to_owned(), "true".to_owned())].into(),
                ..ObjectMeta::default()
            }),
            spec: Some(SandboxSpec {
                template: Some(SandboxTemplate {
                    image: "ghcr.io/acme/agent:1".to_owned(),
                    ..SandboxTemplate::default()
                }),
                ..SandboxSpec::default()
            }),
            status: Some(SandboxStatus {
                current_policy_version: version,
                ..SandboxStatus::default()
            }),
            ..Sandbox::default()
        }
    }

    fn environment(id: &str) -> RuntimeEnvironment {
        RuntimeEnvironment {
            external_id: id.to_owned(),
            name: id.to_owned(),
            ..RuntimeEnvironment::default()
        }
    }

    #[test]
    fn reads_a_create_response() {
        let response = json!({"sandbox": {
            "metadata": {"id": "sbx-1", "name": "research", "labels": {"team": "a"}},
            "spec": {"template": {"image": "ghcr.io/acme/agent:1"}},
            "status": {"currentPolicyVersion": 2}
        }});
        let environment =
            RuntimeEnvironment::from_create_response(&response, Some("gw-1")).unwrap();
        assert_eq!(
            environment,
            RuntimeEnvironment {
                external_id: "sbx-1".to_owned(),
                name: "research".to_owned(),
                gateway: Some("gw-1".to_owned()),
                image: Some("ghcr.io/acme/agent:1".to_owned()),
                policy_version: Some(2),
                labels: [("team".to_owned(), "a".to_owned())].into(),
            }
        );
        assert_eq!(
            serde_json::to_value(&environment).unwrap(),
            json!({
                "name": "research",
                "gateway": "gw-1",
                "image": "ghcr.io/acme/agent:1",
                "policyVersion": 2,
                "labels": {"team": "a"}
            })
        );
    }

    #[test]
    fn a_create_response_without_an_id_is_not_recorded() {
        assert!(RuntimeEnvironment::from_create_response(&json!({"sandbox": {}}), None).is_none());
        assert!(RuntimeEnvironment::from_create_response(&json!({}), None).is_none());
    }

    #[test]
    fn reads_a_listed_sandbox() {
        let environment = RuntimeEnvironment::from_sandbox(&sandbox("sbx-2", "", 0), None).unwrap();
        assert_eq!(environment.name, "sbx-2");
        assert_eq!(environment.policy_version, None);
        assert_eq!(environment.image.as_deref(), Some("ghcr.io/acme/agent:1"));
    }

    #[tokio::test]
    async fn reconcile_writes_present_and_deletes_gone() {
        let backend = FakeBackend::default();
        backend
            .rows
            .lock()
            .unwrap()
            .insert("gone".to_owned(), environment("gone"));
        backend
            .rows
            .lock()
            .unwrap()
            .insert("kept".to_owned(), environment("kept"));
        let lister = FakeLister(Ok(vec![sandbox("kept", "k", 3), sandbox("new", "n", 1)]));

        let stats = reconcile(&backend, &lister, Some("gw-1")).await.unwrap();

        assert_eq!(
            stats,
            ReconcileStats {
                written: 2,
                deleted: 1,
                failed: 0
            }
        );
        let rows = backend.rows.lock().unwrap();
        assert_eq!(rows.keys().collect::<Vec<_>>(), ["kept", "new"]);
        assert_eq!(rows["kept"].policy_version, Some(3));
    }

    #[tokio::test]
    async fn a_failed_gateway_list_deletes_nothing() {
        let backend = FakeBackend::default();
        backend
            .rows
            .lock()
            .unwrap()
            .insert("a".to_owned(), environment("a"));
        let lister = FakeLister(Err("gateway list failed: Unavailable".to_owned()));

        assert!(reconcile(&backend, &lister, None).await.is_err());
        assert!(backend.calls.lock().unwrap().is_empty());
        assert!(backend.rows.lock().unwrap().contains_key("a"));
    }

    #[tokio::test]
    async fn a_failed_backend_list_deletes_nothing() {
        let backend = FakeBackend {
            fail_list: true,
            ..FakeBackend::default()
        };
        let lister = FakeLister(Ok(vec![sandbox("a", "a", 1)]));

        assert!(reconcile(&backend, &lister, None).await.is_err());
        assert!(
            backend
                .calls
                .lock()
                .unwrap()
                .iter()
                .all(|call| call.starts_with("put"))
        );
    }

    #[tokio::test]
    async fn write_failures_are_counted_not_fatal() {
        let backend = FakeBackend {
            fail_writes: true,
            ..FakeBackend::default()
        };
        let lister = FakeLister(Ok(vec![sandbox("a", "a", 1), sandbox("b", "b", 1)]));

        let stats = reconcile(&backend, &lister, None).await.unwrap();
        assert_eq!(stats.failed, 2);
    }

    async fn settle(backend: &FakeBackend, calls: usize) -> Vec<String> {
        for _ in 0..200 {
            let seen = backend.calls.lock().unwrap().clone();
            if seen.len() >= calls {
                return seen;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        backend.calls.lock().unwrap().clone()
    }

    #[tokio::test]
    async fn events_reach_the_backend_in_order() {
        let backend = Arc::new(FakeBackend::default());
        let inventory = HttpInventory::spawn(
            backend.clone(),
            None,
            Some("gw-1".to_owned()),
            Duration::from_secs(3600),
        );
        inventory
            .record(InventoryEvent::Created {
                sandbox: json!({"sandbox": {"metadata": {"id": "sbx-1", "name": "r"}}}),
            })
            .await
            .unwrap();
        inventory
            .record(InventoryEvent::Deleted {
                response: json!({"outcome": "DELETION_OUTCOME_DELETED", "sandboxId": "sbx-1"}),
            })
            .await
            .unwrap();
        // ALREADY_ABSENT carries no id and deletes nothing.
        inventory
            .record(InventoryEvent::Deleted {
                response: json!({"outcome": "DELETION_OUTCOME_ALREADY_ABSENT", "sandboxId": ""}),
            })
            .await
            .unwrap();

        assert_eq!(settle(&backend, 2).await, ["put sbx-1", "delete sbx-1"]);
    }

    #[tokio::test]
    async fn a_policy_change_triggers_a_reconcile() {
        let backend = Arc::new(FakeBackend::default());
        let lister: Arc<dyn SandboxLister> =
            Arc::new(FakeLister(Ok(vec![sandbox("sbx-1", "r", 4)])));
        let inventory = HttpInventory::spawn(
            backend.clone(),
            Some(lister),
            None,
            Duration::from_secs(3600),
        );
        // The first tick reconciles at start; wait for it, then change policy.
        settle(&backend, 1).await;
        inventory
            .record(InventoryEvent::PolicyChanged {
                request: json!({"version": 4, "policyHash": "abc"}),
            })
            .await
            .unwrap();

        assert_eq!(settle(&backend, 2).await, ["put sbx-1", "put sbx-1"]);
    }

    #[tokio::test]
    async fn a_create_without_an_id_is_reported() {
        let inventory = HttpInventory::spawn(
            Arc::new(FakeBackend::default()),
            None,
            None,
            Duration::from_secs(3600),
        );
        assert!(
            inventory
                .record(InventoryEvent::Created {
                    sandbox: json!({"sandbox": {}})
                })
                .await
                .is_err()
        );
    }

    #[test]
    fn reads_the_backend_list_envelope() {
        // The shape the backend returns, trimmed to the fields that matter.
        let body = json!({
            "status": 200,
            "data": [
                {"id": "7538b4b6", "external_id": "sbx-1", "status": "active"},
                {"id": "9c0e2f11", "external_id": "sbx-2", "status": "active"}
            ]
        });
        assert_eq!(
            parse_active_list(body.to_string().as_bytes()).unwrap(),
            ["sbx-1", "sbx-2"]
        );
        assert!(
            parse_active_list(br#"{"status":200,"data":[]}"#)
                .unwrap()
                .is_empty()
        );
        // A bare array is not what the backend sends.
        assert!(parse_active_list(br#"[{"external_id":"sbx-1"}]"#).is_err());
    }

    #[test]
    fn encodes_path_segments() {
        assert_eq!(percent_encode("sbx-1.a_b~"), "sbx-1.a_b~");
        assert_eq!(percent_encode("a/b c"), "a%2Fb%20c");
    }
}
