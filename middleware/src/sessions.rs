//! Sandbox sessions in `OpenBox` Core, opened on create and closed on delete.
//!
//! Each `OpenShell` sandbox is one Core session. The front desk opens it when
//! the gateway creates the sandbox and closes it when the gateway deletes it,
//! so a session has a start, every governed request in between, and an end
//! Core can seal.
//!
//! The verdict middleware still opens the session on a sandbox's first
//! request, so a missed create costs nothing: `WorkflowStarted` is
//! idempotent and whichever arrives second is replayed. A missed delete
//! leaves the session open, as before this module existed.
//!
//! The session's input is the sandbox as created (name, image, policy
//! version, labels); its duration comes from the start time the front desk
//! keeps in the shared store, so any replica can close it.
//!
//! Like the inventory, this runs in `post_commit` and is best effort. Core
//! calls run in the background so a slow Core never holds up the gateway.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

use crate::core_client::CoreClient;
use crate::interceptor::{Inventory, InventoryEvent};
use crate::inventory::RuntimeEnvironment;
use crate::store::{SharedStore, session_key};

/// The two Core calls a sandbox's lifecycle needs.
#[tonic::async_trait]
pub trait SessionGovernance: Send + Sync + 'static {
    async fn start(
        &self,
        sandbox_id: &str,
        sandbox_name: &str,
        input: &Value,
    ) -> Result<(), String>;
    async fn end(&self, sandbox_id: &str, duration_ms: Option<u64>) -> Result<(), String>;
}

#[tonic::async_trait]
impl SessionGovernance for CoreClient {
    async fn start(
        &self,
        sandbox_id: &str,
        sandbox_name: &str,
        input: &Value,
    ) -> Result<(), String> {
        self.start_session_with(sandbox_id, sandbox_name, Some(input))
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    async fn end(&self, sandbox_id: &str, duration_ms: Option<u64>) -> Result<(), String> {
        self.end_session(sandbox_id, duration_ms)
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }
}

/// Opens and closes Core sessions on the way to the inventory, which still
/// receives every event.
pub struct SessionLifecycle {
    inventory: Arc<dyn Inventory>,
    core: Arc<dyn SessionGovernance>,
    store: Arc<dyn SharedStore>,
    gateway: Option<String>,
}

impl SessionLifecycle {
    pub fn new(
        inventory: Arc<dyn Inventory>,
        core: Arc<dyn SessionGovernance>,
        store: Arc<dyn SharedStore>,
        gateway: Option<String>,
    ) -> Self {
        Self {
            inventory,
            core,
            store,
            gateway,
        }
    }
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

#[tonic::async_trait]
impl Inventory for SessionLifecycle {
    async fn record(&self, event: InventoryEvent) -> Result<(), String> {
        match &event {
            InventoryEvent::Created { sandbox } => {
                let id = text(sandbox, "/sandbox/metadata/id");
                if !id.is_empty() {
                    let name = text(sandbox, "/sandbox/metadata/name");
                    let mut input =
                        RuntimeEnvironment::from_create_response(sandbox, self.gateway.as_deref())
                            .and_then(|environment| serde_json::to_value(environment).ok())
                            .unwrap_or_else(|| json!({}));
                    input["sandboxId"] = json!(id);
                    if let Err(error) = self
                        .store
                        .set(&session_key(&id), &unix_millis().to_string(), None)
                        .await
                    {
                        eprintln!(
                            "openbox: session start time for sandbox_id={id} not kept, its end carries no duration: {error}"
                        );
                    }
                    let core = Arc::clone(&self.core);
                    tokio::spawn(async move {
                        match core.start(&id, &name, &input).await {
                            Ok(()) => eprintln!("openbox: session started sandbox_id={id}"),
                            Err(error) => {
                                eprintln!("openbox: session start failed sandbox_id={id}: {error}");
                            }
                        }
                    });
                }
            }
            // Empty for ALREADY_ABSENT: nothing was deleted by this call.
            InventoryEvent::Deleted { response } => {
                let id = text(response, "/sandboxId");
                if !id.is_empty() {
                    let duration = self
                        .store
                        .take(&session_key(&id))
                        .await
                        .unwrap_or_default()
                        .and_then(|started| started.parse::<u64>().ok())
                        .map(|started| unix_millis().saturating_sub(started));
                    let core = Arc::clone(&self.core);
                    tokio::spawn(async move {
                        match core.end(&id, duration).await {
                            Ok(()) => eprintln!("openbox: session completed sandbox_id={id}"),
                            Err(error) => {
                                eprintln!("openbox: session end failed sandbox_id={id}: {error}");
                            }
                        }
                    });
                }
            }
            InventoryEvent::PolicyChanged { .. } => {}
        }
        self.inventory.record(event).await
    }
}

fn text(value: &Value, pointer: &str) -> String {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemoryStore;
    use std::sync::Mutex;
    use std::time::Duration;
    use tokio::sync::mpsc;

    struct FakeCore {
        calls: mpsc::UnboundedSender<String>,
        fail: bool,
    }

    #[tonic::async_trait]
    impl SessionGovernance for FakeCore {
        async fn start(
            &self,
            sandbox_id: &str,
            sandbox_name: &str,
            input: &Value,
        ) -> Result<(), String> {
            self.calls
                .send(format!(
                    "start {sandbox_id} {sandbox_name} image={}",
                    input["image"].as_str().unwrap_or("-")
                ))
                .unwrap();
            if self.fail {
                Err("down".to_owned())
            } else {
                Ok(())
            }
        }

        async fn end(&self, sandbox_id: &str, duration_ms: Option<u64>) -> Result<(), String> {
            self.calls
                .send(format!("end {sandbox_id} timed={}", duration_ms.is_some()))
                .unwrap();
            if self.fail {
                Err("down".to_owned())
            } else {
                Ok(())
            }
        }
    }

    #[derive(Default)]
    struct FakeInventory(Mutex<Vec<InventoryEvent>>);

    #[tonic::async_trait]
    impl Inventory for FakeInventory {
        async fn record(&self, event: InventoryEvent) -> Result<(), String> {
            self.0.lock().unwrap().push(event);
            Ok(())
        }
    }

    fn lifecycle(
        fail: bool,
    ) -> (
        SessionLifecycle,
        Arc<FakeInventory>,
        mpsc::UnboundedReceiver<String>,
    ) {
        let (calls, received) = mpsc::unbounded_channel();
        let inventory = Arc::new(FakeInventory::default());
        let sink: Arc<dyn Inventory> = inventory.clone();
        let sessions = SessionLifecycle::new(
            sink,
            Arc::new(FakeCore { calls, fail }),
            Arc::new(MemoryStore::default()),
            Some("gw-1".to_owned()),
        );
        (sessions, inventory, received)
    }

    async fn next(received: &mut mpsc::UnboundedReceiver<String>) -> Option<String> {
        tokio::time::timeout(Duration::from_secs(1), received.recv())
            .await
            .ok()
            .flatten()
    }

    #[tokio::test]
    async fn create_opens_and_delete_closes_the_session() {
        let (sessions, inventory, mut received) = lifecycle(false);
        let created = InventoryEvent::Created {
            sandbox: json!({"sandbox": {
                "metadata": {"id": "sbx-1", "name": "research"},
                "spec": {"template": {"image": "ubuntu:24.04"}},
            }}),
        };
        let deleted = InventoryEvent::Deleted {
            response: json!({"sandboxId": "sbx-1"}),
        };
        sessions.record(created.clone()).await.unwrap();
        assert_eq!(
            next(&mut received).await.as_deref(),
            Some("start sbx-1 research image=ubuntu:24.04")
        );
        sessions.record(deleted.clone()).await.unwrap();
        assert_eq!(
            next(&mut received).await.as_deref(),
            Some("end sbx-1 timed=true"),
            "the end carries the time since the create"
        );
        assert_eq!(*inventory.0.lock().unwrap(), [created, deleted]);
    }

    #[tokio::test]
    async fn no_id_means_no_core_call() {
        let (sessions, inventory, mut received) = lifecycle(false);
        // ALREADY_ABSENT delete, and a create result without an id.
        sessions
            .record(InventoryEvent::Deleted {
                response: json!({"sandboxId": ""}),
            })
            .await
            .unwrap();
        sessions
            .record(InventoryEvent::Created { sandbox: json!({}) })
            .await
            .unwrap();
        sessions
            .record(InventoryEvent::PolicyChanged {
                request: json!({"version": 2}),
            })
            .await
            .unwrap();
        assert_eq!(next(&mut received).await, None);
        assert_eq!(inventory.0.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn a_core_failure_still_reaches_the_inventory() {
        let (sessions, inventory, mut received) = lifecycle(true);
        sessions
            .record(InventoryEvent::Deleted {
                response: json!({"sandboxId": "sbx-2"}),
            })
            .await
            .unwrap();
        assert_eq!(
            next(&mut received).await.as_deref(),
            Some("end sbx-2 timed=false")
        );
        assert_eq!(inventory.0.lock().unwrap().len(), 1);
    }
}
