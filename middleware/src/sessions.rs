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
//! Like the inventory, this runs in `post_commit` and is best effort. Core
//! calls run in the background so a slow Core never holds up the gateway.

use std::sync::Arc;

use serde_json::Value;

use crate::core_client::CoreClient;
use crate::interceptor::{Inventory, InventoryEvent};

/// The two Core calls a sandbox's lifecycle needs.
#[tonic::async_trait]
pub trait SessionGovernance: Send + Sync + 'static {
    async fn start(&self, sandbox_id: &str, sandbox_name: &str) -> Result<(), String>;
    async fn end(&self, sandbox_id: &str) -> Result<(), String>;
}

#[tonic::async_trait]
impl SessionGovernance for CoreClient {
    async fn start(&self, sandbox_id: &str, sandbox_name: &str) -> Result<(), String> {
        self.start_session(sandbox_id, sandbox_name)
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    async fn end(&self, sandbox_id: &str) -> Result<(), String> {
        self.end_session(sandbox_id)
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
}

impl SessionLifecycle {
    pub fn new(inventory: Arc<dyn Inventory>, core: Arc<dyn SessionGovernance>) -> Self {
        Self { inventory, core }
    }
}

#[tonic::async_trait]
impl Inventory for SessionLifecycle {
    async fn record(&self, event: InventoryEvent) -> Result<(), String> {
        match &event {
            InventoryEvent::Created { sandbox } => {
                let id = text(sandbox, "/sandbox/metadata/id");
                if !id.is_empty() {
                    let name = text(sandbox, "/sandbox/metadata/name");
                    let core = Arc::clone(&self.core);
                    tokio::spawn(async move {
                        match core.start(&id, &name).await {
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
                    let core = Arc::clone(&self.core);
                    tokio::spawn(async move {
                        match core.end(&id).await {
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
    use serde_json::json;
    use std::sync::Mutex;
    use std::time::Duration;
    use tokio::sync::mpsc;

    struct FakeCore {
        calls: mpsc::UnboundedSender<String>,
        fail: bool,
    }

    #[tonic::async_trait]
    impl SessionGovernance for FakeCore {
        async fn start(&self, sandbox_id: &str, sandbox_name: &str) -> Result<(), String> {
            self.calls
                .send(format!("start {sandbox_id} {sandbox_name}"))
                .unwrap();
            if self.fail {
                Err("down".to_owned())
            } else {
                Ok(())
            }
        }

        async fn end(&self, sandbox_id: &str) -> Result<(), String> {
            self.calls.send(format!("end {sandbox_id}")).unwrap();
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
        let sessions = SessionLifecycle::new(sink, Arc::new(FakeCore { calls, fail }));
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
            sandbox: json!({"sandbox": {"metadata": {"id": "sbx-1", "name": "research"}}}),
        };
        let deleted = InventoryEvent::Deleted {
            response: json!({"sandboxId": "sbx-1"}),
        };
        sessions.record(created.clone()).await.unwrap();
        assert_eq!(
            next(&mut received).await.as_deref(),
            Some("start sbx-1 research")
        );
        sessions.record(deleted.clone()).await.unwrap();
        assert_eq!(next(&mut received).await.as_deref(), Some("end sbx-1"));
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
        assert_eq!(next(&mut received).await.as_deref(), Some("end sbx-2"));
        assert_eq!(inventory.0.lock().unwrap().len(), 1);
    }
}
