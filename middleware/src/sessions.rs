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
//! A tool the model asked for that never got its result back (the sandbox
//! went away mid-tool) is closed before the session, so no activity is left
//! open.
//!
//! Like the inventory, this runs in `post_commit` and is best effort. Core
//! calls run in the background so a slow Core never holds up the gateway.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

use crate::core_client::{Activity, CoreClient, Outcome};
use crate::interceptor::{Inventory, InventoryEvent};
use crate::inventory::RuntimeEnvironment;
use crate::store::{SharedStore, open_tools_key, session_key, tool_key};

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
    /// Closes a tool left open, opening it first when Core never heard of
    /// it.
    async fn close_tool(
        &self,
        sandbox_id: &str,
        tool: &Activity,
        opened: bool,
    ) -> Result<(), String>;
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

    async fn close_tool(
        &self,
        sandbox_id: &str,
        tool: &Activity,
        opened: bool,
    ) -> Result<(), String> {
        if !opened {
            self.open_activity(sandbox_id, tool)
                .await
                .map_err(|error| error.to_string())?;
        }
        let outcome = Outcome {
            output: Some(json!({"reason": "sandbox deleted"})),
            ..Outcome::default()
        };
        self.close_activity(sandbox_id, tool, &outcome)
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

impl SessionLifecycle {
    /// Takes the sandbox's tools that are still open, marking them closed.
    async fn open_tools(&self, sandbox_id: &str) -> Vec<(Activity, bool)> {
        let ids: Vec<String> = self
            .store
            .take(&open_tools_key(sandbox_id))
            .await
            .ok()
            .flatten()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default();
        let mut tools = Vec::new();
        for call_id in ids {
            let key = tool_key(sandbox_id, &call_id);
            let Some(entry) = self
                .store
                .take(&key)
                .await
                .ok()
                .flatten()
                .and_then(|text| serde_json::from_str::<Value>(&text).ok())
            else {
                continue;
            };
            let state = entry.get("state").and_then(Value::as_str);
            let activity = entry.get("activity").and_then(|activity| {
                Some(Activity {
                    id: activity.get("id")?.as_str()?.to_owned(),
                    kind: activity.get("kind")?.as_str()?.to_owned(),
                    input: activity.get("input").cloned().unwrap_or_else(|| json!([])),
                })
            });
            if let (Some("open" | "opened"), Some(activity)) = (state, activity) {
                tools.push((activity, state == Some("opened")));
            }
        }
        tools
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
                    let tools = self.open_tools(&id).await;
                    let core = Arc::clone(&self.core);
                    tokio::spawn(async move {
                        for (tool, opened) in tools {
                            if let Err(error) = core.close_tool(&id, &tool, opened).await {
                                eprintln!(
                                    "openbox: tool activity {} left open sandbox_id={id}: {error}",
                                    tool.id
                                );
                            }
                        }
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

        async fn close_tool(
            &self,
            sandbox_id: &str,
            tool: &Activity,
            opened: bool,
        ) -> Result<(), String> {
            self.calls
                .send(format!(
                    "close-tool {sandbox_id} {} {} opened={opened}",
                    tool.id, tool.kind
                ))
                .unwrap();
            Ok(())
        }
    }

    #[tokio::test]
    async fn delete_closes_tools_left_open_before_the_session() {
        let (calls, mut received) = mpsc::unbounded_channel();
        let store: Arc<dyn SharedStore> = Arc::new(MemoryStore::default());
        let tool = |state: &str, id: &str| {
            json!({"activity": {"id": format!("oshx-tool-{id}"), "kind": "fetch", "input": [{}]}, "state": state})
                .to_string()
        };
        store
            .set(&tool_key("sbx-1", "a"), &tool("opened", "a"), None)
            .await
            .unwrap();
        store
            .set(&tool_key("sbx-1", "b"), &tool("open", "b"), None)
            .await
            .unwrap();
        store
            .set(&tool_key("sbx-1", "c"), &tool("closed", "c"), None)
            .await
            .unwrap();
        store
            .set(
                &open_tools_key("sbx-1"),
                &json!(["a", "b", "c"]).to_string(),
                None,
            )
            .await
            .unwrap();
        let sessions = SessionLifecycle::new(
            Arc::new(FakeInventory::default()),
            Arc::new(FakeCore { calls, fail: false }),
            Arc::clone(&store),
            None,
        );
        sessions
            .record(InventoryEvent::Deleted {
                response: json!({"sandboxId": "sbx-1"}),
            })
            .await
            .unwrap();
        assert_eq!(
            next(&mut received).await.as_deref(),
            Some("close-tool sbx-1 oshx-tool-a fetch opened=true")
        );
        assert_eq!(
            next(&mut received).await.as_deref(),
            Some("close-tool sbx-1 oshx-tool-b fetch opened=false")
        );
        assert_eq!(
            next(&mut received).await.as_deref(),
            Some("end sbx-1 timed=false")
        );
        assert!(store.get(&open_tools_key("sbx-1")).await.unwrap().is_none());
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
