# OpenBox for OpenShell

OpenBox governance for [NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell)
sandboxes, on OpenShell v0.1.2. Two services sit next to an OpenShell gateway:

- **Door guard** (`openbox-verdict-middleware`): OpenShell supervisor middleware.
  Every request a sandbox makes gets an OpenBox Core verdict before it leaves,
  and its response is recorded. A sandbox is one OpenBox session, following
  the agent SDK's pattern (`llm_call` and tool activities, prompts as signals).
- **Front desk** (`openbox-governance-interceptor`): gateway interceptor.
  Attaches the door guard to every sandbox on create, refuses policy and
  provider-profile changes that would weaken it, opens and closes the
  sandbox's Core session, and registers sandboxes in the AI Inventory.

Epic: [PROD-770](https://krnl-labs.atlassian.net/browse/PROD-770). Status,
decisions and verification live on the Jira tickets.

| Path | What |
|---|---|
| `middleware/` | Both services (one crate), tests, examples |
| `middleware/scripts/openbox-openshell.sh` | Run OpenShell governed by OpenBox locally, for an agent's dashboard snippet |
| `middleware/scripts/verify-*.sh` | Live checks against a real OpenShell gateway and OpenBox Core |
| `deploy/helm/openbox-openshell/` | Helm chart for both services |
| `docs/install.md` | Installing on an OpenShell gateway |
| `docs/runbook.md` | Operating it: metrics, alerts, slow verdicts, break-glass |
| `docs/agent-approvals.md` | What an agent sees when a request needs approval |
| `docs/websocket.md` | What is and is not governed on a WebSocket |

## Build and test

```sh
cd middleware
cargo clippy --all-targets -- -D warnings
cargo test
```

## Try it

```sh
middleware/scripts/openbox-openshell.sh up --agent-env agent.env
middleware/scripts/openbox-openshell.sh demo
middleware/scripts/openbox-openshell.sh down
```

`agent.env` is the snippet the OpenBox dashboard shows for an agent with a
workload identity. The script needs the OpenShell v0.1.2 release binaries
(`OPENSHELL_PREFIX`, default `~/openshell-repro`).

History before this repository is in `OpenBox-AI/openbox-sandbox`, where the
work started under `middleware/`.
