# Install OpenBox for OpenShell

This guide adds OpenBox governance to an OpenShell v0.1.2 gateway you already
run. When it is done, every sandbox the gateway creates sends its HTTP traffic
through an OpenBox verdict, and nobody can turn that off from the sandbox
policy.

Two services do the work. Both come from `middleware/` in this repository.

| Service | Binary | Role |
|---|---|---|
| Door guard | `openbox-verdict-middleware` | Supervisor middleware. Asks OpenBox Core for a verdict on every request a sandbox makes, and records each response. |
| Front desk | `openbox-governance-interceptor` | Gateway interceptor. Attaches the door guard to every new sandbox, refuses policy changes that weaken it, and records sandboxes. |

For local development, use `middleware/scripts/openbox-openshell.sh` instead.
It starts everything on one machine without TLS.

## Before you start

You need:

- An OpenShell v0.1.2 gateway with extension tokens on. That is the
  `[openshell.gateway.gateway_jwt]` section of the gateway TOML. Note its
  `gateway_id` and the PEM file at `public_key_path`. Both services check
  every call against them.
- An agent in the OpenBox dashboard with a workload identity. The dashboard
  shows an env snippet with `OPENBOX_API_URL`, `OPENBOX_API_KEY` and
  `OPENBOX_WORKLOAD_PRIVATE_KEY`.
- The key's kid. Ask Core for it:

  ```bash
  curl -fsS -H "Authorization: Bearer $OPENBOX_API_KEY" \
    "$OPENBOX_API_URL/api/v3/auth/bootstrap"
  ```

  The response holds `kid`, `client_id` and `token_endpoint`. If `kid` is
  empty, the agent has no workload key registered.
- Workload tokens that carry the `openbox-core` audience. Core and the backend
  reject tokens without it. `openbox-openshell.sh up` checks this for you.
- A Redis that every door guard replica can reach. See "Shared store" below.
- A gateway API client certificate for OpenBox (optional, but you want it).
  The door guard uses it to stop a halted sandbox, and the front desk uses it
  to reconcile the AI Inventory. Without it, HALT still denies all of the
  sandbox's traffic but cannot stop the sandbox.

## 1. Build the image

We do not publish an image yet. Build both binaries and put them on `PATH` in
one image:

```bash
cd middleware
cargo build --release --locked \
  --bin openbox-verdict-middleware --bin openbox-governance-interceptor
```

The chart runs the image as UID 65532 with a read-only root filesystem. Neither
binary writes to disk.

## 2. Issue the server certificates

The gateway and the sandbox supervisors call both services over TLS. They check
each certificate against the registration's `tls_ca_cert_path`, with normal
hostname checks. So:

- Issue both certificates from a CA you will name in `tls_ca_cert_path`. The
  gateway's own CA works.
- Put the names the gateway and the supervisors dial in the SANs. For the
  in-cluster Service that is `<release>-openbox-openshell-door-guard.<ns>.svc`
  and the matching front desk name. For an IP endpoint such as
  `https://127.0.0.1:50051`, the certificate needs that IP SAN.

Store each one as a `kubernetes.io/tls` Secret, or set
`tls.certManager.enabled` and point `tls.certManager.issuerRef` at a
cert-manager Issuer that signs with that CA.

## 3. Install the chart

```bash
helm install openbox deploy/helm/openbox-openshell -n openbox --create-namespace \
  --set image.repository=<registry>/openbox-openshell \
  --set openbox.url=<Core URL> \
  --set openbox.backendUrl=<backend URL> \
  --set credentials.existingSecret=openbox-agent \
  --set gateway.id=<gateway_id> \
  --set-file gateway.publicKey=<public_key_path> \
  --set gateway.api.endpoint=<gateway API URL> \
  --set gateway.api.mtlsSecret=openbox-gateway-client \
  --set tls.doorGuard.existingSecret=openbox-door-guard-tls \
  --set tls.frontDesk.existingSecret=openbox-front-desk-tls \
  --set externalRedis.url=redis://<host>:6379/0
```

`openbox-agent` holds `api-key`, `workload.pem` and `workload-kid`.
`openbox-gateway-client` holds `ca.crt`, `tls.crt` and `tls.key`.
`deploy/helm/openbox-openshell/values.yaml` documents every value and the
environment variable it sets.

The chart refuses settings the binaries would refuse at startup. It also
refuses more than one door guard replica without a shared Redis.

### Shared store

The door guard runs two or more replicas. An approval's retry and a response's
completion can land on any replica, so they are matched through Redis
(`OPENBOX_REDIS_URL`). Without Redis, a retry on another replica asks for
approval again.

The client speaks plain TCP with an optional password:
`redis://[:password@]host[:port][/db]`. It does not speak TLS, so keep Redis on
a network you trust. If Redis is unreachable, nothing is skipped: a retry is
scored as a new activity and needs a new approval.

`redis.enabled=true` runs a single Redis in the release. Use it for evaluation
only.

## 4. Register OpenBox with the gateway

Start OpenBox first. The gateway does not start while a registered service is
unreachable or rejects its manifest. Then add the following to the gateway TOML
and restart the gateway. `helm install` prints this block with your Service
names filled in.

```toml
# The front desk, governing: attaches the door guard to every new sandbox and
# refuses changes that weaken it. Fail closed.
[[openshell.gateway.interceptors]]
name = "openbox"
grpc_endpoint = "https://<front desk>:50061"
tls_ca_cert_path = "/etc/openshell/openbox-ca.pem"
audience = "urn:openshell:extension:interceptor:openbox"
failure_policy = "fail_closed"
binding_policy = "allowlist"

[[openshell.gateway.interceptors.bindings]]
rpc = "openshell.v1.OpenShell/CreateSandbox"
phases = ["modify_operation", "validate"]

[[openshell.gateway.interceptors.bindings]]
rpc = "openshell.v1.OpenShell/UpdateConfig"
phases = ["validate"]

[[openshell.gateway.interceptors.bindings]]
rpc = "openshell.v1.OpenShell/ImportProviderProfiles"
phases = ["validate"]

[[openshell.gateway.interceptors.bindings]]
rpc = "openshell.v1.OpenShell/UpdateProviderProfiles"
phases = ["validate"]

# The front desk, recording: AI Inventory and each sandbox's OpenBox session.
# Fail open, because it runs after the gateway has committed the change.
[[openshell.gateway.interceptors]]
name = "openbox-inventory"
grpc_endpoint = "https://<front desk>:50062"
tls_ca_cert_path = "/etc/openshell/openbox-ca.pem"
audience = "urn:openshell:extension:interceptor:openbox-inventory"
failure_policy = "fail_open"
binding_policy = "allowlist"

[[openshell.gateway.interceptors.bindings]]
rpc = "openshell.v1.OpenShell/CreateSandbox"
phases = ["post_commit"]

[[openshell.gateway.interceptors.bindings]]
rpc = "openshell.v1.OpenShell/UpdateConfig"
phases = ["post_commit"]

[[openshell.gateway.interceptors.bindings]]
rpc = "openshell.v1.OpenShell/DeleteSandbox"
phases = ["post_commit"]

# The door guard: a verdict on every request, and every response recorded.
[[openshell.supervisor.middleware]]
name = "openbox"
grpc_endpoint = "https://<door guard>:50051"
tls_ca_cert_path = "/etc/openshell/openbox-ca.pem"
audience = "urn:openshell:extension:middleware:openbox"
max_payload_bytes = 1048576
timeout = "30s"
```

Keep these settings as they are:

- **Names.** The front desk attaches a middleware named `openbox`, so the door
  guard registration must be named `openbox`. The audiences above are
  OpenShell's defaults for these names, and the services expect them. If you
  change an audience, change `doorGuard.audience`, `frontDesk.audience` or
  `frontDesk.inventoryAudience` to match. The gateway refuses to start on a
  mismatch.
- **`timeout = "30s"`.** This is the most OpenShell allows. A full Core verdict
  runs policy, guardrails and behaviour rules, and takes seconds. The door
  guard gives all Core calls behind one verdict 29 s
  (`OPENBOX_CORE_TIMEOUT_MS`), so a slow Core ends in an explicit
  `openbox_unavailable` deny before the gateway gives up.
- **`max_payload_bytes`.** It must not exceed what the door guard advertises,
  which is `OPENBOX_MW_MAX_PAYLOAD_BYTES` (default 1 MiB). Keep the two equal.
- **`binding_policy = "allowlist"`.** The gateway enables only the RPCs and
  phases listed here. The two provider profile bindings matter: a provider's
  profile endpoints join a sandbox's policy when the provider is attached, so
  they never pass the policy checks on `CreateSandbox` and `UpdateConfig`.
  Since v0.1.2 every profile enters through `ImportProviderProfiles` or
  `UpdateProviderProfiles`, and the front desk refuses any profile endpoint
  that sends credentials uninspected.
- **`failure_policy`.** The governing registration fails closed. The
  inventory registration must fail open: OpenShell refuses a fail-closed
  `post_commit` binding.

### Registration endpoint per compute driver

The door guard is called by each sandbox's supervisor, not only by the gateway.
Its `grpc_endpoint` must resolve and connect from wherever the supervisors run.

| Compute driver | Where supervisors run | Door guard endpoint |
|---|---|---|
| Kubernetes | In the sandbox pods | The in-cluster Service name, e.g. `https://openbox-openbox-openshell-door-guard.openbox.svc:50051` |
| VM | On the gateway host, next to each VM | An address that resolves on the host, e.g. `https://127.0.0.1:50051` when the door guard runs on that host |
| Docker, Podman | Not verified by us | An address that resolves from both the gateway and the supervisor |

Do not use `host.openshell.internal` for the VM driver. The supervisor runs on
the host, and that name does not resolve there. The VM driver rewrites it to
loopback only for the gateway's own endpoint, not for extension endpoints. The
certificate must carry whatever you put in the endpoint, including an IP SAN
for `127.0.0.1`.

The front desk is called only by the gateway, so its endpoint must resolve
from the gateway.

### Profiles imported before the front desk

The front desk checks a provider profile when it is imported or updated.
Profiles already stored in the gateway were never checked. Audit them once,
right after you register the front desk:

```bash
openshell profile list
openshell profile export <name> --global > <name>.yaml   # for each profile
grep -n allow_uninspected_credentials *.yaml
```

Any endpoint with `allow_uninspected_credentials: true` sends its credential
past the door guard. Update that profile without it. The front desk now checks
the update.

## 5. Check it

Create a sandbox the usual way, then confirm the door guard is attached:

```bash
openshell sandbox create --name check --policy policy.yaml
openshell policy get check --full | grep 'middleware: openbox'
```

Make a request from inside the sandbox. Each door guard pod logs one line per
verdict, with identifiers and the outcome only:

```
openbox: eval request_id=<id> sandbox_id=<id> decision=allow reason_code=- ms=<ms>
```

The agent's sessions appear in the OpenBox dashboard. Each sandbox is one
session.

## What the front desk does to every sandbox

On `CreateSandbox` the front desk adds a `network_middlewares.openbox` entry
to the policy:

- middleware `openbox`, every host (`**`), `on_error: fail_closed`
- `order` 1000, or higher than any other entry, so it runs after operator
  middleware such as redaction and the verdict covers what actually leaves
- `config: { approval_mode: queue }`
- hosts on `tls: skip` endpoints excluded, because OpenShell cannot inspect
  them and refuses a fail-closed middleware that selects them

It also labels the sandbox `openbox.ai/governed=true`.

It refuses, on create and on `UpdateConfig`:

- a policy whose `openbox` entry is missing, uses another middleware, or does
  not fail closed
- any endpoint with `allow_uninspected_credentials`
- turning on automatic approval of policy proposals written by the agent

### Sandboxes created without `--policy`

A sandbox created without `--policy` gets OpenShell's restrictive default
policy, with OpenBox attached (PROD-889). Before this, such a sandbox fell back
to the default inside the sandbox with no attachment, and its provider traffic
bypassed OpenBox.

The trade-off: a policy shipped inside the sandbox image is ignored. Pass
`--policy` to use it.

## The approval retry contract

OpenShell cannot hold a request, so an approval is deny-then-retry:

1. Core asks for approval. The door guard denies the request with reason code
   `openbox_approval_required` and remembers it.
2. A person approves or rejects it in OpenBox.
3. The agent sends the identical request again. The door guard matches it and
   asks Core about the held approval. Approved: it goes through. Still
   pending: denied again with the same code. Rejected: the sandbox is halted.

`docs/agent-approvals.md` is the version to give agent authors.

To treat every approval as a block instead, set `approval_mode: deny` in the
`openbox` entry's `config` with a policy update. The front desk writes
`queue` at create time.

## Forwarding to your SIEM

There are two sources.

**OpenShell's OCSF log.** Each supervisor records every middleware call, its
decision and the reason code, in OCSF. It does not record the door guard's
free-form reason text. Turn the JSON export on for all sandboxes:

```bash
openshell settings set --global --key ocsf_json_enabled --value true
```

Each sandbox then writes `/var/log/openshell-ocsf.YYYY-MM-DD.log` (JSON Lines,
rotated daily, three files kept). Ship those with your log agent.

**The door guard's log.** One line per verdict on stderr, carrying
`request_id`, `sandbox_id`, the decision, the reason code and the time taken.
Ship the pod logs.

Join the two on the sandbox id and time. We planned to key this on
`request_id`, but OpenShell v0.1.2 does not put the request id in its OCSF
events: each event's `metadata.uid` is its own random id. OCSF's
`container.uid` names the sandbox. Until OpenShell carries the request id,
`request_id` joins the door guard's log with OpenBox Core, not with OCSF.

## Known gaps in v1

Blocked upstream, in OpenShell:

- No process lineage on spans. OpenShell never fills the originating process
  ([NVIDIA/OpenShell#4269](https://github.com/NVIDIA/OpenShell/issues/4269)).
- Plain-HTTP URLs are recorded as `https://host:80`. OpenShell reports scheme
  `https` for plaintext
  ([NVIDIA/OpenShell#4253](https://github.com/NVIDIA/OpenShell/issues/4253)).

Ours, or OpenShell's design:

- Raw TCP (`protocol: tcp`: Postgres, SSH, Redis) and `tls: skip` hosts are
  allowed or denied by host and port only. No per-request verdict. Put
  internal systems behind HTTP or MCP.
- WebSocket traffic passes through without per-message verdicts. See
  `docs/websocket.md`.
- Response bodies are recorded but never decide a verdict. Compressed
  responses are recorded without a body, because OpenShell only offers their
  headers.
- A policy shipped inside a sandbox image is ignored unless `--policy` is
  passed.
- The mounted workspace is a write path to the host, limited by Landlock.
- Approval is deny-then-retry. OpenShell has no way to hold a request.
- A slow verdict can still fail on an allow. The destination may drop the idle
  upstream first (example.com does after about 15 s), and a change of the
  sandbox's policy generation drops requests still waiting on a verdict.
- Verdicts take seconds: 3-8 s per model call on staging. A person using an
  agent interactively will notice.
- The dashboard shows a model call as an LLM call only for known provider
  domains (OpenAI, Anthropic, Google, OpenRouter). A model behind a proxy shows
  as plain HTTP, though the door guard still records it as `llm_call`.
- OCSF events do not carry `request_id` (see above).
- No published container image yet.
