# Runbook: OpenBox for OpenShell

For the people who run the door guard (`openbox-verdict-middleware`) and the
front desk (`openbox-governance-interceptor`). `docs/install.md` covers the
install.

## Availability

**With `fail_closed`, OpenBox availability is sandbox availability.**

- The door guard is attached to every sandbox with `on_error: fail_closed`.
  While no door guard answers, every governed sandbox's HTTP traffic is
  refused. While Core gives no verdict, every request is denied with
  `openbox_unavailable`.
- The front desk's `openbox` registration fails closed. While it is down,
  nobody can create a sandbox, change a sandbox policy, or import or update a
  provider profile. Running sandboxes keep working.
- The front desk's `openbox-inventory` registration fails open. While it is
  down, sandboxes still work, but the AI Inventory and sandbox sessions miss
  events. Reconciliation repairs the inventory when the gateway API credential
  is set.
- A shared Redis outage costs approvals, not safety: a retry is scored as a
  new action and needs a new approval.

Core counts too: the door guard is never more available than Core.

We have not set a number for v1. Measure it at the door guard as the share
of evaluations not denied with `openbox_unavailable`, over a rolling 30 days,
and set it no lower than the sandbox target. There is no `fail_open` way out
for the door guard: the front desk refuses an attachment that does not fail
closed.

To meet it:

- Run two or more door guard replicas with a shared Redis. The chart refuses
  more than one replica without Redis.
- Keep the PodDisruptionBudgets on (`minAvailable: 1`).
- Keep `terminationGracePeriodSeconds` at 30 or more. On SIGTERM the door guard
  stops taking calls and finishes the verdicts in flight.
- Upgrade one replica at a time. The chart uses `maxUnavailable: 0`.
- Start OpenBox before the gateway. The gateway does not start while a
  registered service is unreachable.

## Metrics

The door guard serves Prometheus metrics at `/metrics` on its admin port
(`OPENBOX_MW_ADMIN_LISTEN`, chart default 9464), with `/healthz` and
`/readyz`. The front desk has no metrics endpoint; watch its logs and pod
health.

| Metric | Type | Labels |
|---|---|---|
| `openbox_mw_evaluations_total` | counter | `decision` (`allow`, `deny`), `reason_code` |
| `openbox_mw_evaluation_duration_seconds` | histogram | none |
| `openbox_mw_core_requests_total` | counter | `call` (`session`, `approval`, `evaluate`, `signal`), `outcome` (`ok`, `error`) |
| `openbox_mw_core_duration_seconds` | histogram | `call` |

Histogram buckets run from 10 ms to 30 s.

Alert on these:

```promql
# OpenBox cannot give verdicts: sandboxes are being refused.
sum(rate(openbox_mw_evaluations_total{reason_code="openbox_unavailable"}[5m]))
  / sum(rate(openbox_mw_evaluations_total[5m])) > 0.01

# Core calls failing.
sum by (call) (rate(openbox_mw_core_requests_total{outcome="error"}[5m]))
  / sum by (call) (rate(openbox_mw_core_requests_total[5m])) > 0.05

# Verdicts close to the 29 s budget: the next step is openbox_unavailable.
histogram_quantile(0.99,
  sum by (le) (rate(openbox_mw_evaluation_duration_seconds_bucket[10m]))) > 20

# Halts: each one stops a sandbox. Page a person.
increase(openbox_mw_evaluations_total{reason_code="openbox_halted"}[5m]) > 0

# No door guard ready.
sum(up{job="<door guard scrape job>"}) < 1
```

Watch, without paging: the rate of `openbox_blocked` and
`openbox_approval_required` by deployment. A sudden jump is usually a policy
change in OpenBox.

## Verdicts are slow

A model-call verdict takes 3-8 s on staging. That is normal. Look further when
the p99 of `openbox_mw_evaluation_duration_seconds` climbs toward 29 s.

1. Find which Core call is slow:
   `histogram_quantile(0.99, sum by (call, le) (rate(openbox_mw_core_duration_seconds_bucket[10m])))`.
   `evaluate` is policy, guardrails and behaviour rules. `session` is the
   first request of each sandbox. `approval` is a retry checking its approval.
2. Check Core. The door guard waits for Core and does little else. Core's
   evaluate is a synchronous workflow; check its workers and queue.
3. Check one sandbox's queue. The door guard sends each sandbox's events to
   Core in order, so a request waits for that sandbox's earlier events. One
   busy sandbox does not slow the others.
4. Check the door guard pods for CPU throttling and restarts.

Slow verdicts fail even when Core allows: the destination may drop the idle
upstream connection first (about 15 s for example.com), and a sandbox policy
change drops requests still waiting.

## Requests are denied with `openbox_unavailable`

The door guard denies with `openbox_unavailable` whenever it gets no verdict.
It never allows instead. Its reason text goes back to OpenShell with the
deny, but OpenShell logs only the reason code, and the door guard's own log
line carries the code and the time taken, not the text. So work from the
metrics and the time taken:

| Sign | Cause | Check |
|---|---|---|
| `ms=` near 29000 in the log line | Core slower than the budget (`OpenBox did not return a verdict within 29000 ms`) | The slow-verdict steps above |
| `openbox_mw_core_requests_total{outcome="error"}` rising, short `ms=` | Core refused, failed or is unreachable (`core returned HTTP <code>`, `core unreachable or timed out`, `core response was malformed`) | Core health; the agent's API key and workload key; DNS, network policy, Core's certificate, `OPENBOX_URL` |
| No Core call recorded for the request | The supervisor sent no sandbox id | OpenShell version; should not happen on v0.1.2 |

Then check:

- The workload token. Core and the backend reject tokens without the
  `openbox-core` audience. A rotated or removed workload key also fails here.
- `OPENBOX_CORE_TIMEOUT_MS` is under the gateway registration's `timeout`
  (29000 under `30s`).

If the sandbox sees `middleware_failed` instead, the door guard did not answer
at all: no ready pod, a TLS or extension-token mismatch with the gateway, or a
body over `max_payload_bytes`. The door guard returns a refused token to the
gateway as `unauthenticated` with the reason (expired, wrong audience, wrong
issuer) and does not log it itself, so look in the gateway and supervisor
logs.

## Break-glass: run without OpenBox

Use this only when OpenBox is down, cannot be fixed fast enough, and the
sandboxes must run. While it is in effect, sandbox traffic is not governed.

**Log it before you start.** Record who, when, why, and the incident or ticket,
in the incident channel. Keep a copy of the gateway TOML as it was. Record the
time OpenBox was restored. Every break-glass is reviewed afterwards.

1. Remove three registrations from the gateway TOML: the `openbox`
   interceptor, the `openbox-inventory` interceptor, and the `openbox`
   supervisor middleware. Restart the gateway.
2. Sandboxes still carry the `network_middlewares.openbox` entry, and
   OpenShell refuses a policy that names a middleware that is not registered.
   With the front desk gone, the entry can be removed: update each sandbox's
   policy without it, or recreate the sandbox. We have not verified how a
   running sandbox behaves between steps 1 and 2; plan for its traffic to stop
   until its policy is updated.

To restore:

1. Fix and start OpenBox. Check `/readyz` on the door guard.
2. Put the three registrations back and restart the gateway.
3. Recreate every sandbox created or changed during the break-glass. The
   front desk attaches the door guard only on `CreateSandbox`, and refuses a
   later policy update that lacks the attachment, so those sandboxes stay
   ungoverned and their policies cannot be changed until they are recreated.
4. Audit provider profiles imported or updated during the break-glass (see
   "Profiles imported before the front desk" in `docs/install.md`).

## Halts

A halt denies everything from the sandbox with `openbox_halted` and stops it
through the gateway API. If the door guard has no gateway credential
(`OPENBOX_GATEWAY_ENDPOINT`, `OPENBOX_GATEWAY_MTLS_DIR`), it logs
`HALT denies traffic but cannot stop sandboxes` at startup, and a halted
sandbox keeps running with all traffic denied.

The door guard logs `halted sandbox <id> stopped`, or why it could not stop
it. A halted sandbox is stopped, not deleted. Inspect it before you restart
it: OpenBox Core latches the halt on the session.
