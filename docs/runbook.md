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

## Load: SPEC-001 test A9

A9 is 200 requests a second of 1 MiB bodies for 30 minutes, answered by
Tier 0 (a local rule from Core allowing them), with Tier 0-1 inside p50 60 ms
and p99 250 ms at the door guard. Run it with `middleware/examples/loadgen.rs`
(an in-cluster Job pointed at the door guard Service, signing tokens with
the gateway's key; it sends each allowed request's response too, as a
supervisor does).

**It does not pass yet.** Measured on kind on one laptop (10 CPUs for the
whole cluster, two door guard replicas, the chart's Redis, OpenShell
v0.1.8, Core on a preview environment taking about 5 s a call):

| Run | Served | Door guard | Client latency |
|---|---|---|---|
| 50 rps, 90 s, requests only | 100% | steady | p50 6 ms, p99 140 ms |
| 100 rps, 60 s, requests only | 100% | memory climbing | p50 6 ms, p99 223 ms |
| 200 rps, 30 min, before the fixes below | 27% | OOMKilled 19 times | p50 45 ms, p99 > 290 s |
| 200 rps, 120 s, with the fixes, one connection | 40% (79 rps) | no restarts, under 450 MiB | queued at the client |
| 200 rps, 120 s, with the fixes, two connections | 49% (98 rps) | no restarts | queued at the client |
| 100 rps, 60 s, with the Redis pool | 100% | no restarts | p50 19 ms, p99 25 ms |
| 200 rps, 60 s, with the Redis pool | 100% | no restarts; every Tier 0 answer under 50 ms inside the door guard | p50 10 ms, p99 20 ms |

What the runs found, and what changed:

- **Background Core records held whole requests.** A locally answered request
  queued a Core record holding the raw body, behind a Core that takes
  seconds, without limit. The body no longer goes into the queue, and the
  queue holds at most 256 jobs per sandbox and 4096 in all; past that,
  background records are dropped and counted in
  `openbox_mw_core_background_dropped_total`. Verdicts are never dropped.
- **A replica that fell behind accepted every request a burst brought.** It
  now takes at most 128 requests in flight per connection
  (`OPENBOX_MW_MAX_CONCURRENT_STREAMS`); past that the supervisor waits.
- **One connection lands on one replica.** gRPC runs over one HTTP/2
  connection, and a Kubernetes Service balances connections, not requests,
  so with few supervisors one door guard replica takes all of it. Both
  two-connection runs landed on the same replica.

What held Tier 0 back was the shared store. Each process sent every Redis
command over one connection, so a command waited for all the others, and
past the 200 ms store timeout it counted as "nothing remembered" and the
connection was reopened (before the pool, Redis served about 54 commands
for each request and its response, and only 12% of Tier 0 answers took
under 250 ms inside the door guard). Each process now keeps a pool of
connections (`OPENBOX_REDIS_POOL`, default 16; set it through
`doorGuard.extraEnv`), and a test holds a Tier 0 request to five store
commands and its response to one. With the pool, the 200 rps runs above
served every request.

Still open before A9 passes:

- **The 30-minute run.** The pool runs above are 60 s smoke runs on a
  laptop; A9 is 30 minutes, on a cluster sized for it.
- **Background Core records are dropped under load.** Core takes about 5 s
  a call (PROD-1151), so at 200 rps the background queue fills and records
  of locally allowed requests are dropped
  (`openbox_mw_core_background_dropped_total`, about 27,700 in the 200 rps
  run). Verdicts are never dropped, but those requests are missing from
  the session in OpenBox until Core is faster or records are batched.

Sizing until then: give each door guard replica 1 GiB of memory for 1 MiB
bodies at 100 requests a second or more, and set `MALLOC_ARENA_MAX=2`
(`doorGuard.extraEnv`): glibc's per-thread arenas otherwise keep freed
1 MiB buffers, which more than doubled resident memory in these runs.

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
| No Core call recorded for the request | The supervisor sent no sandbox id | OpenShell version; should not happen on v0.1.8 |

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

The door guard logs `halted sandbox <id> stopped stop_ms=<ms>` once the gateway
reports the sandbox stopped (not just accepted the stop), or why it could not
stop it within 30 s. `openbox_mw_halt_stop_seconds` is the time from the HALT
verdict to that confirmation; SPEC-001 FR-1.6 asks for 5 s. Alert on
`openbox_mw_halt_stops_total{outcome="failed"}`.

A halted sandbox is stopped, not deleted. Inspect it before you restart it.

### Resuming a halted sandbox

A halt is held in two places: OpenBox Core latches it on the session, and each
door guard replica caches it. Resume clears both. It is off unless the door
guard has an admin token (`doorGuard.adminTokenSecret`, a Secret with
`admin-token`, 32 characters or more):

```bash
kubectl -n openbox port-forward deploy/openbox-openbox-openshell-door-guard 9464 &
curl -X POST -H "Authorization: Bearer $(cat admin-token)" \
  "http://127.0.0.1:9464/admin/resume?sandbox_id=<sandbox id>"
openshell sandbox start <sandbox name>
```

`200` means the door guard and Core both cleared it; the replica that answers
tells the others through the shared store. `502` means the door guard cleared
it but Core did not: requests stay halted until Core's latch is cleared.
Core's side of resume (`POST /api/v3/governance/session/resume`) is proposed
and not yet served, so today expect `502` with Core's `404`.

After the resume the sandbox's traffic is scored again from its next request.
