#!/bin/sh
# Verify PROD-839 (with PROD-831 and PROD-772): an OpenShell sandbox is one
# complete OpenBox Core session that follows the OpenBox event sequence:
#
#   WorkflowStarted    sandbox created, input = the sandbox (name, image, ...)
#   SignalReceived     user_prompt: a new user turn in a model call (PROD-840)
#   ActivityStarted    each request, its own activity, named "GET example.com"
#   ActivityCompleted  its response, same activity id, status and duration
#   WorkflowCompleted  sandbox deleted, with the session's duration
#
# after which Core seals it. The result is what the dashboard shows under
# Sessions.
#
#   OBX_API_KEY_FILE=... OBX_WORKLOAD_KEY_FILE=... OBX_WORKLOAD_KID=... \
#     middleware/scripts/verify-sessions.sh
#
# Runs against a real OpenBox stack (Core, its workers and Temporal) and
# starts its own OpenShell v0.1.2 gateway (VM driver) with its own state,
# ports and CLI config, plus the front desk and the verdict middleware. The
# gateway-to-extension legs run plaintext (OPENBOX_*_INSECURE=1, no gateway
# token check); the legs to Core are the real ones (Keycloak workload token,
# Core v3).
#
# Model calls are Anthropic Messages requests (POST /v1/messages) sent to
# example.com instead of a provider, so no provider key is needed: the door
# guard reads the prompt from the request, and example.com answers 405, which
# proves the call was let through. Everything between the sandbox and Core is
# real. Results that depend on it are labelled "stand-in provider".
#
# example.com is also the GET target, so one policy rule covers both.
#
# The middleware gets a larger time budget than OpenShell's 500 ms default,
# because a local Core answers an evaluate in about a second (see PROD-832).
#
# Required: an OpenBox agent with a Keycloak workload identity (IAM v3):
#   OBX_API_KEY_FILE        file with the agent's obx_ API key
#   OBX_WORKLOAD_KEY_FILE   file with the RSA private key registered with it
#   OBX_WORKLOAD_KID        that key's kid
#
# Optional:
#   OPENBOX_URL             Core, default http://localhost:8086
#   OBX_PSQL                command that runs one SQL query against the
#                           OpenBox database and prints unaligned rows
#                           (default: the local stack's Postgres on Colima)
#   OBX_HOST_IP             host IPv4 the sandbox VM can reach the middleware
#                           on (default: en0's address)
#   OBX_MW_TIMEOUT          OpenShell's budget for the middleware, default 5s
#   OBX_REDIS_URL           shared store for both services, default the local
#                           stack's Redis, database 7
#   OPENSHELL_PREFIX        OpenShell v0.1.2 install (default ~/openshell-repro)
#   OBX_GATEWAY_PORT        default 17890 (+1 health, +2 metrics)
#   OBX_MW_PORT             default 50251 (+1 admin)
#   OBX_FD_PORT             default 50271 (+1 inventory)
#   KEEP=1                  keep the work dir
#
# Prints PASS/FAIL per scenario, exits non-zero if any fail, and removes the
# sandbox, gateway, front desk and middleware it created on exit. The Core
# session stays, so it can be opened in the dashboard afterwards.
set -eu

HERE=$(cd "$(dirname "$0")/.." && pwd)
PREFIX=${OPENSHELL_PREFIX:-$HOME/openshell-repro}
GW_PORT=${OBX_GATEWAY_PORT:-17890}
MW_PORT=${OBX_MW_PORT:-50251}
ADMIN_PORT=$((MW_PORT + 1))
FD_PORT=${OBX_FD_PORT:-50271}
MODEL_HOST=example.com
INV_PORT=$((FD_PORT + 1))
MW_TIMEOUT=${OBX_MW_TIMEOUT:-5s}
CORE=${OPENBOX_URL:-http://localhost:8086}
REDIS=${OBX_REDIS_URL:-redis://localhost:6379/7}
PSQL=${OBX_PSQL:-docker --context colima exec -i openbox-local-postgres-1 psql -U postgres -d openbox -tA -c}
HOST_IP=${OBX_HOST_IP:-$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || true)}
: "${OBX_API_KEY_FILE:?set OBX_API_KEY_FILE}"
: "${OBX_WORKLOAD_KEY_FILE:?set OBX_WORKLOAD_KEY_FILE}"
: "${OBX_WORKLOAD_KID:?set OBX_WORKLOAD_KID}"
[ -n "$HOST_IP" ] || { echo "no host IPv4 found; set OBX_HOST_IP"; exit 1; }
WORK=$(mktemp -d /tmp/obx-ses.XXXXXX)
RUN=$(($(date +%s) % 1000000))
A=obx-session-$RUN
FAILED=0

ISOLATE="XDG_STATE_HOME=$WORK/state XDG_CONFIG_HOME=$WORK/config OPENSHELL_LOCAL_TLS_DIR=$WORK/tls"
os() { env $ISOLATE "$PREFIX/bin/openshell" "$@"; }

cleanup() {
  if [ -f "$WORK/gateway.pid" ]; then
    os sandbox delete "$A" >/dev/null 2>&1 || true
  fi
  for pid in "$WORK"/*.pid; do
    [ -f "$pid" ] && kill "$(cat "$pid")" 2>/dev/null || true
  done
  if [ "${KEEP:-0}" = 1 ]; then echo "kept $WORK"; else rm -rf "$WORK"; fi
}
trap cleanup EXIT INT TERM

pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1"; FAILED=1; }
free() { ! lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1; }
wait_listen() {
  i=0
  until ! free "$1"; do
    i=$((i + 1))
    kill -0 "$(cat "$2")" 2>/dev/null || { echo "process for :$1 exited, see $3"; tail -20 "$3"; exit 1; }
    [ $i -lt 120 ] || { echo "nothing listening on :$1"; exit 1; }
    sleep 0.5
  done
}
q() { $PSQL "$1" | tr -d '[:space:]'; }
# wait_q <seconds> <sql> <expected>: until the query prints the expected value.
wait_q() {
  i=0
  while [ "$(q "$2")" != "$3" ]; do
    i=$((i + 1))
    [ $i -le "$1" ] || return 1
    sleep 1
  done
}

sandbox_id() {
  os sandbox get "$1" -o json 2>/dev/null |
    python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("id") or d.get("metadata",{}).get("id",""))'
}
# request <sandbox> <path>: one plain-HTTP GET from inside the sandbox; prints
# the status code. Egress is mediated transparently (OpenShell strips the proxy
# variables), and the base image has no curl, so bash speaks HTTP over /dev/tcp.
request() {
  os sandbox exec -n "$1" --no-tty --timeout 60 -- bash -c '
    exec 3<>/dev/tcp/example.com/80 || { echo "connect failed"; exit 0; }
    printf "GET %s HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n" "$0" >&3
    IFS=" " read -r _ code _ <&3; echo "${code:-none}"' "$2" 2>&1 | tail -1 || true
}

# post <sandbox> <path> <json>: one Anthropic-shaped model call from inside the
# sandbox to the stand-in provider; prints the status code.
post() {
  os sandbox exec -n "$1" --no-tty --timeout 60 -- bash -c '
    exec 3<>/dev/tcp/'"$MODEL_HOST"'/80 || { echo "connect failed"; exit 0; }
    printf "POST %s HTTP/1.1\r\nHost: '"$MODEL_HOST"'\r\nContent-Type: application/json\r\nContent-Length: %s\r\nConnection: close\r\n\r\n%s" "$0" "${#1}" "$1" >&3
    IFS=" " read -r _ code _ <&3; echo "${code:-none}"' "$2" "$3" 2>&1 | tail -1 || true
}

for port in "$GW_PORT" $((GW_PORT + 1)) $((GW_PORT + 2)) "$MW_PORT" "$ADMIN_PORT" "$FD_PORT" "$INV_PORT"; do
  free "$port" || { echo "port $port is in use; set OBX_GATEWAY_PORT / OBX_MW_PORT / OBX_FD_PORT"; exit 1; }
done
[ -x "$PREFIX/bin/openshell-gateway" ] && [ -x "$PREFIX/libexec/openshell-driver-vm" ] ||
  { echo "set OPENSHELL_PREFIX to an OpenShell v0.1.2 install (see verify-provider-profiles.sh)"; exit 1; }

echo "== OpenBox stack"
curl -fsS -o /dev/null "$CORE/" || { echo "Core not reachable at $CORE"; exit 1; }
$PSQL "select 1" >/dev/null || { echo "OBX_PSQL cannot query the OpenBox database"; exit 1; }
"$PREFIX/bin/openshell" --version
echo "middleware reachable from the sandbox at $HOST_IP:$MW_PORT, budget $MW_TIMEOUT"

echo "== Shared store against the real Redis ($REDIS)"
if (cd "$HERE" && OBX_TEST_REDIS_URL=$REDIS cargo test -q --lib store::tests::redis_store_round_trip 2>&1 | grep -q '1 passed'); then
  pass "0 the shared store reads, writes and takes against Redis"
else
  fail "0 the shared store reads, writes and takes against Redis"
fi

echo "== Build and start the front desk and the verdict middleware"
(cd "$HERE" && cargo build -q --bin openbox-governance-interceptor --bin openbox-verdict-middleware)
CORE_ENV="OPENBOX_REDIS_URL=$REDIS OPENBOX_URL=$CORE OPENBOX_API_KEY_FILE=$OBX_API_KEY_FILE OPENBOX_WORKLOAD_KEY_FILE=$OBX_WORKLOAD_KEY_FILE OPENBOX_WORKLOAD_KID=$OBX_WORKLOAD_KID"
env $CORE_ENV OPENBOX_FD_INSECURE=1 OPENBOX_FD_LISTEN=127.0.0.1:$FD_PORT \
  OPENBOX_FD_INVENTORY_LISTEN=127.0.0.1:$INV_PORT OPENBOX_FD_GATEWAY_ID=obx-verify-sessions \
  "$HERE/target/debug/openbox-governance-interceptor" >"$WORK/fd.log" 2>&1 &
echo $! >"$WORK/fd.pid"
wait_listen "$INV_PORT" "$WORK/fd.pid" "$WORK/fd.log"
env $CORE_ENV OPENBOX_MW_INSECURE=1 OPENBOX_MW_LISTEN=0.0.0.0:$MW_PORT \
  OPENBOX_MW_ADMIN_LISTEN=127.0.0.1:$ADMIN_PORT OPENBOX_CORE_TIMEOUT_MS=${OPENBOX_CORE_TIMEOUT_MS:-2000} \
  "$HERE/target/debug/openbox-verdict-middleware" >"$WORK/mw.log" 2>&1 &
echo $! >"$WORK/mw.pid"
wait_listen "$MW_PORT" "$WORK/mw.pid" "$WORK/mw.log"

echo "== Gateway with both registered"
mkdir -p "$WORK/state/openshell/vm-driver" "$WORK/config"
[ -d "$HOME/.local/state/openshell/vm-driver/images" ] &&
  ln -s "$HOME/.local/state/openshell/vm-driver/images" "$WORK/state/openshell/vm-driver/images"
"$PREFIX/bin/openshell-gateway" generate-certs --output-dir "$WORK/tls" --server-san localhost >/dev/null 2>&1
cat >"$WORK/gateway.toml" <<EOF
[openshell]
version = 2

[openshell.gateway]
compute_driver = "vm"
bind_address = "127.0.0.1:$GW_PORT"
health_bind_address = "127.0.0.1:$((GW_PORT + 1))"
metrics_bind_address = "127.0.0.1:$((GW_PORT + 2))"

[[openshell.gateway.interceptors]]
name = "openbox-inventory"
grpc_endpoint = "http://127.0.0.1:$INV_PORT"
allow_insecure_transport = true
failure_policy = "fail_open"
binding_policy = "allowlist"

[[openshell.gateway.interceptors.bindings]]
rpc = "openshell.v1.OpenShell/CreateSandbox"
phases = ["post_commit"]

[[openshell.gateway.interceptors.bindings]]
rpc = "openshell.v1.OpenShell/DeleteSandbox"
phases = ["post_commit"]

[[openshell.supervisor.middleware]]
name = "openbox"
grpc_endpoint = "http://$HOST_IP:$MW_PORT"
allow_insecure_transport = true
max_payload_bytes = 1048576
timeout = "$MW_TIMEOUT"
EOF
env $ISOLATE "$PREFIX/bin/openshell-gateway" --config "$WORK/gateway.toml" >"$WORK/gateway.log" 2>&1 &
echo $! >"$WORK/gateway.pid"
wait_listen "$GW_PORT" "$WORK/gateway.pid" "$WORK/gateway.log"
os gateway add "https://127.0.0.1:$GW_PORT" --local --name obx-verify-sessions >/dev/null

cat >"$WORK/policy.yaml" <<'EOF'
version: 1
filesystem_policy:
  include_workdir: true
  read_only: [/usr, /lib, /etc, /proc]
  read_write: [/sandbox, /tmp]
landlock:
  compatibility: best_effort
process:
  run_as_user: sandbox
  run_as_group: sandbox
network_middlewares:
  openbox:
    name: OpenBox governance
    middleware: openbox
    order: 10
    on_error: fail_closed
    endpoints:
      include:
        - example.com
network_policies:
  example:
    name: example
    endpoints:
      - host: example.com
        port: 80
        protocol: rest
        access: read-write
    binaries:
      - path: /usr/bin/bash
EOF

echo "== Scenarios"
os sandbox create --name "$A" --policy "$WORK/policy.yaml" --detach --no-tty --no-auto-providers >/dev/null
ID=$(sandbox_id "$A")
[ -n "$ID" ] || { echo "sandbox $A did not come up"; tail -20 "$WORK/gateway.log"; exit 1; }
EV="from governance_events where workflow_id='$ID'"
SESSION="select count(*) from sessions where workflow_id='$ID'"
# About 10 s after start the sandbox's settings poll picks up its provider
# environment and reloads; a request still waiting on a verdict at that moment
# is dropped ("policy generation is stale"). Let it settle before traffic.
i=0
until os logs "$A" --source sandbox 2>/dev/null | grep -q 'Settings poll'; do
  i=$((i + 1))
  [ $i -le 30 ] || break
  sleep 1
done
if wait_q 30 "$SESSION" 1; then
  pass "1 creating the sandbox opens its Core session, before any traffic ($ID)"
else
  fail "1 creating the sandbox opens its Core session, before any traffic (sessions: $(q "$SESSION"))"
fi
STARTED_IN="select coalesce(input->0->>'name','') || '|' || coalesce(input->0->>'image','') $EV and event_type='WorkflowStarted'"
got=$(q "$STARTED_IN")
if [ "${got%%|*}" = "$A" ] && [ -n "${got#*|}" ]; then
  pass "2 WorkflowStarted carries the sandbox as its input (name $A, image ${got#*|})"
else
  fail "2 WorkflowStarted carries the sandbox as its input (got '$got')"
fi

# Two identical requests and a third: each is its own activity.
ok=0
for path in "/?n=1" "/?n=1" "/?n=2"; do
  code=$(request "$A" "$path")
  [ "$code" = 200 ] && ok=$((ok + 1))
done
if [ $ok = 3 ]; then
  pass "3 three requests from the sandbox, two of them identical, are allowed (HTTP 200)"
else
  fail "3 three requests from the sandbox, two of them identical, are allowed ($ok/3, last '$code')"
fi
STARTS="select count(distinct activity_id) $EV and event_type='ActivityStarted' and activity_type='GET example.com' and verdict=0"
if wait_q 30 "$STARTS" 3; then
  pass "4 each request is its own activity named 'GET example.com', identical ones too"
else
  fail "4 each request is its own activity named 'GET example.com', identical ones too (distinct: $(q "$STARTS"))"
fi
PAIRED="select count(*) $EV and event_type='ActivityStarted' and activity_id in
        (select activity_id $EV and event_type='ActivityCompleted' and output is not null and duration_ms is not null)"
if wait_q 30 "$PAIRED" 3; then
  pass "5 every activity is completed by its response, with output and duration"
else
  fail "5 every activity is completed by its response, with output and duration (paired: $(q "$PAIRED"))"
fi

# The user's prompts, as an agent sends them to its model (stand-in provider):
# a first turn, a tool-loop call that resends it, and a second turn.
FIRST='{"model":"claude-standin","messages":[{"role":"user","content":"refactor the payment module"}]}'
LOOP='{"model":"claude-standin","messages":[{"role":"user","content":"refactor the payment module"},{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"read_file","input":{"path":"pay.py"}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"def pay(): ..."}]}]}'
SECOND='{"model":"claude-standin","messages":[{"role":"user","content":"refactor the payment module"},{"role":"assistant","content":"done"},{"role":"user","content":"now add tests"}]}'
ok=0
for body in "$FIRST" "$LOOP" "$SECOND"; do
  code=$(post "$A" /v1/messages "$body")
  # Any upstream status means it was let through; 403 is a deny.
  case $code in [1-5][0-9][0-9]) [ "$code" != 403 ] && ok=$((ok + 1)) ;; esac
done
if [ $ok = 3 ]; then
  pass "8 three model calls from the sandbox are let through to the provider (stand-in provider)"
else
  fail "8 three model calls from the sandbox are let through to the provider ($ok/3, last '$code') (stand-in provider)"
  sleep 8
  os logs "$A" --source sandbox >"$WORK/sandbox.log" 2>&1 || true
  echo "      sandbox log saved: $WORK/sandbox.log"
fi
PROMPTS="select string_agg(input->0->>'prompt', ' | ' order by created_at) $EV and event_type='SignalReceived' and signal_name='user_prompt'"
if wait_q 30 "select count(*) $EV and event_type='SignalReceived' and signal_name='user_prompt'" 2 &&
  [ "$($PSQL "$PROMPTS")" = "refactor the payment module | now add tests" ]; then
  pass "9 each new user turn is one user_prompt signal; the tool-loop call adds none"
else
  fail "9 each new user turn is one user_prompt signal; the tool-loop call adds none (got '$($PSQL "$PROMPTS")')"
fi
ORDER="select string_agg(case when event_type='SignalReceived' then 'S' else 'A' end, '' order by created_at)
       $EV and (event_type='SignalReceived' or (event_type='ActivityStarted' and activity_type='POST $MODEL_HOST'))"
if [ "$(q "$ORDER")" = "SAASA" ]; then
  pass "10 each prompt is recorded before the model call that carries it (SAASA)"
else
  fail "10 each prompt is recorded before the model call that carries it (order '$(q "$ORDER")', want SAASA)"
fi

os sandbox delete "$A" >/dev/null
STATUS="select status from sessions where workflow_id='$ID'"
ENDED="select count(*) $EV and event_type='WorkflowCompleted' and duration_ms is not null"
if wait_q 30 "$STATUS" completed && [ "$(q "$ENDED")" = 1 ]; then
  pass "6 deleting the sandbox completes the session, with its duration"
else
  fail "6 deleting the sandbox completes the session, with its duration (status '$(q "$STATUS")', timed ends $(q "$ENDED"))"
fi
SEALED="select count(*) from session_attestations a join sessions s on s.id=a.session_id where s.workflow_id='$ID'"
if wait_q 90 "$SEALED" 1; then
  pass "7 Core seals the completed session (attestation recorded)"
else
  fail "7 Core seals the completed session (attestations: $(q "$SEALED"))"
fi

echo "== The session (open it in the dashboard under the agent)"
$PSQL "select 'session ' || s.id || '  ' || s.status || '  ' || s.started_at || ' -> ' || coalesce(s.completed_at::text,'-')
       from sessions s where s.workflow_id='$ID'"
$PSQL "select '  ' || to_char(e.created_at,'HH24:MI:SS.MS') || '  ' || rpad(e.event_type,18) || rpad(coalesce(e.activity_type, e.signal_name, ''),28)
              || rpad(coalesce(e.activity_id, e.input->0->>'prompt', ''),42) || coalesce(round(e.duration_ms)::text || ' ms','')
       from governance_events e where e.workflow_id='$ID' order by e.created_at"
echo "== Front desk and middleware logs"
grep 'session' "$WORK/fd.log" || true
grep -E 'eval |completed request_id|prompt' "$WORK/mw.log" || true
[ $FAILED = 0 ] && echo "ALL PASS" || { echo "SOME FAILED (logs: rerun with KEEP=1)"; exit 1; }
