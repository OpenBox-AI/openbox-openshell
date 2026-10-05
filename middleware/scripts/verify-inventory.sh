#!/bin/sh
# Verify PROD-828 (with PROD-827): every OpenShell sandbox appears in the
# OpenBox AI Inventory, follows its policy changes and deletion, and the
# reconciler repairs what a missed post_commit event left wrong.
#
#   OBX_API_KEY_FILE=... OBX_WORKLOAD_KEY_FILE=... OBX_WORKLOAD_KID=... \
#     middleware/scripts/verify-inventory.sh
#
# Runs against a real OpenBox stack (backend with PROD-827, Core) and starts
# its own OpenShell v0.1.2 gateway (VM driver) with its own state, ports and
# CLI config. The front desk runs its inventory registration only (post_commit,
# fail open) and reconciles over the gateway API with the gateway's local
# client certificate.
#
# Required: an OpenBox agent with a Keycloak workload identity (IAM v3):
#   OBX_API_KEY_FILE        file with the agent's obx_ API key
#   OBX_WORKLOAD_KEY_FILE   file with the RSA private key registered with it
#   OBX_WORKLOAD_KID        that key's kid
#
# Optional:
#   OPENBOX_URL             Core, default http://localhost:8086
#   OPENBOX_BACKEND_URL     backend, default http://localhost:3000
#   OBX_PSQL                command that runs one SQL query against the
#                           backend database and prints unaligned rows
#                           (default: the local stack's Postgres on Colima)
#   OPENSHELL_PREFIX        OpenShell v0.1.2 install (default ~/openshell-repro)
#   OBX_GATEWAY_PORT        default 17790 (+1 health, +2 metrics)
#   OBX_FD_PORT             default 50171 (+1 inventory)
#   KEEP=1                  keep the work dir
#
# Prints PASS/FAIL per scenario, exits non-zero if any fail, and removes the
# sandboxes, gateway and front desk it created on exit. Inventory rows it
# created stay in the database, marked deleted.
set -eu

HERE=$(cd "$(dirname "$0")/.." && pwd)
PREFIX=${OPENSHELL_PREFIX:-$HOME/openshell-repro}
GW_PORT=${OBX_GATEWAY_PORT:-17790}
FD_PORT=${OBX_FD_PORT:-50171}
INV_PORT=$((FD_PORT + 1))
CORE=${OPENBOX_URL:-http://localhost:8086}
BACKEND=${OPENBOX_BACKEND_URL:-http://localhost:3000}
PSQL=${OBX_PSQL:-docker --context colima exec -i openbox-local-postgres-1 psql -U postgres -d openbox -tA -c}
: "${OBX_API_KEY_FILE:?set OBX_API_KEY_FILE}"
: "${OBX_WORKLOAD_KEY_FILE:?set OBX_WORKLOAD_KEY_FILE}"
: "${OBX_WORKLOAD_KID:?set OBX_WORKLOAD_KID}"
WORK=$(mktemp -d /tmp/obx-inv.XXXXXX)
RUN=$(($(date +%s) % 1000000))
A=obx-inv-a-$RUN
B=obx-inv-b-$RUN
C=obx-inv-c-$RUN
FAILED=0

ISOLATE="XDG_STATE_HOME=$WORK/state XDG_CONFIG_HOME=$WORK/config OPENSHELL_LOCAL_TLS_DIR=$WORK/tls"
os() { env $ISOLATE "$PREFIX/bin/openshell" "$@"; }

cleanup() {
  if [ -f "$WORK/gateway.pid" ]; then
    for s in "$A" "$B" "$C"; do os sandbox delete "$s" >/dev/null 2>&1 || true; done
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

# sandbox_id <name>: the gateway's id for a sandbox.
sandbox_id() {
  os sandbox get "$1" -o json 2>/dev/null |
    python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("id") or d.get("metadata",{}).get("id",""))'
}
# row <sandbox id>: "status|policy_version|session linked" of its inventory row.
row() {
  $PSQL "select status || '|' || coalesce(policy_version::text,'') || '|' || (session_id is not null)
         from agent_runtime_environments where runtime_kind='openshell' and external_id='$1'" | tr -d '[:space:]'
}
# wait_row <sandbox id> <pattern> <seconds>: until the row matches; prints it.
wait_row() {
  i=0
  while :; do
    got=$(row "$1")
    case "$got" in $2) echo "$got"; return 0 ;; esac
    i=$((i + 1))
    [ $i -le "$3" ] || { echo "$got"; return 1; }
    sleep 1
  done
}
create() {
  os sandbox create --name "$1" --policy "$WORK/policy.yaml" --detach --no-tty --no-auto-providers >/dev/null
}

# start_fd <backend url> <log>: the front desk's inventory registration.
start_fd() {
  OPENBOX_FD_INSECURE=1 OPENBOX_FD_LISTEN=127.0.0.1:$FD_PORT OPENBOX_FD_INVENTORY_LISTEN=127.0.0.1:$INV_PORT \
    OPENBOX_FD_GATEWAY_ID=obx-verify-inventory \
    OPENBOX_BACKEND_URL=$1 OPENBOX_URL=$CORE OPENBOX_API_KEY_FILE=$OBX_API_KEY_FILE \
    OPENBOX_WORKLOAD_KEY_FILE=$OBX_WORKLOAD_KEY_FILE OPENBOX_WORKLOAD_KID=$OBX_WORKLOAD_KID \
    OPENBOX_GATEWAY_ENDPOINT=https://localhost:$GW_PORT OPENBOX_GATEWAY_MTLS_DIR=$WORK/gwclient \
    OPENBOX_FD_RECONCILE_SECS=5 \
    "$HERE/target/debug/openbox-governance-interceptor" >"$2" 2>&1 &
  echo $! >"$WORK/fd.pid"
  wait_listen "$INV_PORT" "$WORK/fd.pid" "$2"
}
stop_fd() {
  kill "$(cat "$WORK/fd.pid")"
  rm "$WORK/fd.pid"
  while ! free "$INV_PORT"; do sleep 0.2; done
}

for port in "$GW_PORT" $((GW_PORT + 1)) $((GW_PORT + 2)) "$FD_PORT" "$INV_PORT"; do
  free "$port" || { echo "port $port is in use; set OBX_GATEWAY_PORT / OBX_FD_PORT"; exit 1; }
done
[ -x "$PREFIX/bin/openshell-gateway" ] && [ -x "$PREFIX/libexec/openshell-driver-vm" ] ||
  { echo "set OPENSHELL_PREFIX to an OpenShell v0.1.2 install (see verify-provider-profiles.sh)"; exit 1; }

echo "== OpenBox stack"
curl -fsS -o /dev/null "$BACKEND/health" || { echo "backend not reachable at $BACKEND"; exit 1; }
code=$(curl -s -o /dev/null -w '%{http_code}' "$BACKEND/api/v3/runtime-environments")
[ "$code" = 401 ] || { echo "backend at $BACKEND has no runtime-environment routes (HTTP $code); it needs PROD-827"; exit 1; }
$PSQL "select 1" >/dev/null || { echo "OBX_PSQL cannot query the backend database"; exit 1; }
"$PREFIX/bin/openshell" --version

echo "== Build the front desk"
(cd "$HERE" && cargo build -q --bin openbox-governance-interceptor)

echo "== Gateway with the inventory registration (post_commit, fail open)"
mkdir -p "$WORK/state/openshell/vm-driver" "$WORK/config" "$WORK/gwclient"
# Reuse an already prepared VM image instead of building one (read only).
[ -d "$HOME/.local/state/openshell/vm-driver/images" ] &&
  ln -s "$HOME/.local/state/openshell/vm-driver/images" "$WORK/state/openshell/vm-driver/images"
"$PREFIX/bin/openshell-gateway" generate-certs --output-dir "$WORK/tls" --server-san localhost >/dev/null 2>&1
cp "$WORK/tls/ca.crt" "$WORK/gwclient/ca.crt"
cp "$WORK/tls/client/tls.crt" "$WORK/tls/client/tls.key" "$WORK/gwclient/"
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
rpc = "openshell.v1.OpenShell/UpdateConfig"
phases = ["post_commit"]

[[openshell.gateway.interceptors.bindings]]
rpc = "openshell.v1.OpenShell/DeleteSandbox"
phases = ["post_commit"]
EOF
start_fd "$BACKEND" "$WORK/fd.log"
env $ISOLATE "$PREFIX/bin/openshell-gateway" --config "$WORK/gateway.toml" >"$WORK/gateway.log" 2>&1 &
echo $! >"$WORK/gateway.pid"
wait_listen "$GW_PORT" "$WORK/gateway.pid" "$WORK/gateway.log"
os gateway add "https://127.0.0.1:$GW_PORT" --local --name obx-verify-inventory >/dev/null

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
network_policies:
  example:
    name: example
    endpoints:
      - host: example.com
        port: 80
        protocol: rest
        access: read-only
    binaries:
      - path: /usr/bin/bash
EOF
sed 's/access: read-only/access: read-write/' "$WORK/policy.yaml" >"$WORK/policy-v2.yaml"

echo "== Scenarios"
started=$(date +%s)
create "$A"
ID_A=$(sandbox_id "$A")
if got=$(wait_row "$ID_A" 'active|*' 10); then
  pass "1 a created sandbox is in the inventory within $(($(date +%s) - started)) s ($got)"
else
  fail "1 a created sandbox is in the inventory within 10 s (row: '${got:-none}')"
fi

before=$(row "$ID_A" | cut -d'|' -f2)
if os policy set "$A" --policy "$WORK/policy-v2.yaml" --wait --timeout 120 >/dev/null 2>&1; then
  # UpdateConfig names no sandbox; the triggered reconcile reads the version.
  if got=$(wait_row "$ID_A" "active|*" 20) && after=$(echo "$got" | cut -d'|' -f2) &&
    [ -n "$after" ] && [ "$after" != "$before" ]; then
    pass "2 a policy change updates the row's policy version ($before -> $after)"
  else
    fail "2 a policy change updates the row's policy version (was '$before', row '$got')"
  fi
else
  fail "2 policy set on $A failed"
fi

os sandbox delete "$A" >/dev/null
if got=$(wait_row "$ID_A" 'deleted|*' 10); then
  pass "3 a deleted sandbox is marked deleted ($got)"
else
  fail "3 a deleted sandbox is marked deleted (row: '$got')"
fi

echo "== Backend unreachable during a create, then the reconciler"
stop_fd
start_fd "http://127.0.0.1:9" "$WORK/fd-down.log"
create "$B"
ID_B=$(sandbox_id "$B")
sleep 3
if [ -n "$ID_B" ] && [ -z "$(row "$ID_B")" ] && grep -q 'inventory write failed' "$WORK/fd-down.log"; then
  pass "4 backend down: the create still succeeds, the write fails and is logged"
else
  fail "4 backend down: the create still succeeds, the write fails and is logged (row: '$(row "$ID_B")')"
fi
stop_fd
start_fd "$BACKEND" "$WORK/fd-up.log"
if got=$(wait_row "$ID_B" 'active|*' 15); then
  pass "5 backend back: the reconciler records the missed sandbox ($got)"
else
  fail "5 backend back: the reconciler records the missed sandbox (row: '$got')"
fi

echo "== Deleted while the front desk was down"
create "$C"
ID_C=$(sandbox_id "$C")
wait_row "$ID_C" 'active|*' 10 >/dev/null || true
stop_fd
os sandbox delete "$C" >/dev/null
start_fd "$BACKEND" "$WORK/fd-again.log"
if got=$(wait_row "$ID_C" 'deleted|*' 15); then
  pass "6 the reconciler deletes a row whose sandbox is gone ($got)"
else
  fail "6 the reconciler deletes a row whose sandbox is gone (row: '$got')"
fi

echo "== Front desk log (last run)"
grep 'inventory' "$WORK/fd-again.log" | tail -5 || true
[ $FAILED = 0 ] && echo "ALL PASS" || { echo "SOME FAILED (logs: rerun with KEEP=1)"; exit 1; }
