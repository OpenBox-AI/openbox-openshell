#!/bin/sh
# Verify PROD-772: a slow Core verdict (full policy, guardrails and behaviour
# rules) reaches the sandbox, inside OpenShell's 30 s middleware timeout.
#
#   middleware/scripts/verify-core-timeout.sh
#
# Real OpenShell v0.1.2 gateway and sandbox (VM driver), the real door guard,
# and a fake Core whose answer delay is set per scenario. A sandbox's first
# request through a fresh door guard makes two Core calls (session start and
# evaluation; the approval check only runs for a retry holding an approval,
# PROD-839):
#
#   A  Core takes 13 s per call (26 s per verdict): the request goes through
#   B  Core takes 15 s per call (30 s): explicit deny openbox_unavailable at
#      29 s, before the gateway's 30 s, so the sandbox sees OpenBox's reason
#   C  the old 450 ms door guard default with the same 9 s Core: denied at
#      once. This is what the change fixes
#   D  (informational, needs internet) the same 17 s allow to example.com
#      gets no response: OpenShell opens the upstream connection before the
#      verdict and example.com drops it after ~15 s idle. A real destination's
#      idle timeout, not only the 30 s, bounds how slow a verdict can be
#
# The requests go from bash inside the sandbox (the default image has no
# curl) to a local HTTP server on this machine, reached from the sandbox as
# host.openshell.internal, so the result doesn't depend on a public host.
#
# Isolated state, ports and CLI config: no gateway you already run is touched.
# Prints PASS/FAIL per scenario, exits non-zero if any fail, removes
# everything on exit (KEEP=1 keeps the logs; HOLD=1 stops once the sandbox is
# up and prints a CLI wrapper, so you can poke at it). Takes about 5 minutes; most of
# it is the sandbox booting.
#
# Needs the OpenShell v0.1.2 release binaries in OPENSHELL_PREFIX (default
# ~/openshell-repro: bin/openshell, bin/openshell-gateway,
# libexec/openshell-driver-vm), python3 and cargo.
# Optional: OBX_GATEWAY_PORT (default 17790; +1, +2 health and metrics),
# OBX_MW_PORT (default 50181; +1 admin), OBX_CORE_PORT (default 18790),
# OBX_UPSTREAM_PORT (default 18791).
set -eu

HERE=$(cd "$(dirname "$0")/.." && pwd)
PREFIX=${OPENSHELL_PREFIX:-$HOME/openshell-repro}
GW_PORT=${OBX_GATEWAY_PORT:-17790}
MW_PORT=${OBX_MW_PORT:-50181}
CORE_PORT=${OBX_CORE_PORT:-18790}
UP_PORT=${OBX_UPSTREAM_PORT:-18791}
SANDBOX=obx-timeout
# A short path: the VM driver's unix socket must fit in SUN_LEN.
WORK=$(mktemp -d /tmp/obx-verify.XXXXXX)
FAILED=0

cleanup() {
  [ -f "$WORK/gateway.pid" ] && os sandbox delete "$SANDBOX" >/dev/null 2>&1 || true
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
    kill -0 "$(cat "$2")" 2>/dev/null || { echo "process for :$1 exited:"; tail -20 "$3"; exit 1; }
    [ $i -lt 120 ] || { echo "nothing listening on :$1"; exit 1; }
    sleep 0.5
  done
}
stop() { [ -f "$WORK/$1.pid" ] && kill "$(cat "$WORK/$1.pid")" 2>/dev/null; rm -f "$WORK/$1.pid"; }

for port in "$GW_PORT" $((GW_PORT + 1)) $((GW_PORT + 2)) "$MW_PORT" $((MW_PORT + 1)) "$CORE_PORT" "$UP_PORT"; do
  free "$port" || { echo "port $port is in use; set OBX_GATEWAY_PORT / OBX_MW_PORT / OBX_CORE_PORT / OBX_UPSTREAM_PORT"; exit 1; }
done
[ -x "$PREFIX/bin/openshell-gateway" ] && [ -x "$PREFIX/libexec/openshell-driver-vm" ] ||
  { echo "set OPENSHELL_PREFIX to an OpenShell v0.1.2 install"; exit 1; }
"$PREFIX/bin/openshell" --version

# Fake Core: answers the door guard's v1 evaluate and approval calls after
# DELAY seconds. Evaluate always allows; approval reports none (404).
cat >"$WORK/core.py" <<'EOF'
import http.server, json, os, sys, time
DELAY = float(os.environ["DELAY"])
class Core(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get("content-length", 0)))
        time.sleep(DELAY)
        if self.path.endswith("/governance/approval"):
            self.send_response(404); self.end_headers(); return
        body = json.dumps({"verdict": "allow", "action": "allow",
                           "governance_event_id": "evt-test"}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers(); self.wfile.write(body)
    def log_message(self, fmt, *args):
        print(f"{time.strftime('%H:%M:%S')} {self.path}", flush=True)
http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), Core).serve_forever()
EOF

# The destination: answers any GET with 200, holds idle connections 120 s.
cat >"$WORK/upstream.py" <<'EOF'
import http.server, sys
class Upstream(http.server.BaseHTTPRequestHandler):
    timeout = 120
    def do_GET(self):
        self.send_response(200); self.send_header("content-length", "2")
        self.end_headers(); self.wfile.write(b"ok")
    def log_message(self, *args): pass
http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), Upstream).serve_forever()
EOF
python3 "$WORK/upstream.py" "$UP_PORT" >"$WORK/upstream.log" 2>&1 &
echo $! >"$WORK/upstream.pid"
wait_listen "$UP_PORT" "$WORK/upstream.pid" "$WORK/upstream.log"

echo "== Build the door guard"
(cd "$HERE" && cargo build -q --bin openbox-verdict-middleware)
echo "obx_test_key" >"$WORK/api-key"

# start_stack <core delay s> [door guard Core budget ms]; empty budget = default
start_stack() {
  stop core; stop mw
  while ! free "$CORE_PORT" || ! free "$MW_PORT"; do sleep 0.2; done
  DELAY=$1 python3 "$WORK/core.py" "$CORE_PORT" >"$WORK/core.log" 2>&1 &
  echo $! >"$WORK/core.pid"
  wait_listen "$CORE_PORT" "$WORK/core.pid" "$WORK/core.log"
  env OPENBOX_MW_INSECURE=1 OPENBOX_MW_LISTEN=127.0.0.1:$MW_PORT \
    OPENBOX_MW_ADMIN_LISTEN=127.0.0.1:$((MW_PORT + 1)) \
    OPENBOX_URL=http://127.0.0.1:$CORE_PORT OPENBOX_API_KEY_FILE="$WORK/api-key" \
    ${2:+OPENBOX_CORE_TIMEOUT_MS=$2} \
    "$HERE/target/debug/openbox-verdict-middleware" >>"$WORK/mw.log" 2>&1 &
  echo $! >"$WORK/mw.pid"
  wait_listen "$MW_PORT" "$WORK/mw.pid" "$WORK/mw.log"
}

echo "== Gateway with the door guard registered at timeout = 30s"
cat >"$WORK/gateway.toml" <<EOF
[openshell]
version = 2

[openshell.gateway]
compute_driver = "vm"
bind_address = "127.0.0.1:$GW_PORT"
health_bind_address = "127.0.0.1:$((GW_PORT + 1))"
metrics_bind_address = "127.0.0.1:$((GW_PORT + 2))"

[[openshell.supervisor.middleware]]
name = "openbox"
grpc_endpoint = "http://127.0.0.1:$MW_PORT"
allow_insecure_transport = true
max_payload_bytes = 1048576
timeout = "30s"
EOF
mkdir -p "$WORK/state/openshell/vm-driver" "$WORK/config"
# Reuse an already prepared VM image instead of building one (read only).
[ -d "$HOME/.local/state/openshell/vm-driver/images" ] &&
  ln -s "$HOME/.local/state/openshell/vm-driver/images" "$WORK/state/openshell/vm-driver/images"
ISOLATE="XDG_STATE_HOME=$WORK/state XDG_CONFIG_HOME=$WORK/config OPENSHELL_LOCAL_TLS_DIR=$WORK/tls"
os() { env $ISOLATE "$PREFIX/bin/openshell" "$@"; }
"$PREFIX/bin/openshell-gateway" generate-certs --output-dir "$WORK/tls" --server-san localhost >/dev/null 2>&1
start_stack 0
env $ISOLATE "$PREFIX/bin/openshell-gateway" --config "$WORK/gateway.toml" >"$WORK/gateway.log" 2>&1 &
echo $! >"$WORK/gateway.pid"
wait_listen "$GW_PORT" "$WORK/gateway.pid" "$WORK/gateway.log"
os gateway add "https://127.0.0.1:$GW_PORT" --local --name obx-verify >/dev/null

echo "== Sandbox whose example.com traffic goes through the door guard"
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
      - host: host.openshell.internal
        port: UP_PORT
        protocol: rest
        access: read-only
        allowed_ips: ["0.0.0.0/0"]
      - host: example.com
        port: 80
        protocol: rest
        access: read-only
    binaries:
      - path: /usr/bin/bash
network_middlewares:
  openbox:
    middleware: openbox
    on_error: fail_closed
    endpoints:
      include: ["**"]
EOF
sed -i.bak "s/UP_PORT/$UP_PORT/" "$WORK/policy.yaml"
os sandbox create --name "$SANDBOX" --policy "$WORK/policy.yaml" --detach --no-tty --no-auto-providers >/dev/null
i=0
until [ "$(os sandbox get "$SANDBOX" -o json 2>/dev/null | python3 -c 'import sys,json;print(json.load(sys.stdin).get("phase"))' 2>/dev/null)" = Ready ]; do
  i=$((i + 1)); [ $i -lt 200 ] || { echo "sandbox not ready"; tail -20 "$WORK/gateway.log"; exit 1; }
  sleep 3
done
echo "sandbox ready"
# The supervisor's first settings poll (~10 s in) reports a provider
# environment change and bumps its policy generation, which closes every
# connection still waiting on a verdict ("policy generation is stale"). Let it
# pass first so it can't land inside a slow scenario.
i=0
until os logs "$SANDBOX" -n 500 2>/dev/null | grep -q 'CONFIG:DETECTED'; do
  i=$((i + 1)); [ $i -lt 30 ] || { echo "no settings poll after 60 s; continuing"; break; }
  sleep 2
done
sleep 2
if [ "${HOLD:-0}" = 1 ]; then
  printf '#!/bin/sh\nexec env %s "%s" "$@"\n' "$ISOLATE" "$PREFIX/bin/openshell" >"$WORK/os"
  chmod +x "$WORK/os"
  echo "HOLD=1: stack is up. CLI: $WORK/os sandbox exec -n $SANDBOX -- <cmd>. Ctrl-C to tear down."
  while :; do sleep 60 & wait $!; done
fi

# request [host port]: one HTTP GET from inside the sandbox with bash's
# /dev/tcp; sets CODE (empty if no response) and SECS. Default: the local
# upstream. stdin is closed: sandbox exec forwards stdin and waits for its end.
request() {
  host=${1:-host.openshell.internal}
  port=${2:-$UP_PORT}
  authority=$host:$port
  [ "$port" = 80 ] && authority=$host
  started=$(date +%s)
  os sandbox exec -n "$SANDBOX" --timeout 90 -- bash -c "
    exec 3<>/dev/tcp/$host/$port || exit 1
    printf 'GET / HTTP/1.1\r\nHost: $authority\r\nConnection: close\r\n\r\n' >&3
    head -1 <&3" </dev/null >"$WORK/last-request.txt" 2>&1 || true
  SECS=$(($(date +%s) - started))
  CODE=$(awk '/^HTTP\//{print $2; exit}' "$WORK/last-request.txt")
}
# what the last request printed, for failure messages
raw() { tr -d '\r' <"$WORK/last-request.txt" | tail -3 | tr '\n' ' '; }
evals() { grep -c 'openbox: eval ' "$WORK/mw.log" || true; }
last_eval() { grep 'openbox: eval ' "$WORK/mw.log" | tail -1; }

echo "== Scenarios"
start_stack 0
request
if [ "$CODE" = 200 ] && [ "$(evals)" -ge 1 ]; then
  pass "0 fast Core: request allowed through the door guard (${SECS}s)"
else
  fail "0 fast Core: expected 200 via the door guard, got '$CODE' (evals: $(evals)) [$(raw)]; the rest is meaningless"
fi

start_stack 13
request
if [ "$CODE" = 200 ] && [ "$SECS" -ge 25 ] && last_eval | grep -q 'decision=allow'; then
  pass "A Core 13 s per call (26 s verdict): allowed after ${SECS}s"
else
  fail "A Core 13 s per call: expected 200 after ~26 s, got '$CODE' after ${SECS}s [$(raw)]: $(last_eval)"
fi

start_stack 15
request
if [ "$CODE" = 403 ] && [ "$SECS" -ge 28 ] && [ "$SECS" -le 31 ] &&
  last_eval | grep -q 'reason_code=openbox_unavailable'; then
  pass "B Core 15 s per call (30 s verdict): explicit openbox_unavailable deny after ${SECS}s"
else
  fail "B Core 15 s per call: expected 403 openbox_unavailable at ~29 s, got '$CODE' after ${SECS}s [$(raw)]: $(last_eval)"
fi

start_stack 9 450
request
if [ "$CODE" = 403 ] && [ "$SECS" -le 5 ] && last_eval | grep -q 'reason_code=openbox_unavailable'; then
  pass "C old 450 ms budget, Core 9 s: denied after ${SECS}s (every real verdict would be)"
else
  fail "C old 450 ms budget: expected a quick 403 openbox_unavailable, got '$CODE' after ${SECS}s [$(raw)]: $(last_eval)"
fi

start_stack 8.5
request example.com 80
if [ -z "$CODE" ]; then
  echo "INFO  D example.com, 17 s allow: no response after ${SECS}s (its ~15 s idle timeout dropped the upstream)"
else
  echo "INFO  D example.com, 17 s allow: got '$CODE' after ${SECS}s (not the idle drop; see the door guard log)"
fi

# E: the D verdict (~17 s) is visible in the latency histogram, not lumped
# into +Inf above a 10 s top bucket.
M=$(curl -s "http://127.0.0.1:$((MW_PORT + 1))/metrics")
b15=$(echo "$M" | awk -F' ' '/^openbox_mw_evaluation_duration_seconds_bucket\{le="15"\}/{print $2}')
b20=$(echo "$M" | awk -F' ' '/^openbox_mw_evaluation_duration_seconds_bucket\{le="20"\}/{print $2}')
if [ "$b15" = 0 ] && [ "$b20" = 1 ]; then
  pass "E /metrics: the ~17 s verdict falls in the 15-20 s bucket"
else
  fail "E /metrics: expected le=15 0 and le=20 1, got le=15 '$b15' le=20 '$b20'"
fi

echo "== Door guard verdicts"
grep 'openbox: eval ' "$WORK"/mw.log || true
[ $FAILED = 0 ] && echo "ALL PASS" || { echo "SOME FAILED (rerun with KEEP=1 for logs)"; exit 1; }
