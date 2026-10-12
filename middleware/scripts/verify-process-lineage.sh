#!/bin/sh
# Verify PROD-891: every request the door guard scores carries the process
# inside the sandbox that made it, so a policy or behaviour rule can match on
# the program as well as the destination. On the request's span:
#
#   process.executable.path     the binary, e.g. /usr/bin/bash
#   openbox.process.ancestors   its ancestors, nearest parent first
#   openbox.sandbox.id          the sandbox
#   sandbox.provider            openshell
#
#   OBX_BACKEND_URL=https://api.example OBX_BACKEND_API_KEY_FILE=org-key \
#     middleware/scripts/verify-process-lineage.sh agent.env
#
# agent.env is the dashboard snippet for an agent with a workload identity
# (OPENBOX_API_URL, OPENBOX_API_KEY, OPENBOX_WORKLOAD_PRIVATE_KEY), on any
# OpenBox: shared staging or the local stack. The script brings up its own
# OpenShell v0.1.2 gateway, front desk and door guard with
# openbox-openshell.sh, in its own directory and on its own ports, so it never
# touches a dev environment you already run.
#
# The span is read back the way the dashboard reads it: from the backend's
# session logs (pages count from 0), with an organisation API key
# (X-API-Key) that may read agent sessions and logs:
#   OBX_BACKEND_URL           the backend, e.g. https://api.<env>
#   OBX_BACKEND_API_KEY_FILE  file with the organisation API key
# Without them, scenarios 3-5 are reported SKIP, not PASS, and the lineage is
# not checked at all: scenarios 1-2 only show the request was governed.
#
# Optional:
#   OPENBOX_REDIS_URL         shared store (default redis://localhost:6379/7)
#   OPENSHELL_PREFIX, OBX_HOST_IP   as for openbox-openshell.sh
#   KEEP=1                    keep the work dir and its logs
#
# Prints PASS/FAIL/SKIP per scenario, exits non-zero if any fail, and stops
# everything it started on exit. The Core session stays for the dashboard.
set -eu

AGENT_ENV=${1:?usage: $0 agent.env}
[ -f "$AGENT_ENV" ] || { echo "no such file: $AGENT_ENV"; exit 1; }
HERE=$(cd "$(dirname "$0")" && pwd)
export OBX_DEV_DIR=${OBX_DEV_DIR:-/tmp/obx-pl$$}
export OBX_GATEWAY_PORT=${OBX_GATEWAY_PORT:-18090}
export OBX_MW_PORT=${OBX_MW_PORT:-50451}
export OBX_FD_PORT=${OBX_FD_PORT:-50471}
export OBX_MODEL_PORT=${OBX_MODEL_PORT:-18095}
export OPENBOX_BACKEND_URL=-
BACKEND=${OBX_BACKEND_URL:-}
BACKEND_KEY_FILE=${OBX_BACKEND_API_KEY_FILE:-}
BOX=obx-lineage-$(($(date +%s) % 1000000))
FAILED=0

bring() { "$HERE/openbox-openshell.sh" "$@"; }
os() { "$OBX_DEV_DIR/bin/openshell" "$@"; }
cleanup() {
  bring down >/dev/null 2>&1 || true
  if [ "${KEEP:-0}" = 1 ]; then echo "kept $OBX_DEV_DIR"; else rm -rf "$OBX_DEV_DIR"; fi
}
trap cleanup EXIT INT TERM
pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1"; FAILED=1; }
skip() { echo "SKIP  $1"; }

# backend <path>: GET from the backend with the organisation API key.
backend() {
  curl -fsS -H "X-API-Key: $(cat "$BACKEND_KEY_FILE")" -H 'User-Agent: verify-process-lineage.sh' \
    "${BACKEND%/}$1"
}

echo "== Bring up OpenShell governed by OpenBox ($OBX_DEV_DIR)"
bring up --agent-env "$AGENT_ENV"
. "$OBX_DEV_DIR/agent"
echo "   Core $CORE, agent $AGENT_ID"

echo "== Scenarios"
os sandbox create --name "$BOX" --policy "$OBX_DEV_DIR/policy.yaml" --detach --no-tty --no-auto-providers >/dev/null
ID=$(os sandbox get "$BOX" -o json |
  python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("id") or d.get("metadata",{}).get("id",""))')
[ -n "$ID" ] || { echo "sandbox $BOX did not come up"; exit 1; }
# A request still waiting on a verdict when the sandbox's first settings poll
# reloads its policy is dropped; let it settle first.
i=0
until os logs "$BOX" --source sandbox 2>/dev/null | grep -q 'Settings poll'; do
  i=$((i + 1)); [ $i -le 30 ] || break; sleep 1
done

# bash makes the request, started by sh: the lineage is bash, then sh.
# stdin is closed: sandbox exec forwards stdin and waits for its end.
code=$(os sandbox exec -n "$BOX" --no-tty --timeout 60 -- sh -c 'bash -c '"'"'
  exec 3<>/dev/tcp/example.com/80 || { echo "connect failed"; exit 0; }
  printf "GET /?lineage=1 HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n" >&3
  IFS=" " read -r _ code _ <&3; echo "${code:-none}"'"'" </dev/null 2>&1 | tail -1 || true)
if [ "$code" = 200 ]; then
  pass "1 a request from bash in the sandbox is allowed by Core (HTTP 200)"
else
  fail "1 a request from bash in the sandbox is allowed by Core (got '$code')"
fi
if grep -q "eval .*sandbox_id=$ID decision=allow" "$OBX_DEV_DIR/door-guard.log"; then
  pass "2 the door guard scored it with Core (allow in its log)"
else
  fail "2 the door guard scored it with Core (no allow in $OBX_DEV_DIR/door-guard.log)"
fi

if [ -z "$BACKEND" ] || [ -z "$BACKEND_KEY_FILE" ]; then
  skip "3-5 the stored span (set OBX_BACKEND_URL and OBX_BACKEND_API_KEY_FILE)"
else
  # The session Core opened for this sandbox, found by its workflow id.
  SESSION=
  i=0
  while [ -z "$SESSION" ] && [ $i -lt 30 ]; do
    SESSION=$(backend "/agent/$AGENT_ID/sessions?page=0&perPage=50" 2>/dev/null | python3 -c '
import json, sys
want = sys.argv[1]
def walk(node):
    if isinstance(node, dict):
        if node.get("workflow_id") == want and node.get("id"):
            print(node["id"]); sys.exit(0)
        for value in node.values(): walk(value)
    elif isinstance(node, list):
        for value in node: walk(value)
walk(json.load(sys.stdin))' "$ID" || true)
    i=$((i + 1)); [ -n "$SESSION" ] || sleep 2
  done
  if [ -z "$SESSION" ]; then
    fail "3-5 the sandbox's session is in the backend (none with workflow_id $ID)"
  else
    # Every span in the session's logs whose URL is the request above.
    got=""
    i=0
    while [ -z "$got" ] && [ $i -lt 30 ]; do
      got=$(backend "/agent/$AGENT_ID/sessions/$SESSION/logs/chronological?page=0&perPage=100" 2>/dev/null |
        python3 -c '
import json, sys
found = []
def walk(node):
    if isinstance(node, dict):
        attrs = node.get("attributes")
        if isinstance(attrs, dict) and "lineage=1" in str(attrs.get("http.url", "")):
            found.append(attrs)
        for value in node.values(): walk(value)
    elif isinstance(node, list):
        for value in node: walk(value)
    elif isinstance(node, str) and node[:1] in "[{":
        try: walk(json.loads(node))
        except ValueError: pass
walk(json.load(sys.stdin))
if found:
    a = found[0]
    print(json.dumps({k: a.get(k) for k in ("process.executable.path", "openbox.process.ancestors",
                                            "openbox.sandbox.id", "sandbox.provider")}))' || true)
      i=$((i + 1)); [ -n "$got" ] || sleep 2
    done
    echo "   stored span attributes: ${got:-none}"
    check() { printf '%s' "$got" | python3 -c "import json,sys; a=json.load(sys.stdin); sys.exit(0 if $1 else 1)" 2>/dev/null; }
    if check 'a["process.executable.path"] == "/usr/bin/bash"'; then
      pass "3 the stored span names the program: process.executable.path = /usr/bin/bash"
    else
      fail "3 the stored span names the program: process.executable.path = /usr/bin/bash"
    fi
    if check 'isinstance(a["openbox.process.ancestors"], list) and a["openbox.process.ancestors"] and a["openbox.process.ancestors"][0] != "/usr/bin/bash"'; then
      pass "4 the stored span carries the ancestors, nearest parent (the sh that started bash) first"
    else
      fail "4 the stored span carries the ancestors, nearest parent (the sh that started bash) first"
    fi
    if check "a['openbox.sandbox.id'] == '$ID' and a['sandbox.provider'] == 'openshell'"; then
      pass "5 the stored span names the sandbox ($ID) and the provider (openshell)"
    else
      fail "5 the stored span names the sandbox ($ID) and the provider (openshell)"
    fi
  fi
fi

echo "== Door guard log for the request"
grep "eval .*sandbox_id=$ID" "$OBX_DEV_DIR/door-guard.log" | tail -5 || true
echo "Session: agent $AGENT_ID, sandbox $ID${SESSION:+, session $SESSION}"
[ $FAILED = 0 ] && echo "ALL PASS" || { echo "SOME FAILED (keep the logs with KEEP=1)"; exit 1; }
