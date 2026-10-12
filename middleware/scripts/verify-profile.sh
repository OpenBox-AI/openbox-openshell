#!/bin/sh
# Verify PROD-892: a sandbox whose policy names a profile has it sent to Core
# as profile_id on every activity, so a policy can tell one kind of sandbox
# from another under the same agent. The profile is set where a policy
# author sets the door guard's other settings:
#
#   network_middlewares:
#     openbox:
#       config: { profile: coding }
#
#   OBX_BACKEND_URL=https://api.example OBX_BACKEND_API_KEY_FILE=org-key \
#     middleware/scripts/verify-profile.sh agent.env
#
# agent.env is the dashboard snippet for an agent with a workload identity
# (OPENBOX_API_URL, OPENBOX_API_KEY, OPENBOX_WORKLOAD_PRIVATE_KEY), on any
# OpenBox: shared staging or the local stack. The script brings up its own
# OpenShell v0.1.2 gateway, front desk and door guard with
# openbox-openshell.sh, in its own directory and on its own ports, so it never
# touches a dev environment you already run.
#
# The events are read back the way the dashboard reads them: from the
# backend's session logs, with an organisation API key (X-API-Key) that may
# read agent sessions and logs:
#   OBX_BACKEND_URL           the backend, e.g. https://api.<env>
#   OBX_BACKEND_API_KEY_FILE  file with the organisation API key
# Without them, scenarios 3-4 are reported SKIP, not PASS.
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
export OBX_DEV_DIR=${OBX_DEV_DIR:-/tmp/obx-pf$$}
export OBX_GATEWAY_PORT=${OBX_GATEWAY_PORT:-18190}
export OBX_MW_PORT=${OBX_MW_PORT:-50551}
export OBX_FD_PORT=${OBX_FD_PORT:-50571}
export OBX_MODEL_PORT=${OBX_MODEL_PORT:-18195}
export OPENBOX_BACKEND_URL=-
BACKEND=${OBX_BACKEND_URL:-}
BACKEND_KEY_FILE=${OBX_BACKEND_API_KEY_FILE:-}
BOX=obx-profile-$(($(date +%s) % 1000000))
PROFILE=coding
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
  curl -fsS -H "X-API-Key: $(cat "$BACKEND_KEY_FILE")" -H 'User-Agent: verify-profile.sh' \
    "${BACKEND%/}$1"
}

echo "== Bring up OpenShell governed by OpenBox ($OBX_DEV_DIR)"
bring up --agent-env "$AGENT_ENV"
. "$OBX_DEV_DIR/agent"
echo "   Core $CORE, agent $AGENT_ID"

# The bring-up's plain policy, plus the author's door guard settings. The
# front desk completes the attachment and must keep them.
cp "$OBX_DEV_DIR/policy.yaml" "$OBX_DEV_DIR/profiled.yaml"
cat >>"$OBX_DEV_DIR/profiled.yaml" <<EOF
network_middlewares:
  openbox:
    name: OpenBox governance
    middleware: openbox
    order: 10
    on_error: fail_closed
    endpoints:
      include:
        - "**"
    config:
      profile: $PROFILE
EOF

echo "== Scenarios"
os sandbox create --name "$BOX" --policy "$OBX_DEV_DIR/profiled.yaml" --detach --no-tty --no-auto-providers >/dev/null
ID=$(os sandbox get "$BOX" -o json |
  python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("id") or d.get("metadata",{}).get("id",""))')
[ -n "$ID" ] || { echo "sandbox $BOX did not come up"; exit 1; }
if os sandbox get "$BOX" -o json | grep -q "\"profile\": *\"$PROFILE\""; then
  pass "1 the sandbox's effective policy keeps profile: $PROFILE on the OpenBox attachment"
else
  fail "1 the sandbox's effective policy keeps profile: $PROFILE on the OpenBox attachment"
fi
i=0
until os logs "$BOX" --source sandbox 2>/dev/null | grep -q 'Settings poll'; do
  i=$((i + 1)); [ $i -le 30 ] || break; sleep 1
done

code=$(os sandbox exec -n "$BOX" --no-tty --timeout 60 -- bash -c '
  exec 3<>/dev/tcp/example.com/80 || { echo "connect failed"; exit 0; }
  printf "GET /?profile=1 HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n" >&3
  IFS=" " read -r _ code _ <&3; echo "${code:-none}"' 2>&1 | tail -1 || true)
if [ "$code" = 200 ] && grep -q "eval .*sandbox_id=$ID decision=allow" "$OBX_DEV_DIR/door-guard.log"; then
  pass "2 a request from the profiled sandbox is scored by Core and allowed (HTTP 200)"
else
  fail "2 a request from the profiled sandbox is scored by Core and allowed (got '$code')"
fi

if [ -z "$BACKEND" ] || [ -z "$BACKEND_KEY_FILE" ]; then
  skip "3-4 the stored events (set OBX_BACKEND_URL and OBX_BACKEND_API_KEY_FILE)"
else
  SESSION=
  i=0
  while [ -z "$SESSION" ] && [ $i -lt 30 ]; do
    SESSION=$(backend "/agent/$AGENT_ID/sessions?page=1&perPage=50" 2>/dev/null | python3 -c '
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
    fail "3-4 the sandbox's session is in the backend (none with workflow_id $ID)"
  else
    # "<activity events> <with profile_id = PROFILE>" once the request's
    # start and completion have both arrived.
    got=""
    i=0
    while [ $i -lt 30 ]; do
      got=$(backend "/agent/$AGENT_ID/sessions/$SESSION/logs/chronological?page=1&perPage=100" 2>/dev/null |
        python3 -c '
import json, sys
want = sys.argv[1]
events = {}
def profile(node):
    meta = node.get("metadata")
    if isinstance(meta, str):
        try: meta = json.loads(meta)
        except ValueError: meta = None
    return node.get("profile_id") or (meta or {}).get("profile_id")
def walk(node):
    if isinstance(node, dict):
        kind = node.get("event_type")
        if node.get("activity_id") and kind in ("ActivityStarted", "ActivityCompleted"):
            key = node.get("id") or (node["activity_id"], kind, len(events))
            events[str(key)] = profile(node)
        for value in node.values(): walk(value)
    elif isinstance(node, list):
        for value in node: walk(value)
walk(json.load(sys.stdin))
kinds = list(events.values())
print(len(kinds), sum(1 for p in kinds if p == want))' "$PROFILE" || true)
      case $got in "" | 0\ * | 1\ *) i=$((i + 1)); sleep 2 ;; *) break ;; esac
    done
    total=${got%% *} profiled=${got##* }
    echo "   activity events: ${total:-0}, with profile_id=$PROFILE: ${profiled:-0}"
    if [ "${total:-0}" -ge 2 ]; then
      pass "3 the request's activity is in the session, started and completed ($total events)"
    else
      fail "3 the request's activity is in the session, started and completed (${total:-0} events)"
    fi
    if [ "${total:-0}" -ge 2 ] && [ "$profiled" = "$total" ]; then
      pass "4 every activity event carries profile_id = $PROFILE"
    else
      fail "4 every activity event carries profile_id = $PROFILE (${profiled:-0} of ${total:-0})"
    fi
  fi
fi

echo "== Door guard log for the sandbox"
grep "eval .*sandbox_id=$ID" "$OBX_DEV_DIR/door-guard.log" | tail -5 || true
echo "Session: agent $AGENT_ID, sandbox $ID${SESSION:+, session $SESSION}"
[ $FAILED = 0 ] && echo "ALL PASS" || { echo "SOME FAILED (keep the logs with KEEP=1)"; exit 1; }
