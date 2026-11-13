#!/bin/sh
# Verify that an agent's OpenBox policy rules govern an OpenShell sandbox end
# to end: each verdict Core returns reaches the sandbox as the right HTTP
# result and door guard log line, and is stored on the agent's session.
#
#   OBX_ORG_KEY_FILE=org-key middleware/scripts/verify-policies.sh agent.env
#
# agent.env is the dashboard's snippet for an agent with a workload identity
# (see openbox-openshell.sh). OBX_ORG_KEY_FILE holds an organisation API key
# for the backend, used to create the rules, decide the approval and read the
# session back. OPENBOX_BACKEND_URL is the backend (default the shared
# staging one, https://openbox-api.node.lat).
#
# Creates four policy rules in the organisation's control library and attaches
# them to the agent, each matching only requests whose URL carries its marker,
# so no other traffic of the agent is affected:
#
#   0  uat=plain      (no rule)          200, decision=allow
#   1  uat=block      BLOCK              403, openbox_blocked, the rule's reason
#   2  uat=constrain  CONSTRAIN          200, decision=allow
#   3  uat=approve    REQUIRE_APPROVAL   403 openbox_approval_required; approved
#                                        through the API, the identical retry is
#                                        200; a modified retry asks again
#   4  uat=halt       HALT               403 openbox_halted, the sandbox is
#                                        stopped, and a plain request after it
#                                        is denied too
#
# The script waits until the backend reports all four enforced on the agent,
# and deletes them from the library on exit.
#
# The door guard is restarted with the gateway's client certificate so a halt
# can stop the sandbox (openbox-openshell.sh does not give it one).
#
# Optional: OBX_DEV_DIR (default /tmp/obx-pol), OBX_GATEWAY_PORT (18490),
# OBX_MW_PORT (50851), OBX_FD_PORT (50871), OBX_MODEL_PORT (18495),
# OPENBOX_REDIS_URL, OBX_RULE_WAIT (seconds to wait for the rules to be
# enforced, default 180), KEEP=1 to leave the stack and the rules in place.
set -eu

[ $# = 1 ] && [ -f "$1" ] || { echo "usage: OBX_ORG_KEY_FILE=... $0 agent.env" >&2; exit 2; }
[ -f "${OBX_ORG_KEY_FILE:-}" ] || { echo "set OBX_ORG_KEY_FILE to a file with an organisation API key" >&2; exit 2; }
HERE=$(cd "$(dirname "$0")/.." && pwd)
BRINGUP=$HERE/scripts/openbox-openshell.sh
API=${OPENBOX_BACKEND_URL:-https://openbox-api.node.lat}
export OBX_DEV_DIR=${OBX_DEV_DIR:-/tmp/obx-pol}
export OBX_GATEWAY_PORT=${OBX_GATEWAY_PORT:-18490} OBX_MW_PORT=${OBX_MW_PORT:-50851}
export OBX_FD_PORT=${OBX_FD_PORT:-50871} OBX_MODEL_PORT=${OBX_MODEL_PORT:-18495}
export OPENBOX_BACKEND_URL=-
REDIS=${OPENBOX_REDIS_URL:-redis://localhost:6379/7}
DIR=$OBX_DEV_DIR
BOX=obx-pol-$(($(date +%s) % 100000))
RUN=$(date +%s)
FAILED=0
CREATED=

pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; FAILED=1; }
os() { "$DIR/bin/openshell" "$@"; }
api() { # method path [json]
  if [ $# -ge 3 ]; then
    curl -sS -X "$1" -H "X-API-Key: $(cat "$OBX_ORG_KEY_FILE")" -H 'Content-Type: application/json' --data "$3" "$API$2"
  else
    curl -sS -X "$1" -H "X-API-Key: $(cat "$OBX_ORG_KEY_FILE")" "$API$2"
  fi
}
cleanup() {
  if [ "${KEEP:-0}" = 1 ]; then echo "kept: $DIR, rules:$CREATED"; return; fi
  for id in $CREATED; do api DELETE "/governance/controls/$id" >/dev/null 2>&1 && echo "deleted rule $id"; done
  os sandbox delete "$BOX" >/dev/null 2>&1 || true
  "$BRINGUP" down >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

# One plain-HTTP GET to example.com from inside the sandbox; prints the status.
request() {
  os sandbox exec -n "$BOX" --no-tty --timeout 60 -- bash -c \
    'exec 3<>/dev/tcp/example.com/80; printf "GET /?'"$1"' HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n" >&3; head -1 <&3' \
    </dev/null 2>/dev/null | tr -d '\r' | awk '/^HTTP\//{print $2; exit}'
}
last_eval() { grep 'openbox: eval ' "$DIR/door-guard.log" | tail -1; }

# Creates a library rule matching URLs that contain $1 and attaches it to
# the agent; prints its id.
rule() { # marker decision
  id=$(api POST "/governance/controls" "$(python3 - "$1" "$2" "$RUN" <<'PY'
import json, sys
marker, decision, run = sys.argv[1:]
print(json.dumps({"kind": "policy_rule", "body": {
    "rule_name": f"OpenShell verify {decision.lower()} {run}",
    "description": f"verify-policies.sh: matches only URLs carrying {marker}",
    "priority": 20, "match_mode": "any", "decision": decision,
    "reason": f"verify-policies {decision.lower()}: {marker} is not allowed",
    "conditions": [{"id": "c1",
        "left": {"kind": "field", "field": "spans[_].attributes.http.url", "transform": "value", "valueType": "string"},
        "operator": "contains",
        "right": {"kind": "literal", "value": marker, "valueType": "string"}}],
}}))
PY
)" | python3 -c 'import sys,json; d=json.load(sys.stdin); d=d.get("data",d); print(d["id"])') || return 1
  api PUT "/agent/$AGENT_ID/governance-controls/$id" '{}' | python3 -c '
import sys, json
d = json.load(sys.stdin); d = d.get("data", d)
sys.exit(0 if d.get("desiredState") == "attached" else 1)' || { echo "could not attach rule $id" >&2; api DELETE "/governance/controls/$id" >/dev/null 2>&1; return 1; }
  echo "$id"
}

"$BRINGUP" up --agent-env "$1"
. "$DIR/agent"

echo "== Policy rules attached to agent $AGENT_ID"
for spec in "uat=halt HALT" "uat=block BLOCK" "uat=constrain CONSTRAIN" "uat=approve REQUIRE_APPROVAL"; do
  set -- $spec
  id=$(rule "$1" "$2") || { echo "could not create the $2 rule" >&2; exit 1; }
  CREATED="$CREATED $id"
  echo "   $2 rule $id"
done

echo "== Door guard restarted with the gateway's client certificate (halt can stop)"
kill "$(cat "$DIR/door-guard.pid")"
while kill -0 "$(cat "$DIR/door-guard.pid")" 2>/dev/null; do sleep 0.2; done
env OPENBOX_URL="$CORE" OPENBOX_API_KEY_FILE="$DIR/creds/api-key" \
  OPENBOX_WORKLOAD_KEY_FILE="$DIR/creds/workload.pem" OPENBOX_WORKLOAD_KID="$KID" \
  OPENBOX_REDIS_URL="$REDIS" OPENBOX_MW_INSECURE=1 OPENBOX_MW_LISTEN=0.0.0.0:$OBX_MW_PORT \
  OPENBOX_MW_ADMIN_LISTEN=127.0.0.1:$((OBX_MW_PORT + 1)) \
  OPENBOX_GATEWAY_ENDPOINT=https://localhost:$OBX_GATEWAY_PORT OPENBOX_GATEWAY_MTLS_DIR=$DIR/gwclient \
  "$HERE/target/debug/openbox-verdict-middleware" >>"$DIR/door-guard.log" 2>&1 &
echo $! >"$DIR/door-guard.pid"
i=0
until lsof -nP -iTCP:"$OBX_MW_PORT" -sTCP:LISTEN >/dev/null 2>&1; do
  i=$((i + 1)); [ $i -le 60 ] || { echo "door guard did not restart" >&2; exit 1; }
  sleep 0.5
done

echo "== Sandbox $BOX"
os sandbox create --name "$BOX" --policy "$DIR/policy.yaml" --detach --no-tty --no-auto-providers >/dev/null
i=0
until os logs "$BOX" --source sandbox 2>/dev/null | grep -q 'Settings poll'; do
  i=$((i + 1)); [ $i -le 90 ] || { echo "sandbox did not come up" >&2; exit 1; }
  sleep 2
done
SANDBOX_ID=$(os sandbox get "$BOX" -o json | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("id") or d.get("metadata",{}).get("id",""))')
echo "   sandbox id $SANDBOX_ID"

# Attaching is asynchronous: wait until the backend reports every rule
# enforced on the agent (applied, and confirmed live by the policy runtime).
wait=${OBX_RULE_WAIT:-180}
echo "== Waiting up to ${wait}s for the rules to be enforced"
start=$(date +%s)
while :; do
  state=$(api GET "/agent/$AGENT_ID/effective-governance-controls?kind=policy_rule" | python3 -c '
import sys, json
want = sys.argv[1].split()
d = json.load(sys.stdin); d = d.get("data", d)
rows = {r["control"]["id"]: r for r in d.get("controls", []) if isinstance(r, dict) and "control" in r}
states = [rows[i]["enforcement"] if i in rows else "missing" for i in want]
print("enforced" if all(s == "enforced" for s in states) else " ".join(states))' "$CREATED" 2>/dev/null || echo unreadable)
  [ "$state" = enforced ] && break
  if [ $(($(date +%s) - start)) -ge "$wait" ]; then echo "rules not enforced after ${wait}s: $state" >&2; exit 1; fi
  sleep 3
done
echo "   enforced after $(($(date +%s) - start))s"

echo "== 0 no rule matches"
code=$(request "uat=plain&run=$RUN"); line=$(last_eval)
case "$code $line" in
  "200 "*"decision=allow reason_code=- "*) pass "0 allowed (HTTP $code)" ;;
  *) fail "0 expected 200 allow, got '$code': $line" ;;
esac

echo "== 1 BLOCK"
code=$(request "uat=block&run=$RUN"); line=$(last_eval)
case "$code $line" in
  "403 "*"decision=deny reason_code=openbox_blocked "*'reason="'*"uat=block is not allowed"*) pass "1 blocked (HTTP $code): ${line#*decision=}" ;;
  *) fail "1 expected 403 openbox_blocked with the rule's reason, got '$code': $line" ;;
esac

echo "== 2 CONSTRAIN"
code=$(request "uat=constrain&run=$RUN"); line=$(last_eval)
case "$code $line" in
  "200 "*"decision=allow "*) pass "2 constrain lets the request through (HTTP $code): ${line#*decision=}" ;;
  *) fail "2 expected 200 allow, got '$code': $line" ;;
esac

echo "== 3 REQUIRE_APPROVAL"
code=$(request "uat=approve&run=$RUN"); line=$(last_eval)
case "$code $line" in
  "403 "*"reason_code=openbox_approval_required "*) pass "3a held for approval (HTTP $code): ${line#*decision=}" ;;
  *) fail "3a expected 403 openbox_approval_required, got '$code': $line" ;;
esac
event=
i=0
while [ -z "$event" ] && [ $i -lt 20 ]; do
  event=$(api GET "/agent/$AGENT_ID/approvals/pending?page=0&perPage=50" | python3 -c '
import sys, json
for a in json.load(sys.stdin)["data"]["data"]:
    if sys.argv[1] in json.dumps(a):
        print(a.get("event_id") or a.get("id")); break' "$SANDBOX_ID")
  i=$((i + 1)); [ -n "$event" ] || sleep 2
done
if [ -n "$event" ]; then
  decided=$(api PUT "/agent/$AGENT_ID/approvals/$event/decide?action=approve" '{}' | python3 -c 'import sys,json; print(json.load(sys.stdin).get("status"))')
  echo "   approved $event through the API (HTTP $decided)"
  sleep 3
  code=$(request "uat=approve&run=$RUN"); line=$(last_eval)
  case "$code $line" in
    "200 "*"decision=allow "*) pass "3b identical retry after approval goes through (HTTP $code)" ;;
    *) fail "3b expected 200 on the approved retry, got '$code': $line" ;;
  esac
  code=$(request "uat=approve&run=$RUN&changed=1"); line=$(last_eval)
  case "$code $line" in
    "403 "*"reason_code=openbox_approval_required "*) pass "3c a modified retry needs its own approval (HTTP $code)" ;;
    *) fail "3c expected 403 openbox_approval_required for a modified request, got '$code': $line" ;;
  esac
else
  fail "3b no pending approval for sandbox $SANDBOX_ID appeared on the agent"
fi

echo "== 4 HALT"
code=$(request "uat=halt&run=$RUN"); line=$(last_eval)
case "$code $line" in
  "403 "*"decision=deny reason_code=openbox_halted "*) pass "4a halted (HTTP $code): ${line#*decision=}" ;;
  *) fail "4a expected 403 openbox_halted, got '$code': $line" ;;
esac
i=0; phase=
while [ $i -lt 30 ]; do
  phase=$(os sandbox get "$BOX" -o json 2>/dev/null | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("phase") or d.get("status",{}).get("phase") or "")' 2>/dev/null || echo gone)
  case "$phase" in *[Rr]unning*|*[Rr]eady*) ;; *) break ;; esac
  i=$((i + 1)); sleep 2
done
case "$phase" in
  *[Rr]unning*|*[Rr]eady*) fail "4b sandbox still '$phase' 60 s after the halt" ;;
  *) pass "4b sandbox stopped after the halt (now '${phase:-gone}')" ;;
esac
grep -E 'openbox: (halt|stop)' "$DIR/door-guard.log" | tail -2 || true

echo "== Session for sandbox $SANDBOX_ID as stored"
sleep 10
sid=$(api GET "/agent/$AGENT_ID/sessions?page=0&perPage=50" | python3 -c '
import sys, json
for s in json.load(sys.stdin)["data"]["data"]:
    if s["workflow_id"] == sys.argv[1]: print(s["id"]); break' "$SANDBOX_ID")
if [ -n "$sid" ]; then
  api GET "/agent/$AGENT_ID/sessions/$sid/logs/chronological?page=0&perPage=100" | python3 -c '
import json, sys
for e in json.load(sys.stdin)["data"]["data"]:
    url = ""
    for s in e.get("spans") or []:
        url = (s.get("attributes") or {}).get("http.url") or url
    print("  ", e["created_at"][11:23], e["event_type"], e.get("activity_type") or e.get("signal_name") or "",
          "verdict=%s" % e.get("verdict"), (e.get("reason") or "")[:60], url[-40:])'
else
  fail "no stored session for sandbox $SANDBOX_ID"
fi

echo "== Door guard verdicts"
grep 'openbox: eval ' "$DIR/door-guard.log" || true
[ $FAILED = 0 ] && echo "ALL PASS" || { echo "SOME FAILED (KEEP=1 to inspect $DIR)"; exit 1; }
