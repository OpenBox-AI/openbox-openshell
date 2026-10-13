#!/bin/sh
# Verify PROD-901: the door guard's log line for a deny carries the reason
# the sandbox was given, not only the reason code; an allow carries none.
#
#   middleware/scripts/verify-deny-reason.sh agent.env
#
# agent.env is the dashboard's snippet for an agent with a workload identity
# (see openbox-openshell.sh). Runs against the OpenBox Core it names, with a
# real OpenShell v0.1.2 gateway and sandbox brought up by openbox-openshell.sh:
#
#   1  a request the agent's Core allows: decision=allow, no reason=
#   2  the door guard restarted with an API key Core does not know, so Core
#      itself refuses the call: decision=deny reason_code=openbox_unavailable
#      reason="core returned HTTP <code>", and the sandbox gets 403
#
# The bring-up policy allows example.com; the front desk attaches the door
# guard. Changes nothing on the OpenBox side: no policy, no agent setting. Scenario 1
# leaves one ordinary session on the agent.
#
# Optional: OBX_DEV_DIR (default /tmp/obx-901), OBX_GATEWAY_PORT (18290),
# OBX_MW_PORT (50651), OBX_FD_PORT (50671), OBX_MODEL_PORT (18295),
# OPENBOX_REDIS_URL, OPENBOX_BACKEND_URL (default "-": no AI Inventory),
# KEEP=1 to leave the stack up.
set -eu

[ $# = 1 ] && [ -f "$1" ] || { echo "usage: $0 agent.env" >&2; exit 2; }
HERE=$(cd "$(dirname "$0")/.." && pwd)
BRINGUP=$HERE/scripts/openbox-openshell.sh
export OBX_DEV_DIR=${OBX_DEV_DIR:-/tmp/obx-901}
export OBX_GATEWAY_PORT=${OBX_GATEWAY_PORT:-18290} OBX_MW_PORT=${OBX_MW_PORT:-50651}
export OBX_FD_PORT=${OBX_FD_PORT:-50671} OBX_MODEL_PORT=${OBX_MODEL_PORT:-18295}
export OPENBOX_BACKEND_URL=${OPENBOX_BACKEND_URL:--}
REDIS=${OPENBOX_REDIS_URL:-redis://localhost:6379/7}
DIR=$OBX_DEV_DIR
BOX=obx-901-$(($(date +%s) % 100000))
FAILED=0

pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; FAILED=1; }
os() { "$DIR/bin/openshell" "$@"; }
cleanup() {
  [ "${KEEP:-0}" = 1 ] && { echo "kept: $DIR ($BRINGUP down to stop)"; return; }
  os sandbox delete "$BOX" >/dev/null 2>&1 || true
  "$BRINGUP" down >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

# One plain-HTTP GET to example.com from inside the sandbox; prints the status.
request() {
  os sandbox exec -n "$BOX" --no-tty --timeout 60 -- bash -c \
    'exec 3<>/dev/tcp/example.com/80; printf "GET /?prod901='"$1"' HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n" >&3; head -1 <&3' \
    </dev/null 2>/dev/null | tr -d '\r' | awk '/^HTTP\//{print $2; exit}'
}
evals() { grep 'openbox: eval ' "$DIR/door-guard.log" || true; }

"$BRINGUP" up --agent-env "$1"
. "$DIR/agent"
echo "== Sandbox $BOX"
os sandbox create --name "$BOX" --policy "$DIR/policy.yaml" --detach --no-tty --no-auto-providers >/dev/null
i=0
until os logs "$BOX" --source sandbox 2>/dev/null | grep -q 'Settings poll'; do
  i=$((i + 1)); [ $i -le 90 ] || { echo "sandbox did not come up" >&2; exit 1; }
  sleep 2
done

echo "== 1 Core $CORE allows"
code=$(request allow)
line=$(evals | tail -1)
case "$code $line" in
  "200 "*"decision=allow reason_code=- ms="*)
    case "$line" in
      *reason=*) fail "1 allow logged a reason: $line" ;;
      *) pass "1 allowed (HTTP $code), no reason on the line: $line" ;;
    esac ;;
  *) fail "1 expected HTTP 200 and an allow, got '$code': $line" ;;
esac

echo "== 2 Core $CORE refuses an unknown API key"
kill "$(cat "$DIR/door-guard.pid")"
while kill -0 "$(cat "$DIR/door-guard.pid")" 2>/dev/null; do sleep 0.2; done
printf 'obx_key_prod901_not_a_real_key\n' >"$DIR/creds/bogus-key"
chmod 600 "$DIR/creds/bogus-key"
env OPENBOX_URL="$CORE" OPENBOX_API_KEY_FILE="$DIR/creds/bogus-key" \
  OPENBOX_WORKLOAD_KEY_FILE="$DIR/creds/workload.pem" OPENBOX_WORKLOAD_KID="$KID" \
  OPENBOX_REDIS_URL="$REDIS" OPENBOX_MW_INSECURE=1 OPENBOX_MW_LISTEN=0.0.0.0:$OBX_MW_PORT \
  OPENBOX_MW_ADMIN_LISTEN=127.0.0.1:$((OBX_MW_PORT + 1)) \
  "$HERE/target/debug/openbox-verdict-middleware" >>"$DIR/door-guard.log" 2>&1 &
echo $! >"$DIR/door-guard.pid"
i=0
until lsof -nP -iTCP:"$OBX_MW_PORT" -sTCP:LISTEN >/dev/null 2>&1; do
  i=$((i + 1)); [ $i -le 60 ] || { echo "door guard did not restart" >&2; exit 1; }
  sleep 0.5
done
code=$(request deny)
line=$(evals | tail -1)
case "$code $line" in
  "403 "*"decision=deny reason_code=openbox_unavailable ms="*' reason="core returned HTTP '[0-9][0-9][0-9]'"')
    pass "2 denied (HTTP $code), reason logged: $line" ;;
  *) fail "2 expected HTTP 403 and a deny ending reason=\"core returned HTTP <code>\", got '$code': $line" ;;
esac

echo "== Door guard verdicts"
evals
[ $FAILED = 0 ] && echo "ALL PASS" || { echo "SOME FAILED (KEEP=1 to inspect $DIR)"; exit 1; }
