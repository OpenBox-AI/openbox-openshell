#!/bin/sh
# Verify PROD-773: the front desk refuses provider profiles that send
# credentials uninspected, on ImportProviderProfiles and UpdateProviderProfiles.
#
#   middleware/scripts/verify-provider-profiles.sh
#
# Scenario 0 reproduces the gap on plain OpenShell (no front desk): its own
# example copilot profile, which sends credentials uninspected, is accepted.
# Scenarios 1-5 run the same gateway with the front desk registered.
#
# Starts its own OpenShell v0.1.2 gateway (VM driver) with its own state,
# ports and CLI config, so it does not touch any gateway you already run.
# Prints PASS/FAIL per scenario, exits non-zero if any fail, and removes
# everything it created on exit.
#
# Needs the OpenShell v0.1.2 release binaries: set OPENSHELL_PREFIX to a
# directory with bin/openshell, bin/openshell-gateway and
# libexec/openshell-driver-vm (default ~/openshell-repro). If they are not
# there, they are downloaded from NVIDIA's release and checksum-verified
# (macOS arm64 only).
#
# Optional: OBX_GATEWAY_PORT (default 17690; +1 health, +2 metrics),
# OBX_FD_PORT (default 50071; +1 inventory), KEEP=1 to keep the work dir.
set -eu

HERE=$(cd "$(dirname "$0")/.." && pwd)
PREFIX=${OPENSHELL_PREFIX:-$HOME/openshell-repro}
GW_PORT=${OBX_GATEWAY_PORT:-17690}
FD_PORT=${OBX_FD_PORT:-50071}
REV=$(sed -n 's/^openshell-core = .*rev = "\([0-9a-f]*\)".*/\1/p' "$HERE/Cargo.toml")
# A short path: the VM driver's unix socket must fit in SUN_LEN.
WORK=$(mktemp -d /tmp/obx-verify.XXXXXX)
FAILED=0

cleanup() {
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

for port in "$GW_PORT" $((GW_PORT + 1)) $((GW_PORT + 2)) "$FD_PORT" $((FD_PORT + 1)); do
  free "$port" || { echo "port $port is in use; set OBX_GATEWAY_PORT / OBX_FD_PORT"; exit 1; }
done

echo "== OpenShell v0.1.2 binaries"
if [ ! -x "$PREFIX/bin/openshell-gateway" ] || [ ! -x "$PREFIX/libexec/openshell-driver-vm" ]; then
  [ "$(uname -sm)" = "Darwin arm64" ] || { echo "set OPENSHELL_PREFIX to an OpenShell v0.1.2 install"; exit 1; }
  PREFIX=$WORK/openshell
  mkdir -p "$PREFIX/bin" "$PREFIX/libexec" "$PREFIX/dl"
  R=https://github.com/NVIDIA/OpenShell/releases/download/v0.1.2
  (
    cd "$PREFIX/dl"
    for f in openshell-aarch64-apple-darwin.tar.gz openshell-gateway-aarch64-apple-darwin.tar.gz \
      openshell-driver-vm-aarch64-apple-darwin.tar.gz openshell-checksums-sha256.txt \
      openshell-gateway-checksums-sha256.txt; do
      curl -fsSL -O "$R/$f"
    done
    cat openshell-checksums-sha256.txt openshell-gateway-checksums-sha256.txt |
      grep -E ' openshell-(gateway-|driver-vm-)?aarch64-apple-darwin.tar.gz$' | shasum -a 256 -c - >/dev/null
  )
  tar -xzf "$PREFIX/dl/openshell-aarch64-apple-darwin.tar.gz" -C "$PREFIX/bin"
  tar -xzf "$PREFIX/dl/openshell-gateway-aarch64-apple-darwin.tar.gz" -C "$PREFIX/bin"
  tar -xzf "$PREFIX/dl/openshell-driver-vm-aarch64-apple-darwin.tar.gz" -C "$PREFIX/libexec"
  cat >"$PREFIX/vm.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>com.apple.security.hypervisor</key><true/></dict></plist>
EOF
  /usr/bin/codesign --entitlements "$PREFIX/vm.plist" --force -s - "$PREFIX/libexec/openshell-driver-vm"
fi
"$PREFIX/bin/openshell" --version

echo "== Profiles from OpenShell at the pinned rev $REV"
for p in copilot github anthropic; do
  curl -fsSL -o "$WORK/$p.yaml" "https://raw.githubusercontent.com/NVIDIA/OpenShell/$REV/providers/$p.yaml"
done
grep -q 'allow_uninspected_credentials: true' "$WORK/copilot.yaml" ||
  { echo "copilot.yaml no longer has uninspected endpoints; this test needs a new fixture"; exit 1; }

echo "== Build and start the front desk"
(cd "$HERE" && cargo build -q --bin openbox-governance-interceptor)
OPENBOX_FD_INSECURE=1 OPENBOX_FD_LISTEN=127.0.0.1:$FD_PORT \
  OPENBOX_FD_INVENTORY_LISTEN=127.0.0.1:$((FD_PORT + 1)) \
  "$HERE/target/debug/openbox-governance-interceptor" >"$WORK/fd.log" 2>&1 &
echo $! >"$WORK/fd.pid"
wait_listen "$FD_PORT" "$WORK/fd.pid" "$WORK/fd.log"

mkdir -p "$WORK/config"
"$PREFIX/bin/openshell-gateway" generate-certs --output-dir "$WORK/tls" --server-san localhost >/dev/null 2>&1
ISOLATE="XDG_STATE_HOME=$WORK/state XDG_CONFIG_HOME=$WORK/config OPENSHELL_LOCAL_TLS_DIR=$WORK/tls"
os() { env $ISOLATE "$PREFIX/bin/openshell" "$@"; }
stored() { os profile list 2>/dev/null | grep -q "^$1 "; }

# start_gateway <config>: fresh state each time, CLI pointed at it.
start_gateway() {
  rm -rf "$WORK/state" && mkdir -p "$WORK/state"
  env $ISOLATE "$PREFIX/bin/openshell-gateway" --config "$1" >"$WORK/gateway.log" 2>&1 &
  echo $! >"$WORK/gateway.pid"
  i=0
  until ! free "$GW_PORT"; do
    i=$((i + 1))
    if ! kill -0 "$(cat "$WORK/gateway.pid")" 2>/dev/null; then
      if grep -q 'did not declare configured' "$WORK/gateway.log"; then
        echo "FAIL  gateway refused to start: the front desk does not declare the configured bindings"
      fi
      tail -5 "$WORK/gateway.log"
      exit 1
    fi
    [ $i -lt 120 ] || { echo "gateway did not listen on :$GW_PORT"; exit 1; }
    sleep 0.5
  done
  os gateway add "https://127.0.0.1:$GW_PORT" --local --name obx-verify >/dev/null 2>&1 || true
}
stop_gateway() {
  kill "$(cat "$WORK/gateway.pid")"
  rm "$WORK/gateway.pid"
  while ! free "$GW_PORT"; do sleep 0.2; done
}

cat >"$WORK/plain.toml" <<EOF
[openshell]
version = 2

[openshell.gateway]
compute_driver = "vm"
bind_address = "127.0.0.1:$GW_PORT"
health_bind_address = "127.0.0.1:$((GW_PORT + 1))"
metrics_bind_address = "127.0.0.1:$((GW_PORT + 2))"
EOF
cat "$WORK/plain.toml" - >"$WORK/governed.toml" <<EOF

[[openshell.gateway.interceptors]]
name = "openbox"
grpc_endpoint = "http://127.0.0.1:$FD_PORT"
allow_insecure_transport = true
failure_policy = "fail_closed"
binding_policy = "allowlist"

[[openshell.gateway.interceptors.bindings]]
rpc = "openshell.v1.OpenShell/ImportProviderProfiles"
phases = ["validate"]

[[openshell.gateway.interceptors.bindings]]
rpc = "openshell.v1.OpenShell/UpdateProviderProfiles"
phases = ["validate"]
EOF

echo "== The gap: plain OpenShell, no front desk"
start_gateway "$WORK/plain.toml"
if os profile import -f "$WORK/copilot.yaml" --global >/dev/null 2>&1 && stored copilot; then
  pass "0 without the front desk, OpenShell accepts copilot.yaml (the gap this closes)"
else
  fail "0 without the front desk, OpenShell accepts copilot.yaml (baseline changed; recheck the gap)"
fi
stop_gateway

echo "== Governed gateway with the two validate bindings"
start_gateway "$WORK/governed.toml"
grep -q 'gateway interceptors initialized.*bindings.*=.*2' "$WORK/gateway.log" ||
  { echo "gateway did not register both bindings"; grep -i interceptor "$WORK/gateway.log"; exit 1; }

echo "== Scenarios"
if out=$(os profile import -f "$WORK/copilot.yaml" --global 2>&1); then
  fail "1 import copilot.yaml is refused (it was imported)"
elif echo "$out" | grep -q 'uninspected traffic' && ! stored copilot; then
  pass "1 import copilot.yaml is refused and not stored"
else
  fail "1 import copilot.yaml refused for the wrong reason: $out"
fi

if os profile import -f "$WORK/github.yaml" --global >/dev/null 2>&1 && stored github; then
  pass "2 import github.yaml is accepted"
else
  fail "2 import github.yaml is accepted"
fi

os profile export github --global >"$WORK/github-stored.yaml"
awk '{print} /^endpoints:$/ && !done {print "  - host: leak.example.com\n    port: 443\n    allow_uninspected_credentials: true"; done=1}' \
  "$WORK/github-stored.yaml" >"$WORK/github-weak.yaml"
if out=$(os profile update github -f "$WORK/github-weak.yaml" --global 2>&1); then
  fail "3 update adding an uninspected endpoint is refused (it was applied)"
elif echo "$out" | grep -q 'leak.example.com' &&
  ! os profile export github --global 2>/dev/null | grep -q leak.example.com; then
  pass "3 update adding an uninspected endpoint is refused, stored profile unchanged"
else
  fail "3 update refused for the wrong reason: $out"
fi

if os profile update github -f "$WORK/github-stored.yaml" --global >/dev/null 2>&1; then
  pass "4 update with the stored profile is accepted"
else
  fail "4 update with the stored profile is accepted"
fi

kill "$(cat "$WORK/fd.pid")"
rm "$WORK/fd.pid"
sleep 0.5
if os profile import -f "$WORK/anthropic.yaml" --global >/dev/null 2>&1 || stored anthropic; then
  fail "5 front desk down: import is refused (fail closed)"
else
  pass "5 front desk down: import is refused (fail closed) and not stored"
fi

echo "== Front desk log"
grep 'intercept' "$WORK/fd.log" || true
[ $FAILED = 0 ] && echo "ALL PASS" || { echo "SOME FAILED (logs: rerun with KEEP=1)"; exit 1; }
