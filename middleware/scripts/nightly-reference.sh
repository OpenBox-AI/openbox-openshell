#!/usr/bin/env bash
# The nightly reference stack: OpenShell at the pinned version on Kubernetes
# with OpenBox for OpenShell in front of it, driven by a scripted agent.
#
#   middleware/scripts/nightly-reference.sh
#
# Brings up, in a kind cluster of its own:
#   - the Agent Sandbox controller and the OpenShell Helm chart (Kubernetes
#     driver), with the front desk and door guard registered as in
#     docs/install.md;
#   - OpenBox for OpenShell from this checkout (image built here, chart from
#     deploy/helm), pointed at a stand-in Core that allows everything (the
#     nightly checks the OpenShell contract, not Core's policies);
#   - an echo server for the sandbox to reach.
# Then, as an agent would, with the OpenShell CLI:
#   A  creates a sandbox: the front desk attaches the door guard;
#   B  sends a request from the sandbox: the door guard asks Core, allows it,
#      and the request reaches the echo server;
#   C  sets a policy without the door guard: the front desk refuses it;
#   D  creates a sandbox whose policy sends credentials uninspected: refused;
#   E  the door guard's metrics show the verdict.
#
# Needs docker, kind, kubectl, helm, openssl, curl and python3. Linux x86_64
# or arm64, or macOS arm64. Environment:
#   OPENSHELL_VERSION      pinned OpenShell release   (default 0.1.8)
#   AGENT_SANDBOX_VERSION  Agent Sandbox release      (default v1.0.10)
#   CLUSTER                kind cluster name          (default obx-nightly)
#   KEEP_CLUSTER=1         leave the cluster up afterwards
set -euo pipefail

OPENSHELL_VERSION=${OPENSHELL_VERSION:-0.1.8}
AGENT_SANDBOX_VERSION=${AGENT_SANDBOX_VERSION:-v1.0.10}
CLUSTER=${CLUSTER:-obx-nightly}
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
CTX="kind-$CLUSTER"
IMAGE=openbox-openshell:nightly
WORK=$(mktemp -d "${TMPDIR:-/tmp}/obx-nightly.XXXXXX")
RUN=$(date +%s)
FAILS=0
PF_PID=""

k() { kubectl --context "$CTX" "$@"; }
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; FAILS=$((FAILS + 1)); }
step() { echo; echo "== $*"; }

cleanup() {
  [ -n "$PF_PID" ] && kill "$PF_PID" 2>/dev/null || true
  if [ "${KEEP_CLUSTER:-}" != 1 ]; then
    kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

case "$(uname -sm)" in
  "Linux x86_64") CLI_ASSET=openshell-x86_64-unknown-linux-musl.tar.gz ;;
  "Linux aarch64") CLI_ASSET=openshell-aarch64-unknown-linux-musl.tar.gz ;;
  "Darwin arm64") CLI_ASSET=openshell-aarch64-apple-darwin.tar.gz ;;
  *) echo "unsupported platform $(uname -sm)"; exit 2 ;;
esac

step "cluster and image"
if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  kind create cluster --name "$CLUSTER" --wait 180s
fi
docker build -q -t "$IMAGE" "$ROOT" >/dev/null
kind load docker-image "$IMAGE" --name "$CLUSTER" >/dev/null

step "Agent Sandbox $AGENT_SANDBOX_VERSION"
k apply -f "https://github.com/kubernetes-sigs/agent-sandbox/releases/download/$AGENT_SANDBOX_VERSION/sandbox.yaml" >/dev/null
k -n agent-sandbox-system rollout status deploy/agent-sandbox-controller --timeout=300s

step "certificates"
k create namespace openbox --dry-run=client -o yaml | k apply -f - >/dev/null
k create namespace openshell --dry-run=client -o yaml | k apply -f - >/dev/null
DG=openbox-openbox-openshell-door-guard
FD=openbox-openbox-openshell-front-desk
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
  -subj "/CN=openbox nightly CA" -keyout "$WORK/ca.key" -out "$WORK/ca.crt" 2>/dev/null
issue() { # name dns...
  local name=$1; shift
  local san; san=$(printf 'DNS:%s,' "$@"); san=${san%,}
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$1" \
    -keyout "$WORK/$name.key" -out "$WORK/$name.csr" 2>/dev/null
  printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth\n' "$san" > "$WORK/$name.ext"
  openssl x509 -req -in "$WORK/$name.csr" -CA "$WORK/ca.crt" -CAkey "$WORK/ca.key" \
    -CAcreateserial -days 2 -extfile "$WORK/$name.ext" -out "$WORK/$name.crt" 2>/dev/null
  k -n openbox create secret tls "openbox-$name-tls" --cert "$WORK/$name.crt" --key "$WORK/$name.key" \
    --dry-run=client -o yaml | k apply -f - >/dev/null
}
issue door-guard "$DG.openbox.svc" "$DG.openbox.svc.cluster.local"
issue front-desk "$FD.openbox.svc" "$FD.openbox.svc.cluster.local"
k -n openshell create configmap openbox-ca --from-file=openbox-ca.pem="$WORK/ca.crt" \
  --dry-run=client -o yaml | k apply -f - >/dev/null

step "stand-in Core and echo server"
cat > "$WORK/stub.py" <<'PY'
# A Core stand-in that allows everything, and an echo server.
import http.server, json, sys
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def reply(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    def handle_any(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode(errors="replace") if length else ""
        if sys.argv[1] == "echo":
            return self.reply(200, {"path": self.path, "body": body})
        if "/governance/approval" in self.path:
            return self.reply(404, {"error": "no approval"})
        self.reply(200, {"verdict": "allow", "action": "allow", "governance_event_id": "stub"})
    do_GET = do_POST = do_PUT = handle_any
    def log_message(self, *args): pass
http.server.ThreadingHTTPServer(("0.0.0.0", int(sys.argv[2])), H).serve_forever()
PY
k -n openbox create configmap nightly-stub --from-file=stub.py="$WORK/stub.py" --dry-run=client -o yaml | k apply -f - >/dev/null
for svc in stub-core:core:8086 echo:echo:8080; do
  IFS=: read -r name mode port <<< "$svc"
  cat <<YAML | k apply -f - >/dev/null
apiVersion: apps/v1
kind: Deployment
metadata: {name: $name, namespace: openbox}
spec:
  selector: {matchLabels: {app: $name}}
  template:
    metadata: {labels: {app: $name}}
    spec:
      containers:
        - name: $name
          image: python:3.13-alpine
          command: [python3, /stub/stub.py, $mode, "$port"]
          ports: [{containerPort: $port}]
          volumeMounts: [{name: stub, mountPath: /stub}]
      volumes: [{name: stub, configMap: {name: nightly-stub}}]
---
apiVersion: v1
kind: Service
metadata: {name: $name, namespace: openbox}
spec:
  selector: {app: $name}
  ports: [{port: $port, targetPort: $port}]
YAML
done
k -n openbox rollout status deploy/stub-core deploy/echo --timeout=180s >/dev/null

step "OpenShell $OPENSHELL_VERSION"
cat > "$WORK/openshell-values.yaml" <<YAML
gatewayConfig:
  openshell.gateway:
    interceptors:
      - name: openbox
        grpc_endpoint: https://$FD.openbox.svc:50061
        tls_ca_cert_path: /etc/openshell/openbox/openbox-ca.pem
        audience: urn:openshell:extension:interceptor:openbox
        failure_policy: fail_closed
        binding_policy: allowlist
        timeout: 10s
        bindings:
          - {rpc: openshell.v1.OpenShell/CreateSandbox, phases: [modify_operation, validate]}
          - {rpc: openshell.v1.OpenShell/UpdateConfig, phases: [validate]}
          - {rpc: openshell.v1.OpenShell/ImportProviderProfiles, phases: [validate]}
          - {rpc: openshell.v1.OpenShell/UpdateProviderProfiles, phases: [validate]}
  openshell.supervisor:
    middleware:
      - name: openbox
        grpc_endpoint: https://$DG.openbox.svc:50051
        tls_ca_cert_path: /etc/openshell/openbox/openbox-ca.pem
        audience: urn:openshell:extension:middleware:openbox
        max_payload_bytes: 1048576
        timeout: 30s
server:
  auth:
    allowUnauthenticatedUsers: true
  extraVolumes:
    - name: openbox-ca
      configMap: {name: openbox-ca}
  extraVolumeMounts:
    - {name: openbox-ca, mountPath: /etc/openshell/openbox, readOnly: true}
YAML
# No --wait: the gateway registers the door guard and front desk at start and
# exits until they answer, and they need the gateway's signing key first. Wait
# for the key, install OpenBox for OpenShell, then wait for the gateway.
helm upgrade --install openshell oci://ghcr.io/nvidia/openshell/helm-chart --version "$OPENSHELL_VERSION" \
  -n openshell --kube-context "$CTX" -f "$WORK/openshell-values.yaml" --timeout 10m >/dev/null
for _ in $(seq 1 120); do
  k -n openshell get secret openshell-jwt-keys >/dev/null 2>&1 && break
  sleep 5
done
k -n openshell get secret openshell-jwt-keys -o jsonpath='{.data.public\.pem}' | base64 -d > "$WORK/gateway-public.pem"
GATEWAY_ID=$(k -n openshell get configmap openshell-config -o jsonpath='{.data}' |
  python3 -c 'import json,re,sys; t="".join(json.load(sys.stdin).values()); m=re.search(r"gateway_id\s*=\s*\"([^\"]+)\"", t); print(m.group(1) if m else "openshell")')

step "OpenBox for OpenShell"
helm upgrade --install openbox "$ROOT/deploy/helm/openbox-openshell" -n openbox --kube-context "$CTX" \
  --set image.repository=openbox-openshell --set image.tag=nightly --set image.pullPolicy=Never \
  --set openbox.url=http://stub-core.openbox.svc:8086 \
  --set credentials.identity=apiKey --set credentials.apiKey=obx_nightly_stub \
  --set frontDesk.sessions=false --set doorGuard.replicaCount=1 --set frontDesk.replicaCount=1 \
  --set gateway.id="$GATEWAY_ID" --set-file gateway.publicKey="$WORK/gateway-public.pem" \
  --set tls.doorGuard.existingSecret=openbox-door-guard-tls \
  --set tls.frontDesk.existingSecret=openbox-front-desk-tls \
  --wait --timeout 5m >/dev/null
# The gateway and the supervisor pool read the door guard and front desk
# registrations at start: restart both now that they answer; both must come up.
k -n openshell rollout restart statefulset,deployment >/dev/null
k -n openshell rollout status statefulset --timeout=300s >/dev/null
k -n openshell rollout status deployment --timeout=300s >/dev/null

step "OpenShell CLI"
curl -fsSL -o "$WORK/$CLI_ASSET" "https://github.com/NVIDIA/OpenShell/releases/download/v$OPENSHELL_VERSION/$CLI_ASSET"
curl -fsSL -o "$WORK/sums" "https://github.com/NVIDIA/OpenShell/releases/download/v$OPENSHELL_VERSION/openshell-checksums-sha256.txt"
if command -v sha256sum >/dev/null; then SHA=(sha256sum -c -); else SHA=(shasum -a 256 -c -); fi
(cd "$WORK" && grep " $CLI_ASSET\$" sums | "${SHA[@]}" >/dev/null)
tar -xzf "$WORK/$CLI_ASSET" -C "$WORK"
CLI="$WORK/openshell"
PORT=$((20000 + RUN % 20000))
k -n openshell port-forward svc/openshell "$PORT:8080" > "$WORK/pf.log" 2>&1 &
PF_PID=$!
GW="$WORK/config/openshell/gateways/nightly"
mkdir -p "$GW/mtls" "$WORK/state"
for f in ca.crt tls.crt tls.key; do
  k -n openshell get secret openshell-client-tls -o jsonpath="{.data.${f//./\\.}}" | base64 -d > "$GW/mtls/$f"
done
printf '{"name":"nightly","gateway_endpoint":"https://127.0.0.1:%s","is_remote":false,"gateway_port":0,"auth_mode":"mtls"}' "$PORT" > "$GW/metadata.json"
echo nightly > "$WORK/config/openshell/active_gateway"
os() { XDG_CONFIG_HOME="$WORK/config" XDG_STATE_HOME="$WORK/state" "$CLI" "$@"; }
for _ in $(seq 1 30); do os status >/dev/null 2>&1 && break; sleep 2; done

ECHO=echo.openbox.svc.cluster.local
cat > "$WORK/policy.yaml" <<YAML
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
  echo:
    name: echo
    endpoints:
      - host: $ECHO
        port: 8080
        protocol: rest
        access: read-write
    binaries:
      - path: /usr/bin/bash
YAML

step "A: create a sandbox"
BOX="nightly-$((RUN % 100000))"
if out=$(os sandbox create --name "$BOX" --policy "$WORK/policy.yaml" --detach --no-tty --no-auto-providers 2>&1); then
  pass "A sandbox created"
else
  fail "A sandbox create: $(echo "$out" | tail -3 | tr '\n' ' ')"
fi
for _ in $(seq 1 90); do
  os logs "$BOX" --source sandbox 2>/dev/null | grep -qE 'Settings poll|Acknowledged initial policy revision' && break
  sleep 2
done
if os policy get "$BOX" --full -o json 2>/dev/null | grep -q '"middleware": *"openbox"'; then
  pass "A the front desk attached the door guard"
else
  fail "A the sandbox policy does not carry the openbox middleware"
fi

step "B: a request from the sandbox"
REQ="POST /nightly?run=$RUN HTTP/1.1\r\nHost: $ECHO:8080\r\nContent-Type: application/json\r\nContent-Length: 15\r\nConnection: close\r\n\r\n{\"hello\":\"you\"}"
reply=$(os sandbox exec -n "$BOX" --no-tty --timeout 90 -- bash -c \
  "exec 3<>/dev/tcp/$ECHO/8080; printf '$REQ' >&3; cat <&3" 2>&1 || true)
if echo "$reply" | grep -q '^HTTP/1.1 200' && echo "$reply" | grep -q "run=$RUN"; then
  pass "B the request reached the echo server"
else
  fail "B no 200 from the echo server: $(echo "$reply" | tr '\r\n' '  ' | cut -c1-400)"
fi
if k -n openbox logs deploy/$DG --since=5m | grep -E "openbox: eval" | grep -q "decision=allow"; then
  pass "B the door guard judged it (decision=allow)"
else
  fail "B no door guard allow line: $(k -n openbox logs deploy/$DG --since=5m | tail -3 | tr '\n' ' ')"
fi

step "C: a policy without the door guard"
if out=$(os policy set "$BOX" --policy "$WORK/policy.yaml" 2>&1); then
  fail "C the policy without the door guard was accepted"
elif echo "$out" | grep -q "must stay attached"; then
  pass "C refused: the OpenBox middleware must stay attached"
else
  fail "C refused for another reason: $(echo "$out" | tail -2 | tr '\n' ' ')"
fi

step "D: credentials sent uninspected"
python3 - "$WORK/policy.yaml" "$WORK/creds.yaml" <<'PY'
import sys
text = open(sys.argv[1]).read().replace("        access: read-write\n", "        access: read-write\n        allow_uninspected_credentials: true\n")
open(sys.argv[2], "w").write(text)
PY
if out=$(os sandbox create --name "$BOX-c" --policy "$WORK/creds.yaml" --detach --no-tty --no-auto-providers 2>&1); then
  fail "D the uninspected-credentials sandbox was created"
  os sandbox delete "$BOX-c" >/dev/null 2>&1 || true
elif echo "$out" | grep -qi "uninspected\|credential"; then
  pass "D refused: credentials sent uninspected"
else
  fail "D refused for another reason: $(echo "$out" | tail -2 | tr '\n' ' ')"
fi

step "E: metrics"
k -n openbox port-forward deploy/$DG 19464:9464 > "$WORK/pf-metrics.log" 2>&1 &
MPF=$!
sleep 3
if curl -fsS http://127.0.0.1:19464/metrics 2>/dev/null | grep -q 'openbox_mw_evaluations_total{decision="allow"'; then
  pass "E the door guard's metrics count the verdict"
else
  fail "E no verdict metrics"
fi
kill "$MPF" 2>/dev/null || true

os sandbox delete "$BOX" >/dev/null 2>&1 || true
echo
if [ "$FAILS" -eq 0 ]; then echo "ALL PASS (OpenShell $OPENSHELL_VERSION)"; else echo "$FAILS FAILED (OpenShell $OPENSHELL_VERSION)"; fi
[ "$FAILS" -eq 0 ]
