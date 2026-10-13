#!/bin/sh
# Run OpenShell governed by OpenBox, the way a developer would: bring up the
# OpenBox door guard and front desk next to an OpenShell gateway, then use
# the plain `openshell` CLI. Sandboxes need no OpenBox configuration: the
# front desk attaches the door guard to every sandbox it creates.
#
#   openbox-openshell.sh up --agent-env agent.env   start everything, leave it running
#   openbox-openshell.sh demo                       one scripted sandbox session
#   openbox-openshell.sh status                     what is running
#   openbox-openshell.sh down                       stop it all
#
# agent.env is the snippet the OpenBox dashboard shows for an agent with a
# workload identity, unchanged:
#
#   OPENBOX_API_URL=http://localhost:8086
#   OPENBOX_API_KEY=obx_...
#   OPENBOX_WORKLOAD_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"
#
# `up` stores the key material in private files, reads the key's kid from
# Core's bootstrap, checks that a workload token carries Core's audience, and
# starts:
#   - the door guard (verdict middleware), registered for every request and
#     response, with OpenShell's maximum 30 s timeout
#   - the front desk, twice: governing (fail closed: attaches the door guard
#     on CreateSandbox, refuses weakening policy and uninspected credentials)
#     and inventory (fail open: AI Inventory, session start and end)
#   - an OpenShell v0.1.2 gateway (VM driver) with its own state and CLI
#     config, so no gateway you already run is touched
#
# Local development only: the gateway-to-extension legs run plaintext without
# OpenShell's extension tokens (OPENBOX_*_INSECURE=1). The legs to OpenBox
# are the real ones.
#
# Optional:
#   OBX_DEV_DIR             state, logs and credentials (default /tmp/obx-dev;
#                           short, because the VM driver's socket path is)
#   OPENBOX_BACKEND_URL     AI Inventory backend (default http://localhost:3000;
#                           "-" turns the inventory off)
#   OPENBOX_REDIS_URL       shared store (default redis://localhost:6379/7)
#   OBX_DASHBOARD_URL       for links (default http://localhost:3233)
#   OBX_HOST_IP             host IPv4 the sandbox VM reaches the door guard on
#   OPENSHELL_PREFIX        OpenShell v0.1.2 install (default ~/openshell-repro)
#   OBX_GATEWAY_PORT        default 17990 (+1 health, +2 metrics)
#   OBX_MW_PORT             door guard, default 50351 (+1 admin)
#   OBX_FD_PORT             front desk, default 50371 (+1 inventory)
#   OBX_MODEL_PORT          the demo's stand-in model, default 17995
set -eu

HERE=$(cd "$(dirname "$0")/.." && pwd)
DIR=${OBX_DEV_DIR:-/tmp/obx-dev}
PREFIX=${OPENSHELL_PREFIX:-$HOME/openshell-repro}
GW_PORT=${OBX_GATEWAY_PORT:-17990}
MW_PORT=${OBX_MW_PORT:-50351}
FD_PORT=${OBX_FD_PORT:-50371}
INV_PORT=$((FD_PORT + 1))
MODEL_PORT=${OBX_MODEL_PORT:-17995}
BACKEND=${OPENBOX_BACKEND_URL:-http://localhost:3000}
REDIS=${OPENBOX_REDIS_URL:-redis://localhost:6379/7}
DASHBOARD=${OBX_DASHBOARD_URL:-http://localhost:3233}
GATEWAY_NAME=openbox-dev
ISOLATE="XDG_STATE_HOME=$DIR/state XDG_CONFIG_HOME=$DIR/config OPENSHELL_LOCAL_TLS_DIR=$DIR/tls"

say() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
os() { env $ISOLATE "$PREFIX/bin/openshell" "$@"; }
free() { ! lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1; }
running() { [ -f "$DIR/$1.pid" ] && kill -0 "$(cat "$DIR/$1.pid")" 2>/dev/null; }
wait_listen() {
  i=0
  until ! free "$1"; do
    i=$((i + 1))
    running "$2" || { tail -20 "$DIR/$2.log" >&2; die "$2 exited (log: $DIR/$2.log)"; }
    [ $i -lt 120 ] || die "nothing listening on :$1 ($2)"
    sleep 0.5
  done
}

# Splits the dashboard snippet into private files and prints Core's URL.
import_agent_env() {
  python3 - "$1" "$DIR/creds" <<'PY'
import os, re, sys
src, out = sys.argv[1], sys.argv[2]
values = {}
for line in open(src):
    m = re.match(r'\s*(?:export\s+)?([A-Z_]+)\s*=\s*(.*)\s*$', line)
    if not m:
        continue
    key, value = m.groups()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
    values[key] = value.replace("\\n", "\n")
missing = [k for k in ("OPENBOX_API_URL", "OPENBOX_API_KEY", "OPENBOX_WORKLOAD_PRIVATE_KEY") if not values.get(k)]
if missing:
    sys.exit("agent env is missing " + ", ".join(missing))
os.makedirs(out, mode=0o700, exist_ok=True)
for name, key in (("api-key", "OPENBOX_API_KEY"), ("workload.pem", "OPENBOX_WORKLOAD_PRIVATE_KEY")):
    path = os.path.join(out, name)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(values[key].strip() + ("\n" if name.endswith(".pem") else ""))
print(values["OPENBOX_API_URL"].rstrip("/"))
PY
}

# Asks Core for the agent's workload bootstrap; prints "kid client_id token_endpoint".
bootstrap() {
  curl -fsS -H "Authorization: Bearer $(cat "$DIR/creds/api-key")" "$1/api/v3/auth/bootstrap" |
    python3 -c 'import sys,json; b=json.load(sys.stdin); print(b.get("kid") or "", b["client_id"], b["token_endpoint"])'
}

# Mints a workload token as the door guard will and prints its audience.
token_audience() {
  python3 - "$DIR/creds/workload.pem" "$1" "$2" "$3" <<'PY'
import base64, json, subprocess, sys, time, urllib.parse, urllib.request, uuid
pem, kid, client_id, endpoint = sys.argv[1:]
b64 = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")
now = int(time.time())
head = b64(json.dumps({"alg": "RS256", "kid": kid, "typ": "JWT"}).encode())
claims = b64(json.dumps({"aud": endpoint, "iss": client_id, "sub": client_id, "iat": now,
                         "exp": now + 60, "jti": str(uuid.uuid4())}).encode())
sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign", pem],
                     input=f"{head}.{claims}".encode(), capture_output=True, check=True).stdout
body = urllib.parse.urlencode({
    "grant_type": "client_credentials", "client_id": client_id,
    "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    "client_assertion": f"{head}.{claims}.{b64(sig)}"}).encode()
# Cloudflare in front of hosted Keycloak bans urllib's default User-Agent (error 1010).
req = urllib.request.Request(endpoint, data=body, headers={"User-Agent": "openbox-openshell.sh"})
token = json.load(urllib.request.urlopen(req))["access_token"]
payload = token.split(".")[1]
aud = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))).get("aud")
print(" ".join(aud) if isinstance(aud, list) else (aud or ""))
PY
}

up() {
  agent_env=
  while [ $# -gt 0 ]; do
    case $1 in
      --agent-env) agent_env=$2; shift 2 ;;
      *) die "unknown option $1" ;;
    esac
  done
  [ -n "$agent_env" ] || die "up needs --agent-env <file> (the agent's env snippet from the dashboard)"
  [ -f "$agent_env" ] || die "no such file: $agent_env"
  running gateway && die "already up; run '$0 down' first"
  [ -x "$PREFIX/bin/openshell-gateway" ] && [ -x "$PREFIX/libexec/openshell-driver-vm" ] ||
    die "OpenShell v0.1.2 not found in $PREFIX (set OPENSHELL_PREFIX; see verify-provider-profiles.sh)"
  for port in "$GW_PORT" $((GW_PORT + 1)) $((GW_PORT + 2)) "$MW_PORT" $((MW_PORT + 1)) "$FD_PORT" "$INV_PORT" "$MODEL_PORT"; do
    free "$port" || die "port $port is in use (set OBX_GATEWAY_PORT / OBX_MW_PORT / OBX_FD_PORT / OBX_MODEL_PORT)"
  done
  host_ip=${OBX_HOST_IP:-$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || true)}
  [ -n "$host_ip" ] || die "no host IPv4 found; set OBX_HOST_IP"
  mkdir -p "$DIR" && chmod 700 "$DIR"

  say "== Agent credentials"
  core=$(import_agent_env "$agent_env") || die "could not read $agent_env"
  curl -fsS -o /dev/null "$core/" || die "OpenBox Core not reachable at $core"
  set -- $(bootstrap "$core") || die "Core refused the API key (bootstrap failed)"
  kid=$1 client_id=$2 token_endpoint=$3
  [ -n "$kid" ] || die "the agent has no workload key registered (bootstrap returned no kid)"
  agent_id=$(printf '%s' "$client_id" | sed -n 's/^openbox-agent-\([0-9a-f-]\{36\}\)-.*/\1/p')
  say "   Core $core, agent ${agent_id:-?}, key $kid"
  aud=$(token_audience "$kid" "$client_id" "$token_endpoint") || die "could not get a workload token from $token_endpoint"
  case " $aud " in
    *" openbox-core "*) say "   workload token audience: $aud" ;;
    *) die "workload tokens carry no 'openbox-core' audience (got '${aud:-none}'): Core and the
       backend will reject them. Create a bearer-only client 'openbox-core' in the
       Keycloak realm (local stack: kcadm create clients -r openbox -s clientId=openbox-core -s bearerOnly=true)." ;;
  esac
  printf 'CORE=%s\nKID=%s\nAGENT_ID=%s\nMODEL_PORT=%s\n' "$core" "$kid" "$agent_id" "$MODEL_PORT" >"$DIR/agent"

  say "== Build the door guard and front desk"
  (cd "$HERE" && cargo build -q --bin openbox-verdict-middleware --bin openbox-governance-interceptor)
  creds="OPENBOX_URL=$core OPENBOX_API_KEY_FILE=$DIR/creds/api-key OPENBOX_WORKLOAD_KEY_FILE=$DIR/creds/workload.pem OPENBOX_WORKLOAD_KID=$kid OPENBOX_REDIS_URL=$REDIS"
  # "-" turns the inventory off: the front desk must not see the variable
  # at all, and the caller may have exported it.
  inventory="-u OPENBOX_BACKEND_URL"
  [ "$BACKEND" = - ] || inventory="OPENBOX_BACKEND_URL=$BACKEND"

  # The gateway's certificates first: the front desk reconciles over the
  # gateway API with its client certificate and reads it at startup.
  rm -rf "$DIR/tls"
  mkdir -p "$DIR/state/openshell/vm-driver" "$DIR/config" "$DIR/gwclient"
  [ -d "$HOME/.local/state/openshell/vm-driver/images" ] && [ ! -e "$DIR/state/openshell/vm-driver/images" ] &&
    ln -s "$HOME/.local/state/openshell/vm-driver/images" "$DIR/state/openshell/vm-driver/images"
  "$PREFIX/bin/openshell-gateway" generate-certs --output-dir "$DIR/tls" --server-san localhost >/dev/null 2>&1
  cp "$DIR/tls/ca.crt" "$DIR/gwclient/ca.crt"
  cp "$DIR/tls/client/tls.crt" "$DIR/tls/client/tls.key" "$DIR/gwclient/"
  say "== Start the door guard on :$MW_PORT and the front desk on :$FD_PORT/:$INV_PORT"
  env $creds OPENBOX_MW_INSECURE=1 OPENBOX_MW_LISTEN=0.0.0.0:$MW_PORT \
    OPENBOX_MW_ADMIN_LISTEN=127.0.0.1:$((MW_PORT + 1)) \
    "$HERE/target/debug/openbox-verdict-middleware" >"$DIR/door-guard.log" 2>&1 &
  echo $! >"$DIR/door-guard.pid"
  wait_listen "$MW_PORT" door-guard
  env $inventory $creds OPENBOX_FD_INSECURE=1 OPENBOX_FD_LISTEN=127.0.0.1:$FD_PORT \
    OPENBOX_FD_INVENTORY_LISTEN=127.0.0.1:$INV_PORT OPENBOX_FD_GATEWAY_ID=$GATEWAY_NAME \
    OPENBOX_GATEWAY_ENDPOINT=https://localhost:$GW_PORT OPENBOX_GATEWAY_MTLS_DIR=$DIR/gwclient \
    "$HERE/target/debug/openbox-governance-interceptor" >"$DIR/front-desk.log" 2>&1 &
  echo $! >"$DIR/front-desk.pid"
  wait_listen "$INV_PORT" front-desk

  say "== Start the demo's stand-in model on :$MODEL_PORT"
  stand_in_model >"$DIR/model.py"
  python3 "$DIR/model.py" "$MODEL_PORT" >"$DIR/model.log" 2>&1 &
  echo $! >"$DIR/model.pid"
  wait_listen "$MODEL_PORT" model

  say "== Start the OpenShell gateway on :$GW_PORT"
  cat >"$DIR/gateway.toml" <<EOF
[openshell]
version = 2

[openshell.gateway]
compute_driver = "vm"
bind_address = "127.0.0.1:$GW_PORT"
health_bind_address = "127.0.0.1:$((GW_PORT + 1))"
metrics_bind_address = "127.0.0.1:$((GW_PORT + 2))"

# The front desk, governing: attaches the door guard to every new sandbox and
# refuses changes that weaken it. Fail closed.
[[openshell.gateway.interceptors]]
name = "openbox"
grpc_endpoint = "http://127.0.0.1:$FD_PORT"
allow_insecure_transport = true
failure_policy = "fail_closed"
binding_policy = "allowlist"

[[openshell.gateway.interceptors.bindings]]
rpc = "openshell.v1.OpenShell/CreateSandbox"
phases = ["modify_operation", "validate"]

[[openshell.gateway.interceptors.bindings]]
rpc = "openshell.v1.OpenShell/UpdateConfig"
phases = ["validate"]

[[openshell.gateway.interceptors.bindings]]
rpc = "openshell.v1.OpenShell/ImportProviderProfiles"
phases = ["validate"]

[[openshell.gateway.interceptors.bindings]]
rpc = "openshell.v1.OpenShell/UpdateProviderProfiles"
phases = ["validate"]

# The front desk, recording: AI Inventory and the sandbox's OpenBox session.
# Fail open: it runs after the gateway has committed.
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

# The door guard: an OpenBox verdict on every request a sandbox makes, and its
# response recorded. The sandbox VM reaches it on the host's address.
[[openshell.supervisor.middleware]]
name = "openbox"
grpc_endpoint = "http://$host_ip:$MW_PORT"
allow_insecure_transport = true
max_payload_bytes = 1048576
timeout = "30s"
EOF
  env $ISOLATE "$PREFIX/bin/openshell-gateway" --config "$DIR/gateway.toml" >"$DIR/gateway.log" 2>&1 &
  echo $! >"$DIR/gateway.pid"
  wait_listen "$GW_PORT" gateway
  # A registration left by an earlier run would make `gateway add` refuse.
  os gateway remove "$GATEWAY_NAME" >/dev/null 2>&1 || true
  os gateway add "https://127.0.0.1:$GW_PORT" --local --name "$GATEWAY_NAME" >/dev/null

  # A CLI wrapper bound to this gateway's config, so `openshell` here never
  # touches another gateway.
  mkdir -p "$DIR/bin"
  cat >"$DIR/bin/openshell" <<EOF
#!/bin/sh
exec env $ISOLATE "$PREFIX/bin/openshell" "\$@"
EOF
  chmod +x "$DIR/bin/openshell"
  cat >"$DIR/policy.yaml" <<'EOF'
# A plain OpenShell sandbox policy. No OpenBox settings: the front desk
# attaches the door guard when the sandbox is created.
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
    name: example.com
    endpoints:
      - host: example.com
        port: 80
        protocol: rest
        access: read-write
    binaries:
      - path: /usr/bin/bash
  model:
    name: demo-model
    endpoints:
      - host: host.openshell.internal
        port: MODEL_PORT
        protocol: rest
        access: read-write
    binaries:
      - path: /usr/bin/bash
EOF
  sed -i.bak "s/MODEL_PORT/$MODEL_PORT/" "$DIR/policy.yaml" && rm -f "$DIR/policy.yaml.bak"

  say ""
  say "OpenShell is running, governed by OpenBox."
  say ""
  say "  export PATH=$DIR/bin:\$PATH       # 'openshell' now talks to this gateway"
  say "  openshell sandbox create --name my-box --policy $DIR/policy.yaml --detach --no-tty --no-auto-providers"
  say "  openshell sandbox exec -n my-box -- bash -c 'exec 3<>/dev/tcp/example.com/80; printf \"GET / HTTP/1.1\\r\\nHost: example.com\\r\\nConnection: close\\r\\n\\r\\n\" >&3; head -1 <&3'"
  say "  openshell sandbox delete my-box"
  say ""
  say "  Agent's sessions: $DASHBOARD/agents/${agent_id:-<agent id>}"
  say "  Or run the scripted session:  $0 demo"
  say "  Logs: $DIR/{door-guard,front-desk,gateway}.log    Stop: $0 down"
}

# The demo's model: a stand-in for the provider that answers like the
# Anthropic Messages API, so the door guard reads real replies. The first
# prompt gets a streamed reply asking for the `fetch` tool, the tool's result
# gets a text answer, and any other prompt a text answer. Not a model: fixed
# replies, on this machine only.
stand_in_model() {
  cat <<'EOF'
import http.server, json, sys

TOOL = {"type": "tool_use", "id": "toolu_demo_1", "name": "fetch", "input": {"url": "http://example.com/"}}

class Model(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("content-length", 0))) or b"{}")
        last = (body.get("messages") or [{}])[-1].get("content")
        tool_result = isinstance(last, list) and any(b.get("type") == "tool_result" for b in last)
        if not tool_result and "summarise" in json.dumps(last):
            return self.stream_tool_call()
        text = ("It is a placeholder page reserved for documentation examples." if tool_result
                else "Documentation examples, test fixtures and tutorials.")
        data = json.dumps({"id": "msg_demo", "type": "message", "role": "assistant", "model": "claude-demo",
                           "content": [{"type": "text", "text": text}], "stop_reason": "end_turn",
                           "usage": {"input_tokens": 40, "output_tokens": 12}}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def stream_tool_call(self):
        events = [
            ("message_start", {"type": "message_start", "message": {"id": "msg_demo_1", "model": "claude-demo", "usage": {"input_tokens": 25, "output_tokens": 1}}}),
            ("content_block_start", {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
            ("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "I'll fetch the page."}}),
            ("content_block_stop", {"type": "content_block_stop", "index": 0}),
            ("content_block_start", {"type": "content_block_start", "index": 1, "content_block": dict(TOOL, input={})}),
            ("content_block_delta", {"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta", "partial_json": json.dumps(TOOL["input"])}}),
            ("content_block_stop", {"type": "content_block_stop", "index": 1}),
            ("message_delta", {"type": "message_delta", "delta": {"stop_reason": "tool_use"}, "usage": {"output_tokens": 18}}),
            ("message_stop", {"type": "message_stop"}),
        ]
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.end_headers()
        for name, data in events:
            self.wfile.write(f"event: {name}\ndata: {json.dumps(data)}\n\n".encode())
            self.wfile.flush()

http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), Model).serve_forever()
EOF
}

# Runs inside the sandbox: what an agent does, without needing a model key.
# The user's prompt goes to the model, which asks for the `fetch` tool; the
# agent fetches the page and sends the result back; then the user asks
# something new.
demo_agent() {
  cat <<'EOF'
# Reads a response on fd 3 the way an HTTP client does: the status, the
# headers, then the body by Content-Length or by chunks, or to the end of a
# stream that has neither. OpenShell keeps the sandbox's connection open
# after a response, so waiting for it to close would hang.
response() {
  IFS=" " read -r _ code _ <&3
  len= chunked=
  while IFS= read -r line <&3; do
    line=${line%$'\r'}
    [ -z "$line" ] && break
    case ${line,,} in
      content-length:*) len=${line#*:}; len=${len// /} ;;
      transfer-encoding:*chunked*) chunked=1 ;;
    esac
  done
  if [ -n "$chunked" ]; then
    len=0
    while IFS= read -r size <&3; do
      size=${size%$'\r'}; size=$((16#${size%%;*}))
      [ "$size" -eq 0 ] && break
      LC_ALL=C read -r -N "$size" _ <&3; IFS= read -r _ <&3
      len=$((len + size))
    done
  elif [ -n "$len" ]; then
    [ "$len" -gt 0 ] && LC_ALL=C read -r -N "$len" _ <&3
  else
    cat <&3 >/dev/null
  fi
  exec 3>&-
}
post() {
  exec 3<>/dev/tcp/host.openshell.internal/MODEL_PORT
  printf "POST /v1/messages HTTP/1.1\r\nHost: host.openshell.internal:MODEL_PORT\r\nContent-Type: application/json\r\nContent-Length: %s\r\nConnection: close\r\n\r\n%s" "${#1}" "$1" >&3
  response; echo "model call: HTTP $code"
}
get() {
  exec 3<>/dev/tcp/example.com/80
  printf "GET %s HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n" "$1" >&3
  response; echo "fetch $1: HTTP $code (${len:-?} bytes)"
}
post '{"model":"claude-demo","stream":true,"messages":[{"role":"user","content":"summarise the example.com homepage"}]}'
get /
post '{"model":"claude-demo","messages":[{"role":"user","content":"summarise the example.com homepage"},{"role":"assistant","content":[{"type":"text","text":"I will fetch the page."},{"type":"tool_use","id":"toolu_demo_1","name":"fetch","input":{"url":"http://example.com/"}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_demo_1","content":"Example Domain. This domain is for use in documentation examples."}]}]}'
post '{"model":"claude-demo","messages":[{"role":"user","content":"summarise the example.com homepage"},{"role":"assistant","content":[{"type":"tool_use","id":"toolu_demo_1","name":"fetch","input":{"url":"http://example.com/"}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_demo_1","content":"Example Domain. This domain is for use in documentation examples."}]},{"role":"assistant","content":"It is a placeholder page reserved for documentation examples."},{"role":"user","content":"now list three uses for it"}]}'
EOF
}

demo() {
  running gateway || die "not up; run '$0 up --agent-env <file>' first"
  . "$DIR/agent"
  box=demo-$(($(date +%s) % 100000))
  say "== Create sandbox $box from a policy with no OpenBox settings"
  os sandbox create --name "$box" --policy "$DIR/policy.yaml" --detach --no-tty --no-auto-providers >/dev/null
  id=$(os sandbox get "$box" -o json | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("id") or d.get("metadata",{}).get("id",""))')
  attached=$(os policy get "$box" --full 2>/dev/null | grep -c 'middleware: openbox' || true)
  say "   sandbox id $id; door guard attached by the front desk: $([ "$attached" -gt 0 ] && echo yes || echo NO)"
  # About 10 s after start OpenShell reloads the sandbox's settings and drops a
  # request still waiting on a verdict; let that pass first.
  i=0
  until os logs "$box" --source sandbox 2>/dev/null | grep -q 'Settings poll'; do
    i=$((i + 1)); [ $i -le 30 ] || break; sleep 1
  done
  say "== The agent works (inside the sandbox)"
  os sandbox exec -n "$box" --no-tty --timeout 120 -- bash -c "$(demo_agent | sed "s/MODEL_PORT/${MODEL_PORT:-17995}/g")" 2>&1 | sed 's/^/   /'
  say "== Delete the sandbox"
  os sandbox delete "$box" >/dev/null
  say ""
  say "Session for sandbox $id (workflow id = sandbox id):"
  say "  $DASHBOARD/agents/$AGENT_ID  -> Sessions -> the newest openshell.sandbox session"
  say "Expected, as the agent SDK reports a session:"
  say "  WorkflowStarted"
  say "  SignalReceived user_prompt"
  say "  llm_call   (prompt in; claude-demo, 25/18 tokens, has_tool_calls out; its POST span started + completed)"
  say "  fetch      (url in; the GET example.com span inside it; the page text out)"
  say "  llm_call   (the answer out)"
  say "  SignalReceived user_prompt   (the new question)"
  say "  llm_call   (the answer out)"
  say "  WorkflowCompleted"
  say "On the local stack, check the seal:  python3 $HERE/scripts/verify-session-seal.py $id"
}

status() {
  for p in door-guard front-desk gateway model; do
    if running $p; then say "$p: running (pid $(cat "$DIR/$p.pid"))"; else say "$p: stopped"; fi
  done
  running gateway && os sandbox list 2>/dev/null || true
}

down() {
  if running gateway; then
    for box in $(os sandbox list --names 2>/dev/null); do
      os sandbox delete "$box" >/dev/null 2>&1 && say "deleted sandbox $box"
    done
  fi
  for p in gateway front-desk door-guard model; do
    if running $p; then kill "$(cat "$DIR/$p.pid")" && say "stopped $p"; fi
    rm -f "$DIR/$p.pid"
  done
  rm -rf "$DIR/creds"
  say "credentials removed from $DIR/creds; logs kept in $DIR"
}

cmd=${1:-}
[ $# -gt 0 ] && shift
case $cmd in
  up) up "$@" ;;
  demo) demo ;;
  status) status ;;
  down) down ;;
  *) sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
