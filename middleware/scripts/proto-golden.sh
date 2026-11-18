#!/bin/sh
# The OpenShell contract we build against, as a golden summary (SPEC-001 R1,
# PROD-1142 R9.2): every service, RPC, message field and enum value in the
# protos of the pinned openshell-core, one per line, comments dropped.
#
#   scripts/proto-golden.sh           rewrite tests/golden/openshell-proto.txt
#   scripts/proto-golden.sh --check   fail if the pinned protos differ from it
#
# Run without --check after bumping the OpenShell pin, and read the diff: it
# is every contract change the bump brings.
set -eu
HERE=$(cd "$(dirname "$0")/.." && pwd)
GOLDEN=$HERE/tests/golden/openshell-proto.txt
ROOT=$(cargo metadata --format-version 1 --manifest-path "$HERE/Cargo.toml" --locked 2>/dev/null |
  python3 -c 'import sys, json, os
for p in json.load(sys.stdin)["packages"]:
    if p["name"] == "openshell-core":
        print(os.path.dirname(os.path.dirname(os.path.dirname(p["manifest_path"])))); break')
[ -d "$ROOT/proto" ] || { echo "openshell-core protos not found (cargo fetch first)" >&2; exit 2; }
summary() {
  python3 - "$ROOT/proto" <<'PY'
import os, re, sys
root = sys.argv[1]
out = []
for name in sorted(os.listdir(root)):
    if not name.endswith(".proto"):
        continue
    text = open(os.path.join(root, name)).read()
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"//[^\n]*", "", text)
    scope = []
    for raw in text.splitlines():
        line = " ".join(raw.split())
        if not line:
            continue
        opened = re.match(r"^(message|enum|service|oneof) (\w+) ?\{", line)
        if opened:
            scope.append(f"{opened.group(1)} {opened.group(2)}")
            out.append(f"{name}: {' > '.join(scope)}")
            continue
        if line.startswith("}"):
            if scope:
                scope.pop()
            continue
        if line.startswith(("rpc ", "reserved ")) or re.search(r"= ?-?\d+", line):
            out.append(f"{name}: {' > '.join(scope)} :: {line.rstrip(';').rstrip('{').strip()}")
print("\n".join(out))
PY
}
if [ "${1:-}" = "--check" ]; then
  summary | diff -u "$GOLDEN" - || {
    echo "The pinned OpenShell protos differ from tests/golden/openshell-proto.txt." >&2
    echo "If the pin moved on purpose, run scripts/proto-golden.sh and commit the diff." >&2
    exit 1
  }
else
  summary >"$GOLDEN"
  echo "wrote $GOLDEN ($(wc -l <"$GOLDEN" | tr -d ' ') lines)"
fi
