#!/usr/bin/env python3
"""Check a sealed OpenBox Core session independently of Core.

    middleware/scripts/verify-session-seal.py <session id | sandbox id>

Reads the session, its governance events, its Merkle leaves and its
attestation straight from the OpenBox database and checks, without asking
Core:

  1. the session is completed and was sealed;
  2. every governance event in the session is covered by exactly one leaf,
     and no leaf points outside the session;
  3. the attestation's event count matches the leaves;
  4. the Merkle root rebuilt from the leaves (Core's algorithm: SHA-256 over
     byte-sorted pairs, last node duplicated on odd levels) equals the
     attested root;
  5. every leaf's stored inclusion proof leads to that root;
  6. changing any one leaf changes the root (tamper check, in memory only);
  7. the root's signature, when it can be checked here: with Core's local
     KMS (KMS_PROVIDER=local) it is an HMAC, checked only if the secret is
     given as OBX_LOCAL_KMS_SECRET; AWS KMS signatures are not checked here.

What it cannot check: that each leaf hashes that event's content. Core hashes
the event metadata including the client's original timestamp string, which
it does not store, so leaves cannot be recomputed from the stored events.

OBX_PSQL overrides the query command (default: the local stack's Postgres on
Colima). Prints PASS/FAIL/SKIP per check and exits non-zero on any FAIL.
"""

import base64
import hashlib
import hmac
import json
import os
import re
import shlex
import subprocess
import sys

PSQL = os.environ.get(
    "OBX_PSQL",
    "docker --context colima exec -i openbox-local-postgres-1 psql -U postgres -d openbox -tA -c",
)
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
failed = False


def query(sql):
    """One row of JSON from the database, or None."""
    out = subprocess.run(
        shlex.split(PSQL) + [sql], capture_output=True, text=True, check=True
    ).stdout.strip()
    return json.loads(out) if out else None


def result(ok, label, detail=""):
    global failed
    if ok is None:
        status = "SKIP"
    elif ok:
        status = "PASS"
    else:
        status, failed = "FAIL", True
    print(f"{status}  {label}" + (f" ({detail})" if detail else ""))


def hash_pair(a, b):
    if a > b:
        a, b = b, a
    return hashlib.sha256(a + b).digest()


def merkle_root(leaves):
    """Core's pkg/merkle BuildTree."""
    if not leaves:
        return hashlib.sha256(b"").digest()
    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hash_pair(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def fold_proof(leaf, proof):
    node = leaf
    for sibling in proof:
        node = hash_pair(node, sibling)
    return node


def main():
    if len(sys.argv) != 2 or not UUID.match(sys.argv[1].lower()):
        sys.exit(__doc__)
    ident = sys.argv[1].lower()

    session = query(
        f"""select row_to_json(s) from (
              select id, agent_id, workflow_id, status, started_at, completed_at
              from sessions where id::text = '{ident}' or workflow_id = '{ident}'
              order by created_at desc limit 1) s"""
    )
    if not session:
        sys.exit(f"no session with id or workflow_id {ident}")
    sid = session["id"]
    events = query(
        f"""select coalesce(json_agg(e order by e.created_at), '[]') from (
              select id, event_type, activity_type, verdict, input, created_at
              from governance_events where session_id = '{sid}') e"""
    )
    leaves = query(
        f"""select coalesce(json_agg(l order by l.leaf_index), '[]') from (
              select leaf_index, leaf_type, encode(leaf_hash, 'hex') as leaf_hash,
                     governance_event_id, proof
              from session_merkle_leaves where session_id = '{sid}') l"""
    )
    attestation = query(
        f"""select row_to_json(a) from (
              select encode(merkle_root, 'hex') as merkle_root, signature, event_count,
                     metadata, created_at
              from session_attestations where session_id = '{sid}'
              order by created_at desc limit 1) a"""
    )

    print(f"session   {sid}")
    print(f"sandbox   {session['workflow_id']}")
    print(f"agent     {session['agent_id']}")
    print(f"window    {session['started_at']} -> {session['completed_at']}")
    print("timeline")
    for event in events:
        target = ""
        if isinstance(event.get("input"), list) and event["input"]:
            first = event["input"][0]
            target = f"  {first.get('method', '')} {first.get('url', '')}"
        verdict = {0: "allow", 3: "block", 4: "halt"}.get(event["verdict"], event["verdict"])
        print(f"  {event['created_at']}  {event['event_type']:<17}{target}  verdict={verdict}")
    print()

    result(
        session["status"] == "completed" and session["completed_at"] is not None,
        "1 the session is completed",
        f"status {session['status']}",
    )
    if not attestation:
        result(False, "1 the session was sealed", "no attestation row")
        sys.exit(1)
    result(True, "1 the session was sealed", f"attested {attestation['created_at']}")

    event_ids = {event["id"] for event in events}
    covered = [leaf["governance_event_id"] for leaf in leaves if leaf["leaf_type"] == "event"]
    missing = event_ids - set(covered)
    doubled = {i for i in covered if covered.count(i) > 1}
    foreign = {leaf["governance_event_id"] for leaf in leaves} - event_ids - {None}
    result(
        not missing and not doubled and not foreign,
        "2 every event in the session is covered by exactly one leaf",
        f"{len(events)} events, {len(leaves)} leaves"
        + (f", missing {sorted(missing)}" if missing else "")
        + (f", doubled {sorted(doubled)}" if doubled else "")
        + (f", foreign {sorted(foreign)}" if foreign else ""),
    )
    result(
        attestation["event_count"] == len(leaves),
        "3 the attested event count matches the leaves",
        f"attested {attestation['event_count']}, leaves {len(leaves)}",
    )

    hashes = [bytes.fromhex(leaf["leaf_hash"]) for leaf in leaves]
    root = merkle_root(hashes)
    result(
        root.hex() == attestation["merkle_root"],
        "4 the root rebuilt from the leaves equals the attested root",
        attestation["merkle_root"],
    )

    bad = []
    for leaf, leaf_hash in zip(leaves, hashes):
        proof = [bytes.fromhex(h) for h in (leaf["proof"] or [])]
        if fold_proof(leaf_hash, proof) != root:
            bad.append(leaf["leaf_index"])
    result(not bad, "5 every leaf's inclusion proof leads to the root",
           f"bad leaves {bad}" if bad else f"{len(leaves)} proofs")

    undetected = []
    for i in range(len(hashes)):
        tampered = list(hashes)
        tampered[i] = bytes([tampered[i][0] ^ 1]) + tampered[i][1:]
        if merkle_root(tampered) == root:
            undetected.append(i)
    result(not undetected, "6 changing any one leaf changes the root",
           f"undetected at {undetected}" if undetected else "flipped one bit in each leaf in turn")

    public = base64.b64decode((attestation.get("metadata") or {}).get("public_key", "") or b"").decode(
        "utf-8", "replace"
    )
    if public.startswith("local-kms-public-key:"):
        key_id = public.removeprefix("local-kms-public-key:")
        secret = os.environ.get("OBX_LOCAL_KMS_SECRET")
        if not secret:
            result(None, "7 the root's signature",
                   f"local KMS HMAC (key {key_id}); set OBX_LOCAL_KMS_SECRET to check it")
        else:
            expected = base64.b64encode(
                hmac.new(f"{secret}:{key_id}".encode(), root.hex().encode(), hashlib.sha256).digest()
            ).decode()
            result(hmac.compare_digest(expected, attestation["signature"]),
                   "7 the root's signature (local KMS HMAC)", f"key {key_id}")
    else:
        result(None, "7 the root's signature", "AWS KMS signature, not checked by this script")

    print()
    print("ALL PASS" if not failed else "SOME FAILED")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
