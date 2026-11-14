# Evidence: signed verdict records

The door guard can write a signed record of every verdict it gives. Records
are chained, so a record edited, deleted, duplicated or moved after it was
written is caught by a verifier that needs only the public key.

## Turn it on

Make an Ed25519 key, keep the private half in a Secret the sandboxes cannot
read, and keep the public half wherever you verify:

```bash
openssl genpkey -algorithm ed25519 -out evidence.pem
openssl pkey -in evidence.pem -pubout -out evidence.pub
kubectl -n openbox create secret generic openbox-evidence --from-file=evidence.pem
helm upgrade openbox ... --set doorGuard.evidenceKeySecret=openbox-evidence
```

Each door guard pod then writes one JSON line per verdict to its stdout (its
log lines go to stderr), for your log pipeline to keep. Outside Kubernetes,
`OPENBOX_EVIDENCE_KEY_FILE` names the key and `OPENBOX_EVIDENCE_DIR` a
directory for daily files (`evidence-YYYY-MM-DD.jsonl`, UTC).

## What a record says

```json
{
  "class_uid": 6003, "category_uid": 6, "activity_id": 2, "time": 1794563000123,
  "metadata": {"uid": "sbx-1:door-guard-7c9f-x2:42", "sequence": 42, "version": "1.9.0",
               "product": {"name": "openbox-openshell", "vendor_name": "OpenBox"}},
  "openbox": {"sandbox_id": "sbx-1", "request_id": "…", "decision": "deny",
              "reason_code": "openbox_blocked", "governance_event_id": "…",
              "fast_path": false, "method": "POST", "host": "api.example.com",
              "url_sha256": "…"},
  "attestation": {"chain_uid": "sbx-1:door-guard-7c9f-x2", "prev_event": "<fingerprint of 41>",
                  "fingerprint": "<sha256>",
                  "signatures": [{"algorithm": "Ed25519", "key_id": "…", "value": "…"}]}
}
```

- **No content.** Identifiers and the outcome only; the URL as its SHA-256,
  since a query string can carry data.
- **One chain per sandbox per pod** (`chain_uid`), numbered from 1
  (`metadata.sequence`). Replicas never share a chain, so they never race for
  a number.
- **`fingerprint`** is the SHA-256 of the record without `fingerprint` and
  `signatures`, keys sorted. **`prev_event`** is the previous record's
  fingerprint. **`signatures`** sign the fingerprint.
- Field names follow the OCSF 1.9 `attestation` object proposed upstream for
  OpenShell's own events (NVIDIA/OpenShell#5177), so OpenShell's records and
  ours can be checked the same way once that lands.

`openbox_mw_evidence_records_total{outcome="failed"}` counts records that
could not be written: alert on it, since each one is a gap.

## Verify

`openbox-evidence` ships in the image next to the two services:

```bash
openbox-evidence verify --key evidence.pub records-*.jsonl
```

```
1200 records in 3 chains
ok      sbx-1:door-guard-7c9f-x2  records 1..800
FAILED  sbx-2:door-guard-7c9f-x2  records 1..300
      record 117: changed after it was written
ok      sbx-2:door-guard-7c9f-q8  records 1..100
```

It checks every fingerprint and signature and each chain's links and
numbering, across files given in any order (so a gap at a daily file's edge
is found too), and exits 1 on any problem: an edited, missing, duplicated or
reordered record, or one signed by an unknown key. `--partial` accepts a
chain that starts after record 1, for checking a later slice. Give `--key`
more than once while rotating keys.

## Seal

A certificate fixes a stretch of a chain under one Merkle root:

```bash
openbox-evidence seal --signing-key evidence.pem --chain sbx-1:door-guard-7c9f-x2 records-*.jsonl > cert.json
openbox-evidence check --key evidence.pub --certificate cert.json records-*.jsonl
```

`check` fails if any record the certificate covers has changed since.

## OpenBox Proof Certificates

With `doorGuard.evidenceCertifySecs` above 0 (`OPENBOX_EVIDENCE_CERTIFY_SECS`)
the door guard sends each chain's new records to Core that often, up to 1,000
per request, and on shutdown. Core (`POST /api/v3/governance/evidence/certify`)
checks them the way `verify` does, checks that the chain's sandbox is one of
the agent's own sessions, and returns a Proof Certificate: the range, count
and Merkle root of the records, the key that signed them and the previous
batch's last fingerprint (`first_prev_event`), signed with your
organisation's attestation key (AWS KMS, ECDSA P-256). The door guard writes
it next to the records as one line:

```json
{"openbox_certificate": {"certificate": {"chain_uid": "...", "first_sequence": 1, "last_sequence": 23, "merkle_root": "..."}, "signature": {"algorithm": "ECDSA_P256_SHA256", "key_id": "...", "value": "...", "public_key": "..."}}}
```

Check one with your organisation's public key, which you pin; the key the
certificate carries is for reference only:

```bash
openbox-evidence check --core-key org-attestation.pub --certificate cert-line.json records-*.jsonl
```

A batch Core cannot take is retried next time; one it refuses (HTTP 422: a
record changed, a gap, the wrong key) is dropped from the queue and counted
in `openbox_mw_evidence_certified_records_total{outcome="failed"}`, so the
chain's later records still get certificates. The records stay in the
output either way.

## OpenShell's OCSF log next to our records

OpenShell writes its own OCSF log, `/var/log/openshell-ocsf.YYYY-MM-DD.jsonl`
(JSON Lines, daily, three kept; `.log` before v0.1.8), once
`ocsf_json_enabled` is on:

```bash
openshell settings set --global --key ocsf_json_enabled --value true
```

**Collecting it.** On Kubernetes, set `ocsfCollector.enabled: true`. A
DaemonSet follows every OCSF file on each node (whichever pod runs the
supervisor, the shared supervisor pods or the sandbox pod, keeps it in an
`emptyDir` named `logs`) and writes each
line, unchanged, to stdout every `ocsfCollector.intervalSecs` (2 s), so the
pipeline that ships your pod logs ships these too. It keeps its place in a
hostPath, so a restart neither repeats nor skips lines, and a new day's file
or a replaced one is read from its start. Elsewhere, run the same command
where the files are:

```bash
openbox-evidence collect-ocsf --dir /var/log --state /var/lib/openbox-ocsf.json
```

The Docker and VM drivers keep the file inside the sandbox; collecting from
those hosts is not covered yet.

**Joining it to our records.** OpenShell v0.1.8's OCSF events do not carry
the request id (each event's `metadata.uid` is its own), so `join` pairs a
record with the event for the same sandbox (`device.container.uid`) and
destination host nearest in time, within `--window-ms` (default 2000), using
each event once. For each request OpenShell writes one event for its own
policy and one for the `openbox` middleware's decision
(`firewall_rule.type: middleware`, `status_detail:
middleware_denied:openbox:<reason code>`); `join` prefers the latter and
reports whether OpenShell recorded the same decision the record holds
(`agrees`, and `decisions_disagree` in the totals):

```bash
openbox-evidence join --ocsf openshell-ocsf.2026-11-14.jsonl records.jsonl
```

One JSON line per record (`record`, `request_id`, `sandbox_id`, `host`,
`ocsf_uid`, `ocsf_class_uid`, `ocsf_action`, `ocsf_status_detail`, `agrees`,
`delta_ms`), and the totals on stderr. A record
with no event in the window has `ocsf_uid: null`.
