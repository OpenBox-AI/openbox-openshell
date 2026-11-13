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

## What is not done yet

- **OpenBox Proof Certificates.** Sending batches of records to OpenBox's
  attestation service, to be anchored and issued as Proof Certificates the
  way Core seals sessions, needs an intake on Core's side. Until it exists,
  `seal` gives the same guarantee locally.
- **Collecting OpenShell's OCSF log.** Each sandbox writes
  `/var/log/openshell-ocsf.YYYY-MM-DD.log` (JSON Lines, daily, three kept)
  when `ocsf_json_enabled` is on. Shipping it within 60 s needs a collector
  per compute driver: on Kubernetes, a log agent that reads the sandbox pods'
  file; on the Docker and VM drivers, one on the host. Not built yet.
- **Joining OCSF events to our records.** OpenShell v0.1.8's OCSF events do
  not carry the request id, so a join uses the sandbox (`container.uid` in
  OCSF, `openbox.sandbox_id` here), the destination host and the time.
