//! Signed, hash-chained verdict records: evidence of what the door guard
//! decided that a later edit, deletion or reordering cannot hide.
//!
//! One record per verdict, as a JSON line. Records form a chain per sandbox
//! and replica (`attestation.chain_uid`), each carrying its sequence number
//! (`metadata.sequence`), the previous record's fingerprint
//! (`attestation.prev_event`), its own fingerprint (SHA-256 of the record
//! without `fingerprint` and `signatures`, keys sorted) and an Ed25519
//! signature over that fingerprint from a key the sandbox cannot reach. Field
//! names follow the OCSF 1.9 `attestation` object proposed for `OpenShell`
//! upstream (NVIDIA/OpenShell#5177), so the two can be read together.
//!
//! Records carry identifiers and outcomes only: no request content.
//! [`verify`] checks a set of records; [`seal`] batches a chain's records
//! under a Merkle root into a signed certificate.
//!
//! With an outbox ([`Evidence::with_outbox`]) each chain's new records also
//! wait to be sent to Core, which checks them and returns a Proof
//! Certificate signed with the organisation's attestation key
//! (OB-OSHELL-SPEC-002 R6.4). Certificates are written to the same sink as
//! one line under [`CERTIFICATE_KEY`]; [`verify`] skips those lines and
//! [`check_core_certificate`] checks one against the records it covers.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use ring::signature::{
    ECDSA_P256_SHA256_ASN1, ED25519, Ed25519KeyPair, KeyPair as _, UnparsedPublicKey,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// The top-level key of a Proof Certificate line in the evidence sink.
pub const CERTIFICATE_KEY: &str = "openbox_certificate";
/// Most records one chain keeps waiting for a certificate; past it the
/// oldest are dropped from the outbox (they stay in the sink) and the next
/// certificate starts after the gap.
const MAX_OUTBOX: usize = 10_000;

/// The signing key, kept by the door guard (a Kubernetes Secret), never in a
/// sandbox.
pub struct Signer {
    key: Ed25519KeyPair,
    pub key_id: String,
}

impl Signer {
    /// From a PKCS#8 PEM (`openssl genpkey -algorithm ed25519`).
    pub fn from_pem(pem: &str) -> Result<Self, String> {
        let der = pem_body(pem, "PRIVATE KEY")?;
        let key = Ed25519KeyPair::from_pkcs8_maybe_unchecked(&der)
            .map_err(|_| "evidence key: not an Ed25519 PKCS#8 key".to_owned())?;
        let key_id = key_id(key.public_key().as_ref());
        Ok(Self { key, key_id })
    }

    pub fn public_key(&self) -> &[u8] {
        self.key.public_key().as_ref()
    }

    fn sign(&self, message: &[u8]) -> String {
        B64.encode(self.key.sign(message).as_ref())
    }
}

/// A public key for verification: an SPKI PEM (`openssl pkey -pubout`) or
/// the raw 32 bytes in base64.
pub fn public_key(text: &str) -> Result<Vec<u8>, String> {
    let raw = if text.contains("-----BEGIN") {
        let der = pem_body(text, "PUBLIC KEY")?;
        der.get(der.len().saturating_sub(32)..)
            .ok_or("public key: too short")?
            .to_vec()
    } else {
        B64.decode(text.trim())
            .map_err(|_| "public key: not base64".to_owned())?
    };
    if raw.len() != 32 {
        return Err("public key: an Ed25519 key is 32 bytes".to_owned());
    }
    Ok(raw)
}

pub fn key_id(public: &[u8]) -> String {
    hex(&Sha256::digest(public)[..8])
}

fn pem_body(pem: &str, label: &str) -> Result<Vec<u8>, String> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let start = pem
        .find(&begin)
        .ok_or_else(|| format!("expected a PEM {label}"))?
        + begin.len();
    let stop = pem[start..]
        .find(&end)
        .ok_or_else(|| format!("unterminated PEM {label}"))?
        + start;
    let body: String = pem[start..stop].split_whitespace().collect();
    B64.decode(body)
        .map_err(|_| format!("PEM {label}: not base64"))
}

/// Where records go.
pub enum Sink {
    /// One JSON line per record on stdout, for the log pipeline.
    Stdout,
    /// `evidence-YYYY-MM-DD.jsonl` in this directory, by UTC day.
    Directory(PathBuf),
    /// For tests.
    Memory(Mutex<Vec<String>>),
}

/// What a verdict record states.
pub struct Verdict<'a> {
    pub sandbox_id: &'a str,
    pub request_id: &'a str,
    pub method: &'a str,
    pub host: &'a str,
    pub url: &'a str,
    pub allowed: bool,
    pub reason_code: &'a str,
    pub governance_event_id: Option<&'a str>,
    pub fast_path: bool,
}

pub struct Evidence {
    signer: Signer,
    sink: Sink,
    /// This replica: its chains are its own, so replicas never race on a
    /// sequence number.
    replica: String,
    /// chain → (last sequence, last fingerprint).
    chains: Mutex<HashMap<String, (u64, String)>>,
    /// chain → records not yet certified by Core, oldest first.
    outbox: Option<Mutex<BTreeMap<String, VecDeque<Value>>>>,
}

impl Evidence {
    pub fn new(signer: Signer, sink: Sink, replica: impl Into<String>) -> Self {
        Self {
            signer,
            sink,
            replica: replica.into(),
            chains: Mutex::new(HashMap::new()),
            outbox: None,
        }
    }

    /// Keeps each chain's new records for Core to certify.
    #[must_use]
    pub fn with_outbox(mut self) -> Self {
        self.outbox = Some(Mutex::new(BTreeMap::new()));
        self
    }

    pub fn certifies(&self) -> bool {
        self.outbox.is_some()
    }

    /// The signing key's public half, raw 32 bytes in base64, as Core takes it.
    pub fn public_key_base64(&self) -> String {
        B64.encode(self.signer.public_key())
    }

    /// Takes up to `max` of the oldest uncertified records of every chain.
    pub fn take_batches(&self, max: usize) -> Vec<(String, Vec<Value>)> {
        let Some(outbox) = &self.outbox else {
            return Vec::new();
        };
        let mut outbox = outbox.lock().expect("evidence lock");
        let batches = outbox
            .iter_mut()
            .filter(|(_, records)| !records.is_empty())
            .map(|(chain, records)| {
                let take = records.len().min(max);
                (chain.clone(), records.drain(..take).collect())
            })
            .collect();
        outbox.retain(|_, records| !records.is_empty());
        batches
    }

    /// Puts a batch Core did not certify back at the front of its chain.
    pub fn restore(&self, chain: &str, batch: Vec<Value>) {
        let Some(outbox) = &self.outbox else { return };
        let mut outbox = outbox.lock().expect("evidence lock");
        let records = outbox.entry(chain.to_owned()).or_default();
        for record in batch.into_iter().rev() {
            records.push_front(record);
        }
        while records.len() > MAX_OUTBOX {
            records.pop_front();
        }
    }

    /// Writes a certificate Core issued, as one line under
    /// [`CERTIFICATE_KEY`].
    pub fn write_certificate(&self, certificate: &Value) -> Result<(), String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| {
                u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
            });
        self.write(&json!({ CERTIFICATE_KEY: certificate }), now)
    }

    /// Writes the record for one verdict. Returns the record, or an error if
    /// it could not be written.
    pub fn record(&self, verdict: &Verdict<'_>) -> Result<Value, String> {
        let chain = format!("{}:{}", verdict.sandbox_id, self.replica);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| {
                u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
            });
        let mut chains = self.chains.lock().expect("evidence lock");
        let (sequence, previous) = chains
            .get(&chain)
            .map_or((1, String::new()), |(sequence, fingerprint)| {
                (sequence + 1, fingerprint.clone())
            });
        let mut record = json!({
            "class_uid": 6003,
            "category_uid": 6,
            "activity_id": if verdict.allowed { 1 } else { 2 },
            "time": now,
            "metadata": {
                "uid": format!("{chain}:{sequence}"),
                "sequence": sequence,
                "version": "1.9.0",
                "product": {"name": "openbox-openshell", "vendor_name": "OpenBox"},
            },
            "openbox": {
                "sandbox_id": verdict.sandbox_id,
                "request_id": verdict.request_id,
                "decision": if verdict.allowed { "allow" } else { "deny" },
                "reason_code": verdict.reason_code,
                "governance_event_id": verdict.governance_event_id,
                "fast_path": verdict.fast_path,
                "method": verdict.method,
                "host": verdict.host,
                // The URL can carry data in its query: its digest only.
                "url_sha256": hex(&Sha256::digest(verdict.url.as_bytes())),
            },
            "attestation": {
                "chain_uid": chain,
                "prev_event": if previous.is_empty() { Value::Null } else { json!(previous) },
            },
        });
        let fingerprint = fingerprint(&record);
        record["attestation"]["fingerprint"] = json!(fingerprint);
        record["attestation"]["signatures"] = json!([{
            "algorithm": "Ed25519",
            "key_id": self.signer.key_id,
            "value": self.signer.sign(fingerprint.as_bytes()),
        }]);
        self.write(&record, now)?;
        if let Some(outbox) = &self.outbox {
            let mut outbox = outbox.lock().expect("evidence lock");
            let waiting = outbox.entry(chain.clone()).or_default();
            waiting.push_back(record.clone());
            if waiting.len() > MAX_OUTBOX {
                waiting.pop_front();
            }
        }
        chains.insert(chain, (sequence, fingerprint));
        Ok(record)
    }

    fn write(&self, record: &Value, now_ms: u64) -> Result<(), String> {
        let line = record.to_string();
        match &self.sink {
            Sink::Stdout => {
                let mut out = std::io::stdout().lock();
                writeln!(out, "{line}").map_err(|error| error.to_string())
            }
            Sink::Directory(dir) => {
                let path = dir.join(format!("evidence-{}.jsonl", utc_day(now_ms / 1000)));
                let mut file = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&path)
                    .map_err(|error| format!("{}: {error}", path.display()))?;
                writeln!(file, "{line}").map_err(|error| error.to_string())
            }
            Sink::Memory(lines) => {
                lines.lock().expect("evidence lock").push(line);
                Ok(())
            }
        }
    }

    pub fn written(&self) -> Vec<String> {
        match &self.sink {
            Sink::Memory(lines) => lines.lock().expect("evidence lock").clone(),
            _ => Vec::new(),
        }
    }
}

/// A record's fingerprint: SHA-256 (hex) of the record without
/// `attestation.fingerprint` and `attestation.signatures`, serialised with
/// sorted keys.
pub fn fingerprint(record: &Value) -> String {
    let mut bare = record.clone();
    if let Some(attestation) = bare.get_mut("attestation").and_then(Value::as_object_mut) {
        attestation.remove("fingerprint");
        attestation.remove("signatures");
    }
    hex(&Sha256::digest(bare.to_string().as_bytes()))
}

/// What [`verify`] found, per chain.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub records: usize,
    pub chains: BTreeMap<String, ChainReport>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ChainReport {
    pub first: u64,
    pub last: u64,
    pub problems: Vec<String>,
}

impl Report {
    pub fn ok(&self) -> bool {
        self.chains.values().all(|chain| chain.problems.is_empty())
    }
}

/// Verifies records: every fingerprint, signature and chain link.
///
/// Records are JSON lines, in any order, from any number of files joined.
/// Signatures are checked against `keys`. A chain is expected to start at 1
/// unless `allow_partial` (checking a later slice of it).
pub fn verify(lines: &[String], keys: &[Vec<u8>], allow_partial: bool) -> Report {
    let keys: HashMap<String, &Vec<u8>> = keys.iter().map(|key| (key_id(key), key)).collect();
    let mut report = Report::default();
    let mut by_chain: BTreeMap<String, Vec<(u64, Value)>> = BTreeMap::new();
    for (index, line) in lines.iter().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let Ok(record) = serde_json::from_str::<Value>(line) else {
            report.records += 1;
            report
                .chains
                .entry("<unreadable>".to_owned())
                .or_default()
                .problems
                .push(format!("line {}: not JSON", index + 1));
            continue;
        };
        if record.get(CERTIFICATE_KEY).is_some() {
            continue;
        }
        report.records += 1;
        let chain = record
            .pointer("/attestation/chain_uid")
            .and_then(Value::as_str)
            .unwrap_or("<no chain>")
            .to_owned();
        let sequence = record
            .pointer("/metadata/sequence")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        by_chain.entry(chain).or_default().push((sequence, record));
    }
    for (chain, mut records) in by_chain {
        records.sort_by_key(|(sequence, _)| *sequence);
        report
            .chains
            .insert(chain, check_chain(&records, &keys, allow_partial));
    }
    report
}

/// One chain's checks, its records in sequence order.
fn check_chain(
    records: &[(u64, Value)],
    keys: &HashMap<String, &Vec<u8>>,
    allow_partial: bool,
) -> ChainReport {
    let mut entry = ChainReport::default();
    let entry = &mut entry;
    entry.first = records.first().map_or(0, |(sequence, _)| *sequence);
    entry.last = records.last().map_or(0, |(sequence, _)| *sequence);
    if !allow_partial && entry.first != 1 {
        entry.problems.push(format!(
            "records 1 to {} are missing",
            entry.first.saturating_sub(1)
        ));
    }
    let mut previous: Option<(u64, String)> = None;
    for (sequence, record) in records {
        let stated = record
            .pointer("/attestation/fingerprint")
            .and_then(Value::as_str)
            .unwrap_or("");
        let actual = fingerprint(record);
        if stated != actual {
            entry
                .problems
                .push(format!("record {sequence}: changed after it was written"));
        }
        let signed = signed_by(record, stated, keys);
        if !signed {
            entry.problems.push(format!(
                "record {sequence}: no valid signature from a known key"
            ));
        }
        let prev = record
            .pointer("/attestation/prev_event")
            .and_then(Value::as_str)
            .unwrap_or("");
        match &previous {
            Some((last, fingerprint)) => {
                if *sequence == *last {
                    entry
                        .problems
                        .push(format!("record {sequence}: duplicated"));
                } else if *sequence != last + 1 {
                    entry.problems.push(format!(
                        "records {} to {} are missing",
                        last + 1,
                        sequence - 1
                    ));
                } else if prev != fingerprint {
                    entry
                        .problems
                        .push(format!("record {sequence}: does not follow record {last}"));
                }
            }
            None if *sequence == 1 && !prev.is_empty() => {
                entry
                    .problems
                    .push("record 1: names a previous record".to_owned());
            }
            None => {}
        }
        previous = Some((*sequence, stated.to_owned()));
    }
    std::mem::take(entry)
}

/// Whether a record carries a valid signature over `fingerprint` from a key
/// in `keys`.
fn signed_by(record: &Value, fingerprint: &str, keys: &HashMap<String, &Vec<u8>>) -> bool {
    record
        .pointer("/attestation/signatures")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|signature| {
            let key = signature
                .get("key_id")
                .and_then(Value::as_str)
                .and_then(|id| keys.get(id));
            let value = signature
                .get("value")
                .and_then(Value::as_str)
                .and_then(|value| B64.decode(value).ok());
            matches!((key, value), (Some(key), Some(value))
                if UnparsedPublicKey::new(&ED25519, key.as_slice())
                    .verify(fingerprint.as_bytes(), &value)
                    .is_ok())
        })
}

/// Seals one chain's records (already verified) into a certificate: the
/// Merkle root of their fingerprints in sequence order, signed.
pub fn seal(lines: &[String], chain: &str, signer: &Signer) -> Result<Value, String> {
    let mut records: Vec<(u64, String)> = lines
        .iter()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|record| {
            record
                .pointer("/attestation/chain_uid")
                .and_then(Value::as_str)
                == Some(chain)
        })
        .filter_map(|record| {
            Some((
                record.pointer("/metadata/sequence")?.as_u64()?,
                record
                    .pointer("/attestation/fingerprint")?
                    .as_str()?
                    .to_owned(),
            ))
        })
        .collect();
    if records.is_empty() {
        return Err(format!("no records for chain {chain}"));
    }
    records.sort_by_key(|(sequence, _)| *sequence);
    let leaves: Vec<String> = records
        .iter()
        .map(|(_, fingerprint)| fingerprint.clone())
        .collect();
    let root = merkle_root(&leaves);
    let mut certificate = json!({
        "chain_uid": chain,
        "first_sequence": records[0].0,
        "last_sequence": records[records.len() - 1].0,
        "count": records.len(),
        "merkle_root": root,
        "issued_at": SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_secs()),
    });
    certificate["signature"] = json!({
        "algorithm": "Ed25519",
        "key_id": signer.key_id,
        "value": signer.sign(certificate.to_string().as_bytes()),
    });
    Ok(certificate)
}

/// Checks a certificate against the records it covers and a key.
pub fn check_certificate(
    certificate: &Value,
    lines: &[String],
    keys: &[Vec<u8>],
) -> Result<(), String> {
    let mut bare = certificate.clone();
    let signature = bare
        .as_object_mut()
        .and_then(|object| object.remove("signature"))
        .ok_or("certificate: no signature")?;
    let key_id = signature
        .get("key_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let key = keys
        .iter()
        .find(|key| self::key_id(key) == key_id)
        .ok_or("certificate: signed by an unknown key")?;
    let value = signature
        .get("value")
        .and_then(Value::as_str)
        .and_then(|value| B64.decode(value).ok())
        .ok_or("certificate: unreadable signature")?;
    UnparsedPublicKey::new(&ED25519, key.as_slice())
        .verify(bare.to_string().as_bytes(), &value)
        .map_err(|_| "certificate: signature does not match")?;
    let chain = certificate["chain_uid"].as_str().unwrap_or("");
    let (first, last) = (
        certificate["first_sequence"].as_u64().unwrap_or(0),
        certificate["last_sequence"].as_u64().unwrap_or(0),
    );
    let mut covered: Vec<(u64, String)> = lines
        .iter()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|record| {
            record
                .pointer("/attestation/chain_uid")
                .and_then(Value::as_str)
                == Some(chain)
        })
        .filter_map(|record| {
            let sequence = record.pointer("/metadata/sequence")?.as_u64()?;
            (first..=last)
                .contains(&sequence)
                .then(|| (sequence, fingerprint(&record)))
        })
        .collect();
    covered.sort_by_key(|(sequence, _)| *sequence);
    let leaves: Vec<String> = covered
        .into_iter()
        .map(|(_, fingerprint)| fingerprint)
        .collect();
    if merkle_root(&leaves) != certificate["merkle_root"].as_str().unwrap_or("") {
        return Err("certificate: the records it covers have changed".to_owned());
    }
    Ok(())
}

/// An ECDSA P-256 public key for [`check_core_certificate`]: an SPKI PEM or
/// base64 SPKI DER, as Core reports the organisation's attestation key.
/// Returns the uncompressed point ring verifies with.
pub fn core_public_key(text: &str) -> Result<Vec<u8>, String> {
    let der = if text.contains("-----BEGIN") {
        pem_body(text, "PUBLIC KEY")?
    } else {
        B64.decode(text.trim())
            .map_err(|_| "Core key: not base64".to_owned())?
    };
    let point = der
        .get(der.len().saturating_sub(65)..)
        .ok_or("Core key: too short")?;
    if point.len() != 65 || point[0] != 4 {
        return Err("Core key: not an uncompressed P-256 key".to_owned());
    }
    Ok(point.to_vec())
}

/// Checks a Proof Certificate Core issued against the records it covers.
///
/// The certificate is `{certificate, signature}`, alone or under
/// [`CERTIFICATE_KEY`]. Checked: Core's
/// ECDSA P-256 signature over the certificate's sorted-key JSON, by one of
/// `core_keys` (the organisation key you pin, never the one the certificate
/// carries), and the Merkle root of the covered records' fingerprints.
pub fn check_core_certificate(
    issued: &Value,
    lines: &[String],
    core_keys: &[Vec<u8>],
) -> Result<(), String> {
    let issued = issued.get(CERTIFICATE_KEY).unwrap_or(issued);
    let certificate = issued
        .get("certificate")
        .ok_or("Core certificate: no certificate")?;
    let signature = issued
        .get("signature")
        .ok_or("Core certificate: no signature")?;
    if signature.get("algorithm").and_then(Value::as_str) != Some("ECDSA_P256_SHA256") {
        return Err("Core certificate: not an ECDSA P-256 signature".to_owned());
    }
    let value = signature
        .get("value")
        .and_then(Value::as_str)
        .and_then(|value| B64.decode(value).ok())
        .ok_or("Core certificate: unreadable signature")?;
    let signed = certificate.to_string();
    if !core_keys.iter().any(|key| {
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, key.as_slice())
            .verify(signed.as_bytes(), &value)
            .is_ok()
    }) {
        return Err("Core certificate: not signed by a pinned Core key".to_owned());
    }
    let chain = certificate["chain_uid"].as_str().unwrap_or("");
    let (first, last) = (
        certificate["first_sequence"].as_u64().unwrap_or(0),
        certificate["last_sequence"].as_u64().unwrap_or(0),
    );
    let mut covered: Vec<(u64, String)> = lines
        .iter()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|record| {
            record
                .pointer("/attestation/chain_uid")
                .and_then(Value::as_str)
                == Some(chain)
        })
        .filter_map(|record| {
            let sequence = record.pointer("/metadata/sequence")?.as_u64()?;
            (first..=last)
                .contains(&sequence)
                .then(|| (sequence, fingerprint(&record)))
        })
        .collect();
    covered.sort_by_key(|(sequence, _)| *sequence);
    covered.dedup_by_key(|(sequence, _)| *sequence);
    if u64::try_from(covered.len()).unwrap_or(0) != last.saturating_sub(first) + 1
        || certificate["count"].as_u64() != u64::try_from(covered.len()).ok()
    {
        return Err(format!(
            "Core certificate: records {first} to {last} of {chain} are not all here"
        ));
    }
    let leaves: Vec<String> = covered
        .into_iter()
        .map(|(_, fingerprint)| fingerprint)
        .collect();
    if merkle_root(&leaves) != certificate["merkle_root"].as_str().unwrap_or("") {
        return Err("Core certificate: the records it covers have changed".to_owned());
    }
    Ok(())
}

/// Binary Merkle root over hex leaves; an odd node is promoted unchanged.
fn merkle_root(leaves: &[String]) -> String {
    let mut level: Vec<Vec<u8>> = leaves
        .iter()
        .map(|leaf| Sha256::digest([&[0_u8][..], leaf.as_bytes()].concat()).to_vec())
        .collect();
    if level.is_empty() {
        return String::new();
    }
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| match pair {
                [left, right] => Sha256::digest([&[1_u8][..], left, right].concat()).to_vec(),
                [single] => single.clone(),
                _ => unreachable!(),
            })
            .collect();
    }
    hex(&level[0])
}

fn utc_day(unix: u64) -> String {
    let days = i64::try_from(unix / 86_400).unwrap_or(0);
    // Civil from days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub fn signer() -> Signer {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let pem = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            B64.encode(pkcs8.as_ref())
        );
        Signer::from_pem(&pem).unwrap()
    }

    fn verdict(request_id: &str) -> Verdict<'_> {
        Verdict {
            sandbox_id: "sbx-1",
            request_id,
            method: "GET",
            host: "example.com",
            url: "https://example.com/?q=secret",
            allowed: true,
            reason_code: "",
            governance_event_id: Some("evt-1"),
            fast_path: false,
        }
    }

    fn chain(n: usize) -> (Vec<String>, Vec<u8>, Signer) {
        let signer = signer();
        let public = signer.public_key().to_vec();
        let evidence = Evidence::new(signer, Sink::Memory(Mutex::new(Vec::new())), "r1");
        for i in 0..n {
            evidence.record(&verdict(&format!("req-{i}"))).unwrap();
        }
        (evidence.written(), public, self::signer())
    }

    /// SPEC-001 C1: an intact chain verifies; the record carries no content.
    #[test]
    fn an_intact_chain_verifies() {
        let (lines, key, _) = chain(5);
        let report = verify(&lines, &[key], false);
        assert!(report.ok(), "{report:?}");
        assert_eq!(report.records, 5);
        assert_eq!(report.chains["sbx-1:r1"].last, 5);
        assert!(!lines.join("").contains("secret"));
    }

    /// C2 and the done-when: editing one record after it was written fails.
    #[test]
    fn an_edited_record_fails() {
        let (mut lines, key, _) = chain(3);
        lines[1] = lines[1].replace("\"allow\"", "\"deny\"");
        let report = verify(&lines, &[key], false);
        assert!(!report.ok());
        assert!(
            report.chains["sbx-1:r1"].problems[0].contains("record 2: changed"),
            "{report:?}"
        );
    }

    /// C3 and R6.5: a deleted record and a reordered chain are found, across
    /// files given in any order.
    #[test]
    fn missing_and_forged_links_fail() {
        let (lines, key, _) = chain(4);
        let mut gap = lines.clone();
        gap.remove(2);
        let report = verify(&gap, std::slice::from_ref(&key), false);
        assert!(
            report.chains["sbx-1:r1"]
                .problems
                .iter()
                .any(|p| p.contains("records 3 to 3 are missing"))
        );
        let mut shuffled = lines.clone();
        shuffled.reverse();
        assert!(
            verify(&shuffled, std::slice::from_ref(&key), false).ok(),
            "order on disk does not matter"
        );
        // A record signed by another key.
        let other = signer().public_key().to_vec();
        assert!(!verify(&lines, &[other], false).ok());
        // A later slice verifies only when asked to.
        assert!(!verify(&lines[2..], std::slice::from_ref(&key), false).ok());
        assert!(verify(&lines[2..], &[key], true).ok());
    }

    #[test]
    fn a_certificate_seals_its_records() {
        let (lines, _, _) = chain(5);
        let sealer = signer();
        let key = sealer.public_key().to_vec();
        let certificate = seal(&lines, "sbx-1:r1", &sealer).unwrap();
        assert_eq!(certificate["count"], 5);
        assert!(check_certificate(&certificate, &lines, std::slice::from_ref(&key)).is_ok());
        let mut edited = lines.clone();
        edited[4] = edited[4].replace("\"GET\"", "\"PUT\"");
        assert!(check_certificate(&certificate, &edited, std::slice::from_ref(&key)).is_err());
        let mut forged = certificate;
        forged["count"] = json!(4);
        assert!(check_certificate(&forged, &lines, &[key]).is_err());
    }

    #[test]
    fn the_outbox_hands_out_batches_and_takes_refused_ones_back() {
        let evidence =
            Evidence::new(signer(), Sink::Memory(Mutex::new(Vec::new())), "r1").with_outbox();
        assert!(evidence.certifies());
        for i in 0..5 {
            evidence.record(&verdict(&format!("req-{i}"))).unwrap();
        }
        let batches = evidence.take_batches(3);
        assert_eq!(batches.len(), 1);
        let (chain, first) = &batches[0];
        assert_eq!(chain, "sbx-1:r1");
        assert_eq!(first.len(), 3);
        assert_eq!(first[0]["metadata"]["sequence"], 1);
        evidence.restore(chain, first.clone());
        let again = evidence.take_batches(10);
        assert_eq!(again[0].1.len(), 5, "a refused batch goes back in front");
        assert_eq!(again[0].1[0]["metadata"]["sequence"], 1);
        assert!(evidence.take_batches(10).is_empty());
        assert!(!Evidence::new(signer(), Sink::Memory(Mutex::new(Vec::new())), "r1").certifies());
    }

    /// Core's certificate format: `{certificate, signature}` signed with an
    /// ECDSA P-256 key over the certificate's sorted-key JSON.
    fn core_issue(lines: &[String], first: u64, last: u64) -> (Value, Vec<u8>) {
        use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair};
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        let leaves: Vec<String> = lines
            .iter()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .filter(|record| {
                (first..=last).contains(&record["metadata"]["sequence"].as_u64().unwrap())
            })
            .map(|record| fingerprint(&record))
            .collect();
        let certificate = json!({
            "scheme": "openbox.proof_certificate.v1",
            "organization_id": "example.test",
            "agent_id": "agent-1",
            "chain_uid": "sbx-1:r1",
            "first_sequence": first,
            "last_sequence": last,
            "count": leaves.len(),
            "merkle_root": merkle_root(&leaves),
            "record_key_id": "k",
            "issued_at": "2026-11-14T10:00:00Z",
        });
        let signature = key.sign(&rng, certificate.to_string().as_bytes()).unwrap();
        let point = key.public_key().as_ref().to_vec();
        (
            json!({
                "certificate": certificate,
                "signature": {"algorithm": "ECDSA_P256_SHA256", "key_id": "org", "value": B64.encode(signature.as_ref())},
            }),
            point,
        )
    }

    #[test]
    fn a_core_certificate_checks_against_the_records_it_covers() {
        let (lines, _, _) = chain(6);
        let (issued, point) = core_issue(&lines, 2, 5);
        let keys = std::slice::from_ref(&point);
        assert!(check_core_certificate(&issued, &lines, keys).is_ok());
        let line = json!({ CERTIFICATE_KEY: &issued });
        assert!(
            check_core_certificate(&line, &lines, keys).is_ok(),
            "as written in the sink"
        );

        let mut edited = lines.clone();
        edited[2] = edited[2].replace("\"GET\"", "\"PUT\"");
        assert!(check_core_certificate(&issued, &edited, keys).is_err());
        let missing: Vec<String> = lines.iter().take(4).cloned().collect();
        assert!(check_core_certificate(&issued, &missing, keys).is_err());
        let (_, other) = core_issue(&lines, 2, 5);
        assert!(check_core_certificate(&issued, &lines, &[other]).is_err());
        let mut forged = issued;
        forged["certificate"]["last_sequence"] = json!(4);
        assert!(check_core_certificate(&forged, &lines, keys).is_err());
    }

    #[test]
    fn verify_skips_certificate_lines() {
        let (mut lines, public, _) = chain(3);
        lines.push(json!({ CERTIFICATE_KEY: {"certificate": {}, "signature": {}} }).to_string());
        let report = verify(&lines, &[public], false);
        assert_eq!(report.records, 3);
        assert!(
            report
                .chains
                .values()
                .all(|chain| chain.problems.is_empty())
        );
    }

    #[test]
    fn core_keys_load_from_spki_pem_and_base64() {
        let mut spki = vec![0x30, 0x59, 0x30, 0x13];
        spki.extend([0_u8; 21]);
        spki.extend([0x03, 0x42, 0x00, 0x04]);
        spki.extend([7_u8; 64]);
        let b64 = B64.encode(&spki);
        assert_eq!(core_public_key(&b64).unwrap().len(), 65);
        let pem = format!("-----BEGIN PUBLIC KEY-----\n{b64}\n-----END PUBLIC KEY-----\n");
        assert_eq!(core_public_key(&pem).unwrap()[0], 4);
        assert!(core_public_key(&B64.encode([4_u8; 10])).is_err());
    }

    #[test]
    fn keys_load_from_pem_and_base64() {
        let signer = signer();
        let raw = signer.public_key().to_vec();
        assert_eq!(public_key(&B64.encode(&raw)).unwrap(), raw);
        let mut spki = vec![
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        spki.extend_from_slice(&raw);
        let pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            B64.encode(&spki)
        );
        assert_eq!(public_key(&pem).unwrap(), raw);
        assert_eq!(utc_day(0), "1970-01-01");
        assert_eq!(utc_day(1_794_560_000), "2026-11-13");
    }
}
