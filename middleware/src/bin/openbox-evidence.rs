//! Checks and seals the door guard's signed verdict records.
//!
//! ```text
//! openbox-evidence verify --key <public key> [--partial] <records.jsonl>...
//! openbox-evidence seal --signing-key <private key> --chain <chain_uid> <records.jsonl>...
//! openbox-evidence check --key <public key> --certificate <cert.json> <records.jsonl>...
//! openbox-evidence check --core-key <org public key> --certificate <cert.json> <records.jsonl>...
//! openbox-evidence collect-ocsf [--dir <dir>]... [--kubelet-pods <dir>]... [--state <file>] [--interval-secs <n>] [--once]
//! openbox-evidence join --ocsf <openshell-ocsf.log>... [--window-ms <n>] <records.jsonl>...
//! ```
//!
//! `verify` checks every record's fingerprint and signature and each chain's
//! links and sequence, across any number of files in any order (daily files
//! included), and exits 1 on any problem: an edited, missing, duplicated or
//! reordered record. `--partial` accepts a chain that starts after record 1.
//! `seal` writes a certificate for one chain: the Merkle root of its records,
//! signed. `check` verifies a certificate against the records it covers:
//! one `seal` wrote (`--key`), or a Proof Certificate Core issued
//! (`--core-key`, the organisation's attestation key as an SPKI PEM or base64
//! DER; pin the key you trust, not the one the certificate carries). A
//! certificate line from the evidence sink (`{"openbox_certificate": ...}`)
//! can be passed as the certificate file.
//!
//! `collect-ocsf` follows `OpenShell`'s OCSF JSON Lines files and writes each
//! new line to stdout, unchanged, keeping its place in `--state` across
//! restarts (see `ocsf.rs`). `join` pairs each verdict record with the
//! `OpenShell` OCSF event for the same sandbox and host nearest in time, one
//! JSON line per record, and prints the totals to stderr.
//!
//! Keys: a PEM (`openssl genpkey -algorithm ed25519`, `openssl pkey -pubout`)
//! or a raw base64 public key. `--key` may be given more than once.

use std::process::ExitCode;

use std::path::PathBuf;
use std::time::Duration;

use openbox_verdict_middleware::evidence::{self, Signer};
use openbox_verdict_middleware::ocsf::{self, Collector, Source};

fn usage() -> ExitCode {
    eprintln!(
        "usage:\n  openbox-evidence verify --key <public key> [--partial] <records.jsonl>...\n  openbox-evidence seal --signing-key <private key> --chain <chain_uid> <records.jsonl>...\n  openbox-evidence check --key <public key> --certificate <cert.json> <records.jsonl>...\n  openbox-evidence check --core-key <org public key> --certificate <cert.json> <records.jsonl>...\n  openbox-evidence collect-ocsf [--dir <dir>]... [--kubelet-pods <dir>]... [--state <file>] [--interval-secs <n>] [--once]\n  openbox-evidence join --ocsf <openshell-ocsf.log>... [--window-ms <n>] <records.jsonl>..."
    );
    ExitCode::from(2)
}

fn read(path: &str) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|error| format!("{path}: {error}"))
}

/// Follows OCSF files until stopped (or once, with `--once`).
fn collect_ocsf(args: &[String]) -> Result<bool, String> {
    let (mut sources, mut state, mut every, mut once) = (Vec::new(), None, 2, false);
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        let mut value = || {
            rest.next()
                .cloned()
                .ok_or_else(|| format!("{arg} needs a value"))
        };
        match arg.as_str() {
            "--dir" => sources.push(Source::Dir(PathBuf::from(value()?))),
            "--kubelet-pods" => sources.push(Source::KubeletPods(PathBuf::from(value()?))),
            "--state" => state = Some(PathBuf::from(value()?)),
            "--interval-secs" => {
                every = value()?
                    .parse::<u64>()
                    .map_err(|_| "--interval-secs must be a number")?
                    .max(1);
            }
            "--once" => once = true,
            other => return Err(format!("collect-ocsf: unknown argument {other}")),
        }
    }
    if sources.is_empty() {
        return Err("collect-ocsf needs --dir or --kubelet-pods".to_owned());
    }
    let mut collector = Collector::new(sources, state);
    let stdout = std::io::stdout();
    loop {
        collector
            .poll(&mut stdout.lock())
            .map_err(|error| format!("collect-ocsf: {error}"))?;
        if once {
            return Ok(true);
        }
        std::thread::sleep(Duration::from_secs(every));
    }
}

fn json_lines(text: &str) -> Vec<serde_json::Value> {
    text.lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|value| value.get(evidence::CERTIFICATE_KEY).is_none())
        .collect()
}

fn join(args: &[String]) -> Result<bool, String> {
    let (mut events, mut records, mut window) = (Vec::new(), Vec::new(), 2_000);
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        let mut value = || {
            rest.next()
                .cloned()
                .ok_or_else(|| format!("{arg} needs a value"))
        };
        match arg.as_str() {
            "--ocsf" => events.extend(json_lines(&read(&value()?)?)),
            "--window-ms" => {
                window = value()?
                    .parse::<i64>()
                    .map_err(|_| "--window-ms must be a number")?;
            }
            file => records.extend(json_lines(&read(file)?)),
        }
    }
    if events.is_empty() {
        return Err("join needs --ocsf with at least one event".to_owned());
    }
    let joined = ocsf::join(&records, &events, window);
    for row in &joined {
        println!(
            "{}",
            serde_json::to_string(row).map_err(|error| error.to_string())?
        );
    }
    eprintln!("{}", ocsf::join_summary(&joined));
    Ok(true)
}

fn run(args: &[String]) -> Result<bool, String> {
    let command = args.first().ok_or("no command")?;
    let mut keys = Vec::new();
    let mut core_keys = Vec::new();
    let (mut partial, mut signing, mut chain, mut certificate) = (false, None, None, None);
    let mut files = Vec::new();
    let mut rest = args[1..].iter();
    while let Some(arg) = rest.next() {
        let mut value = || {
            rest.next()
                .cloned()
                .ok_or_else(|| format!("{arg} needs a value"))
        };
        match arg.as_str() {
            "--key" => keys.push(evidence::public_key(&read(&value()?)?)?),
            "--core-key" => core_keys.push(evidence::core_public_key(&read(&value()?)?)?),
            "--partial" => partial = true,
            "--signing-key" => signing = Some(Signer::from_pem(&read(&value()?)?)?),
            "--chain" => chain = Some(value()?),
            "--certificate" => certificate = Some(value()?),
            file => files.push(file.to_owned()),
        }
    }
    let mut lines = Vec::new();
    for file in &files {
        lines.extend(read(file)?.lines().map(str::to_owned));
    }
    match command.as_str() {
        "verify" => {
            if keys.is_empty() {
                return Err("verify needs --key".to_owned());
            }
            let report = evidence::verify(&lines, &keys, partial);
            println!(
                "{} records in {} chains",
                report.records,
                report.chains.len()
            );
            for (chain, result) in &report.chains {
                let status = if result.problems.is_empty() {
                    "ok"
                } else {
                    "FAILED"
                };
                println!(
                    "{status}  {chain}  records {}..{}",
                    result.first, result.last
                );
                for problem in &result.problems {
                    println!("      {problem}");
                }
            }
            Ok(report.ok())
        }
        "seal" => {
            let signer = signing.ok_or("seal needs --signing-key")?;
            let chain = chain.ok_or("seal needs --chain")?;
            let certificate = evidence::seal(&lines, &chain, &signer)?;
            println!("{certificate}");
            Ok(true)
        }
        "check" => {
            let path = certificate.ok_or("check needs --certificate")?;
            let certificate: serde_json::Value =
                serde_json::from_str(&read(&path)?).map_err(|error| format!("{path}: {error}"))?;
            let (checked, body) = if core_keys.is_empty() {
                (
                    evidence::check_certificate(&certificate, &lines, &keys),
                    &certificate,
                )
            } else {
                let issued = certificate
                    .get(evidence::CERTIFICATE_KEY)
                    .unwrap_or(&certificate);
                (
                    evidence::check_core_certificate(&certificate, &lines, &core_keys),
                    issued.get("certificate").unwrap_or(issued),
                )
            };
            match checked {
                Ok(()) => {
                    println!(
                        "ok  {} records {}..{} match the certificate",
                        body["chain_uid"].as_str().unwrap_or(""),
                        body["first_sequence"],
                        body["last_sequence"]
                    );
                    Ok(true)
                }
                Err(error) => {
                    println!("FAILED  {error}");
                    Ok(false)
                }
            }
        }
        _ => Err(format!("unknown command {command}")),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        return usage();
    }
    let outcome = match args[0].as_str() {
        "collect-ocsf" => collect_ocsf(&args[1..]),
        "join" => join(&args[1..]),
        _ => run(&args),
    };
    match outcome {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(error) => {
            eprintln!("openbox-evidence: {error}");
            usage()
        }
    }
}
