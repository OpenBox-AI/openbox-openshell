//! Checks and seals the door guard's signed verdict records.
//!
//! ```text
//! openbox-evidence verify --key <public key> [--partial] <records.jsonl>...
//! openbox-evidence seal --signing-key <private key> --chain <chain_uid> <records.jsonl>...
//! openbox-evidence check --key <public key> --certificate <cert.json> <records.jsonl>...
//! ```
//!
//! `verify` checks every record's fingerprint and signature and each chain's
//! links and sequence, across any number of files in any order (daily files
//! included), and exits 1 on any problem: an edited, missing, duplicated or
//! reordered record. `--partial` accepts a chain that starts after record 1.
//! `seal` writes a certificate for one chain: the Merkle root of its records,
//! signed. `check` verifies a certificate against the records it covers.
//!
//! Keys: a PEM (`openssl genpkey -algorithm ed25519`, `openssl pkey -pubout`)
//! or a raw base64 public key. `--key` may be given more than once.

use std::process::ExitCode;

use openbox_verdict_middleware::evidence::{self, Signer};

fn usage() -> ExitCode {
    eprintln!(
        "usage:\n  openbox-evidence verify --key <public key> [--partial] <records.jsonl>...\n  openbox-evidence seal --signing-key <private key> --chain <chain_uid> <records.jsonl>...\n  openbox-evidence check --key <public key> --certificate <cert.json> <records.jsonl>..."
    );
    ExitCode::from(2)
}

fn read(path: &str) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|error| format!("{path}: {error}"))
}

fn run(args: &[String]) -> Result<bool, String> {
    let command = args.first().ok_or("no command")?;
    let mut keys = Vec::new();
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
            match evidence::check_certificate(&certificate, &lines, &keys) {
                Ok(()) => {
                    println!(
                        "ok  {} records {}..{} match the certificate",
                        certificate["chain_uid"].as_str().unwrap_or(""),
                        certificate["first_sequence"],
                        certificate["last_sequence"]
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
    match run(&args) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(error) => {
            eprintln!("openbox-evidence: {error}");
            usage()
        }
    }
}
