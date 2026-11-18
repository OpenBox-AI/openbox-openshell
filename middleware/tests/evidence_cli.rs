//! The `openbox-evidence` command line, end to end: records written by the
//! library with an openssl-generated key, verified, tampered with, sealed.

use std::process::Command;
use std::sync::Mutex;

use openbox_verdict_middleware::evidence::{Evidence, Signer, Sink, Verdict};

fn openssl(args: &[&str]) {
    let status = Command::new("openssl")
        .args(args)
        .status()
        .expect("openssl");
    assert!(status.success(), "openssl {args:?}");
}

#[test]
fn verify_seal_and_check_from_the_command_line() {
    let dir = std::env::temp_dir().join(format!("obx-evidence-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = |name: &str| dir.join(name).to_string_lossy().into_owned();
    openssl(&["genpkey", "-algorithm", "ed25519", "-out", &path("key.pem")]);
    openssl(&[
        "pkey",
        "-in",
        &path("key.pem"),
        "-pubout",
        "-out",
        &path("key.pub"),
    ]);

    let signer = Signer::from_pem(&std::fs::read_to_string(path("key.pem")).unwrap()).unwrap();
    let evidence = Evidence::new(signer, Sink::Memory(Mutex::new(Vec::new())), "pod-a");
    for i in 0..4 {
        let request = format!("req-{i}");
        evidence
            .record(&Verdict {
                sandbox_id: "sbx-1",
                request_id: &request,
                method: "POST",
                host: "api.example.com",
                url: "https://api.example.com/pay",
                allowed: i != 2,
                reason_code: if i == 2 { "openbox_blocked" } else { "" },
                governance_event_id: None,
                fast_path: false,
            })
            .unwrap();
    }
    let lines = evidence.written();
    std::fs::write(path("day1.jsonl"), lines[..2].join("\n") + "\n").unwrap();
    std::fs::write(path("day2.jsonl"), lines[2..].join("\n") + "\n").unwrap();

    let cli = env!("CARGO_BIN_EXE_openbox-evidence");
    let run = |args: &[&str]| {
        let output = Command::new(cli).args(args).output().unwrap();
        (
            output.status.code(),
            String::from_utf8_lossy(&output.stdout).into_owned(),
        )
    };
    // Both days, given in either order.
    let (code, out) = run(&[
        "verify",
        "--key",
        &path("key.pub"),
        &path("day2.jsonl"),
        &path("day1.jsonl"),
    ]);
    assert_eq!(code, Some(0), "{out}");
    assert!(out.contains("ok  sbx-1:pod-a  records 1..4"), "{out}");
    // A missing day is a gap.
    let (code, out) = run(&["verify", "--key", &path("key.pub"), &path("day2.jsonl")]);
    assert_eq!(code, Some(1), "{out}");
    assert!(out.contains("records 1 to 2 are missing"), "{out}");

    let (code, certificate) = run(&[
        "seal",
        "--signing-key",
        &path("key.pem"),
        "--chain",
        "sbx-1:pod-a",
        &path("day1.jsonl"),
        &path("day2.jsonl"),
    ]);
    assert_eq!(code, Some(0));
    std::fs::write(path("cert.json"), certificate).unwrap();
    let (public, cert) = (path("key.pub"), path("cert.json"));
    let check = |files: &[String]| {
        let mut args = vec![
            "check",
            "--key",
            public.as_str(),
            "--certificate",
            cert.as_str(),
        ];
        args.extend(files.iter().map(String::as_str));
        run(&args)
    };
    assert_eq!(check(&[path("day1.jsonl"), path("day2.jsonl")]).0, Some(0));

    // The blocked request edited to look allowed: verify and check both fail.
    let edited = std::fs::read_to_string(path("day2.jsonl"))
        .unwrap()
        .replacen("\"deny\"", "\"allow\"", 1);
    std::fs::write(path("day2.jsonl"), edited).unwrap();
    let (code, out) = run(&[
        "verify",
        "--key",
        &path("key.pub"),
        &path("day1.jsonl"),
        &path("day2.jsonl"),
    ]);
    assert_eq!(code, Some(1));
    assert!(
        out.contains("record 3: changed after it was written"),
        "{out}"
    );
    assert_eq!(check(&[path("day1.jsonl"), path("day2.jsonl")]).0, Some(1));
    std::fs::remove_dir_all(&dir).unwrap();
}
