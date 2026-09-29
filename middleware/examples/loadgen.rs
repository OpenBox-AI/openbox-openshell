// A test tool: percentile and rate arithmetic is approximate by design.
#![allow(
    clippy::too_many_lines,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

//! Open-loop load generator for the verdict middleware (spec acceptance A9).
//!
//! Sends `EvaluateHttpRequest` calls at a fixed rate, the way `OpenShell`
//! supervisors would, with a signed extension token per call, and reports
//! latency percentiles and how many requests were denied because `OpenBox`
//! could not answer (`openbox_unavailable`).
//!
//! ```text
//! cargo run --release --example loadgen -- \
//!   --target https://127.0.0.1:50051 --ca ca.crt \
//!   --signing-key signing.pem --gateway-id openshell \
//!   --rate 200 --seconds 60 --body-bytes 1048576 --sandboxes 20
//! cargo run --release --example loadgen -- --stub-core 127.0.0.1:18086
//! ```
//!
//! `--stub-core` instead serves a Core stand-in that allows everything at
//! once, to measure the middleware on its own.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use openshell_core::proto::middleware::v1::supervisor_middleware_client::SupervisorMiddlewareClient;
use openshell_core::proto::{
    Decision, HttpHeader, HttpRequestEvaluation, HttpRequestTarget, RequestContext,
    SupervisorMiddlewarePhase,
};
use ring::signature::Ed25519KeyPair;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint};

fn arg(name: &str) -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    args.iter()
        .position(|value| value == name)
        .and_then(|index| args.get(index + 1).cloned())
}

fn number(name: &str, default: u64) -> u64 {
    arg(name)
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0))
}

struct Signer {
    key: Ed25519KeyPair,
    gateway_id: String,
    audience: String,
}

impl Signer {
    fn token(&self, sandbox_id: &str) -> String {
        let header = URL_SAFE_NO_PAD.encode(r#"{"typ":"openshell-ext+jwt","alg":"EdDSA"}"#);
        let claims = URL_SAFE_NO_PAD.encode(
            serde_json::json!({
                "iss": format!("openshell-gateway:{}", self.gateway_id),
                "aud": self.audience,
                "exp": now() + 300,
                "caller_kind": "supervisor",
                "sandbox_id": sandbox_id,
            })
            .to_string(),
        );
        let signed = format!("{header}.{claims}");
        let signature = self.key.sign(signed.as_bytes());
        format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature.as_ref()))
    }
}

fn read_pkcs8_pem(path: &str) -> Vec<u8> {
    let pem = std::fs::read_to_string(path).expect("read signing key");
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(body)
        .expect("signing key is PEM")
}

/// A Core stand-in: `WorkflowStarted` and `ActivityStarted` are allowed, and
/// no approval is ever pending.
async fn stub_core(address: &str) {
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .expect("bind stub");
    eprintln!("stub core listening on http://{address}");
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            continue;
        };
        tokio::spawn(async move {
            let mut buffer = Vec::with_capacity(8192);
            loop {
                let mut chunk = [0_u8; 8192];
                let Ok(read) = stream.read(&mut chunk).await else {
                    return;
                };
                if read == 0 {
                    return;
                }
                buffer.extend_from_slice(&chunk[..read]);
                // Serve every complete request on this keep-alive connection.
                while let Some(end) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buffer[..end]).to_ascii_lowercase();
                    let length: usize = head
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length:"))
                        .and_then(|value| value.trim().parse().ok())
                        .unwrap_or(0);
                    if buffer.len() < end + 4 + length {
                        break;
                    }
                    let response = if head.starts_with("post /api/v1/governance/approval") {
                        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_owned()
                    } else {
                        let body =
                            r#"{"verdict":"allow","action":"allow","governance_event_id":"stub"}"#;
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                            body.len()
                        )
                    };
                    if stream.write_all(response.as_bytes()).await.is_err() {
                        return;
                    }
                    buffer.drain(..end + 4 + length);
                }
            }
        });
    }
}

#[tokio::main]
async fn main() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    if let Some(address) = arg("--stub-core") {
        stub_core(&address).await;
        return;
    }
    let target = arg("--target").unwrap_or_else(|| "https://127.0.0.1:50051".to_owned());
    let ca = std::fs::read(arg("--ca").expect("--ca")).expect("read ca");
    let signer = Arc::new(Signer {
        key: Ed25519KeyPair::from_pkcs8_maybe_unchecked(&read_pkcs8_pem(
            &arg("--signing-key").expect("--signing-key"),
        ))
        .expect("Ed25519 PKCS#8 key"),
        gateway_id: arg("--gateway-id").unwrap_or_else(|| "openshell".to_owned()),
        audience: arg("--audience")
            .unwrap_or_else(|| "urn:openshell:extension:middleware:openbox".to_owned()),
    });
    let rate = number("--rate", 200);
    let seconds = number("--seconds", 60);
    let body = vec![b'x'; usize::try_from(number("--body-bytes", 1024 * 1024)).unwrap_or(0)];
    let sandboxes = number("--sandboxes", 20).max(1);
    let prefix = arg("--sandbox-prefix").unwrap_or_else(|| format!("load-{}", now()));

    let channel = Endpoint::from_shared(target)
        .expect("target")
        .tls_config(ClientTlsConfig::new().ca_certificate(Certificate::from_pem(ca)))
        .expect("tls")
        .connect()
        .await
        .expect("connect to middleware");
    let client = SupervisorMiddlewareClient::new(channel)
        .max_encoding_message_size(5 * 1024 * 1024)
        .max_decoding_message_size(5 * 1024 * 1024);

    let latencies = Arc::new(std::sync::Mutex::new(Vec::<Duration>::new()));
    let (allowed, denied, unavailable, errors) = (
        Arc::new(AtomicU64::new(0)),
        Arc::new(AtomicU64::new(0)),
        Arc::new(AtomicU64::new(0)),
        Arc::new(AtomicU64::new(0)),
    );
    let body = Arc::new(body);
    let mut ticker = tokio::time::interval(Duration::from_secs_f64(1.0 / rate as f64));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Burst);
    let total = rate * seconds;
    let started = Instant::now();
    let mut tasks = Vec::with_capacity(usize::try_from(total).unwrap_or(0));
    for index in 0..total {
        ticker.tick().await;
        let sandbox_id = format!("{prefix}-{}", index % sandboxes);
        let mut request = tonic::Request::new(HttpRequestEvaluation {
            phase: SupervisorMiddlewarePhase::PreCredentials as i32,
            context: Some(RequestContext {
                request_id: format!("{prefix}-req-{index}"),
                sandbox_id: sandbox_id.clone(),
                sandbox: sandbox_id.clone(),
                ..RequestContext::default()
            }),
            target: Some(HttpRequestTarget {
                scheme: "https".to_owned(),
                host: "load.example".to_owned(),
                port: 443,
                method: "POST".to_owned(),
                path: format!("/upload/{index}"),
                query: String::new(),
            }),
            headers: vec![HttpHeader {
                name: "content-type".to_owned(),
                value: "application/octet-stream".to_owned(),
            }],
            body: body.as_ref().clone(),
            middleware_name: "openbox".to_owned(),
            ..HttpRequestEvaluation::default()
        });
        request.metadata_mut().insert(
            "authorization",
            format!("Bearer {}", signer.token(&sandbox_id))
                .parse()
                .unwrap(),
        );
        let mut client = client.clone();
        let (latencies, allowed, denied, unavailable, errors) = (
            Arc::clone(&latencies),
            Arc::clone(&allowed),
            Arc::clone(&denied),
            Arc::clone(&unavailable),
            Arc::clone(&errors),
        );
        tasks.push(tokio::spawn(async move {
            let sent = Instant::now();
            match client.evaluate_http_request(request).await {
                Ok(response) => {
                    let result = response.into_inner();
                    if result.decision == Decision::Allow as i32 {
                        allowed.fetch_add(1, Ordering::Relaxed);
                    } else if result.reason_code == "openbox_unavailable" {
                        unavailable.fetch_add(1, Ordering::Relaxed);
                    } else {
                        denied.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Err(_) => {
                    errors.fetch_add(1, Ordering::Relaxed);
                }
            }
            latencies.lock().unwrap().push(sent.elapsed());
        }));
    }
    for task in tasks {
        let _ = task.await;
    }
    let wall = started.elapsed();
    let mut latencies = latencies.lock().unwrap().clone();
    latencies.sort();
    let percentile = |p: f64| {
        let index = ((latencies.len() as f64 * p).ceil() as usize).saturating_sub(1);
        latencies.get(index).map_or(0, Duration::as_millis)
    };
    println!(
        "sent={total} in {:.1}s ({:.0} rps) body={}B sandboxes={sandboxes}",
        wall.as_secs_f64(),
        total as f64 / wall.as_secs_f64(),
        body.len()
    );
    println!(
        "allowed={} denied={} unavailable(fail-closed)={} rpc_errors={}",
        allowed.load(Ordering::Relaxed),
        denied.load(Ordering::Relaxed),
        unavailable.load(Ordering::Relaxed),
        errors.load(Ordering::Relaxed)
    );
    println!(
        "latency ms p50={} p95={} p99={} max={}",
        percentile(0.50),
        percentile(0.95),
        percentile(0.99),
        latencies.last().map_or(0, Duration::as_millis)
    );
}
