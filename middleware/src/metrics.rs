//! RED metrics in Prometheus text format, and the admin HTTP listener that
//! serves them with liveness and readiness probes.
//!
//! Kept dependency-free: a few atomics and a minimal HTTP/1.1 responder. The
//! admin port serves only these three paths and never request content.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

/// Upper bounds in seconds, up to the 30 s middleware timeout: a full Core
/// verdict (policy, guardrails, behaviour rules) can take tens of seconds.
const BUCKETS: [f64; 15] = [
    0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 10.0, 15.0, 20.0, 25.0, 30.0,
];

#[derive(Default)]
struct Histogram {
    counts: [AtomicU64; BUCKETS.len()],
    total: AtomicU64,
    sum_micros: AtomicU64,
}

impl Histogram {
    fn observe(&self, elapsed: Duration) {
        let secs = elapsed.as_secs_f64();
        for (bound, count) in BUCKETS.iter().zip(&self.counts) {
            if secs <= *bound {
                count.fetch_add(1, Ordering::Relaxed);
            }
        }
        self.total.fetch_add(1, Ordering::Relaxed);
        self.sum_micros.fetch_add(
            u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }

    fn render(&self, out: &mut String, name: &str, labels: &str) {
        for (bound, count) in BUCKETS.iter().zip(&self.counts) {
            let _ = writeln!(
                out,
                "{name}_bucket{{{labels}le=\"{bound}\"}} {}",
                count.load(Ordering::Relaxed)
            );
        }
        let total = self.total.load(Ordering::Relaxed);
        let _ = writeln!(out, "{name}_bucket{{{labels}le=\"+Inf\"}} {total}");
        #[allow(clippy::cast_precision_loss)]
        let sum = self.sum_micros.load(Ordering::Relaxed) as f64 / 1e6;
        let _ = writeln!(out, "{name}_sum{{{}}} {sum}", labels.trim_end_matches(','));
        let _ = writeln!(
            out,
            "{name}_count{{{}}} {total}",
            labels.trim_end_matches(',')
        );
    }
}

/// Which Core call a latency or outcome belongs to.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CoreCall {
    Session,
    Approval,
    Evaluate,
    Signal,
}

impl CoreCall {
    const fn label(self) -> &'static str {
        match self {
            Self::Session => "session",
            Self::Approval => "approval",
            Self::Evaluate => "evaluate",
            Self::Signal => "signal",
        }
    }
}

#[derive(Default)]
pub struct Metrics {
    ready: AtomicBool,
    /// (decision, `reason_code`) → count.
    results: Mutex<BTreeMap<(&'static str, String), u64>>,
    /// (call, ok) → count.
    core_outcomes: Mutex<BTreeMap<(CoreCall, bool), u64>>,
    evaluation_latency: Histogram,
    session_latency: Histogram,
    approval_latency: Histogram,
    evaluate_latency: Histogram,
    signal_latency: Histogram,
}

impl Metrics {
    pub fn set_ready(&self) {
        self.ready.store(true, Ordering::Relaxed);
    }

    pub fn record_result(&self, allowed: bool, reason_code: &str, elapsed: Duration) {
        let decision = if allowed { "allow" } else { "deny" };
        *self
            .results
            .lock()
            .expect("metrics lock")
            .entry((decision, reason_code.to_owned()))
            .or_default() += 1;
        self.evaluation_latency.observe(elapsed);
    }

    pub fn record_core(&self, call: CoreCall, ok: bool, elapsed: Duration) {
        *self
            .core_outcomes
            .lock()
            .expect("metrics lock")
            .entry((call, ok))
            .or_default() += 1;
        match call {
            CoreCall::Session => &self.session_latency,
            CoreCall::Approval => &self.approval_latency,
            CoreCall::Evaluate => &self.evaluate_latency,
            CoreCall::Signal => &self.signal_latency,
        }
        .observe(elapsed);
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str("# HELP openbox_mw_evaluations_total Evaluated requests by result.\n");
        out.push_str("# TYPE openbox_mw_evaluations_total counter\n");
        for ((decision, reason), count) in self.results.lock().expect("metrics lock").iter() {
            let _ = writeln!(
                out,
                "openbox_mw_evaluations_total{{decision=\"{decision}\",reason_code=\"{reason}\"}} {count}"
            );
        }
        out.push_str("# HELP openbox_mw_core_requests_total Calls to OpenBox Core.\n");
        out.push_str("# TYPE openbox_mw_core_requests_total counter\n");
        for ((call, ok), count) in self.core_outcomes.lock().expect("metrics lock").iter() {
            let outcome = if *ok { "ok" } else { "error" };
            let _ = writeln!(
                out,
                "openbox_mw_core_requests_total{{call=\"{}\",outcome=\"{outcome}\"}} {count}",
                call.label()
            );
        }
        out.push_str(
            "# HELP openbox_mw_evaluation_duration_seconds Time to answer one evaluation.\n",
        );
        out.push_str("# TYPE openbox_mw_evaluation_duration_seconds histogram\n");
        self.evaluation_latency
            .render(&mut out, "openbox_mw_evaluation_duration_seconds", "");
        out.push_str("# HELP openbox_mw_core_duration_seconds Latency of Core calls.\n");
        out.push_str("# TYPE openbox_mw_core_duration_seconds histogram\n");
        for (call, histogram) in [
            (CoreCall::Session, &self.session_latency),
            (CoreCall::Approval, &self.approval_latency),
            (CoreCall::Evaluate, &self.evaluate_latency),
            (CoreCall::Signal, &self.signal_latency),
        ] {
            histogram.render(
                &mut out,
                "openbox_mw_core_duration_seconds",
                &format!("call=\"{}\",", call.label()),
            );
        }
        out
    }
}

/// Serves `/healthz`, `/readyz` and `/metrics` until the process exits.
pub async fn serve_admin(listener: TcpListener, metrics: std::sync::Arc<Metrics>) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            continue;
        };
        let metrics = std::sync::Arc::clone(&metrics);
        tokio::spawn(async move {
            let mut buffer = [0_u8; 1024];
            let Ok(Ok(read)) =
                tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buffer)).await
            else {
                return;
            };
            let request = String::from_utf8_lossy(&buffer[..read]);
            let path = request
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .unwrap_or("");
            let (status, body) = match path {
                "/healthz" => ("200 OK", "ok\n".to_owned()),
                "/readyz" if metrics.ready.load(Ordering::Relaxed) => {
                    ("200 OK", "ready\n".to_owned())
                }
                "/readyz" => ("503 Service Unavailable", "starting\n".to_owned()),
                "/metrics" => ("200 OK", metrics.render()),
                _ => ("404 Not Found", "not found\n".to_owned()),
            };
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_counters_and_cumulative_buckets() {
        let metrics = Metrics::default();
        metrics.record_result(true, "", Duration::from_millis(40));
        metrics.record_result(false, "openbox_blocked", Duration::from_millis(900));
        metrics.record_core(CoreCall::Evaluate, true, Duration::from_millis(300));
        metrics.record_core(CoreCall::Approval, false, Duration::from_millis(20));
        let text = metrics.render();
        assert!(text.contains(
            "openbox_mw_evaluations_total{decision=\"deny\",reason_code=\"openbox_blocked\"} 1"
        ));
        assert!(
            text.contains("openbox_mw_core_requests_total{call=\"approval\",outcome=\"error\"} 1")
        );
        assert!(text.contains("openbox_mw_evaluation_duration_seconds_bucket{le=\"0.05\"} 1"));
        assert!(text.contains("openbox_mw_evaluation_duration_seconds_bucket{le=\"1\"} 2"));
        assert!(text.contains("openbox_mw_evaluation_duration_seconds_count{} 2"));
        assert!(
            text.contains(
                "openbox_mw_core_duration_seconds_bucket{call=\"evaluate\",le=\"0.25\"} 0"
            )
        );
        assert!(
            text.contains(
                "openbox_mw_core_duration_seconds_bucket{call=\"evaluate\",le=\"0.5\"} 1"
            )
        );
    }

    #[tokio::test]
    async fn admin_listener_serves_probes_and_metrics() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let metrics = std::sync::Arc::new(Metrics::default());
        tokio::spawn(serve_admin(listener, std::sync::Arc::clone(&metrics)));
        let get = |path: &'static str| async move {
            let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
            stream
                .write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
                .await
                .unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).await.unwrap();
            response
        };
        assert!(get("/healthz").await.starts_with("HTTP/1.1 200"));
        assert!(get("/readyz").await.starts_with("HTTP/1.1 503"));
        metrics.set_ready();
        assert!(get("/readyz").await.starts_with("HTTP/1.1 200"));
        assert!(
            get("/metrics")
                .await
                .contains("openbox_mw_evaluations_total")
        );
        assert!(get("/other").await.starts_with("HTTP/1.1 404"));
    }
}
