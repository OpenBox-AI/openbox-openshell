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
    /// Answers per fast-path tier, and their latency.
    tiers: Mutex<BTreeMap<crate::fastpath::Tier, u64>>,
    local_rule_latency: Histogram,
    recent_verdict_latency: Histogram,
    core_tier_latency: Histogram,
    pending_latency: Histogram,
    /// Shadow-mode local rules: (agreed with Core) → count.
    shadow: Mutex<BTreeMap<bool, u64>>,
    /// Fast-path allows Core later disagreed with.
    fast_disagreements: AtomicU64,
    /// From a HALT verdict to the gateway confirming the sandbox stopped.
    halt_stop_latency: Histogram,
    /// (confirmed) → count.
    halt_stops: Mutex<BTreeMap<bool, u64>>,
    /// Evidence records: (written) → count.
    evidence: Mutex<BTreeMap<bool, u64>>,
    /// Requests seen again under a request id already answered.
    duplicates: AtomicU64,
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

    pub fn record_tier(&self, tier: crate::fastpath::Tier, elapsed: Duration) {
        use crate::fastpath::Tier;
        *self
            .tiers
            .lock()
            .expect("metrics lock")
            .entry(tier)
            .or_default() += 1;
        match tier {
            Tier::LocalRule | Tier::Grant => &self.local_rule_latency,
            Tier::RecentVerdict => &self.recent_verdict_latency,
            Tier::Core => &self.core_tier_latency,
            Tier::Pending => &self.pending_latency,
        }
        .observe(elapsed);
    }

    pub fn record_shadow(&self, agreed: bool) {
        *self
            .shadow
            .lock()
            .expect("metrics lock")
            .entry(agreed)
            .or_default() += 1;
    }

    pub fn record_halt_stop(&self, confirmed: bool, elapsed: Duration) {
        *self
            .halt_stops
            .lock()
            .expect("metrics lock")
            .entry(confirmed)
            .or_default() += 1;
        if confirmed {
            self.halt_stop_latency.observe(elapsed);
        }
    }

    pub fn record_duplicate(&self) {
        self.duplicates.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_evidence(&self, written: bool) {
        *self
            .evidence
            .lock()
            .expect("metrics lock")
            .entry(written)
            .or_default() += 1;
    }

    pub fn record_fast_disagreement(&self) {
        self.fast_disagreements.fetch_add(1, Ordering::Relaxed);
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
        self.render_tiers(&mut out);
        out
    }

    fn render_tiers(&self, out: &mut String) {
        use crate::fastpath::Tier;
        out.push_str("# HELP openbox_mw_tier_total Verdicts by the tier that gave them.\n");
        out.push_str("# TYPE openbox_mw_tier_total counter\n");
        for (tier, count) in self.tiers.lock().expect("metrics lock").iter() {
            let _ = writeln!(
                out,
                "openbox_mw_tier_total{{tier=\"{}\"}} {count}",
                tier.label()
            );
        }
        out.push_str("# HELP openbox_mw_tier_duration_seconds Time to answer, by tier.\n");
        out.push_str("# TYPE openbox_mw_tier_duration_seconds histogram\n");
        for (tier, histogram) in [
            (Tier::LocalRule, &self.local_rule_latency),
            (Tier::RecentVerdict, &self.recent_verdict_latency),
            (Tier::Core, &self.core_tier_latency),
            (Tier::Pending, &self.pending_latency),
        ] {
            histogram.render(
                out,
                "openbox_mw_tier_duration_seconds",
                &format!("tier=\"{}\",", tier.label()),
            );
        }
        out.push_str(
            "# HELP openbox_mw_rule_shadow_total Shadow-mode local rules against Core's verdict.\n",
        );
        out.push_str("# TYPE openbox_mw_rule_shadow_total counter\n");
        for (agreed, count) in self.shadow.lock().expect("metrics lock").iter() {
            let agreement = if *agreed { "agree" } else { "disagree" };
            let _ = writeln!(
                out,
                "openbox_mw_rule_shadow_total{{agreement=\"{agreement}\"}} {count}"
            );
        }
        out.push_str("# HELP openbox_mw_halt_stops_total Sandboxes stopped after a HALT, by whether the gateway confirmed it.\n");
        out.push_str("# TYPE openbox_mw_halt_stops_total counter\n");
        for (confirmed, count) in self.halt_stops.lock().expect("metrics lock").iter() {
            let outcome = if *confirmed { "confirmed" } else { "failed" };
            let _ = writeln!(
                out,
                "openbox_mw_halt_stops_total{{outcome=\"{outcome}\"}} {count}"
            );
        }
        out.push_str("# HELP openbox_mw_halt_stop_seconds From a HALT verdict to the sandbox confirmed stopped.\n");
        out.push_str("# TYPE openbox_mw_halt_stop_seconds histogram\n");
        self.halt_stop_latency
            .render(out, "openbox_mw_halt_stop_seconds", "");
        out.push_str("# HELP openbox_mw_duplicate_requests_total Requests answered again under the same request id.\n");
        out.push_str("# TYPE openbox_mw_duplicate_requests_total counter\n");
        let _ = writeln!(
            out,
            "openbox_mw_duplicate_requests_total {}",
            self.duplicates.load(Ordering::Relaxed)
        );
        out.push_str("# HELP openbox_mw_evidence_records_total Verdict records, by whether they were written. Alert on failed: the evidence has a gap.\n");
        out.push_str("# TYPE openbox_mw_evidence_records_total counter\n");
        for (written, count) in self.evidence.lock().expect("metrics lock").iter() {
            let outcome = if *written { "written" } else { "failed" };
            let _ = writeln!(
                out,
                "openbox_mw_evidence_records_total{{outcome=\"{outcome}\"}} {count}"
            );
        }
        out.push_str("# HELP openbox_mw_fast_path_disagreements_total Fast-path allows Core later refused.\n");
        out.push_str("# TYPE openbox_mw_fast_path_disagreements_total counter\n");
        let _ = writeln!(
            out,
            "openbox_mw_fast_path_disagreements_total {}",
            self.fast_disagreements.load(Ordering::Relaxed)
        );
    }
}

/// Serves `/healthz`, `/readyz` and `/metrics` until the process exits.
/// Clears a halt for a sandbox; returns what it did.
pub type Resume = std::sync::Arc<
    dyn Fn(String) -> std::pin::Pin<Box<dyn Future<Output = Result<String, String>> + Send>>
        + Send
        + Sync,
>;

/// The admin actions beyond the probes: off unless a token is configured.
#[derive(Clone)]
pub struct AdminActions {
    pub token: String,
    pub resume: Resume,
}

/// `POST /admin/resume?sandbox_id=<id>` with `Authorization: Bearer <token>`.
async fn admin_action(request: &str, actions: Option<&AdminActions>) -> (&'static str, String) {
    let Some(actions) = actions else {
        return ("404 Not Found", "not found\n".to_owned());
    };
    let mut lines = request.lines();
    let mut first = lines.next().unwrap_or("").split_whitespace();
    let (method, target) = (first.next().unwrap_or(""), first.next().unwrap_or(""));
    let authorized = lines
        .take_while(|line| !line.is_empty())
        .filter_map(|line| line.split_once(':'))
        .any(|(name, value)| {
            name.trim().eq_ignore_ascii_case("authorization")
                && constant_time_eq(
                    value.trim().as_bytes(),
                    format!("Bearer {}", actions.token).as_bytes(),
                )
        });
    if method != "POST" {
        return ("405 Method Not Allowed", "use POST\n".to_owned());
    }
    if !authorized {
        return (
            "401 Unauthorized",
            "a valid bearer token is required\n".to_owned(),
        );
    }
    let sandbox_id = target
        .split_once('?')
        .map_or("", |(_, query)| query)
        .split('&')
        .find_map(|pair| pair.strip_prefix("sandbox_id="))
        .unwrap_or("");
    if sandbox_id.is_empty()
        || sandbox_id.len() > 128
        || !sandbox_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return ("400 Bad Request", "sandbox_id is required\n".to_owned());
    }
    match (actions.resume)(sandbox_id.to_owned()).await {
        Ok(done) => ("200 OK", format!("{done}\n")),
        Err(error) => ("502 Bad Gateway", format!("{error}\n")),
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0, |diff, (a, b)| diff | (a ^ b))
            == 0
}

pub async fn serve_admin(
    listener: TcpListener,
    metrics: std::sync::Arc<Metrics>,
    actions: Option<AdminActions>,
) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            continue;
        };
        let metrics = std::sync::Arc::clone(&metrics);
        let actions = actions.clone();
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
                admin if admin.starts_with("/admin/resume") => {
                    admin_action(&request, actions.as_ref()).await
                }
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
    async fn resume_needs_post_and_the_token() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let resumed = std::sync::Arc::new(Mutex::new(Vec::new()));
        let seen = std::sync::Arc::clone(&resumed);
        let resume: Resume = std::sync::Arc::new(move |id: String| {
            let seen = std::sync::Arc::clone(&seen);
            Box::pin(async move {
                seen.lock().unwrap().push(id.clone());
                Ok(format!("resumed {id}"))
            })
        });
        let actions = AdminActions {
            token: "t".repeat(32),
            resume,
        };
        tokio::spawn(serve_admin(
            listener,
            std::sync::Arc::new(Metrics::default()),
            Some(actions),
        ));
        let send = |request: String| async move {
            let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
            stream.write_all(request.as_bytes()).await.unwrap();
            let mut reply = String::new();
            stream.read_to_string(&mut reply).await.unwrap();
            reply.lines().next().unwrap_or("").to_owned()
        };
        let good = format!("Bearer {}", "t".repeat(32));
        assert!(
            send(format!(
                "GET /admin/resume?sandbox_id=s1 HTTP/1.1\r\nAuthorization: {good}\r\n\r\n"
            ))
            .await
            .contains("405")
        );
        assert!(
            send(
                "POST /admin/resume?sandbox_id=s1 HTTP/1.1\r\nAuthorization: Bearer nope\r\n\r\n"
                    .to_owned()
            )
            .await
            .contains("401")
        );
        assert!(
            send(format!(
                "POST /admin/resume HTTP/1.1\r\nAuthorization: {good}\r\n\r\n"
            ))
            .await
            .contains("400")
        );
        assert!(
            send(format!(
                "POST /admin/resume?sandbox_id=s1 HTTP/1.1\r\nAuthorization: {good}\r\n\r\n"
            ))
            .await
            .contains("200")
        );
        assert_eq!(*resumed.lock().unwrap(), ["s1"]);
    }

    #[tokio::test]
    async fn admin_listener_serves_probes_and_metrics() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let metrics = std::sync::Arc::new(Metrics::default());
        tokio::spawn(serve_admin(listener, std::sync::Arc::clone(&metrics), None));
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
