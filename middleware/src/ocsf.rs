//! `OpenShell`'s OCSF log: collecting it (OB-OSHELL-SPEC-002 R6.1) and joining
//! it to the door guard's verdict records (R6.3).
//!
//! With `ocsf_json_enabled` on, each `OpenShell` supervisor writes
//! `/var/log/openshell-ocsf.YYYY-MM-DD.jsonl` (`.log` before v0.1.8): JSON Lines, a new file each
//! day, three kept. On Kubernetes `/var/log` is an `emptyDir` named `logs`,
//! in the sandbox pod or the shared supervisor pod alike, so a node agent
//! finds every file under the kubelet's pod directory.
//!
//! [`Collector`] follows those files and writes each complete new line,
//! unchanged, to its output (stdout in the `DaemonSet`, where the cluster's log
//! pipeline ships it). It remembers how far it read in each file, by path
//! and inode, in a positions file, so a restart neither repeats nor skips
//! lines; a file that shrank or was replaced is read again from the start.
//!
//! [`join`] pairs records with events. `OpenShell` v0.1.8 does not put the
//! request id in its OCSF events (`metadata.uid` is each event's own id), so
//! the join uses the sandbox (`device.container.uid`), the destination host
//! and the time, preferring the event `OpenShell` writes for the `openbox`
//! middleware's decision (`firewall_rule.type: middleware`), which also
//! carries that decision, so the two can be compared.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Where the OCSF files are.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    /// A directory holding the files (a sidecar's `/var/log`, a Docker host).
    Dir(PathBuf),
    /// The kubelet's pod directory (`/var/lib/kubelet/pods`): every pod's
    /// `logs` emptyDir.
    KubeletPods(PathBuf),
}

/// True for `openshell-ocsf.YYYY-MM-DD.jsonl` (v0.1.8) or `.log` (earlier).
pub fn is_ocsf_file(name: &str) -> bool {
    name.strip_prefix("openshell-ocsf.")
        .and_then(|rest| {
            rest.strip_suffix(".jsonl")
                .or_else(|| rest.strip_suffix(".log"))
        })
        .is_some_and(|date| {
            date.len() == 10
                && date.bytes().enumerate().all(|(i, b)| {
                    if i == 4 || i == 7 {
                        b == b'-'
                    } else {
                        b.is_ascii_digit()
                    }
                })
        })
}

fn ocsf_files_in(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if entry.file_name().to_str().is_some_and(is_ocsf_file)
            && entry.file_type().is_ok_and(|kind| kind.is_file())
        {
            out.push(entry.path());
        }
    }
}

impl Source {
    fn files(&self, out: &mut Vec<PathBuf>) {
        match self {
            Self::Dir(dir) => ocsf_files_in(dir, out),
            Self::KubeletPods(root) => {
                let Ok(pods) = std::fs::read_dir(root) else {
                    return;
                };
                for pod in pods.flatten() {
                    ocsf_files_in(
                        &pod.path().join("volumes/kubernetes.io~empty-dir/logs"),
                        out,
                    );
                }
            }
        }
    }
}

/// How far a file has been read.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Position {
    pub inode: u64,
    pub offset: u64,
}

/// Follows the OCSF files of every source.
pub struct Collector {
    sources: Vec<Source>,
    positions: BTreeMap<PathBuf, Position>,
    state: Option<PathBuf>,
}

impl Collector {
    /// A collector that keeps its positions in `state` (if given), loading
    /// what an earlier run left there.
    pub fn new(sources: Vec<Source>, state: Option<PathBuf>) -> Self {
        let positions = state
            .as_deref()
            .and_then(|path| std::fs::read_to_string(path).ok())
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default();
        Self {
            sources,
            positions,
            state,
        }
    }

    pub fn positions(&self) -> &BTreeMap<PathBuf, Position> {
        &self.positions
    }

    /// Writes every complete line added since the last poll, and returns how
    /// many. A partial last line waits for its newline.
    pub fn poll(&mut self, out: &mut impl Write) -> io::Result<usize> {
        let mut files = Vec::new();
        for source in &self.sources {
            source.files(&mut files);
        }
        files.sort();
        // Forget files that are gone (rotated out after three days).
        self.positions.retain(|path, _| files.contains(path));
        let mut lines = 0;
        for path in files {
            let Ok(file) = File::open(&path) else {
                continue;
            };
            let meta = file.metadata()?;
            let known = self.positions.get(&path).copied().unwrap_or_default();
            let mut offset = if known.inode == meta.ino() && known.offset <= meta.len() {
                known.offset
            } else {
                0
            };
            if offset == meta.len() {
                self.positions.insert(
                    path,
                    Position {
                        inode: meta.ino(),
                        offset,
                    },
                );
                continue;
            }
            let mut reader = BufReader::new(file);
            reader.seek(SeekFrom::Start(offset))?;
            let mut line = Vec::new();
            loop {
                line.clear();
                let read = reader.read_until(b'\n', &mut line)?;
                if read == 0 || line.last() != Some(&b'\n') {
                    break;
                }
                offset += read as u64;
                if line.iter().any(|b| !b.is_ascii_whitespace()) {
                    out.write_all(&line)?;
                    lines += 1;
                }
            }
            self.positions.insert(
                path,
                Position {
                    inode: meta.ino(),
                    offset,
                },
            );
        }
        out.flush()?;
        self.save()?;
        Ok(lines)
    }

    fn save(&self) -> io::Result<()> {
        let Some(path) = &self.state else {
            return Ok(());
        };
        let staging = path.with_extension("tmp");
        std::fs::write(&staging, serde_json::to_vec(&self.positions)?)?;
        std::fs::rename(staging, path)
    }
}

/// The sandbox an OCSF event belongs to (`device.container.uid` in
/// v0.1.8, `container.uid` in other OCSF producers).
fn event_sandbox(event: &Value) -> Option<&str> {
    event
        .pointer("/device/container/uid")
        .or_else(|| event.pointer("/container/uid"))
        .and_then(Value::as_str)
}

/// True for the event `OpenShell` writes for a middleware's decision.
fn is_middleware_event(event: &Value) -> bool {
    event.pointer("/firewall_rule/type").and_then(Value::as_str) == Some("middleware")
}

/// The destination host an OCSF event names.
fn event_host(event: &Value) -> Option<String> {
    [
        "/http_request/url/hostname",
        "/dst_endpoint/hostname",
        "/dst_endpoint/domain",
        "/url/hostname",
    ]
    .iter()
    .find_map(|pointer| event.pointer(pointer).and_then(Value::as_str))
    .map(str::to_ascii_lowercase)
}

/// One record matched to an event, or not.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Joined {
    pub record: String,
    pub request_id: Option<String>,
    pub sandbox_id: String,
    pub host: String,
    pub ocsf_uid: Option<String>,
    pub ocsf_class_uid: Option<u64>,
    /// `OpenShell`'s `action` (`Allowed`, `Denied`) and `status_detail`
    /// (`middleware_denied:openbox:<reason code>`).
    pub ocsf_action: Option<String>,
    pub ocsf_status_detail: Option<String>,
    /// Whether `OpenShell` recorded the decision the record holds; only for a
    /// middleware event.
    pub agrees: Option<bool>,
    pub delta_ms: Option<i64>,
}

/// Pairs each verdict record with the nearest OCSF event in time.
///
/// The event must be for the same sandbox and host and within `window_ms`;
/// each event is used once. Records and events with no sandbox, host or
/// time are left out.
pub fn join(records: &[Value], events: &[Value], window_ms: i64) -> Vec<Joined> {
    // (sandbox, host, middleware event) -> [(time, index)]
    let mut by_key: BTreeMap<(String, String, bool), Vec<(i64, usize)>> = BTreeMap::new();
    for (index, event) in events.iter().enumerate() {
        let (Some(sandbox), Some(host), Some(time)) = (
            event_sandbox(event),
            event_host(event),
            event.get("time").and_then(Value::as_i64),
        ) else {
            continue;
        };
        by_key
            .entry((sandbox.to_owned(), host, is_middleware_event(event)))
            .or_default()
            .push((time, index));
    }
    let mut used = vec![false; events.len()];
    let mut joined = Vec::new();
    for record in records {
        let (Some(sandbox), Some(host), Some(time)) = (
            record
                .pointer("/openbox/sandbox_id")
                .and_then(Value::as_str),
            record.pointer("/openbox/host").and_then(Value::as_str),
            record.get("time").and_then(Value::as_i64),
        ) else {
            continue;
        };
        let host = host.to_ascii_lowercase();
        let nearest = |middleware: bool| {
            by_key
                .get(&(sandbox.to_owned(), host.clone(), middleware))
                .into_iter()
                .flatten()
                .filter(|(at, index)| !used[*index] && (at - time).abs() <= window_ms)
                .min_by_key(|(at, _)| (at - time).abs())
                .copied()
        };
        let best = nearest(true).or_else(|| nearest(false));
        if let Some((_, index)) = best {
            used[index] = true;
        }
        let event = best.map(|(_, index)| &events[index]);
        joined.push(Joined {
            record: record
                .pointer("/metadata/uid")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned(),
            request_id: record
                .pointer("/openbox/request_id")
                .and_then(Value::as_str)
                .map(str::to_owned),
            sandbox_id: sandbox.to_owned(),
            host,
            ocsf_uid: event
                .and_then(|event| event.pointer("/metadata/uid"))
                .and_then(Value::as_str)
                .map(str::to_owned),
            ocsf_class_uid: event
                .and_then(|event| event.get("class_uid"))
                .and_then(Value::as_u64),
            ocsf_action: text(event, "/action"),
            ocsf_status_detail: text(event, "/status_detail"),
            agrees: event
                .filter(|event| is_middleware_event(event))
                .map(|event| {
                    let allowed = event.get("action").and_then(Value::as_str) == Some("Allowed");
                    let record_allowed =
                        record.pointer("/openbox/decision").and_then(Value::as_str)
                            == Some("allow");
                    allowed == record_allowed
                }),
            delta_ms: best.map(|(at, _)| at - time),
        });
    }
    joined
}

fn text(event: Option<&Value>, pointer: &str) -> Option<String> {
    event
        .and_then(|event| event.pointer(pointer))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

/// Totals for a join, for the CLI's last line.
pub fn join_summary(joined: &[Joined]) -> Value {
    let matched = joined.iter().filter(|j| j.ocsf_uid.is_some()).count();
    let disagree = joined.iter().filter(|j| j.agrees == Some(false)).count();
    json!({"records": joined.len(), "matched": matched, "unmatched": joined.len() - matched,
           "decisions_disagree": disagree})
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("obx-ocsf-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn append(path: &Path, text: &str) {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        file.write_all(text.as_bytes()).unwrap();
    }

    #[test]
    fn only_daily_ocsf_files_count() {
        assert!(is_ocsf_file("openshell-ocsf.2026-11-14.jsonl"));
        assert!(is_ocsf_file("openshell-ocsf.2026-11-14.log"));
        assert!(!is_ocsf_file("openshell-ocsf.log"));
        assert!(!is_ocsf_file("openshell-ocsf.2026-11-14.log.gz"));
        assert!(!is_ocsf_file("openshell.2026-11-14.log"));
        assert!(!is_ocsf_file("openshell-ocsf.2026-1x-14.log"));
    }

    #[test]
    fn follows_new_lines_across_restarts_rotation_and_replacement() {
        let root = temp_dir("follow");
        let logs = root.join("pods/uid-1/volumes/kubernetes.io~empty-dir/logs");
        std::fs::create_dir_all(&logs).unwrap();
        let day1 = logs.join("openshell-ocsf.2026-11-13.log");
        let state = root.join("positions.json");
        append(&day1, "{\"a\":1}\n{\"a\":2}\n{\"a\":");
        append(&logs.join("other.log"), "not ours\n");

        let sources = vec![Source::KubeletPods(root.join("pods"))];
        let mut collector = Collector::new(sources.clone(), Some(state.clone()));
        let mut out = Vec::new();
        assert_eq!(collector.poll(&mut out).unwrap(), 2);
        assert_eq!(String::from_utf8_lossy(&out), "{\"a\":1}\n{\"a\":2}\n");

        // the partial line completes; a restart carries on where it stopped
        append(&day1, "3}\n");
        let mut collector = Collector::new(sources, Some(state));
        let mut out = Vec::new();
        assert_eq!(collector.poll(&mut out).unwrap(), 1);
        assert_eq!(String::from_utf8_lossy(&out), "{\"a\":3}\n");

        // a new day's file starts at its beginning
        let day2 = logs.join("openshell-ocsf.2026-11-14.jsonl");
        append(&day2, "{\"b\":1}\n");
        let mut out = Vec::new();
        assert_eq!(collector.poll(&mut out).unwrap(), 1);
        assert_eq!(String::from_utf8_lossy(&out), "{\"b\":1}\n");

        // a replaced file (new inode) is read again from the start
        std::fs::remove_file(&day2).unwrap();
        append(&day2, "{\"c\":1}\n");
        let mut out = Vec::new();
        assert_eq!(collector.poll(&mut out).unwrap(), 1);
        assert_eq!(String::from_utf8_lossy(&out), "{\"c\":1}\n");

        // a file rotated out is forgotten
        std::fs::remove_file(&day1).unwrap();
        let mut out = Vec::new();
        assert_eq!(collector.poll(&mut out).unwrap(), 0);
        assert!(!collector.positions().contains_key(&day1));

        // a plain directory source works the same
        let mut plain = Collector::new(vec![Source::Dir(logs)], None);
        let mut out = Vec::new();
        assert_eq!(plain.poll(&mut out).unwrap(), 1);
        let _ = std::fs::remove_dir_all(&root);
    }

    fn record(seq: u64, sandbox: &str, host: &str, time: i64) -> Value {
        json!({"metadata": {"uid": format!("chain:{seq}")}, "time": time,
               "openbox": {"sandbox_id": sandbox, "host": host, "request_id": format!("r{seq}"), "decision": "allow"}})
    }

    // The shape OpenShell v0.1.8 writes.
    fn event(uid: &str, sandbox: &str, host: &str, time: i64) -> Value {
        json!({"class_uid": 4002, "metadata": {"uid": uid}, "time": time,
               "device": {"container": {"name": "box", "uid": sandbox}},
               "http_request": {"url": {"hostname": host}}, "dst_endpoint": {"domain": host},
               "firewall_rule": {"name": "example", "type": "l7"}, "action": "Allowed"})
    }

    fn middleware_event(uid: &str, sandbox: &str, host: &str, time: i64, action: &str) -> Value {
        let mut event = event(uid, sandbox, host, time);
        event["firewall_rule"]["type"] = json!("middleware");
        event["action"] = json!(action);
        event["status_detail"] = json!("middleware_denied:openbox:openbox_blocked");
        event
    }

    #[test]
    fn join_pairs_by_sandbox_host_and_nearest_time_once() {
        let records = [
            record(1, "sb-1", "example.com", 1_000),
            record(2, "sb-1", "Example.com", 1_050),
            record(3, "sb-2", "example.com", 1_000),
            record(4, "sb-1", "api.example.com", 9_000),
        ];
        let events = [
            event("e-late", "sb-1", "example.com", 1_060),
            event("e-early", "sb-1", "example.com", 1_010),
            event("e-other", "sb-2", "example.com", 1_400),
            event("e-api", "sb-1", "api.example.com", 20_000),
        ];
        let joined = join(&records, &events, 500);
        let pairs: Vec<_> = joined
            .iter()
            .map(|j| (j.record.as_str(), j.ocsf_uid.as_deref(), j.delta_ms))
            .collect();
        assert_eq!(
            pairs,
            [
                ("chain:1", Some("e-early"), Some(10)),
                ("chain:2", Some("e-late"), Some(10)),
                ("chain:3", Some("e-other"), Some(400)),
                ("chain:4", None, None),
            ]
        );
        assert_eq!(
            join_summary(&joined),
            json!({"records": 4, "matched": 3, "unmatched": 1, "decisions_disagree": 0})
        );
    }

    #[test]
    fn join_prefers_the_middleware_event_and_compares_decisions() {
        let records = [record(1, "sb", "example.com", 1_000)];
        let events = [
            event("policy", "sb", "example.com", 1_001),
            middleware_event("mw", "sb", "example.com", 1_300, "Denied"),
        ];
        let joined = join(&records, &events, 2_000);
        assert_eq!(joined[0].ocsf_uid.as_deref(), Some("mw"));
        assert_eq!(joined[0].ocsf_action.as_deref(), Some("Denied"));
        assert_eq!(joined[0].agrees, Some(false), "the record says allow");
        assert_eq!(join_summary(&joined)["decisions_disagree"], 1);
        // without a middleware event the policy event is used, no comparison
        let joined = join(&records, &events[..1], 2_000);
        assert_eq!(joined[0].ocsf_uid.as_deref(), Some("policy"));
        assert_eq!(joined[0].agrees, None);
    }
}
