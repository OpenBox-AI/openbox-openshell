//! Collects `OpenShell`'s OCSF JSONL audit files without losing or repeating
//! events.
//!
//! A supervisor writes `openshell-ocsf.YYYY-MM-DD.log` in its `/var/log`,
//! rotates daily and keeps three files, so an event that is not collected
//! within about three days is gone. The collector reads the directory where
//! those files are mounted (a Kubernetes sidecar or `DaemonSet` volume, or a
//! Docker bind mount), one directory per sandbox.
//!
//! - Progress is a byte offset per file, kept in a [`Checkpoint`] the caller
//!   persists after the batch is safely handed on. A restart resumes from
//!   there, and a partly written last line is left for the next poll.
//! - Every record is identified by `metadata.uid`, which `OpenShell` keeps
//!   stable across re-serialisation, so re-reads after a crash are dropped.
//! - A file that was known but disappeared before it was read to the end, or
//!   a checkpointed file that shrank, is a [`Gap`]: evidence was lost, and
//!   that is reported rather than hidden.
//!
//! Records are kept as parsed JSON with unknown fields intact, so schema
//! drift between OCSF minor versions never breaks collection.

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::fs::File;
use std::io::{Read as _, Seek as _, SeekFrom};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

const PREFIX: &str = "openshell-ocsf.";
const SUFFIX: &str = ".log";
/// Remembered record ids, enough to cover several polls of overlap.
const SEEN_CAPACITY: usize = 100_000;
/// Upper bound on one read, so a huge backlog is taken in slices.
const MAX_READ_BYTES: u64 = 8 * 1024 * 1024;

/// Where reading stopped, per file name. Persist it with the batch it covers.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Checkpoint {
    pub files: BTreeMap<String, Progress>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Progress {
    /// Byte offset after the last complete line read.
    pub offset: u64,
    /// Read to the end after a newer file appeared, so it will not grow
    /// again and its rotation is expected.
    pub finished: bool,
}

/// One collected OCSF record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Record {
    /// `metadata.uid`.
    pub uid: String,
    /// `container.uid`: the sandbox, when the record has one.
    pub sandbox_id: Option<String>,
    pub class_uid: Option<i64>,
    /// Event time in milliseconds, when present.
    pub time_ms: Option<i64>,
    /// The complete record as written, unknown fields included.
    pub raw: Value,
}

/// Evidence that could not be collected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Gap {
    /// A file rotated away before it was read to the end.
    RotatedUnread { file: String, read_to: u64 },
    /// A file is shorter than the checkpoint: it was truncated or replaced.
    Truncated {
        file: String,
        checkpoint: u64,
        length: u64,
    },
    /// A line was not valid JSON or had no `metadata.uid`.
    Unparseable { file: String, offset: u64 },
}

#[derive(Debug, Default)]
pub struct Batch {
    pub records: Vec<Record>,
    pub gaps: Vec<Gap>,
    pub duplicates: usize,
    /// Checkpoint to persist once `records` are safely stored.
    pub checkpoint: Checkpoint,
}

pub struct Tail {
    directory: PathBuf,
    seen: HashSet<String>,
    seen_order: VecDeque<String>,
}

impl Tail {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
            seen: HashSet::new(),
            seen_order: VecDeque::new(),
        }
    }

    /// Reads everything new since `checkpoint`, oldest file first.
    pub fn poll(&mut self, checkpoint: &Checkpoint) -> std::io::Result<Batch> {
        let files = self.files()?;
        let mut batch = Batch::default();
        for (name, progress) in &checkpoint.files {
            if !progress.finished && !files.iter().any(|(file, _)| file == name) {
                batch.gaps.push(Gap::RotatedUnread {
                    file: name.clone(),
                    read_to: progress.offset,
                });
            }
        }
        let newest = files.last().map(|(name, _)| name.clone());
        for (name, path) in files {
            let start = checkpoint
                .files
                .get(&name)
                .map_or(0, |progress| progress.offset);
            let length = std::fs::metadata(&path)?.len();
            if length < start {
                batch.gaps.push(Gap::Truncated {
                    file: name.clone(),
                    checkpoint: start,
                    length,
                });
                batch.checkpoint.files.insert(
                    name,
                    Progress {
                        offset: length,
                        finished: false,
                    },
                );
                continue;
            }
            let offset = self.read_file(&name, &path, start, &mut batch)?;
            let finished = offset >= length && Some(&name) != newest.as_ref();
            batch
                .checkpoint
                .files
                .insert(name, Progress { offset, finished });
        }
        Ok(batch)
    }

    fn files(&self) -> std::io::Result<Vec<(String, PathBuf)>> {
        let mut files: Vec<(String, PathBuf)> = std::fs::read_dir(&self.directory)?
            .filter_map(Result::ok)
            .filter_map(|entry| {
                let name = entry.file_name().into_string().ok()?;
                (name.starts_with(PREFIX) && name.ends_with(SUFFIX)).then(|| (name, entry.path()))
            })
            .collect();
        // YYYY-MM-DD names sort chronologically.
        files.sort();
        Ok(files)
    }

    /// Reads complete lines from `start`, returning the offset after the last
    /// complete line.
    fn read_file(
        &mut self,
        name: &str,
        path: &Path,
        start: u64,
        batch: &mut Batch,
    ) -> std::io::Result<u64> {
        let mut file = File::open(path)?;
        file.seek(SeekFrom::Start(start))?;
        let mut buffer = Vec::new();
        file.take(MAX_READ_BYTES).read_to_end(&mut buffer)?;
        let mut offset = start;
        let mut consumed = 0;
        for line in buffer.split_inclusive(|byte| *byte == b'\n') {
            if line.last() != Some(&b'\n') {
                break; // partly written; the next poll picks it up whole
            }
            let line_offset = offset;
            offset += line.len() as u64;
            consumed += line.len();
            let text = &line[..line.len() - 1];
            if text.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            match parse(text) {
                Some(record) => {
                    if self.remember(&record.uid) {
                        batch.records.push(record);
                    } else {
                        batch.duplicates += 1;
                    }
                }
                None => batch.gaps.push(Gap::Unparseable {
                    file: name.to_owned(),
                    offset: line_offset,
                }),
            }
        }
        Ok(start + consumed as u64)
    }

    fn remember(&mut self, uid: &str) -> bool {
        if !self.seen.insert(uid.to_owned()) {
            return false;
        }
        self.seen_order.push_back(uid.to_owned());
        if self.seen_order.len() > SEEN_CAPACITY
            && let Some(oldest) = self.seen_order.pop_front()
        {
            self.seen.remove(&oldest);
        }
        true
    }
}

fn parse(line: &[u8]) -> Option<Record> {
    let raw: Value = serde_json::from_slice(line).ok()?;
    let uid = raw.pointer("/metadata/uid")?.as_str()?.to_owned();
    if uid.is_empty() {
        return None;
    }
    Some(Record {
        uid,
        sandbox_id: raw
            .pointer("/container/uid")
            .and_then(Value::as_str)
            .map(str::to_owned),
        class_uid: raw.get("class_uid").and_then(Value::as_i64),
        time_ms: raw.get("time").and_then(Value::as_i64),
        raw,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn event(uid: &str) -> String {
        format!(
            r#"{{"class_uid":4002,"time":1790676000000,"metadata":{{"uid":"{uid}","version":"1.8.0"}},"container":{{"uid":"sbx-1"}},"future_field":{{"x":1}}}}"#
        )
    }

    fn write(dir: &Path, name: &str, lines: &[String], trailing_partial: Option<&str>) {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join(name))
            .unwrap();
        for line in lines {
            writeln!(file, "{line}").unwrap();
        }
        if let Some(partial) = trailing_partial {
            write!(file, "{partial}").unwrap();
        }
    }

    const DAY1: &str = "openshell-ocsf.2026-09-28.log";
    const DAY2: &str = "openshell-ocsf.2026-09-29.log";

    #[test]
    fn reads_new_records_and_keeps_unknown_fields() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), DAY1, &[event("a"), event("b")], None);
        let mut tail = Tail::new(dir.path());
        let batch = tail.poll(&Checkpoint::default()).unwrap();
        assert_eq!(batch.records.len(), 2);
        assert_eq!(batch.records[0].uid, "a");
        assert_eq!(batch.records[0].sandbox_id.as_deref(), Some("sbx-1"));
        assert_eq!(batch.records[0].class_uid, Some(4002));
        assert_eq!(batch.records[0].raw["future_field"]["x"], 1);
        assert!(batch.gaps.is_empty());
    }

    #[test]
    fn resumes_from_the_checkpoint_and_waits_for_partial_lines() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), DAY2, &[event("a")], Some(r#"{"metadata":{"ui"#));
        let mut tail = Tail::new(dir.path());
        let first = tail.poll(&Checkpoint::default()).unwrap();
        assert_eq!(first.records.len(), 1);
        // Finish the partial line and add one more.
        write(
            dir.path(),
            DAY2,
            &[r#"d":"b"}}"#.to_owned(), event("c")],
            None,
        );
        let second = tail.poll(&first.checkpoint).unwrap();
        let uids: Vec<_> = second
            .records
            .iter()
            .map(|record| record.uid.as_str())
            .collect();
        assert_eq!(uids, ["b", "c"]);
        assert!(second.gaps.is_empty());
    }

    #[test]
    fn a_restart_from_an_old_checkpoint_drops_duplicates_by_uid() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), DAY2, &[event("a"), event("b")], None);
        let mut tail = Tail::new(dir.path());
        tail.poll(&Checkpoint::default()).unwrap();
        // Crash before the checkpoint was persisted: re-read from zero.
        let again = tail.poll(&Checkpoint::default()).unwrap();
        assert!(again.records.is_empty());
        assert_eq!(again.duplicates, 2);
    }

    #[test]
    fn rotation_after_a_full_read_is_not_a_gap() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), DAY1, &[event("a")], None);
        write(dir.path(), DAY2, &[event("b")], None);
        let mut tail = Tail::new(dir.path());
        let first = tail.poll(&Checkpoint::default()).unwrap();
        assert_eq!(first.records.len(), 2);
        std::fs::remove_file(dir.path().join(DAY1)).unwrap();
        let second = tail.poll(&first.checkpoint).unwrap();
        assert!(second.gaps.is_empty(), "{:?}", second.gaps);
        assert!(
            !second.checkpoint.files.contains_key(DAY1),
            "rotated files drop out"
        );
    }

    #[test]
    fn rotation_before_a_full_read_is_a_gap() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), DAY1, &[event("a")], None);
        let mut tail = Tail::new(dir.path());
        let first = tail.poll(&Checkpoint::default()).unwrap();
        // More was written to DAY1, then it rotated away unread.
        write(dir.path(), DAY1, &[event("lost")], None);
        write(dir.path(), DAY2, &[event("b")], None);
        std::fs::remove_file(dir.path().join(DAY1)).unwrap();
        let second = tail.poll(&first.checkpoint).unwrap();
        assert!(
            matches!(&second.gaps[..], [Gap::RotatedUnread { file, .. }] if file == DAY1),
            "{:?}",
            second.gaps
        );
        assert_eq!(second.records.len(), 1);
    }

    #[test]
    fn truncation_and_garbage_are_reported() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            DAY2,
            &[
                event("a"),
                "not json".to_owned(),
                r#"{"metadata":{}}"#.to_owned(),
            ],
            None,
        );
        let mut tail = Tail::new(dir.path());
        let first = tail.poll(&Checkpoint::default()).unwrap();
        assert_eq!(first.records.len(), 1);
        assert_eq!(
            first
                .gaps
                .iter()
                .filter(|gap| matches!(gap, Gap::Unparseable { .. }))
                .count(),
            2
        );
        std::fs::write(dir.path().join(DAY2), format!("{}\n", event("x"))).unwrap();
        let second = tail.poll(&first.checkpoint).unwrap();
        assert!(
            second
                .gaps
                .iter()
                .any(|gap| matches!(gap, Gap::Truncated { .. }))
        );
    }

    #[test]
    fn ignores_unrelated_files() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "openshell.2026-09-29.log",
            &[event("shorthand")],
            None,
        );
        write(dir.path(), DAY2, &[event("a")], None);
        let batch = Tail::new(dir.path()).poll(&Checkpoint::default()).unwrap();
        assert_eq!(batch.records.len(), 1);
    }
}
