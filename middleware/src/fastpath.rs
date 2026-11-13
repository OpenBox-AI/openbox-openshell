//! Fast-path verdicts: answer without waiting for Core when that is safe.
//!
//! | Tier | Decides | How |
//! |------|---------|-----|
//! | 0 | Requests matched by a local rule snapshot | [`Snapshot`], loaded from a file Core publishes (or an operator mounts); `shadow` by default |
//! | 1 | An identical action Core allowed within its TTL | the shared store, keyed by the action fingerprint |
//! | 2 | Everything else | Core, inline (as before) or `pending`: wait briefly, otherwise deny `openbox_pending` and keep evaluating, so the identical retry gets the verdict at once |
//!
//! A request answered by tier 0 or 1 is still recorded in Core, in order,
//! in the background ([`crate::sequence`]). Model calls always go to Core:
//! their prompt and tool bookkeeping happens there.

use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::{Duration, SystemTime};

use serde::Deserialize;

use crate::action::{Action, Payload};
use crate::capture::host_matches;

/// Which tier answered a request, for the metrics.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Tier {
    LocalRule,
    RecentVerdict,
    Core,
    Pending,
}

impl Tier {
    pub const fn label(self) -> &'static str {
        match self {
            Self::LocalRule => "local_rule",
            Self::RecentVerdict => "recent_verdict",
            Self::Core => "core",
            Self::Pending => "pending",
        }
    }
}

/// What the local rule snapshot does.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RulesMode {
    Off,
    /// Evaluate locally and count agreement with Core; Core still decides.
    #[default]
    Shadow,
    /// A matching rule decides; Core is not asked (the request is still
    /// recorded there).
    Enforce,
}

impl RulesMode {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "off" => Some(Self::Off),
            "shadow" => Some(Self::Shadow),
            "enforce" => Some(Self::Enforce),
            _ => None,
        }
    }
}

/// What tier 2 does while Core is slow (decision D1).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SlowCore {
    /// Wait for Core, up to the Core budget (the behaviour before W3).
    #[default]
    Inline,
    /// Wait up to the given time; then deny `openbox_pending`, keep
    /// evaluating, and answer the identical retry from the result.
    Pending(Duration),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalDecision {
    Allow,
    Block,
}

/// One local rule. Every field that is set must match; an empty rule
/// matches nothing.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct Rule {
    pub id: String,
    pub decision: String,
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub path_prefixes: Vec<String>,
    #[serde(default)]
    pub tools: Vec<String>,
}

/// A versioned rule snapshot. Stale (past `expires_at`) means unusable: the
/// request goes to Core.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct Snapshot {
    pub version: String,
    /// Unix seconds.
    pub expires_at: i64,
    pub rules: Vec<Rule>,
}

impl Snapshot {
    pub fn parse(text: &str) -> Result<Self, String> {
        let snapshot: Self =
            serde_json::from_str(text).map_err(|error| format!("rule snapshot: {error}"))?;
        if snapshot.version.trim().is_empty() {
            return Err("rule snapshot: version is required".to_owned());
        }
        for rule in &snapshot.rules {
            if !matches!(rule.decision.as_str(), "allow" | "block") {
                return Err(format!(
                    "rule snapshot: rule {:?} decision must be allow or block",
                    rule.id
                ));
            }
            if rule.hosts.is_empty()
                && rule.methods.is_empty()
                && rule.path_prefixes.is_empty()
                && rule.tools.is_empty()
            {
                return Err(format!(
                    "rule snapshot: rule {:?} matches nothing; give it a condition",
                    rule.id
                ));
            }
        }
        Ok(snapshot)
    }

    pub fn is_stale(&self, now: i64) -> bool {
        now >= self.expires_at
    }

    /// The first rule matching the request, with its decision.
    pub fn decide(&self, action: &Action) -> Option<(&Rule, LocalDecision)> {
        let host = action.host.to_ascii_lowercase();
        let tools = action.tools();
        self.rules.iter().find_map(|rule| {
            let matches = (rule.hosts.is_empty()
                || rule
                    .hosts
                    .iter()
                    .any(|pattern| host_matches(&pattern.to_ascii_lowercase(), &host)))
                && (rule.methods.is_empty()
                    || rule
                        .methods
                        .iter()
                        .any(|method| method.eq_ignore_ascii_case(&action.method)))
                && (rule.path_prefixes.is_empty()
                    || rule
                        .path_prefixes
                        .iter()
                        .any(|prefix| action.path.starts_with(prefix.as_str())))
                && (rule.tools.is_empty()
                    || (matches!(action.payload, Payload::JsonRpc(_))
                        && !tools.is_empty()
                        && tools
                            .iter()
                            .all(|tool| rule.tools.iter().any(|allowed| allowed == tool))));
            matches.then(|| {
                let decision = if rule.decision == "allow" {
                    LocalDecision::Allow
                } else {
                    LocalDecision::Block
                };
                (rule, decision)
            })
        })
    }
}

/// The snapshot file and what was last loaded from it. Reloaded when the
/// file changes ([`Rules::refresh`]); a file that fails to parse keeps the
/// previous snapshot until it expires.
pub struct Rules {
    pub mode: RulesMode,
    path: Option<PathBuf>,
    loaded: RwLock<Option<(SystemTime, Snapshot)>>,
}

impl Rules {
    pub fn new(mode: RulesMode, path: Option<PathBuf>) -> Self {
        Self {
            mode,
            path,
            loaded: RwLock::new(None),
        }
    }

    pub fn off() -> Self {
        Self::new(RulesMode::Off, None)
    }

    /// For tests: a fixed snapshot.
    pub fn fixed(mode: RulesMode, snapshot: Snapshot) -> Self {
        let rules = Self::new(mode, None);
        *rules.loaded.write().expect("rules lock") = Some((SystemTime::UNIX_EPOCH, snapshot));
        rules
    }

    /// Reloads the file if it changed since the last load.
    pub fn refresh(&self) {
        let Some(path) = &self.path else { return };
        let Ok(modified) = std::fs::metadata(path).and_then(|meta| meta.modified()) else {
            return;
        };
        if self
            .loaded
            .read()
            .expect("rules lock")
            .as_ref()
            .is_some_and(|(at, _)| *at == modified)
        {
            return;
        }
        match load(path) {
            Ok(snapshot) => {
                eprintln!(
                    "openbox: rule snapshot {} loaded ({} rules)",
                    snapshot.version,
                    snapshot.rules.len()
                );
                *self.loaded.write().expect("rules lock") = Some((modified, snapshot));
            }
            Err(error) => eprintln!("openbox: rule snapshot not loaded: {error}"),
        }
    }

    /// The local decision for a request, if the snapshot is fresh and a rule
    /// matches. Returns the snapshot version and rule id with it.
    pub fn decide(&self, action: &Action, now: i64) -> Option<(String, String, LocalDecision)> {
        if self.mode == RulesMode::Off {
            return None;
        }
        let loaded = self.loaded.read().expect("rules lock");
        let (_, snapshot) = loaded.as_ref()?;
        if snapshot.is_stale(now) {
            return None;
        }
        snapshot
            .decide(action)
            .map(|(rule, decision)| (snapshot.version.clone(), rule.id.clone(), decision))
    }
}

fn load(path: &Path) -> Result<Snapshot, String> {
    let text = std::fs::read_to_string(path).map_err(|error| error.to_string())?;
    Snapshot::parse(&text)
}

/// Shared-store key for an action Core allowed recently.
pub fn verdict_key(sandbox_id: &str, fingerprint: &str) -> String {
    format!("openbox:verdict:{sandbox_id}:{fingerprint}")
}

/// Shared-store key for a verdict still being worked out, or worked out for
/// an identical retry.
pub fn pending_key(sandbox_id: &str, fingerprint: &str) -> String {
    format!("openbox:pending:{sandbox_id}:{fingerprint}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::tests::evaluation;

    fn action(method: &str, host: &str, path: &str, body: &[u8]) -> Action {
        let mut evaluation = evaluation(method, path, body);
        evaluation.target.as_mut().unwrap().host = host.to_owned();
        Action::from_evaluation(&evaluation)
    }

    fn snapshot() -> Snapshot {
        Snapshot::parse(
            r#"{"version": "v42", "expires_at": 2000000000, "rules": [
                {"id": "no-paste", "decision": "block", "hosts": ["pastebin.com", "*.pastebin.com"]},
                {"id": "docs-read", "decision": "allow", "hosts": ["docs.example.com"], "methods": ["GET", "HEAD"]},
                {"id": "safe-tools", "decision": "allow", "tools": ["search", "fetch"]}
            ]}"#,
        )
        .unwrap()
    }

    #[test]
    fn first_matching_rule_decides() {
        let snapshot = snapshot();
        let decide = |a: &Action| snapshot.decide(a).map(|(rule, d)| (rule.id.clone(), d));
        assert_eq!(
            decide(&action("POST", "www.pastebin.com", "/", b"x")),
            Some(("no-paste".to_owned(), LocalDecision::Block))
        );
        assert_eq!(
            decide(&action("GET", "docs.example.com", "/a", b"")),
            Some(("docs-read".to_owned(), LocalDecision::Allow))
        );
        assert_eq!(decide(&action("POST", "docs.example.com", "/a", b"")), None);
        let search = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search","arguments":{}}}"#;
        let delete = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete","arguments":{}}}"#;
        assert_eq!(
            decide(&action("POST", "mcp.example.com", "/mcp", search)),
            Some(("safe-tools".to_owned(), LocalDecision::Allow))
        );
        assert_eq!(
            decide(&action("POST", "mcp.example.com", "/mcp", delete)),
            None
        );
    }

    #[test]
    fn stale_or_off_decides_nothing() {
        let request = action("GET", "docs.example.com", "/", b"");
        let rules = Rules::fixed(RulesMode::Enforce, snapshot());
        assert!(rules.decide(&request, 1_000).is_some());
        assert!(rules.decide(&request, 2_000_000_000).is_none(), "stale");
        let off = Rules::fixed(RulesMode::Off, snapshot());
        assert!(off.decide(&request, 1_000).is_none());
    }

    #[test]
    fn parse_refuses_unusable_snapshots() {
        for bad in [
            r#"{"version": "", "expires_at": 1, "rules": []}"#,
            r#"{"version": "v", "expires_at": 1, "rules": [{"id": "x", "decision": "maybe", "hosts": ["a"]}]}"#,
            r#"{"version": "v", "expires_at": 1, "rules": [{"id": "x", "decision": "allow"}]}"#,
            "not json",
        ] {
            assert!(Snapshot::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn reloads_the_file_when_it_changes() {
        let dir = std::env::temp_dir().join(format!("obx-rules-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("rules.json");
        std::fs::write(&path, r#"{"version": "v1", "expires_at": 2000000000, "rules": [{"id": "a", "decision": "block", "hosts": ["x.test"]}]}"#).unwrap();
        let rules = Rules::new(RulesMode::Enforce, Some(path.clone()));
        rules.refresh();
        let request = action("GET", "x.test", "/", b"");
        assert_eq!(rules.decide(&request, 0).unwrap().0, "v1");
        // A broken file keeps the previous snapshot.
        std::thread::sleep(Duration::from_millis(20));
        std::fs::write(&path, "{").unwrap();
        rules.refresh();
        assert_eq!(rules.decide(&request, 0).unwrap().0, "v1");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
