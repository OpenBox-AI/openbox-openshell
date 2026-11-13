//! CONSTRAIN as a rewrite: the request goes out changed, never as sent.
//!
//! Core's CONSTRAIN verdict carries machine-readable constraints in its
//! `constraints` field. The door guard applies them to the request and
//! returns `DECISION_ALLOW` with the replacement body and header removals.
//! Three kinds:
//!
//! | `kind`          | Fields                                   | Does |
//! |-----------------|------------------------------------------|------|
//! | `redact`        | `paths` (JSON Pointers), `findings` (kinds from [`crate::capture`]) | Replaces each value at a path, and every match of a finding kind in any string, with `[REDACTED]` |
//! | `narrow`        | `tool` (optional), `drop`, `set`         | For MCP `tools/call` (of that tool, or any), removes the `drop` argument keys and writes the `set` keys |
//! | `strip_headers` | `names`                                  | Removes those request headers |
//!
//! Core also sends plain strings. `"run_in_sandbox"` is met by the sandbox
//! itself: the request goes out unchanged, as CONSTRAIN always meant. Any
//! other string is a constraint the door guard does not know, so it cannot
//! be met.
//!
//! A constraint that cannot be applied (a path into a body that is not JSON,
//! a `narrow` on a request with no matching tool call, a header `OpenShell`
//! protects, a result over the size limit) fails the request with
//! `openbox_constrain_failed`. The original request is never forwarded under
//! a CONSTRAIN it could not meet.
//!
//! The approval fingerprint is the request as the agent sent it
//! ([`crate::action`]), so an identical retry still matches; the result
//! records the SHA-256 of both the original and the rewritten body.

use regex::Regex;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::action::Action;

/// What a redacted value or span becomes.
pub const REDACTED: &str = "[REDACTED]";
/// The most constraints one verdict may carry.
const MAX_CONSTRAINTS: usize = 32;
/// `OpenShell`'s limit on header mutations per result.
const MAX_HEADER_REMOVALS: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Constraint {
    /// Met by running in an `OpenShell` sandbox; nothing to change.
    RunInSandbox,
    Redact {
        paths: Vec<String>,
        findings: Vec<String>,
    },
    Narrow {
        tool: Option<String>,
        drop: Vec<String>,
        set: Map<String, Value>,
    },
    StripHeaders {
        names: Vec<String>,
    },
}

/// Reads Core's `constraints`. Unknown kinds and malformed entries are an
/// error: a constraint the door guard does not understand cannot be met.
pub fn parse(value: &Value) -> Result<Vec<Constraint>, String> {
    let items = value.as_array().ok_or("constraints must be a list")?;
    if items.len() > MAX_CONSTRAINTS {
        return Err(format!("at most {MAX_CONSTRAINTS} constraints"));
    }
    items.iter().map(parse_one).collect()
}

fn strings(item: &Value, key: &str) -> Result<Vec<String>, String> {
    match item.get(key) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| format!("{key} must be a list of strings"))
            })
            .collect(),
        Some(_) => Err(format!("{key} must be a list of strings")),
    }
}

fn parse_one(item: &Value) -> Result<Constraint, String> {
    if let Some(name) = item.as_str() {
        return match name {
            "run_in_sandbox" => Ok(Constraint::RunInSandbox),
            other => Err(format!("unknown constraint {other:?}")),
        };
    }
    let kind = item
        .get("kind")
        .and_then(Value::as_str)
        .ok_or("a constraint needs a kind")?;
    match kind {
        "redact" => {
            let paths = strings(item, "paths")?;
            let findings = strings(item, "findings")?;
            if paths.is_empty() && findings.is_empty() {
                return Err("redact needs paths or findings".to_owned());
            }
            if let Some(path) = paths.iter().find(|path| !path.starts_with('/')) {
                return Err(format!("redact path {path:?} is not a JSON Pointer"));
            }
            if let Some(kind) = findings
                .iter()
                .find(|kind| crate::capture::detector(kind).is_none())
            {
                return Err(format!("redact: unknown finding kind {kind:?}"));
            }
            Ok(Constraint::Redact { paths, findings })
        }
        "narrow" => {
            let drop = strings(item, "drop")?;
            let set = match item.get("set") {
                None | Some(Value::Null) => Map::new(),
                Some(Value::Object(set)) => set.clone(),
                Some(_) => return Err("narrow set must be an object".to_owned()),
            };
            if drop.is_empty() && set.is_empty() {
                return Err("narrow needs drop or set".to_owned());
            }
            let tool = match item.get("tool") {
                None | Some(Value::Null) => None,
                Some(Value::String(tool)) => Some(tool.clone()),
                Some(_) => return Err("narrow tool must be a string".to_owned()),
            };
            Ok(Constraint::Narrow { tool, drop, set })
        }
        "strip_headers" => {
            let names: Vec<String> = strings(item, "names")?
                .into_iter()
                .map(|name| name.to_ascii_lowercase())
                .collect();
            if names.is_empty() {
                return Err("strip_headers needs names".to_owned());
            }
            Ok(Constraint::StripHeaders { names })
        }
        other => Err(format!("unknown constraint kind {other:?}")),
    }
}

/// The request after its constraints.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Rewrite {
    /// The replacement body, when the body changed.
    pub body: Option<Vec<u8>>,
    /// Header names to remove, lowercase.
    pub remove_headers: Vec<String>,
    /// What was done, for the evidence: `redact:/card`, `narrow:delete_repo`.
    pub applied: Vec<String>,
    pub original_sha256: String,
    pub rewritten_sha256: String,
}

/// Applies `constraints` to the request. `max_body` is the most the gateway
/// accepts as a replacement body.
pub fn apply(
    action: &Action,
    constraints: &[Constraint],
    max_body: usize,
) -> Result<Rewrite, String> {
    let mut body = action.body.clone();
    let mut json: Option<Value> = None;
    let mut remove_headers = Vec::new();
    let mut applied = Vec::new();
    let parse = |body: &[u8]| serde_json::from_slice::<Value>(body).ok();
    for constraint in constraints {
        match constraint {
            Constraint::RunInSandbox => {}
            Constraint::Redact { paths, findings } => {
                if !paths.is_empty() {
                    let document = match json.as_mut() {
                        Some(document) => document,
                        None => json.insert(parse(&body).ok_or("redact paths need a JSON body")?),
                    };
                    for path in paths {
                        // A path that is absent is already met: nothing to
                        // redact there.
                        if let Some(target) = document.pointer_mut(path) {
                            *target = Value::String(REDACTED.to_owned());
                            applied.push(format!("redact:{path}"));
                        }
                    }
                }
                for kind in findings {
                    let pattern = crate::capture::detector(kind)
                        .ok_or_else(|| format!("unknown finding kind {kind:?}"))?;
                    let hits = if let Some(document) = json.as_mut() {
                        redact_strings(document, pattern)
                    } else if let Some(mut document) = parse(&body) {
                        let hits = redact_strings(&mut document, pattern);
                        json = Some(document);
                        hits
                    } else {
                        let text = String::from_utf8(body.clone())
                            .map_err(|_| "redact findings need a text body")?;
                        let (replaced, hits) = replace(&text, pattern);
                        body = replaced.into_bytes();
                        hits
                    };
                    if hits > 0 {
                        applied.push(format!("redact:{kind}x{hits}"));
                    }
                }
            }
            Constraint::Narrow { tool, drop, set } => {
                let document = match json.as_mut() {
                    Some(document) => document,
                    None => json.insert(parse(&body).ok_or("narrow needs a JSON-RPC body")?),
                };
                let narrowed = narrow(document, tool.as_deref(), drop, set);
                if narrowed == 0 {
                    return Err(format!(
                        "narrow: no tools/call{} in the request",
                        tool.as_deref()
                            .map_or_else(String::new, |tool| format!(" of {tool}"))
                    ));
                }
                applied.push(format!("narrow:{}", tool.as_deref().unwrap_or("*")));
            }
            Constraint::StripHeaders { names } => {
                for name in names {
                    if is_protected(name) {
                        return Err(format!("strip_headers: {name} is protected by OpenShell"));
                    }
                    if action
                        .headers
                        .iter()
                        .any(|(header, _)| header.eq_ignore_ascii_case(name))
                        && !remove_headers.contains(name)
                    {
                        remove_headers.push(name.clone());
                        applied.push(format!("strip_header:{name}"));
                    }
                }
            }
        }
    }
    if remove_headers.len() > MAX_HEADER_REMOVALS {
        return Err(format!("more than {MAX_HEADER_REMOVALS} headers to strip"));
    }
    if let Some(document) = json {
        body = serde_json::to_vec(&document).map_err(|_| "rewritten body not serialisable")?;
    }
    if body.len() > max_body {
        return Err(format!(
            "rewritten body is {} bytes, over the {max_body}-byte limit",
            body.len()
        ));
    }
    let original_sha256 = hex(&Sha256::digest(&action.body));
    let rewritten_sha256 = hex(&Sha256::digest(&body));
    let changed = body != action.body;
    Ok(Rewrite {
        body: changed.then_some(body),
        remove_headers,
        applied,
        original_sha256,
        rewritten_sha256,
    })
}

/// Replaces every match in every string of `document`; returns the count.
fn redact_strings(document: &mut Value, pattern: &Regex) -> usize {
    match document {
        Value::String(text) => {
            let (replaced, hits) = replace(text, pattern);
            if hits > 0 {
                *text = replaced;
            }
            hits
        }
        Value::Array(items) => items
            .iter_mut()
            .map(|item| redact_strings(item, pattern))
            .sum(),
        Value::Object(object) => object
            .values_mut()
            .map(|item| redact_strings(item, pattern))
            .sum(),
        _ => 0,
    }
}

fn replace(text: &str, pattern: &Regex) -> (String, usize) {
    let hits = pattern.find_iter(text).count();
    (pattern.replace_all(text, REDACTED).into_owned(), hits)
}

/// Narrows the arguments of each MCP `tools/call` in a JSON-RPC message or
/// batch; returns how many calls it changed.
fn narrow(
    document: &mut Value,
    tool: Option<&str>,
    drop: &[String],
    set: &Map<String, Value>,
) -> usize {
    let calls: Vec<&mut Value> = match document {
        Value::Array(batch) => batch.iter_mut().collect(),
        single @ Value::Object(_) => vec![single],
        _ => return 0,
    };
    let mut narrowed = 0;
    for call in calls {
        if call.get("method").and_then(Value::as_str) != Some("tools/call") {
            continue;
        }
        let Some(params) = call.get_mut("params").and_then(Value::as_object_mut) else {
            continue;
        };
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .map(str::to_owned);
        if tool.is_some_and(|tool| name.as_deref() != Some(tool)) {
            continue;
        }
        let arguments = params
            .entry("arguments")
            .or_insert_with(|| Value::Object(Map::new()));
        let Some(arguments) = arguments.as_object_mut() else {
            continue;
        };
        for key in drop {
            arguments.remove(key);
        }
        for (key, value) in set {
            arguments.insert(key.clone(), value.clone());
        }
        narrowed += 1;
    }
    narrowed
}

/// The request headers `OpenShell` v0.1.8 never lets a middleware change:
/// credential, routing, framing and hop-by-hop headers.
pub fn is_protected(name: &str) -> bool {
    matches!(
        name,
        "authorization"
            | "proxy-authorization"
            | "proxy-authenticate"
            | "cookie"
            | "host"
            | "content-length"
            | "transfer-encoding"
            | "connection"
            | "proxy-connection"
            | "keep-alive"
            | "te"
            | "trailer"
            | "upgrade"
    ) || name.starts_with("x-amz-")
        || name.starts_with("x-openshell-credential")
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::tests::evaluation;
    use serde_json::json;

    fn action(body: &Value, headers: &[(&str, &str)]) -> Action {
        let mut evaluation = evaluation("POST", "/mcp", body.to_string().as_bytes());
        for (name, value) in headers {
            evaluation.headers.push(openshell_core::proto::HttpHeader {
                name: (*name).to_owned(),
                value: (*value).to_owned(),
            });
        }
        Action::from_evaluation(&evaluation)
    }

    fn constraints(value: Value) -> Vec<Constraint> {
        parse(&value).unwrap()
    }

    /// SPEC-001 A2: a card number and an email address leave redacted, by
    /// path and by finding, and the fingerprint is still the original's.
    #[test]
    fn redacts_by_path_and_by_finding() {
        let body = json!({"customer": {"email": "jane@example.com", "card": "4111 1111 1111 1111"},
                          "note": "call jane@example.com", "amount": 10});
        let request = action(&body, &[]);
        let rewrite = apply(
            &request,
            &constraints(json!([
                {"kind": "redact", "paths": ["/customer/card"]},
                {"kind": "redact", "findings": ["email"]}
            ])),
            4 << 20,
        )
        .unwrap();
        let out: Value = serde_json::from_slice(rewrite.body.as_ref().unwrap()).unwrap();
        assert_eq!(out["customer"]["card"], REDACTED);
        assert_eq!(out["customer"]["email"], REDACTED);
        assert_eq!(out["note"], "call [REDACTED]");
        assert_eq!(out["amount"], 10);
        assert_eq!(rewrite.applied, ["redact:/customer/card", "redact:emailx2"]);
        assert_ne!(rewrite.original_sha256, rewrite.rewritten_sha256);
        assert_eq!(
            request.body,
            body.to_string().into_bytes(),
            "the original is untouched"
        );
    }

    #[test]
    fn redacts_findings_in_a_text_body() {
        let mut evaluation = evaluation("POST", "/notes", b"card 4111 1111 1111 1111 ok");
        evaluation.headers.clear();
        let request = Action::from_evaluation(&evaluation);
        let rewrite = apply(
            &request,
            &constraints(json!([{"kind": "redact", "findings": ["payment_card"]}])),
            1024,
        )
        .unwrap();
        assert_eq!(rewrite.body.unwrap(), b"card [REDACTED] ok");
    }

    /// Narrows a destructive MCP argument: `force` goes, `dry_run` is set,
    /// and a call to another tool is left alone.
    #[test]
    fn narrows_a_destructive_mcp_argument() {
        let body = json!([
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": "delete_repo", "arguments": {"repo": "core", "force": true}}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
             "params": {"name": "list_repos", "arguments": {"force": true}}}
        ]);
        let rewrite = apply(
            &action(&body, &[]),
            &constraints(json!([{"kind": "narrow", "tool": "delete_repo",
                                  "drop": ["force"], "set": {"dry_run": true}}])),
            4 << 20,
        )
        .unwrap();
        let out: Value = serde_json::from_slice(rewrite.body.as_ref().unwrap()).unwrap();
        assert_eq!(
            out[0]["params"]["arguments"],
            json!({"repo": "core", "dry_run": true})
        );
        assert_eq!(out[1]["params"]["arguments"], json!({"force": true}));
        assert_eq!(rewrite.applied, ["narrow:delete_repo"]);
    }

    #[test]
    fn strips_a_header_and_refuses_a_protected_one() {
        let request = action(
            &json!({}),
            &[("x-debug-token", "abc"), ("authorization", "Bearer x")],
        );
        let rewrite = apply(
            &request,
            &constraints(
                json!([{"kind": "strip_headers", "names": ["X-Debug-Token", "x-absent"]}]),
            ),
            1024,
        )
        .unwrap();
        assert_eq!(rewrite.remove_headers, ["x-debug-token"]);
        assert_eq!(rewrite.body, None, "the body is unchanged");
        assert!(
            apply(
                &request,
                &constraints(json!([{"kind": "strip_headers", "names": ["Authorization"]}])),
                1024
            )
            .is_err()
        );
    }

    #[test]
    fn unmet_constraints_fail() {
        let text = Action::from_evaluation(&evaluation("POST", "/x", b"not json"));
        let path = constraints(json!([{"kind": "redact", "paths": ["/a"]}]));
        assert!(
            apply(&text, &path, 1024).is_err(),
            "a path into a non-JSON body"
        );
        let narrow = constraints(json!([{"kind": "narrow", "tool": "pay", "drop": ["x"]}]));
        assert!(
            apply(&action(&json!({"a": 1}), &[]), &narrow, 1024).is_err(),
            "no tool call"
        );
        let big = action(&json!({"a": "jane@example.com"}), &[]);
        let redact = constraints(json!([{"kind": "redact", "findings": ["email"]}]));
        assert!(apply(&big, &redact, 8).is_err(), "over the size limit");
    }

    /// What Core sends today (seen on the ash-barriers env): CONSTRAIN with
    /// `["run_in_sandbox"]`, met by the sandbox, the request unchanged.
    #[test]
    fn run_in_sandbox_is_already_met() {
        let parsed = parse(&json!(["run_in_sandbox"])).unwrap();
        assert_eq!(parsed, [Constraint::RunInSandbox]);
        let rewrite = apply(&action(&json!({"a": 1}), &[]), &parsed, 1024).unwrap();
        assert_eq!(rewrite.body, None);
        assert!(rewrite.remove_headers.is_empty());
        assert!(rewrite.applied.is_empty());
        assert!(parse(&json!(["encrypt_at_rest"])).is_err());
    }

    #[test]
    fn parse_refuses_what_cannot_be_met() {
        for bad in [
            json!({"kind": "redact"}),
            json!([{"kind": "redact"}]),
            json!([{"kind": "redact", "paths": ["a.b"]}]),
            json!([{"kind": "redact", "findings": ["dna"]}]),
            json!([{"kind": "narrow", "tool": "x"}]),
            json!([{"kind": "strip_headers", "names": []}]),
            json!([{"kind": "rewrite_url"}]),
        ] {
            assert!(parse(&bad).is_err(), "{bad}");
        }
    }
}
