//! What an outbound request is trying to do, derived from one
//! `HttpRequestEvaluation`, and the deterministic fingerprint that ties an
//! approval to exactly that action.
//!
//! MCP traffic is recognised by its JSON-RPC 2.0 envelope rather than by
//! path, since servers mount MCP anywhere. A `tools/call` exposes the tool
//! name and arguments; any other JSON-RPC method is still described by
//! method so it gets method-level treatment. Bodies that are not JSON-RPC
//! fall back to the HTTP surface (method, host, path) and never fail the
//! evaluation.

use openshell_core::proto::HttpRequestEvaluation;
use serde_json::Value;
use sha2::{Digest as _, Sha256};

/// One JSON-RPC call found in the request body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RpcCall {
    pub method: String,
    /// `params.name` for `tools/call`.
    pub tool: Option<String>,
    /// `params.arguments` for `tools/call`, or the whole `params` otherwise.
    pub arguments: Option<Value>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Payload {
    /// No body.
    Empty,
    /// A JSON-RPC 2.0 request or batch (MCP or other JSON-RPC).
    JsonRpc(Vec<RpcCall>),
    /// A JSON document that is not JSON-RPC.
    Json,
    /// Anything else, described only by size.
    Opaque,
}

/// The evaluated action, stripped of anything `OpenShell` withheld (credentials,
/// routing and framing headers never reach the middleware).
///
/// The body lives only in memory for the duration of one evaluation; `Debug`
/// omits it and the RPC arguments so request content never reaches logs.
#[derive(Clone, Eq, PartialEq)]
pub struct Action {
    pub request_id: String,
    pub sandbox_id: String,
    pub sandbox_name: String,
    pub workspace: String,
    pub process_binary: Option<String>,
    pub process_ancestors: Vec<String>,
    pub scheme: String,
    pub host: String,
    pub port: u32,
    pub method: String,
    pub path: String,
    pub query: String,
    pub content_type: Option<String>,
    pub body_bytes: usize,
    pub body: Vec<u8>,
    pub payload: Payload,
    /// Deterministic identity used to match a retry to an approval.
    pub fingerprint: String,
}

impl core::fmt::Debug for Action {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Action")
            .field("request_id", &self.request_id)
            .field("sandbox_id", &self.sandbox_id)
            .field("method", &self.method)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("path", &self.path)
            .field("body_bytes", &self.body_bytes)
            .field("tools", &self.tools())
            .field("fingerprint", &self.fingerprint)
            .finish_non_exhaustive()
    }
}

impl Action {
    pub fn from_evaluation(evaluation: &HttpRequestEvaluation) -> Self {
        let context = evaluation.context.clone().unwrap_or_default();
        let target = evaluation.target.clone().unwrap_or_default();
        let process = context.originating_process.unwrap_or_default();
        let content_type = evaluation
            .headers
            .iter()
            .find(|header| header.name == "content-type")
            .map(|header| header.value.clone());
        let parsed = parse_json(&evaluation.body);
        let payload = classify(&evaluation.body, parsed.as_ref());
        let fingerprint = fingerprint(
            &context.sandbox_id,
            &target.scheme,
            &target.host,
            target.port,
            &target.method,
            &target.path,
            &target.query,
            &evaluation.body,
            parsed.as_ref(),
        );
        Self {
            request_id: context.request_id,
            sandbox_id: context.sandbox_id,
            sandbox_name: context.sandbox,
            workspace: context.workspace,
            process_binary: (!process.binary.is_empty()).then_some(process.binary),
            process_ancestors: process.ancestors,
            scheme: target.scheme,
            host: target.host,
            port: target.port,
            method: target.method,
            path: target.path,
            query: target.query,
            content_type,
            body_bytes: evaluation.body.len(),
            body: evaluation.body.clone(),
            payload,
            fingerprint,
        }
    }

    /// Tool names of every MCP `tools/call` in the request.
    pub fn tools(&self) -> Vec<&str> {
        match &self.payload {
            Payload::JsonRpc(calls) => calls
                .iter()
                .filter_map(|call| call.tool.as_deref())
                .collect(),
            _ => Vec::new(),
        }
    }
}

fn parse_json(body: &[u8]) -> Option<Value> {
    let first = body.iter().find(|byte| !byte.is_ascii_whitespace())?;
    if *first != b'{' && *first != b'[' {
        return None;
    }
    serde_json::from_slice(body).ok()
}

fn classify(body: &[u8], parsed: Option<&Value>) -> Payload {
    if body.is_empty() {
        return Payload::Empty;
    }
    let Some(value) = parsed else {
        return Payload::Opaque;
    };
    let calls: Option<Vec<RpcCall>> = match value {
        Value::Array(items) if !items.is_empty() => items.iter().map(rpc_call).collect(),
        Value::Object(_) => rpc_call(value).map(|call| vec![call]),
        _ => None,
    };
    calls.map_or(Payload::Json, Payload::JsonRpc)
}

fn rpc_call(value: &Value) -> Option<RpcCall> {
    let object = value.as_object()?;
    if object.get("jsonrpc")?.as_str()? != "2.0" {
        return None;
    }
    let method = object.get("method")?.as_str()?.to_owned();
    let params = object.get("params");
    if method == "tools/call" {
        return Some(RpcCall {
            method,
            tool: params
                .and_then(|params| params.get("name"))
                .and_then(Value::as_str)
                .map(str::to_owned),
            arguments: params.and_then(|params| params.get("arguments")).cloned(),
        });
    }
    Some(RpcCall {
        method,
        tool: None,
        arguments: params.cloned(),
    })
}

/// Deterministic action identity for approval matching.
///
/// Covers the sandbox, the full request target and the body. Excluded, because
/// they differ between an original attempt and its retry without changing what
/// the action does: `request_id`, every header (dates, trace ids, nonces), and
/// the JSON-RPC `id`. JSON bodies are hashed in a canonical form with object
/// keys sorted, so key order does not matter; array order does. A body that
/// is not JSON is hashed byte for byte.
#[allow(clippy::too_many_arguments)]
fn fingerprint(
    sandbox_id: &str,
    scheme: &str,
    host: &str,
    port: u32,
    method: &str,
    path: &str,
    query: &str,
    body: &[u8],
    parsed: Option<&Value>,
) -> String {
    let mut hasher = Sha256::new();
    for field in [
        "openbox-approval-v1",
        sandbox_id,
        &scheme.to_ascii_lowercase(),
        &host.to_ascii_lowercase(),
        &port.to_string(),
        &method.to_ascii_uppercase(),
        path,
        query,
    ] {
        hasher.update((field.len() as u64).to_le_bytes());
        hasher.update(field.as_bytes());
    }
    if let Some(value) = parsed {
        let mut canonical = String::new();
        write_canonical(&strip_rpc_ids(value), &mut canonical);
        hasher.update(b"json");
        hasher.update(canonical.as_bytes());
    } else {
        hasher.update(b"raw");
        hasher.update(body);
    }
    hasher
        .finalize()
        .iter()
        .fold(String::with_capacity(64), |mut out, byte| {
            use std::fmt::Write as _;
            let _ = write!(out, "{byte:02x}");
            out
        })
}

fn strip_rpc_ids(value: &Value) -> Value {
    let strip = |item: &Value| {
        let mut item = item.clone();
        if let Some(object) = item.as_object_mut()
            && object.get("jsonrpc").and_then(Value::as_str) == Some("2.0")
        {
            object.remove("id");
        }
        item
    };
    match value {
        Value::Array(items) => Value::Array(items.iter().map(strip).collect()),
        other => strip(other),
    }
}

fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Object(object) => {
            let mut keys: Vec<&String> = object.keys().collect();
            keys.sort();
            out.push('{');
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String(key.clone()).to_string());
                out.push(':');
                write_canonical(&object[key], out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        scalar => out.push_str(&scalar.to_string()),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use openshell_core::proto::{HttpHeader, HttpRequestTarget, Process, RequestContext};

    pub fn evaluation(method: &str, path: &str, body: &[u8]) -> HttpRequestEvaluation {
        HttpRequestEvaluation {
            context: Some(RequestContext {
                request_id: "req-1".to_owned(),
                sandbox_id: "sbx-id-1".to_owned(),
                sandbox: "sbx-name".to_owned(),
                originating_process: Some(Process {
                    binary: "/usr/bin/python3".to_owned(),
                    pid: 42,
                    ancestors: vec!["/bin/sh".to_owned()],
                }),
                workspace: "default".to_owned(),
            }),
            target: Some(HttpRequestTarget {
                scheme: "https".to_owned(),
                host: "mcp.example.com".to_owned(),
                port: 443,
                method: method.to_owned(),
                path: path.to_owned(),
                query: String::new(),
            }),
            headers: vec![HttpHeader {
                name: "content-type".to_owned(),
                value: "application/json".to_owned(),
            }],
            body: body.to_vec(),
            ..HttpRequestEvaluation::default()
        }
    }

    #[test]
    fn describes_an_mcp_tool_call() {
        let body = br#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"delete_database","arguments":{"name":"prod","force":true}}}"#;
        let action = Action::from_evaluation(&evaluation("POST", "/mcp", body));
        assert_eq!(action.tools(), ["delete_database"]);
        assert_eq!(action.sandbox_id, "sbx-id-1");
        assert_eq!(action.process_binary.as_deref(), Some("/usr/bin/python3"));
        let Payload::JsonRpc(calls) = &action.payload else {
            panic!("expected JSON-RPC");
        };
        assert_eq!(
            calls[0].arguments,
            Some(serde_json::json!({"name": "prod", "force": true}))
        );
    }

    #[test]
    fn describes_batches_and_other_rpc_methods() {
        let body = br#"[{"jsonrpc":"2.0","id":1,"method":"tools/list"},{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"search"}}]"#;
        let action = Action::from_evaluation(&evaluation("POST", "/", body));
        let Payload::JsonRpc(calls) = &action.payload else {
            panic!("expected JSON-RPC");
        };
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].method, "tools/list");
        assert_eq!(action.tools(), ["search"]);
    }

    #[test]
    fn falls_back_to_the_http_surface() {
        assert_eq!(
            Action::from_evaluation(&evaluation("GET", "/v1/items", b"")).payload,
            Payload::Empty
        );
        assert_eq!(
            Action::from_evaluation(&evaluation("POST", "/", br#"{"query":"x"}"#)).payload,
            Payload::Json
        );
        assert_eq!(
            Action::from_evaluation(&evaluation("POST", "/", b"{not json")).payload,
            Payload::Opaque
        );
        assert_eq!(
            Action::from_evaluation(&evaluation(
                "POST",
                "/",
                br#"{"jsonrpc":"1.0","method":"x"}"#
            ))
            .payload,
            Payload::Json
        );
        assert_eq!(
            Action::from_evaluation(&evaluation("POST", "/", &[0xff, 0xfe, 0x00])).payload,
            Payload::Opaque
        );
    }

    #[test]
    fn a_retry_with_a_new_rpc_id_and_reordered_keys_matches() {
        let first = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"pay","arguments":{"amount":10,"to":"acme"}}}"#;
        let retry = br#"{"params":{"arguments":{"to":"acme","amount":10},"name":"pay"},"method":"tools/call","id":"retry-2","jsonrpc":"2.0"}"#;
        let mut retry_eval = evaluation("POST", "/mcp", retry);
        retry_eval.context.as_mut().unwrap().request_id = "req-2".to_owned();
        retry_eval.headers.push(HttpHeader {
            name: "x-request-date".to_owned(),
            value: "later".to_owned(),
        });
        assert_eq!(
            Action::from_evaluation(&evaluation("POST", "/mcp", first)).fingerprint,
            Action::from_evaluation(&retry_eval).fingerprint
        );
    }

    #[test]
    fn a_changed_action_does_not_match() {
        let base = Action::from_evaluation(&evaluation(
            "POST",
            "/mcp",
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"pay","arguments":{"amount":10}}}"#,
        ))
        .fingerprint;
        let changed_amount = Action::from_evaluation(&evaluation(
            "POST",
            "/mcp",
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"pay","arguments":{"amount":1000}}}"#,
        ))
        .fingerprint;
        let changed_path = Action::from_evaluation(&evaluation(
            "POST",
            "/other",
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"pay","arguments":{"amount":10}}}"#,
        ))
        .fingerprint;
        let mut other_sandbox = evaluation(
            "POST",
            "/mcp",
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"pay","arguments":{"amount":10}}}"#,
        );
        other_sandbox.context.as_mut().unwrap().sandbox_id = "sbx-id-2".to_owned();
        assert_ne!(base, changed_amount);
        assert_ne!(base, changed_path);
        assert_ne!(base, Action::from_evaluation(&other_sandbox).fingerprint);
    }

    #[test]
    fn non_json_bodies_are_hashed_byte_for_byte() {
        let a = Action::from_evaluation(&evaluation("POST", "/", b"a=1&b=2")).fingerprint;
        let b = Action::from_evaluation(&evaluation("POST", "/", b"b=2&a=1")).fingerprint;
        assert_ne!(a, b);
        assert_eq!(a.len(), 64);
    }
}
