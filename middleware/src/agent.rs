//! The agent's own steps, read from its calls to its model provider.
//!
//! `OpenShell` sees HTTP requests; the agent SDK reports model calls and tool
//! calls. The model call carries both: its request is the conversation so far
//! (the tools the model asked for and the results the agent sends back), and
//! its reply says which tools the model wants next. Sessions follow the
//! agent SDK's activity pattern from these:
//!
//! - each model call is an `llm_call` activity: the user's prompt in, the
//!   model, token usage, completion and whether it asked for tools out
//!   ([`Reply::output`])
//! - each tool the model asks for is an activity named by the tool, opened
//!   when the reply asks for it and closed with the result the agent sends
//!   on its next model call
//!
//! Provider APIs are recognised by path and body shape on any host, as in
//! [`crate::prompt`]: Anthropic Messages, `OpenAI` Chat Completions and
//! `OpenAI` Responses. Replies are read whole (JSON) or streamed (SSE).

use serde_json::{Map, Value, json};

use crate::action::Action;

/// A model provider API.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Api {
    Anthropic,
    OpenAiChat,
    OpenAiResponses,
}

impl Api {
    /// The API a request calls, by path. The body decides whether it is a
    /// model call ([`model_call`]).
    pub fn of(action: &Action) -> Option<Self> {
        if action.method != "POST" {
            return None;
        }
        let path = action.path.trim_end_matches('/');
        if path.ends_with("/v1/messages") {
            Some(Self::Anthropic)
        } else if path.ends_with("/chat/completions") {
            Some(Self::OpenAiChat)
        } else if path.ends_with("/v1/responses") {
            Some(Self::OpenAiResponses)
        } else {
            None
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Anthropic => "anthropic",
            Self::OpenAiChat => "openai_chat",
            Self::OpenAiResponses => "openai_responses",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        [Self::Anthropic, Self::OpenAiChat, Self::OpenAiResponses]
            .into_iter()
            .find(|api| api.name() == name)
    }
}

/// A tool the model asked for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolCall {
    /// The provider's call id (`tool_use.id`, `tool_calls[].id`, `call_id`).
    pub id: String,
    pub name: String,
    pub input: Value,
}

/// A tool's result, as the agent sends it back to the model.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolResult {
    pub id: String,
    pub output: Value,
    pub is_error: bool,
}

/// What a model call's request says about the agent's tools.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelCall {
    pub api: Api,
    /// Every tool call in the conversation, so a tool whose call the reply
    /// did not show can still be recorded when its result arrives.
    pub tool_calls: Vec<ToolCall>,
    /// Every tool result in the conversation.
    pub tool_results: Vec<ToolResult>,
}

impl ModelCall {
    pub fn tool_call(&self, id: &str) -> Option<&ToolCall> {
        self.tool_calls.iter().find(|call| call.id == id)
    }
}

/// The model call in a request, if it is one.
pub fn model_call(action: &Action) -> Option<ModelCall> {
    let api = Api::of(action)?;
    let body: Value = serde_json::from_slice(&action.body).ok()?;
    let (tool_calls, tool_results) = match api {
        Api::Anthropic => anthropic_tools(body.get("messages")?.as_array()?),
        Api::OpenAiChat => chat_tools(body.get("messages")?.as_array()?),
        Api::OpenAiResponses => responses_tools(body.get("input")?),
    };
    Some(ModelCall {
        api,
        tool_calls,
        tool_results,
    })
}

/// What the model answered, as far as the reply could be read.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Reply {
    pub model: Option<String>,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub completion: Option<String>,
    pub tool_calls: Vec<ToolCall>,
}

impl Reply {
    /// The `llm_call` activity's output, with the agent SDK's keys.
    pub fn output(&self) -> Value {
        let total = match (self.input_tokens, self.output_tokens) {
            (None, None) => None,
            (input, output) => Some(input.unwrap_or(0) + output.unwrap_or(0)),
        };
        json!({
            "llm_model": self.model,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "total_tokens": total,
            "completion": self.completion,
            "has_tool_calls": !self.tool_calls.is_empty(),
        })
    }
}

/// Reads a model's reply: a JSON document, or a server-sent event stream. A
/// stream cut short still yields what arrived. `None` when the body is
/// neither (an HTML error page, say).
pub fn parse_reply(api: Api, body: &[u8]) -> Option<Reply> {
    let text = std::str::from_utf8(body).ok()?;
    let start = text.trim_start();
    if start.starts_with("event:") || start.starts_with("data:") {
        let events = sse_data(text);
        return Some(match api {
            Api::Anthropic => anthropic_stream(&events),
            Api::OpenAiChat => chat_stream(&events),
            Api::OpenAiResponses => responses_stream(&events),
        });
    }
    let value: Value = serde_json::from_str(start).ok()?;
    match api {
        Api::Anthropic => anthropic_reply(&value),
        Api::OpenAiChat => chat_reply(&value),
        Api::OpenAiResponses => responses_reply(&value),
    }
}

// ── requests ────────────────────────────────────────────────────────────────

fn anthropic_tools(messages: &[Value]) -> (Vec<ToolCall>, Vec<ToolResult>) {
    let mut calls = Vec::new();
    let mut results = Vec::new();
    for block in messages
        .iter()
        .filter_map(|message| message.get("content").and_then(Value::as_array))
        .flatten()
    {
        match block.get("type").and_then(Value::as_str) {
            Some("tool_use") => calls.extend(tool_call(
                block.get("id"),
                block.get("name"),
                block.get("input").cloned(),
            )),
            Some("tool_result") => {
                if let Some(id) = block.get("tool_use_id").and_then(Value::as_str) {
                    results.push(ToolResult {
                        id: id.to_owned(),
                        output: content_value(block.get("content")),
                        is_error: block.get("is_error").and_then(Value::as_bool) == Some(true),
                    });
                }
            }
            _ => {}
        }
    }
    (calls, results)
}

fn chat_tools(messages: &[Value]) -> (Vec<ToolCall>, Vec<ToolResult>) {
    let mut calls = Vec::new();
    let mut results = Vec::new();
    for message in messages {
        for call in message
            .get("tool_calls")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let function = call.get("function");
            calls.extend(tool_call(
                call.get("id"),
                function.and_then(|function| function.get("name")),
                function
                    .and_then(|function| function.get("arguments"))
                    .map(arguments),
            ));
        }
        if message.get("role").and_then(Value::as_str) == Some("tool")
            && let Some(id) = message.get("tool_call_id").and_then(Value::as_str)
        {
            results.push(ToolResult {
                id: id.to_owned(),
                output: content_value(message.get("content")),
                is_error: false,
            });
        }
    }
    (calls, results)
}

fn responses_tools(input: &Value) -> (Vec<ToolCall>, Vec<ToolResult>) {
    let mut calls = Vec::new();
    let mut results = Vec::new();
    for item in input.as_array().into_iter().flatten() {
        match item.get("type").and_then(Value::as_str) {
            Some("function_call") => calls.extend(tool_call(
                item.get("call_id"),
                item.get("name"),
                item.get("arguments").map(arguments),
            )),
            Some("function_call_output") => {
                if let Some(id) = item.get("call_id").and_then(Value::as_str) {
                    results.push(ToolResult {
                        id: id.to_owned(),
                        output: content_value(item.get("output")),
                        is_error: false,
                    });
                }
            }
            _ => {}
        }
    }
    (calls, results)
}

fn tool_call(id: Option<&Value>, name: Option<&Value>, input: Option<Value>) -> Option<ToolCall> {
    Some(ToolCall {
        id: id?.as_str()?.to_owned(),
        name: name?.as_str()?.to_owned(),
        input: input.unwrap_or_else(|| json!({})),
    })
}

/// `OpenAI` sends tool arguments as a JSON string; keep the string when it is
/// not JSON.
fn arguments(value: &Value) -> Value {
    match value.as_str() {
        Some(text) if text.trim().is_empty() => json!({}),
        Some(text) => serde_json::from_str(text).unwrap_or_else(|_| value.clone()),
        None => value.clone(),
    }
}

/// A tool result's content: a string as is, text blocks joined, anything
/// else as sent.
fn content_value(content: Option<&Value>) -> Value {
    let Some(content) = content else {
        return Value::Null;
    };
    if let Some(blocks) = content.as_array() {
        let texts: Vec<&str> = blocks
            .iter()
            .filter(|block| {
                matches!(
                    block.get("type").and_then(Value::as_str),
                    Some("text" | "input_text" | "output_text")
                )
            })
            .filter_map(|block| block.get("text").and_then(Value::as_str))
            .collect();
        if texts.len() == blocks.len() && !texts.is_empty() {
            return Value::String(texts.join("\n"));
        }
    }
    content.clone()
}

// ── whole replies ───────────────────────────────────────────────────────────

fn anthropic_reply(value: &Value) -> Option<Reply> {
    let content = value.get("content")?.as_array()?;
    let mut reply = Reply {
        model: string(value.get("model")),
        input_tokens: number(value.pointer("/usage/input_tokens")),
        output_tokens: number(value.pointer("/usage/output_tokens")),
        ..Reply::default()
    };
    let mut texts = Vec::new();
    for block in content {
        match block.get("type").and_then(Value::as_str) {
            Some("text") => texts.extend(string(block.get("text"))),
            Some("tool_use") => reply.tool_calls.extend(tool_call(
                block.get("id"),
                block.get("name"),
                block.get("input").cloned(),
            )),
            _ => {}
        }
    }
    reply.completion = joined(texts);
    Some(reply)
}

fn chat_reply(value: &Value) -> Option<Reply> {
    let message = value.pointer("/choices/0/message")?;
    let (calls, _) = chat_tools(std::slice::from_ref(message));
    Some(Reply {
        model: string(value.get("model")),
        input_tokens: number(value.pointer("/usage/prompt_tokens")),
        output_tokens: number(value.pointer("/usage/completion_tokens")),
        completion: match message.get("content") {
            Some(Value::String(text)) if !text.is_empty() => Some(text.clone()),
            Some(Value::Array(parts)) => joined(
                parts
                    .iter()
                    .filter_map(|part| string(part.get("text")))
                    .collect(),
            ),
            _ => None,
        },
        tool_calls: calls,
    })
}

fn responses_reply(value: &Value) -> Option<Reply> {
    let output = value.get("output")?.as_array()?;
    let mut reply = Reply {
        model: string(value.get("model")),
        input_tokens: number(value.pointer("/usage/input_tokens")),
        output_tokens: number(value.pointer("/usage/output_tokens")),
        ..Reply::default()
    };
    let mut texts = Vec::new();
    for item in output {
        match item.get("type").and_then(Value::as_str) {
            Some("message") => texts.extend(
                item.get("content")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter(|part| part.get("type").and_then(Value::as_str) == Some("output_text"))
                    .filter_map(|part| string(part.get("text"))),
            ),
            Some("function_call") => reply.tool_calls.extend(tool_call(
                item.get("call_id"),
                item.get("name"),
                item.get("arguments").map(arguments),
            )),
            _ => {}
        }
    }
    reply.completion = joined(texts);
    Some(reply)
}

// ── streamed replies ────────────────────────────────────────────────────────

/// The JSON `data:` payloads of a server-sent event stream, in order. Lines
/// of one event are joined; `[DONE]` and payloads that are not JSON (a cut
/// final event) are dropped.
fn sse_data(text: &str) -> Vec<Value> {
    let mut events = Vec::new();
    let mut data = String::new();
    let mut flush = |data: &mut String| {
        if !data.is_empty() {
            if let Ok(value) = serde_json::from_str(data) {
                events.push(value);
            }
            data.clear();
        }
    };
    for line in text.lines() {
        if line.is_empty() {
            flush(&mut data);
        } else if let Some(payload) = line.strip_prefix("data:") {
            if !data.is_empty() {
                data.push('\n');
            }
            data.push_str(payload.strip_prefix(' ').unwrap_or(payload));
        }
    }
    flush(&mut data);
    events
}

/// A content block being streamed: text, or a tool call whose input arrives
/// as JSON fragments.
enum Block {
    Text(String),
    Tool {
        id: String,
        name: String,
        json: String,
    },
}

fn anthropic_stream(events: &[Value]) -> Reply {
    let mut reply = Reply::default();
    let mut blocks: Vec<(u64, Block)> = Vec::new();
    for event in events {
        match event.get("type").and_then(Value::as_str) {
            Some("message_start") => {
                reply.model = string(event.pointer("/message/model"));
                reply.input_tokens = number(event.pointer("/message/usage/input_tokens"));
                reply.output_tokens = number(event.pointer("/message/usage/output_tokens"));
            }
            Some("content_block_start") => {
                let index = number(event.get("index")).unwrap_or(0);
                let block = event.get("content_block");
                match block
                    .and_then(|block| block.get("type"))
                    .and_then(Value::as_str)
                {
                    Some("text") => blocks.push((
                        index,
                        Block::Text(
                            string(block.and_then(|block| block.get("text"))).unwrap_or_default(),
                        ),
                    )),
                    Some("tool_use") => blocks.push((
                        index,
                        Block::Tool {
                            id: string(block.and_then(|block| block.get("id"))).unwrap_or_default(),
                            name: string(block.and_then(|block| block.get("name")))
                                .unwrap_or_default(),
                            json: String::new(),
                        },
                    )),
                    _ => {}
                }
            }
            Some("content_block_delta") => {
                let index = number(event.get("index")).unwrap_or(0);
                let Some((_, block)) = blocks.iter_mut().find(|(at, _)| *at == index) else {
                    continue;
                };
                match (block, event.pointer("/delta/type").and_then(Value::as_str)) {
                    (Block::Text(text), Some("text_delta")) => {
                        text.push_str(
                            event
                                .pointer("/delta/text")
                                .and_then(Value::as_str)
                                .unwrap_or(""),
                        );
                    }
                    (Block::Tool { json, .. }, Some("input_json_delta")) => {
                        json.push_str(
                            event
                                .pointer("/delta/partial_json")
                                .and_then(Value::as_str)
                                .unwrap_or(""),
                        );
                    }
                    _ => {}
                }
            }
            Some("message_delta") => {
                if let Some(output) = number(event.pointer("/usage/output_tokens")) {
                    reply.output_tokens = Some(output);
                }
                if let Some(input) = number(event.pointer("/usage/input_tokens")) {
                    reply.input_tokens = Some(input);
                }
            }
            _ => {}
        }
    }
    finish(&mut reply, blocks.into_iter().map(|(_, block)| block));
    reply
}

fn chat_stream(events: &[Value]) -> Reply {
    let mut reply = Reply::default();
    let mut text = String::new();
    let mut tools: Vec<(u64, Block)> = Vec::new();
    for event in events {
        if reply.model.is_none() {
            reply.model = string(event.get("model"));
        }
        if let Some(usage) = event.get("usage").filter(|usage| usage.is_object()) {
            reply.input_tokens = number(usage.get("prompt_tokens"));
            reply.output_tokens = number(usage.get("completion_tokens"));
        }
        let Some(delta) = event.pointer("/choices/0/delta") else {
            continue;
        };
        if let Some(content) = delta.get("content").and_then(Value::as_str) {
            text.push_str(content);
        }
        for call in delta
            .get("tool_calls")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let index = number(call.get("index")).unwrap_or(0);
            if !tools.iter().any(|(at, _)| *at == index) {
                tools.push((
                    index,
                    Block::Tool {
                        id: String::new(),
                        name: String::new(),
                        json: String::new(),
                    },
                ));
            }
            if let Some((_, Block::Tool { id, name, json })) =
                tools.iter_mut().find(|(at, _)| *at == index)
            {
                if let Some(value) = call.get("id").and_then(Value::as_str) {
                    value.clone_into(id);
                }
                if let Some(value) = call.pointer("/function/name").and_then(Value::as_str) {
                    name.push_str(value);
                }
                if let Some(value) = call.pointer("/function/arguments").and_then(Value::as_str) {
                    json.push_str(value);
                }
            }
        }
    }
    let blocks = std::iter::once(Block::Text(text)).chain(tools.into_iter().map(|(_, tool)| tool));
    finish(&mut reply, blocks);
    reply
}

fn responses_stream(events: &[Value]) -> Reply {
    if let Some(reply) = events
        .iter()
        .filter(|event| event.get("type").and_then(Value::as_str) == Some("response.completed"))
        .find_map(|event| event.get("response").and_then(responses_reply))
    {
        return reply;
    }
    // Cut short: the text that streamed so far.
    let mut reply = Reply::default();
    let mut text = String::new();
    for event in events {
        match event.get("type").and_then(Value::as_str) {
            Some("response.created") => reply.model = string(event.pointer("/response/model")),
            Some("response.output_text.delta") => {
                text.push_str(event.get("delta").and_then(Value::as_str).unwrap_or(""));
            }
            _ => {}
        }
    }
    reply.completion = joined(vec![text]);
    reply
}

fn finish(reply: &mut Reply, blocks: impl Iterator<Item = Block>) {
    let mut texts = Vec::new();
    for block in blocks {
        match block {
            Block::Text(text) => texts.push(text),
            Block::Tool { id, name, json } if !id.is_empty() && !name.is_empty() => {
                reply.tool_calls.push(ToolCall {
                    id,
                    name,
                    input: arguments(&Value::String(json)),
                });
            }
            Block::Tool { .. } => {}
        }
    }
    reply.completion = joined(texts);
}

// ── helpers ─────────────────────────────────────────────────────────────────

/// Text parts joined with a space, as the agent SDK joins them; `None` when
/// there is no text.
fn joined(texts: Vec<String>) -> Option<String> {
    let texts: Vec<String> = texts.into_iter().filter(|text| !text.is_empty()).collect();
    (!texts.is_empty()).then(|| texts.join(" "))
}

fn string(value: Option<&Value>) -> Option<String> {
    value.and_then(Value::as_str).map(str::to_owned)
}

fn number(value: Option<&Value>) -> Option<u64> {
    value.and_then(Value::as_u64)
}

/// Response headers as a JSON object, credentials redacted the way the agent
/// SDK redacts them (`OpenShell` already withholds the ones it injects).
pub fn headers_object<'a>(headers: impl Iterator<Item = (&'a str, &'a str)>) -> Value {
    const REDACTED: [&str; 6] = [
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "api-key",
    ];
    let mut object = Map::new();
    for (name, value) in headers {
        let name = name.to_ascii_lowercase();
        let value = if REDACTED.contains(&name.as_str()) {
            "[REDACTED]"
        } else {
            value
        };
        match object.get_mut(&name) {
            Some(Value::String(existing)) => {
                existing.push_str(", ");
                existing.push_str(value);
            }
            _ => {
                object.insert(name, Value::String(value.to_owned()));
            }
        }
    }
    Value::Object(object)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::tests::evaluation;

    fn call(path: &str, body: &Value) -> Action {
        Action::from_evaluation(&evaluation("POST", path, body.to_string().as_bytes()))
    }

    #[test]
    fn anthropic_conversation_tools() {
        let action = call(
            "/v1/messages",
            &json!({"model": "claude", "messages": [
                {"role": "user", "content": "weather?"},
                {"role": "assistant", "content": [
                    {"type": "text", "text": "Checking."},
                    {"type": "tool_use", "id": "toolu_1", "name": "get_weather", "input": {"city": "Paris"}}
                ]},
                {"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "toolu_1", "content": [{"type": "text", "text": "18C"}]}
                ]}
            ]}),
        );
        let model = model_call(&action).unwrap();
        assert_eq!(model.api, Api::Anthropic);
        assert_eq!(
            model.tool_calls,
            vec![ToolCall {
                id: "toolu_1".to_owned(),
                name: "get_weather".to_owned(),
                input: json!({"city": "Paris"}),
            }]
        );
        assert_eq!(model.tool_results[0].id, "toolu_1");
        assert_eq!(model.tool_results[0].output, json!("18C"));
    }

    #[test]
    fn openai_chat_and_responses_conversation_tools() {
        let chat = model_call(&call(
            "/v1/chat/completions",
            &json!({"messages": [
                {"role": "user", "content": "weather?"},
                {"role": "assistant", "content": null, "tool_calls": [
                    {"id": "call_1", "type": "function", "function": {"name": "get_weather", "arguments": "{\"city\":\"Paris\"}"}}
                ]},
                {"role": "tool", "tool_call_id": "call_1", "content": "18C"}
            ]}),
        ))
        .unwrap();
        assert_eq!(chat.tool_calls[0].input, json!({"city": "Paris"}));
        assert_eq!(chat.tool_results[0].output, json!("18C"));

        let responses = model_call(&call(
            "/v1/responses",
            &json!({"input": [
                {"role": "user", "content": "weather?"},
                {"type": "function_call", "call_id": "call_2", "name": "get_weather", "arguments": "{}"},
                {"type": "function_call_output", "call_id": "call_2", "output": "18C"}
            ]}),
        ))
        .unwrap();
        assert_eq!(responses.tool_call("call_2").unwrap().name, "get_weather");
        assert_eq!(responses.tool_results[0].output, json!("18C"));
    }

    #[test]
    fn not_a_model_call() {
        assert!(model_call(&call("/v1/messages", &json!({"no": "messages"}))).is_none());
        assert!(model_call(&call("/api/things", &json!({"messages": []}))).is_none());
        let get = Action::from_evaluation(&evaluation("GET", "/v1/messages", b""));
        assert!(model_call(&get).is_none());
    }

    #[test]
    fn anthropic_whole_and_streamed_replies_agree() {
        let whole = json!({"model": "claude-x", "content": [
            {"type": "text", "text": "Let me check."},
            {"type": "tool_use", "id": "toolu_9", "name": "fetch", "input": {"url": "http://example.com/"}}
        ], "usage": {"input_tokens": 12, "output_tokens": 7}});
        let stream = concat!(
            "event: message_start\n",
            "data: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-x\",\"usage\":{\"input_tokens\":12,\"output_tokens\":1}}}\n\n",
            "event: content_block_start\n",
            "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Let me \"}}\n\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"check.\"}}\n\n",
            "data: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_9\",\"name\":\"fetch\",\"input\":{}}}\n\n",
            "data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"url\\\": \\\"http://exa\"}}\n\n",
            "data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"mple.com/\\\"}\"}}\n\n",
            "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"output_tokens\":7}}\n\n",
            "data: {\"type\":\"message_stop\"}\n\n",
        );
        let expected = Reply {
            model: Some("claude-x".to_owned()),
            input_tokens: Some(12),
            output_tokens: Some(7),
            completion: Some("Let me check.".to_owned()),
            tool_calls: vec![ToolCall {
                id: "toolu_9".to_owned(),
                name: "fetch".to_owned(),
                input: json!({"url": "http://example.com/"}),
            }],
        };
        assert_eq!(
            parse_reply(Api::Anthropic, whole.to_string().as_bytes()).unwrap(),
            expected
        );
        assert_eq!(
            parse_reply(Api::Anthropic, stream.as_bytes()).unwrap(),
            expected
        );
        assert_eq!(
            expected.output(),
            json!({"llm_model": "claude-x", "input_tokens": 12, "output_tokens": 7,
                   "total_tokens": 19, "completion": "Let me check.", "has_tool_calls": true})
        );
    }

    #[test]
    fn openai_chat_whole_and_streamed_replies() {
        let whole = json!({"model": "gpt-x", "choices": [{"message": {"role": "assistant",
            "content": null, "tool_calls": [{"id": "call_1", "type": "function",
            "function": {"name": "get_weather", "arguments": "{\"city\":\"Paris\"}"}}]}}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 3}});
        let reply = parse_reply(Api::OpenAiChat, whole.to_string().as_bytes()).unwrap();
        assert_eq!(reply.tool_calls[0].input, json!({"city": "Paris"}));
        assert_eq!(reply.completion, None);
        assert_eq!(reply.output()["total_tokens"], 8);

        let stream = concat!(
            "data: {\"model\":\"gpt-x\",\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}\n\n",
            "data: {\"model\":\"gpt-x\",\"choices\":[{\"delta\":{\"content\":\"lo\"}}]}\n\n",
            "data: {\"model\":\"gpt-x\",\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_2\",\"function\":{\"name\":\"search\",\"arguments\":\"{\\\"q\\\":\"}}]}}]}\n\n",
            "data: {\"model\":\"gpt-x\",\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"\\\"x\\\"}\"}}]}}]}\n\n",
            "data: {\"model\":\"gpt-x\",\"choices\":[],\"usage\":{\"prompt_tokens\":4,\"completion_tokens\":2}}\n\n",
            "data: [DONE]\n\n",
        );
        let reply = parse_reply(Api::OpenAiChat, stream.as_bytes()).unwrap();
        assert_eq!(reply.completion.as_deref(), Some("Hello"));
        assert_eq!(reply.tool_calls[0].name, "search");
        assert_eq!(reply.tool_calls[0].input, json!({"q": "x"}));
        assert_eq!(
            (reply.input_tokens, reply.output_tokens),
            (Some(4), Some(2))
        );
    }

    #[test]
    fn openai_responses_whole_and_streamed_replies() {
        let response = json!({"model": "gpt-r", "output": [
            {"type": "message", "content": [{"type": "output_text", "text": "Done."}]},
            {"type": "function_call", "call_id": "call_3", "name": "lookup", "arguments": "{\"id\":1}"}
        ], "usage": {"input_tokens": 9, "output_tokens": 4}});
        let reply = parse_reply(Api::OpenAiResponses, response.to_string().as_bytes()).unwrap();
        assert_eq!(reply.completion.as_deref(), Some("Done."));
        assert_eq!(reply.tool_calls[0].id, "call_3");
        let stream = format!(
            "event: response.output_text.delta\ndata: {}\n\nevent: response.completed\ndata: {}\n\n",
            json!({"type": "response.output_text.delta", "delta": "Done."}),
            json!({"type": "response.completed", "response": response}),
        );
        assert_eq!(
            parse_reply(Api::OpenAiResponses, stream.as_bytes()).unwrap(),
            reply
        );
    }

    #[test]
    fn a_reply_cut_short_or_not_a_reply() {
        let cut = "data: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-x\"}}\n\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"Hi\"}}\n\ndata: {\"type\":\"content_bl";
        let reply = parse_reply(Api::Anthropic, cut.as_bytes()).unwrap();
        assert_eq!(reply.completion.as_deref(), Some("Hi"));
        assert!(parse_reply(Api::Anthropic, b"<html>405</html>").is_none());
        assert!(parse_reply(Api::Anthropic, b"").is_none());
    }

    #[test]
    fn headers_are_redacted_and_merged() {
        let headers = headers_object(
            [
                ("Content-Type", "application/json"),
                ("Set-Cookie", "a=1"),
                ("Vary", "Accept"),
                ("vary", "Origin"),
            ]
            .into_iter(),
        );
        assert_eq!(
            headers,
            json!({"content-type": "application/json", "set-cookie": "[REDACTED]", "vary": "Accept, Origin"})
        );
    }
}
