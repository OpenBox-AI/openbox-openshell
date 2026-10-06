//! The user's prompt, read from the agent's call to its model provider.
//!
//! `OpenShell` has no notion of a prompt, but the agent sends it to its model
//! provider, and that request reaches the door guard. Recognised by path and
//! body shape on any host, so proxies and gateways in front of a provider
//! still count:
//!
//! | Provider API            | Path ends in        | Conversation          |
//! |-------------------------|---------------------|-----------------------|
//! | Anthropic Messages      | `/v1/messages`      | `messages[]`          |
//! | `OpenAI` Chat Completions | `/chat/completions` | `messages[]`          |
//! | `OpenAI` Responses        | `/v1/responses`     | `input` (text or list)|
//!
//! The prompt is the newest user turn that carries text. A user message with
//! only tool results is the agent's own loop, not the user, so a model call
//! that ends in one has no prompt. Agents resend the whole conversation on
//! every call; [`Prompt::turn`] identifies the turn so it is signalled once.

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::action::Action;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prompt {
    /// `anthropic`, `openai`.
    pub provider: &'static str,
    pub model: Option<String>,
    pub text: String,
    /// Position among the conversation's user text turns (1-based) and the
    /// text, hashed: stable across the calls that resend this conversation.
    pub turn: String,
}

/// What Core receives for a prompt.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Capture {
    /// The prompt text, as the SDK sends it.
    #[default]
    Text,
    /// SHA-256 and length only.
    Hash,
    /// No prompt signals.
    Off,
}

impl Capture {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "text" => Some(Self::Text),
            "hash" => Some(Self::Hash),
            "off" => Some(Self::Off),
            _ => None,
        }
    }
}

/// The newest user prompt in a model call, if this is one and it has one.
pub fn extract(action: &Action) -> Option<Prompt> {
    if action.method != "POST" {
        return None;
    }
    let path = action.path.trim_end_matches('/');
    let body: Value = serde_json::from_slice(&action.body).ok()?;
    let (provider, turns) = if path.ends_with("/v1/messages") {
        (
            "anthropic",
            user_turns(body.get("messages")?, anthropic_text),
        )
    } else if path.ends_with("/chat/completions") {
        (
            "openai",
            user_turns(body.get("messages")?, openai_chat_text),
        )
    } else if path.ends_with("/v1/responses") {
        ("openai", responses_turns(body.get("input")?))
    } else {
        return None;
    };
    let position = turns.len();
    let text = turns.into_iter().last()??;
    let turn = hex(&Sha256::digest(format!("{position}\n{text}").as_bytes())[..16]);
    Some(Prompt {
        provider,
        model: body.get("model").and_then(Value::as_str).map(str::to_owned),
        text,
        turn,
    })
}

/// The signal's arguments for a prompt, as captured.
pub fn signal_args(prompt: &Prompt, capture: Capture, limit: usize) -> Value {
    let mut args = serde_json::json!({
        "provider": prompt.provider,
        "model": prompt.model,
        "chars": prompt.text.chars().count(),
    });
    match capture {
        Capture::Text => args["prompt"] = Value::String(truncate(&prompt.text, limit)),
        Capture::Hash | Capture::Off => {
            args["sha256"] = Value::String(hex(&Sha256::digest(prompt.text.as_bytes())));
        }
    }
    args
}

/// One entry per user message, in order: its text, or `None` when it carries
/// none (tool results only). Non-user messages are skipped.
fn user_turns(messages: &Value, text_of: fn(&Value) -> Option<String>) -> Vec<Option<String>> {
    messages
        .as_array()
        .into_iter()
        .flatten()
        .filter(|message| message.get("role").and_then(Value::as_str) == Some("user"))
        .map(|message| message.get("content").and_then(text_of))
        .collect()
}

/// Anthropic: a string, or blocks where only `text` blocks are the user's
/// words (`tool_result`, images and documents are not).
fn anthropic_text(content: &Value) -> Option<String> {
    blocks_text(content, &["text"])
}

/// `OpenAI` chat: a string, or parts where `text` parts are words. Tool
/// results arrive as `role: tool` and are not user turns at all.
fn openai_chat_text(content: &Value) -> Option<String> {
    blocks_text(content, &["text"])
}

/// `OpenAI` Responses: `input` is the prompt itself as a string, or a list of
/// items where user messages carry `input_text` parts.
fn responses_turns(input: &Value) -> Vec<Option<String>> {
    if let Some(text) = input.as_str() {
        return vec![non_empty(text.to_owned())];
    }
    input
        .as_array()
        .into_iter()
        .flatten()
        .filter(|item| {
            item.get("role").and_then(Value::as_str) == Some("user")
                && item
                    .get("type")
                    .and_then(Value::as_str)
                    .is_none_or(|kind| kind == "message")
        })
        .map(|item| {
            item.get("content")
                .and_then(|content| blocks_text(content, &["input_text", "text"]))
        })
        .collect()
}

fn blocks_text(content: &Value, kinds: &[&str]) -> Option<String> {
    if let Some(text) = content.as_str() {
        return non_empty(text.to_owned());
    }
    let parts: Vec<&str> = content
        .as_array()?
        .iter()
        .filter(|block| {
            block
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|kind| kinds.contains(&kind))
        })
        .filter_map(|block| block.get("text").and_then(Value::as_str))
        .collect();
    non_empty(parts.join("\n"))
}

fn non_empty(text: String) -> Option<String> {
    (!text.trim().is_empty()).then_some(text)
}

fn truncate(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_owned();
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
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

    fn call(path: &str, body: &Value) -> Action {
        Action::from_evaluation(&evaluation("POST", path, body.to_string().as_bytes()))
    }

    #[test]
    fn anthropic_messages() {
        let prompt = extract(&call(
            "/v1/messages",
            &json!({"model": "claude-x", "messages": [
                {"role": "user", "content": "refactor the payment module"}
            ]}),
        ))
        .unwrap();
        assert_eq!(prompt.provider, "anthropic");
        assert_eq!(prompt.model.as_deref(), Some("claude-x"));
        assert_eq!(prompt.text, "refactor the payment module");
    }

    #[test]
    fn a_tool_result_turn_is_the_agent_not_the_user() {
        let first = json!({"role": "user", "content": [{"type": "text", "text": "refactor it"}]});
        let looped = call(
            "/v1/messages",
            &json!({"messages": [
                first,
                {"role": "assistant", "content": [{"type": "tool_use", "id": "t1", "name": "read", "input": {}}]},
                {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1", "content": "file text"}]}
            ]}),
        );
        assert_eq!(extract(&looped), None);
        // The next real turn is a new prompt, and the first stays the same turn.
        let next = call(
            "/v1/messages",
            &json!({"messages": [
                first,
                {"role": "assistant", "content": "done"},
                {"role": "user", "content": "now add tests"}
            ]}),
        );
        let only_first = call("/v1/messages", &json!({"messages": [first]}));
        let (next, only_first) = (extract(&next).unwrap(), extract(&only_first).unwrap());
        assert_eq!(next.text, "now add tests");
        assert_ne!(next.turn, only_first.turn);
    }

    #[test]
    fn a_resent_conversation_is_the_same_turn() {
        let body = json!({"messages": [{"role": "user", "content": "hello"}]});
        let a = extract(&call("/v1/messages", &body)).unwrap();
        let b = extract(&call("/v1/messages", &body)).unwrap();
        assert_eq!(a.turn, b.turn);
        // The same words later in the conversation are a new turn.
        let again = extract(&call(
            "/v1/messages",
            &json!({"messages": [
                {"role": "user", "content": "hello"},
                {"role": "assistant", "content": "hi"},
                {"role": "user", "content": "hello"}
            ]}),
        ))
        .unwrap();
        assert_ne!(a.turn, again.turn);
    }

    #[test]
    fn openai_chat_and_responses() {
        let chat = extract(&call(
            "/v1/chat/completions",
            &json!({"model": "gpt-x", "messages": [
                {"role": "system", "content": "be brief"},
                {"role": "user", "content": [{"type": "text", "text": "summarise this"}]},
                {"role": "assistant", "content": null, "tool_calls": []},
                {"role": "tool", "content": "result"}
            ]}),
        ))
        .unwrap();
        assert_eq!(
            (chat.provider, chat.text.as_str()),
            ("openai", "summarise this")
        );
        let responses = extract(&call(
            "/v1/responses",
            &json!({"input": [{"role": "user", "content": [{"type": "input_text", "text": "plan a trip"}]}]}),
        ))
        .unwrap();
        assert_eq!(responses.text, "plan a trip");
        let plain = extract(&call("/v1/responses", &json!({"input": "just text"}))).unwrap();
        assert_eq!(plain.text, "just text");
    }

    #[test]
    fn not_a_model_call() {
        assert_eq!(
            extract(&call("/v1/charges", &json!({"messages": []}))),
            None
        );
        assert_eq!(
            extract(&Action::from_evaluation(&evaluation(
                "GET",
                "/v1/messages",
                b""
            ))),
            None
        );
        assert_eq!(
            extract(&Action::from_evaluation(&evaluation(
                "POST",
                "/v1/messages",
                b"not json"
            ))),
            None
        );
    }

    #[test]
    fn capture_modes() {
        let prompt = Prompt {
            provider: "anthropic",
            model: None,
            text: "secret plan".to_owned(),
            turn: String::new(),
        };
        let text = signal_args(&prompt, Capture::Text, 6);
        assert_eq!(text["prompt"], "secret");
        assert_eq!(text["chars"], 11);
        let hashed = signal_args(&prompt, Capture::Hash, 64);
        assert!(hashed.get("prompt").is_none());
        assert_eq!(hashed["sha256"].as_str().unwrap().len(), 64);
        assert_eq!(Capture::parse("hash"), Some(Capture::Hash));
        assert_eq!(Capture::parse("full"), None);
    }
}
