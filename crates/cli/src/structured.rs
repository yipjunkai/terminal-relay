#![allow(dead_code)]
//! Structured agent session: spawns an AI tool (e.g., Claude Code) with JSON
//! streaming output instead of a PTY, parses the NDJSON events, and emits
//! [`AgentEvent`] variants alongside reconstructed text for terminal clients.
//!
//! This is the dual of [`crate::pty::PtySession`] — same interface shape
//! (`send_input` / event receivers / exit code) but structured data instead of
//! raw terminal bytes.

use std::{
    io::{BufRead, BufReader},
    process::{Command, Stdio},
    thread,
};

use anyhow::Context;
use serde::Deserialize;
use tokio::sync::{mpsc as tokio_mpsc, oneshot};

use protocol::protocol::AgentEvent;

// ── Public types ────────────────────────────────────────────────────────

/// A running structured agent session.
///
/// Each invocation runs `claude -p` with a single prompt (print mode).
/// Follow-up prompts require spawning a new session.
pub struct StructuredSession;

/// Async receivers for the host event loop.
pub struct StructuredStreams {
    /// Parsed [`AgentEvent`] variants from the agent's JSON output.
    pub event_rx: tokio_mpsc::Receiver<AgentEvent>,
    /// Reconstructed plain-text output (for terminal clients that ignore AgentEvent).
    pub text_rx: tokio_mpsc::Receiver<Vec<u8>>,
    /// Process exit code.
    pub exit_rx: oneshot::Receiver<i32>,
    /// Log messages for the host TUI (stderr output, parse errors, etc.).
    pub log_rx: tokio_mpsc::Receiver<String>,
}

// ── Claude Code stream-json types ───────────────────────────────────────

/// Top-level NDJSON line from `claude -p --output-format stream-json --verbose`.
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum StreamEvent {
    #[serde(rename = "system")]
    System(SystemEvent),
    #[serde(rename = "assistant")]
    Assistant(AssistantEvent),
    #[serde(rename = "user")]
    User(UserEvent),
    #[serde(rename = "stream_event")]
    StreamDelta(StreamDeltaEvent),
    #[serde(rename = "result")]
    Result(ResultEvent),
    // Catch-all for unknown event types (rate_limit_event, etc.)
    #[serde(other)]
    Other,
}

#[derive(Debug, Deserialize)]
struct SystemEvent {
    #[serde(default)]
    session_id: String,
    #[serde(default)]
    model: String,
    #[serde(default)]
    tools: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct AssistantEvent {
    message: AssistantMessage,
}

#[derive(Debug, Deserialize)]
struct AssistantMessage {
    #[serde(default)]
    content: Vec<ContentBlock>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum ContentBlock {
    #[serde(rename = "text")]
    Text {
        text: String,
        #[serde(default)]
        thinking: bool,
    },
    #[serde(rename = "tool_use")]
    ToolUse {
        id: String,
        name: String,
        #[serde(default)]
        input: serde_json::Value,
    },
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Deserialize)]
struct UserEvent {
    message: UserMessage,
}

#[derive(Debug, Deserialize)]
struct UserMessage {
    #[serde(default)]
    content: Vec<ToolResultBlock>,
}

#[derive(Debug, Deserialize)]
struct ToolResultBlock {
    #[serde(default)]
    tool_use_id: String,
    #[serde(default)]
    content: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct StreamDeltaEvent {
    event: StreamDeltaInner,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum StreamDeltaInner {
    #[serde(rename = "content_block_start")]
    #[allow(dead_code)]
    ContentBlockStart {
        #[serde(default)]
        content_block: ContentBlockType,
    },
    #[serde(rename = "content_block_delta")]
    ContentBlockDelta {
        #[serde(default)]
        delta: DeltaPayload,
    },
    #[serde(rename = "content_block_stop")]
    ContentBlockStop {},
    #[serde(rename = "message_start")]
    MessageStart {},
    #[serde(rename = "message_delta")]
    MessageDelta {
        #[serde(default)]
        delta: MessageDeltaPayload,
    },
    #[serde(rename = "message_stop")]
    MessageStop {},
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Default, Deserialize)]
#[allow(dead_code)]
struct ContentBlockType {
    #[serde(default, rename = "type")]
    kind: String,
    #[serde(default)]
    text: String,
}

#[derive(Debug, Default, Deserialize)]
struct DeltaPayload {
    #[serde(default, rename = "type")]
    kind: String,
    #[serde(default)]
    text: String,
}

#[derive(Debug, Default, Deserialize)]
struct MessageDeltaPayload {
    #[serde(default)]
    stop_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ResultEvent {
    #[serde(default)]
    subtype: String,
    #[serde(default)]
    is_error: bool,
    #[serde(default)]
    duration_ms: u64,
    #[serde(default)]
    num_turns: u32,
    #[serde(default)]
    result: String,
}

// ── Implementation ──────────────────────────────────────────────────────

impl StructuredSession {
    /// Spawn Claude Code (or another agent) in structured JSON mode.
    ///
    /// The command is run as a subprocess (not a PTY) with:
    ///   `claude -p --output-format stream-json --verbose --include-partial-messages`
    ///
    /// Returns the session handle and async event streams.
    pub fn spawn(
        command: &str,
        args: &[String],
        initial_prompt: &str,
    ) -> anyhow::Result<(Self, StructuredStreams)> {
        let mut full_args = vec![
            "-p".to_string(),
            "--output-format".to_string(),
            "stream-json".to_string(),
            "--verbose".to_string(),
            "--include-partial-messages".to_string(),
        ];
        full_args.extend(args.iter().cloned());
        full_args.push(initial_prompt.to_string());

        let mut child = Command::new(command)
            .args(&full_args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("failed to spawn structured agent process")?;

        let stdout = child.stdout.take().context("failed to take stdout")?;
        let stderr = child.stderr.take().context("failed to take stderr")?;

        let (event_tx, event_rx) = tokio_mpsc::channel::<AgentEvent>(256);
        let (text_tx, text_rx) = tokio_mpsc::channel::<Vec<u8>>(512);
        let (log_tx, log_rx) = tokio_mpsc::channel::<String>(64);
        let (exit_tx, exit_rx) = oneshot::channel::<i32>();

        // ── Stdout reader thread: parse NDJSON → AgentEvent + reconstructed text ──
        let stdout_log_tx = log_tx.clone();
        thread::spawn(move || {
            let reader = BufReader::new(stdout);
            let mut line_count = 0u64;
            for line in reader.lines() {
                let Ok(line) = line else {
                    let _ = stdout_log_tx.blocking_send("stdout reader: stream ended".to_string());
                    break;
                };
                if line.is_empty() {
                    continue;
                }
                line_count += 1;

                let event = match serde_json::from_str::<StreamEvent>(&line) {
                    Ok(e) => e,
                    Err(err) => {
                        let preview = if line.len() > 120 {
                            &line[..120]
                        } else {
                            &line
                        };
                        let _ =
                            stdout_log_tx.blocking_send(format!("parse error: {err} | {preview}"));
                        continue;
                    }
                };

                let (agent_events, text_chunks) = process_stream_event(event);

                for ae in agent_events {
                    if event_tx.blocking_send(ae).is_err() {
                        return;
                    }
                }
                for chunk in text_chunks {
                    if text_tx.blocking_send(chunk).is_err() {
                        return;
                    }
                }
            }
            let _ = stdout_log_tx.blocking_send(format!("stdout done: {line_count} lines parsed"));
        });

        // ── Stderr reader thread: surface agent errors to TUI ──
        let stderr_log_tx = log_tx.clone();
        thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines() {
                let Ok(line) = line else { break };
                if !line.is_empty() {
                    let _ = stderr_log_tx.blocking_send(format!("agent: {line}"));
                }
            }
        });

        // ── Wait thread: capture exit code ──
        thread::spawn(move || {
            let status = child.wait();
            let code = status.ok().and_then(|s| s.code()).unwrap_or(1);
            let _ = exit_tx.send(code);
        });

        Ok((
            Self,
            StructuredStreams {
                event_rx,
                text_rx,
                exit_rx,
                log_rx,
            },
        ))
    }
}

/// Process a single parsed stream event into zero or more [`AgentEvent`] values
/// and zero or more reconstructed text chunks (for terminal-only clients).
fn process_stream_event(event: StreamEvent) -> (Vec<AgentEvent>, Vec<Vec<u8>>) {
    let mut events = Vec::new();
    let mut text = Vec::new();

    match event {
        StreamEvent::System(sys) => {
            events.push(AgentEvent::SessionInit {
                session_id: sys.session_id,
                model: sys.model,
                tools: sys.tools,
            });
        }
        StreamEvent::Assistant(assistant) => {
            // Complete assistant message — emit structured events and text.
            events.push(AgentEvent::TurnStarted);
            for block in assistant.message.content {
                match block {
                    ContentBlock::Text { text: t, thinking } => {
                        if thinking {
                            // Don't reconstruct thinking text for terminal clients
                            // (it's hidden in the normal TUI too).
                            events.push(AgentEvent::ThinkingDelta { text: t });
                        } else {
                            events.push(AgentEvent::TextBlock { text: t.clone() });
                            // Reconstruct for terminal clients: render text with newline.
                            text.push(format!("{t}\n").into_bytes());
                        }
                    }
                    ContentBlock::ToolUse { id, name, input } => {
                        let input_str = serde_json::to_string(&input).unwrap_or_default();
                        events.push(AgentEvent::ToolUseStart {
                            id: id.clone(),
                            name: name.clone(),
                            input: input_str,
                        });
                        // Reconstruct for terminal: show tool invocation.
                        text.push(format!("\x1b[36m⚡ {name}\x1b[0m {id}\n").into_bytes());
                    }
                    ContentBlock::Unknown => {}
                }
            }
        }
        StreamEvent::User(user) => {
            // Tool results.
            for result_block in user.message.content {
                let content = match &result_block.content {
                    serde_json::Value::String(s) => s.clone(),
                    other => serde_json::to_string(other).unwrap_or_default(),
                };
                events.push(AgentEvent::ToolResult {
                    id: result_block.tool_use_id.clone(),
                    content: content.clone(),
                    is_error: false,
                });
                // Reconstruct: show truncated result.
                let preview = if content.len() > 200 {
                    format!("{}...", &content[..200])
                } else {
                    content
                };
                text.push(format!("\x1b[2m{preview}\x1b[0m\n").into_bytes());
            }
        }
        StreamEvent::StreamDelta(delta) => {
            match delta.event {
                StreamDeltaInner::ContentBlockDelta { delta: payload } => {
                    if payload.kind == "text_delta" && !payload.text.is_empty() {
                        events.push(AgentEvent::TextDelta {
                            text: payload.text.clone(),
                        });
                        // Reconstruct: stream text for terminal clients.
                        text.push(payload.text.into_bytes());
                    }
                }
                StreamDeltaInner::MessageDelta { delta: payload } => {
                    if let Some(reason) = payload.stop_reason {
                        let status = match reason.as_str() {
                            "end_turn" => "completed",
                            "max_tokens" => "completed",
                            _ => "completed",
                        };
                        events.push(AgentEvent::TurnCompleted {
                            status: status.to_string(),
                        });
                    }
                }
                // Other stream deltas (message_start, content_block_start, etc.)
                // are structural — we don't need to emit events for them.
                _ => {}
            }
        }
        StreamEvent::Result(result) => {
            events.push(AgentEvent::SessionResult {
                result: result.result.clone(),
                is_error: result.is_error,
                duration_ms: result.duration_ms,
                num_turns: result.num_turns,
            });
            // Reconstruct: show final summary.
            let status = if result.is_error { "ERROR" } else { "DONE" };
            text.push(
                format!(
                    "\n\x1b[1m[{status}]\x1b[0m ({:.1}s, {} turn{})\n",
                    result.duration_ms as f64 / 1000.0,
                    result.num_turns,
                    if result.num_turns == 1 { "" } else { "s" },
                )
                .into_bytes(),
            );
        }
        StreamEvent::Other => {}
    }

    (events, text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_system_init() {
        let json = r#"{"type":"system","subtype":"init","session_id":"abc","model":"claude-sonnet-4-6","tools":["Read","Edit"],"cwd":"/tmp"}"#;
        let event: StreamEvent = serde_json::from_str(json).unwrap();
        let (events, _) = process_stream_event(event);
        assert_eq!(events.len(), 1);
        assert!(
            matches!(&events[0], AgentEvent::SessionInit { model, .. } if model == "claude-sonnet-4-6")
        );
    }

    #[test]
    fn parse_assistant_text() {
        let json = r#"{"type":"assistant","message":{"model":"claude-sonnet-4-6","id":"msg_1","type":"message","role":"assistant","content":[{"type":"text","text":"Hello world"}],"stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":1}},"session_id":"abc"}"#;
        let event: StreamEvent = serde_json::from_str(json).unwrap();
        let (events, text) = process_stream_event(event);
        // TurnStarted + TextBlock
        assert!(events.len() >= 2);
        assert!(matches!(&events[0], AgentEvent::TurnStarted));
        assert!(matches!(&events[1], AgentEvent::TextBlock { text } if text == "Hello world"));
        assert!(!text.is_empty());
    }

    #[test]
    fn parse_assistant_tool_use() {
        let json = r#"{"type":"assistant","message":{"model":"claude-sonnet-4-6","id":"msg_1","type":"message","role":"assistant","content":[{"type":"tool_use","id":"toolu_123","name":"Read","input":{"file_path":"/src/main.rs"}}],"stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":1}},"session_id":"abc"}"#;
        let event: StreamEvent = serde_json::from_str(json).unwrap();
        let (events, text) = process_stream_event(event);
        assert!(events.len() >= 2);
        assert!(matches!(&events[1], AgentEvent::ToolUseStart { name, .. } if name == "Read"));
        // Terminal reconstruction should mention the tool name.
        let text_str = String::from_utf8(text.concat()).unwrap();
        assert!(text_str.contains("Read"));
    }

    #[test]
    fn parse_stream_text_delta() {
        let json = r#"{"type":"stream_event","event":{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}},"session_id":"abc"}"#;
        let event: StreamEvent = serde_json::from_str(json).unwrap();
        let (events, text) = process_stream_event(event);
        assert_eq!(events.len(), 1);
        assert!(matches!(&events[0], AgentEvent::TextDelta { text } if text == "Hello"));
        assert_eq!(text.len(), 1);
        assert_eq!(text[0], b"Hello");
    }

    #[test]
    fn parse_result_success() {
        let json = r#"{"type":"result","subtype":"success","is_error":false,"duration_ms":5000,"num_turns":2,"result":"Done!","session_id":"abc"}"#;
        let event: StreamEvent = serde_json::from_str(json).unwrap();
        let (events, text) = process_stream_event(event);
        assert_eq!(events.len(), 1);
        assert!(matches!(
            &events[0],
            AgentEvent::SessionResult {
                is_error: false,
                num_turns: 2,
                ..
            }
        ));
        let text_str = String::from_utf8(text.concat()).unwrap();
        assert!(text_str.contains("DONE"));
    }

    #[test]
    fn parse_unknown_type_graceful() {
        let json = r#"{"type":"rate_limit_event","rate_limit_info":{}}"#;
        let event: StreamEvent = serde_json::from_str(json).unwrap();
        let (events, text) = process_stream_event(event);
        assert!(events.is_empty());
        assert!(text.is_empty());
    }

    #[test]
    fn parse_user_tool_result() {
        let json = r#"{"type":"user","message":{"role":"user","content":[{"tool_use_id":"toolu_123","type":"tool_result","content":"file contents here"}]},"session_id":"abc"}"#;
        let event: StreamEvent = serde_json::from_str(json).unwrap();
        let (events, _) = process_stream_event(event);
        assert_eq!(events.len(), 1);
        assert!(
            matches!(&events[0], AgentEvent::ToolResult { id, content, .. } if id == "toolu_123" && content == "file contents here")
        );
    }
}
