//! Watches Claude Code's `.jsonl` session log and emits [`AgentEvent`] variants.
//!
//! Claude Code writes a structured log to:
//!   `~/.claude/projects/<project-hash>/<sessionId>.jsonl`
//!
//! where `<project-hash>` is the cwd with `/` replaced by `-`.
//!
//! This module tails the newest `.jsonl` file in the project directory using
//! filesystem notifications (`notify` crate) and parses each line into
//! `AgentEvent` variants for the mobile client.

use std::{
    fs,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

use notify::{Event, EventKind, RecursiveMode, Watcher};
use tokio::sync::mpsc as tokio_mpsc;

use protocol::protocol::AgentEvent;

// ── Public types ────────────────────────────────────────────────────────

/// Handles returned by [`start_watching`].
pub struct JsonlWatcher {
    /// Parsed agent events from the session log.
    pub event_rx: tokio_mpsc::Receiver<AgentEvent>,
    /// Log messages for the host TUI.
    pub log_rx: tokio_mpsc::Receiver<String>,
}

// ── Entry point ─────────────────────────────────────────────────────────

/// Start watching for Claude Code's `.jsonl` session log in the current
/// working directory's project folder.
pub fn start_watching() -> anyhow::Result<JsonlWatcher> {
    let project_dir = find_project_dir()?;
    let (event_tx, event_rx) = tokio_mpsc::channel::<AgentEvent>(256);
    let (log_tx, log_rx) = tokio_mpsc::channel::<String>(64);

    let log_tx2 = log_tx.clone();
    thread::spawn(move || {
        if let Err(err) = watcher_loop(project_dir, event_tx, log_tx) {
            let _ = log_tx2.blocking_send(format!("watcher error: {err}"));
        }
    });

    Ok(JsonlWatcher { event_rx, log_rx })
}

/// Compute the project directory from the cwd.
/// `/Users/junkai/Desktop/red-remote` → `~/.claude/projects/-Users-junkai-Desktop-red-remote/`
fn find_project_dir() -> anyhow::Result<PathBuf> {
    let cwd = std::env::current_dir()?;
    let cwd_str = cwd.to_string_lossy();
    // Replace / with - to match Claude Code's naming convention.
    let hash = cwd_str.replace('/', "-");

    let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("no home directory"))?;
    let project_dir = home.join(".claude").join("projects").join(&hash);

    if !project_dir.exists() {
        // Create the directory so the watcher has something to watch.
        // Claude Code will create files in it.
        fs::create_dir_all(&project_dir)?;
    }

    Ok(project_dir)
}

/// Find the newest `.jsonl` file in a directory, or wait for one to appear.
fn find_newest_jsonl(dir: &Path) -> Option<PathBuf> {
    let entries = fs::read_dir(dir).ok()?;
    entries
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "jsonl"))
        .max_by_key(|e| e.metadata().ok().and_then(|m| m.modified().ok()))
        .map(|e| e.path())
}

// ── Main watcher loop ───────────────────────────────────────────────────

fn watcher_loop(
    project_dir: PathBuf,
    event_tx: tokio_mpsc::Sender<AgentEvent>,
    log_tx: tokio_mpsc::Sender<String>,
) -> anyhow::Result<()> {
    let _ = log_tx.blocking_send(format!("Watching {}", project_dir.display()));

    // Set up filesystem watcher on the project directory.
    let (notify_tx, notify_rx) = std::sync::mpsc::channel();
    let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
        if let Ok(event) = res {
            let _ = notify_tx.send(event);
        }
    })?;
    watcher.watch(&project_dir, RecursiveMode::NonRecursive)?;

    // Find the current newest file or wait for one.
    let mut current_file: Option<PathBuf> = find_newest_jsonl(&project_dir);
    let mut file: Option<fs::File> = None;
    let mut read_buf = String::new();
    let mut remainder = String::new(); // partial line from last read

    // If there's already a file, open it and seek to the end (only process new lines).
    if let Some(ref path) = current_file {
        match fs::File::open(path) {
            Ok(mut f) => {
                let _ = f.seek(SeekFrom::End(0));
                file = Some(f);
                let _ = log_tx.blocking_send(format!(
                    "Tailing {}",
                    path.file_name().unwrap_or_default().to_string_lossy()
                ));
            }
            Err(err) => {
                let _ = log_tx.blocking_send(format!("Failed to open: {err}"));
            }
        }
    } else {
        let _ = log_tx.blocking_send("Waiting for session log file...".to_string());
    }

    loop {
        // Process filesystem events (non-blocking with timeout).
        match notify_rx.recv_timeout(Duration::from_millis(200)) {
            Ok(event) => {
                match event.kind {
                    EventKind::Create(_) => {
                        // New file created — check if it's a newer .jsonl.
                        if let Some(newest) = find_newest_jsonl(&project_dir) {
                            if current_file.as_ref() != Some(&newest) {
                                let _ = log_tx.blocking_send(format!(
                                    "New session: {}",
                                    newest.file_name().unwrap_or_default().to_string_lossy()
                                ));
                                current_file = Some(newest.clone());
                                match fs::File::open(&newest) {
                                    Ok(f) => {
                                        file = Some(f);
                                        remainder.clear();
                                    }
                                    Err(err) => {
                                        let _ = log_tx.blocking_send(format!("Open error: {err}"));
                                    }
                                }
                            }
                        }
                    }
                    EventKind::Modify(_) | EventKind::Other => {
                        // File modified — read new lines below.
                    }
                    _ => {}
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                // No event — still try reading in case we missed a notify.
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }

        // Read any new data from the file (raw read, no BufReader caching).
        if let Some(ref mut f) = file {
            read_buf.clear();
            match f.read_to_string(&mut read_buf) {
                Ok(0) => {} // No new data.
                Ok(_) => {
                    // Prepend any leftover partial line from the last read.
                    let data = if remainder.is_empty() {
                        read_buf.as_str()
                    } else {
                        remainder.push_str(&read_buf);
                        remainder.as_str()
                    };

                    let mut lines: Vec<&str> = data.split('\n').collect();

                    // If the data doesn't end with \n, the last element is a partial line.
                    let leftover = if !data.ends_with('\n') {
                        lines.pop().unwrap_or("")
                    } else {
                        ""
                    };

                    for line in lines {
                        let line = line.trim();
                        if line.is_empty() {
                            continue;
                        }
                        match parse_jsonl_line(line) {
                            Ok(events) => {
                                for evt in events {
                                    if event_tx.blocking_send(evt).is_err() {
                                        return Ok(());
                                    }
                                }
                            }
                            Err(err) => {
                                let preview = if line.len() > 80 { &line[..80] } else { line };
                                let _ =
                                    log_tx.blocking_send(format!("Parse error: {err} | {preview}"));
                            }
                        }
                    }

                    // Save partial line for next read.
                    remainder = leftover.to_string();
                }
                Err(err) => {
                    let _ = log_tx.blocking_send(format!("Read error: {err}"));
                }
            }
        }
    }

    Ok(())
}

// ── JSONL → AgentEvent parser ───────────────────────────────────────────

fn parse_jsonl_line(line: &str) -> anyhow::Result<Vec<AgentEvent>> {
    let parsed: serde_json::Value = serde_json::from_str(line)?;
    let kind = parsed.get("type").and_then(|v| v.as_str()).unwrap_or("");

    let mut events = Vec::new();

    match kind {
        "assistant" => {
            let message = parsed.get("message");
            let content = message
                .and_then(|m| m.get("content"))
                .and_then(|c| c.as_array());

            if let Some(blocks) = content {
                for block in blocks {
                    let block_type = block.get("type").and_then(|v| v.as_str()).unwrap_or("");
                    match block_type {
                        "thinking" => {
                            if let Some(text) = block.get("thinking").and_then(|v| v.as_str()) {
                                events.push(AgentEvent::ThinkingDelta {
                                    text: text.to_string(),
                                });
                            }
                        }
                        "text" => {
                            if let Some(text) = block.get("text").and_then(|v| v.as_str()) {
                                events.push(AgentEvent::TextBlock {
                                    text: text.to_string(),
                                });
                            }
                        }
                        "tool_use" => {
                            let id = block
                                .get("id")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let name = block
                                .get("name")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let input = block
                                .get("input")
                                .map(|v| serde_json::to_string(v).unwrap_or_default())
                                .unwrap_or_default();
                            events.push(AgentEvent::ToolUseStart { id, name, input });
                        }
                        _ => {}
                    }
                }
            }

            // Check stop_reason — "end_turn" means Claude is done and waiting for input.
            let stop_reason = message
                .and_then(|m| m.get("stop_reason"))
                .and_then(|v| v.as_str());
            if stop_reason == Some("end_turn") {
                events.push(AgentEvent::TurnCompleted {
                    status: "completed".to_string(),
                });
            }
        }
        "user" => {
            let content = parsed.get("message").and_then(|m| m.get("content"));

            // User prompt (string content).
            if let Some(serde_json::Value::String(text)) = content {
                events.push(AgentEvent::TurnStarted);
                events.push(AgentEvent::TextBlock {
                    text: format!("> {text}"),
                });
            }

            // Tool results (array content).
            if let Some(serde_json::Value::Array(blocks)) = content {
                for block in blocks {
                    let block_type = block.get("type").and_then(|v| v.as_str()).unwrap_or("");
                    if block_type == "tool_result" {
                        let id = block
                            .get("tool_use_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let mut result_content = block
                            .get("content")
                            .map(|v| match v {
                                serde_json::Value::String(s) => s.clone(),
                                other => serde_json::to_string(other).unwrap_or_default(),
                            })
                            .unwrap_or_default();
                        // Cap tool result content to avoid sending huge payloads
                        // (e.g., a tool that read a large file) over the relay.
                        const MAX_RESULT_LEN: usize = 32 * 1024; // 32 KB
                        if result_content.len() > MAX_RESULT_LEN {
                            result_content.truncate(MAX_RESULT_LEN);
                            result_content.push_str("\n... (truncated)");
                        }
                        let is_error = block
                            .get("is_error")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        events.push(AgentEvent::ToolResult {
                            id,
                            content: result_content,
                            is_error,
                        });
                    }
                }
            }
        }
        "last-prompt" => {
            events.push(AgentEvent::TurnCompleted {
                status: "completed".to_string(),
            });
        }
        // queue-operation and other types are ignored.
        _ => {}
    }

    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_assistant_thinking() {
        let line = r#"{"type":"assistant","message":{"role":"assistant","content":[{"type":"thinking","thinking":"Let me think..."}]}}"#;
        let events = parse_jsonl_line(line).unwrap();
        assert_eq!(events.len(), 1);
        assert!(
            matches!(&events[0], AgentEvent::ThinkingDelta { text } if text == "Let me think...")
        );
    }

    #[test]
    fn parse_assistant_text() {
        let line = r#"{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"Hello world"}]}}"#;
        let events = parse_jsonl_line(line).unwrap();
        assert_eq!(events.len(), 1);
        assert!(matches!(&events[0], AgentEvent::TextBlock { text } if text == "Hello world"));
    }

    #[test]
    fn parse_assistant_tool_use() {
        let line = r#"{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","id":"toolu_123","name":"Read","input":{"file_path":"/src/main.rs"}}]}}"#;
        let events = parse_jsonl_line(line).unwrap();
        assert_eq!(events.len(), 1);
        assert!(matches!(&events[0], AgentEvent::ToolUseStart { name, .. } if name == "Read"));
    }

    #[test]
    fn parse_user_prompt() {
        let line = r#"{"type":"user","message":{"role":"user","content":"Fix the bug"}}"#;
        let events = parse_jsonl_line(line).unwrap();
        assert_eq!(events.len(), 2);
        assert!(matches!(&events[0], AgentEvent::TurnStarted));
        assert!(
            matches!(&events[1], AgentEvent::TextBlock { text } if text.contains("Fix the bug"))
        );
    }

    #[test]
    fn parse_user_tool_result() {
        let line = r#"{"type":"user","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_123","content":"file contents"}]}}"#;
        let events = parse_jsonl_line(line).unwrap();
        assert_eq!(events.len(), 1);
        assert!(
            matches!(&events[0], AgentEvent::ToolResult { id, content, .. } if id == "toolu_123" && content == "file contents")
        );
    }

    #[test]
    fn parse_last_prompt() {
        let line = r#"{"type":"last-prompt"}"#;
        let events = parse_jsonl_line(line).unwrap();
        assert_eq!(events.len(), 1);
        assert!(
            matches!(&events[0], AgentEvent::TurnCompleted { status } if status == "completed")
        );
    }

    #[test]
    fn parse_queue_operation_ignored() {
        let line = r#"{"type":"queue-operation","operation":"enqueue"}"#;
        let events = parse_jsonl_line(line).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn project_dir_computation() {
        // Verify the function doesn't panic and returns a usable result.
        // It depends on HOME and CWD, so we just check it resolves without error.
        assert!(find_project_dir().is_ok());
    }

    #[test]
    fn parse_assistant_end_turn() {
        let line = r#"{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"Done."}],"stop_reason":"end_turn"}}"#;
        let events = parse_jsonl_line(line).unwrap();
        assert_eq!(events.len(), 2);
        assert!(matches!(&events[0], AgentEvent::TextBlock { .. }));
        assert!(
            matches!(&events[1], AgentEvent::TurnCompleted { status } if status == "completed")
        );
    }

    #[test]
    fn parse_assistant_multiple_blocks() {
        let line = r#"{"type":"assistant","message":{"role":"assistant","content":[{"type":"thinking","thinking":"hmm"},{"type":"text","text":"hello"},{"type":"tool_use","id":"t1","name":"Write","input":{}}]}}"#;
        let events = parse_jsonl_line(line).unwrap();
        assert_eq!(events.len(), 3);
        assert!(matches!(&events[0], AgentEvent::ThinkingDelta { .. }));
        assert!(matches!(&events[1], AgentEvent::TextBlock { .. }));
        assert!(matches!(&events[2], AgentEvent::ToolUseStart { .. }));
    }

    #[test]
    fn parse_assistant_no_content() {
        let line = r#"{"type":"assistant","message":{"role":"assistant"}}"#;
        let events = parse_jsonl_line(line).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn parse_user_tool_result_is_error() {
        let line = r#"{"type":"user","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"failed","is_error":true}]}}"#;
        let events = parse_jsonl_line(line).unwrap();
        assert_eq!(events.len(), 1);
        assert!(matches!(&events[0], AgentEvent::ToolResult { is_error, .. } if *is_error));
    }

    #[test]
    fn parse_user_tool_result_truncation() {
        let big_content = "x".repeat(40_000);
        let line = format!(
            r#"{{"type":"user","message":{{"role":"user","content":[{{"type":"tool_result","tool_use_id":"t1","content":"{big_content}"}}]}}}}"#
        );
        let events = parse_jsonl_line(&line).unwrap();
        assert_eq!(events.len(), 1);
        if let AgentEvent::ToolResult { content, .. } = &events[0] {
            assert!(content.len() < 40_000, "content should be truncated");
            assert!(content.ends_with("... (truncated)"));
        } else {
            panic!("expected ToolResult");
        }
    }

    #[test]
    fn parse_invalid_json_returns_err() {
        let result = parse_jsonl_line("not json at all");
        assert!(result.is_err());
    }

    #[test]
    fn parse_unknown_type_returns_empty() {
        let line = r#"{"type":"something-new","data":123}"#;
        let events = parse_jsonl_line(line).unwrap();
        assert!(events.is_empty());
    }
}
