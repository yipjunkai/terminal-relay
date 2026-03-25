//! OpenCode API adapter: structured event bridge between OpenCode's HTTP/SSE
//! server API and Farwatch's encrypted relay protocol.
//!
//! Instead of spawning OpenCode in a PTY and tailing JSONL logs, this adapter
//! starts `opencode serve`, connects to its SSE event stream, and translates
//! events into [`AgentEvent`] variants for the mobile client. Commands from the
//! mobile client (`AgentCommand`) are mapped to OpenCode's REST API.
//!
//! This is "Option B" — no PTY, fully structured, bidirectional.

use std::{process::Stdio, time::Duration};

use serde::{Deserialize, Serialize};
use tokio::{
    process::{Child, Command},
    sync::mpsc as tokio_mpsc,
};
use tracing::{debug, info, warn};

use protocol::protocol::{AgentCommand, AgentEvent, TodoItem};

use crate::constants;

// ── Public types ────────────────────────────────────────────────────────

/// Handles returned by [`OpenCodeAdapter::start`].
pub struct OpenCodeAdapter {
    /// Base URL for the OpenCode HTTP server (e.g. `http://127.0.0.1:18923`).
    base_url: String,
    /// The active OpenCode session ID.
    session_id: String,
    /// HTTP client for REST API calls.
    client: reqwest::Client,
    /// The `opencode serve` child process (killed on drop).
    process: Child,
    /// Port the server is listening on.
    #[allow(dead_code)]
    port: u16,
}

/// Minimal session info from the OpenCode API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenCodeSession {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub time: SessionTime,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionTime {
    #[serde(default)]
    pub created: u64,
    #[serde(default)]
    pub updated: u64,
}

/// Channels for communicating with the adapter from the host event loop.
pub struct AdapterChannels {
    /// Receive parsed `AgentEvent`s (from the SSE stream).
    pub event_rx: tokio_mpsc::Receiver<AgentEvent>,
    /// Send `AgentCommand`s to be executed via the HTTP API.
    pub command_tx: tokio_mpsc::Sender<AgentCommand>,
    /// Receive log messages for the host TUI.
    pub log_rx: tokio_mpsc::Receiver<String>,
    /// Fires when the SSE event stream closes (e.g. user ran `/exit`).
    pub stream_ended_rx: tokio::sync::oneshot::Receiver<()>,
}

// ── OpenCode SSE event types (for deserialization) ──────────────────────

/// Top-level SSE event envelope from OpenCode's `/event` endpoint.
#[derive(Debug, Deserialize)]
struct SseEvent {
    #[serde(rename = "type")]
    event_type: String,
    properties: serde_json::Value,
}

// ── Implementation ──────────────────────────────────────────────────────

impl OpenCodeAdapter {
    /// Start `opencode serve` on the given port, wait for it to become healthy,
    /// and return the adapter.
    ///
    /// The caller is responsible for calling [`OpenCodeAdapter::subscribe`] to
    /// start the event stream and [`OpenCodeAdapter::shutdown`] to clean up.
    pub async fn start(port: u16) -> anyhow::Result<Self> {
        let base_url = format!("http://127.0.0.1:{port}");

        info!(port, "starting opencode serve");

        let process = Command::new("opencode")
            .args(["serve", "--port", &port.to_string()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| anyhow::anyhow!("failed to start `opencode serve`: {e}"))?;

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?;

        let adapter = Self {
            base_url,
            session_id: String::new(),
            client,
            process,
            port,
        };

        adapter.wait_for_health().await?;
        Ok(adapter)
    }

    /// Connect to an already-running OpenCode server (no process management).
    #[allow(dead_code)]
    pub fn connect(base_url: &str) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?;

        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            session_id: String::new(),
            client,
            process: dummy_child()?,
            port: 0,
        })
    }

    /// Poll the health endpoint until the server is ready.
    async fn wait_for_health(&self) -> anyhow::Result<()> {
        let url = format!("{}/global/health", self.base_url);
        let deadline = tokio::time::Instant::now()
            + Duration::from_secs(constants::OPENCODE_HEALTH_TIMEOUT_SECS);

        loop {
            if tokio::time::Instant::now() > deadline {
                return Err(anyhow::anyhow!(
                    "opencode server did not become healthy within {}s",
                    constants::OPENCODE_HEALTH_TIMEOUT_SECS
                ));
            }

            match self.client.get(&url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    info!("opencode server is healthy");
                    return Ok(());
                }
                Ok(resp) => {
                    debug!(status = %resp.status(), "health check returned non-200");
                }
                Err(_) => {
                    debug!("health check failed, retrying...");
                }
            }

            tokio::time::sleep(Duration::from_millis(constants::OPENCODE_HEALTH_POLL_MS)).await;
        }
    }

    // ── Session management ──────────────────────────────────────────

    /// List all sessions from the OpenCode server.
    pub async fn list_sessions(&self) -> anyhow::Result<Vec<OpenCodeSession>> {
        let url = format!("{}/session", self.base_url);
        let resp = self.client.get(&url).send().await?;
        if !resp.status().is_success() {
            return Err(anyhow::anyhow!(
                "failed to list sessions: HTTP {}",
                resp.status()
            ));
        }
        let sessions: Vec<OpenCodeSession> = resp.json().await?;
        Ok(sessions)
    }

    /// Create a new session and set it as the active session.
    pub async fn create_session(&mut self, title: Option<&str>) -> anyhow::Result<OpenCodeSession> {
        let url = format!("{}/session", self.base_url);
        let body = serde_json::json!({
            "title": title.unwrap_or("farwatch session"),
        });
        let resp = self.client.post(&url).json(&body).send().await?;
        if !resp.status().is_success() {
            return Err(anyhow::anyhow!(
                "failed to create session: HTTP {}",
                resp.status()
            ));
        }
        let session: OpenCodeSession = resp.json().await?;
        self.session_id = session.id.clone();
        Ok(session)
    }

    /// Set the active session by ID.
    pub fn set_session(&mut self, session_id: &str) {
        self.session_id = session_id.to_string();
    }

    /// Get the active session ID.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Get the port the server is listening on.
    #[allow(dead_code)]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Get the base URL.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    // ── Event subscription ──────────────────────────────────────────

    /// Subscribe to the SSE event stream and start mapping events to `AgentEvent`.
    /// Also starts a command handler task that routes `AgentCommand` to the HTTP API.
    ///
    /// Returns channels for the host event loop to consume events and send commands.
    pub fn subscribe(&self) -> anyhow::Result<AdapterChannels> {
        let (event_tx, event_rx) = tokio_mpsc::channel::<AgentEvent>(256);
        let (command_tx, command_rx) = tokio_mpsc::channel::<AgentCommand>(64);
        let (log_tx, log_rx) = tokio_mpsc::channel::<String>(64);
        let (stream_ended_tx, stream_ended_rx) = tokio::sync::oneshot::channel::<()>();

        // Spawn the SSE reader task.
        let sse_url = format!("{}/event", self.base_url);
        let sse_client = self.client.clone();
        let sse_log_tx = log_tx.clone();
        let sse_event_tx = event_tx.clone();
        tokio::spawn(async move {
            if let Err(err) =
                run_sse_loop(sse_url, sse_client, sse_event_tx, sse_log_tx.clone()).await
            {
                let _ = sse_log_tx.send(format!("SSE stream error: {err}")).await;
            }
            // Signal that the SSE stream has ended (normal close or error).
            let _ = stream_ended_tx.send(());
        });

        // Spawn the command handler task.
        let cmd_base_url = self.base_url.clone();
        let cmd_session_id = self.session_id.clone();
        let cmd_client = self.client.clone();
        let cmd_log_tx = log_tx.clone();
        tokio::spawn(async move {
            run_command_loop(
                command_rx,
                cmd_base_url,
                cmd_session_id,
                cmd_client,
                cmd_log_tx,
            )
            .await;
        });

        Ok(AdapterChannels {
            event_rx,
            command_tx,
            log_rx,
            stream_ended_rx,
        })
    }

    // ── Lifecycle ───────────────────────────────────────────────────

    /// Spawn a task that waits for the `opencode serve` process to exit and
    /// sends the exit code on a oneshot channel. Used by the host event loop
    /// to detect when the server dies.
    pub fn take_exit_rx(&mut self) -> tokio::sync::oneshot::Receiver<i32> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let mut child = std::mem::replace(
            &mut self.process,
            // Replace with a dummy — the spawned task now owns the real child.
            // We still get kill_on_drop from the task's owned Child.
            dummy_child().expect("failed to spawn placeholder process"),
        );
        tokio::spawn(async move {
            let code = match child.wait().await {
                Ok(status) => status.code().unwrap_or(1),
                Err(_) => 1,
            };
            let _ = tx.send(code);
        });
        rx
    }

    /// Shut down the `opencode serve` process.
    pub async fn shutdown(&mut self) {
        info!("shutting down opencode server");
        let _ = self.process.kill().await;
    }
}

impl Drop for OpenCodeAdapter {
    fn drop(&mut self) {
        // Best-effort kill. The process has `kill_on_drop(true)` set, but
        // we also try to kill it explicitly for faster cleanup.
        let _ = self.process.start_kill();
    }
}

// ── Session picker ──────────────────────────────────────────────────────

/// The result of the interactive session picker.
pub enum SessionChoice {
    /// User chose to create a new session.
    New,
    /// User selected an existing session.
    Existing(OpenCodeSession),
}

/// Show an interactive TUI picker for OpenCode sessions.
///
/// Lists existing sessions (most recently updated first) with a "New session"
/// option at the top. If there are no existing sessions, returns
/// `SessionChoice::New` immediately without showing the picker.
pub fn pick_session(sessions: &[OpenCodeSession]) -> anyhow::Result<SessionChoice> {
    use crossterm::{
        cursor,
        event::{self, Event, KeyCode},
        execute,
        style::{Attribute, Color, Print, ResetColor, SetAttribute, SetForegroundColor},
        terminal::{self, Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen},
    };
    use std::io::{self, Write};

    if sessions.is_empty() {
        return Ok(SessionChoice::New);
    }

    // Sort sessions by updated time (most recent first).
    let mut sorted: Vec<&OpenCodeSession> = sessions.iter().collect();
    sorted.sort_by(|a, b| b.time.updated.cmp(&a.time.updated));

    // Total entries: "New session" + existing sessions.
    let total = 1 + sorted.len();

    terminal::enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, cursor::Hide)?;

    let mut selected: usize = 0;

    let result = loop {
        execute!(stdout, cursor::MoveTo(0, 0), Clear(ClearType::All))?;

        execute!(
            stdout,
            cursor::MoveTo(2, 1),
            SetForegroundColor(Color::White),
            SetAttribute(Attribute::Bold),
            Print("OpenCode Sessions"),
            SetAttribute(Attribute::Reset),
        )?;

        execute!(
            stdout,
            cursor::MoveTo(2, 3),
            SetForegroundColor(Color::DarkGrey),
            Print("Select a session to resume, or start a new one:"),
            ResetColor,
        )?;

        // Row 0: "New session"
        let y = 5u16;
        if selected == 0 {
            execute!(
                stdout,
                cursor::MoveTo(2, y),
                SetForegroundColor(Color::Cyan),
                Print("  > + New session"),
                ResetColor,
            )?;
        } else {
            execute!(
                stdout,
                cursor::MoveTo(2, y),
                SetForegroundColor(Color::White),
                Print("    + New session"),
                ResetColor,
            )?;
        }

        // Existing sessions.
        for (i, session) in sorted.iter().enumerate() {
            let row = y + 1 + i as u16;
            let label = format_session_label(session);
            if selected == i + 1 {
                execute!(
                    stdout,
                    cursor::MoveTo(2, row),
                    SetForegroundColor(Color::Cyan),
                    Print(format!("  > {label}")),
                    ResetColor,
                )?;
            } else {
                execute!(
                    stdout,
                    cursor::MoveTo(2, row),
                    SetForegroundColor(Color::White),
                    Print(format!("    {label}")),
                    ResetColor,
                )?;
            }
        }

        let hint_y = y + total as u16 + 1;
        execute!(
            stdout,
            cursor::MoveTo(2, hint_y),
            SetForegroundColor(Color::DarkGrey),
            Print("↑/↓ navigate   enter select   q quit"),
            ResetColor,
        )?;

        stdout.flush()?;

        if let Event::Key(key) = event::read()? {
            match key.code {
                KeyCode::Up | KeyCode::Char('k') => {
                    selected = selected.saturating_sub(1);
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if selected + 1 < total {
                        selected += 1;
                    }
                }
                KeyCode::Enter => {
                    if selected == 0 {
                        break Ok(SessionChoice::New);
                    } else {
                        break Ok(SessionChoice::Existing(sorted[selected - 1].clone()));
                    }
                }
                KeyCode::Char('q') | KeyCode::Esc => {
                    break Err(anyhow::anyhow!("session selection cancelled"));
                }
                _ => {}
            }
        }
    };

    execute!(stdout, cursor::Show, LeaveAlternateScreen)?;
    terminal::disable_raw_mode()?;

    result
}

/// Format a session label for the picker. Shows title and a relative time hint.
fn format_session_label(session: &OpenCodeSession) -> String {
    let title = if session.title.is_empty() {
        "Untitled"
    } else {
        &session.title
    };

    if session.time.updated > 0 {
        let age = format_relative_time(session.time.updated);
        format!("{title}  ({age})")
    } else {
        title.to_string()
    }
}

/// Format a Unix timestamp (seconds) as a human-readable relative time.
fn format_relative_time(timestamp_secs: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let delta = now.saturating_sub(timestamp_secs);

    match delta {
        0..=59 => "just now".to_string(),
        60..=3599 => {
            let mins = delta / 60;
            if mins == 1 {
                "1 min ago".to_string()
            } else {
                format!("{mins} mins ago")
            }
        }
        3600..=86399 => {
            let hours = delta / 3600;
            if hours == 1 {
                "1 hour ago".to_string()
            } else {
                format!("{hours} hours ago")
            }
        }
        _ => {
            let days = delta / 86400;
            if days == 1 {
                "1 day ago".to_string()
            } else {
                format!("{days} days ago")
            }
        }
    }
}

// ── SSE event stream ────────────────────────────────────────────────────

/// Connect to the SSE endpoint and parse events indefinitely.
async fn run_sse_loop(
    url: String,
    _client: reqwest::Client,
    event_tx: tokio_mpsc::Sender<AgentEvent>,
    log_tx: tokio_mpsc::Sender<String>,
) -> anyhow::Result<()> {
    use futures_util::StreamExt;

    let _ = log_tx
        .send("Connecting to OpenCode event stream...".to_string())
        .await;

    // Build a long-lived streaming request with no timeout (SSE streams never "complete").
    let sse_client = reqwest::Client::builder().no_proxy().build()?;

    let resp = sse_client
        .get(&url)
        .header("Accept", "text/event-stream")
        .send()
        .await?;

    if !resp.status().is_success() {
        return Err(anyhow::anyhow!(
            "SSE connection failed: HTTP {}",
            resp.status()
        ));
    }

    let _ = log_tx
        .send("Connected to OpenCode event stream".to_string())
        .await;

    let mut stream = resp.bytes_stream();
    let mut buffer = String::new();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        let text = String::from_utf8_lossy(&chunk);
        buffer.push_str(&text);

        // SSE events are delimited by double newlines.
        while let Some(boundary) = buffer.find("\n\n") {
            let event_text = buffer[..boundary].to_string();
            buffer = buffer[boundary + 2..].to_string();

            // Parse the SSE event lines.
            let mut data = String::new();
            for line in event_text.lines() {
                if let Some(d) = line.strip_prefix("data: ") {
                    if !data.is_empty() {
                        data.push('\n');
                    }
                    data.push_str(d);
                } else if let Some(d) = line.strip_prefix("data:") {
                    if !data.is_empty() {
                        data.push('\n');
                    }
                    data.push_str(d);
                }
            }

            if data.is_empty() {
                continue;
            }

            match serde_json::from_str::<SseEvent>(&data) {
                Ok(sse_event) => {
                    let events = map_sse_event(&sse_event);
                    for evt in events {
                        if event_tx.send(evt).await.is_err() {
                            return Ok(()); // Receiver dropped
                        }
                    }
                }
                Err(err) => {
                    let preview = if data.len() > 100 {
                        &data[..100]
                    } else {
                        &data
                    };
                    debug!(error = %err, data = preview, "failed to parse SSE event");
                }
            }
        }
    }

    let _ = log_tx.send("OpenCode event stream ended".to_string()).await;
    Ok(())
}

// ── SSE → AgentEvent mapping ────────────────────────────────────────────

/// Map a single OpenCode SSE event to zero or more `AgentEvent` variants.
fn map_sse_event(event: &SseEvent) -> Vec<AgentEvent> {
    match event.event_type.as_str() {
        "message.part.updated" => map_part_updated(&event.properties),
        "message.updated" => map_message_updated(&event.properties),
        "permission.updated" => map_permission_updated(&event.properties),
        "permission.replied" => map_permission_replied(&event.properties),
        "todo.updated" => map_todo_updated(&event.properties),
        "session.status" => map_session_status(&event.properties),
        "session.error" => map_session_error(&event.properties),
        "session.idle" => vec![AgentEvent::TurnCompleted {
            status: "idle".to_string(),
        }],
        _ => vec![], // Ignore unknown event types
    }
}

fn map_part_updated(props: &serde_json::Value) -> Vec<AgentEvent> {
    let part = match props.get("part") {
        Some(p) => p,
        None => return vec![],
    };
    let delta = props.get("delta").and_then(|d| d.as_str());
    let part_type = part.get("type").and_then(|t| t.as_str()).unwrap_or("");

    match part_type {
        "text" => {
            if let Some(delta_text) = delta {
                // Streaming text delta
                vec![AgentEvent::TextDelta {
                    text: delta_text.to_string(),
                }]
            } else {
                // Complete text block
                let text = part.get("text").and_then(|t| t.as_str()).unwrap_or("");
                vec![AgentEvent::TextBlock {
                    text: text.to_string(),
                }]
            }
        }
        "reasoning" => {
            let text = if let Some(delta_text) = delta {
                delta_text.to_string()
            } else {
                part.get("text")
                    .and_then(|t| t.as_str())
                    .unwrap_or("")
                    .to_string()
            };
            vec![AgentEvent::ThinkingDelta { text }]
        }
        "tool" => map_tool_part(part),
        "step-start" => vec![AgentEvent::TurnStarted],
        "step-finish" => map_step_finish(part),
        _ => vec![],
    }
}

fn map_tool_part(part: &serde_json::Value) -> Vec<AgentEvent> {
    let state = match part.get("state") {
        Some(s) => s,
        None => return vec![],
    };
    let status = state.get("status").and_then(|s| s.as_str()).unwrap_or("");
    let tool_name = part.get("tool").and_then(|t| t.as_str()).unwrap_or("");
    let call_id = part.get("callID").and_then(|c| c.as_str()).unwrap_or("");

    match status {
        "pending" | "running" => {
            let input = state
                .get("input")
                .map(|i| serde_json::to_string(i).unwrap_or_default())
                .unwrap_or_default();
            vec![AgentEvent::ToolUseStart {
                id: call_id.to_string(),
                name: tool_name.to_string(),
                input,
            }]
        }
        "completed" => {
            let mut content = state
                .get("output")
                .and_then(|o| o.as_str())
                .unwrap_or("")
                .to_string();
            // Truncate large outputs
            if content.len() > constants::OPENCODE_MAX_RESULT_LEN {
                content.truncate(constants::OPENCODE_MAX_RESULT_LEN);
                content.push_str("\n... (truncated)");
            }
            vec![AgentEvent::ToolResult {
                id: call_id.to_string(),
                content,
                is_error: false,
            }]
        }
        "error" => {
            let error_msg = state
                .get("error")
                .and_then(|e| e.as_str())
                .unwrap_or("unknown error")
                .to_string();
            vec![AgentEvent::ToolResult {
                id: call_id.to_string(),
                content: error_msg,
                is_error: true,
            }]
        }
        _ => vec![],
    }
}

fn map_step_finish(part: &serde_json::Value) -> Vec<AgentEvent> {
    let mut events = vec![];

    let reason = part
        .get("reason")
        .and_then(|r| r.as_str())
        .unwrap_or("completed");
    events.push(AgentEvent::TurnCompleted {
        status: reason.to_string(),
    });

    // Extract cost/token info from step-finish
    let cost = part.get("cost").and_then(|c| c.as_f64()).unwrap_or(0.0);
    let tokens = part.get("tokens");
    if let Some(tokens) = tokens {
        events.push(AgentEvent::CostUpdate {
            input_tokens: tokens.get("input").and_then(|v| v.as_u64()).unwrap_or(0),
            output_tokens: tokens.get("output").and_then(|v| v.as_u64()).unwrap_or(0),
            reasoning_tokens: tokens
                .get("reasoning")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            cache_read_tokens: tokens
                .get("cache")
                .and_then(|c| c.get("read"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            cache_write_tokens: tokens
                .get("cache")
                .and_then(|c| c.get("write"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            cost_usd: cost,
        });
    }

    events
}

fn map_message_updated(props: &serde_json::Value) -> Vec<AgentEvent> {
    let info = match props.get("info") {
        Some(i) => i,
        None => return vec![],
    };
    let role = info.get("role").and_then(|r| r.as_str()).unwrap_or("");

    // When an assistant message first appears, emit SessionInit with model info.
    if role == "assistant" {
        let model_id = info.get("modelID").and_then(|m| m.as_str()).unwrap_or("");
        let provider_id = info
            .get("providerID")
            .and_then(|p| p.as_str())
            .unwrap_or("");
        let model = if !provider_id.is_empty() && !model_id.is_empty() {
            format!("{provider_id}/{model_id}")
        } else {
            model_id.to_string()
        };

        // Check for errors on the message
        if let Some(error) = info.get("error") {
            let error_name = error
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("UnknownError");
            let error_msg = error
                .get("data")
                .and_then(|d| d.get("message"))
                .and_then(|m| m.as_str())
                .unwrap_or("unknown error");
            return vec![AgentEvent::TurnCompleted {
                status: format!("error: {error_name}: {error_msg}"),
            }];
        }

        // Only emit SessionInit if we have model info (first message of a turn)
        if !model.is_empty() {
            return vec![AgentEvent::SessionInit {
                session_id: info
                    .get("sessionID")
                    .and_then(|s| s.as_str())
                    .unwrap_or("")
                    .to_string(),
                model,
                tools: vec![], // Tools are not in message.updated
            }];
        }
    }

    vec![]
}

fn map_permission_updated(props: &serde_json::Value) -> Vec<AgentEvent> {
    let id = props.get("id").and_then(|i| i.as_str()).unwrap_or("");
    let tool = props
        .get("type")
        .and_then(|t| t.as_str())
        .unwrap_or("unknown");
    let title = props.get("title").and_then(|t| t.as_str()).unwrap_or("");
    let metadata = props
        .get("metadata")
        .map(|m| serde_json::to_string(m).unwrap_or_default())
        .unwrap_or_default();

    vec![AgentEvent::PermissionRequest {
        id: id.to_string(),
        tool: tool.to_string(),
        title: title.to_string(),
        metadata,
    }]
}

fn map_permission_replied(props: &serde_json::Value) -> Vec<AgentEvent> {
    let id = props
        .get("permissionID")
        .and_then(|i| i.as_str())
        .unwrap_or("");
    let response = props
        .get("response")
        .and_then(|r| r.as_str())
        .unwrap_or("unknown");

    vec![AgentEvent::PermissionResolved {
        id: id.to_string(),
        response: response.to_string(),
    }]
}

fn map_todo_updated(props: &serde_json::Value) -> Vec<AgentEvent> {
    let raw_todos = match props.get("todos").and_then(|t| t.as_array()) {
        Some(arr) => arr,
        None => return vec![],
    };

    let todos: Vec<TodoItem> = raw_todos
        .iter()
        .map(|t| TodoItem {
            id: t
                .get("id")
                .and_then(|i| i.as_str())
                .unwrap_or("")
                .to_string(),
            content: t
                .get("content")
                .and_then(|c| c.as_str())
                .unwrap_or("")
                .to_string(),
            status: t
                .get("status")
                .and_then(|s| s.as_str())
                .unwrap_or("pending")
                .to_string(),
            priority: t
                .get("priority")
                .and_then(|p| p.as_str())
                .unwrap_or("medium")
                .to_string(),
        })
        .collect();

    vec![AgentEvent::TodoUpdate { todos }]
}

fn map_session_status(props: &serde_json::Value) -> Vec<AgentEvent> {
    let status = props.get("status");
    let status_type = status
        .and_then(|s| s.get("type"))
        .and_then(|t| t.as_str())
        .unwrap_or("");

    match status_type {
        "idle" => vec![AgentEvent::TurnCompleted {
            status: "idle".to_string(),
        }],
        "busy" => vec![AgentEvent::TurnStarted],
        "retry" => {
            let message = status
                .and_then(|s| s.get("message"))
                .and_then(|m| m.as_str())
                .unwrap_or("retrying");
            vec![AgentEvent::TurnCompleted {
                status: format!("retry: {message}"),
            }]
        }
        _ => vec![],
    }
}

fn map_session_error(props: &serde_json::Value) -> Vec<AgentEvent> {
    let error = match props.get("error") {
        Some(e) => e,
        None => {
            return vec![AgentEvent::TurnCompleted {
                status: "error".to_string(),
            }];
        }
    };

    let error_name = error
        .get("name")
        .and_then(|n| n.as_str())
        .unwrap_or("UnknownError");
    let error_msg = error
        .get("data")
        .and_then(|d| d.get("message"))
        .and_then(|m| m.as_str())
        .unwrap_or("unknown error");

    vec![AgentEvent::TurnCompleted {
        status: format!("error: {error_name}: {error_msg}"),
    }]
}

// ── Command routing ─────────────────────────────────────────────────────

/// Process incoming `AgentCommand`s and route them to the OpenCode HTTP API.
async fn run_command_loop(
    mut command_rx: tokio_mpsc::Receiver<AgentCommand>,
    base_url: String,
    session_id: String,
    client: reqwest::Client,
    log_tx: tokio_mpsc::Sender<String>,
) {
    while let Some(cmd) = command_rx.recv().await {
        let result = execute_command(&cmd, &base_url, &session_id, &client).await;
        match result {
            Ok(()) => {
                debug!(?cmd, "command executed successfully");
            }
            Err(err) => {
                warn!(?cmd, error = %err, "command execution failed");
                let _ = log_tx.send(format!("Command failed: {err}")).await;
            }
        }
    }
}

async fn execute_command(
    cmd: &AgentCommand,
    base_url: &str,
    session_id: &str,
    client: &reqwest::Client,
) -> anyhow::Result<()> {
    match cmd {
        AgentCommand::Prompt { text } => {
            let url = format!("{base_url}/session/{session_id}/prompt_async");
            let body = serde_json::json!({
                "parts": [{"type": "text", "text": text}],
            });
            let resp = client.post(&url).json(&body).send().await?;
            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                return Err(anyhow::anyhow!("prompt failed: HTTP {status}: {body}"));
            }
            Ok(())
        }
        AgentCommand::ApproveToolUse { id } => {
            let url = format!("{base_url}/session/{session_id}/permissions/{id}");
            let body = serde_json::json!({"response": "allow"});
            let resp = client.post(&url).json(&body).send().await?;
            if !resp.status().is_success() {
                return Err(anyhow::anyhow!("approve failed: HTTP {}", resp.status()));
            }
            Ok(())
        }
        AgentCommand::DenyToolUse { id, .. } => {
            let url = format!("{base_url}/session/{session_id}/permissions/{id}");
            let body = serde_json::json!({"response": "deny"});
            let resp = client.post(&url).json(&body).send().await?;
            if !resp.status().is_success() {
                return Err(anyhow::anyhow!("deny failed: HTTP {}", resp.status()));
            }
            Ok(())
        }
        AgentCommand::AbortSession => {
            let url = format!("{base_url}/session/{session_id}/abort");
            let resp = client.post(&url).send().await?;
            if !resp.status().is_success() {
                return Err(anyhow::anyhow!("abort failed: HTTP {}", resp.status()));
            }
            Ok(())
        }
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// Create a dummy child process (for the `connect` path where we don't own the process).
fn dummy_child() -> anyhow::Result<Child> {
    // Spawn `true` (or `echo` on Windows) — exits immediately, placeholder only.
    let child = Command::new("true")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    Ok(child)
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_sse(event_type: &str, properties: serde_json::Value) -> SseEvent {
        SseEvent {
            event_type: event_type.to_string(),
            properties,
        }
    }

    // ── Text events ─────────────────────────────────────────────────

    #[test]
    fn map_text_delta() {
        let event = make_sse(
            "message.part.updated",
            json!({
                "part": {"type": "text", "text": "Hello world"},
                "delta": "Hello"
            }),
        );
        let events = map_sse_event(&event);
        assert_eq!(events.len(), 1);
        assert!(matches!(&events[0], AgentEvent::TextDelta { text } if text == "Hello"));
    }

    #[test]
    fn map_text_block_no_delta() {
        let event = make_sse(
            "message.part.updated",
            json!({
                "part": {"type": "text", "text": "Complete text block"}
            }),
        );
        let events = map_sse_event(&event);
        assert_eq!(events.len(), 1);
        assert!(
            matches!(&events[0], AgentEvent::TextBlock { text } if text == "Complete text block")
        );
    }

    // ── Reasoning events ────────────────────────────────────────────

    #[test]
    fn map_reasoning_delta() {
        let event = make_sse(
            "message.part.updated",
            json!({
                "part": {"type": "reasoning", "text": "full thinking"},
                "delta": "Let me think..."
            }),
        );
        let events = map_sse_event(&event);
        assert_eq!(events.len(), 1);
        assert!(
            matches!(&events[0], AgentEvent::ThinkingDelta { text } if text == "Let me think...")
        );
    }

    #[test]
    fn map_reasoning_no_delta() {
        let event = make_sse(
            "message.part.updated",
            json!({
                "part": {"type": "reasoning", "text": "Full reasoning block"}
            }),
        );
        let events = map_sse_event(&event);
        assert_eq!(events.len(), 1);
        assert!(
            matches!(&events[0], AgentEvent::ThinkingDelta { text } if text == "Full reasoning block")
        );
    }

    // ── Tool events ─────────────────────────────────────────────────

    #[test]
    fn map_tool_running() {
        let event = make_sse(
            "message.part.updated",
            json!({
                "part": {
                    "type": "tool",
                    "tool": "Edit",
                    "callID": "call_123",
                    "state": {
                        "status": "running",
                        "input": {"file_path": "src/main.rs"},
                        "time": {"start": 1000}
                    }
                }
            }),
        );
        let events = map_sse_event(&event);
        assert_eq!(events.len(), 1);
        assert!(
            matches!(&events[0], AgentEvent::ToolUseStart { id, name, .. }
            if id == "call_123" && name == "Edit")
        );
    }

    #[test]
    fn map_tool_completed() {
        let event = make_sse(
            "message.part.updated",
            json!({
                "part": {
                    "type": "tool",
                    "tool": "Read",
                    "callID": "call_456",
                    "state": {
                        "status": "completed",
                        "input": {},
                        "output": "file contents here",
                        "title": "Read src/main.rs",
                        "metadata": {},
                        "time": {"start": 1000, "end": 2000}
                    }
                }
            }),
        );
        let events = map_sse_event(&event);
        assert_eq!(events.len(), 1);
        assert!(
            matches!(&events[0], AgentEvent::ToolResult { id, content, is_error }
            if id == "call_456" && content == "file contents here" && !is_error)
        );
    }

    #[test]
    fn map_tool_error() {
        let event = make_sse(
            "message.part.updated",
            json!({
                "part": {
                    "type": "tool",
                    "tool": "Bash",
                    "callID": "call_789",
                    "state": {
                        "status": "error",
                        "input": {},
                        "error": "command not found",
                        "time": {"start": 1000, "end": 2000}
                    }
                }
            }),
        );
        let events = map_sse_event(&event);
        assert_eq!(events.len(), 1);
        assert!(
            matches!(&events[0], AgentEvent::ToolResult { id, content, is_error }
            if id == "call_789" && content == "command not found" && *is_error)
        );
    }

    #[test]
    fn map_tool_pending() {
        let event = make_sse(
            "message.part.updated",
            json!({
                "part": {
                    "type": "tool",
                    "tool": "Write",
                    "callID": "call_aaa",
                    "state": {
                        "status": "pending",
                        "input": {"path": "/tmp/test.txt"},
                        "raw": "{}"
                    }
                }
            }),
        );
        let events = map_sse_event(&event);
        assert_eq!(events.len(), 1);
        assert!(matches!(&events[0], AgentEvent::ToolUseStart { name, .. } if name == "Write"));
    }

    // ── Step events ─────────────────────────────────────────────────

    #[test]
    fn map_step_start() {
        let event = make_sse(
            "message.part.updated",
            json!({
                "part": {"type": "step-start"}
            }),
        );
        let events = map_sse_event(&event);
        assert_eq!(events.len(), 1);
        assert!(matches!(&events[0], AgentEvent::TurnStarted));
    }

    #[test]
    fn map_step_finish_with_cost() {
        let event = make_sse(
            "message.part.updated",
            json!({
                "part": {
                    "type": "step-finish",
                    "reason": "end_turn",
                    "cost": 0.0042,
                    "tokens": {
                        "input": 1500,
                        "output": 340,
                        "reasoning": 800,
                        "cache": {"read": 500, "write": 120}
                    }
                }
            }),
        );
        let events = map_sse_event(&event);
        assert_eq!(events.len(), 2);
        assert!(matches!(&events[0], AgentEvent::TurnCompleted { status } if status == "end_turn"));
        assert!(matches!(
            &events[1],
            AgentEvent::CostUpdate {
                input_tokens: 1500,
                output_tokens: 340,
                reasoning_tokens: 800,
                cache_read_tokens: 500,
                cache_write_tokens: 120,
                ..
            }
        ));
    }

    // ── Permission events ───────────────────────────────────────────

    #[test]
    fn map_permission_request() {
        let event = make_sse(
            "permission.updated",
            json!({
                "id": "perm_001",
                "type": "bash",
                "title": "Run: rm -rf node_modules",
                "metadata": {"command": "rm -rf node_modules"},
                "sessionID": "sess_123",
                "time": {"created": 1000}
            }),
        );
        let events = map_sse_event(&event);
        assert_eq!(events.len(), 1);
        assert!(
            matches!(&events[0], AgentEvent::PermissionRequest { id, tool, title, .. }
            if id == "perm_001" && tool == "bash" && title == "Run: rm -rf node_modules")
        );
    }

    #[test]
    fn map_permission_replied_allow() {
        let event = make_sse(
            "permission.replied",
            json!({
                "sessionID": "sess_123",
                "permissionID": "perm_001",
                "response": "allow"
            }),
        );
        let events = map_sse_event(&event);
        assert_eq!(events.len(), 1);
        assert!(
            matches!(&events[0], AgentEvent::PermissionResolved { id, response }
            if id == "perm_001" && response == "allow")
        );
    }

    // ── Todo events ─────────────────────────────────────────────────

    #[test]
    fn map_todo_update() {
        let event = make_sse(
            "todo.updated",
            json!({
                "sessionID": "sess_123",
                "todos": [
                    {"id": "t1", "content": "Fix bug", "status": "in_progress", "priority": "high"},
                    {"id": "t2", "content": "Add tests", "status": "pending", "priority": "medium"}
                ]
            }),
        );
        let events = map_sse_event(&event);
        assert_eq!(events.len(), 1);
        if let AgentEvent::TodoUpdate { todos } = &events[0] {
            assert_eq!(todos.len(), 2);
            assert_eq!(todos[0].id, "t1");
            assert_eq!(todos[0].content, "Fix bug");
            assert_eq!(todos[0].status, "in_progress");
            assert_eq!(todos[1].priority, "medium");
        } else {
            panic!("expected TodoUpdate");
        }
    }

    #[test]
    fn map_todo_update_empty() {
        let event = make_sse(
            "todo.updated",
            json!({
                "sessionID": "sess_123",
                "todos": []
            }),
        );
        let events = map_sse_event(&event);
        assert_eq!(events.len(), 1);
        assert!(matches!(&events[0], AgentEvent::TodoUpdate { todos } if todos.is_empty()));
    }

    // ── Session status events ───────────────────────────────────────

    #[test]
    fn map_session_idle() {
        let event = make_sse("session.idle", json!({"sessionID": "sess_123"}));
        let events = map_sse_event(&event);
        assert_eq!(events.len(), 1);
        assert!(matches!(&events[0], AgentEvent::TurnCompleted { status } if status == "idle"));
    }

    #[test]
    fn map_session_status_busy() {
        let event = make_sse(
            "session.status",
            json!({
                "sessionID": "sess_123",
                "status": {"type": "busy"}
            }),
        );
        let events = map_sse_event(&event);
        assert_eq!(events.len(), 1);
        assert!(matches!(&events[0], AgentEvent::TurnStarted));
    }

    #[test]
    fn map_session_status_idle() {
        let event = make_sse(
            "session.status",
            json!({
                "sessionID": "sess_123",
                "status": {"type": "idle"}
            }),
        );
        let events = map_sse_event(&event);
        assert_eq!(events.len(), 1);
        assert!(matches!(&events[0], AgentEvent::TurnCompleted { status } if status == "idle"));
    }

    #[test]
    fn map_session_error_with_details() {
        let event = make_sse(
            "session.error",
            json!({
                "sessionID": "sess_123",
                "error": {
                    "name": "ProviderAuthError",
                    "data": {"message": "invalid API key", "providerID": "anthropic"}
                }
            }),
        );
        let events = map_sse_event(&event);
        assert_eq!(events.len(), 1);
        assert!(matches!(&events[0], AgentEvent::TurnCompleted { status }
            if status.contains("ProviderAuthError") && status.contains("invalid API key")));
    }

    // ── Unknown events ──────────────────────────────────────────────

    #[test]
    fn map_unknown_event_returns_empty() {
        let event = make_sse("some.future.event", json!({"data": "whatever"}));
        let events = map_sse_event(&event);
        assert!(events.is_empty());
    }

    // ── Tool result truncation ──────────────────────────────────────

    #[test]
    fn map_tool_result_truncation() {
        let big_output = "x".repeat(40_000);
        let event = make_sse(
            "message.part.updated",
            json!({
                "part": {
                    "type": "tool",
                    "tool": "Read",
                    "callID": "call_big",
                    "state": {
                        "status": "completed",
                        "input": {},
                        "output": big_output,
                        "title": "Read big file",
                        "metadata": {},
                        "time": {"start": 1000, "end": 2000}
                    }
                }
            }),
        );
        let events = map_sse_event(&event);
        assert_eq!(events.len(), 1);
        if let AgentEvent::ToolResult { content, .. } = &events[0] {
            assert!(content.len() < 40_000);
            assert!(content.ends_with("... (truncated)"));
        } else {
            panic!("expected ToolResult");
        }
    }

    // ── Edge cases ──────────────────────────────────────────────────

    #[test]
    fn map_part_updated_missing_part() {
        let event = make_sse("message.part.updated", json!({}));
        let events = map_sse_event(&event);
        assert!(events.is_empty());
    }

    #[test]
    fn map_tool_part_missing_state() {
        let event = make_sse(
            "message.part.updated",
            json!({
                "part": {"type": "tool", "tool": "Edit", "callID": "c1"}
            }),
        );
        let events = map_sse_event(&event);
        assert!(events.is_empty());
    }

    #[test]
    fn map_permission_updated_missing_fields() {
        let event = make_sse("permission.updated", json!({}));
        let events = map_sse_event(&event);
        assert_eq!(events.len(), 1);
        // Should still produce a PermissionRequest with empty/default fields
        assert!(matches!(&events[0], AgentEvent::PermissionRequest { .. }));
    }
}
