use std::io::{self, Write};

use serde::{Deserialize, Serialize};

use crate::config::Config;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCandidate {
    pub name: String,
    pub command: String,
    pub args: Vec<String>,
    pub available: bool,
}

#[derive(Debug, Clone)]
pub struct ToolCommand {
    pub name: String,
    pub command: String,
    pub args: Vec<String>,
    /// Whether this tool supports `--output-format stream-json` for structured events.
    pub supports_structured: bool,
}

/// Known AI tools with their binary names and default arguments.
fn known_tools() -> Vec<(&'static str, &'static str, Vec<String>)> {
    vec![
        ("claude", "claude", vec![]),
        ("opencode", "opencode", vec![]),
        (
            "copilot",
            "gh",
            vec!["copilot".to_string(), "cli".to_string()],
        ),
        ("gemini", "gemini", vec![]),
        ("aider", "aider", vec![]),
    ]
}

pub fn detect_known_tools() -> Vec<ToolCandidate> {
    known_tools()
        .into_iter()
        .map(|(name, command, args)| ToolCandidate {
            name: name.to_string(),
            command: command.to_string(),
            args,
            available: which::which(command).is_ok(),
        })
        .collect()
}

/// Resolve a tool by name or config default. If neither is set and no default
/// exists in config, show an interactive picker (first-run experience).
///
/// `tool_name` is the first positional arg (if any), `extra_args` are the rest.
pub fn resolve_tool(tool_name: Option<&str>, extra_args: &[String]) -> anyhow::Result<ToolCommand> {
    let tools = detect_known_tools();

    let chosen = match tool_name {
        Some(name) => resolve_by_name(name, &tools)?,
        None => {
            // Check config for a saved default.
            let config = Config::load().unwrap_or_default();
            if let Some(ref default) = config.default_tool {
                resolve_by_name(default, &tools)?
            } else {
                // First run — show interactive picker.
                pick_and_save_default(&tools)?
            }
        }
    };

    let mut args = chosen.args;
    args.extend(extra_args.iter().cloned());
    Ok(ToolCommand {
        name: chosen.name,
        command: chosen.command,
        supports_structured: chosen.supports_structured,
        args,
    })
}

/// Resolve a tool by name against known tools, or treat as a raw command.
fn resolve_by_name(name: &str, tools: &[ToolCandidate]) -> anyhow::Result<ToolCommand> {
    if let Some(candidate) = tools.iter().find(|c| c.name == name) {
        if !candidate.available {
            return Err(anyhow::anyhow!(
                "tool '{}' is not available on PATH. Install it or use --tool <name>",
                candidate.name
            ));
        }
        Ok(ToolCommand {
            name: candidate.name.clone(),
            command: candidate.command.clone(),
            args: candidate.args.clone(),
            supports_structured: tool_supports_structured(&candidate.name),
        })
    } else {
        // Unknown name — treat as a raw command.
        let parts: Vec<&str> = name.split_whitespace().collect();
        let (cmd, cmd_args) = parts
            .split_first()
            .ok_or_else(|| anyhow::anyhow!("--tool value cannot be empty"))?;

        if which::which(cmd).is_err() {
            return Err(anyhow::anyhow!("'{}' is not found on PATH", cmd));
        }

        Ok(ToolCommand {
            name: cmd.to_string(),
            command: cmd.to_string(),
            args: cmd_args.iter().map(|s| s.to_string()).collect(),
            supports_structured: false,
        })
    }
}

/// Interactive first-run tool picker using a TUI. Shows available tools with
/// arrow-key navigation, saves the selection to config as the default.
fn pick_and_save_default(tools: &[ToolCandidate]) -> anyhow::Result<ToolCommand> {
    use crossterm::{
        cursor,
        event::{self, Event, KeyCode},
        execute,
        style::{Attribute, Color as CtColor, Print, ResetColor, SetAttribute, SetForegroundColor},
        terminal::{self, Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen},
    };

    let available: Vec<&ToolCandidate> = tools.iter().filter(|t| t.available).collect();
    let unavailable: Vec<&ToolCandidate> = tools.iter().filter(|t| !t.available).collect();

    if available.is_empty() {
        eprintln!("No supported AI tools found on PATH.\n");
        eprintln!("Install one of these:");
        for t in tools {
            eprintln!("  - {}", t.name);
        }
        eprintln!("\nOr use --tool <command> to specify any command.");
        return Err(anyhow::anyhow!("no AI tools available"));
    }

    // Single tool — auto-select without TUI.
    if available.len() == 1 {
        let tool = available[0];
        println!("  Using {} (only available tool).", tool.name);
        save_default(&tool.name)?;
        return Ok(ToolCommand {
            name: tool.name.clone(),
            command: tool.command.clone(),
            args: tool.args.clone(),
            supports_structured: tool_supports_structured(&tool.name),
        });
    }

    // Multiple tools — show interactive TUI picker.
    terminal::enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, cursor::Hide)?;

    let mut selected: usize = 0;

    let result = loop {
        // Draw.
        execute!(stdout, cursor::MoveTo(0, 0), Clear(ClearType::All))?;

        execute!(
            stdout,
            cursor::MoveTo(2, 1),
            SetForegroundColor(CtColor::White),
            SetAttribute(Attribute::Bold),
            Print("Welcome to Farwatch"),
            SetAttribute(Attribute::Reset),
        )?;

        execute!(
            stdout,
            cursor::MoveTo(2, 3),
            SetForegroundColor(CtColor::DarkGrey),
            Print("Select your default AI tool:"),
            ResetColor,
        )?;

        for (i, t) in available.iter().enumerate() {
            let y = 5 + i as u16;
            if i == selected {
                execute!(
                    stdout,
                    cursor::MoveTo(2, y),
                    SetForegroundColor(CtColor::Cyan),
                    Print(format!("  > {}", t.name)),
                    ResetColor,
                )?;
            } else {
                execute!(
                    stdout,
                    cursor::MoveTo(2, y),
                    SetForegroundColor(CtColor::White),
                    Print(format!("    {}", t.name)),
                    ResetColor,
                )?;
            }
        }

        if !unavailable.is_empty() {
            let y = 5 + available.len() as u16 + 1;
            for (i, t) in unavailable.iter().enumerate() {
                execute!(
                    stdout,
                    cursor::MoveTo(2, y + i as u16),
                    SetForegroundColor(CtColor::DarkGrey),
                    Print(format!("    {} (not installed)", t.name)),
                    ResetColor,
                )?;
            }
        }

        let hint_y = 5 + tools.len() as u16 + 2;
        execute!(
            stdout,
            cursor::MoveTo(2, hint_y),
            SetForegroundColor(CtColor::DarkGrey),
            Print("↑/↓ navigate   enter select   q quit"),
            ResetColor,
        )?;

        stdout.flush()?;

        // Handle input.
        if let Event::Key(key) = event::read()? {
            match key.code {
                KeyCode::Up | KeyCode::Char('k') => {
                    selected = selected.saturating_sub(1);
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if selected + 1 < available.len() {
                        selected += 1;
                    }
                }
                KeyCode::Enter => {
                    break Ok(available[selected]);
                }
                KeyCode::Char('q') | KeyCode::Esc => {
                    break Err(anyhow::anyhow!("tool selection cancelled"));
                }
                _ => {}
            }
        }
    };

    // Restore terminal.
    execute!(stdout, cursor::Show, LeaveAlternateScreen)?;
    terminal::disable_raw_mode()?;

    let tool = result?;
    println!("  Saved {} as your default tool.\n", tool.name);
    save_default(&tool.name)?;

    Ok(ToolCommand {
        name: tool.name.clone(),
        command: tool.command.clone(),
        args: tool.args.clone(),
        supports_structured: tool_supports_structured(&tool.name),
    })
}

/// Returns `true` if a known tool supports structured JSON output
/// (`--output-format stream-json` for Claude Code, SSE API for OpenCode).
pub fn tool_supports_structured(name: &str) -> bool {
    matches!(name, "claude" | "opencode")
}

/// Returns `true` if a known tool supports a full HTTP API mode (no PTY needed).
/// Tools with API support use an adapter that communicates via HTTP/SSE instead of
/// spawning a PTY and tailing log files.
pub fn tool_supports_api(name: &str) -> bool {
    matches!(name, "opencode")
}

fn save_default(tool_name: &str) -> anyhow::Result<()> {
    let mut config = Config::load().unwrap_or_default();
    config.default_tool = Some(tool_name.to_string());
    config.save()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── tool_supports_structured ─────────────────────────────────────

    #[test]
    fn structured_supported_tools() {
        assert!(tool_supports_structured("claude"));
        assert!(tool_supports_structured("opencode"));
        assert!(!tool_supports_structured("aider"));
        assert!(!tool_supports_structured(""));
        assert!(!tool_supports_structured("unknown-tool"));
    }

    #[test]
    fn api_supported_tools() {
        assert!(tool_supports_api("opencode"));
        assert!(!tool_supports_api("claude"));
        assert!(!tool_supports_api("aider"));
        assert!(!tool_supports_api(""));
    }

    // ── known_tools ──────────────────────────────────────────────────

    #[test]
    fn known_tools_contains_expected_entries() {
        let tools = known_tools();
        let names: Vec<&str> = tools.iter().map(|(n, _, _)| *n).collect();
        assert!(names.contains(&"claude"));
        assert!(names.contains(&"opencode"));
        assert!(names.contains(&"copilot"));
        assert!(names.contains(&"gemini"));
        assert!(names.contains(&"aider"));
    }

    #[test]
    fn known_tools_copilot_uses_gh() {
        let tools = known_tools();
        let copilot = tools.iter().find(|(n, _, _)| *n == "copilot").unwrap();
        assert_eq!(copilot.1, "gh");
        assert_eq!(copilot.2, vec!["copilot", "cli"]);
    }

    // ── resolve_by_name ──────────────────────────────────────────────

    #[test]
    fn resolve_by_name_known_unavailable() {
        let tools = vec![ToolCandidate {
            name: "claude".to_string(),
            command: "claude".to_string(),
            args: vec![],
            available: false,
        }];
        let err = resolve_by_name("claude", &tools).unwrap_err();
        assert!(err.to_string().contains("not available on PATH"));
    }

    #[test]
    fn resolve_by_name_known_available() {
        let tools = vec![ToolCandidate {
            name: "claude".to_string(),
            command: "claude".to_string(),
            args: vec![],
            available: true,
        }];
        let result = resolve_by_name("claude", &tools).unwrap();
        assert_eq!(result.name, "claude");
        assert_eq!(result.command, "claude");
        assert!(result.supports_structured);
    }

    #[test]
    fn resolve_by_name_empty_string_errors() {
        let tools = vec![];
        let err = resolve_by_name("", &tools).unwrap_err();
        assert!(err.to_string().contains("empty"));
    }
}
