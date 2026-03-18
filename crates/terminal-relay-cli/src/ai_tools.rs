use serde::{Deserialize, Serialize};

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

/// Resolve a tool by name. If `tool` is None, auto-detect the first available.
/// If the name matches a known tool, use its binary and default args.
/// Otherwise, treat the name as a raw command.
pub fn resolve_tool(tool: Option<&str>, extra_args: &[String]) -> anyhow::Result<ToolCommand> {
    let tools = detect_known_tools();

    let chosen = match tool {
        None => {
            // Auto-detect: pick the first available known tool.
            let candidate = tools.into_iter().find(|c| c.available).ok_or_else(|| {
                anyhow::anyhow!(
                    "no supported AI tool detected on PATH. Use --tool <name> to specify one"
                )
            })?;
            ToolCommand {
                name: candidate.name,
                command: candidate.command,
                args: candidate.args,
            }
        }
        Some(name) => {
            // Check known tools first.
            if let Some(candidate) = tools.iter().find(|c| c.name == name) {
                if !candidate.available {
                    return Err(anyhow::anyhow!(
                        "tool '{}' is not available on PATH",
                        candidate.name
                    ));
                }
                ToolCommand {
                    name: candidate.name.clone(),
                    command: candidate.command.clone(),
                    args: candidate.args.clone(),
                }
            } else {
                // Unknown name — treat as a raw command.
                // Split on whitespace to support e.g. --tool "my-tool --flag"
                let parts: Vec<&str> = name.split_whitespace().collect();
                let (cmd, cmd_args) = parts
                    .split_first()
                    .ok_or_else(|| anyhow::anyhow!("--tool value cannot be empty"))?;

                if which::which(cmd).is_err() {
                    return Err(anyhow::anyhow!("'{}' is not found on PATH", cmd));
                }

                ToolCommand {
                    name: cmd.to_string(),
                    command: cmd.to_string(),
                    args: cmd_args.iter().map(|s| s.to_string()).collect(),
                }
            }
        }
    };

    let mut args = chosen.args;
    args.extend(extra_args.iter().cloned());
    Ok(ToolCommand {
        name: chosen.name,
        command: chosen.command,
        args,
    })
}
