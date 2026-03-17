use clap::ValueEnum;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCandidate {
    pub name: String,
    pub command: String,
    pub args: Vec<String>,
    pub available: bool,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum ToolSelector {
    Auto,
    Claude,
    Copilot,
    Gemini,
    Aider,
}

#[derive(Debug, Clone)]
pub struct ToolCommand {
    pub name: String,
    pub command: String,
    pub args: Vec<String>,
}

pub fn detect_known_tools() -> Vec<ToolCandidate> {
    let candidates = [
        ("claude", "claude", vec![]),
        (
            "copilot",
            "gh",
            vec!["copilot".to_string(), "cli".to_string()],
        ),
        ("gemini", "gemini", vec![]),
        ("aider", "aider", vec![]),
    ];

    candidates
        .into_iter()
        .map(|(name, command, args)| ToolCandidate {
            name: name.to_string(),
            command: command.to_string(),
            args,
            available: which::which(command).is_ok(),
        })
        .collect()
}

pub fn resolve_tool(selector: ToolSelector, extra_args: &[String]) -> anyhow::Result<ToolCommand> {
    let tools = detect_known_tools();
    let chosen = match selector {
        ToolSelector::Auto => tools
            .into_iter()
            .find(|candidate| candidate.available)
            .ok_or_else(|| anyhow::anyhow!("no supported AI terminal tool detected"))?,
        ToolSelector::Claude => pick(&tools, "claude")?,
        ToolSelector::Copilot => pick(&tools, "copilot")?,
        ToolSelector::Gemini => pick(&tools, "gemini")?,
        ToolSelector::Aider => pick(&tools, "aider")?,
    };

    if !chosen.available {
        return Err(anyhow::anyhow!(
            "selected tool '{}' is not available on PATH",
            chosen.name
        ));
    }

    let mut args = chosen.args;
    args.extend(extra_args.iter().cloned());
    Ok(ToolCommand {
        name: chosen.name,
        command: chosen.command,
        args,
    })
}

fn pick(tools: &[ToolCandidate], name: &str) -> anyhow::Result<ToolCandidate> {
    tools
        .iter()
        .find(|candidate| candidate.name == name)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("unknown tool {name}"))
}
