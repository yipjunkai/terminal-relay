#[cfg(feature = "hosted")]
mod account;
mod ai_tools;
mod attach;
mod common;
mod config;
mod constants;
mod host;
mod jsonl_watcher;
mod opencode_adapter;
mod pty;
mod relay_client;
mod state;
mod tui;

use std::path::PathBuf;

use anyhow::Context;
use clap::{CommandFactory, Parser, Subcommand};

use clap_complete::Shell;

use crate::{
    ai_tools::detect_known_tools,
    attach::{AttachArgs, run_attach},
    host::{HostArgs, run_host_sessions},
    state::SessionStore,
};

#[derive(Debug, Parser)]
#[command(name = constants::APP_NAME)]
#[command(version)]
#[command(about = "Mirror local terminal AI sessions to remote clients")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Start a host session (spawn an AI tool and share via relay).
    Start(HostArgs),
    /// Attach to a remote session as a client.
    Attach(AttachArgs),
    /// Authenticate with the Farwatch hosted service.
    #[cfg(feature = "hosted")]
    Auth {
        /// Email address to register a new account.
        #[arg(long)]
        email: Option<String>,
        /// Existing API key to log in with.
        #[arg(long)]
        api_key: Option<String>,
        /// Invite code (required for new registrations).
        #[arg(long)]
        invite_code: Option<String>,
    },
    /// Log out and remove the stored API key.
    #[cfg(feature = "hosted")]
    Logout,
    /// Show environment, auth status, detected tools, and connectivity.
    Doctor,
    /// Generate shell completions.
    Completions {
        /// Shell to generate completions for.
        #[arg(value_enum)]
        shell: Shell,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load .env file if present (silently ignored if missing).
    let _ = dotenvy::dotenv();

    let cli = Cli::parse();

    // For the `start` command, suppress tracing stderr output because the TUI
    // owns the terminal. Other commands use normal stderr logging.
    let is_tui = matches!(cli.command, Command::Start(_));
    if is_tui {
        tracing_subscriber::fmt()
            .with_writer(std::io::sink)
            .with_env_filter("off")
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "info,cli=debug".into()),
            )
            .init();
    }

    let store = SessionStore::new(default_state_dir()?)?;

    match cli.command {
        Command::Start(args) => run_host_sessions(args, store).await?,
        Command::Attach(args) => run_attach(args).await?,
        #[cfg(feature = "hosted")]
        Command::Auth {
            email,
            api_key,
            invite_code,
        } => {
            account::auth(email.as_deref(), api_key.as_deref(), invite_code.as_deref()).await?;
        }
        #[cfg(feature = "hosted")]
        Command::Logout => {
            account::logout()?;
        }
        Command::Doctor => {
            run_doctor().await;
        }
        Command::Completions { shell } => {
            clap_complete::generate(
                shell,
                &mut Cli::command(),
                constants::APP_NAME,
                &mut std::io::stdout(),
            );
        }
    }

    Ok(())
}

async fn run_doctor() {
    use crossterm::style::{Attribute, Color, Print, ResetColor, SetAttribute, SetForegroundColor};

    fn label(s: &str) {
        let _ = crossterm::execute!(
            std::io::stdout(),
            SetForegroundColor(Color::DarkGrey),
            Print(format!("  {:<14}", s)),
            ResetColor
        );
    }
    fn ok(s: &str) {
        let _ = crossterm::execute!(
            std::io::stdout(),
            SetForegroundColor(Color::Green),
            Print("✓ "),
            ResetColor,
            Print(format!("{s}\n"))
        );
    }
    fn warn(s: &str) {
        let _ = crossterm::execute!(
            std::io::stdout(),
            SetForegroundColor(Color::Yellow),
            Print("! "),
            ResetColor,
            Print(format!("{s}\n"))
        );
    }
    fn fail(s: &str) {
        let _ = crossterm::execute!(
            std::io::stdout(),
            SetForegroundColor(Color::Red),
            Print("✗ "),
            ResetColor,
            Print(format!("{s}\n"))
        );
    }

    println!();
    crossterm::execute!(
        std::io::stdout(),
        SetAttribute(Attribute::Bold),
        Print("  Farwatch Doctor\n"),
        SetAttribute(Attribute::Reset),
    )
    .ok();
    println!();

    // Version
    label("Version");
    ok(&format!("v{}", constants::CLIENT_VERSION));

    // Build
    label("Build");
    if cfg!(feature = "hosted") {
        ok("hosted (with auth)");
    } else {
        ok("self-hosted (no auth)");
    }

    // Config
    label("Config");
    let config = config::Config::load().unwrap_or_default();
    match &config.default_tool {
        Some(tool) => ok(&format!("default tool: {tool}")),
        None => warn("no default tool (will prompt on first start)"),
    }

    // Auth (hosted only)
    #[cfg(feature = "hosted")]
    {
        label("Auth");
        match &config.api_key {
            Some(key) => {
                let prefix = if key.len() > 16 { &key[..16] } else { key };
                ok(&format!("{prefix}..."));
            }
            None => warn("not authenticated — run `farwatch auth`"),
        }
    }

    // Relay connectivity
    label("Relay");
    #[cfg(feature = "hosted")]
    {
        let relay_url = format!(
            "{}/healthz",
            constants::DEFAULT_RELAY_URL
                .replace("wss://", "https://")
                .replace("ws://", "http://")
                .replace("/ws", "")
        );
        match reqwest::get(&relay_url).await {
            Ok(resp) if resp.status().is_success() => {
                ok(&format!("{} (reachable)", constants::DEFAULT_RELAY_URL))
            }
            Ok(resp) => warn(&format!(
                "{} (HTTP {})",
                constants::DEFAULT_RELAY_URL,
                resp.status()
            )),
            Err(_) => fail(&format!("{} (unreachable)", constants::DEFAULT_RELAY_URL)),
        }
    }
    #[cfg(not(feature = "hosted"))]
    {
        ok("self-hosted (use FARWATCH_URL to configure)");
    }

    // Tools
    println!();
    let _ = crossterm::execute!(
        std::io::stdout(),
        SetAttribute(Attribute::Bold),
        Print("  AI Tools\n"),
        SetAttribute(Attribute::Reset),
    );
    println!();

    for tool in detect_known_tools() {
        label(&tool.name);
        if tool.available {
            let path = which::which(&tool.command)
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| tool.command.clone());
            ok(&path);
        } else {
            fail("not found");
        }
    }

    println!();
}

fn default_state_dir() -> anyhow::Result<PathBuf> {
    let base = dirs::home_dir().context("failed resolving home directory")?;
    Ok(base.join(constants::STATE_DIR_NAME))
}
