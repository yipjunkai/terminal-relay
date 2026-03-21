#[cfg(feature = "hosted")]
mod account;
mod ai_tools;
mod attach;
mod common;
mod config;
mod constants;
mod host;
mod pty;
mod relay_client;
mod state;
mod tui;

use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand};

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
    /// Authenticate with the Terminal Relay hosted service.
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
    /// Show the current authentication status.
    #[cfg(feature = "hosted")]
    Status,
    /// List known AI tools and their PATH availability.
    DetectTools,
    /// List persisted session records.
    Sessions,
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
        #[cfg(feature = "hosted")]
        Command::Status => {
            let config = config::Config::load()?;
            match config.api_key {
                Some(key) => {
                    let prefix = if key.len() > 16 { &key[..16] } else { &key };
                    println!("Authenticated");
                    println!("  API key:     {prefix}...");
                    println!(
                        "  Control API: {}",
                        config
                            .control_api_url
                            .as_deref()
                            .unwrap_or(constants::DEFAULT_CONTROL_API_URL)
                    );
                }
                None => {
                    println!("Not authenticated. Run `terminal-relay auth` to get started.");
                }
            }
        }
        Command::DetectTools => {
            for tool in detect_known_tools() {
                println!(
                    "{}\t{}\t{}",
                    tool.name,
                    if tool.available {
                        "available"
                    } else {
                        "missing"
                    },
                    tool.command
                );
            }
        }
        Command::Sessions => {
            let records = store.list().context("failed reading persisted sessions")?;
            if records.is_empty() {
                println!("No persisted sessions");
            } else {
                for record in records {
                    println!(
                        "{}\t{}\t{}\t{}",
                        record.session_id, record.tool, record.relay_url, record.created_at
                    );
                }
            }
        }
    }

    Ok(())
}

fn default_state_dir() -> anyhow::Result<PathBuf> {
    let base = dirs::home_dir().context("failed resolving home directory")?;
    Ok(base.join(constants::STATE_DIR_NAME))
}
