mod ai_tools;
mod attach;
mod constants;
mod host;
mod pty;
mod relay_client;
mod state;

use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand};
use tracing::info;

use crate::{
    ai_tools::detect_known_tools,
    attach::{AttachArgs, run_attach},
    host::{HostArgs, run_host_sessions},
    state::SessionStore,
};

#[derive(Debug, Parser)]
#[command(name = constants::APP_NAME)]
#[command(about = "Mirror local terminal AI sessions to remote clients")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Start(HostArgs),
    Attach(AttachArgs),
    DetectTools,
    Sessions,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,terminal_relay_cli=debug".into()),
        )
        .init();

    let cli = Cli::parse();
    let store = SessionStore::new(default_state_dir()?)?;

    match cli.command {
        Command::Start(args) => run_host_sessions(args, store).await?,
        Command::Attach(args) => run_attach(args).await?,
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

    info!("command finished");
    Ok(())
}

fn default_state_dir() -> anyhow::Result<PathBuf> {
    let base = dirs::home_dir().context("failed resolving home directory")?;
    Ok(base.join(constants::STATE_DIR_NAME))
}
