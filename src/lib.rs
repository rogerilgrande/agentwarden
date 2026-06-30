//! agentwarden: a miniature AI-agent tool-call policy gate.
//!
//! POST a proposed tool call to `/evaluate`; get back `allow` / `deny` / `ask`
//! against a hot-reloadable `policy.toml`. This is the *decision* layer of an
//! agent safety harness: the allow/deny/ask policy, not kernel-level enforcement.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used))]

mod config;
mod engine;
mod error;
mod policy;
mod server;
mod types;

use anyhow::Context;
use clap::{Parser, Subcommand};

use crate::config::Config;
use crate::policy::{FilePolicyStore, PolicyStore};
use crate::types::ToolCall;

/// The CLI: one binary, three front doors onto the same engine.
#[derive(Parser)]
#[command(name = "agentwarden", about = "AI-agent tool-call policy gate")]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the HTTP service (default).
    Serve,
    /// Evaluate one command against the policy and print the decision as JSON.
    Check {
        #[arg(long)]
        command: String,
        #[arg(long, default_value = "bash")]
        tool: String,
        #[arg(long, default_value = "cli")]
        agent: String,
    },
    /// Validate the policy file and report the rule count.
    Lint,
}

/// Parse the CLI and dispatch to the selected subcommand. The binary's `main`
/// is a thin wrapper over this so the logic lives in (and is testable from) the library.
pub async fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config = Config::from_env()?;
    match cli.cmd.unwrap_or(Command::Serve) {
        Command::Serve => server::serve(config).await,
        Command::Check {
            command,
            tool,
            agent,
        } => check(config, tool, command, agent).await,
        Command::Lint => lint(config).await,
    }
}

/// One-shot evaluation from the terminal, reusing the same engine as the server.
async fn check(config: Config, tool: String, command: String, agent: String) -> anyhow::Result<()> {
    let store = FilePolicyStore::load(config.policy_path.clone())
        .await
        .with_context(|| format!("loading policy from {}", config.policy_path.display()))?;
    let policy = store.current().await;
    let call = ToolCall {
        tool,
        command,
        agent: agent.parse().context("invalid --agent")?,
        session: None,
    };
    println!(
        "{}",
        serde_json::to_string(&engine::evaluate(&policy, &call))?
    );
    Ok(())
}

/// Validate the policy file (compiling every rule) and report the rule count.
async fn lint(config: Config) -> anyhow::Result<()> {
    let store = FilePolicyStore::load(config.policy_path.clone())
        .await
        .with_context(|| format!("loading policy from {}", config.policy_path.display()))?;
    println!("ok: {} rules", store.current().await.rules.len());
    Ok(())
}
