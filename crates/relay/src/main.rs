//! The laptop relay component of the OIDC agent compatibility server.
//!
//! The relay listens on `127.0.0.1`, authenticates the employee via OIDC
//! against the enterprise IdP, mints a local API key that is auto-injected
//! into the agent's config, and forwards agent requests to the central proxy
//! over mTLS. It holds **no master backend key** — only a short-lived user
//! token and an mTLS client certificate.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod db;
pub mod entity;
pub mod migration;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use oidc_agent_common::config::RelayConfig;
use oidc_agent_common::error::Result;

/// The laptop relay for the OIDC agent compatibility server.
#[derive(Parser, Debug)]
#[command(name = "oac-relay", version, about)]
struct Cli {
    /// Path to the config file.
    #[arg(short, long, env = "OAC_RELAY_CONFIG", default_value = "config.toml")]
    config: PathBuf,

    /// The subcommand to run.
    #[command(subcommand)]
    command: Option<Command>,
}

/// Available subcommands.
#[derive(Subcommand, Debug)]
enum Command {
    /// Start the relay server (default).
    Serve,
    /// Authenticate via OIDC and configure the agent.
    Login,
    /// Revoke local keys and clear agent config.
    Logout,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = load_config(&cli.config)?;

    match cli.command.unwrap_or(Command::Serve) {
        Command::Serve => serve(config),
        Command::Login => login(config),
        Command::Logout => logout(config),
    }
}

/// Loads the relay config from the given path.
fn load_config(path: &std::path::Path) -> Result<RelayConfig> {
    let contents = std::fs::read_to_string(path).map_err(|e| {
        oidc_agent_common::error::Error::Config(format!("read {}: {e}", path.display()))
    })?;
    RelayConfig::from_toml(&contents)
}

/// Starts the relay server.
fn serve(_config: RelayConfig) -> Result<()> {
    println!("oac-relay: serve (not yet implemented — see Phase 3)");
    Ok(())
}

/// Runs the OIDC login flow and configures the agent.
fn login(_config: RelayConfig) -> Result<()> {
    println!("oac-relay: login (not yet implemented — see Phase 2)");
    Ok(())
}

/// Revokes local keys and clears the agent config.
fn logout(_config: RelayConfig) -> Result<()> {
    println!("oac-relay: logout (not yet implemented)");
    Ok(())
}
