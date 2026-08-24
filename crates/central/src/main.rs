//! The central proxy binary entrypoint.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use oac_central::audit::AuditLogger;
use oac_central::db;
use oac_central::proxy;
use oac_central::secrets;
use oidc_agent_common::config::CentralConfig;
use oidc_agent_common::error::Result;

/// The central proxy for the OIDC agent compatibility server.
#[derive(Parser, Debug)]
#[command(name = "oac-central", version, about)]
struct Cli {
    /// Path to the config file.
    #[arg(short, long, env = "OAC_CENTRAL_CONFIG", default_value = "config.toml")]
    config: PathBuf,

    /// The subcommand to run.
    #[command(subcommand)]
    command: Option<Command>,
}

/// Available subcommands.
#[derive(Subcommand, Debug)]
enum Command {
    /// Start the central proxy server (default).
    Serve,
    /// Set the master backend key in the secret store.
    SetBackendKey,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = load_config(&cli.config)?;

    let _ = oidc_agent_common::logging::init();

    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| oidc_agent_common::error::Error::Internal(format!("tokio runtime: {e}")))?;
    rt.block_on(async {
        match cli.command.unwrap_or(Command::Serve) {
            Command::Serve => serve(config).await,
            Command::SetBackendKey => set_backend_key(config).await,
        }
    })
}

/// Loads the central config from the given path.
fn load_config(path: &std::path::Path) -> Result<CentralConfig> {
    let contents = std::fs::read_to_string(path).map_err(|e| {
        oidc_agent_common::error::Error::Config(format!("read {}: {e}", path.display()))
    })?;
    CentralConfig::from_toml(&contents)
}

/// Starts the central proxy server.
async fn serve(config: CentralConfig) -> Result<()> {
    let db = db::setup(&config.database_url).await?;
    let audit = AuditLogger::new(db);

    // Load the master key from the secret store.
    let secret_store = secrets::from_config(&config.secret_store)?;
    let master_key = secret_store.load_master_key().await?;

    proxy::serve(config, master_key, audit).await
}

/// Sets the master backend key in the secret store.
async fn set_backend_key(config: CentralConfig) -> Result<()> {
    let secret_store = secrets::from_config(&config.secret_store)?;

    // Prompt for the key via rpassword (no echo).
    let key = rpassword::prompt_password("Enter master backend key: ")
        .map_err(|e| oidc_agent_common::error::Error::SecretStore(format!("read password: {e}")))?;

    if key.is_empty() {
        return Err(oidc_agent_common::error::Error::SecretStore(
            "master key must not be empty".into(),
        ));
    }

    secret_store.store_master_key(&key).await?;
    println!("oac-central: master key stored in secret store");
    Ok(())
}
