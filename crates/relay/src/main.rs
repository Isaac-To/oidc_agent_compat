//! The laptop relay binary entrypoint.

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
use oac_relay::db;
use oac_relay::keystore::KeyStore;
use oac_relay::login;
use oac_relay::proxy;
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
    /// Re-display the local API key from the agent config file.
    PrintKey,
    /// List all local API keys.
    ListKeys,
    /// Revoke a local API key by its ID.
    RevokeKey {
        /// The key ID to revoke.
        key_id: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = load_config(&cli.config)?;

    // Initialize logging.
    let _ = oidc_agent_common::logging::init();

    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| oidc_agent_common::error::Error::Internal(format!("tokio runtime: {e}")))?;
    rt.block_on(async {
        match cli.command.unwrap_or(Command::Serve) {
            Command::Serve => serve(config).await,
            Command::Login => login_cmd(config).await,
            Command::Logout => logout_cmd(config).await,
            Command::PrintKey => print_key_cmd().await,
            Command::ListKeys => list_keys_cmd(config).await,
            Command::RevokeKey { key_id } => revoke_key_cmd(config, &key_id).await,
        }
    })
}

/// Loads the relay config from the given path.
fn load_config(path: &std::path::Path) -> Result<RelayConfig> {
    let contents = std::fs::read_to_string(path).map_err(|e| {
        oidc_agent_common::error::Error::Config(format!("read {}: {e}", path.display()))
    })?;
    RelayConfig::from_toml(&contents)
}

/// Starts the relay server.
async fn serve(config: RelayConfig) -> Result<()> {
    let db = db::setup(&config.database_url).await?;
    let key_store = KeyStore::new(db);

    // In dev mode, seed a well-known API key so containerized agents (e.g.
    // Goose) and manual curl can authenticate without running the full OIDC
    // login flow. This is strictly gated behind `dev_mode` (false in all
    // production configs) and is idempotent across restarts.
    if config.dev_mode {
        seed_dev_key(&key_store).await?;
    }

    proxy::serve(config, key_store).await
}

/// The well-known plaintext dev API key minted when `dev_mode` is enabled.
///
/// This matches the `OPENAI_API_KEY` configured for the Goose service in
/// `docker/dev/docker-compose.yml`. It is intentionally a constant (not random)
/// so the dev stack works out of the box without any login step.
const DEV_KEY_PLAINTEXT: &str = "oac_test_key_alice";

/// Seeds the well-known dev API key into the key store if it is not already
/// present. Idempotent: skips minting if a key with the dev plaintext already
/// verifies.
///
/// # Security
///
/// Only called when `config.dev_mode` is true. The key value is never logged.
///
/// # Errors
///
/// Returns [`Error`] if the identity upsert, verification, or mint fails.
async fn seed_dev_key(key_store: &KeyStore) -> Result<()> {
    // Upsert a dev identity (issuer "dev", subject "dev-user").
    let identity = key_store
        .upsert_identity("dev", "dev-user", None, Some("Dev User"), None)
        .await?;

    // Only mint if the dev key is not already present (idempotent across
    // restarts — avoids duplicate rows).
    let existing = key_store.verify_key(DEV_KEY_PLAINTEXT).await?;
    if existing.is_none() {
        key_store
            .mint_dev_key(&identity.id, "dev", DEV_KEY_PLAINTEXT)
            .await?;
        tracing::info!(
            "dev_mode: seeded well-known dev API key (label 'dev') for identity {}",
            identity.id
        );
    } else {
        tracing::debug!("dev_mode: dev API key already present, skipping seed");
    }
    Ok(())
}

/// Runs the OIDC login flow and configures the agent.
async fn login_cmd(config: RelayConfig) -> Result<()> {
    let db = db::setup(&config.database_url).await?;
    let key_store = KeyStore::new(db);
    let result = login::run_login(&config, &key_store).await?;
    println!(
        "oac-relay: login successful for {} (agent config written to {})",
        result.email.as_deref().unwrap_or(&result.subject),
        result.injection.path.display()
    );
    Ok(())
}

/// Revokes local keys and clears the agent config.
async fn logout_cmd(config: RelayConfig) -> Result<()> {
    let db = db::setup(&config.database_url).await?;
    let key_store = KeyStore::new(db);
    use sea_orm::EntityTrait;
    let identities = oac_relay::entity::identity::Entity::find()
        .all(&key_store.db)
        .await
        .map_err(|e| oidc_agent_common::error::Error::Database(format!("load identities: {e}")))?;
    let mut total = 0;
    for ident in identities {
        total += key_store
            .revoke_all_keys(&ident.id)
            .await
            .map(|n| n as usize)
            .unwrap_or(0);
    }
    println!("oac-relay: revoked {total} key(s)");
    Ok(())
}

/// Re-displays the local API key from the agent config file.
///
/// The key is read from the agent config file (where `login` wrote it), not
/// from the database (which only stores the hash). This is useful when the
/// employee needs to reconfigure their agent manually.
async fn print_key_cmd() -> Result<()> {
    let config = oac_relay::agent_config::read()?;
    println!("oac-relay: agent config:");
    println!("  base_url = {}", config.base_url);
    println!("  api_key  = {}", config.api_key);
    Ok(())
}

/// Lists all local API keys (key ID, label, creation time, last used).
async fn list_keys_cmd(config: RelayConfig) -> Result<()> {
    let db = oac_relay::db::setup(&config.database_url).await?;
    let key_store = oac_relay::keystore::KeyStore::new(db);

    use oac_relay::entity::api_key;
    use sea_orm::EntityTrait;
    let keys = api_key::Entity::find()
        .all(&key_store.db)
        .await
        .map_err(|e| oidc_agent_common::error::Error::Database(format!("list keys: {e}")))?;

    if keys.is_empty() {
        println!("oac-relay: no keys found");
        return Ok(());
    }

    println!("oac-relay: {} key(s):", keys.len());
    for key in &keys {
        println!(
            "  id={} label={} created={} last_used={}",
            key.id,
            key.label,
            key.created_at,
            key.last_used_at
                .map(|t| t.to_string())
                .unwrap_or_else(|| "never".into()),
        );
    }
    Ok(())
}

/// Revokes a local API key by its ID (deletes it from the database).
async fn revoke_key_cmd(config: RelayConfig, key_id: &str) -> Result<()> {
    let db = oac_relay::db::setup(&config.database_url).await?;
    let key_store = oac_relay::keystore::KeyStore::new(db);

    let revoked = key_store.revoke_key(key_id).await?;

    if revoked {
        println!("oac-relay: revoked key {key_id}");
    } else {
        println!("oac-relay: key {key_id} not found");
    }
    Ok(())
}
