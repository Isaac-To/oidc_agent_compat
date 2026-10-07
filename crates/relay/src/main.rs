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
    Login {
        /// Optional token lifetime (e.g. '1d', '12h', '1y', '3600s').
        /// If omitted, the token never expires (unless the admin backstop clamps it).
        #[arg(long)]
        ttl: Option<String>,
    },
    /// Revoke the current central token (does not delete the agent config file).
    Logout,
    /// Re-display the local API key from the agent config file.
    PrintKey,
    /// List all tokens for the current user (via the central token API).
    ListKeys,
    /// Show recent relay request activity.
    Activity {
        /// Maximum number of entries to display (default 20, max 1000).
        #[arg(long, default_value_t = 20)]
        limit: u32,
    },
    /// Manage central tokens (create, list, revoke).
    Token {
        /// The token subcommand.
        #[command(subcommand)]
        command: TokenCommand,
    },
    /// Show relay status: config, database, central connectivity, token info.
    Status,
}

/// Subcommands for `oac-relay token`.
#[derive(Subcommand, Debug)]
enum TokenCommand {
    /// Mint a new labeled token using the current token for authentication.
    Create {
        /// Human-readable label for the new token (e.g. "codex").
        #[arg(long)]
        label: String,
        /// Optional token lifetime (e.g. '1d', '12h', '1y', '3600s').
        /// If omitted, the token never expires (unless the admin backstop clamps it).
        #[arg(long)]
        ttl: Option<String>,
    },
    /// List all tokens for the current user (same as `list-keys`).
    List,
    /// Revoke a specific token by its ID.
    Revoke {
        /// The token row ID (UUID) to revoke.
        token_id: String,
    },
}

fn main() {
    let cli = Cli::parse();

    // Initialize logging.
    let _ = oidc_agent_common::logging::init();

    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("oac-relay: error: failed to create async runtime: {e}");
            std::process::exit(1);
        }
    };

    let result = rt.block_on(async move {
        // `print-key` reads from the agent config file (written by `login`),
        // not from the relay TOML config or the database, so it does not need
        // to load a config file. All other subcommands require the config.
        if matches!(cli.command, Some(Command::PrintKey)) {
            return print_key_cmd().await;
        }
        let config = load_config(&cli.config)?;
        match cli.command.unwrap_or(Command::Serve) {
            Command::Serve => serve(config).await,
            Command::Login { ttl } => login_cmd(config, ttl.as_deref()).await,
            Command::Logout => logout_cmd(config).await,
            Command::PrintKey => print_key_cmd().await,
            Command::ListKeys => list_keys_cmd(config).await,
            Command::Activity { limit } => activity_cmd(config, limit).await,
            Command::Token { command } => token_cmd(config, command).await,
            Command::Status => status_cmd(&config).await,
        }
    });

    if let Err(e) = result {
        print_error(&e);
        std::process::exit(1);
    }
}

/// Prints a user-friendly error message with actionable hints.
fn print_error(err: &oidc_agent_common::error::Error) {
    use oidc_agent_common::error::Error;
    eprintln!("oac-relay: error: {err}");
    match err {
        Error::Config(msg) => {
            if msg.contains("No such file or directory") {
                eprintln!();
                eprintln!("hint: the config file was not found. Create one from the example:");
                eprintln!("  cp config.example.toml config.toml");
                eprintln!("  # then edit config.toml with your settings");
            } else if msg.contains("not logged in") {
                eprintln!();
                eprintln!("hint: run 'oac-relay login' first to authenticate via OIDC.");
            }
        }
        Error::Http(msg) => {
            if msg.contains("Connection refused") || msg.contains("connect") {
                eprintln!();
                eprintln!("hint: could not reach the central proxy. Is it running?");
                eprintln!("  Check the central URL in your config file.");
            }
        }
        Error::Database(msg) => {
            eprintln!();
            eprintln!("hint: database error: {msg}");
            eprintln!("  Check that the database_url in your config is correct.");
        }
        _ => {}
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
///
/// The relay is a dumb forwarder: it does not seed a local dev key. In dev
/// mode, the relay skips auth entirely (central rejects unauthenticated
/// requests via its token store). The dev stack should run `oac-relay login`
/// (or use a pre-minted central dev token).
async fn serve(config: RelayConfig) -> Result<()> {
    let db = db::setup(&config.database_url).await?;
    proxy::serve(config, db).await
}

/// Runs the OIDC login flow and configures the agent.
///
/// The optional `ttl` string is parsed into seconds and forwarded to the
/// central token API. See [`login::parse_ttl_to_seconds`] for supported
/// formats.
async fn login_cmd(config: RelayConfig, ttl: Option<&str>) -> Result<()> {
    let db = db::setup(&config.database_url).await?;
    let key_store = KeyStore::new(db);
    let result = login::run_login(&config, &key_store, ttl).await?;
    println!(
        "oac-relay: login successful for {} (agent config written to {})",
        result.email.as_deref().unwrap_or(&result.subject),
        result.injection.path.display()
    );
    Ok(())
}

/// Revokes the current central token via `DELETE /v1/tokens/current`.
///
/// Reads the current token from the agent config file, sends it to the
/// central proxy for revocation, and prints the result. The local identity
/// DB is left intact (the user's OIDC identity record stays for
/// convenience).
async fn logout_cmd(config: RelayConfig) -> Result<()> {
    // 1. Read the current token from the agent config file.
    let agent_config = oac_relay::agent_config::read().map_err(|e| {
        oidc_agent_common::error::Error::Config(format!(
            "not logged in — run oac-relay login first ({e})"
        ))
    })?;

    // 2. Build the central HTTP client (handles mTLS in production).
    let client = proxy::forward::build_client(&config)?;

    // 3. Call DELETE /v1/tokens/current with Authorization Bearer.
    let url = format!("{}/v1/tokens/current", config.central.url);
    let resp = client
        .delete(&url)
        .header("authorization", format!("Bearer {}", agent_config.api_key))
        .send()
        .await
        .map_err(|e| {
            oidc_agent_common::error::Error::Http(format!("failed to revoke token at central: {e}"))
        })?;

    let status = resp.status();
    if status == axum::http::StatusCode::NO_CONTENT {
        println!("oac-relay: token revoked at central");
        Ok(())
    } else if status == axum::http::StatusCode::NOT_FOUND {
        println!("oac-relay: token not found at central (already revoked or expired)");
        Ok(())
    } else {
        let body = resp.text().await.unwrap_or_default();
        Err(oidc_agent_common::error::Error::Http(format!(
            "failed to revoke token at central: {status} {body}"
        )))
    }
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

/// Lists all tokens for the current user via `GET /v1/tokens`.
///
/// Reads the current token from the agent config file, calls the central
/// token API with it as the bearer, and displays the returned list: id,
/// label, created_at, expires_at, last_used_at.
async fn list_keys_cmd(config: RelayConfig) -> Result<()> {
    // 1. Read the current token from the agent config file.
    let agent_config = oac_relay::agent_config::read().map_err(|e| {
        oidc_agent_common::error::Error::Config(format!(
            "not logged in — run oac-relay login first ({e})"
        ))
    })?;

    // 2. Build the central HTTP client (handles mTLS in production).
    let client = proxy::forward::build_client(&config)?;

    // 3. Call GET /v1/tokens with Authorization Bearer.
    let url = format!("{}/v1/tokens", config.central.url);
    let resp = client
        .get(&url)
        .header("authorization", format!("Bearer {}", agent_config.api_key))
        .send()
        .await
        .map_err(|e| {
            oidc_agent_common::error::Error::Http(format!("failed to list tokens at central: {e}"))
        })?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(oidc_agent_common::error::Error::Http(format!(
            "failed to list tokens at central: {status} {body}"
        )));
    }

    // 4. Parse and display the returned list.
    let items: Vec<serde_json::Value> = resp.json().await.map_err(|e| {
        oidc_agent_common::error::Error::Http(format!("failed to parse token list: {e}"))
    })?;

    if items.is_empty() {
        println!("oac-relay: no tokens found");
        return Ok(());
    }

    println!("oac-relay: {} token(s):", items.len());
    for item in &items {
        let id = item["id"].as_str().unwrap_or("-");
        let label = item["label"].as_str().unwrap_or("-");
        let created_at = item["created_at"].as_str().unwrap_or("-");
        let expires_at = item["expires_at"].as_str().unwrap_or("never");
        let last_used_at = item["last_used_at"].as_str().unwrap_or("never");
        println!(
            "  id={id} label={label} created={created_at} expires={expires_at} last_used={last_used_at}"
        );
    }
    Ok(())
}

/// Prints recent relay-side request activity.
async fn activity_cmd(config: RelayConfig, limit: u32) -> Result<()> {
    let db = oac_relay::db::setup(&config.database_url).await?;
    let logger = oac_relay::activity::ActivityLogger::new(db);
    let entries = logger.list_activity(limit).await?;

    if entries.is_empty() {
        println!("oac-relay: no activity found");
        return Ok(());
    }

    let suffix = if entries.len() == 1 { "y" } else { "ies" };
    println!("oac-relay: {} recent entr{}:", entries.len(), suffix);
    for entry in entries {
        println!(
            "  {} {} status={} latency_ms={} identity={} key={} model={} request_id={} created={}",
            entry.method,
            entry.endpoint,
            entry
                .central_status
                .map(|status| status.to_string())
                .unwrap_or_else(|| "unknown".into()),
            entry.latency_ms,
            entry.identity_id,
            entry.key_id,
            entry.model.unwrap_or_else(|| "-".into()),
            entry.request_id.unwrap_or_else(|| "-".into()),
            entry.created_at,
        );
    }
    Ok(())
}

/// Dispatches `oac-relay token` subcommands.
///
/// - `Create` → [`token_create_cmd`]: mints a new labeled token.
/// - `List` → [`list_keys_cmd`]: reuses the existing list-keys flow.
/// - `Revoke` → [`token_revoke_cmd`]: revokes a token by ID.
async fn token_cmd(config: RelayConfig, command: TokenCommand) -> Result<()> {
    match command {
        TokenCommand::Create { label, ttl } => {
            token_create_cmd(config, &label, ttl.as_deref()).await
        }
        TokenCommand::List => list_keys_cmd(config).await,
        TokenCommand::Revoke { token_id } => token_revoke_cmd(config, &token_id).await,
    }
}

/// Mints a new labeled token via `POST /v1/tokens` using the current token
/// for authentication.
///
/// The current token (from the agent config file) is sent as the `Authorization:
/// Bearer` header. The central proxy verifies it and uses the identity from
/// the token record — the body carries only `label` and `ttl_seconds`. The
/// returned plaintext token is printed for the user to copy into their agent
/// config manually.
async fn token_create_cmd(config: RelayConfig, label: &str, ttl: Option<&str>) -> Result<()> {
    // 1. Read the current token from the agent config file.
    let agent_config = oac_relay::agent_config::read().map_err(|e| {
        oidc_agent_common::error::Error::Config(format!(
            "not logged in — run oac-relay login first ({e})"
        ))
    })?;

    // 2. Parse the TTL.
    let ttl_seconds = match ttl {
        Some(t) => login::parse_ttl_to_seconds(t)?,
        None => None,
    };

    // 3. Build the central HTTP client (handles mTLS in production).
    let client = proxy::forward::build_client(&config)?;

    // 4. Compute the device fingerprint from the config client cert (if not
    //    dev mode).
    let device_fingerprint = if config.dev_mode {
        None
    } else {
        oidc_agent_common::mtls::cert_fingerprint(&config.central.client_cert_path)
    };

    // 5. POST to /v1/tokens with the current token as Bearer auth.
    let url = format!("{}/v1/tokens", config.central.url);
    let body = serde_json::json!({
        "label": label,
        "ttl_seconds": ttl_seconds,
    });

    let mut req = client
        .post(&url)
        .header("authorization", format!("Bearer {}", agent_config.api_key))
        .json(&body);

    if let Some(ref fp) = device_fingerprint {
        req = req.header(oidc_agent_common::identity::HEADER_DEVICE_FINGERPRINT, fp);
    }

    let resp = req.send().await.map_err(|e| {
        oidc_agent_common::error::Error::Http(format!("failed to mint token at central: {e}"))
    })?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(oidc_agent_common::error::Error::Http(format!(
            "failed to mint token at central: {status} {body}"
        )));
    }

    // 6. Parse and print the returned token plaintext.
    let minted: serde_json::Value = resp.json().await.map_err(|e| {
        oidc_agent_common::error::Error::Http(format!("failed to parse token response: {e}"))
    })?;

    let token = minted
        .get("token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| oidc_agent_common::error::Error::Http("missing token in response".into()))?;
    let token_id = minted
        .get("token_id")
        .and_then(|v| v.as_str())
        .unwrap_or("-");
    let expires_at = minted
        .get("expires_at")
        .and_then(|v| v.as_str())
        .unwrap_or("never");

    println!("oac-relay: token created");
    println!("  token_id  = {token_id}");
    println!("  label     = {label}");
    println!("  expires   = {expires_at}");
    println!("  token     = {token}");
    println!();
    println!("Copy this token into your agent config (api_key field).");

    Ok(())
}

/// Revokes a specific token by its ID via `DELETE /v1/tokens/{id}`.
///
/// Reads the current token from the agent config file for authentication,
/// then calls the central proxy's revoke-by-id endpoint.
async fn token_revoke_cmd(config: RelayConfig, token_id: &str) -> Result<()> {
    // 1. Read the current token from the agent config file.
    let agent_config = oac_relay::agent_config::read().map_err(|e| {
        oidc_agent_common::error::Error::Config(format!(
            "not logged in — run oac-relay login first ({e})"
        ))
    })?;

    // 2. Build the central HTTP client (handles mTLS in production).
    let client = proxy::forward::build_client(&config)?;

    // 3. DELETE /v1/tokens/{id} with Authorization Bearer.
    let url = format!("{}/v1/tokens/{token_id}", config.central.url);
    let resp = client
        .delete(&url)
        .header("authorization", format!("Bearer {}", agent_config.api_key))
        .send()
        .await
        .map_err(|e| {
            oidc_agent_common::error::Error::Http(format!("failed to revoke token at central: {e}"))
        })?;

    let status = resp.status();
    if status == axum::http::StatusCode::NO_CONTENT {
        println!("oac-relay: token {token_id} revoked at central");
        Ok(())
    } else {
        let body = resp.text().await.unwrap_or_default();
        Err(oidc_agent_common::error::Error::Http(format!(
            "failed to revoke token at central: {status} {body}"
        )))
    }
}

/// Shows relay status: config summary, database health, central connectivity,
/// and token info.
///
/// This is a diagnostic command — it does not start the relay server. It
/// checks each component and reports OK/WARN/FAIL for each.
async fn status_cmd(config: &RelayConfig) -> Result<()> {
    println!("oac-relay: status");
    println!();

    // 1. Config summary (redacted).
    println!("Config:");
    println!("  listen_addr   = {}", config.listen_addr);
    println!("  database_url  = {}", redact_db_url(&config.database_url));
    println!("  oidc.issuer   = {}", config.oidc.issuer);
    println!("  oidc.client_id = {}", config.oidc.client_id);
    println!("  central.url   = {}", config.central.url);
    println!("  dev_mode      = {}", config.dev_mode);
    println!();

    // 2. Database health.
    print!("Database: ");
    match db::setup(&config.database_url).await {
        Ok(_db) => println!("OK"),
        Err(e) => println!("FAIL ({e})"),
    }
    println!();

    // 3. Central connectivity.
    print!("Central proxy: ");
    match check_central_health(config).await {
        Ok(()) => println!("OK (reachable)"),
        Err(e) => println!("WARN ({e})"),
    }
    println!();

    // 4. Agent config (login status).
    print!("Agent config: ");
    match oac_relay::agent_config::read() {
        Ok(agent_cfg) => {
            println!("OK (logged in)");
            println!("  base_url = {}", agent_cfg.base_url);
            // Redact the API key — show only the prefix.
            let key_preview = if agent_cfg.api_key.len() > 12 {
                format!("{}...", &agent_cfg.api_key[..12])
            } else {
                "***".to_string()
            };
            println!("  api_key  = {key_preview}");
        }
        Err(_) => {
            println!("NOT FOUND (run 'oac-relay login' to authenticate)");
        }
    }
    println!();

    // 5. Token list (if logged in).
    if oac_relay::agent_config::read().is_ok() {
        print!("Token list: ");
        match list_tokens_for_status(config).await {
            Ok(count) => println!("OK ({count} token(s))"),
            Err(e) => println!("WARN ({e})"),
        }
    }

    Ok(())
}

/// Checks if the central proxy is reachable by hitting its health endpoint.
async fn check_central_health(config: &RelayConfig) -> Result<()> {
    let client = proxy::forward::build_client(config)?;
    let url = format!("{}/healthz", config.central.url.trim_end_matches('/'));
    let resp = client
        .get(&url)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
        .map_err(|e| oidc_agent_common::error::Error::Http(format!("health check: {e}")))?;
    if resp.status().is_success() {
        Ok(())
    } else {
        Err(oidc_agent_common::error::Error::Http(format!(
            "health check returned {}",
            resp.status()
        )))
    }
}

/// Lists tokens for the status command. Returns the count on success.
async fn list_tokens_for_status(config: &RelayConfig) -> Result<usize> {
    let agent_config = oac_relay::agent_config::read()
        .map_err(|e| oidc_agent_common::error::Error::Config(format!("not logged in: {e}")))?;
    let client = proxy::forward::build_client(config)?;
    let url = format!("{}/v1/tokens", config.central.url);
    let resp = client
        .get(&url)
        .header("authorization", format!("Bearer {}", agent_config.api_key))
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
        .map_err(|e| oidc_agent_common::error::Error::Http(format!("list tokens: {e}")))?;
    if !resp.status().is_success() {
        return Err(oidc_agent_common::error::Error::Http(format!(
            "list tokens returned {}",
            resp.status()
        )));
    }
    let items: Vec<serde_json::Value> = resp
        .json()
        .await
        .map_err(|e| oidc_agent_common::error::Error::Http(format!("parse token list: {e}")))?;
    Ok(items.len())
}

/// Redacts a database URL for display (shows only the scheme and filename).
fn redact_db_url(url: &str) -> String {
    if let Some(path) = url.strip_prefix("sqlite://") {
        // Show only the filename, not the full path.
        let filename = std::path::Path::new(path)
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_else(|| path.to_string());
        format!("sqlite://.../{filename}")
    } else if url.starts_with("postgres://") || url.starts_with("postgresql://") {
        // Redact credentials in postgres URLs: postgres://user:pass@host/db
        // → postgres://user:***@host/db
        if let Some(at_pos) = url.rfind('@') {
            let scheme_end = url.find("://").map(|i| i + 3).unwrap_or(0);
            let after_scheme = &url[scheme_end..];
            if let Some(colon_pos) = after_scheme.find(':') {
                let user = &after_scheme[..colon_pos];
                let rest = &url[at_pos..];
                let scheme = &url[..scheme_end];
                return format!("{scheme}{user}:***{rest}");
            }
        }
        url.to_string()
    } else {
        url.to_string()
    }
}
