//! Agent configuration injection.
//!
//! After a successful OIDC login, the relay writes the base URL + local API
//! key directly into the agent's config file so the employee never has to
//! copy/paste a key. This module detects known agent config formats and
//! updates them.
//!
//! # Supported agents (v1)
//!
//! - **Codex** (`~/.codex/config.json` or `$CODEX_HOME/config.json`): writes
//!   `api_base_url` and `api_key` fields.
//! - **Generic OpenAI-compatible**: writes a `~/.oac/agent-env.sh` file with
//!   `OPENAI_API_BASE` and `OPENAI_API_KEY` that the user can `source`.
//!
//! # Security
//!
//! The config file is written with `0600` permissions so other local users
//! cannot read the key.

use std::path::{Path, PathBuf};

use oidc_agent_common::error::{Error, Result};

/// The agent config to inject.
#[derive(Debug, Clone)]
pub struct AgentConfig {
    /// The base URL the agent should point at (e.g. `http://127.0.0.1:8787/v1`).
    pub base_url: String,
    /// The local API key (plaintext, written once then dropped).
    pub api_key: String,
}

/// The result of injecting config: which agent was configured and where.
#[derive(Debug, Clone)]
pub struct InjectionResult {
    /// The agent kind that was configured.
    pub agent: AgentKind,
    /// The config file path that was written.
    pub path: PathBuf,
}

/// Known agent config formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentKind {
    /// OpenAI Codex (`config.json`).
    Codex,
    /// Generic OpenAI-compatible env file.
    GenericEnv,
}

/// Detects which agent config to inject into, based on the environment.
///
/// Returns the agent kind and the config file path. If `CODEX_HOME` is set or
/// `~/.codex/config.json` exists, returns `Codex`. Otherwise, falls back to
/// `GenericEnv` at `~/.oac/agent-env.sh`.
///
/// # Errors
///
/// Returns [`Error::Config`] if the home directory cannot be determined.
pub fn detect_agent() -> Result<(AgentKind, PathBuf)> {
    // Check for Codex.
    if let Ok(codez_home) = std::env::var("CODEX_HOME") {
        let path = PathBuf::from(codez_home).join("config.json");
        return Ok((AgentKind::Codex, path));
    }
    if let Some(home) = home_dir()? {
        let codex_path = home.join(".codex").join("config.json");
        if codex_path.exists() {
            return Ok((AgentKind::Codex, codex_path));
        }
    }

    // Fall back to generic env file.
    let home = home_dir()?.ok_or_else(|| Error::Config("HOME not set".into()))?;
    let path = home.join(".oac").join("agent-env.sh");
    Ok((AgentKind::GenericEnv, path))
}

/// Injects the agent config into the detected config file.
///
/// # Security
///
/// The config file is written with `0600` permissions (Unix) so other local
/// users cannot read the key.
///
/// # Errors
///
/// Returns [`Error::Config`] if the config file cannot be written.
pub fn inject(config: &AgentConfig) -> Result<InjectionResult> {
    let (agent, path) = detect_agent()?;
    match agent {
        AgentKind::Codex => inject_codex(&path, config)?,
        AgentKind::GenericEnv => inject_generic_env(&path, config)?,
    }
    Ok(InjectionResult { agent, path })
}

/// Reads the previously-injected agent config (base URL + API key) from the
/// detected config file.
///
/// This is used by the `print-key` subcommand to re-display the key the
/// employee configured during `login`. The key is read from the agent config
/// file (where `login` wrote it), not from the database (which only stores
/// the hash).
///
/// # Errors
///
/// Returns [`Error::Config`] if the config file does not exist or cannot be
/// parsed.
pub fn read() -> Result<AgentConfig> {
    let (agent, path) = detect_agent()?;
    match agent {
        AgentKind::Codex => read_codex(&path),
        AgentKind::GenericEnv => read_generic_env(&path),
    }
}

/// Reads the base URL and API key from a Codex `config.json` file.
fn read_codex(path: &Path) -> Result<AgentConfig> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| Error::Config(format!("read {}: {e}", path.display())))?;
    let json: serde_json::Value = serde_json::from_str(&contents)
        .map_err(|e| Error::Config(format!("parse {}: {e}", path.display())))?;
    let base_url = json
        .get("api_base_url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            Error::Config(format!(
                "{} does not contain api_base_url; run `oac-relay login` first",
                path.display()
            ))
        })?
        .to_string();
    let api_key = json
        .get("api_key")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            Error::Config(format!(
                "{} does not contain api_key; run `oac-relay login` first",
                path.display()
            ))
        })?
        .to_string();
    Ok(AgentConfig { base_url, api_key })
}

/// Reads the base URL and API key from a generic env file (`agent-env.sh`).
fn read_generic_env(path: &Path) -> Result<AgentConfig> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| Error::Config(format!("read {}: {e}", path.display())))?;
    let base_url = extract_env_var(&contents, "OPENAI_API_BASE").ok_or_else(|| {
        Error::Config(format!(
            "{} does not contain OPENAI_API_BASE; run `oac-relay login` first",
            path.display()
        ))
    })?;
    let api_key = extract_env_var(&contents, "OPENAI_API_KEY").ok_or_else(|| {
        Error::Config(format!(
            "{} does not contain OPENAI_API_KEY; run `oac-relay login` first",
            path.display()
        ))
    })?;
    Ok(AgentConfig { base_url, api_key })
}

/// Extracts a `export VAR='value'` (or `export VAR="value"`) assignment from
/// a shell env file.
fn extract_env_var(contents: &str, var_name: &str) -> Option<String> {
    let prefix = format!("export {var_name}=");
    for line in contents.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix(&prefix) {
            // Strip surrounding single or double quotes.
            let rest = rest.trim();
            if (rest.starts_with('\'') && rest.ends_with('\''))
                || (rest.starts_with('"') && rest.ends_with('"'))
            {
                return Some(rest[1..rest.len() - 1].to_string());
            }
            return Some(rest.to_string());
        }
    }
    None
}

/// Injects config into a Codex `config.json` file.
///
/// Reads the existing JSON (or creates a new object), updates `api_base_url`
/// and `api_key`, and writes it back with `0600` permissions.
fn inject_codex(path: &Path, config: &AgentConfig) -> Result<()> {
    let mut json = if path.exists() {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("read {}: {e}", path.display())))?;
        serde_json::from_str::<serde_json::Value>(&contents)
            .map_err(|e| Error::Config(format!("parse {}: {e}", path.display())))?
            .as_object()
            .cloned()
            .unwrap_or_else(serde_json::Map::new)
    } else {
        serde_json::Map::new()
    };

    json.insert(
        "api_base_url".to_string(),
        serde_json::Value::String(config.base_url.clone()),
    );
    json.insert(
        "api_key".to_string(),
        serde_json::Value::String(config.api_key.clone()),
    );

    let serialized = serde_json::to_string_pretty(&serde_json::Value::Object(json))
        .map_err(|e| Error::Config(format!("serialize config: {e}")))?;

    write_secure(path, serialized.as_bytes())?;
    Ok(())
}

/// Injects config into a generic env file (`agent-env.sh`).
///
/// Writes `export OPENAI_API_BASE=...` and `export OPENAI_API_KEY=...` with
/// `0600` permissions.
fn inject_generic_env(path: &Path, config: &AgentConfig) -> Result<()> {
    let content = format!(
        "# Generated by oac-relay. Source this file to configure your agent:\n\
         #   source {}\n\
         export OPENAI_API_BASE={}\n\
         export OPENAI_API_KEY={}\n",
        path.display(),
        shell_escape(&config.base_url),
        shell_escape(&config.api_key),
    );
    write_secure(path, content.as_bytes())?;
    Ok(())
}

/// Writes a file with `0600` permissions (Unix).
fn write_secure(path: &Path, content: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| Error::Config(format!("create dir {}: {e}", parent.display())))?;
    }
    std::fs::write(path, content)
        .map_err(|e| Error::Config(format!("write {}: {e}", path.display())))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| Error::Config(format!("chmod {}: {e}", path.display())))?;
    }

    Ok(())
}

/// Shell-escapes a string for safe inclusion in a `export VAR=value` line.
fn shell_escape(s: &str) -> String {
    // Single-quote escape: replace ' with '\'' and wrap in single quotes.
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Returns the user's home directory.
fn home_dir() -> Result<Option<PathBuf>> {
    #[cfg(windows)]
    {
        Ok(std::env::var_os("USERPROFILE")
            .or_else(|| {
                let drive = std::env::var_os("HOMEDRIVE")?;
                let path = std::env::var_os("HOMEPATH")?;
                Some(PathBuf::from(drive).join(path))
            })
            .map(PathBuf::from))
    }

    #[cfg(not(windows))]
    {
        Ok(std::env::var_os("HOME").map(PathBuf::from))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> AgentConfig {
        AgentConfig {
            base_url: "http://127.0.0.1:8787/v1".into(),
            api_key: "oac_test_key_12345".into(),
        }
    }

    #[test]
    fn shell_escape_handles_simple_strings() {
        assert_eq!(shell_escape("hello"), "'hello'");
        assert_eq!(
            shell_escape("http://127.0.0.1:8787/v1"),
            "'http://127.0.0.1:8787/v1'"
        );
    }

    #[test]
    fn shell_escape_escapes_single_quotes() {
        let result = shell_escape("it's");
        assert_eq!(result, "'it'\\''s'");
    }

    #[test]
    fn inject_generic_env_writes_correct_content() {
        let tmp = std::env::temp_dir().join(format!(
            "oac-agent-test-{}-{}.sh",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        ));
        let config = test_config();
        inject_generic_env(&tmp, &config).expect("inject");

        let content = std::fs::read_to_string(&tmp).expect("read");
        assert!(
            content.contains("OPENAI_API_BASE='http://127.0.0.1:8787/v1'"),
            "{content}"
        );
        assert!(
            content.contains("OPENAI_API_KEY='oac_test_key_12345'"),
            "{content}"
        );
        assert!(content.contains("source"), "{content}");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&tmp).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "file must be 0600, got {mode:o}");
        }

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn inject_codex_creates_new_config() {
        let tmp = std::env::temp_dir().join(format!(
            "oac-codex-test-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        ));
        let config = test_config();
        inject_codex(&tmp, &config).expect("inject");

        let content = std::fs::read_to_string(&tmp).expect("read");
        let json: serde_json::Value = serde_json::from_str(&content).expect("parse");
        assert_eq!(json["api_base_url"], "http://127.0.0.1:8787/v1");
        assert_eq!(json["api_key"], "oac_test_key_12345");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&tmp).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "file must be 0600, got {mode:o}");
        }

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn inject_codex_preserves_existing_fields() {
        let tmp = std::env::temp_dir().join(format!(
            "oac-codex-preserve-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        ));
        // Write an existing config with a custom field.
        std::fs::write(&tmp, r#"{"model": "gpt-4", "custom_setting": true}"#)
            .expect("write existing");

        let config = test_config();
        inject_codex(&tmp, &config).expect("inject");

        let content = std::fs::read_to_string(&tmp).expect("read");
        let json: serde_json::Value = serde_json::from_str(&content).expect("parse");
        assert_eq!(json["model"], "gpt-4");
        assert_eq!(json["custom_setting"], true);
        assert_eq!(json["api_base_url"], "http://127.0.0.1:8787/v1");
        assert_eq!(json["api_key"], "oac_test_key_12345");

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn inject_codex_overwrites_existing_api_key() {
        let tmp = std::env::temp_dir().join(format!(
            "oac-codex-overwrite-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        ));
        std::fs::write(
            &tmp,
            r#"{"api_key": "old_key", "api_base_url": "https://old.example.com"}"#,
        )
        .expect("write existing");

        let config = test_config();
        inject_codex(&tmp, &config).expect("inject");

        let content = std::fs::read_to_string(&tmp).expect("read");
        let json: serde_json::Value = serde_json::from_str(&content).expect("parse");
        assert_eq!(json["api_key"], "oac_test_key_12345");
        assert_eq!(json["api_base_url"], "http://127.0.0.1:8787/v1");

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn write_secure_creates_parent_dirs() {
        let tmp_dir = std::env::temp_dir().join(format!(
            "oac-nested-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        ));
        let nested = tmp_dir.join("sub").join("dir").join("file.txt");
        write_secure(&nested, b"test").expect("write");
        assert!(nested.exists(), "file must be created");
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn extract_env_var_finds_single_quoted_value() {
        let contents = "# comment\nexport OPENAI_API_BASE='http://127.0.0.1:8787/v1'\nexport OPENAI_API_KEY='oac_abc'\n";
        assert_eq!(
            extract_env_var(contents, "OPENAI_API_BASE"),
            Some("http://127.0.0.1:8787/v1".into())
        );
        assert_eq!(
            extract_env_var(contents, "OPENAI_API_KEY"),
            Some("oac_abc".into())
        );
    }

    #[test]
    fn extract_env_var_finds_double_quoted_value() {
        let contents = "export OPENAI_API_KEY=\"oac_xyz\"\n";
        assert_eq!(
            extract_env_var(contents, "OPENAI_API_KEY"),
            Some("oac_xyz".into())
        );
    }

    #[test]
    fn extract_env_var_returns_none_for_missing_var() {
        let contents = "export OTHER_VAR='value'\n";
        assert_eq!(extract_env_var(contents, "OPENAI_API_KEY"), None);
    }

    #[test]
    fn read_generic_env_round_trips_with_inject() {
        let tmp = std::env::temp_dir().join(format!(
            "oac-read-env-{}-{}.sh",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        ));
        let config = test_config();
        inject_generic_env(&tmp, &config).expect("inject");
        let read_back = read_generic_env(&tmp).expect("read");
        assert_eq!(read_back.base_url, config.base_url);
        assert_eq!(read_back.api_key, config.api_key);
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn read_codex_round_trips_with_inject() {
        let tmp = std::env::temp_dir().join(format!(
            "oac-read-codex-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        ));
        let config = test_config();
        inject_codex(&tmp, &config).expect("inject");
        let read_back = read_codex(&tmp).expect("read");
        assert_eq!(read_back.base_url, config.base_url);
        assert_eq!(read_back.api_key, config.api_key);
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn read_codex_missing_file_returns_error() {
        let err = read_codex(Path::new("/nonexistent/config.json")).unwrap_err();
        assert!(err.to_string().contains("read"), "{err}");
    }

    #[test]
    fn read_codex_missing_api_key_returns_error() {
        let tmp = std::env::temp_dir().join(format!(
            "oac-read-codex-missing-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        ));
        std::fs::write(&tmp, r#"{"api_base_url": "http://localhost"}"#).expect("write");
        let err = read_codex(&tmp).unwrap_err();
        assert!(err.to_string().contains("api_key"), "{err}");
        let _ = std::fs::remove_file(&tmp);
    }
}
