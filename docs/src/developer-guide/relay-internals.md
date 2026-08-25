# Relay Internals

The `oac-relay` crate (`crates/relay`) is the laptop relay. This page
documents the internal architecture. For full type signatures, run
`cargo doc -p oac-relay --open`.

## CLI dispatch (`main.rs`)

Entry point: `oac-relay [OPTIONS] [COMMAND]`. Built with `clap` derive.

- If no subcommand is given, `serve` is assumed.
- `serve` calls `db::setup()`, creates a `KeyStore`, and if `dev_mode`
  is true, calls `seed_dev_key()` (idempotently mints
  `oac_test_key_alice`).
- `login` calls `login::run_login()`.
- `logout`, `print-key`, `list-keys`, `revoke-key` are straightforward
  DB/key operations.

See [CLI Reference](../user-guide/cli-reference.md) for the user-facing
command docs.

## OIDC login flow (`login.rs`)

The `run_login()` function implements the full auth-code + PKCE flow.
See [OIDC Security](./oidc-security.md) for the RFC citations.

### Steps

1. `oidc::validate_loopback_redirect(&config.oidc.redirect_uri)` — RFC 8252.
2. `oidc::resolve_client_secret(&config.oidc)` — reads env var.
3. `oidc::build_http_client()` — rustls, no redirects (SSRF), timeouts.
4. OIDC discovery via `CustomProviderMetadata::discover_async`.
5. Binds one-shot loopback listener `127.0.0.1:0` (random port, RFC 8252
   §7.3); substitutes actual port into redirect URI.
6. Builds `CustomClient` from provider metadata + `ClientId` +
   `ClientSecret`.
7. Generates PKCE S256 (`PkceCodeChallenge::new_random_sha256`),
   `state` (`CsrfToken::new_random`), `nonce` (`Nonce::new_random`).
8. Builds authorize URL with scopes (`openid` always first).
9. Prints URL + calls `open_browser(url)` (macOS `open`, Linux
   `xdg-open`, Windows `cmd /C start`).
10. `wait_for_callback(listener, CALLBACK_TIMEOUT)` —
    `CALLBACK_TIMEOUT = 300s` (5 min).
11. Verifies `state` (CSRF defense).
12. Exchanges code with PKCE verifier.
13. ID-token validation:
    - 13a. **Alg pin**: `is_allowed_alg` accepts only RS256 + ES256.
      Checked **before** signature verification.
    - 13b. `id_token.claims(&client.id_token_verifier(), &nonce)` —
      verifies iss, aud, exp, nonce, signature via JWKS.
    - 13c. `at_hash` validation (OIDC Core §3.1.3.7 step 3) if present.
14. Fetches userinfo; falls back to `claims_from_id_token` on failure.
    Extracts subject, email, display_name, groups.
15. Calls `complete_login()`.

### `complete_login()`

1. `key_store.upsert_identity(issuer, subject, email, display_name, groups)`.
2. `key_store.mint_key(&identity.id, "default")`.
3. Builds `AgentConfig { base_url, api_key }`.
4. `agent_config::inject(&agent_config)` — writes with `0600` perms.

### `wait_for_callback()`

- `tokio::time::timeout(timeout, listener.accept())`.
- Reads request with `read_to_end` (10s sub-timeout).
- Parses first request line: `GET /callback?code=...&state=... HTTP/1.1`.
- If `error` param present → `Error::oidc`.
- Writes minimal HTML response (`<h1>Login complete</h1>`).

## Proxy pipeline (`proxy/`)

### Router (`proxy/mod.rs`)

Middleware order (outer → inner):

1. `RequestBodyLimitLayer(10 MB)` — `MAX_BODY_SIZE`.
2. `host_guard_middleware` — DNS rebinding defense.
3. `auth_middleware` — local key verification.
4. Handler (`forward::proxy_handler`).

Routes:

| Method | Path | Auth |
|---|---|---|
| `GET` | `/healthz` | bypassed |
| `POST` | `/v1/chat/completions` | required |
| `POST` | `/v1/responses` | required |
| `GET` | `/v1/models` | required |
| `POST` | `/v1/embeddings` | required |

### `AppState`

```rust
pub struct AppState {
    pub key_store: KeyStore,
    pub config: RelayConfig,
    pub client: reqwest::Client,        // mTLS client to central
    pub listen_addr: SocketAddr,
    pub activity: ActivityLogger,
}
```

### Host guard (`proxy/host_guard.rs`)

`host_guard_middleware` runs **before** auth. Reads `Host` header,
compares case-insensitively against `allowed_hosts()`:

- Always: `127.0.0.1:{port}`, `localhost:{port}`, `[::1]:{port}`.
- If `dev_mode`: also `relay:{port}` (Docker service name).

Mismatch → `400 Bad Request`. Reference: Jackson et al., Stanford 2007.

### Auth middleware (`proxy/auth.rs`)

`auth_middleware`:

- Skips `/healthz`.
- Extracts `Authorization: Bearer <key>` via `keys::extract_bearer`.
- Missing/invalid → `401 Unauthorized`.
- DB error → `500 Internal Server Error`.
- On success, inserts `VerifiedIdentity` into request extensions.

`VerifiedIdentity`:

```rust
pub struct VerifiedIdentity {
    pub identity_id: String,
    pub subject: String,
    pub email: Option<String>,
    pub groups: Option<String>,   // JSON array string
    pub key_id: String,
}
```

### Forwarding (`proxy/forward.rs`)

`build_client(config)`:

- `use_rustls_tls()`, `redirect(Policy::none())` (SSRF), `timeout(300s)`,
  `connect_timeout(10s)`.
- Production: rustls `ClientConfig` via
  `mtls::build_client_config(ca, cert, key)`, `https_only(true)`.
- Dev: plain HTTP, no mTLS.

`proxy_handler`:

1. Generates `request_id = Uuid::new_v4()`.
2. Extracts `VerifiedIdentity` from extensions.
3. Calls `forward_request()`.
4. Records a `RelayActivityEntry` (best-effort).
5. On error: `502 Bad Gateway`.

`forward_request`:

- Reads body (`to_bytes`, max `MAX_BODY_SIZE`).
- Extracts `model` via `http_util::extract_model`.
- Sanitizes path via `http_util::sanitize_path`.
- Builds upstream URL: `{config.central.url}{sanitized_path}`.
- Builds forward headers via `http_util::build_forward_headers`.
- **Replaces** `Authorization` with identity headers (set only from
  `VerifiedIdentity`, never from incoming request headers):
  - `x-oac-user-subject`, `x-oac-user-email`, `x-oac-user-groups`,
    `x-oac-identity-id`, `x-oac-request-id`.
- Sends request; on response:
  - Strips hop-by-hop + `content-length` headers.
  - If SSE: streams via `bytes_stream()` → `Body::from_stream`.
  - Otherwise: buffers and returns.

## KeyStore (`keystore.rs`)

```rust
pub struct KeyStore { pub db: DatabaseConnection }
```

Methods:

- `new(db)` — creates a store.
- `upsert_identity(issuer, subject, email, display_name, groups)` —
  finds by (issuer, subject); inserts with UUID id if absent.
- `mint_key(identity_id, label)` — `LocalKey::generate()` (256-bit
  OsRng); stores only SHA-256 hash.
- `mint_dev_key(identity_id, label, plaintext)` — caller-supplied
  plaintext (dev only).
- `verify_key(bearer_token)` — loads all keys, compares each via
  `KeyHash::matches` (constant-time, **no early return** — prevents
  timing leaks, CWE-208). Updates `last_used_at` on match.
- `revoke_all_keys(identity_id)` — `delete_many`.
- `revoke_key(key_id)` — `delete_by_id`.

## Activity logger (`activity.rs`)

```rust
pub struct RelayActivityEntry {
    pub identity_id: String,
    pub key_id: String,
    pub method: String,
    pub endpoint: String,
    pub model: Option<String>,
    pub central_status: Option<i32>,
    pub latency_ms: i64,
    pub request_id: Option<String>,
}
```

`ActivityLogger::record()` inserts into `relay_activity_log` (append-only,
enforced by DB triggers). The `proxy_handler` constructs an entry after
each forwarded request.

## Agent config injection (`agent_config.rs`)

```rust
pub struct AgentConfig {
    pub base_url: String,   // e.g. "http://127.0.0.1:8787/v1"
    pub api_key: String,    // plaintext, written once then dropped
}

pub enum AgentKind { Codex, GenericEnv }
```

- `detect_agent()` — if `CODEX_HOME` env set → Codex at
  `$CODEX_HOME/config.json`. Else if `~/.codex/config.json` exists →
  Codex. Else → GenericEnv at `~/.oac/agent-env.sh`.
- `inject(config)` — detects agent, delegates to `inject_codex` /
  `inject_generic_env`. Writes with `0600` perms.
- `read()` — reads back the injected config.

### Codex format (`~/.codex/config.json`)

JSON object; sets `api_base_url` and `api_key`, preserves all other
existing fields.

### Generic env format (`~/.oac/agent-env.sh`)

```sh
export OPENAI_API_BASE='<base_url>'
export OPENAI_API_KEY='<api_key>'
```

Single-quote escaped via `shell_escape` (replaces `'` with `'\''`).

## Persistence

### `db.rs`

`setup(database_url)` — delegates to
`persistence::setup_database::<Migrator>`. On Unix, tightens the SQLite
file to `0600`.

### `migration.rs`

Two migrations:

- `m000001_initial_schema` — creates `identities` and `api_keys` tables
  (FK `ON DELETE CASCADE`).
- `m000002_relay_activity_log` — creates `relay_activity_log` + two
  append-only triggers.

### Entities

- `identity::Model` — `id`, `issuer`, `subject`, `email`, `display_name`,
  `groups`, `created_at`.
- `api_key::Model` — `id`, `identity_id`, `key_hash` (Binary(32)), `label`,
  `created_at`, `last_used_at`.
- `relay_activity_log::Model` — `id`, `identity_id`, `key_id`, `method`,
  `endpoint`, `model`, `central_status`, `latency_ms`, `request_id`,
  `created_at`.

See [Persistence](./persistence.md) for full schemas.
