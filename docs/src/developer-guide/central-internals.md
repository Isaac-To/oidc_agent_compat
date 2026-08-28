# Central Internals

The `oac-central` crate (`crates/central`) is the central proxy. This page
documents the internal architecture. For full type signatures, run
`cargo doc -p oac-central --open`.

## CLI dispatch (`main.rs`)

Entry point: `oac-central [OPTIONS] [COMMAND]`.

- `serve` (default) — starts the proxy.
- `admin` — manages runtime providers, provider keys, policies, devices, and
   audit data through the relay.

See [CLI Reference](../user-guide/cli-reference.md) for the user-facing
command docs.

## Server (`proxy/mod.rs`)

### `AppState`

```rust
pub struct AppState {
    pub config: CentralConfig,
   pub provider_store: ProviderStore,
    pub client: reqwest::Client,
    pub audit: AuditLogger,
    pub rate_limiter: Option<RateLimiter>,
    pub policy_store: PolicyStore,
    pub device_store: DeviceStore,
    pub usage_tracker: UsageTracker,
    pub price_table: PriceTable,
    pub mcp_manager: McpManager,
}
```

### `serve()`

- Opens the database (runs migrations).
- Loads the provider encryption key and opens the `ProviderStore`; provider
   API keys are decrypted into `Zeroizing` memory only for upstream requests.
- Builds the `reqwest::Client` via `forward::build_client()`.
- Creates `PolicyStore`, `DeviceStore`, `UsageTracker`, `PriceTable`.
- If `[pricing]` is configured with a non-zero interval, refreshes model
   prices from each enabled provider (best-effort).
- Binds:
  - **Dev mode**: plain HTTP via `axum::serve` + `TcpListener`.
  - **Production**: mTLS via `axum_server::bind_rustls` with
    `mtls::build_server_config`, ALPN `http/1.1`, client cert required.
- Graceful shutdown via `shutdown::shutdown_signal()`.

### Router

Middleware order (outer → inner):

1. `RequestBodyLimitLayer(10 MB)`.
2. `auth::auth_middleware` — validates relay-forwarded identity headers.
3. `permissions::permissions_middleware` — group-based enforcement.
4. `rate_limit::rate_limit_middleware` — per-IP token bucket (prod only).
5. Handler (`forward::proxy_handler`).

The admin API router is merged only if `config.admin` is present.

Routes (same as relay):

| Method | Path | Auth |
|---|---|---|
| `GET` | `/healthz` | bypassed |
| `POST` | `/v1/chat/completions` | required |
| `POST` | `/v1/responses` | required |
| `GET` | `/v1/models` | required |
| `POST` | `/v1/embeddings` | required |

## Auth middleware (`proxy/auth.rs`)

`VerifiedRelayIdentity`:

```rust
pub struct VerifiedRelayIdentity {
    pub subject: String,
    pub email: Option<String>,
    pub identity_id: Option<String>,
    pub groups: Option<String>,      // JSON array string
    pub request_id: Option<String>,
}
```

`auth_middleware`:

- Skips `/healthz`.
- Extracts `x-oac-*` headers (from `identity` constants).
- Returns `401` if `x-oac-user-subject` is missing/empty (unless
  `dev_mode`, which logs a warning and allows through).
- Inserts `VerifiedRelayIdentity` into extensions.

## Permissions middleware (`proxy/permissions.rs`)

`PermissionDecision`:

```rust
pub struct PermissionDecision {
    pub decision: String,        // "allowed" or "denied"
    pub reason: Option<String>,  // set when denied
}
```

Enforcement order:

1. Skip `/healthz`.
2. Extract `VerifiedRelayIdentity`.
3. Parse groups from JSON array string.
4. `PolicyStore::resolve_policy(&groups)` — on error, **fails open**
   (logs loudly, allows through).
5. **Device revocation check** — uses `identity_id` or `subject` as
   device ID. If revoked → `403` (`"device_revoked"`).
6. **Endpoint check** — `policy.is_endpoint_allowed(&endpoint)`. Deny
   `403` (`"endpoint_not_allowed"`).
7. **Model check** (POST only) — reads body, extracts model, checks
   `policy.is_model_allowed`. Deny `403` (`"model_not_allowed"`).
8. **Request-count quota check** (pre-flight) — if
   `daily_request_quota` set and `usage.request_count >= quota` →
   `429` (`"quota_exceeded"`). Token quotas enforced post-hoc.
9. On allow: inserts `PermissionDecision` into extensions.

Denial response:

```json
{"error":{"message":"access denied: {reason}","type":"permission_denied"}}
```

Denials also write an `AuditEntry` with
`permission_decision = "denied"`.

## Forwarding (`proxy/forward.rs`)

`build_client()` — `rustls-tls`, 300s timeout, 10s connect timeout.

`proxy_handler`:

1. Extracts `VerifiedRelayIdentity` and `PermissionDecision`.
2. Calls `forward_request()`:
   - Reads body (max `MAX_BODY_SIZE`).
   - Extracts model.
   - Sanitizes path.
   - Builds upstream URL: `{provider.base_url}{sanitized_path}`.
   - Builds forward headers (strips hop-by-hop).
   - **Replaces** `Authorization` with the selected provider key.
   - Sends request.
3. If non-streaming: buffers response, extracts token usage from `usage`
   JSON field.
4. If SSE: passes through as raw byte stream, wraps with
   `wrap_stream_with_usage_extraction` to intercept `data:` lines and
   extract `usage` from the final chunk.
5. Computes cost via `PriceTable::compute_cost`; enabled providers are
   refreshed periodically when configured.
6. Records `AuditEntry` (best-effort) and increments daily usage. For SSE,
   audit and usage accounting are deferred until the stream completes.
7. Increments usage counters (best-effort, allowed requests only).
8. On error: `502 Bad Gateway`.

## Policy store (`policy.rs`)

`ResolvedPolicy`:

```rust
pub struct ResolvedPolicy {
    pub allowed_models: Option<HashSet<String>>,      // None = all
    pub allowed_endpoints: Option<HashSet<String>>,    // None = all
    pub daily_token_quota: Option<i64>,                 // None = unlimited
    pub daily_request_quota: Option<i64>,               // None = unlimited
}
```

`resolve_policy(&groups)` — **most-permissive-wins** merge:

- **Models**: union. If any group has `None`, result is `None`.
- **Endpoints**: union. If any group has `None`, result is `None`.
- **Quotas**: `max`. If any group has `None`, result is `None`.

If no policies exist for any group, returns `ResolvedPolicy::default()`
(all allowed).

CRUD: `list_policies()`, `get_policy()`, `upsert_policy()`,
`delete_policy()`.

## Device store (`device_store.rs`)

```rust
pub struct DeviceStore { db: DatabaseConnection }
```

- `list_devices()`, `get_device(fingerprint)`.
- `upsert_device(fingerprint, subject, email)` — inserts or updates
  `last_seen_at` + `user_email`.
- `set_revoked(fingerprint, bool)` — returns `true` if updated.
- `revoke(fingerprint)`, `reinstate(fingerprint)`.
- `is_revoked(fingerprint)` — `None` if not registered, `Some(true)` if
  revoked, `Some(false)` if active.

Enforcement: checked in `permissions_middleware` using `identity_id`
(or `subject` as fallback) as the device ID.

## Provider store (`provider.rs`)

`ProviderStore` manages providers and their API keys at runtime through the
admin API. Provider metadata and AES-256-GCM ciphertexts are stored in the
central database; plaintext keys are decrypted into `Zeroizing<String>` only
when selecting an upstream request key. The 32-byte encryption key is loaded
from `OAC_PROVIDER_ENCRYPTION_KEY` or `/run/secrets/provider-encryption-key`.

Each provider can have multiple priority-ordered keys with optional group
access rules. A failed upstream `401` or `429` causes the proxy to try the
next authorized key. Manual prices remain overrides while enabled providers'
`/v1/models` catalogs can be refreshed periodically.

## Audit logger (`audit.rs`)

`AuditEntry`:

```rust
pub struct AuditEntry {
    pub device_id: String,
    pub user_subject: String,
    pub model: Option<String>,
    pub backend: String,
    pub status: i32,
    pub latency_ms: i64,
    pub stream: bool,
    pub prompt_tokens: Option<i32>,
    pub completion_tokens: Option<i32>,
    pub total_tokens: Option<i32>,
    pub identity_id: Option<String>,
    pub email: Option<String>,
    pub groups: Option<String>,
    pub endpoint: Option<String>,
    pub request_id: Option<String>,
    pub permission_decision: Option<String>,
    pub denial_reason: Option<String>,
    pub cost_usd: Option<f64>,
}
```

`AuditLogger::record()` inserts into `audit_log` (append-only, enforced
by DB triggers). Uses parameterized SQL (SQL-injection-safe).

## Usage tracker (`usage.rs`)

`UsageSnapshot`:

```rust
pub struct UsageSnapshot {
    pub user_subject: String,
    pub period_date: String,    // YYYY-MM-DD (UTC)
    pub period_kind: String,    // "daily"
    pub request_count: i64,
    pub token_count: i64,
    pub cost_usd: f64,
}
```

`UsageTracker`:

- `increment(subject, group, request_delta, token_delta, cost_delta)` —
  SQLite UPSERT keyed on `(user_subject, period_date, period_kind)`.
- `get_usage(subject)` — today's usage.
- `get_all_usage()` — all users' usage for today.

## Pricing (`pricing.rs`)

`PriceTable` — thread-safe via `Arc<RwLock<HashMap<String, PricedModel>>>`.

- `from_config(config)` — config entries stored as `Override`.
- `compute_cost(model, prompt_tokens, completion_tokens)` —
  `(prompt/1000) * input_per_1k + (completion/1000) * output_per_1k`.
  Returns `0.0` for unknown models or missing tokens.
- `fetch_from_backend(client, base_url)` — fetches `GET {base_url}/v1/models`,
  parses OpenRouter format. **Overrides are never overwritten**.
- `spawn_refresh_task(client, base_url, interval)` — periodic background
  refresh.

Precedence: manual config (`Override`) > auto-fetched (`Fetched`).

## MCP servers (`mcp.rs`)

`McpManager` manages centrally-hosted MCP servers at runtime, mirroring the
`ProviderStore` pattern. A configured server has a `base_url` (the MCP
Streamable HTTP endpoint) and an optional per-server `auth_header` stored as
AES-256-GCM `ciphertext`/`nonce` encrypted at rest with the master key.

- `upsert_server` / `get_server` / `list_servers` / `delete_server`.
- `resolve_server(id)` — returns a `ResolvedMcpServer` with the decrypted
  auth header in `Zeroizing` memory (only for the forwarding path).
- `encryption_key_from_hex` — parses the 32-byte master key.

## MCP forwarding + permissions (`proxy/mcp_forward.rs`, `proxy/mcp_permissions.rs`)

MCP traffic uses the Streamable HTTP transport (JSON-RPC 2.0 over HTTP). The
relay tunnels raw bytes to central on `/mcp/{server}`.

- `mcp_permissions_middleware` (runs after auth) reads the JSON-RPC body,
  extracts the tool name via `oac-mcp::parse`, and resolves the caller's
  per-group, per-server, per-tool policy
  (`PolicyStore::resolve_mcp_tool_allowed`). Denials return `403` and are
  audit-logged with the tool, server, method, and a redacted argument preview.
- `mcp_forward::mcp_handler` resolves the upstream server, injects its auth
  header, strips hop-by-hop headers, forwards the bytes, and passes SSE
  responses through. Records an `AuditEntry` with `mcp_server`, `mcp_tool`,
  `mcp_method`, and `mcp_args_preview`.

MCP policy resolution (`policy.rs`) treats tools as **deny-by-default**:
`resolve_mcp_allowed_tools` returns `None` only for an explicit allow-all
(`allowed_tools = NULL`) policy; otherwise it returns the union of
`"server:tool"` entries across the user's groups, or an empty set (deny all)
when none exist.

## Rate limiting (`proxy/rate_limit.rs`)

`RateLimiter` — token bucket per IP.

- `DEFAULT_RATE_LIMIT = 60` requests per window.
- `DEFAULT_WINDOW = 60s`.
- `try_take(ip)` — returns `Err(retry_after_secs)` if exceeded.

`rate_limit_middleware` — skips `/healthz` and dev mode. On limit
exceeded: `429 Too Many Requests` with `Retry-After` header.

## Admin API (`admin.rs`)

See [Admin API](../user-guide/admin-api.md) for the user-facing endpoint
docs.

`AdminState`:

```rust
pub struct AdminState {
    pub policy_store: PolicyStore,
    pub device_store: DeviceStore,
    pub audit: AuditLogger,
    pub usage_tracker: UsageTracker,
    pub admin_group: String,
}
```

`admin_auth_middleware`:

- Requires `x-oac-user-subject` (non-empty) → else `401`.
- Parses `x-oac-user-groups` as JSON array → if `admin_group` not in
  groups → `403`.

All mutations write to `admin_audit_log` (append-only).

## Persistence

### Migrations

1. `m000001_initial_schema` — `devices`, `audit_log` + append-only
   triggers.
2. `m000002_audit_enrichment` — adds nullable columns to `audit_log`.
3. `m000003_group_policies` — `group_policies`, `admin_audit_log` +
   triggers.
4. `m000004_usage_counters` — `usage_counters` with unique index on
   `(user_subject, period_date, period_kind)`.
5. `m000005_providers` — `providers`, `provider_keys` (encrypted),
   `provider_key_access`.
6. `m000006_token_saver` — token-saver + budget columns on `group_policies`;
   saver accounting columns on `audit_log`.
7. `m000007_collapse_repeated_lines` — RTK collapse toggle.
8. `m000008_strip_ansi` — ANSI-strip toggle.
9. `m000009_mcp` — `mcp_servers` (encrypted auth), `mcp_server_policies`,
   and MCP audit columns.

See [Persistence](./persistence.md) for full schemas.
