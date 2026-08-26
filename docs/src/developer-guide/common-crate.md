# Common Crate

The `oidc-agent-common` crate (`crates/common`) provides shared primitives
used by both the relay and the central proxy. Each module is independently
testable and documented.

For full type signatures, run `cargo doc -p oidc-agent-common --open`.

## Module tour

### `config`

TOML config schemas + validation for both components.

- `RelayConfig` — relay config; `from_toml()` + `validate()`. Rejects
  non-loopback `listen_addr` unless `dev_mode`.
- `CentralConfig` — central config; `from_toml()` + `validate()`.
- Sub-configs: `OidcConfig`, `CentralConnectionConfig`, `MtlsServerConfig`,
  `AdminConfig`, `PricingConfig`, and `ModelPriceConfig`.
- `RelayConfig` includes the validated `session_ttl_hours` setting; the
  default is 24 hours and `null` explicitly disables expiry.
- `CentralConfig` includes validated per-IP rate-limit settings and optional
  pricing configuration.

### `error`

Unified error type. Single `Error` enum wraps every error kind. `Result<T>`
type alias. Constructor helpers: `config()`, `oidc()`, `crypto()`,
`auth()`, `forbidden()`, `internal()`, `database()`, `http()`.

`#[from]` impls for `sea_orm::DbErr`, `reqwest::Error`, `std::io::Error`,
`serde_json::Error`.

### `keys`

Local API key generation, hashing, constant-time verification.

- `LocalKey` — 256-bit key, base64url, `oac_` prefix, `Zeroizing` memory.
  `generate()`, `from_string()` (dev only).
- `KeyHash` — SHA-256 hash for DB storage. `from_plaintext()`,
  `matches()` (constant-time via `subtle::ConstantTimeEq`).
- `HmacKeyHash` — HMAC-SHA-256 keyed hash (pepper not in DB).
- `extract_bearer()` — extracts `Bearer <token>` from header value.

### `oidc`

OIDC relying-party helpers.

- `CustomAdditionalClaims` — `groups` + `roles` fields, implements
  `openidconnect::AdditionalClaims`.
- Type aliases: `CustomClient`, `CustomProviderMetadata`,
  `CustomIdTokenClaims`, `CustomUserInfoClaims`.
- `build_http_client()` — rustls TLS, `redirect::Policy::none()` (SSRF
  prevention), timeouts.
- `resolve_client_secret()` — reads secret from env var.
- `validate_loopback_redirect()` — requires `http://` + loopback IP.
- `is_allowed_signing_alg()` — accepts only RS256, ES256.
- `union_groups_roles()` — deduplicates and sorts groups + roles.
- Constants: `ALLOWED_SIGNING_ALGS = &["RS256", "ES256"]`,
  `CONNECT_TIMEOUT = 10s`, `REQUEST_TIMEOUT = 30s`.

### `mtls`

rustls mTLS client/server config builders. TLS 1.3 preferred, 1.2 minimum.

- `load_certs(path)` — loads PEM certs from file.
- `load_private_key(path)` — loads PEM private key.
- `enforce_secure_perms(path)` — verifies `0600` on Unix.
- `build_client_config(ca, cert, key)` — rustls `ClientConfig` for
  relay→central mTLS.
- `build_server_config(ca, cert, key)` — rustls `ServerConfig` for central
  proxy, requires client certs via `WebPkiClientVerifier`.

### `logging`

Structured JSON logging with secret redaction.

- `init()` — initializes global tracing subscriber (JSON + EnvFilter +
  redacting writer).
- `SENSITIVE_FIELDS` — list of field names redacted: `authorization`,
  `api_key`, `apikey`, `client_secret`, `refresh_token`, `id_token`,
  `access_token`, `token`, `secret`, `password`, `master_key`, `key`,
  `bearer`.
- `RedactingMakeWriter` / `RedactingWriter` — buffers output, redacts on
  flush.

### `shutdown`

- `shutdown_signal()` — resolves on SIGINT (Ctrl-C) or SIGTERM (Unix).

### `http_util`

Shared HTTP forwarding utilities.

- `HOP_BY_HOP_HEADERS` — RFC 7230 §6.1 list.
- `FORWARDABLE_HEADERS` — allowlist: `content-type`, `accept`,
  `accept-encoding`, `accept-language`, `user-agent`.
- `MAX_BODY_SIZE` — 10 MB.
- `is_sse_content_type()` — checks for `text/event-stream`.
- `extract_model()` — parses JSON body, returns `model` field.
- `sanitize_path()` — rejects `..`, `//`, `\`, absolute URLs.
- `build_forward_headers()` — allowlist model, strips hop-by-hop.
- `is_response_header_stripped()` — hop-by-hop + `content-length`.

### `identity`

`X-OAC-*` identity header constants:

- `HEADER_USER_SUBJECT` = `"x-oac-user-subject"`
- `HEADER_USER_EMAIL` = `"x-oac-user-email"`
- `HEADER_USER_GROUPS` = `"x-oac-user-groups"`
- `HEADER_IDENTITY_ID` = `"x-oac-identity-id"`
- `HEADER_REQUEST_ID` = `"x-oac-request-id"`

### `persistence`

Shared DB helpers.

- `setup_database::<M>(url)` — opens DB, runs migrations.
- `enforce_db_perms(path)` — tightens SQLite file to `0600` on Unix.
- `temp_sqlite_url()` — generates temp SQLite URL (behind `test-utils`
  feature).
- `sqlite_path()`, `normalize_sqlite_url()`.

### `time_util`

- `now_utc()` — current UTC `TimeDateTime`.
- `format_time(dt)` — formats as `YYYY-MM-DD HH:MM:SS`.

### `test_certs`

Test certificate generation via `rcgen`. Behind the `test-certs` feature
flag. Used by integration and E2E tests.

## Feature flags

| Feature | Default | Description |
|---|---|---|
| `test-certs` | no | Enables `test_certs` module (pulls in `rcgen`). For integration tests. |
| `test-utils` | no | Enables `persistence::temp_sqlite_url` helper for test builds. |
