# Configuration Reference

The configuration file is TOML. The relay reads the `[relay]` section (or
top-level fields when using a relay-only config), and the central proxy
reads the `[central]` section (or top-level fields when using a
central-only config). The example file `config.example.toml` shows both
side by side.

All configs are parsed and validated by
`oidc_agent_common::config::{RelayConfig, CentralConfig}::from_toml()`.

## Relay configuration

### Top-level fields

| Field | Type | Required | Default | Validation |
|---|---|---|---|---|
| `listen_addr` | `SocketAddr` | yes | — | Must be loopback (`127.0.0.0/8` or `::1`) unless `dev_mode = true` |
| `database_url` | `String` | yes | — | SQLite URL, e.g. `sqlite:///data/relay.db` |
| `oidc` | table | yes | — | See [OIDC](#oidc) below |
| `central` | table | yes | — | See [Central connection](#central-connection) below |
| `dev_mode` | `bool` | no | `false` | When `true`: allows non-loopback bind, HTTP central URL, auto-mints dev key |

### OIDC

| Field | Type | Required | Validation |
|---|---|---|---|
| `issuer` | `String` | yes | Non-empty; must start with `http://` or `https://` |
| `client_id` | `String` | yes | Non-empty |
| `client_secret_env` | `String` | yes | Non-empty — **name** of env var holding the secret (never the secret itself) |
| `redirect_uri` | `String` | yes | Must start with `http://127.0.0.1` (loopback) |
| `scopes` | `Vec<String>` | yes | e.g. `["openid", "email", "profile", "groups"]` |

> Include `"groups"` in scopes if you want group-based authorization
> enforced by the central proxy.

### Central connection

| Field | Type | Required | Validation |
|---|---|---|---|
| `url` | `String` | yes | Non-empty; must be `https://` unless `dev_mode = true` |
| `ca_cert_path` | `PathBuf` | yes | Company CA cert (PEM) |
| `client_cert_path` | `PathBuf` | yes | Relay mTLS client cert (PEM) |
| `client_key_path` | `PathBuf` | yes | Relay mTLS client key (PEM, must be `0600`) |

### Example (production)

```toml
listen_addr = "127.0.0.1:8787"
database_url = "sqlite:///data/relay.db"
dev_mode = false

[oidc]
issuer = "https://idp.example.com"
client_id = "oac-relay"
client_secret_env = "OAC_OIDC_CLIENT_SECRET"
redirect_uri = "http://127.0.0.1:0/callback"
scopes = ["openid", "email", "profile", "groups"]

[central]
url = "https://central.example.com:8443"
ca_cert_path = "/etc/oac/ca.crt"
client_cert_path = "/etc/oac/client.crt"
client_key_path = "/etc/oac/client.key"
```

---

## Central proxy configuration

### Top-level fields

| Field | Type | Required | Default | Validation |
|---|---|---|---|---|
| `listen_addr` | `SocketAddr` | yes | — | e.g. `0.0.0.0:8443` |
| `database_url` | `String` | yes | — | SQLite or Postgres URL |
| `oidc` | table | yes | — | See [OIDC](#oidc-1) below |
| `backend` | table | yes | — | See [Backend](#backend) below |
| `mtls` | table | yes | — | See [mTLS server](#mtls-server) below |
| `secret_store` | table | yes | — | See [Secret store](#secret-store) below |
| `admin` | table | no | `None` (admin API disabled) | See [Admin](#admin) below |
| `pricing` | table | no | `None` (no cost tracking) | See [Pricing](#pricing) below |
| `dev_mode` | `bool` | no | `false` | When `true`: plain HTTP, permissive auth |

### OIDC

Same shape as the relay's OIDC config:

| Field | Type | Required | Validation |
|---|---|---|---|
| `issuer` | `String` | yes | Non-empty; valid URL |
| `client_id` | `String` | yes | Non-empty |
| `client_secret_env` | `String` | yes | Non-empty (env var name) |
| `redirect_uri` | `String` | yes | Must start with `http://127.0.0.1` |
| `scopes` | `Vec<String>` | yes | e.g. `["openid"]` |

### Backend

| Field | Type | Required | Validation |
|---|---|---|---|
| `name` | `String` | yes | Non-empty (human-readable, e.g. `"openai"`) |
| `base_url` | `String` | yes | Non-empty (e.g. `https://api.openai.com`) |

### mTLS server

| Field | Type | Description |
|---|---|---|
| `ca_cert_path` | `PathBuf` | Company CA cert (PEM) — validates relay client certs |
| `server_cert_path` | `PathBuf` | Server cert (PEM) |
| `server_key_path` | `PathBuf` | Server private key (PEM, must be `0600`) |

### Secret store

| Field | Type | Values |
|---|---|---|
| `kind` | `String` (serde `"kind"`) | `"file"` \| `"vault"` \| `"aws"` \| `"gcp"` \| `"azure"` |
| `path` | `String` | File path, Vault path, AWS ARN, etc. |

> Only `kind = "file"` is implemented. `vault` / `aws` / `gcp` / `azure`
> return an error ("not yet implemented").

For `kind = "file"`, the file must:
- Exist and be readable.
- Have exactly `0600` permissions on Unix (enforced at load time).
- Contain the master key (whitespace trimmed).

### Admin

| Field | Type | Required | Validation |
|---|---|---|---|
| `admin_group` | `String` | yes | Non-empty — the IdP group that grants admin access |

If this section is absent, the admin API (`/admin/v1/`) is not mounted.

### Pricing

| Field | Type | Default | Description |
|---|---|---|---|
| `models` | `Vec<ModelPrice>` | `[]` | Manual price overrides |
| `fetch_interval_secs` | `u64` | `3600` (1 hour) | Auto-fetch interval; `0` disables |

#### `[[pricing.models]]`

| Field | Type | Description |
|---|---|---|
| `model` | `String` | Model name (must match request `model` field) |
| `input_per_1k_usd` | `f64` | Price per 1K prompt tokens (USD) |
| `output_per_1k_usd` | `f64` | Price per 1K completion tokens (USD) |

Manual config overrides take precedence over auto-fetched prices.

### Example (production)

```toml
listen_addr = "0.0.0.0:8443"
database_url = "sqlite:///data/central.db"
dev_mode = false

[oidc]
issuer = "https://idp.example.com"
client_id = "oac-central"
client_secret_env = "OAC_OIDC_CLIENT_SECRET"
redirect_uri = "http://127.0.0.1:0/callback"
scopes = ["openid"]

[backend]
name = "openai"
base_url = "https://api.openai.com"

[mtls]
ca_cert_path = "/etc/oac/ca.crt"
server_cert_path = "/etc/oac/server.crt"
server_key_path = "/etc/oac/server.key"

[secret_store]
kind = "file"
path = "/run/secrets/master-key"

[admin]
admin_group = "oac-admins"

[pricing]
fetch_interval_secs = 3600

[[pricing.models]]
model = "gpt-4o"
input_per_1k_usd = 0.0025
output_per_1k_usd = 0.01
```

---

## Environment variables

| Variable | Used by | Description |
|---|---|---|
| `OAC_OIDC_CLIENT_SECRET` | Both | OIDC client secret (referenced by `client_secret_env` in config) |
| `OAC_RELAY_CONFIG` | Relay | Path to config file (alternative to `--config`) |
| `OAC_CENTRAL_CONFIG` | Central | Path to config file (alternative to `--config`) |
| `OAC_API_KEY` | Central admin CLI | Local API key from `oac-relay login` |
| `OAC_ADMIN_URL` | Central admin CLI | Relay URL (default `http://127.0.0.1:8787`) |
| `RUST_LOG` | Both | Log level (default `info`) |
