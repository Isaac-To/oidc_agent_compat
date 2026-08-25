# Central Proxy Setup

The central proxy (`oac-central`) is a company-hosted server that holds the
master backend key in a secret store and forwards mTLS-authenticated relay
requests to the OpenAI-compatible backend.

> The master key lives only in the central proxy's `Zeroizing` memory,
> loaded from a secret store. It is never sent to a laptop, never logged,
> never in a config file.

## Configuration

The central proxy config uses flat top-level fields (no `[central]`
wrapper). A minimal production config:

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
```

Key points:

- `listen_addr` is `0.0.0.0:8443` (network-accessible) in production.
- `dev_mode = false` enforces mTLS and rejects requests without
  relay-forwarded identity headers.
- `[secret_store]` — only `kind = "file"` is implemented. The file must
  be `0600` and contain the master key.
- `[admin]` is optional. If present, the admin API is enabled and
  restricted to users in the `admin_group`.

See [Configuration Reference](./configuration.md) for all fields.

Set the OIDC client secret:

```sh
export OAC_OIDC_CLIENT_SECRET="your-oidc-client-secret"
```

## Lifecycle

### `oac-central set-backend-key` — store the master key

```sh
oac-central set-backend-key --config config.toml
```

Prompts for the master backend key (no echo) and stores it in the
configured secret store. Prints:

```
Enter master backend key:
oac-central: master key stored in secret store
```

For the `file` secret store, this writes the key to the path in
`[secret_store].path` with `0600` permissions.

### `oac-central serve` — start the central proxy

```sh
oac-central serve --config config.toml
```

- Opens the database (runs migrations).
- Loads the master key from the secret store into `Zeroizing` memory.
- Builds the `reqwest` client for talking to the backend.
- Initializes the policy store, device store, audit logger, usage
  tracker, and price table.
- If `[pricing]` is configured, auto-fetches model prices from the backend
  at startup (best-effort) and spawns a periodic refresh task.
- Binds the server:
  - **Dev mode** (`dev_mode = true`): plain HTTP via `axum::serve`.
  - **Production** (`dev_mode = false`): mTLS via
    `axum_server::bind_rustls` with client cert required, ALPN `http/1.1`.
- Serves with graceful shutdown (SIGINT/SIGTERM).

### `oac-central admin` — admin CLI

The admin CLI sends requests **through the relay** (which authenticates the
user via OIDC and forwards identity headers to central). The user must
belong to the configured `admin_group`.

```sh
# Set the relay URL and API key (from oac-relay login):
export OAC_ADMIN_URL="http://127.0.0.1:8787"
export OAC_API_KEY="oac_..."   # from oac-relay login

# List policies:
oac-central admin policy-list

# Set a policy:
oac-central admin policy-set engineering --models gpt-4o,gpt-4o-mini

# Query the audit log:
oac-central admin audit-query --limit 50
```

See [Admin API](./admin-api.md) for all admin commands and endpoints.

## mTLS certificates

In production, the central proxy requires mTLS. You need:

- A **CA certificate** (`ca.crt`) that signs both the server and client
  certs.
- A **server cert** (`server.crt` + `server.key`) for the central proxy.
- A **client cert** (`client.crt` + `client.key`) distributed to each
  relay.

Generate dev certs with:

```sh
./docker/generate-certs.sh
```

This creates `docker/certs/{ca,server,client}.{crt,key}`. For production,
use your company PKI or a properly signed CA.

Distribute `ca.crt`, `client.crt`, and `client.key` to each employee
laptop for the relay config.

## Docker deployment

The recommended production deployment is via Docker. See
[Docker: Production](./docker-prod.md) for the full setup.

## Next steps

- [Admin API](./admin-api.md) — managing policies, devices, audit.
- [Docker: Production](./docker-prod.md) — container deployment.
- [Configuration Reference](./configuration.md) — all TOML fields.
