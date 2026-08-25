# Relay Setup

The laptop relay (`oac-relay`) is a thin binary that each employee runs on
their machine. It authenticates the employee via OIDC, mints a local API
key, injects it into the agent's config, and forwards agent traffic over
mTLS to the central proxy.

> The relay holds **no master key**. It only holds a local API key (256-bit,
> SHA-256 hashed at rest) and an mTLS client certificate.

## Configuration

Create a config file for the relay. Start from the example:

```sh
cp config.example.toml config.toml
```

The relay reads the `[relay]` section. A minimal production config:

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

Key points:

- `listen_addr` **must** be loopback (`127.0.0.1`) in production. The
  config validator rejects `0.0.0.0` unless `dev_mode = true`.
- `client_secret_env` is the **name of an environment variable** holding
  the OIDC client secret — never the secret itself.
- `redirect_uri` uses port `0` (any port); the relay binds a random
  loopback port at login time per RFC 8252.
- `scopes` should include `groups` if you want group-based authorization
  enforced by the central proxy.
- `central.url` must be `https://` in production (mTLS enforced).

See [Configuration Reference](./configuration.md) for all fields.

Set the OIDC client secret environment variable:

```sh
export OAC_OIDC_CLIENT_SECRET="your-oidc-client-secret"
```

## Lifecycle

### `oac-relay login` — authenticate and configure the agent

```sh
oac-relay login --config config.toml
```

This runs the full OIDC authorization-code + PKCE flow:

1. Validates the loopback redirect URI (RFC 8252).
2. Performs OIDC discovery against the IdP.
3. Binds a random loopback port and opens the system browser to the IdP
   login page.
4. After the employee logs in, the IdP redirects back to the loopback
   callback with an authorization code.
5. The relay exchanges the code (with PKCE verifier) for tokens.
6. Validates the ID token: alg pinned to {RS256, ES256}, verifies iss,
   aud, exp, nonce, signature, and `at_hash`.
7. Fetches userinfo (or falls back to ID-token claims).
8. Upserts the user identity in the local SQLite DB.
9. Mints a 256-bit local API key (stores only the SHA-256 hash).
10. Injects the base URL + key into the agent config file.

The agent config is written to one of:

| Agent | File | Format |
|---|---|---|
| Codex | `~/.codex/config.json` (or `$CODEX_HOME/config.json`) | JSON: `{"api_base_url": "...", "api_key": "..."}` |
| Generic | `~/.oac/agent-env.sh` | Shell: `export OPENAI_API_BASE='...'` / `export OPENAI_API_KEY='...'` |

The file is created with `0600` permissions.

On success, the relay prints:

```
oac-relay: login successful for alice@example.com (agent config written to /home/alice/.oac/agent-env.sh)
```

### `oac-relay serve` — start the relay server

```sh
oac-relay serve --config config.toml
```

- Opens the SQLite DB (runs migrations, enforces `0600` perms).
- If `dev_mode = true`, auto-mints the well-known dev key
  `oac_test_key_alice` (idempotent — only mints if it doesn't exist).
- Binds `TcpListener` to `listen_addr`.
- Serves the HTTP router with graceful shutdown (SIGINT/SIGTERM).

### `oac-relay logout` — revoke all local keys

```sh
oac-relay logout --config config.toml
```

Revokes all API keys for all identities stored in the local DB. Prints
`oac-relay: revoked N key(s)`.

### `oac-relay print-key` — re-print the API key

```sh
oac-relay print-key
```

Reads the agent config file (not the DB) and prints the base URL and API
key. Useful if you need to copy the key into a tool that doesn't read the
auto-injected config.

### `oac-relay list-keys` — list all local keys

```sh
oac-relay list-keys --config config.toml
```

Lists all API keys in the local DB: id, label, created_at, last_used_at.

### `oac-relay revoke-key <KEY_ID>` — revoke a single key

```sh
oac-relay revoke-key <key-id> --config config.toml
```

Revokes a single key by its ID. Prints `revoked key <id>` or
`key <id> not found`.

## How the agent connects

After `login`, the agent is configured to point at:

- **Base URL:** `http://127.0.0.1:8787/v1`
- **API key:** the minted local key (e.g. `oac_abc123...`)

The agent sends standard OpenAI-compatible requests. The relay:

1. Validates the `Host` header (DNS rebinding defense — loopback only).
2. Extracts and verifies the `Authorization: Bearer <local-key>`.
3. Replaces the local key with identity headers (`x-oac-user-subject`,
   `x-oac-user-email`, `x-oac-user-groups`, `x-oac-identity-id`,
   `x-oac-request-id`) — set from the verified identity, never from
   incoming request headers.
4. Forwards over mTLS to the central proxy.
5. Streams the response back (including SSE).

## Dev mode

When `dev_mode = true`:

- The relay can bind `0.0.0.0` (needed for Docker).
- The central URL can be `http://` (no mTLS).
- The relay auto-mints the dev key `oac_test_key_alice` on startup.

Dev mode is for testing only. **Never use it in production.**

## Next steps

- [Central Proxy Setup](./central-setup.md)
- [CLI Reference](./cli-reference.md) — all relay commands and flags.
- [Configuration Reference](./configuration.md) — all TOML fields.
