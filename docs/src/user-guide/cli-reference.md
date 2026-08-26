# CLI Reference

## `oac-relay`

The laptop relay binary.

### Usage

```
oac-relay [OPTIONS] [COMMAND]
```

If no subcommand is given, `serve` is assumed.

### Global options

| Flag | Short | Long | Env var | Default | Description |
|---|---|---|---|---|---|
| config | `-c` | `--config` | `OAC_RELAY_CONFIG` | `config.toml` | Path to the TOML config file |

### Subcommands

#### `serve` (default)

Start the relay HTTP server.

```sh
oac-relay serve --config config.toml
# or simply:
oac-relay --config config.toml
```

- Opens the SQLite DB (runs migrations, enforces `0600` perms).
- If `dev_mode = true`, auto-mints the dev key `oac_test_key_alice`.
- Binds to `listen_addr` and serves with graceful shutdown.

#### `login`

Run the OIDC auth-code + PKCE flow, mint a local key, and inject it into
the agent config.

```sh
oac-relay login --config config.toml
```

Opens a browser to the IdP login page. After successful authentication,
mints a 256-bit local API key and writes the agent config file
(`~/.codex/config.json` or `~/.oac/agent-env.sh`) with `0600` perms.

#### `logout`

Revoke all local keys for all identities.

```sh
oac-relay logout --config config.toml
```

Prints `oac-relay: revoked N key(s)`.

#### `print-key`

Re-print the API key from the agent config file (not the DB).

```sh
oac-relay print-key
```

#### `list-keys`

List all local API keys.

```sh
oac-relay list-keys --config config.toml
```

Output columns: `id`, `label`, `created_at`, `last_used_at` (or `"never"`).

OIDC-login keys expire after `session_ttl_hours` (24 hours by default). An
expired key is rejected with a `session_expired` response; run `login` again.

#### `revoke-key`

Revoke a single key by ID.

```sh
oac-relay revoke-key <KEY_ID> --config config.toml
```

#### `activity`

Show recent relay request activity from the append-only local activity log.

```sh
oac-relay activity --limit 20 --config config.toml
```

Entries are displayed newest first. `--limit` defaults to `20` and is capped
at `1000`. The output contains request metadata only; API keys and provider
key material are never printed.

---

## `oac-central`

The central proxy binary.

### Usage

```
oac-central [OPTIONS] [COMMAND]
```

If no subcommand is given, `serve` is assumed.

### Global options

| Flag | Short | Long | Env var | Default | Description |
|---|---|---|---|---|---|
| config | `-c` | `--config` | `OAC_CENTRAL_CONFIG` | `config.toml` | Path to the TOML config file |

### Subcommands

#### `serve` (default)

Start the central proxy server.

```sh
oac-central serve --config config.toml
# or simply:
oac-central --config config.toml
```

- Opens the database (runs migrations).
- Loads the provider encryption key and opens the runtime provider store.
- Binds the server (dev: plain HTTP; prod: mTLS with client cert required).
- Serves with graceful shutdown.

#### Provider administration

Provider administration commands operate through the relay and require the
admin IdP group. Provider API keys are never command-line arguments.

```sh
oac-central admin provider-list
oac-central admin provider-set openai --name OpenAI --base-url https://api.openai.com --models gpt-4o,gpt-4o-mini --default
oac-central admin provider-default openai
oac-central admin provider-delete openai
oac-central admin provider-key-list openai
oac-central admin provider-key-add openai --label production --priority 0 --groups engineering
oac-central admin provider-key-delete openai KEY_ID
```

`provider-key-add` prompts for the key with input hidden. Key listing returns
metadata only; use a new key for rotation rather than attempting to update
key material.

#### `admin`

Admin API operations. Sends requests **through the relay** (which
authenticates the user via OIDC). The user must belong to the configured
`admin_group`.

```
oac-central admin --key <KEY> [--url <URL>] <SUBCOMMAND>
```

| Flag | Long | Env var | Default | Description |
|---|---|---|---|---|
| url | `--url` | `OAC_ADMIN_URL` | `http://127.0.0.1:8787` | Relay URL |
| key | `--key` | `OAC_API_KEY` | (required) | Local API key from `oac-relay login` |

##### Admin subcommands

| Subcommand | Args / Flags | Description |
|---|---|---|
| `policy-list` | — | List all group policies |
| `policy-get <name>` | `name` (positional) | Get a single policy |
| `policy-set <name>` | `name` (positional), `--models <CSV>`, `--endpoints <CSV>`, `--token-quota <I64>`, `--request-quota <I64>` | Create or update a policy |
| `policy-delete <name>` | `name` (positional) | Delete a policy |
| `device-list` | — | List all registered devices |
| `device-revoke <fingerprint>` | `fingerprint` (positional) | Revoke a device |
| `device-reinstate <fingerprint>` | `fingerprint` (positional) | Reinstate a revoked device |
| `audit-query` | `--subject <STRING>`, `--limit <U32>` (default 100), `--offset <U32>` (default 0) | Query the newest-first audit log page |
| `usage-query` | `--subject <STRING>` (optional) | Query usage counters |
| `quota-get <subject>` | `subject` (positional) | Get quota status for a user |

##### `policy-set` examples

```sh
# Allow the "engineering" group to use only gpt-4o and gpt-4o-mini:
oac-central admin policy-set engineering \
  --models gpt-4o,gpt-4o-mini \
  --key $OAC_API_KEY

# Restrict the "limited" group to chat completions only:
oac-central admin policy-set limited \
  --endpoints /v1/chat/completions \
  --key $OAC_API_KEY

# Set a daily request quota of 1000:
oac-central admin policy-set engineering \
  --request-quota 1000 \
  --key $OAC_API_KEY
```

See [Admin API](./admin-api.md) for the HTTP endpoint equivalents and
response shapes.
