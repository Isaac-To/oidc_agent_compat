# OIDC Agent Compatibility Server

An enterprise-grade OIDC-to-AI-agent forwarder that lets employees use any
OpenAI-compatible AI agent (Codex, etc.) through company-approved backends —
**without the master backend key ever touching an employee's laptop**.

## Architecture

The system has two components:

1. **Central proxy** (company-hosted, cloud/VPC) — holds the master backend
   key in a managed secret store (Vault / AWS Secrets Manager / etc.),
   authenticates employees via OIDC, and forwards approved requests to the AI
   backend with SSE streaming.
2. **Laptop relay** (thin, per-employee) — listens on `127.0.0.1`, authenticates
   the employee via OIDC, and relays agent traffic to the central proxy over
   mTLS. Holds **no master key** — only a short-lived user token + an mTLS
   client cert.

```
Agent → [127.0.0.1 relay] → mTLS → [central proxy] → [OpenAI-compatible backend]
                                   ↑ master key (secret manager)
```

## Status

🚧 **Under development.** See `docs/threat-model.md` and the session plan for
the full design.

## Security

- `#![forbid(unsafe_code)]` across all crates.
- Master key never on any laptop — only in the central secret manager.
- mTLS (TLS 1.3) between relay and central proxy.
- OIDC auth-code + PKCE (S256) against the enterprise IdP.
- 256-bit local API keys, SHA-256 hashed at rest, constant-time comparison.
- Host-header validation (DNS rebinding defense).
- Hop-by-hop header stripping (RFC 7230 §6.1).
- Secret-redaction logging layer.
- `cargo audit` + `cargo deny` in CI.

## Quickstart

### Prerequisites

- Rust 1.85+ (stable)
- An OIDC IdP (Okta, Entra ID, Keycloak, Auth0, etc.)
- An OpenAI-compatible backend (OpenAI, Azure OpenAI, OpenRouter, Ollama, vLLM, etc.)

### Build

```sh
cargo build --release
```

### Configure

Copy the example config and edit for your environment:

```sh
cp config.example.toml config.toml
```

Set the OIDC client secret via an environment variable (never in the config
file):

```sh
export OAC_OIDC_CLIENT_SECRET="your-oidc-client-secret"
```

### Run the central proxy (company-hosted)

```sh
# Load the master backend key into the secret manager (admin only):
oac-central set-backend-key

# Start the central proxy:
oac-central serve --config config.toml
```

### Run the laptop relay (per-employee)

```sh
# Authenticate via OIDC (opens a browser) and auto-configure the agent:
oac-relay login --config config.toml

# Start the relay server:
oac-relay serve --config config.toml
```

After `login`, the relay writes the base URL + local API key directly into
the agent's config file (Codex `config.json` or `~/.oac/agent-env.sh`). The
employee never sees or copies a key.

### Point your agent at the relay

The agent should use:

- **Base URL:** `http://127.0.0.1:8787/v1`
- **API key:** (auto-injected by `oac-relay login`)

## Permissions & Admin API

The central proxy enforces group-based authorization policies. Users are
assigned to groups via the IdP (e.g. Keycloak groups/roles), and admins
configure what each group can access via the admin API.

### Prerequisites

1. Add the `groups` scope to the relay's OIDC config so group memberships
   are extracted at login:
   ```toml
   [relay.oidc]
   scopes = ["openid", "email", "profile", "groups"]
   ```

2. Enable the admin API in the central config with the group that grants
   admin access:
   ```toml
   [central.admin]
   admin_group = "oac-admins"
   ```

### Managing policies

Admins authenticate via the IdP through the relay (same OIDC login flow as
regular users). Use the admin CLI with a local API key obtained via
`oac-relay login`:

```sh
# Set a policy allowing the "engineering" group to use only gpt-4o:
oac-central admin policy-set engineering \
  --models gpt-4o,gpt-4o-mini \
  --key $OAC_API_KEY

# Restrict the "limited" group to chat completions only:
oac-central admin policy-set limited \
  --endpoints /v1/chat/completions \
  --key $OAC_API_KEY

# Set a daily request quota:
oac-central admin policy-set engineering \
  --request-quota 1000 \
  --key $OAC_API_KEY

# List all policies:
oac-central admin policy-list --key $OAC_API_KEY

# Delete a policy:
oac-central admin policy-delete engineering --key $OAC_API_KEY
```

### Managing devices

```sh
# List registered devices:
oac-central admin device-list --key $OAC_API_KEY

# Revoke a device:
oac-central admin device-revoke <fingerprint> --key $OAC_API_KEY

# Reinstate a revoked device:
oac-central admin device-reinstate <fingerprint> --key $OAC_API_KEY
```

### Querying the audit log

```sh
# Query recent activity:
oac-central admin audit-query --limit 50 --key $OAC_API_KEY

# Filter by user:
oac-central admin audit-query --subject alice@example.com --key $OAC_API_KEY
```

## Development

```sh
# Run all tests
cargo test

# Lint
cargo clippy --all-targets -- -D warnings

# Check formatting
cargo fmt --all --check

# Build release binaries
cargo build --release
```

