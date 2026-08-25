# Overview

The OIDC Agent Compatibility Server is an enterprise-grade forwarder that
lets employees use any OpenAI-compatible AI agent (Codex, Goose, etc.)
through company-approved backends — **without the master backend key ever
touching an employee's laptop**.

## Why this exists

AI coding agents (Codex, Goose, Cursor, etc.) need an API key to talk to a
backend. In an enterprise, handing every employee the master backend key is
a non-starter: keys leak, get committed to git, and can't be easily
revoked per-person. This project solves that by inserting two components
between the agent and the backend:

1. A **laptop relay** that authenticates the employee via OIDC and holds
   only a short-lived local key.
2. A **central proxy** that holds the master key in a managed secret store
   and enforces group-based authorization policies.

The master key never leaves the central proxy's process memory.

## Architecture

```
Agent → [127.0.0.1 relay] → mTLS → [central proxy] → [OpenAI-compatible backend]
                                   ↑ master key (secret manager)
```

| Component | Where it runs | What it does |
|---|---|---|
| **Agent** (Codex, Goose, etc.) | Employee laptop | Sends OpenAI-compatible API requests to `127.0.0.1:8787/v1` |
| **Relay** (`oac-relay`) | Employee laptop | Authenticates employee via OIDC, mints a local API key, injects it into the agent config, forwards traffic over mTLS to the central proxy |
| **Central proxy** (`oac-central`) | Company-hosted server | Holds the master key in a secret store, validates relay-forwarded identity, enforces group-based policies, forwards to the backend with SSE streaming |
| **IdP** (Okta, Keycloak, etc.) | Company infrastructure | Authenticates employees via OIDC auth-code + PKCE |
| **Backend** (OpenAI, Azure OpenAI, etc.) | External | OpenAI-compatible API that the central proxy calls with the master key |

## Who is this for?

| Role | What you need | Where to start |
|---|---|---|
| **Employee** — wants to use an AI agent | Install the relay, log in, run the agent | [Quickstart](./quickstart.md) → [Relay Setup](./relay-setup.md) |
| **Admin** — manages policies, devices, audit | Configure the central proxy, use the admin CLI | [Central Proxy Setup](./central-setup.md) → [Admin API](./admin-api.md) |
| **Operator** — deploys and runs the infrastructure | Deploy the central proxy, distribute certs | [Docker: Production](./docker-prod.md) → [Configuration Reference](./configuration.md) |

## Key properties

- **Master key isolation** — the master backend key lives only in the
  central proxy's `Zeroizing` memory, loaded from a secret store. It is
  never sent to a laptop, never logged, never in a config file.
- **OIDC authentication** — employees authenticate via the standard
  authorization-code + PKCE flow against your enterprise IdP. No static
  passwords, no shared API keys.
- **mTLS** — relay-to-central traffic is mutually authenticated with TLS
  1.3 and a company CA.
- **Group-based authorization** — the central proxy enforces per-group
  model allowlists, endpoint restrictions, and daily quotas.
- **Audit trail** — every request is logged in an append-only audit log
  with user identity, model, status, latency, token usage, and cost.
- **No `unsafe` code** — `#![forbid(unsafe_code)]` across all crates.

## What's not implemented yet

The following are intentionally **not** documented because they are not yet
built:

- Vault / AWS Secrets Manager / GCP / Azure secret-store backends (only
  `kind = "file"` works today).
- Rate limiting on the central proxy (relies on mTLS + network ACLs for v1).
- Refresh token handling (v1 re-login on expiry; no token storage).
