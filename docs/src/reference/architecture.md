# System Architecture

## System overview

```
Agent (Codex, Goose, etc.)
  │  Authorization: Bearer <local key>
  ▼
[127.0.0.1 relay]  ── mTLS (TLS 1.3) ──►  [central proxy]  ──►  [OpenAI-compatible backend]
  │                                        │
  │ OIDC (browser, auth-code + PKCE)       │ master key (secret manager)
  ▼                                        │
[Enterprise IdP]                           ▼
                                  [Audit log (append-only)]
```

## Components

| Component | Where it runs | Role |
|---|---|---|
| Agent | Employee laptop | Sends OpenAI-compatible API requests to `127.0.0.1:8787/v1` |
| Relay (`oac-relay`) | Employee laptop | Authenticates employee via OIDC, mints local key, forwards over mTLS |
| Central proxy (`oac-central`) | Company-hosted server | Holds master key, enforces policies, forwards to backend |
| IdP | Company infrastructure | Authenticates employees via OIDC auth-code + PKCE |
| Backend | External | OpenAI-compatible API called with the master key |

## Trust boundaries

1. **Agent → relay** (loopback HTTP — same host, low trust).
2. **Relay → central proxy** (mTLS over network — medium trust).
3. **Central proxy → backend** (HTTPS — external, low trust).
4. **Relay/central → IdP** (OIDC — external, low trust).

## Assets

| Asset | Location | Sensitivity |
|---|---|---|
| Master backend key | Central secret manager → `Zeroizing` memory | **CRITICAL** — never on laptop |
| Local API keys (plaintext) | Agent config file (`0600`) | Medium — loopback-only, revocable |
| Local API key hashes | Relay SQLite (`0600`) | Low — SHA-256 hashes |
| OIDC ID tokens | In transit only (not stored in v1) | Medium — short-lived |
| User identity (subject, email) | Relay + central DB, audit log | Medium — PII |
| Audit log | Central DB (append-only) | Medium — tamper-evident |

## Crate map

| Crate | Path | Role |
|---|---|---|
| `oidc-agent-common` | `crates/common` | Shared primitives: config, errors, keys, OIDC, mTLS, logging, HTTP utilities |
| `oac-relay` | `crates/relay` | Laptop relay binary + lib |
| `oac-central` | `crates/central` | Central proxy binary + lib |
| `oac-e2e-tests` | `tests/e2e` | In-process end-to-end tests |

See [Workspace Layout](../developer-guide/workspace-layout.md) for the full
file tree.

## Related

- [Threat Model](./threat-model.md) — STRIDE analysis.
- [Request Data Flow](./data-flow.md) — request lifecycle with header
  table.
- [Developer Guide: Architecture](../developer-guide/README.md).
