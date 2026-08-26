# Architecture

The OIDC Agent Compatibility Server is a Cargo workspace (edition 2024,
resolver 2) with four crates. This page gives the high-level architecture;
for the full file tree, see [Workspace Layout](./workspace-layout.md).

## System overview

```
Agent (Codex, Goose, etc.)
  │  Authorization: Bearer <local key>
  ▼
[127.0.0.1 relay]  ── mTLS (TLS 1.3) ──►  [central proxy]  ──►  [OpenAI-compatible backend]
  │                                        │
  │ OIDC (browser, auth-code + PKCE)       │ encrypted provider keys
  ▼                                        ▼
[Enterprise IdP]                           [Audit log (append-only)]
```

## Crate map

| Crate | Path | Role |
|---|---|---|
| `oidc-agent-common` | `crates/common` | Shared primitives: config, errors, keys, OIDC client, mTLS, logging, shutdown, HTTP utilities, persistence |
| `oac-relay` | `crates/relay` | Laptop relay binary + lib (lib exposed for integration tests) |
| `oac-central` | `crates/central` | Central proxy binary + lib |
| `oac-e2e-tests` | `tests/e2e` | In-process end-to-end tests (spins up mock backend + central + relay) |

## Data flow

1. The **agent** sends an OpenAI-compatible request to `127.0.0.1:8787/v1`
   with `Authorization: Bearer <local-key>`.
2. The **relay** validates the `Host` header (DNS rebinding defense),
   verifies the local key (constant-time, SHA-256 hash lookup), extracts
   the verified identity, replaces the `Authorization` header with
   `x-oac-*` identity headers, and forwards over mTLS to the central
   proxy.
3. The **central proxy** validates the relay-forwarded identity headers,
   resolves the user's group policy, checks device revocation and quotas,
   resolves an encrypted provider key, and forwards to the backend.
4. The **backend** responds (optionally with SSE streaming). The central
   proxy extracts token usage, computes cost, records an audit entry,
   increments usage counters, and streams the response back.
5. The **relay** streams the response back to the agent and records a
   relay activity log entry.

For a detailed walkthrough with the header table, see
[Request Data Flow](../reference/data-flow.md).

## Trust boundaries

1. **Agent → relay** (loopback HTTP — same host, low trust).
2. **Relay → central proxy** (mTLS over network — medium trust).
3. **Central proxy → backend** (HTTPS — external, low trust).
4. **Relay/central → IdP** (OIDC — external, low trust).

## Key design principles

- **Provider-key isolation** — provider keys are encrypted at rest and
  decrypted only in central proxy process memory; the relay never sees them.
- **Defense in depth** — mTLS, OIDC, local key hashing, DNS rebinding
  defense, hop-by-hop header stripping, path sanitization, append-only
  audit logs.
- **No `unsafe` code** — `#![forbid(unsafe_code)]` in every crate.
- **Structured logging with redaction** — all logs are JSON, sensitive
  fields are automatically redacted.
- **RFC compliance** — OIDC Core, RFC 8252, RFC 7636/9700, RFC 7230.

## Next steps

- [Workspace Layout](./workspace-layout.md) — full file tree.
- [Build, Test & Lint](./build-test-lint.md) — how to build and test.
- [Relay Internals](./relay-internals.md) — relay deep dive.
- [Central Internals](./central-internals.md) — central proxy deep dive.
