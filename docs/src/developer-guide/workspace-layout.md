# Workspace Layout

The project is a Cargo workspace with four crates. This page documents the
full source file tree.

## Crate overview

| Crate | Path | Binary | Lib | Role |
|---|---|---|---|---|
| `oidc-agent-common` | `crates/common` | — | `oidc_agent_common` | Shared primitives |
| `oac-relay` | `crates/relay` | `oac-relay` | `oac_relay` | Laptop relay |
| `oac-central` | `crates/central` | `oac-central` | `oac_central` | Central proxy |
| `oac-e2e-tests` | `tests/e2e` | — | `oac_e2e_tests` | In-process E2E tests |

## Full source tree

### `crates/common/` — Shared primitives

```
crates/common/src/
├── lib.rs              # Crate root; re-exports all modules
├── config.rs           # RelayConfig / CentralConfig TOML schemas + validation
├── error.rs            # Unified Error enum + Result alias (thiserror)
├── keys.rs             # Local API key gen, SHA-256 hashing, constant-time compare
├── oidc.rs             # OIDC RP client builder + CustomAdditionalClaims
├── mtls.rs             # rustls mTLS client/server config builders
├── logging.rs          # Structured JSON logging + secret-redaction layer
├── shutdown.rs         # Graceful shutdown signal handler
├── http_util.rs        # HTTP forwarding utilities (hop-by-hop, path sanitization, SSE)
├── identity.rs         # X-OAC-* identity header constants
├── persistence.rs      # Shared DB helpers (setup_database, enforce_db_perms)
├── time_util.rs        # Time utilities (now_utc, format_time)
└── test_certs.rs       # Test cert generation (rcgen, behind test-certs feature)
```

### `crates/relay/` — Laptop relay

```
crates/relay/src/
├── lib.rs              # Lib exposed for integration tests
├── main.rs             # Binary: CLI dispatch, serve(), seed_dev_key
├── login.rs            # OIDC auth-code + PKCE flow, ID-token validation, agent config injection
├── keystore.rs         # KeyStore: key minting, identity upsert, key verification
├── db.rs               # Relay DB setup
├── migration.rs        # SeaORM migrations (2 migrations)
├── activity.rs         # Relay-side activity logger (append-only)
├── agent_config.rs     # Agent config injection (Codex config.json / ~/.oac/agent-env.sh)
├── proxy/
│   ├── mod.rs          # Router, AppState, serve()
│   ├── auth.rs         # Local key auth middleware
│   ├── forward.rs      # Relay→central forwarding (mTLS client, SSE passthrough)
│   └── host_guard.rs   # DNS rebinding defense (Host header validation)
└── entity/
    ├── mod.rs
    ├── api_key.rs          # api_key entity
    ├── identity.rs         # identity entity
    └── relay_activity_log.rs  # relay_activity_log entity

crates/relay/tests/
└── proxy_integration.rs    # 6 integration tests
```

### `crates/central/` — Central proxy

```
crates/central/src/
├── lib.rs              # Lib exposed for integration tests
├── main.rs             # Binary: serve, set-backend-key, admin CLI
├── db.rs               # Central DB setup
├── migration.rs        # SeaORM migrations (4 migrations)
├── admin.rs            # Admin API (/admin/v1/) router, handlers, auth middleware
├── policy.rs           # PolicyStore + resolve_policy (group→policy merge)
├── device_store.rs     # Device registration + revocation store
├── secrets.rs          # SecretStore trait; FileSecretStore
├── audit.rs            # Audit logger (enriched with identity, groups, endpoint, etc.)
├── usage.rs            # UsageTracker (per-user daily token/request quotas)
├── pricing.rs          # PriceTable (model cost computation, auto-fetch from backend)
├── proxy/
│   ├── mod.rs          # Router, AppState, serve()
│   ├── auth.rs         # Validates relay-forwarded identity headers
│   ├── forward.rs      # Central→backend forwarding (SSE streaming, master key injection)
│   ├── permissions.rs  # Group-based model/endpoint/quota enforcement
│   └── rate_limit.rs   # Per-IP token bucket rate limiter
└── entity/
    ├── mod.rs
    ├── audit_log.rs        # audit_log entity (append-only)
    ├── usage_counter.rs    # usage_counter entity
    ├── device.rs           # device entity
    ├── admin_audit_log.rs  # admin_audit_log entity (append-only)
    └── group_policy.rs     # group_policy entity

crates/central/tests/
└── proxy_integration.rs    # 11 integration tests (dev + prod + mTLS modes)
```

### `tests/e2e/` — In-process E2E tests

```
tests/e2e/
├── Cargo.toml
├── src/
│   └── lib.rs          # Lint allows only
└── tests/
    └── e2e.rs          # 15 E2E tests (full chain + permissions + device revocation)
```

## Workspace `Cargo.toml`

Key workspace settings:

```toml
[workspace]
resolver = "2"
members = ["crates/common", "crates/relay", "crates/central", "tests/e2e"]

[workspace.package]
version = "0.1.0"
edition = "2024"
rust-version = "1.85"

[workspace.lints.rust]
unsafe_code = "forbid"
missing_docs = "warn"

[workspace.lints.clippy]
unwrap_used = "warn"
expect_used = "warn"
panic = "warn"
indexing_slicing = "warn"
todo = "warn"
dbg_macro = "warn"
```

## Toolchain

Pinned via `rust-toolchain.toml`:

```toml
[toolchain]
channel = "stable"
components = ["rustfmt", "clippy"]
```

Minimum Rust 1.85; edition 2024.
