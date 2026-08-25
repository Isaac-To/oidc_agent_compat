# AGENTS.md — OIDC Agent Compatibility Server

Guidance for AI coding agents working in this repo. Keep this file concise
and link to existing docs rather than duplicating them.

## What this project is

An enterprise OIDC-to-AI-agent forwarder. Employees run a thin **laptop
relay** (`oac-relay`) that authenticates them via OIDC and forwards agent
traffic over mTLS to a company-hosted **central proxy** (`oac-central`),
which holds the master backend key in a secret store and forwards to an
OpenAI-compatible backend. The master key never touches any laptop.

```
Agent → 127.0.0.1 relay → mTLS → central proxy → OpenAI-compatible backend
                                  ↑ master key (secret manager)
```

See `README.md` for the user-facing overview and `docs/threat-model.md` for
the security design.

## Workspace layout

Cargo workspace, edition 2024, resolver 2. Four members:

| Crate | Path | Role |
|---|---|---|
| `oidc-agent-common` | `crates/common` | Shared primitives: config, errors, keys, OIDC client, mTLS, logging, shutdown |
| `oac-relay` | `crates/relay` | Laptop relay binary + lib (lib exposed for integration tests) |
| `oac-central` | `crates/central` | Central proxy binary + lib |
| `oac-e2e-tests` | `tests/e2e` | In-process end-to-end tests (spins up mock backend + central + relay) |

Key modules:
- `crates/common/src/config.rs` — `RelayConfig` / `CentralConfig` TOML schemas + validation (relay rejects `0.0.0.0`).
- `crates/common/src/error.rs` — unified `Error` enum + `Result` alias. Use this, not `anyhow`, in library code.
- `crates/common/src/keys.rs` — local API key gen, SHA-256 hashing, constant-time compare.
- `crates/common/src/oidc.rs` — OIDC RP client builder.
- `crates/common/src/mtls.rs` — rustls mTLS client/server builders.
- `crates/relay/src/login.rs` — `oac-relay login`: auth-code + PKCE flow, loopback callback, ID-token validation, agent config injection.
- `crates/relay/src/proxy/` — `mod.rs`, `auth.rs` (local key check), `forward.rs` (relay→central), `host_guard.rs` (DNS rebinding defense).
- `crates/relay/src/keystore.rs`, `agent_config.rs`, `db.rs`, `migration.rs`, `entity/` — persistence + agent config injection.
- `crates/central/src/proxy/` — `mod.rs`, `auth.rs` (validates relay user tokens), `forward.rs` (central→backend, SSE streaming).
- `crates/central/src/secrets.rs` — `SecretStore` trait; `FileSecretStore` for dev. Vault/AWS/GCP/Azure are TODO.
- `crates/central/src/audit.rs` — audit logger.
- `crates/central/src/db.rs`, `migration.rs`, `entity/` — central persistence.

## Build, test, lint

```sh
cargo test --workspace          # full suite: unit + integration + in-process e2e
cargo clippy --workspace --all-targets
cargo fmt --all -- --check      # fix with: cargo fmt --all
cargo build --release
```

Rust toolchain is pinned via `rust-toolchain.toml` (stable + rustfmt + clippy).
Minimum Rust 1.85; edition 2024.

### Known tooling caveats (do not "fix" without asking)

- `cargo audit` flags 2 **pre-existing** transitive advisories (`rsa 0.9.10`,
  `rustls-pemfile 2.2.0`) — not our code, no fix available.
- `cargo deny check` is **broken on master**: `deny.toml` line 32
  `allow-build-scripts = true` is incompatible with cargo-deny 0.20.2 (expects
  an array). Fix would be `allow-build-scripts = []`. Do not loosen policy
  without explicit user approval.

## Conventions (enforced by workspace lints)

- `#![forbid(unsafe_code)]` in every crate. No `unsafe` anywhere.
- Workspace clippy lints set to warn: `unwrap_used`, `expect_used`, `panic`,
  `indexing_slicing`, `todo`, `dbg_macro`. Use `?`, `get()`/`get_mut()`, and
  explicit error variants instead. Tests `#![allow]` these for brevity.
- `missing_docs` is warn — document public items.
- Library code returns `oidc_agent_common::error::Result` (thiserror-based
  `Error` enum). Reserve `anyhow` for binary `main` glue if needed.
- Secrets are never literals in config: OIDC client secret is referenced by
  env-var name (`client_secret_env`); master key lives only in the secret
  store. The master key is held in `Zeroizing` memory, never logged, never
  sent to a laptop.
- Logging is structured JSON via `tracing`/`tracing-subscriber` with a
  secret-redaction layer (`crates/common/src/logging.rs`). Never log raw
  keys/tokens.
- Hop-by-hop headers are stripped (RFC 7230 §6.1); host header is validated
  (DNS rebinding defense) in the relay.

## OIDC login flow (security-critical)

`crates/relay/src/login.rs` implements the full auth-code + PKCE flow. When
editing, follow RFC 8252 (loopback redirect, any port), RFC 7636/9700 (PKCE
S256 mandatory), OIDC Core §3.1.3.7 (ID-token validation). The ID-token alg
is pinned to {RS256, ES256}; `none` is disallowed. `state`/`nonce` are
verified; `at_hash` validation is a known TODO (deferred). See
`/memories/repo/oidc-security-research.md` for the full RFC citation list.

Manual verification: run `oac-relay login` on the **host** against dev
Keycloak using `docker/configs/relay-login-test.toml` (`dev_mode=true`,
port 8788). The containerized relay cannot do login (no host browser /
loopback callback).

## Docker dev stack

Everything runs in Docker; Goose runs headless in a container.

```sh
./docker/dev.sh up|down|status|logs|shell|goose|goose-run|test
```

- Central proxy serves **plain HTTP on :8443** (axum::serve, no TLS — mTLS is
  a TODO). Never probe it over HTTPS.
- Relay auto-mints dev key `oac_test_key_alice` when `dev_mode=true`
  (`crates/relay/src/main.rs` `serve()` → `seed_dev_key`). Idempotent.
- `dev.sh test` exercises the full chain + SSE + master-key-leak check.
- Master key `sk-mock-backend-master-key` is loaded via a central-init
  one-shot container. It must never appear in relay responses/logs.
- Dockerfile runtime base **must be `debian:trixie-slim`** (not
  `bookworm-slim`) to match the `rust:1.98-slim` builder's glibc 2.41.
- Keycloak realm `oac-dev` allows `http://127.0.0.1:*` (any port) for client
  `oac-relay`. Test users: `alice`/`alice-pass-123`, `bob`/`bob-pass-456`,
  `charlie`/`charlie-pass-789`, `admin`/`admin-pass-000`.

See `docker/README.md` for the full service table and quick start.

## Out of scope (TODOs — don't assume implemented)

- mTLS relay↔central (plain HTTP over Docker network in dev).
- Vault/AWS/GCP/Azure secret-store backends (only `kind = "file"` works).
- `at_hash` validation.
- Groups extraction from userinfo (not a standard OIDC claim).

## Commit preferences

- Make regular commits during coding tasks.
- Commit messages should include a description (body), not just a subject.
