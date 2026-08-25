# AGENTS.md — OIDC Agent Compatibility Server

Guidance for AI coding agents working in this repo. Read this file before
making any change. Keep it concise; link to existing docs rather than
duplicating them.

---

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

---

## Agent operating principles

These principles govern **every** change an agent makes in this repo. They
are non-negotiable.

### 1. Be responsible

- You are accountable for the correctness and safety of your changes.
  Review your own diff before committing as if a human reviewer would
  reject anything sloppy.
- Never disable a security control to make a test pass or unblock a build.
  If a test fails because of a security check, the code is wrong, not the
  check.
- Never commit secrets, credentials, tokens, or private keys. The repo is
  public-equivalent; assume anything you push will be read by an attacker.
- When in doubt about whether a change is safe, **stop and ask** rather
  than guessing. Security-sensitive areas (mTLS, OIDC, secret store,
  auth, key handling) warrant extra caution.
- Do not "fix" pre-existing advisories or policy files without explicit
  user approval (see [Known caveats](#known-caveats-do-not-fix-without-asking)).

### 2. Always work in a branch

- Create a dedicated branch from `master` before making any change:
  `git checkout -b <type>/<short-description>` (e.g. `feat/refresh-tokens`,
  `docs/redesign-agents-md`, `fix/relay-host-guard`).
- Keep branches focused — one logical change per branch. If a task spans
  multiple unrelated changes, split into separate branches and PRs.
- Never commit directly to `main` or `master`. Never force-push to shared
  branches.
- Squash-merge or rebase-merge into `master` when the work is complete and
  verified.

### 3. Test comprehensively

- Run the full quality gate before considering work done:
  ```sh
  cargo fmt --all -- --check      # formatting clean (fix with: cargo fmt --all)
  cargo clippy --workspace --all-targets  # no warnings
  cargo test --workspace          # unit + integration + in-process e2e
  cargo build --release           # release build succeeds
  ```
- If you changed Docker-relevant code and Docker is available, also run:
  ```sh
  ./docker/dev.sh test            # full chain + SSE + master-key-leak check
  ```
- If you changed documentation, run `mdbook build docs/` and confirm no
  warnings.
- Do not mark a task complete until every gate above passes. If a gate
  fails and you cannot fix it, report the failure honestly rather than
  claiming success.
- Write tests for new behavior. Security-critical code (auth, mTLS, key
  handling) must have negative-path tests (e.g. wrong cert, expired token,
  tampered ID token).

### 4. Update the documentation

Documentation is part of the deliverable, not an afterthought. When you
change behavior, update the relevant docs in the same branch and commit:

| Change type | Update |
|---|---|
| CLI flags / commands | `docs/src/user-guide/cli-reference.md` |
| Config schema / fields | `docs/src/user-guide/configuration.md` |
| Admin API endpoints | `docs/src/user-guide/admin-api.md` |
| Architecture / data flow | `docs/src/developer-guide/README.md`, `docs/src/reference/architecture.md`, `docs/src/reference/data-flow.md` |
| Conventions / lints | `docs/src/developer-guide/conventions.md` |
| Crate internals | corresponding `docs/src/developer-guide/*-internals.md` |
| Threat model / security | `docs/src/reference/threat-model.md`, `docs/src/user-guide/security.md` |
| Docker dev stack | `docs/src/user-guide/docker-dev.md`, `docker/README.md` |
| Docker production | `docs/src/user-guide/docker-prod.md` |
| New mdBook page | add entry to `docs/src/SUMMARY.md` |

Preview the book while editing:

```sh
mdbook serve docs/ --open
```

Rust API type signatures are delegated to rustdoc (`cargo doc --workspace
--open`), not hand-maintained in the mdBook.

### 5. Follow industry standards

This project implements security-critical protocols. Adhere to the relevant
RFCs and standards; do not invent ad-hoc variants.

- **OIDC**: OIDC Core 1.0 (ID-token validation §3.1.3.7), OIDC Core 1.0
  errata, OAuth 2.0 (RFC 6749), OAuth 2.0 Security Best Practices
  (RFC 9700).
- **PKCE**: RFC 7636 (S256 mandatory), RFC 9700 §2.1.1 (reject plain).
- **Native apps / loopback redirect**: RFC 8252 (loopback redirect, any
  port).
- **mTLS**: RFC 8705 (mutual TLS), RFC 8446 (TLS 1.3).
- **HTTP forwarding**: RFC 7230 §6.1 (strip hop-by-hop headers), RFC 7239
  (`Forwarded` header semantics).
- **JWT**: RFC 7519 (JWT), RFC 7515 (JWS). Pin signing alg to
  `{RS256, ES256}`; reject `none`.
- **Secrets**: NIST SP 800-63B (authenticator handling), OWASP Cryptographic
  Storage Cheat Sheet. Master key in `Zeroizing` memory, never logged,
  never sent to a laptop.
- **Constant-time comparison** for secrets (RFC 6151 guidance).

See `/memories/repo/oidc-security-research.md` for the full citation list.

### 6. Commit discipline

- Make regular commits during coding tasks — don't wait until the end to
  commit everything at once. Each commit should be a coherent, reviewable
  unit.
- Commit messages **must** include a description (body), not just a subject.
  The body should explain what changed and why.
- Use Conventional Commits prefixes (`feat:`, `fix:`, `docs:`, `refactor:`,
  `test:`, `chore:`, `security:`).

Example:

```
docs: add mdBook scaffolding and User Guide

Set up mdBook-based documentation suite with tree-based expandable
sidebar navigation. This commit adds:

- docs/book.toml: mdBook configuration
- docs/src/SUMMARY.md: sidebar tree (navigation entry point)
- docs/src/user-guide/: 12 pages covering overview, quickstart, ...

Content is sourced from exhaustive codebase exploration and covers
only implemented features (TODOs excluded to avoid misleading users).
```

---

## Workspace layout

Cargo workspace, edition 2024, resolver 2. Four members:

| Crate | Path | Role |
|---|---|---|
| `oidc-agent-common` | `crates/common` | Shared primitives: config, errors, keys, OIDC client, mTLS, logging, shutdown |
| `oac-relay` | `crates/relay` | Laptop relay binary + lib (lib exposed for integration tests) |
| `oac-central` | `crates/central` | Central proxy binary + lib |
| `oac-e2e-tests` | `tests/e2e` | In-process end-to-end tests (spins up mock backend + central + relay) |

**Documentation:** The project uses an [mdBook](https://rust-lang.github.io/mdBook/)
documentation suite under `docs/`. The sidebar tree (navigation entry point)
is `docs/src/SUMMARY.md`. To preview: `mdbook serve docs/ --open`. Three
sections: User Guide, Developer Guide, Reference. Rust API type signatures
are delegated to `cargo doc --workspace --open` (rustdoc), not hand-maintained
in the mdBook.

Key modules:

- `crates/common/src/config.rs` — `RelayConfig` / `CentralConfig` TOML schemas + validation (relay rejects `0.0.0.0`).
- `crates/common/src/error.rs` — unified `Error` enum + `Result` alias. Use this, not `anyhow`, in library code.
- `crates/common/src/keys.rs` — local API key gen, SHA-256 hashing, constant-time compare.
- `crates/common/src/oidc.rs` — OIDC RP client builder + `CustomAdditionalClaims` (groups/roles extraction).
- `crates/common/src/mtls.rs` — rustls mTLS client/server builders.
- `crates/relay/src/login.rs` — `oac-relay login`: auth-code + PKCE flow, loopback callback, ID-token validation, agent config injection.
- `crates/relay/src/proxy/` — `mod.rs`, `auth.rs` (local key check), `forward.rs` (relay→central), `host_guard.rs` (DNS rebinding defense).
- `crates/relay/src/keystore.rs`, `agent_config.rs`, `db.rs`, `migration.rs`, `entity/` — persistence + agent config injection.
- `crates/relay/src/activity.rs` — relay-side activity logger (append-only `relay_activity_log`).
- `crates/central/src/proxy/` — `mod.rs`, `auth.rs` (validates relay user tokens), `forward.rs` (central→backend, SSE streaming), `permissions.rs` (group-based model/endpoint enforcement), `rate_limit.rs`.
- `crates/central/src/admin.rs` — admin API (`/admin/v1/`) for policy/device/audit management.
- `crates/central/src/policy.rs` — `PolicyStore` + `resolve_policy` (group→policy merge, most-permissive-wins).
- `crates/central/src/device_store.rs` — device registration + revocation store.
- `crates/central/src/secrets.rs` — `SecretStore` trait; `FileSecretStore` for dev. Vault/AWS/GCP/Azure are TODO.
- `crates/central/src/audit.rs` — audit logger (enriched with identity, groups, endpoint, request-id, permission decision).
- `crates/central/src/db.rs`, `migration.rs`, `entity/` — central persistence.

---

## Build, test, lint

```sh
cargo fmt --all -- --check      # fix with: cargo fmt --all
cargo clippy --workspace --all-targets
cargo test --workspace          # full suite: unit + integration + in-process e2e
cargo build --release
```

Rust toolchain is pinned via `rust-toolchain.toml` (stable + rustfmt + clippy).
Minimum Rust 1.85; edition 2024.

### Known caveats (do not "fix" without asking)

- `cargo audit` flags 2 **pre-existing** transitive advisories (`rsa 0.9.10`,
  `rustls-pemfile 2.2.0`) — not our code, no fix available.
- `cargo deny check` is **broken on master**: `deny.toml` line 32
  `allow-build-scripts = true` is incompatible with cargo-deny 0.20.2 (expects
  an array). Fix would be `allow-build-scripts = []`. Do not loosen policy
  without explicit user approval.

---

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

See `docs/src/developer-guide/conventions.md` for the full convention
reference.

---

## OIDC login flow (security-critical)

`crates/relay/src/login.rs` implements the full auth-code + PKCE flow. When
editing, follow RFC 8252 (loopback redirect, any port), RFC 7636/9700 (PKCE
S256 mandatory), OIDC Core §3.1.3.7 (ID-token validation). The ID-token alg
is pinned to {RS256, ES256}; `none` is disallowed. `state`/`nonce` are
verified; `at_hash` validation is implemented (step 13c). See
`/memories/repo/oidc-security-research.md` for the full RFC citation list.

Manual verification: run `oac-relay login` on the **host** against dev
Keycloak using `docker/dev/configs/relay-login-test.toml` (`dev_mode=true`,
port 8788). The containerized relay cannot do login (no host browser /
loopback callback).

---

## Docker dev stack

Everything runs in Docker; Goose runs headless in a container.

```sh
./docker/dev.sh up|down|status|logs|shell|goose|goose-run|test
```

- Central proxy serves **mTLS on :8443** in production mode (`dev_mode=false`),
  using `axum_server::bind_rustls` with client cert required. In dev mode
  (`dev_mode=true`), it serves plain HTTP for the containerized dev stack.
  Never probe a prod central proxy over plain HTTP.
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

---

## Out of scope (TODOs — don't assume implemented)

- Vault/AWS/GCP/Azure secret-store backends (only `kind = "file"` works).
- Groups extraction from userinfo (not a standard OIDC claim).
- Refresh token handling (v1 re-login on expiry; no token storage).
- Token-quota enforcement (request-count quotas are enforced pre-flight;
  token quotas are tracked in the usage counters but not yet blocked).

---

## Definition of done

A change is complete only when **all** of the following are true:

- [ ] Work was done on a dedicated branch (not `main`/`master`).
- [ ] `cargo fmt --all -- --check` passes.
- [ ] `cargo clippy --workspace --all-targets` is warning-free.
- [ ] `cargo test --workspace` passes (unit + integration + e2e).
- [ ] `cargo build --release` succeeds.
- [ ] No secrets, keys, or tokens in the diff.
- [ ] No `unsafe` code added.
- [ ] No `unwrap()` / `expect()` / `panic!()` in library code.
- [ ] Public items have doc comments.
- [ ] New behavior has tests (including negative paths for security code).
- [ ] Documentation updated for any user-facing or architectural change.
- [ ] `mdbook build docs/` is warning-free (if docs changed).
- [ ] Commits are regular, focused, and include a descriptive body.
- [ ] PR is ready for review (or a clear summary of remaining work if
      blocked).
