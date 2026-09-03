# Contributing

## Commit conventions

- **Make regular commits** during coding tasks — don't wait until the end
  to commit everything at once.
- **Commit messages must include a description (body)**, not just a
  subject line. The body should explain what changed and why.

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

## Branch flow

- Create a feature branch from `master` (e.g. `docs/mdbook-suite`).
- Keep branches focused — one logical change per branch.
- Squash-merge or rebase-merge into `master`.

## PR checklist

Before requesting review, ensure all of the following pass:

- [ ] `cargo test --workspace` — all tests pass.
- [ ] `cargo clippy --workspace --all-targets` — no warnings.
- [ ] `cargo fmt --all --check` — formatting is clean.
- [ ] `cargo build --release` — release build succeeds.
- [ ] No secrets in the diff (no API keys, passwords, tokens).
- [ ] No `unsafe` code added.
- [ ] No `unwrap()` / `expect()` / `panic!()` in library code (use `?`,
  `get()`, explicit error variants).
- [ ] Public items have doc comments (`///`).
- [ ] `mdbook build docs/` — no warnings (if docs changed).
- [ ] `./docker/dev.sh test` — full chain passes (if Docker available).

## Code style

- Follow the workspace clippy lints (see
  [Conventions](./conventions.md)).
- Use `oidc_agent_common::error::Result` in library code, not `anyhow`.
- Use `get()` / `get_mut()` instead of indexing.
- Document all public items.
- Never log raw secrets — the redaction layer is a safety net, not a
  license to log secrets.
- Enforce `0600` on security-sensitive files.

## Documentation

If you change user-facing behavior (CLI, config, endpoints), update the
relevant docs:

- CLI changes → `docs/src/user-guide/cli-reference.md`
- Config changes → `docs/src/user-guide/configuration.md`
- Admin API changes → `docs/src/user-guide/admin-api.md`
- Architecture changes → `docs/src/developer-guide/README.md` and
  `docs/src/reference/architecture.md`

Build and preview the docs:

```sh
mdbook serve docs/ --open
```

Generate Rust API docs:

```sh
cargo doc --workspace --open
```

## Known caveats (do not "fix" without asking)

- CI ignores two documented, unavoidable transitive advisories:
  `RUSTSEC-2023-0071` (`rsa 0.9.10`, no fixed upgrade available) and
  `RUSTSEC-2025-0134` (`rustls-pemfile 2.2.0`, unmaintained). All other
  advisories and warnings remain errors.
- `cargo deny check` passes with the repository's explicit policy for
  workspace dependency inheritance, required transitive build scripts, and
  `CDLA-Permissive-2.0` used by `webpki-roots`.
- Dockerfile runtime base must be `debian:trixie-slim` (not
  `bookworm-slim`) to match the `rust:1.98-slim` builder's glibc 2.41.
