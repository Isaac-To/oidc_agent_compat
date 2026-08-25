# OIDC Agent Compatibility Server

An enterprise-grade OIDC-to-AI-agent forwarder that lets employees use any
OpenAI-compatible AI agent (Codex, Goose, etc.) through company-approved
backends — **without the master backend key ever touching an employee's
laptop**.

## Architecture

```
Agent → [127.0.0.1 relay] → mTLS → [central proxy] → [OpenAI-compatible backend]
                                   ↑ master key (secret manager)
```

- **Central proxy** (company-hosted) — holds the master backend key in a
  secret store, authenticates employees via OIDC, forwards approved
  requests to the AI backend with SSE streaming.
- **Laptop relay** (thin, per-employee) — listens on `127.0.0.1`,
  authenticates the employee via OIDC, relays agent traffic to the central
  proxy over mTLS. Holds **no master key**.

## Documentation

Full documentation is in the [`docs/`](docs/) mdBook. To preview it:

```sh
cargo install mdbook   # one-time
mdbook serve docs/ --open
```

Or read the source files directly:

- **[User Guide](docs/src/user-guide/README.md)** — setup, configuration,
  CLI, Docker deployment, troubleshooting.
- **[Developer Guide](docs/src/developer-guide/README.md)** — architecture,
  internals, conventions, testing, contributing.
- **[Reference](docs/src/reference/architecture.md)** — system diagrams,
  threat model, request data flow.

**New here?** Start with the
[Quickstart](docs/src/user-guide/quickstart.md).

For full Rust API type signatures, run `cargo doc --workspace --open`.

## Quickstart

```sh
# Start the dev stack (Keycloak + mock backend + central + relay + Goose):
./docker/dev.sh up

# Verify the full chain:
./docker/dev.sh test

# Make a request:
curl -H 'Authorization: Bearer oac_test_key_alice' \
  http://127.0.0.1:8787/v1/models
```

See [Quickstart](docs/src/user-guide/quickstart.md) for the full
walkthrough.

## Development

```sh
cargo test --workspace          # all tests
cargo clippy --workspace --all-targets
cargo fmt --all --check
cargo build --release
```

See [Build, Test & Lint](docs/src/developer-guide/build-test-lint.md) for
details.

