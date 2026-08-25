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

Production setup in 7 steps (central proxy in Docker + relay on laptop):

```sh
# 1. Generate mTLS certs:
./docker/generate-certs.sh
cp docker/certs/{ca,server,client}.{crt,key} docker/prod/certs/

# 2. Configure the central proxy:
cp docker/prod/configs/central.toml docker/prod/configs/central.toml
# Edit issuer, backend.base_url for your environment.

# 3. Provide secrets:
echo "OAC_OIDC_CLIENT_SECRET=your-secret" > docker/prod/.env
echo -n 'sk-your-master-key' | docker secret create oac_master_key -

# 4. Deploy the central proxy:
cd docker/prod && docker compose up -d --build

# 5. Install the relay on a laptop:
cargo build --release -p oac-relay
cp target/release/oac-relay /usr/local/bin/oac-relay
cp docker/prod/configs/relay.toml ~/.oac/relay.toml
# Copy ca.crt, client.crt, client.key to ~/.oac/certs/

# 6. Log in and start the relay:
export OAC_OIDC_CLIENT_SECRET="your-secret"
oac-relay --config ~/.oac/relay.toml login
oac-relay --config ~/.oac/relay.toml serve

# 7. Make a request:
curl -H "Authorization: Bearer $OPENAI_API_KEY" \
  http://127.0.0.1:8787/v1/models
```

See [Quickstart](docs/src/user-guide/quickstart.md) for the full
walkthrough. For the dev stack (bundled Keycloak + mock backend), see
[Docker: Dev Stack](docs/src/user-guide/docker-dev.md).

## Development

```sh
cargo test --workspace          # all tests
cargo clippy --workspace --all-targets
cargo fmt --all --check
cargo build --release
```

See [Build, Test & Lint](docs/src/developer-guide/build-test-lint.md) for
details.

