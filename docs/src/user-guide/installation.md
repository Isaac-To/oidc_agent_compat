# Installation

## Prerequisites

### Rust toolchain

- **Rust 1.85+** (stable). The toolchain is pinned via
  [`rust-toolchain.toml`](https://github.com/iato/oidc-agent-compat/blob/main/rust-toolchain.toml)
  at the repo root, so if you use rustup it will automatically select the
  right version with `rustfmt` and `clippy` components.

  ```sh
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```

### External services

- **OIDC Identity Provider** — Okta, Entra ID, Keycloak, Auth0, or any
  OIDC-compliant IdP. You need: an issuer URL, a client ID, a client
  secret, and the ability to register a loopback redirect URI
  (`http://127.0.0.1:*`).

- **OpenAI-compatible backend** — OpenAI, Azure OpenAI, OpenRouter, Ollama,
  vLLM, or any backend that speaks the OpenAI API. You need: the base URL
  and a master API key.

### For the dev stack (optional)

- **Docker** and **Docker Compose** — for running the bundled dev stack
  (Keycloak + mock backend + central + relay + Goose).

### For documentation (optional)

- **mdBook** — to build and preview this documentation book locally:

  ```sh
  cargo install mdbook
  mdbook serve docs/ --open
  ```

## Build

From the repository root:

```sh
# Debug build (faster compile, slower runtime):
cargo build

# Release build (optimized, recommended for actual use):
cargo build --release
```

The binaries are placed at:

| Binary | Path | Purpose |
|---|---|---|
| `oac-relay` | `target/debug/oac-relay` or `target/release/oac-relay` | Laptop relay |
| `oac-central` | `target/debug/oac-central` or `target/release/oac-central` | Central proxy |

## Verify the build

```sh
# Run all tests (unit + integration + in-process e2e):
cargo test --workspace

# Lint:
cargo clippy --workspace --all-targets

# Check formatting:
cargo fmt --all --check
```

All three should pass cleanly.

## Binary locations after install

If you are deploying the relay to employee laptops, copy the release
binary to a standard location:

```sh
cp target/release/oac-relay /usr/local/bin/oac-relay
# or per-user:
mkdir -p ~/.local/bin
cp target/release/oac-relay ~/.local/bin/oac-relay
```

The central proxy is typically deployed as a Docker container — see
[Docker: Production](./docker-prod.md).

## Next steps

- [Relay Setup](./relay-setup.md) — configure and run the relay.
- [Central Proxy Setup](./central-setup.md) — configure and run the central
  proxy.
- [Configuration Reference](./configuration.md) — all TOML fields.
