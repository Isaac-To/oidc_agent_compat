# Installation

## Prerequisites

### Rust toolchain

- **Rust 1.85+** (stable). The toolchain is pinned via
  [`rust-toolchain.toml`](https://github.com/isaac-to/oidc-agent-compat/blob/main/rust-toolchain.toml)
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

## Download prebuilt binaries

If you do not want to build from source (and you are not on a platform we
ship binaries for), you normally do **not** need the Rust toolchain at all.
Every tagged release publishes prebuilt, binaries-only `.zip` archives to
the project's **GitHub Releases** page:

> **https://github.com/isaac-to/oidc-agent-compat/releases**

### Available platforms

| Platform | Archive | Notes |
|---|---|---|
| macOS (Apple Silicon) | `oac-<version>-aarch64-apple-darwin.zip` | Most laptop-relay users |
| Linux (x86_64) | `oac-<version>-x86_64-unknown-linux-gnu.zip` | Typical servers |
| Linux (ARM64) | `oac-<version>-aarch64-unknown-linux-gnu.zip` | e.g. AWS Graviton |
| Windows (x86_64) | `oac-<version>-x86_64-pc-windows-msvc.zip` | Windows laptops |

Each archive is pure binaries — it contains `oac-relay` and `oac-central`
at the top level (plus `oac-relay.exe` / `oac-central.exe` on Windows) and
**no config files or secrets**. Alongside the archives, releases also host
a `SHA256SUMS` file so you can verify downloads.

> **Intended audience**
> - The **relay** (`oac-relay`) is what you install on employee laptops.
> - The **central proxy** (`oac-central`) is typically deployed to a server,
>   often as a [Docker container](./docker-prod.md). The standalone binary
>   is just as valid if you run it on a bare-metal or VM host.

### macOS (Apple Silicon) — quick start

```sh
VERSION="0.1.0"
curl -fsSL -o oac-relay.zip \
  "https://github.com/isaac-to/oidc-agent-compat/releases/download/v${VERSION}/oac-${VERSION}-aarch64-apple-darwin.zip"
unzip oac-relay.zip
mv oac-relay oac-central /usr/local/bin/
```

### Linux (x86_64) — quick start

```sh
VERSION="0.1.0"
curl -fsSL -o oac-linux.zip \
  "https://github.com/isaac-to/oidc-agent-compat/releases/download/v${VERSION}/oac-${VERSION}-x86_64-unknown-linux-gnu.zip"
unzip oac-linux.zip
sudo mv oac-relay oac-central /usr/local/bin/
```

### Windows (x86_64) — quick start

Download `oac-<version>-x86_64-pc-windows-msvc.zip`, extract it, and add
the folder containing `oac-relay.exe` to your `PATH`, or move the binaries
to a location already on your `PATH`:

```powershell
# PowerShell
Expand-Archive .\oac-<version>-x86_64-pc-windows-msvc.zip -DestinationPath .\oac
```

### Verify the download (optional)

Compute the SHA-256 of each downloaded archive and compare against the
`SHA256SUMS` file attached to the same release:

```sh
# macOS / Linux
curl -fsSL \
  "https://github.com/isaac-to/oidc-agent-compat/releases/download/v0.1.0/SHA256SUMS"
shasum -c SHA256SUMS       # macOS
# sha256sum -c SHA256SUMS  # Linux
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
