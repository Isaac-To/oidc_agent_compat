# Build, Test & Lint

## Prerequisites

- **Rust 1.85+** (stable). The toolchain is pinned via
  `rust-toolchain.toml` (stable + rustfmt + clippy).
- For the dev stack: **Docker** and **Docker Compose**.
- For this documentation book: **mdBook** (`cargo install mdbook`).

## Build

```sh
# Debug build:
cargo build

# Release build (optimized, LTO, stripped):
cargo build --release
```

Release profile settings (from `Cargo.toml`):

```toml
[profile.release]
lto = true
codegen-units = 1
strip = true
```

## Test

```sh
# Full suite: unit + integration + in-process e2e:
cargo test --workspace

# Just one crate:
cargo test -p oac-relay
cargo test -p oac-central

# Just the E2E tests:
cargo test -p oac-e2e-tests
```

See [Testing](./testing.md) for what each suite covers.

## Lint

```sh
# Clippy (all targets, workspace-wide):
cargo clippy --workspace --all-targets

# Formatting check:
cargo fmt --all --check

# Fix formatting:
cargo fmt --all
```

## Security audit

```sh
# Known advisories (the two unavoidable transitive advisories are ignored):
cargo audit --ignore RUSTSEC-2023-0071 --ignore RUSTSEC-2025-0134
```

The CI audit ignores two documented, unavoidable transitive advisories:
`RUSTSEC-2023-0071` (`rsa 0.9.10`, no fixed upgrade available) and
`RUSTSEC-2025-0134` (`rustls-pemfile 2.2.0`, unmaintained). All other
advisories and warnings remain errors in CI.

```sh
# License + ban checks:
cargo deny check
```

The repository's `deny.toml` explicitly allows the workspace's intentional
dependency inheritance, required transitive build scripts, and
`CDLA-Permissive-2.0` used by `webpki-roots`.

## Docker dev stack

```sh
./docker/dev.sh up       # Start all containers
./docker/dev.sh test     # Run full-chain tests
./docker/dev.sh down     # Stop all containers
```

See [Docker: Dev Stack](../user-guide/docker-dev.md) for details.

## Documentation

```sh
# Build the mdBook:
mdbook build docs/

# Serve with live reload:
mdbook serve docs/ --open

# Generate Rust API docs:
cargo doc --workspace --open
```

## CI checklist

Before merging, ensure all of the following pass:

- [ ] `cargo test --workspace`
- [ ] `cargo clippy --workspace --all-targets`
- [ ] `cargo fmt --all --check`
- [ ] `cargo build --release`
- [ ] `./docker/dev.sh test` (if Docker is available)
- [ ] `mdbook build docs/` (no warnings)
