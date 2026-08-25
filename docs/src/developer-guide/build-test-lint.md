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
# Known advisories:
cargo audit
```

> **Known caveat:** `cargo audit` flags 2 pre-existing transitive
> advisories (`rsa 0.9.10`, `rustls-pemfile 2.2.0`) — these are in
> third-party dependencies, not our code, and no fix is available. Do not
> "fix" these without asking.

```sh
# License + ban checks:
cargo deny check
```

> **Known caveat:** `cargo deny check` is currently broken on master. The
> `deny.toml` line 32 `allow-build-scripts = true` is incompatible with
> cargo-deny 0.20.2 (which expects an array). The fix would be
> `allow-build-scripts = []`. **Do not loosen policy without explicit
> user approval.**

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
