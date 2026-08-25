# Rustdoc API Reference

This documentation book covers architecture, usage, CLI, configuration,
and behavior. For full Rust type signatures (structs, enums, functions,
traits, constants), use **rustdoc** — the standard Rust API documentation
tool.

## Generate the API docs

```sh
# All crates, opens in browser:
cargo doc --workspace --open

# Just the common crate:
cargo doc -p oidc-agent-common --open

# Just the relay:
cargo doc -p oac-relay --open

# Just the central proxy:
cargo doc -p oac-central --open
```

## What rustdoc covers

Rustdoc generates documentation for all **public** items:

- Structs and their fields
- Enums and their variants
- Functions and their signatures
- Traits and their methods
- Type aliases
- Constants
- Module re-exports

Each item's doc comment (`///`) is rendered as formatted documentation.

## What this book covers (that rustdoc doesn't)

- Architecture and data flow diagrams
- CLI commands and flags
- Configuration TOML reference
- HTTP endpoint reference
- Admin API request/response shapes
- Docker deployment guides
- Security threat model
- Testing strategy
- Conventions and coding standards

## Standard split

This is the standard documentation split used by the Rust project itself:

| Tool | Audience | Covers |
|---|---|---|
| **mdBook** (this book) | Users, contributors, operators | Architecture, usage, CLI, config, deployment, security |
| **rustdoc** (`cargo doc`) | Developers reading the API | Type signatures, doc comments, trait impls |

Both are kept in sync with the codebase. If you change a public API, run
`cargo doc` to verify the docs build cleanly. If you change user-facing
behavior, update the relevant mdBook page.
