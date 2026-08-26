# About This Book

Welcome to the documentation for the **OIDC Agent Compatibility Server** —
an enterprise-grade OIDC-to-AI-agent forwarder that lets employees use any
OpenAI-compatible AI agent (Codex, Goose, etc.) through company-approved
backends **without the master backend key ever touching an employee's
laptop**.

## How to use this book

This book has three top-level sections. Pick the one that matches your role:

| Section | Audience | What you'll find |
|---|---|---|
| **[User Guide](./user-guide/README.md)** | Employees, admins, operators | Setup, configuration, CLI commands, Docker deployment, troubleshooting |
| **[Developer Guide](./developer-guide/README.md)** | Contributors, maintainers | Architecture, internals, conventions, testing, how to contribute |
| **[Reference](./reference/architecture.md)** | Everyone | System diagrams, threat model, request data flow, API docs pointer |

**New here?** Start with the [Quickstart](./user-guide/quickstart.md) for a
production deployment walkthrough, or try the bundled dev stack via
[Docker: Dev Stack](./user-guide/docker-dev.md).

## Architecture at a glance

```
Agent → [127.0.0.1 relay] → mTLS → [central proxy] → [OpenAI-compatible backend]
                                   ↑ encrypted provider keys (central DB)
```

- **Central proxy** (company-hosted) — manages encrypted provider keys,
  authenticates employees via OIDC, enforces policy and quotas, and forwards
  approved requests to the AI backend with SSE streaming.
- **Laptop relay** (thin, per-employee) — listens on `127.0.0.1`,
  authenticates the employee via OIDC, relays agent traffic to the central
  proxy over mTLS. Holds **no master key**.

## Status

🚧 **Under development.** This documentation covers the implemented
features. OIDC refresh tokens are intentionally not stored; local relay
sessions expire after 24 hours by default and require re-login. External KMS
backends for the provider encryption key and distributed Redis rate limiting
remain deployment-specific future work.

## API type reference

For full Rust type signatures (structs, enums, functions, traits), run:

```sh
cargo doc --workspace --open
```

This book documents architecture, usage, CLI, and configuration. Rustdoc
documents the type-level API. This is the standard split used by the Rust
project itself.
