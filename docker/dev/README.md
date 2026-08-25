# Docker Dev Stack

> **Full documentation:** [Docker: Dev Stack](../../docs/src/user-guide/docker-dev.md)

A complete development environment for the OIDC Agent Compatibility Server.
Everything runs in Docker containers — no host dependencies beyond Docker
itself.

## Quick reference

| Service | Container | Port | Description |
|---|---|---|---|
| Keycloak | `keycloak` | `localhost:8080` | OIDC IdP (realm `oac-dev`) |
| Mock backend | `mock-backend` | `localhost:8090` | OpenAI-compatible Flask server |
| Central proxy | `central` | `localhost:8443` | Holds the master key |
| Relay | `relay` | `127.0.0.1:8787` | Forwards to central |
| Goose | `goose` | — | AI agent (headless) |

```sh
./docker/dev.sh up       # Start all containers
./docker/dev.sh test     # Run full-chain tests
./docker/dev.sh goose-run "Hello!"  # Run Goose
./docker/dev.sh down     # Stop
```

Test users: `alice`/`alice-pass-123`, `bob`/`bob-pass-456`,
`charlie`/`charlie-pass-789`, `admin`/`admin-pass-000`.

See the [full guide](../../docs/src/user-guide/docker-dev.md) for all
commands, OIDC login testing, admin API, and troubleshooting.
