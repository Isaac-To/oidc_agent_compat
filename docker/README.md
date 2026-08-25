# Docker Dev Stack

A complete development environment for the OIDC Agent Compatibility Server.
**Everything runs in Docker containers** — no host dependencies beyond Docker
itself. Goose runs headless in a container and connects to the relay via the
Docker network.

## Architecture

```
Goose (Docker) → relay (Docker, :8787) → central (Docker, :8443) → mock-backend (Docker, :8090)
                                       ↑ master key (file, dev only)
                    ↑ OIDC (browser)
              Keycloak (Docker, :8080)
```

## Services

| Service | Container | Port | Description |
|---|---|---|---|
| Keycloak | `keycloak` | `localhost:8080` | OIDC IdP with pre-configured realm `oac-dev` |
| Mock backend | `mock-backend` | `localhost:8090` | OpenAI-compatible Flask server |
| Central proxy | `central` | `localhost:8443` | Holds the master key, forwards to mock-backend |
| Relay | `relay` | `127.0.0.1:8787` | Forwards to central; Goose connects here |
| Goose | `goose` | — | AI agent (headless CLI, connects to relay) |

## Test Users

All users are in the `oac-dev` Keycloak realm:

| Username | Password | Email | Role |
|---|---|---|---|
| `alice` | `alice-pass-123` | alice@example.com | Engineer |
| `bob` | `bob-pass-456` | bob@example.com | Senior |
| `charlie` | `charlie-pass-789` | charlie@example.com | Intern |
| `admin` | `admin-pass-000` | admin@example.com | Admin |

Keycloak admin console: `http://localhost:8080/admin` (admin / admin)

## Quick Start

```sh
# 1. Start everything (generates certs, builds images, starts all containers)
./docker/dev.sh up

# 2. Run a headless Goose prompt through the full chain
./docker/dev.sh goose-run "Hello from Goose!"

# 3. Run infrastructure tests
./docker/dev.sh test

# 4. Open an interactive Goose session
docker compose -f docker/docker-compose.yml run --rm goose session
```

## Commands

| Command | Description |
|---|---|
| `./docker/dev.sh up` | Generate certs, build and start all containers |
| `./docker/dev.sh down` | Stop all containers |
| `./docker/dev.sh status` | Show container status |
| `./docker/dev.sh logs` | Tail logs from all services |
| `./docker/dev.sh shell` | Open a shell in the relay container |
| `./docker/dev.sh goose` | Show Goose usage info |
| `./docker/dev.sh goose-run "prompt"` | Run a headless Goose prompt |
| `./docker/dev.sh test` | Send test requests through the full chain (infra + full chain + SSE) |

## Goose Configuration

Goose runs headless in a container and connects to the relay over the
Docker network at `http://relay:8787`. It uses the built-in `openai`
provider with `GOOSE_MODEL=mock-gpt-4` and `OPENAI_API_KEY=oac_test_key_alice`
(see the `goose` service in `docker/docker-compose.yml`).

The dev API key `oac_test_key_alice` is **auto-minted** by the relay on
startup when `dev_mode=true` (see `crates/relay/src/main.rs`), so Goose
works out of the box without running the OIDC login flow. The same key
works for manual `curl`:

```sh
curl -H 'Authorization: Bearer oac_test_key_alice' http://127.0.0.1:8787/v1/models
```

> Note: the central proxy serves **plain HTTP** on `:8443` in this dev
> stack (mTLS between relay and central is not yet wired). The generated
> certs in `docker/certs/` are unused until mTLS is implemented.

## Manual Operations

### Generate mTLS certs

```sh
./docker/generate-certs.sh
```

### Access Keycloak admin console

Open `http://localhost:8080/admin` and log in with `admin` / `admin`.

### Direct mock-backend access

```sh
curl http://localhost:8090/v1/models
curl -X POST http://localhost:8090/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"mock-gpt-4","messages":[{"role":"user","content":"hello"}]}'
```

### Shell into the relay container

```sh
./docker/dev.sh shell
```

## Files

```
docker/
├── dev.sh                    # Orchestration script
├── docker-compose.yml        # Keycloak + mock-backend + central + relay
├── Dockerfile                # Builds oac-central + oac-relay binaries
├── generate-certs.sh         # Generates mTLS CA + server + client certs
├── configs/
│   ├── central.toml          # Central proxy config (Docker DNS)
│   └── relay.toml            # Relay config (dev_mode=true, Docker DNS)
├── keycloak/
│   └── realm-export.json     # Pre-configured realm with 4 test users
├── mock-backend/
│   ├── Dockerfile            # Python Flask image
│   └── app.py               # OpenAI-compatible mock API
└── certs/                    # Generated certs (gitignored)
```
