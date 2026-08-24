# Docker Dev Stack

A complete development environment for the OIDC Agent Compatibility Server.
**Everything runs in Docker containers** — no host dependencies beyond Docker
itself. Goose runs on the host (it's a desktop app) and connects to the relay
at `127.0.0.1:8787`.

## Architecture

```
Goose (host) → relay (Docker, 127.0.0.1:8787) → central (Docker, :8443) → mock-backend (Docker, :8090)
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

# 2. Configure Goose to use the relay
./docker/dev.sh goose

# 3. Set the API key (dev test key for now)
export LOCAL_RELAY_API_KEY="oac_dev_test_key"

# 4. Run infrastructure tests
./docker/dev.sh test

# 5. Start Goose
goose session
```

## Commands

| Command | Description |
|---|---|
| `./docker/dev.sh up` | Generate certs, build and start all containers |
| `./docker/dev.sh down` | Stop all containers |
| `./docker/dev.sh status` | Show container status |
| `./docker/dev.sh logs` | Tail logs from all services |
| `./docker/dev.sh shell` | Open a shell in the relay container |
| `./docker/dev.sh goose` | Configure Goose to use the relay |
| `./docker/dev.sh test` | Send test requests through the full chain |

## Goose Configuration

`./docker/dev.sh goose` creates a custom provider at
`~/.config/goose/custom_providers/local_relay.json` that points Goose at
`http://127.0.0.1:8787/v1/chat/completions`. The API key is read from the
`LOCAL_RELAY_API_KEY` environment variable.

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
