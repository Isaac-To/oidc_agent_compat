# Docker Dev Stack

A complete development environment for the OIDC Agent Compatibility Server,
using open-source components. This is the primary development environment.

## Architecture

```
Goose (host) → relay (host, 127.0.0.1:8787) → mTLS → central (Docker, :8443) → mock-backend (Docker, :8090)
                                                   ↑ master key (file, dev only)
                    ↑ OIDC (browser)
              Keycloak (Docker, :8080)
```

## Services

| Service | Port | Description |
|---|---|---|
| Keycloak | `http://localhost:8080` | OIDC IdP with pre-configured realm `oac-dev` |
| Mock backend | `http://localhost:8090` | OpenAI-compatible Flask server returning fixed responses |
| Central proxy | `https://localhost:8443` | Holds the master key, forwards to mock-backend |
| Relay | `http://127.0.0.1:8787` | Runs on the host; Goose connects here |

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
# 1. Start everything (generates certs, builds Docker images, starts relay)
./docker/dev.sh up

# 2. Authenticate via OIDC (opens browser — log in as alice/alice-pass-123)
./docker/dev.sh login

# 3. Configure Goose to use the relay
./docker/dev.sh goose

# 4. Set the API key from the login output
export LOCAL_RELAY_API_KEY="<key from step 2>"

# 5. Run a test request through the full chain
./docker/dev.sh test

# 6. Start Goose
goose session
```

## Commands

| Command | Description |
|---|---|
| `./docker/dev.sh up` | Generate certs, start Docker stack, build + start relay |
| `./docker/dev.sh down` | Stop everything |
| `./docker/dev.sh status` | Show status of all services |
| `./docker/dev.sh login` | Run OIDC login (opens browser) |
| `./docker/dev.sh goose` | Configure Goose to use the relay |
| `./docker/dev.sh test` | Send test requests through the full chain |

## Goose Configuration

`./docker/dev.sh goose` creates a custom provider at
`~/.config/goose/custom_providers/local_relay.json` that points Goose at
`http://127.0.0.1:8787/v1/chat/completions`. The API key is read from the
`LOCAL_RELAY_API_KEY` environment variable (set it to the key printed by
`./docker/dev.sh login`).

## Manual Operations

### Generate mTLS certs

```sh
./docker/generate-certs.sh
```

Certificates are written to `docker/certs/` (gitignored). Keys have `0600`
permissions.

### Access Keycloak admin console

Open `http://localhost:8080/admin` and log in with `admin` / `admin`.

### Direct mock-backend access

```sh
curl http://localhost:8090/v1/models
curl -X POST http://localhost:8090/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"mock-gpt-4","messages":[{"role":"user","content":"hello"}]}'
```

### Direct central proxy access (with mTLS client cert)

```sh
curl -k --cert docker/certs/client.crt --key docker/certs/client.key \
  https://localhost:8443/healthz
```

## Files

```
docker/
├── dev.sh                    # Orchestration script (up/down/status/login/goose/test)
├── docker-compose.yml        # Keycloak + mock-backend + central proxy
├── Dockerfile                # Builds oac-central + oac-relay binaries
├── generate-certs.sh         # Generates mTLS CA + server + client certs
├── configs/
│   ├── central.toml          # Central proxy config (points at Keycloak + mock-backend)
│   └── relay.toml            # Relay config (points at Keycloak + central proxy)
├── keycloak/
│   └── realm-export.json     # Pre-configured realm with 4 test users
├── mock-backend/
│   ├── Dockerfile            # Python Flask image
│   └── app.py               # OpenAI-compatible mock API
└── certs/                    # Generated certs (gitignored)
```
