# Docker: Dev Stack

The dev stack runs the entire system in Docker: Keycloak (IdP), mock
backend, central proxy, relay, and Goose (AI agent). It's the fastest way
to get a working end-to-end setup.

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

## Test users

All users are in the `oac-dev` Keycloak realm:

| Username | Password | Email | Role |
|---|---|---|---|
| `alice` | `alice-pass-123` | alice@example.com | Engineer |
| `bob` | `bob-pass-456` | bob@example.com | Senior |
| `charlie` | `charlie-pass-789` | charlie@example.com | Intern |
| `admin` | `admin-pass-000` | admin@example.com | Admin |

Keycloak admin console: `http://localhost:8080/admin` (admin / admin).

## Commands

The `docker/dev.sh` script orchestrates the dev stack:

| Command | Description |
|---|---|
| `./docker/dev.sh up` | Generate certs (if missing), build and start all containers, wait for healthchecks, load master key, restart central, print service URLs + test users |
| `./docker/dev.sh down` | Stop all containers |
| `./docker/dev.sh status` | Show container status |
| `./docker/dev.sh logs` | Tail logs from all services |
| `./docker/dev.sh shell` | Open a shell in the relay container |
| `./docker/dev.sh goose` | Show Goose usage info |
| `./docker/dev.sh goose-run "prompt"` | Run a headless Goose prompt through the full chain |
| `./docker/dev.sh test` | Send test requests through the full chain (infra + full chain + SSE + master-key-leak check) |

## Quick start

```sh
# Start everything:
./docker/dev.sh up

# Run a Goose prompt:
./docker/dev.sh goose-run "Hello from Goose!"

# Run the test suite:
./docker/dev.sh test

# Interactive Goose session:
docker compose -f docker/dev/docker-compose.yml run --rm goose session
```

## Manual requests

The relay auto-mints a dev key `oac_test_key_alice` when `dev_mode = true`.
Use it for manual curl:

```sh
# List models:
curl -H 'Authorization: Bearer oac_test_key_alice' \
  http://127.0.0.1:8787/v1/models

# Chat completion (non-streaming):
curl -X POST http://127.0.0.1:8787/v1/chat/completions \
  -H 'Authorization: Bearer oac_test_key_alice' \
  -H 'Content-Type: application/json' \
  -d '{"model":"mock-gpt-4","messages":[{"role":"user","content":"hello"}]}'

# Chat completion (SSE streaming):
curl -X POST http://127.0.0.1:8787/v1/chat/completions \
  -H 'Authorization: Bearer oac_test_key_alice' \
  -H 'Content-Type: application/json' \
  -d '{"model":"mock-gpt-4","messages":[{"role":"user","content":"hello"}],"stream":true}'
```

## Direct mock-backend access

```sh
curl http://localhost:8090/v1/models
curl -X POST http://localhost:8090/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"mock-gpt-4","messages":[{"role":"user","content":"hello"}]}'
```

## OIDC login (real auth flow)

The containerized relay can't open a host browser or receive a loopback
callback, so to test the real OIDC login flow, run the relay binary **on
the host** against the dev Keycloak:

```sh
# Build the relay:
cargo build --release -p oac-relay

# Run login:
OAC_OIDC_CLIENT_SECRET="oac-relay-secret" \
  ./target/release/oac-relay \
    --config docker/dev/configs/relay-login-test.toml login
```

A browser opens to the Keycloak login page. Sign in as a test user. The
relay validates the ID token, mints a local key, and injects it into
`~/.oac/agent-env.sh`.

The login-test config uses `dev_mode = true`, a separate SQLite DB
(`/tmp/oac-relay-login-test.db`), and listens on `127.0.0.1:8788` to
avoid port conflicts with the Docker relay on `:8787`.

## Admin API

The dev central config enables the admin API with
`admin_group = "oac-admins"`. Log in via the relay with a user in the
`oac-admins` group, then use the admin CLI:

```sh
export OAC_API_KEY="<key from oac-relay login>"
./target/release/oac-central admin policy-list --key $OAC_API_KEY
./target/release/oac-central admin policy-set engineering --models gpt-4o --key $OAC_API_KEY
./target/release/oac-central admin audit-query --key $OAC_API_KEY
```

See [Admin API](./admin-api.md) for all endpoints.

## `dev.sh test` scenarios

The test command verifies:

1. Relay healthz → 200.
2. Central healthz → 200.
3. Mock backend `/v1/models` → 200.
4. Relay `/v1/models` without key → 401.
5. Relay `/v1/models` with invalid key → 401.
6. Relay with non-loopback Host header → 400 (DNS rebinding defense).
7. Full chain `GET /v1/models` with dev key → 200, contains `mock-gpt-4`.
8. Full chain `POST /v1/chat/completions` (non-streaming) → 200, contains
   `Mock response to: hello`.
9. Full chain `POST /v1/chat/completions` (SSE streaming) →
   `content-type: text/event-stream` and `data: [DONE]` terminator.
10. Master key leak check: relay response must NOT contain
    `sk-mock-backend-master-key`.

## Files

```
docker/
├── dev.sh                    # Orchestration script
├── generate-certs.sh         # Generates mTLS CA + server + client certs
├── certs/                    # Generated certs (gitignored)
└── dev/
    ├── docker-compose.yml     # Keycloak + mock-backend + central + relay + goose
    ├── Dockerfile             # Builds oac-central + oac-relay binaries
    ├── configs/
    │   ├── central.toml
    │   ├── relay.toml
    │   └── relay-login-test.toml
    ├── keycloak/
    │   └── realm-export.json  # Pre-configured realm with 4 test users
    ├── mock-backend/
    │   ├── Dockerfile         # Python Flask image
    │   └── app.py            # OpenAI-compatible mock API
    └── workspace/             # Goose working directory
```
