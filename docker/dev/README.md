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
docker compose -f docker/dev/docker-compose.yml run --rm goose session
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
(see the `goose` service in `docker/dev/docker-compose.yml`).

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

## OIDC Login (real auth flow)

The relay implements the full OIDC authorization-code + PKCE flow
(`oac-relay login`). In the dev stack, the relay runs in Docker where it
can't open a host browser or receive a loopback callback, so to test the
real login flow, run the relay binary **on the host** against the dev
Keycloak:

```sh
# 1. Build the release binary and start the dev stack (for Keycloak + central):
cargo build --release -p oac-relay
./docker/dev.sh up

# 2. Run the login flow on the host (uses docker/dev/configs/relay-login-test.toml):
OAC_OIDC_CLIENT_SECRET="oac-relay-secret" \
  ./target/release/oac-relay --config docker/dev/configs/relay-login-test.toml login

# 3. A browser opens to the Keycloak login page. Sign in as one of the test
#    users (e.g. alice / alice-pass-123). The relay validates the ID token
#    (alg pin RS256/ES256, iss, aud, exp, nonce, signature), fetches userinfo,
#    mints a local API key, and injects it into ~/.oac/agent-env.sh.

# 4. Source the config and use the minted key:
source ~/.oac/agent-env.sh
curl -H "Authorization: Bearer $OPENAI_API_KEY" http://127.0.0.1:8788/v1/models
```

The login test config (`docker/dev/configs/relay-login-test.toml`) uses
`dev_mode = true` (to allow the HTTP central URL) and a separate SQLite
DB (`/tmp/oac-relay-login-test.db`) so it doesn't conflict with the
containerized relay. It listens on `127.0.0.1:8788` to avoid port
conflicts with the Docker relay on `:8787`.

## Manual Operations

### Admin API (policies, devices, audit)

The dev central config (`docker/dev/configs/central.toml`) enables the admin
API with `admin_group = "oac-admins"`. To test it, log in via the relay
with a user in the `oac-admins` group (configure the group in Keycloak),
then use the admin CLI:

```sh
# Set the admin API key (from oac-relay login):
export OAC_API_KEY="<key from oac-relay login>"

# List group policies:
./target/release/oac-central admin policy-list --key $OAC_API_KEY

# Set a policy:
./target/release/oac-central admin policy-set engineering --models gpt-4o --key $OAC_API_KEY

# Query the audit log:
./target/release/oac-central admin audit-query --key $OAC_API_KEY
```

> Note: the admin CLI sends requests through the relay (default
> `http://127.0.0.1:8787`), which authenticates the user via OIDC and
> forwards to central. The user must belong to the `oac-admins` group.

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
├── generate-certs.sh         # Generates mTLS CA + server + client certs
├── certs/                    # Generated certs (gitignored, shared with prod)
└── dev/
    ├── docker-compose.yml    # Keycloak + mock-backend + central + relay
    ├── Dockerfile            # Builds oac-central + oac-relay binaries
    ├── configs/
    │   ├── central.toml      # Central proxy config (Docker DNS)
    │   ├── relay.toml        # Relay config (dev_mode=true, Docker DNS)
    │   └── relay-login-test.toml
    ├── keycloak/
    │   └── realm-export.json # Pre-configured realm with 4 test users
    ├── mock-backend/
    │   ├── Dockerfile        # Python Flask image
    │   └── app.py           # OpenAI-compatible mock API
    └── workspace/            # Goose working directory
```
