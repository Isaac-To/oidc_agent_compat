# Quickstart

This guide walks you through a complete end-to-end run using the bundled
Docker dev stack (Keycloak + mock backend + central + relay + Goose). It
takes about 5 minutes once Docker is running.

## Prerequisites

- **Docker** and **Docker Compose** installed.
- **Rust 1.85+** (stable) — for building the relay binary on the host for
  the OIDC login test. Install via [rustup](https://rustup.rs/).
- **curl** — for the test requests.

## Step 1: Start the dev stack

From the repository root:

```sh
./docker/dev.sh up
```

This will:

1. Generate mTLS certificates (if not already present).
2. Build and start all containers: Keycloak (IdP), mock backend, central
   proxy, relay, and Goose.
3. Wait for all healthchecks to pass.
4. Load the mock master key into the central proxy.
5. Print service URLs and test user credentials.

You should see output ending with:

```
✓ All services are healthy.

Services:
  Keycloak:     http://localhost:8080  (admin / admin)
  Mock backend: http://localhost:8090
  Central:      http://localhost:8443
  Relay:        http://127.0.0.1:8787

Test users (realm: oac-dev):
  alice   / alice-pass-123
  bob     / bob-pass-456
  charlie / charlie-pass-789
  admin   / admin-pass-000
```

## Step 2: Verify the full chain

Run the built-in test suite:

```sh
./docker/dev.sh test
```

This exercises the full chain — healthchecks, auth rejection, DNS
rebinding defense, model listing, chat completions (non-streaming and
SSE), and a master-key-leak check. All tests should pass.

## Step 3: Make a manual request

The relay auto-mints a dev key `oac_test_key_alice` when `dev_mode = true`.
Use it to make a request through the full chain:

```sh
# List models (relay → central → mock backend):
curl -H 'Authorization: Bearer oac_test_key_alice' \
  http://127.0.0.1:8787/v1/models

# Chat completion (non-streaming):
curl -X POST http://127.0.0.1:8787/v1/chat/completions \
  -H 'Authorization: Bearer oac_test_key_alice' \
  -H 'Content-Type: application/json' \
  -d '{"model":"mock-gpt-4","messages":[{"role":"user","content":"hello"}]}'
```

## Step 4: Run Goose through the chain

Goose is pre-configured to talk to the relay. Run a headless prompt:

```sh
./docker/dev.sh goose-run "Hello from Goose!"
```

Goose → relay (`relay:8787`) → central (`:8443`) → mock backend. You should
see a mock response.

## Step 5: Test the real OIDC login flow (optional)

The containerized relay can't open a host browser or receive a loopback
callback, so to test the real OIDC login flow, run the relay binary **on
the host** against the dev Keycloak:

```sh
# Build the relay binary:
cargo build --release -p oac-relay

# Run login against dev Keycloak:
OAC_OIDC_CLIENT_SECRET="oac-relay-secret" \
  ./target/release/oac-relay \
    --config docker/dev/configs/relay-login-test.toml login
```

A browser window opens to the Keycloak login page. Sign in as
`alice` / `alice-pass-123`. The relay validates the ID token (alg pin
RS256/ES256, iss, aud, exp, nonce, signature), fetches userinfo, mints a
local API key, and injects it into `~/.oac/agent-env.sh`.

## Next steps

- [Relay Setup](./relay-setup.md) — full relay lifecycle and commands.
- [Central Proxy Setup](./central-setup.md) — central proxy lifecycle.
- [Configuration Reference](./configuration.md) — all TOML fields.
- [Docker: Dev Stack](./docker-dev.md) — dev stack in depth.
