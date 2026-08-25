# Production Deployment

This directory contains the **production** containerization for the OIDC
Agent Compatibility Server. It is separate from the [dev stack](../README.md)
(Keycloak, mock-backend, Goose) which is for local testing only.

## Architecture (production)

```
Agent → 127.0.0.1 relay (native binary, laptop) → mTLS → central (container) → OpenAI-compatible backend
                                                       ↑ master key (secret)
```

Two deployment targets, two different shapes:

| Component | Where it runs | How it's deployed |
|---|---|---|
| **Central proxy** | Company-hosted server | Container (`Dockerfile.central` + `docker-compose.yml`) |
| **Relay** | Each employee's laptop | **Native binary** (not containerized) |

The relay runs as a native binary on the laptop because it needs to open a
host browser for the OIDC login flow and receive a loopback callback
(RFC 8252) — neither of which works reliably from inside a container.

## Central proxy — containerized deployment

### Prerequisites

1. **mTLS certs** under `docker/prod/certs/`:
   ```sh
   ./docker/generate-certs.sh
   # then copy ca.crt, server.crt, server.key into docker/prod/certs/
   ```
   Distribute `ca.crt` and `client.crt`/`client.key` to laptops for the relay.

2. **OIDC client secret** — provide via env var or an `.env` file next to
   the compose file:
   ```sh
   echo "OAC_OIDC_CLIENT_SECRET=your-secret" > docker/prod/.env
   ```

3. **Master backend key** — as a Docker secret (preferred) or a mounted file.
   With Docker Swarm:
   ```sh
   echo -n 'sk-...' | docker secret create oac_master_key -
   ```
   Without Swarm, edit `docker/prod/docker-compose.yml` `secrets:` to use a
   `file:` source instead of `external: true`.

4. **Config** — copy `configs/central.toml` and edit `issuer`, `backend.base_url`.

### Deploy

```sh
cd docker/prod
docker compose up -d --build
docker compose logs -f central
```

The central proxy serves mTLS on `:8443` with client cert required. Relays
connect with their client cert; the master key never leaves this container.

## Relay — native laptop install

The relay is **not** containerized for laptop deployment. Install the
native binary via your internal package registry, or extract it from the
central image:

```sh
# Build the relay binary from source (ship the resulting binary via your
# internal package registry — Homebrew tap, deb/rpm repo, etc.):
cargo build --release -p oac-relay
# → target/release/oac-relay
```

### Laptop setup

```sh
# 1. Install the binary (assumed on PATH as oac-relay).
# 2. Copy the reference config and edit for your IdP + central proxy:
cp docker/prod/configs/relay.toml ~/.oac/relay.toml
# 3. Place mTLS client certs (from your admin):
mkdir -p ~/.oac/certs
cp ca.crt client.crt client.key ~/.oac/certs/
# 4. Set the OIDC client secret (provided by your admin):
export OAC_OIDC_CLIENT_SECRET="your-secret"

# 5. Log in (opens a browser, runs the auth-code + PKCE flow):
oac-relay --config ~/.oac/relay.toml login
#    → signs in via your IdP, validates the ID token, mints a local API key,
#      and writes it to ~/.oac/agent-env.sh

# 6. Source the agent env and start the relay:
source ~/.oac/agent-env.sh
oac-relay --config ~/.oac/relay.toml serve
```

The agent (Codex, Goose, etc.) points at `http://127.0.0.1:8787` with the
minted API key. The relay forwards over mTLS to the central proxy.

## Files

```
docker/prod/
├── Dockerfile.central        # Slim single-binary image for oac-central
├── docker-compose.yml        # Central-only prod deployment
├── configs/
│   ├── central.toml          # Central proxy prod config (edit + deploy)
│   └── relay.toml            # Relay prod config reference (for laptops)
└── README.md                 # This file
```

## Security notes

- `dev_mode = false` in all prod configs. The central enforces mTLS and
  rejects relay requests lacking valid identity headers.
- The master key is read from a Docker secret (`/run/secrets/master-key`),
  never an env var, never baked into the image, never sent to a laptop.
- The relay binds `127.0.0.1` only; the config validator rejects
  `0.0.0.0` unless `dev_mode=true`.
- The central image runs as a non-root user; config and certs are mounted
  read-only.
- For real secret-manager backends (Vault/AWS/GCP/Azure), see the
  "Out of scope" section of `AGENTS.md` — only `kind = "file"` is currently
  implemented.
