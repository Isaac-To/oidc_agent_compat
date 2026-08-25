# Docker: Production

The production deployment ships only the **central proxy** as a Docker
container. The relay runs as a **native binary** on each employee's laptop
(it needs to open a host browser for OIDC login and receive a loopback
callback — neither works reliably from inside a container).

## Architecture

```
Agent → 127.0.0.1 relay (native binary, laptop) → mTLS → central (container) → OpenAI-compatible backend
                                                       ↑ master key (secret)
```

| Component | Where it runs | How it's deployed |
|---|---|---|
| **Central proxy** | Company-hosted server | Container (`Dockerfile.central` + `docker-compose.yml`) |
| **Relay** | Each employee's laptop | Native binary (not containerized) |

## Central proxy deployment

### Prerequisites

1. **mTLS certificates** under `docker/prod/certs/`:

   ```sh
   ./docker/generate-certs.sh
   cp docker/certs/{ca,server,client}.{crt,key} docker/prod/certs/
   ```

   Distribute `ca.crt`, `client.crt`, and `client.key` to each employee
   laptop for the relay config.

2. **OIDC client secret** via env var or `.env` file:

   ```sh
   echo "OAC_OIDC_CLIENT_SECRET=your-secret" > docker/prod/.env
   ```

3. **Master backend key** as a Docker secret (preferred) or mounted file.
   With Docker Swarm:

   ```sh
   echo -n 'sk-...' | docker secret create oac_master_key -
   ```

   Without Swarm, edit `docker/prod/docker-compose.yml` `secrets:` to use
   a `file:` source.

4. **Config**: copy `docker/prod/configs/central.toml` and edit `issuer`
   and `backend.base_url` for your environment.

### Deploy

```sh
cd docker/prod
docker compose up -d --build
docker compose logs -f central
```

The central proxy serves mTLS on `:8443` with client cert required. The
master key is read from `/run/secrets/master-key`, never as an env var,
never baked into the image.

### Healthcheck

The production healthcheck uses `pgrep -x oac-central` (process alive
check) because a plain `curl` would fail the TLS handshake (client cert
required).

### Security notes

- `dev_mode = false` in all prod configs. Central enforces mTLS and
  rejects relay requests lacking valid identity headers.
- Master key read from Docker secret (`/run/secrets/master-key`), never
  env var, never baked into image, never sent to laptop.
- Central image runs as non-root user (`oac`).
- Config and certs mounted read-only.
- Dockerfile runtime base is `debian:trixie-slim` (must match the
  `rust:1.98-slim` builder's glibc 2.41 — do NOT switch to
  `bookworm-slim`).

### Production central config

```toml
listen_addr = "0.0.0.0:8443"
database_url = "sqlite:///data/central.db"
dev_mode = false

[oidc]
issuer = "https://idp.example.com/realms/your-realm"
client_id = "oac-relay"
client_secret_env = "OAC_OIDC_CLIENT_SECRET"
redirect_uri = "http://127.0.0.1:0/callback"
scopes = ["openid", "email", "profile"]

[backend]
name = "openai"
base_url = "https://api.openai.com"

[mtls]
ca_cert_path = "/certs/ca.crt"
server_cert_path = "/certs/server.crt"
server_key_path = "/certs/server.key"

[secret_store]
kind = "file"
path = "/run/secrets/master-key"

[admin]
admin_group = "oac-admins"
```

---

## Relay — native laptop install

### Build

```sh
cargo build --release -p oac-relay
# → target/release/oac-relay
```

### Install

```sh
# Copy the binary:
cp target/release/oac-relay /usr/local/bin/oac-relay

# Copy the config:
mkdir -p ~/.oac
cp docker/prod/configs/relay.toml ~/.oac/relay.toml

# Copy the mTLS certs:
mkdir -p ~/.oac/certs
cp ca.crt ~/.oac/certs/
cp client.crt ~/.oac/certs/
cp client.key ~/.oac/certs/
chmod 600 ~/.oac/certs/client.key
```

### Production relay config

```toml
listen_addr = "127.0.0.1:8787"
database_url = "sqlite:///data/relay.db"
dev_mode = false

[oidc]
issuer = "https://idp.example.com/realms/your-realm"
client_id = "oac-relay"
client_secret_env = "OAC_OIDC_CLIENT_SECRET"
redirect_uri = "http://127.0.0.1:0/callback"
scopes = ["openid", "email", "profile"]

[central]
url = "https://central.example.com:8443"
ca_cert_path = "/etc/oac/ca.crt"
client_cert_path = "/etc/oac/client.crt"
client_key_path = "/etc/oac/client.key"
```

### Run

```sh
# Set the OIDC client secret:
export OAC_OIDC_CLIENT_SECRET="your-secret"

# Log in (opens browser, mints key, injects into agent config):
oac-relay --config ~/.oac/relay.toml login

# Source the agent config (if using generic env format):
source ~/.oac/agent-env.sh

# Start the relay server:
oac-relay --config ~/.oac/relay.toml serve
```

The agent points at `http://127.0.0.1:8787` with the minted API key. The
relay forwards over mTLS to the central proxy.

## Secret store backends

Only `kind = "file"` is implemented. For production with a managed secret
store (Vault, AWS Secrets Manager, GCP Secret Manager, Azure Key Vault),
the `SecretStore` trait is extensible but those backends are not yet built.
See [Developer Guide: Conventions](../developer-guide/conventions.md) for
the trait design.
