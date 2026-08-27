# Docker: Production

The production deployment ships only the **central proxy** as a Docker
container. The relay runs as a **native binary** on each employee's laptop
(it needs to open a host browser for OIDC login and receive a loopback
callback — neither works reliably from inside a container).

> Before you deploy, run through the
> [Production Hardening Checklist](./production-checklist.md).

## Architecture

```
Agent → 127.0.0.1 relay (native binary, laptop) → mTLS → central (container) → OpenAI-compatible backend
                                                       ↑ encrypted provider keys (central DB)
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

3. **Provider encryption key** as a Docker secret. Provider API keys are
  added after startup through the admin API.
   With Docker Swarm:

   ```sh
  openssl rand -hex 32 | docker secret create oac_provider_encryption_key -
   ```

   Without Swarm, edit `docker/prod/docker-compose.yml` `secrets:` to use
   a `file:` source.

4. **Config**: copy `docker/prod/configs/central.toml` and edit `issuer`
  and TLS settings for your environment. Add providers after startup.

### Deploy

```sh
cd docker/prod
docker compose up -d --build
docker compose logs -f central
```

The central proxy serves mTLS on `:8443` with client cert required. The
provider encryption key is read from `/run/secrets/provider-encryption-key`, never as an env var,
never baked into the image.

### Healthcheck

The production healthcheck uses `pgrep -x oac-central` (process alive
check) because a plain `curl` would fail the TLS handshake (client cert
required).

### Security notes

- `dev_mode = false` in all prod configs. Central enforces mTLS and
  rejects relay requests lacking valid identity headers.
- Provider encryption key read from Docker secret (`/run/secrets/provider-encryption-key`), never
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
# Central does not log in/validate tokens itself — identity comes from the
# relay over mTLS. client_id is not used at runtime; oac-relay is the RP.
client_id = "oac-central"
client_secret_env = "OAC_OIDC_CLIENT_SECRET"
redirect_uri = "http://127.0.0.1:0/callback"
scopes = ["openid"]

[mtls]
ca_cert_path = "/certs/ca.crt"
server_cert_path = "/certs/server.crt"
server_key_path = "/certs/server.key"

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
# "groups" is REQUIRED for group-based policy enforcement and admin access.
scopes = ["openid", "email", "profile", "groups"]

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

## Provider-key encryption

Providers and their API keys are managed at runtime through the admin API.
Provider API keys are encrypted at rest in the central database with
AES-256-GCM. Supply the 64-hex-character encryption key through the Docker
secret `provider-encryption-key` (mounted at
`/run/secrets/provider-encryption-key`) or through
`OAC_PROVIDER_ENCRYPTION_KEY`. Back up this encryption key securely: losing it
makes stored provider keys unrecoverable.

The relay never receives provider-key material. See [Configuration](configuration.md)
and [Admin API](admin-api.md) for provider and key management.

## Production security checklist

Before going live, verify every item on this checklist:

### Certificates

- [ ] **Use your company PKI** — not the self-signed test certs from
  `./docker/generate-certs.sh` (CN=`OAC Test CA`). Those are for dev only.
- [ ] Server cert CN/SAN matches the central proxy's hostname.
- [ ] Client certs are uniquely issued per relay (not shared across
  employees if individual revocation is needed).
- [ ] Private key files have `0600` permissions.
- [ ] Certs are distributed via your internal PKI, not email or git.

### Configuration

- [ ] `dev_mode = false` in both central and relay configs.
- [ ] Relay `listen_addr` is `127.0.0.1` (loopback only).
- [ ] Central `url` in relay config is `https://` (mTLS enforced).
- [ ] OIDC `issuer` points to your real enterprise IdP (not a dev
  Keycloak).
- [ ] `client_secret_env` references an env var, never a literal secret.
- [ ] `[admin]` section's `admin_group` matches a real group in your IdP.

### Secrets

- [ ] Master backend key stored as a Docker secret (not an env var, not
  baked into the image).
- [ ] OIDC client secret provided via `.env` file or orchestrator secret
  mechanism.
- [ ] `.env` file is in `.gitignore` (it is by default).
- [ ] No secrets appear in config files, Dockerfiles, or git history.

### Network

- [ ] Central proxy port `8443` is accessible only from the corporate
  network or VPN (not the public internet).
- [ ] Firewall rules restrict `8443` to known relay IP ranges where
  possible.
- [ ] The central proxy is behind a reverse proxy or load balancer if
  you need TLS termination, healthcheck routing, or DDoS protection.

### Runtime

- [ ] Central container runs as non-root user (`oac`) — the Dockerfile
  enforces this.
- [ ] Config and certs mounted read-only.
- [ ] Container has resource limits set (memory, CPU) via Docker or your
  orchestrator.
- [ ] Log rotation configured (the compose file sets `max-size: 10m`,
  `max-file: 3`).
- [ ] `RUST_LOG` is `info` or lower (not `debug` in production — debug
  may log sensitive request details).

### OIDC / IdP

- [ ] Your IdP enforces MFA for users who can log in via the relay.
- [ ] The OIDC client is **confidential** (not public), with a real
  client secret.
- [ ] Redirect URIs in the IdP are restricted to `http://127.0.0.1:*`
  (loopback, any port — per RFC 8252).
- [ ] The `groups` scope is configured if you use group-based
  authorization.
- [ ] Users who should not have access are removed from the IdP client's
  allowed groups.

### Audit & monitoring

- [ ] The audit log is monitored for anomalous activity (unexpected 403s,
  unusual request volumes, off-hours access).
- [ ] Admin API mutations are reviewed periodically (via
  `admin_audit_log`).
- [ ] Device revocation is tested — a revoked relay cannot make requests.
