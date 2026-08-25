# Production Deployment

> **Full documentation:** [Docker: Production](../../docs/src/user-guide/docker-prod.md)

Production containerization for the OIDC Agent Compatibility Server. Ships
only the **central proxy** as a container — the relay runs as a native
binary on each employee's laptop.

## Quick reference

| Component | Where it runs | How it's deployed |
|---|---|---|
| **Central proxy** | Company-hosted server | Container (`Dockerfile.central` + `docker-compose.yml`) |
| **Relay** | Each employee's laptop | Native binary (not containerized) |

```sh
cd docker/prod
docker compose up -d --build
docker compose logs -f central
```

### Prerequisites

1. mTLS certs under `docker/prod/certs/` (`./docker/generate-certs.sh`).
2. OIDC client secret: `echo "OAC_OIDC_CLIENT_SECRET=..." > docker/prod/.env`.
3. Master key as Docker secret: `echo -n 'sk-...' | docker secret create oac_master_key -`.
4. Config: edit `docker/prod/configs/central.toml`.

See the [full guide](../../docs/src/user-guide/docker-prod.md) for relay
laptop install, cert distribution, and security notes.
