# Docker

This directory holds both the **development** and **production** Docker
setups for the OIDC Agent Compatibility Server. They are kept separate so
each can evolve for its own purpose.

| Directory | Purpose | What's in it |
|---|---|---|
| [`dev/`](dev/README.md) | Local development & testing stack | Keycloak (test IdP), mock backend, central, relay, Goose — all containerized |
| [`prod/`](prod/README.md) | Production deployment | Only our own server (central proxy); you bring your own IdP and backend |

Shared between the two:

- [`dev.sh`](dev.sh) — orchestration script for the dev stack
- [`generate-certs.sh`](generate-certs.sh) — generates mTLS CA + server + client certs into `certs/`
- [`certs/`](certs/) — generated certs (gitignored), used by both stacks

## Quick start

```sh
# Dev stack (Keycloak + mock backend + central + relay + Goose):
./docker/dev.sh up

# Production (central proxy only — see prod/README.md for prerequisites):
docker compose -f docker/prod/docker-compose.yml up -d --build
```

See [`dev/README.md`](dev/README.md) and [`prod/README.md`](prod/README.md)
for details.
