#!/bin/bash
# Dev environment orchestration for the OIDC Agent Compatibility Server.
#
# Everything runs in Docker containers. Goose runs on the host and connects
# to the relay at 127.0.0.1:8787.
#
# Usage:
#   ./docker/dev.sh up      — generate certs, start all containers
#   ./docker/dev.sh down    — stop all containers
#   ./docker/dev.sh status  — show status
#   ./docker/dev.sh logs    — tail logs from all services
#   ./docker/dev.sh goose   — configure Goose to use the relay
#   ./docker/dev.sh test    — send test requests through the full chain
#   ./docker/dev.sh shell   — open a shell in the relay container

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"
CERT_DIR="$SCRIPT_DIR/certs"

# ─── Colors ──────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()  { echo -e "${BLUE}ℹ${NC}  $*"; }
ok()    { echo -e "${GREEN}✓${NC}  $*"; }
warn()  { echo -e "${YELLOW}⚠${NC}  $*"; }
err()   { echo -e "${RED}✗${NC}  $*" >&2; }

# ─── Commands ────────────────────────────────────────────────────────────

cmd_up() {
    info "Generating mTLS certificates..."
    if [ -f "$CERT_DIR/ca.crt" ]; then
        ok "Certificates already exist (delete $CERT_DIR to regenerate)"
    else
        bash "$SCRIPT_DIR/generate-certs.sh"
        ok "Certificates generated"
    fi

    info "Building and starting all containers..."
    docker compose -f "$COMPOSE_FILE" up -d --build

    info "Waiting for services to be healthy..."
    wait_for "http://localhost:8080/realms/oac-dev/.well-known/openid-configuration" 60 "Keycloak"
    wait_for "http://localhost:8090/v1/models" 30 "Mock backend"
    wait_for_https "https://localhost:8443/healthz" 30 "Central proxy"
    wait_for "http://127.0.0.1:8787/healthz" 30 "Relay"

    info "Loading master key into the central proxy..."
    docker compose -f "$COMPOSE_FILE" exec -T central \
        sh -c 'echo -n "sk-mock-backend-master-key" > /secrets/master-key && chmod 600 /secrets/master-key'
    ok "Master key loaded"

    # Restart central so it picks up the master key
    docker compose -f "$COMPOSE_FILE" restart central
    sleep 3
    wait_for_https "https://localhost:8443/healthz" 30 "Central proxy (after restart)"

    echo ""
    echo "═══════════════════════════════════════════════════════════════════════"
    ok "Dev stack is up!"
    echo ""
    echo "  Keycloak:        http://localhost:8080  (admin/admin)"
    echo "  Mock backend:   http://localhost:8090"
    echo "  Central proxy:  https://localhost:8443"
    echo "  Relay:           http://127.0.0.1:8787"
    echo ""
    echo "  Test users (Keycloak realm: oac-dev):"
    echo "    alice   / alice-pass-123   (alice@example.com)"
    echo "    bob     / bob-pass-456     (bob@example.com)"
    echo "    charlie / charlie-pass-789  (charlie@example.com)"
    echo "    admin   / admin-pass-000   (admin@example.com)"
    echo ""
    echo "  Next steps:"
    echo "    ./docker/dev.sh goose   — configure Goose"
    echo "    ./docker/dev.sh test    — send a test request"
    echo "═══════════════════════════════════════════════════════════════════════"
}

cmd_down() {
    info "Stopping all containers..."
    docker compose -f "$COMPOSE_FILE" down
    ok "Everything stopped"
}

cmd_status() {
    docker compose -f "$COMPOSE_FILE" ps
}

cmd_logs() {
    docker compose -f "$COMPOSE_FILE" logs -f --tail=50
}

cmd_shell() {
    docker compose -f "$COMPOSE_FILE" exec relay /bin/bash
}

cmd_goose() {
    info "Configuring Goose to use the relay..."

    GOOSE_CONFIG_DIR="$HOME/.config/goose"
    GOOSE_PROVIDERS_DIR="$GOOSE_CONFIG_DIR/custom_providers"
    mkdir -p "$GOOSE_PROVIDERS_DIR"

    cat > "$GOOSE_PROVIDERS_DIR/local_relay.json" << 'EOF'
{
  "name": "local_relay",
  "engine": "openai",
  "display_name": "Local Relay (OAC)",
  "description": "OpenAI-compatible relay at 127.0.0.1:8787 with OIDC auth",
  "api_key_env": "LOCAL_RELAY_API_KEY",
  "base_url": "http://127.0.0.1:8787/v1/chat/completions",
  "models": [
    { "name": "mock-gpt-4", "context_limit": 128000 },
    { "name": "mock-gpt-4o", "context_limit": 128000 }
  ],
  "supports_streaming": true,
  "requires_auth": true
}
EOF
    ok "Goose provider config written to $GOOSE_PROVIDERS_DIR/local_relay.json"

    cat > "$GOOSE_CONFIG_DIR/config.yaml" << 'EOF'
GOOSE_PROVIDER: custom_local_relay
GOOSE_MODEL: mock-gpt-4
EOF
    ok "Goose config written to $GOOSE_CONFIG_DIR/config.yaml"

    echo ""
    warn "You need to set LOCAL_RELAY_API_KEY to a valid relay key."
    echo "  For now, use the test key (the relay accepts any key in dev mode):"
    echo "    export LOCAL_RELAY_API_KEY=\"oac_dev_test_key\""
    echo ""
    echo "  Then start Goose:"
    echo "    goose session"
}

cmd_test() {
    info "Sending test requests through the full chain..."
    info "  Goose → relay (127.0.0.1:8787) → central (8443) → mock-backend (8090)"

    # In dev mode, the relay doesn't have a real OIDC login yet, so we
    # need to mint a key directly. Let's use the relay's DB to insert one.
    # For now, test the relay's healthz and the mock backend directly.

    info "Testing relay healthz..."
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8787/healthz)
    if [ "$HTTP_CODE" = "200" ]; then
        ok "Relay healthz → 200"
    else
        err "Relay healthz → $HTTP_CODE"
        exit 1
    fi

    info "Testing central proxy healthz..."
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -k https://localhost:8443/healthz)
    if [ "$HTTP_CODE" = "200" ]; then
        ok "Central healthz → 200"
    else
        err "Central healthz → $HTTP_CODE"
        exit 1
    fi

    info "Testing mock backend directly..."
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8090/v1/models)
    if [ "$HTTP_CODE" = "200" ]; then
        ok "Mock backend /v1/models → 200"
    else
        err "Mock backend /v1/models → $HTTP_CODE"
        exit 1
    fi

    info "Testing relay rejects unauthenticated request..."
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8787/v1/models)
    if [ "$HTTP_CODE" = "401" ]; then
        ok "Relay /v1/models without key → 401 (correct)"
    else
        err "Relay /v1/models without key → $HTTP_CODE (expected 401)"
        exit 1
    fi

    info "Testing relay rejects invalid key..."
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer oac_invalid" \
        http://127.0.0.1:8787/v1/models)
    if [ "$HTTP_CODE" = "401" ]; then
        ok "Relay /v1/models with invalid key → 401 (correct)"
    else
        err "Relay /v1/models with invalid key → $HTTP_CODE (expected 401)"
        exit 1
    fi

    info "Testing relay rejects non-loopback Host header..."
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Host: evil.example.com" \
        http://127.0.0.1:8787/v1/models)
    if [ "$HTTP_CODE" = "400" ]; then
        ok "Relay with non-loopback Host → 400 (DNS rebinding defense works)"
    else
        err "Relay with non-loopback Host → $HTTP_CODE (expected 400)"
        exit 1
    fi

    echo ""
    ok "All infrastructure tests passed!"
    echo ""
    info "To test the full request chain (agent → relay → central → backend),"
    info "you need a valid API key. Run 'oac-relay login' inside the relay"
    info "container to mint one via OIDC, or insert one directly:"
    echo ""
    echo "  docker compose -f docker/docker-compose.yml exec relay /bin/bash"
    echo "  # Inside the container, use the relay CLI to mint a key"
    echo ""
    info "Then use that key with:"
    echo "  curl -H 'Authorization: Bearer <key>' http://127.0.0.1:8787/v1/models"
}

# ─── Helpers ─────────────────────────────────────────────────────────────

wait_for() {
    local url="$1"
    local timeout="${2:-30}"
    local name="${3:-service}"
    local elapsed=0
    while [ $elapsed -lt $timeout ]; do
        if curl -sf "$url" > /dev/null 2>&1; then
            ok "$name is ready"
            return 0
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done
    err "Timeout waiting for $name at $url"
    exit 1
}

wait_for_https() {
    local url="$1"
    local timeout="${2:-30}"
    local name="${3:-service}"
    local elapsed=0
    while [ $elapsed -lt $timeout ]; do
        if curl -skf "$url" > /dev/null 2>&1; then
            ok "$name is ready"
            return 0
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done
    err "Timeout waiting for $name at $url"
    exit 1
}

# ─── Main ────────────────────────────────────────────────────────────────

case "${1:-}" in
    up)     cmd_up ;;
    down)   cmd_down ;;
    status) cmd_status ;;
    logs)   cmd_logs ;;
    shell)  cmd_shell ;;
    goose)  cmd_goose ;;
    test)   cmd_test ;;
    *)
        echo "Usage: $0 {up|down|status|logs|shell|goose|test}"
        echo ""
        echo "  up      — generate certs, build and start all containers"
        echo "  down    — stop all containers"
        echo "  status  — show container status"
        echo "  logs    — tail logs from all services"
        echo "  shell   — open a shell in the relay container"
        echo "  goose   — configure Goose to use the relay"
        echo "  test    — send test requests through the full chain"
        exit 1
        ;;
esac
