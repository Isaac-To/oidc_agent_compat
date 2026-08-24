#!/bin/bash
# Dev environment orchestration for the OIDC Agent Compatibility Server.
#
# Usage:
#   ./docker/dev.sh up       — generate certs, start Docker stack, start relay
#   ./docker/dev.sh down      — stop everything
#   ./docker/shell dev.sh status — show status of all services
#   ./docker/dev.sh goose     — configure Goose to use the relay
#   ./docker/dev.sh login     — run oac-relay login (OIDC browser flow)
#   ./docker/dev.sh test      — run a test request through the full chain
#
# Prerequisites:
#   - Docker + Docker Compose
#   - Rust toolchain (for building the relay on the host)
#   - Goose (brew install --cask block-goose) — optional, for goose subcommand

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CERT_DIR="$SCRIPT_DIR/certs"

# ─── Colors ──────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

    info "Starting Docker stack (Keycloak + mock-backend + central proxy)..."
    docker compose -f "$SCRIPT_DIR/docker-compose.yml" up -d --build

    info "Waiting for Keycloak to be healthy..."
    wait_for "http://localhost:8080/realms/oac-dev/.well-known/openid-configuration" 60
    ok "Keycloak is ready"

    info "Waiting for central proxy to be healthy..."
    wait_for_https "https://localhost:8443/healthz" 30
    ok "Central proxy is ready"

    info "Loading master key into the central proxy..."
    # Write the master key to the central's secrets volume
    docker compose -f "$SCRIPT_DIR/docker-compose.yml" exec -T central \
        sh -c 'echo -n "sk-mock-backend-master-key" > /secrets/master-key && chmod 600 /secrets/master-key'
    ok "Master key loaded"

    info "Building relay (host binary)..."
    cd "$PROJECT_DIR"
    cargo build -p oac-relay --release 2>&1 | tail -3
    ok "Relay built"

    info "Starting relay on 127.0.0.1:8787..."
    # Kill any existing relay
    pkill -f "oac-relay serve" 2>/dev/null || true
    sleep 1
    OAC_OIDC_CLIENT_SECRET="oac-relay-secret" \
        "$PROJECT_DIR/target/release/oac-relay" serve \
        --config "$SCRIPT_DIR/configs/relay.toml" &
    RELAY_PID=$!
    echo $RELAY_PID > /tmp/oac-relay.pid

    sleep 2
    if kill -0 $RELAY_PID 2>/dev/null; then
        ok "Relay is running (PID $RELAY_PID) on http://127.0.0.1:8787"
    else
        err "Relay failed to start"
        exit 1
    fi

    echo ""
    echo "═══════════════════════════════════════════════════════════════════════"
    ok "Dev stack is up!"
    echo ""
    echo "  Keycloak:        http://localhost:8080"
    echo "  Mock backend:   http://localhost:8090"
    echo "  Central proxy:  https://localhost:8443"
    echo "  Relay:          http://127.0.0.1:8787"
    echo ""
    echo "  Test users (Keycloak realm: oac-dev):"
    echo "    alice   / alice-pass-123   (alice@example.com)"
    echo "    bob     / bob-pass-456     (bob@example.com)"
    echo "    charlie / charlie-pass-789  (charlie@example.com)"
    echo "    admin   / admin-pass-000   (admin@example.com)"
    echo ""
    echo "  Next steps:"
    echo "    ./docker/dev.sh login   — authenticate via OIDC"
    echo "    ./docker/dev.sh goose   — configure Goose"
    echo "    ./docker/dev.sh test    — send a test request"
    echo "═══════════════════════════════════════════════════════════════════════"
}

cmd_down() {
    info "Stopping relay..."
    if [ -f /tmp/oac-relay.pid ]; then
        kill "$(cat /tmp/oac-relay.pid)" 2>/dev/null || true
        rm -f /tmp/oac-relay.pid
    fi
    pkill -f "oac-relay serve" 2>/dev/null || true

    info "Stopping Docker stack..."
    docker compose -f "$SCRIPT_DIR/docker-compose.yml" down
    ok "Everything stopped"
}

cmd_status() {
    echo "Docker services:"
    docker compose -f "$SCRIPT_DIR/docker-compose.yml" ps
    echo ""
    echo "Relay:"
    if [ -f /tmp/oac-relay.pid ] && kill -0 "$(cat /tmp/oac-relay.pid)" 2>/dev/null; then
        ok "Running (PID $(cat /tmp/oac-relay.pid))"
    else
        err "Not running"
    fi
}

cmd_login() {
    info "Running OIDC login (opens browser)..."
    cd "$PROJECT_DIR"
    OAC_OIDC_CLIENT_SECRET="oac-relay-secret" \
        "$PROJECT_DIR/target/release/oac-relay" login \
        --config "$SCRIPT_DIR/configs/relay.toml"
}

cmd_goose() {
    info "Configuring Goose to use the relay..."

    GOOSE_CONFIG_DIR="$HOME/.config/goose"
    GOOSE_PROVIDERS_DIR="$GOOSE_CONFIG_DIR/custom_providers"
    mkdir -p "$GOOSE_PROVIDERS_DIR"

    # Create the custom provider for the local relay
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

    # Set the Goose config to use this provider
    cat > "$GOOSE_CONFIG_DIR/config.yaml" << 'EOF'
GOOSE_PROVIDER: custom_local_relay
GOOSE_MODEL: mock-gpt-4
EOF
    ok "Goose config written to $GOOSE_CONFIG_DIR/config.yaml"

    echo ""
    warn "You need to set the LOCAL_RELAY_API_KEY env var to the key from 'oac-relay login'."
    echo "  After running './docker/dev.sh login', copy the printed key and run:"
    echo "    export LOCAL_RELAY_API_KEY=\"<your-key>\""
    echo ""
    echo "  Then start Goose:"
    echo "    goose session"
}

cmd_test() {
    info "Sending a test request through the full chain..."
    info "  Agent → relay (127.0.0.1:8787) → central (8443) → mock-backend"

    # First, we need a valid key. Try to read it from the relay's agent config.
    KEY=""
    if [ -f "$HOME/.oac/agent-env.sh" ]; then
        KEY=$(grep "OPENAI_API_KEY" "$HOME/.oac/agent-env.sh" | sed "s/.*='\(.*\)'.*/\1/")
    fi

    if [ -z "$KEY" ]; then
        err "No API key found. Run './docker/dev.sh login' first."
        exit 1
    fi

    info "Testing /v1/models..."
    RESPONSE=$(curl -s -w "\n%{http_code}" \
        -H "Authorization: Bearer $KEY" \
        http://127.0.0.1:8787/v1/models)

    HTTP_CODE=$(echo "$RESPONSE" | tail -1)
    BODY=$(echo "$RESPONSE" | sed '$d')

    if [ "$HTTP_CODE" = "200" ]; then
        ok "GET /v1/models → 200"
        echo "  $BODY" | head -c 200
        echo ""
    else
        err "GET /v1/models → $HTTP_CODE"
        echo "  $BODY"
        exit 1
    fi

    info "Testing POST /v1/chat/completions (non-streaming)..."
    RESPONSE=$(curl -s -w "\n%{http_code}" \
        -X POST \
        -H "Authorization: Bearer $KEY" \
        -H "Content-Type: application/json" \
        -d '{"model":"mock-gpt-4","messages":[{"role":"user","content":"hello"}]}' \
        http://127.0.0.1:8787/v1/chat/completions)

    HTTP_CODE=$(echo "$RESPONSE" | tail -1)
    BODY=$(echo "$RESPONSE" | sed '$d')

    if [ "$HTTP_CODE" = "200" ]; then
        ok "POST /v1/chat/completions → 200"
        echo "  $BODY" | head -c 200
        echo ""
    else
        err "POST /v1/chat/completions → $HTTP_CODE"
        echo "  $BODY"
        exit 1
    fi

    info "Testing POST /v1/chat/completions (streaming)..."
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST \
        -H "Authorization: Bearer $KEY" \
        -H "Content-Type: application/json" \
        -d '{"model":"mock-gpt-4","messages":[{"role":"user","content":"stream test"}],"stream":true}' \
        http://127.0.0.1:8787/v1/chat/completions)

    if [ "$HTTP_CODE" = "200" ]; then
        ok "POST /v1/chat/completions (stream) → 200"
    else
        err "POST /v1/chat/completions (stream) → $HTTP_CODE"
        exit 1
    fi

    echo ""
    ok "All tests passed!"
}

# ─── Helpers ─────────────────────────────────────────────────────────────

wait_for() {
    local url="$1"
    local timeout="${2:-30}"
    local elapsed=0
    while [ $elapsed -lt $timeout ]; do
        if curl -sf "$url" > /dev/null 2>&1; then
            return 0
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done
    err "Timeout waiting for $url"
    exit 1
}

wait_for_https() {
    local url="$1"
    local timeout="${2:-30}"
    local elapsed=0
    while [ $elapsed -lt $timeout ]; do
        if curl -skf "$url" > /dev/null 2>&1; then
            return 0
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done
    err "Timeout waiting for $url"
    exit 1
}

# ─── Main ────────────────────────────────────────────────────────────────

case "${1:-}" in
    up)     cmd_up ;;
    down)   cmd_down ;;
    status) cmd_status ;;
    login)  cmd_login ;;
    goose)  cmd_goose ;;
    test)   cmd_test ;;
    *)
        echo "Usage: $0 {up|down|status|login|goose|test}"
        echo ""
        echo "  up      — generate certs, start Docker stack, start relay"
        echo "  down    — stop everything"
        echo "  status  — show status of all services"
        echo "  login   — run OIDC login (opens browser)"
        echo "  goose   — configure Goose to use the relay"
        echo "  test    — send a test request through the full chain"
        exit 1
        ;;
esac
