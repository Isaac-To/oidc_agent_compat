# Request Data Flow

This page walks through the full request lifecycle, showing what headers
are added, stripped, and transformed at each hop.

## Overview

```
Agent ──HTTP──► Relay ──mTLS──► Central ──HTTPS──► Backend
                  │                  │
                  │                  ├─ Auth (identity headers)
                  │                  ├─ Permissions (policy, device, quota)
                  │                  ├─ Provider-key injection
                  │                  ├─ Audit log
                  │                  └─ Usage tracking
                  │
                  ├─ Host guard (DNS rebinding)
                  ├─ Auth (local key → identity)
                  ├─ Identity header injection
                  └─ Activity log
```

## Step 1: Agent → Relay

The agent sends a standard OpenAI-compatible request:

```http
POST /v1/chat/completions HTTP/1.1
Host: 127.0.0.1:8787
Authorization: Bearer oac_abc123...
Content-Type: application/json
Accept: */*
User-Agent: codex/1.0

{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}
```

### Relay processing

1. **Host guard** (`host_guard_middleware`):
   - Validates `Host` header is loopback (`127.0.0.1:8787`,
     `localhost:8787`, `[::1]:8787`).
   - Mismatch → `400 Bad Request` (DNS rebinding defense).

2. **Auth** (`auth_middleware`):
   - Extracts `Authorization: Bearer oac_abc123...`.
   - `KeyStore::verify_key()` — loads all key hashes, compares each via
     `KeyHash::matches()` (constant-time, `subtle::ConstantTimeEq`, no
     early return — prevents timing leaks, CWE-208).
   - Missing/invalid → `401 Unauthorized`.
   - On success: inserts `VerifiedIdentity` into request extensions.

3. **Forward** (`proxy_handler` → `forward_request`):
   - Generates `request_id = Uuid::new_v4()`.
   - Reads body (max 10 MB).
   - Extracts `model` from body (for activity logging).
   - Sanitizes path (`sanitize_path` — rejects `..`, `//`, `\`, absolute
     URLs).
   - Builds upstream URL: `{config.central.url}{sanitized_path}`.
   - Builds forward headers (`build_forward_headers` — allowlist model,
     strips hop-by-hop + `Authorization`).
   - **Replaces** `Authorization` with identity headers (set only from
     `VerifiedIdentity`, never from incoming request headers):
     - `x-oac-user-subject`
     - `x-oac-user-email`
     - `x-oac-user-groups`
     - `x-oac-identity-id`
     - `x-oac-request-id`
   - Sends over mTLS (production) or plain HTTP (dev).

4. **Activity log** (best-effort, after response):
   - Records `RelayActivityEntry` (identity_id, key_id, method, endpoint,
     model, central_status, latency_ms, request_id).

## Step 2: Relay → Central (over mTLS)

```http
POST /v1/chat/completions HTTP/1.1
Host: central:8443
x-oac-user-subject: alice@example.com
x-oac-user-email: alice@example.com
x-oac-user-groups: ["engineering"]
x-oac-identity-id: 550e8400-e29b-41d4-a716-446655440000
x-oac-request-id: 660e8400-e29b-41d4-a716-446655440001
Content-Type: application/json
Accept: */*
User-Agent: codex/1.0

{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}
```

> Note: `Authorization` is gone. Hop-by-hop headers are stripped. Identity
> headers are added.

### Central processing

1. **Auth** (`auth_middleware`):
   - Skips `/healthz`.
   - Extracts `x-oac-*` headers.
   - Requires `x-oac-user-subject` (non-empty) in production → else
     `401`. (Dev mode: logs warning, allows through.)
   - Inserts `VerifiedRelayIdentity` into extensions.

2. **Permissions** (`permissions_middleware`):
   - Skip `/healthz`.
   - Parse groups from `x-oac-user-groups` JSON array.
   - `PolicyStore::resolve_policy(&groups)` — most-permissive-wins merge.
   - **Device revocation check** — if `DeviceStore::is_revoked` → `403`
     (`"device_revoked"`).
   - **Endpoint check** — `policy.is_endpoint_allowed(&endpoint)` →
     `403` (`"endpoint_not_allowed"`).
   - **Model check** (POST) — extract model, check
     `policy.is_model_allowed` → `403` (`"model_not_allowed"`).
   - **Request quota check** — if `daily_request_quota` set and
     `usage.request_count >= quota` → `429` (`"quota_exceeded"`).
   - On allow: inserts `PermissionDecision` into extensions.
   - If the resolved policy has the token saver enabled, attaches a
     `TokenSaverGrant` (config) to the extensions for the forward handler.

3. **Rate limit** (`rate_limit_middleware`, production only):
   - Per-IP token bucket (60 req/min default).
   - Exceeded → `429 Too Many Requests` with `Retry-After`.

4. **Forward** (`proxy_handler` → `forward_request`):
   - Reads body (max 10 MB).
   - Extracts model.
   - **Token saver** (if a `TokenSaverGrant` is present): applies the safe
     optimizer to the body — removes exact-verbatim duplicate messages and
     structurally-empty messages, drops empty `tools: []`, and, if a budget
     is set, drops the oldest whole turns (never truncates) to fit. If the
     policy enabled `collapse_repeated_lines`, consecutive exact-verbatim
     repeated lines inside a single message are folded into `[×N]` markers
     (RTK-adapted). If the policy enabled `strip_ansi`, terminal ANSI
     colour/control codes are removed from message content. Kept messages are
     otherwise never rewritten, and a final "never-worse" guard reverts to
     the original body if the optimizer would ever increase token usage.
     Records `OptimizationReport`.
   - Sanitizes path.
  - Builds upstream URL: `{provider.base_url}{sanitized_path}`.
   - Builds forward headers (strips hop-by-hop + identity headers).
   - **Replaces** `Authorization` with the selected provider key (held in
     `Zeroizing<String>` memory).
   - Sends to backend.

## Step 3: Central → Backend (over HTTPS)

```http
POST /v1/chat/completions HTTP/1.1
Host: api.openai.com
Authorization: Bearer sk-<provider-key>
Content-Type: application/json
Accept: */*
User-Agent: codex/1.0

{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}
```

> Note: Identity headers are gone. `Authorization` is now the selected
> provider key; provider keys are never returned to the relay.

## Step 4: Response (Backend → Central → Relay → Agent)

### Non-streaming response

The central proxy:

1. Buffers the response body.
2. Extracts token usage from the `usage` JSON field.
3. Computes cost via `PriceTable::compute_cost`.
4. Records `AuditEntry` (best-effort).
5. Increments usage counters (best-effort, allowed requests only).
6. Strips hop-by-hop + `content-length` headers.
7. Returns the response.

The relay:

1. Strips hop-by-hop + `content-length` headers.
2. Returns the response to the agent.
3. Records `RelayActivityEntry` (best-effort).

### SSE streaming response

When `Content-Type: text/event-stream`:

- **Central**: sets `stream_options.include_usage=true`, then streams via
  `bytes_stream()` → `Body::from_stream` while wrapping with
  `wrap_stream_with_usage_extraction` to intercept `data:` lines and
  extract `usage` from the final chunk (before `data: [DONE]`). Audit and
  usage accounting are deferred until the stream completes; the forwarded
  SSE bytes are not modified.
- **Relay**: streams via `bytes_stream()` → `Body::from_stream` (raw
  byte passthrough).

## Header transformation summary

| Header | Agent→Relay | Relay→Central | Central→Backend |
|---|---|---|---|
| `Authorization` | `Bearer oac_...` (local key) | **stripped** | `Bearer sk-...` (selected provider key) |
| `Host` | `127.0.0.1:8787` | `central:8443` | `api.openai.com` |
| `x-oac-user-subject` | — | **added** (from VerifiedIdentity) | **stripped** |
| `x-oac-user-email` | — | **added** | **stripped** |
| `x-oac-user-groups` | — | **added** | **stripped** |
| `x-oac-identity-id` | — | **added** | **stripped** |
| `x-oac-request-id` | — | **added** (UUID v4) | **stripped** |
| `Content-Type` | forwarded | forwarded | forwarded |
| `Accept` | forwarded | forwarded | forwarded |
| `User-Agent` | forwarded | forwarded | forwarded |
| Hop-by-hop headers | — | **stripped** | **stripped** |
| `content-length` (response) | — | **stripped** (Axum recomputes) | — |
