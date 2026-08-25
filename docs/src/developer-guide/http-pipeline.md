# HTTP Pipeline

The HTTP forwarding pipeline is shared between the relay and central proxy
via `oidc_agent_common::http_util`. This page documents the utilities and
the request/response transformation at each hop.

## Constants

### `HOP_BY_HOP_HEADERS` (RFC 7230 §6.1)

```rust
pub const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade",
];
```

These headers are stripped on both requests and responses at every proxy
hop.

### `FORWARDABLE_HEADERS` (allowlist)

```rust
pub const FORWARDABLE_HEADERS: &[&str] = &[
    "content-type", "accept", "accept-encoding", "accept-language", "user-agent",
];
```

Only these headers are forwarded upstream. `Authorization` is intentionally
**not** in this list — it is replaced by upstream auth (local key →
identity headers at the relay; identity headers → master key at central).

### `MAX_BODY_SIZE`

```rust
pub const MAX_BODY_SIZE: usize = 10 * 1024 * 1024;  // 10 MB
```

Enforced by `RequestBodyLimitLayer` on both the relay and central proxy.

## Functions

### `is_sse_content_type(content_type) -> bool`

Case-insensitive contains check for `text/event-stream`. Used to decide
whether to stream the response or buffer it.

### `extract_model(body) -> Option<String>`

Parses JSON body, returns the `model` string field. Used for activity
logging, audit logging, permission checks, and cost computation.

### `sanitize_path(path) -> Result<String>`

SSRF / path traversal defense. Rejects:

- `..` (literal)
- `%2e%2e`, `%2e.`, `.%2e` (case-insensitive)
- `\` (backslash)
- `//` (double slash)
- Absolute `http(s)://` URLs

Returns `Error::Http` on unsafe path.

### `build_forward_headers(headers) -> Vec<(HeaderName, HeaderValue)>`

Allowlist model: only `FORWARDABLE_HEADERS` are forwarded. Strips:

- Hop-by-hop headers.
- Headers named in the `Connection` header.
- `Authorization` (replaced by upstream auth).

### `is_response_header_stripped(name_lower) -> bool`

Returns `true` for:

- Hop-by-hop headers.
- `content-length` (Axum recomputes it; the upstream value is wrong for
  streaming).

## Identity headers (`identity` module)

The relay sets these headers **only** from the auth-middleware-verified
`VerifiedIdentity`, never from incoming request headers. This prevents
identity spoofing.

| Header | Constant | Set by |
|---|---|---|
| `x-oac-user-subject` | `HEADER_USER_SUBJECT` | Relay auth middleware |
| `x-oac-user-email` | `HEADER_USER_EMAIL` | Relay auth middleware |
| `x-oac-user-groups` | `HEADER_USER_GROUPS` | Relay auth middleware |
| `x-oac-identity-id` | `HEADER_IDENTITY_ID` | Relay auth middleware |
| `x-oac-request-id` | `HEADER_REQUEST_ID` | Relay proxy handler (UUID v4) |

The central proxy trusts these headers after mTLS authentication (in
production mode). In dev mode, the central auth middleware allows requests
without identity headers (with a warning).

## Request lifecycle (header transformation)

### Agent → Relay

```
Authorization: Bearer oac_<local-key>
Content-Type: application/json
Accept: */*
User-Agent: codex/1.0
Host: 127.0.0.1:8787
```

### Relay → Central (over mTLS)

The relay:

1. Validates `Host` header (DNS rebinding defense — loopback only).
2. Verifies `Authorization: Bearer <local-key>` (constant-time, SHA-256
   hash lookup).
3. Strips `Authorization` and hop-by-hop headers.
4. Adds identity headers from `VerifiedIdentity`:
   - `x-oac-user-subject: alice@example.com`
   - `x-oac-user-email: alice@example.com`
   - `x-oac-user-groups: ["engineering","oac-admins"]`
   - `x-oac-identity-id: <uuid>`
   - `x-oac-request-id: <uuid-v4>`
5. Forwards over mTLS.

```
x-oac-user-subject: alice@example.com
x-oac-user-email: alice@example.com
x-oac-user-groups: ["engineering"]
x-oac-identity-id: 550e8400-e29b-41d4-a716-446655440000
x-oac-request-id: 660e8400-e29b-41d4-a716-446655440001
Content-Type: application/json
Accept: */*
User-Agent: codex/1.0
```

### Central → Backend (over HTTPS)

The central proxy:

1. Validates `x-oac-user-subject` (present, non-empty).
2. Resolves group policy.
3. Checks device revocation, endpoint, model, quota.
4. Strips identity headers and hop-by-hop headers.
5. Adds `Authorization: Bearer <master-key>` (from `Zeroizing` memory).
6. Forwards to backend.

```
Authorization: Bearer sk-<master-key>
Content-Type: application/json
Accept: */*
User-Agent: codex/1.0
```

### Response (backend → central → relay → agent)

On the way back:

- Hop-by-hop headers stripped at each hop.
- `content-length` stripped (Axum recomputes).
- If SSE (`text/event-stream`): streamed as raw bytes.
- Otherwise: buffered and returned.

## SSE streaming

When the response `Content-Type` is `text/event-stream`:

- **Relay**: streams via `bytes_stream()` → `Body::from_stream` (raw byte
  passthrough).
- **Central**: streams via `bytes_stream()` → `Body::from_stream`, but
  wraps the stream with `wrap_stream_with_usage_extraction` to intercept
  `data:` lines and extract `usage` from the final chunk (before
  `data: [DONE]`).

This allows the central proxy to record token usage and compute cost even
for streaming responses, without modifying the stream content.
