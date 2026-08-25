# Threat Model

**Methodology:** STRIDE (Spoofing, Tampering, Repudiation, Information
Disclosure, Denial of Service, Elevation of Privilege).

**Scope:** v1 MVP — relay (laptop), central proxy (company-hosted), and
the communication channels between them, the IdP, the backend, and the
agent.

## System overview

```
Agent (Codex, etc.)
  │  Authorization: Bearer <local key>
  ▼
[127.0.0.1 relay]  ── mTLS (TLS 1.3) ──►  [central proxy]  ──►  [OpenAI-compatible backend]
  │                                        │
  │ OIDC (browser, auth-code + PKCE)       │ master key (secret manager)
  ▼                                        │
[Enterprise IdP]                           ▼
                                  [Audit log (append-only)]
```

**Trust boundaries:**

1. Agent → relay (loopback HTTP — same host, low trust).
2. Relay → central proxy (mTLS over network — medium trust).
3. Central proxy → backend (HTTPS — external, low trust).
4. Relay/central → IdP (OIDC — external, low trust).

## Assets

| Asset | Location | Sensitivity |
|---|---|---|
| Master backend key | Central secret manager → `Zeroizing` memory | **CRITICAL** — never on laptop |
| Local API keys (plaintext) | Agent config file (`0600`) | Medium — loopback-only, revocable |
| Local API key hashes | Relay SQLite (`0600`) | Low — SHA-256 hashes |
| OIDC ID tokens | In transit only (not stored in v1) | Medium — short-lived |
| User identity (subject, email) | Relay + central DB, audit log | Medium — PII |
| Audit log | Central DB (append-only) | Medium — tamper-evident |

## STRIDE analysis

### S — Spoofing

| Threat | Control | Status |
|---|---|---|
| Attacker spoofs a local API key | 256-bit `OsRng` key, SHA-256 hash, constant-time compare (`subtle::ConstantTimeEq`) | ✅ Implemented |
| Attacker spoofs the relay to the central proxy | mTLS with company CA (client cert required) | ✅ Implemented |
| Attacker spoofs the IdP | OIDC discovery + JWKS signature verification + alg pin {RS256, ES256} | ✅ Implemented |
| Attacker spoofs the central proxy to the relay | mTLS with company CA (server cert verification) | ✅ Implemented |
| Attacker spoofs the user identity to the central proxy | `X-OAC-User-Subject` header set ONLY by relay auth middleware (never from incoming request headers) | ✅ Implemented |
| Attacker spoofs the Host header (DNS rebinding) | Host header validation middleware (loopback only) | ✅ Implemented |
| Attacker spoofs the OIDC redirect (mix-up) | `state` (CSRF) + `nonce` (replay) + loopback redirect only | ✅ Implemented |

### T — Tampering

| Threat | Control | Status |
|---|---|---|
| Attacker tampers with the request in transit (relay → central) | mTLS (TLS 1.3 integrity) | ✅ Implemented |
| Attacker tampers with the audit log | Append-only triggers (SQLite `BEFORE UPDATE/DELETE` → `RAISE(ABORT)`) | ✅ Implemented |
| Attacker tampers with the local key store (SQLite) | `0600` file permissions, parameterized SQL (no injection) | ✅ Implemented |
| Attacker tampers with the agent config file | `0600` permissions, written by relay only | ✅ Implemented |
| Attacker tampers with the request path (SSRF/path traversal) | Path sanitization (rejects `..`, `//`, `\`, absolute URLs) | ✅ Implemented |

### R — Repudiation

| Threat | Control | Status |
|---|---|---|
| User denies making a request | Audit log records user subject, model, status, latency, tokens | ✅ Implemented |
| Attacker deletes/modifies audit entries | Append-only DB triggers | ✅ Implemented |
| Attacker forges audit entries | Parameterized SQL, server-side only (no client API to write audit) | ✅ Implemented |

### I — Information Disclosure

| Threat | Control | Status |
|---|---|---|
| Master key leaks to laptop | Master key never leaves central proxy process; relay never sees it | ✅ By design |
| Master key leaks in logs/responses | `Zeroizing` memory, never logged, never in error responses, redaction layer | ✅ Implemented |
| Master key leaks in relay response | E2E test verifies master key not in relay response | ✅ Tested |
| Local key leaks to other local users | `0600` on SQLite + agent config | ✅ Implemented |
| Local key leaks in logs | Never logged; `Zeroizing` wrapper | ✅ Implemented |
| PII (email, subject) leaks in logs | Structured logging, no body logging, redaction layer | ✅ Implemented |
| Hop-by-hop header leakage | RFC 7230 §6.1 hop-by-hop stripping on forward + response | ✅ Implemented |
| ID token alg downgrade (`none`/HS*) | Alg pin {RS256, ES256} before signature verification | ✅ Implemented |

### D — Denial of Service

| Threat | Control | Status |
|---|---|---|
| Large request body exhausts memory | 10 MB body limit (`RequestBodyLimitLayer`) | ✅ Implemented |
| Slow client ties up connections | Connect timeout (10s) + request timeout (300s) | ✅ Implemented |
| OIDC callback hangs forever | 5-minute callback timeout | ✅ Implemented |
| Attacker floods relay with requests | Loopback-only binding (not network-accessible) | ✅ Implemented |
| Attacker floods central proxy | Per-IP token-bucket rate limiter (60 req/min default, production only) | ✅ Implemented |

### E — Elevation of Privilege

| Threat | Control | Status |
|---|---|---|
| Unauthenticated user accesses relay | Auth middleware (401 without valid key) | ✅ Implemented |
| Unauthenticated request reaches backend | Central auth middleware (401 without `X-OAC-User-Subject` in prod mode) | ✅ Implemented |
| Attacker bypasses auth via healthz | `/healthz` exempt from auth (returns only "ok", no data) | ✅ Implemented |
| Attacker uses revoked key | Key deletion on logout; `verify_key` checks current keys only | ✅ Implemented |
| Attacker exploits `unsafe` code | `#![forbid(unsafe_code)]` across all crates | ✅ Implemented |
| Authenticated user calls disallowed model | Permissions middleware enforces group-based model allowlists (403) | ✅ Implemented |
| Authenticated user calls disallowed endpoint | Permissions middleware enforces group-based endpoint restrictions (403) | ✅ Implemented |
| Authenticated user exceeds quota | Per-user daily request-count quota enforced pre-flight (429 `quota_exceeded`); token quotas tracked but not yet enforced | ⚠️ Partial (request quota enforced; token quota tracked only) |
| Attacker spoofs group membership | Groups extracted from IdP-signed ID token / TLS-protected userinfo; forwarded over mTLS | ✅ Implemented |
| Admin API accessed without authorization | Admin auth middleware checks IdP group membership (via relay-forwarded `x-oac-user-groups`); 403 if not in admin group | ✅ Implemented |
| Admin API mutations go unlogged | All mutations recorded in append-only `admin_audit_log` | ✅ Implemented |
| Revoked device continues to access | Device revocation checked in `permissions_middleware` (uses `identity_id` or `subject` as device ID) | ✅ Implemented |

## Security standards compliance

| Standard | Requirement | Status |
|---|---|---|
| RFC 8252 (Native Apps) | Loopback redirect, random port, PKCE | ✅ |
| RFC 7636 (PKCE) | S256, 32-octet verifier | ✅ |
| RFC 9700 (OAuth Security BCP) | S256 mandatory, state, exact redirect, no token storage v1 | ✅ |
| OIDC Core §3.1.3.7 | ID token validation (iss, aud, exp, nonce, sig, alg pin) | ✅ |
| RFC 7230 §6.1 | Hop-by-hop header stripping | ✅ |
| NIST SP 800-90A | OS CSPRNG for key generation | ✅ |
| NIST SP 800-131A | 256-bit minimum key length | ✅ |
| OWASP ASVS V2/V3 | Auth, session, federated auth controls | ✅ |
| CWE-208 | Constant-time comparison (timing attack prevention) | ✅ |
