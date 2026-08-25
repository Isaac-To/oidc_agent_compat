# OIDC Security

The relay's OIDC login flow (`crates/relay/src/login.rs`) implements the
full authorization-code + PKCE flow. This page documents the security
controls and RFC compliance.

## RFC compliance

| Standard | Requirement | Implementation |
|---|---|---|
| RFC 8252 (Native Apps) | Loopback redirect, random port, PKCE | ✅ Binds `127.0.0.1:0`, substitutes actual port into redirect URI |
| RFC 7636 (PKCE) | S256, 32-octet verifier | ✅ `PkceCodeChallenge::new_random_sha256` |
| RFC 9700 (OAuth Security BCP) | S256 mandatory, state, exact redirect, no token storage v1 | ✅ S256 only, `state` verified, loopback redirect, no token storage |
| OIDC Core §3.1.3.7 | ID token validation (iss, aud, exp, nonce, sig, alg pin) | ✅ All steps implemented |
| NIST SP 800-90A | OS CSPRNG for key generation | ✅ `OsRng` via `rand` |
| NIST SP 800-131A | 256-bit minimum key length | ✅ 256-bit local API keys |
| OWASP ASVS V2/V3 | Auth, session, federated auth controls | ✅ |
| CWE-208 | Constant-time comparison (timing attack prevention) | ✅ `subtle::ConstantTimeEq`, no early return |

## Login flow (15 steps)

1. **Loopback redirect validation** — `validate_loopback_redirect()`:
   - Requires scheme `http` and loopback IP host (`127.0.0.0/8` or `::1`).
   - Rejects `localhost` hostname, `https`, non-loopback, substring
     bypasses like `127.0.0.1.evil.com`.
   - RFC 8252.

2. **Client secret resolution** — `resolve_client_secret()`: reads from
   env var named by `client_secret_env`. Never a literal in config.

3. **HTTP client** — `build_http_client()`:
   - `redirect::Policy::none()` — no redirects (SSRF prevention).
   - `use_rustls_tls()` — rustls, not native-tls.
   - `CONNECT_TIMEOUT = 10s`, `REQUEST_TIMEOUT = 30s`.

4. **OIDC discovery** — `CustomProviderMetadata::discover_async()`.

5. **Loopback listener** — binds `127.0.0.1:0` (random port, RFC 8252
   §7.3). Substitutes actual port into redirect URI.

6. **Client construction** — `CustomClient` from provider metadata +
   `ClientId` + `ClientSecret`.

7. **PKCE + state + nonce**:
   - PKCE: `PkceCodeChallenge::new_random_sha256` (S256, RFC 7636/9700).
   - `state`: `CsrfToken::new_random` (CSRF defense).
   - `nonce`: `Nonce::new_random` (replay defense).

8. **Authorize URL** — scopes: `openid` always added first; configured
   scopes filtered to skip `openid` (avoid duplicate).

9. **Browser launch** — `open_browser(url)`:
   - macOS: `open <url>`
   - Linux: `xdg-open <url>`
   - Windows: `cmd /C start <url>`

10. **Callback wait** — `wait_for_callback(listener, 300s)`:
    - `tokio::time::timeout(300s, listener.accept())`.
    - Reads request with 10s sub-timeout.
    - Parses `GET /callback?code=...&state=... HTTP/1.1`.
    - If `error` param present → `Error::oidc`.
    - Writes minimal HTML response.

11. **State verification** — compares returned `state` against the one
    sent (CSRF defense).

12. **Token exchange** — `client.exchange_code(code)
    .set_pkce_verifier(verifier).request_async(&http_client)`.

13. **ID-token validation**:
    - 13a. **Alg pin** — `is_allowed_alg()` accepts only:
      - `RS256` (`RsaSsaPkcs1V15Sha256`)
      - `ES256` (`EcdsaP256Sha256`)
      - Rejects `none`, all `HS*`, and other RSA/ECDSA variants.
      - Checked **before** signature verification.
    - 13b. **Claims verification** — `id_token.claims(&verifier, &nonce)`:
      - `iss` (issuer) matches.
      - `aud` (audience) matches `client_id`.
      - `exp` (expiry) in the future.
      - `nonce` matches the one sent.
      - Signature verified via JWKS.
    - 13c. **`at_hash` validation** (OIDC Core §3.1.3.7 step 3) — if
      the IdP includes `at_hash`, verifies it against the access token.
      Prevents token substitution.

14. **Userinfo** — `client.user_info(...)`. Falls back to
    `claims_from_id_token()` on userinfo failure. Extracts:
    - `subject` (sub claim).
    - `email` (email claim).
    - `display_name` (name → preferred_username).
    - `groups` (via `union_groups_roles` + `groups_to_json_string`).

15. **Complete login** — `complete_login()`:
    - `key_store.upsert_identity(...)`.
    - `key_store.mint_key(...)`.
    - `agent_config::inject(...)`.

## Allowed signing algorithms

```rust
pub const ALLOWED_SIGNING_ALGS: &[&str] = &["RS256", "ES256"];
```

- `is_allowed_signing_alg(alg)` — case-insensitive check.
- Rejects `none` (no signature), all `HS*` (symmetric, client secret as
  HMAC key), and other RSA/ECDSA variants.
- This prevents alg downgrade attacks.

## Groups extraction

Groups are extracted from the signed ID token (or TLS-protected userinfo)
via `CustomAdditionalClaims`:

```rust
pub struct CustomAdditionalClaims {
    pub groups: Option<Vec<String>>,
    pub roles: Option<Vec<String>>,
}
```

`union_groups_roles()` deduplicates and sorts groups + roles into a single
list. `groups_to_json_string()` serializes as a JSON array string for the
`x-oac-user-groups` header.

> **Note:** Groups extraction from userinfo is not a standard OIDC claim.
> The `groups` scope must be requested in the relay's OIDC config.

## Manual verification

Run `oac-relay login` on the **host** against dev Keycloak:

```sh
cargo build --release -p oac-relay
./docker/dev.sh up
OAC_OIDC_CLIENT_SECRET="oac-relay-secret" \
  ./target/release/oac-relay \
    --config docker/dev/configs/relay-login-test.toml login
```

The containerized relay cannot do login (no host browser / loopback
callback).
