# mTLS

Mutual TLS (mTLS) authenticates the relay to the central proxy and vice
versa. TLS 1.3 is preferred; TLS 1.2 is the minimum.

## Certificate generation

`docker/generate-certs.sh` generates self-signed certs into
`docker/certs/`:

| File | Purpose | Key | Validity |
|---|---|---|---|
| `ca.crt` / `ca.key` | CA (RSA 4096, SHA-256) | `0600` | 3650 days |
| `server.crt` / `server.key` | Server cert (RSA 2048), CN=`central`, SAN: `DNS:central,DNS:localhost,IP:127.0.0.1` | `0600` | 365 days |
| `client.crt` / `client.key` | Client cert (RSA 2048), CN=`relay`, SAN: `DNS:relay,DNS:localhost,IP:127.0.0.1` | `0600` | 365 days |

For production, use your company PKI or a properly signed CA.

## rustls builders (`crates/common/src/mtls.rs`)

### `load_certs(path) -> Result<Vec<CertificateDer>>`

Loads PEM certs from file. Returns `Error::Tls` if unreadable, malformed,
or empty.

### `load_private_key(path) -> Result<PrivateKeyDer>`

Loads PEM private key. Returns `Error::Tls` if unreadable, malformed, or
no key found.

### `enforce_secure_perms(path) -> Result<()>`

- **Unix**: verifies file is exactly `0600`. Returns `Error::Tls` if more
  permissive.
- **Non-Unix**: no-op.

### `build_client_config(ca, cert, key) -> Result<ClientConfig>`

Builds rustls `ClientConfig` for relay→central mTLS:

1. Enforces `0600` on client key via `enforce_secure_perms`.
2. Loads CA cert into root store.
3. Sets client auth cert.
4. TLS 1.3 preferred, 1.2 minimum.

### `build_server_config(ca, cert, key) -> Result<ServerConfig>`

Builds rustls `ServerConfig` for central proxy:

1. Loads CA cert into `WebPkiClientVerifier` root store.
2. Client cert **required** (not optional).
3. `with_single_cert` for server cert.
4. TLS 1.3 preferred, 1.2 minimum.

## How the relay uses mTLS

`crates/relay/src/proxy/forward.rs` → `build_client(config)`:

- Production (`!dev_mode`):
  - Builds rustls `ClientConfig` via `mtls::build_client_config(ca, cert, key)`.
  - Applies via `reqwest::use_preconfigured_tls`.
  - Enables `https_only(true)`.
- Dev mode: plain HTTP, no mTLS.

## How the central proxy uses mTLS

`crates/central/src/proxy/mod.rs` → `serve()`:

- Production (`!dev_mode`):
  - Builds rustls `ServerConfig` via `mtls::build_server_config(ca, cert, key)`.
  - Binds via `axum_server::bind_rustls` with client cert required.
  - ALPN set to `http/1.1`.
- Dev mode: plain HTTP via `axum::serve` + `TcpListener`.

## Security properties

- **Server cert verification always on** — the relay always verifies the
  central proxy's server cert against the CA. `danger_accept_invalid` is
  never used.
- **Client cert required** — the central proxy requires a client cert
  signed by the CA. Connections without a valid client cert fail the TLS
  handshake.
- **Private key permissions** — private key files must be `0600` on Unix,
  enforced by `enforce_secure_perms`.
- **No `danger_accept_invalid`** — never used anywhere.

## Testing mTLS

The central integration tests include mTLS tests:

- `mtls_accepts_valid_client_cert` — GET with valid client cert → 200.
- `mtls_rejects_connection_without_client_cert` — plain HTTPS client (no
  client cert) → TLS handshake fails.

Test certs are generated via `oidc_agent_common::test_certs::generate_test_certs()`
(behind the `test-certs` feature, uses `rcgen`).

See [Testing](./testing.md) for details.
