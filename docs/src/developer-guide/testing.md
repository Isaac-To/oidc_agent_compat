# Testing

The project has three levels of tests: unit tests (inline in source
files), integration tests (per-crate), and in-process end-to-end tests.

## How to run

```sh
# All tests:
cargo test --workspace

# Just the relay integration tests:
cargo test -p oac-relay

# Just the central integration tests:
cargo test -p oac-central

# Just the E2E tests:
cargo test -p oac-e2e-tests

# Docker dev stack tests (full chain + SSE + master-key-leak check):
./docker/dev.sh test
```

## Unit tests

Unit tests are inline in source files (`#[cfg(test)] mod tests`). They
test individual functions and modules in isolation. Run them as part of
`cargo test --workspace`.

## Relay integration tests (`crates/relay/tests/proxy_integration.rs`)

6 tests. `setup_test_relay()` spins up a mock central proxy (Axum) + relay
proxy (in-process, `dev_mode=true`). Mints a key for identity `user123`.

| Test | Description | Assertion |
|---|---|---|
| `healthz_returns_ok` | GET `/healthz` | 200 OK |
| `rejects_request_without_authorization` | GET `/v1/models` no auth | 401 |
| `rejects_request_with_invalid_key` | GET `/v1/models` with `oac_invalid` | 401 |
| `rejects_non_loopback_host` | GET with `Host: evil.example.com` | 400 (DNS rebinding) |
| `forwards_get_request_with_valid_key` | GET `/v1/models` with valid key | 200, `data` array |
| `forwards_post_request_with_valid_key` | POST `/v1/chat/completions` with valid key | 200, `choices` array |

## Central integration tests (`crates/central/tests/proxy_integration.rs`)

11 tests across three modes:

### Dev mode tests

`setup_test_central()` — mock backend + central (in-process,
`dev_mode=true`) with master key `sk-test-master-key-12345`.

| Test | Description | Assertion |
|---|---|---|
| `healthz_returns_ok` | GET `/healthz` | 200 OK |
| `forwards_get_request_to_backend` | GET `/v1/models` | 200, `data` array |
| `forwards_post_request_with_master_key` | POST `/v1/chat/completions` | 200, `choices`, `usage.total_tokens == 15` |
| `master_key_not_in_response_body` | POST, check body | must NOT contain `sk-test-master-key-12345` |

### Production mode tests

`setup_prod_central()` — same but `dev_mode=false` (auth middleware
enforces `X-OAC-User-Subject`).

| Test | Description | Assertion |
|---|---|---|
| `prod_mode_rejects_request_without_identity_headers` | GET no `X-OAC-User-Subject` | 401 |
| `prod_mode_accepts_request_with_identity_headers` | GET with identity headers | 200 |
| `prod_mode_healthz_bypasses_auth` | GET `/healthz` no auth | 200 (healthz bypasses auth) |
| `prod_mode_rejects_empty_subject` | GET with `X-OAC-User-Subject: ""` | 401 |

### mTLS tests

`setup_mtls_central()` — central with real mTLS (rustls) using test certs
via `test_certs::generate_test_certs()`. Uses `axum_server::bind_rustls`
with client cert required.

| Test | Description | Assertion |
|---|---|---|
| `mtls_accepts_valid_client_cert` | GET with valid client cert + `X-OAC-User-Subject` | 200 |
| `mtls_rejects_connection_without_client_cert` | GET with plain HTTPS client (no client cert) | TLS handshake fails |

## E2E tests (`tests/e2e/tests/e2e.rs`)

15 tests. `setup_full_system()` spins up in-process: mock backend + central
+ relay, all wired together. Mints a key for identity `e2e-user`
(`e2e@example.com`).

### Basic chain tests

| Test | Description | Assertion |
|---|---|---|
| `e2e_healthz` | GET `/healthz` on relay | 200 OK |
| `e2e_get_models_through_full_chain` | GET `/v1/models` with valid key | 200, `data[0].id == "gpt-4"` |
| `e2e_post_chat_completions_through_full_chain` | POST `/v1/chat/completions` | 200, `choices[0].message.content == "hello from backend"`, `usage.total_tokens == 15` |
| `e2e_post_embeddings_through_full_chain` | POST `/v1/embeddings` | 200, `data` array |

### Auth/security tests

| Test | Description | Assertion |
|---|---|---|
| `e2e_rejects_request_without_key` | GET `/v1/models` no auth | 401 |
| `e2e_rejects_invalid_key` | GET `/v1/models` with `oac_invalid` | 401 |
| `e2e_rejects_non_loopback_host` | GET with `Host: evil.example.com` | 400 (DNS rebinding) |
| `e2e_master_key_not_in_relay_response` | POST, check response body | must NOT contain master key |
| `e2e_master_key_not_in_error_response` | GET no auth, check error body | must NOT contain master key |

### Audit/activity tests

| Test | Description | Assertion |
|---|---|---|
| `e2e_identity_forwarded_and_audited` | POST, check central audit log | `user_subject == "e2e-user"`, `model == "gpt-4"`, `status == 200`, `email == "e2e@example.com"`, `endpoint == "/v1/chat/completions"`, `request_id` is some |
| `e2e_relay_activity_log_records_request` | POST, check relay activity log | `method == "POST"`, `endpoint == "/v1/chat/completions"`, `model == "gpt-4"`, `central_status == Some(200)`, `request_id` is some |
| `e2e_request_id_correlates_relay_and_central` | POST, check `request_id` | `request_id` is some (forwarded by relay) |

### Permissions tests

| Test | Description | Assertion |
|---|---|---|
| `e2e_permissions_deny_disallowed_model` | Policy allows only `gpt-4o`; request `gpt-4` | 403; audit has `denial_reason == "model_not_allowed"` |
| `e2e_permissions_allow_allowed_model` | Policy allows `gpt-4`; request `gpt-4` | 200 |
| `e2e_permissions_deny_disallowed_endpoint` | Policy allows only `/v1/chat/completions`; request `/v1/embeddings` | 403; `denial_reason == "endpoint_not_allowed"` |

### Device revocation test

| Test | Description | Assertion |
|---|---|---|
| `e2e_device_revocation_blocks_request` | Register → verify works → revoke → verify denied → reinstate → verify works | Full revoke/reinstate lifecycle; audit has `denial_reason == "device_revoked"` |

## Test cert generation

Integration and E2E tests use `oidc_agent_common::test_certs::generate_test_certs()`
(behind the `test-certs` feature, uses `rcgen`) to generate ephemeral CA,
server, and client certs. Private keys are written to temp files with
`0600` permissions (required by `mtls::enforce_secure_perms`).
