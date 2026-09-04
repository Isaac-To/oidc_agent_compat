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

# Docker dev stack tests (full chain + SSE + provider-key-leak check):
./docker/dev.sh test
```

## Unit tests

Unit tests are inline in source files (`#[cfg(test)] mod tests`). They
test individual functions and modules in isolation. Run them as part of
`cargo test --workspace`.

## Relay integration tests (`crates/relay/tests/proxy_integration.rs`)

12 tests. `setup_test_relay()` spins up a mock central proxy (Axum) + relay
proxy (in-process, `dev_mode=true`). Mints a central token for identity `user123` via the token API.

| Test | Description | Assertion |
|---|---|---|
| `healthz_returns_ok` | GET `/healthz` | 200 OK |
| `rejects_request_without_authorization` | GET `/v1/models` no auth | 401 |
| `rejects_request_with_invalid_key` | GET `/v1/models` with `oac_invalid` | 401 |
| `expired_session_returns_relogin_error_and_removes_key` | Token past `expires_at` | rejected; token deleted from central DB |
| `rejects_non_loopback_host` | GET with `Host: evil.example.com` | 400 (DNS rebinding) |
| `forwards_get_request_with_valid_key` | GET `/v1/models` with valid key | 200, `data` array |
| `forwards_post_request_with_valid_key` | POST `/v1/chat/completions` with valid key | 200, `choices` array |
| `forwards_verified_identity_and_request_id_headers` | Forwarded request headers | `Authorization`/`x-oac-request-id` reach central |
| `streams_sse_response_unchanged` | SSE passthrough | `text/event-stream` body streams verbatim |
| `unreachable_central_returns_typed_502_json` | Central down | typed JSON `502` error |
| `build_client_uses_mtls_in_production_mode` | Client builder | rustls client cert configured when `dev_mode=false` |
| `serve_boots_and_shuts_down_gracefully_on_sigterm` | Lifecycle | SIGTERM → graceful shutdown |

## Central integration tests (`crates/central/tests/proxy_integration.rs`)

22 tests across three modes:

### Dev mode tests

`setup_test_central()` — mock backend + central (in-process,
`dev_mode=true`) with master key `sk-test-master-key-12345`.

| Test | Description | Assertion |
|---|---|---|
| `healthz_returns_ok` | GET `/healthz` | 200 OK |
| `forwards_get_request_to_backend` | GET `/v1/models` | 200, `data` array |
| `forwards_post_request_with_master_key` | POST `/v1/chat/completions` | 200, `choices`, `usage.total_tokens == 15` |
| `master_key_not_in_response_body` | POST, check body | must NOT contain `sk-test-master-key-12345` |
| `streaming_response_records_token_usage_after_stream_completes` | SSE POST, consume stream | usage is recorded and `include_usage` reaches backend |

### Production mode tests

`setup_prod_central()` — same but `dev_mode=false` (auth middleware
enforces bearer token verification via TokenStore.

| Test | Description | Assertion |
|---|---|---|
| `prod_mode_rejects_request_without_identity_headers` | GET no `Authorization` bearer | 401 |
| `prod_mode_accepts_request_with_identity_headers` | GET with valid bearer token | 200 |
| `prod_mode_healthz_bypasses_auth` | GET `/healthz` no auth | 200 (healthz bypasses auth) |
| `prod_mode_rejects_empty_subject` | GET with empty bearer token | 401 |

### mTLS tests

`setup_mtls_central()` — central with real mTLS (rustls) using test certs
via `test_certs::generate_test_certs()`. Uses `axum_server::bind_rustls`
with client cert required.

| Test | Description | Assertion |
|---|---|---|
| `mtls_accepts_valid_client_cert` | GET with valid client cert + bearer token | 200 |
| `mtls_rejects_connection_without_client_cert` | GET with plain HTTPS client (no client cert) | TLS handshake fails |

### Provider-routing tests (mock `RecordingBackend`)

| Test | Description | Assertion |
|---|---|---|
| `routes_request_to_provider_matching_model` | Model in a provider's `models` list | routed to that provider |
| `unknown_model_falls_back_to_default_provider` | Model not listed anywhere | routed to the default provider |
| `group_restricted_key_serves_only_matching_groups` | Key with group ACL | non-members fall through to another key |
| `missing_identity_groups_cannot_use_restricted_keys` | No groups header with restricted key | request not served by that key |
| `key_falls_back_on_upstream_401` | Upstream rejects selected key | next authorized key retried |
| `no_provider_configured_returns_error_without_key_leak` | No providers registered | typed error; no key material leaked |

### Token-saver / rate-limit tests

| Test | Description | Assertion |
|---|---|---|
| `token_saver_deduplicates_and_audits` | Duplicate messages in prompt | deduped; audit records savings |
| `ansi_strip_end_to_end` | ANSI escapes in content | stripped when policy enables it |
| `rtk_collapse_repeated_lines_end_to_end` | Repeated lines in one message | collapsed to `[×N]` when enabled |
| `upstream_failure_releases_request_quota_reservation` | Upstream error after reservation | request quota reservation released |
| `rate_limit_429_through_router_carries_retry_after` | Burst over the limit | 429 with `Retry-After` header |

## Central admin API tests

### `crates/central/tests/provider_admin_api.rs` — 13 tests

Admin auth (401 without bearer token; 403 for non-admin group; 200
for members), provider CRUD round-trip, invalid-payload rejection (4xx),
404s for missing provider/key, exactly-one-default enforcement,
key-metadata-only responses, key 404s, invalid key bodies, cascade key
deletion, admin-audit-log recording, and blank-group rejection.

### `crates/central/tests/mcp_admin_api.rs` — 5 tests

`POST /admin/v1/mcp/servers` creates with the body `id`; missing body `id`
→ 400; `PUT /{id}` takes the id from the path and ignores the body id;
full server CRUD round-trip; responses never contain the `auth_header`.

## E2E tests (`tests/e2e/tests/e2e.rs`)

16 tests. `setup_full_system()` spins up in-process: mock backend + central
+ relay, all wired together. Mints a central token for identity `e2e-user`
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

## MCP E2E tests (`tests/e2e/tests/mcp_e2e.rs`)

13 tests. Same in-process harness plus a mock MCP server. Covers the
per-server endpoint, the combined hub, and the relay tunnel:

| Test | Description | Assertion |
|---|---|---|
| `allowed_tool_is_forwarded_and_audited` | Per-server `tools/call` in policy | forwarded; audit `mcp_*` fields set |
| `denied_tool_returns_403_and_is_denied_in_audit` | `tools/call` outside policy | 403 `-32001`; audit decision `denied` |
| `relay_requires_auth_for_mcp` | `/mcp*` without Authorization header | 401 |
| `per_server_endpoint_allows_non_tools_call_methods_under_specific_policy` | `initialize`/`tools/list` with ≥1 allowed tool | forwarded |
| `per_server_endpoint_denies_non_tools_call_methods_under_deny_all_policy` | Non-`tools/call` with deny-all policy | 403 |
| `relay_activity_records_mcp_metadata` | Activity log for `/mcp*` | `mcp_server`/`mcp_tool`/`mcp_method` recorded |
| `batch_jsonrpc_is_rejected_at_per_server_endpoint` | JSON-RPC array | 403 `-32001` |
| `batch_jsonrpc_is_rejected_at_hub_endpoint` | JSON-RPC array on `/mcp` | 200 `-32600` |
| `hub_tools_list_aggregates_prefixed_and_filters_by_policy` | Hub `tools/list` | `server__tool` names; policy-filtered |
| `hub_tools_call_routes_to_correct_upstream` | `server__tool` call | routed to the right mock server |
| `hub_tools_call_denies_tool_outside_policy` | Hub call outside policy | 403 |
| `hub_tools_call_rejects_unprefixed_tool_name` | Missing `server__` prefix | 400 `-32602` |
| `hub_requires_auth` | `/mcp` without Authorization header | 401 |

## Test cert generation

Integration and E2E tests use `oidc_agent_common::test_certs::generate_test_certs()`
(behind the `test-certs` feature, uses `rcgen`) to generate ephemeral CA,
server, and client certs. Private keys are written to temp files with
`0600` permissions (required by `mtls::enforce_secure_perms`).
