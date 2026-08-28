# Admin API

The central proxy exposes an admin API at `/admin/v1/` for managing group
policies, providers, provider API keys, devices, audit logs, usage, and quotas. The admin API is only
mounted if `[admin]` is present in the central config.

## Authentication

Admin API requests are authenticated via the **same OIDC flow as regular
users** — there is no static admin token. The admin CLI sends requests
through the relay, which authenticates the user via OIDC and forwards
identity headers to the central proxy.

Authorization is enforced by the `admin_auth_middleware`:

1. Requires `x-oac-user-subject` header (non-empty) → else `401 Unauthorized`.
2. Parses `x-oac-user-groups` as a JSON array → if the configured
   `admin_group` is not in the user's groups → `403 Forbidden`.

This means the user must:
- Log in via `oac-relay login` (to get a local API key).
- Belong to the IdP group configured as `admin_group` (e.g. `oac-admins`).

## Endpoints

### Providers

Providers are runtime-managed. No provider URL or provider key is stored in
the central TOML configuration.

#### `GET /admin/v1/providers`

List providers. The response contains provider metadata and never contains
API-key material.

#### `POST /admin/v1/providers`

Create or update a provider.

```json
{
  "id": "openai",
  "name": "OpenAI",
  "base_url": "https://api.openai.com",
  "enabled": true,
  "is_default": true,
  "models": ["gpt-4o", "gpt-4o-mini"]
}
```

`models` is an exact model-name list. A provider with `models: null` is a
catch-all fallback. Model-specific providers take precedence over catch-all
providers. At most one provider is marked as the default.

#### `GET|PUT|DELETE /admin/v1/providers/{id}`

Get, update, or delete a provider. Deleting a provider also deletes its keys.
`PUT` uses the same fields as provider creation, except `id` is taken from the
path.

#### `POST /admin/v1/providers/{id}/default`

Mark an enabled provider as the default fallback.

### Provider keys

#### `GET /admin/v1/providers/{id}/keys`

List key metadata: key ID, label, priority, digest, enabled state, and allowed
groups. Plaintext and encrypted key material are never returned.

#### `POST /admin/v1/providers/{id}/keys`

Add a key. The plaintext is accepted once and encrypted with AES-256-GCM
before it is stored.

```json
{
  "key": "sk-provider-key",
  "label": "production-primary",
  "priority": 0,
  "allowed_groups": ["engineering"]
}
```

Keys are selected by ascending priority and creation time. An empty
`allowed_groups` list permits any authenticated user; otherwise at least one
of the user's IdP groups must match. On upstream `401` or `429`, central
tries the next authorized enabled key.

#### `PUT|DELETE /admin/v1/providers/{id}/keys/{key_id}`

Update key metadata/access rules or delete a key. Key plaintext cannot be
changed by `PUT`; add a replacement key for rotation.

### Group policies

#### `GET /admin/v1/group-policies`

List all group policies.

**Response:** `200` — JSON array of [`GroupPolicyResponse`](#grouppolicyresponse).

#### `GET /admin/v1/group-policies/{name}`

Get a single policy by group name.

**Response:** `200` — [`GroupPolicyResponse`](#grouppolicyresponse), or
`404` if not found.

#### `PUT /admin/v1/group-policies/{name}`

Create or update a policy.

**Request body** ([`UpsertPolicyRequest`](#upsertpolicyrequest)):

```json
{
  "allowed_models": ["gpt-4o", "gpt-4o-mini"],
  "allowed_endpoints": ["/v1/chat/completions"],
  "daily_token_quota": 1000000,
  "daily_request_quota": 1000,
  "token_saver_enabled": false,
  "max_input_tokens": null,
  "collapse_repeated_lines": false,
  "strip_ansi": false
}
```

All fields are optional (`null` means "all allowed" / "unlimited").
`token_saver_enabled` defaults to `false`; `max_input_tokens` must be a
positive integer when set. `collapse_repeated_lines` (default `false`)
enables the RTK-adapted pass that folds consecutive exact-verbatim repeated
lines inside a single message into `[×N]` markers. `strip_ansi` (default
`false`) enables removal of terminal ANSI colour/control codes from message
content.

**Response:** `200` — [`GroupPolicyResponse`](#grouppolicyresponse).

#### `DELETE /admin/v1/group-policies/{name}`

Delete a policy.

**Response:** `204` (no content), or `404` if not found.

### Devices

#### `GET /admin/v1/devices`

List all registered devices.

**Response:** `200` — JSON array of [`DeviceResponse`](#deviceresponse).

#### `POST /admin/v1/devices/{fingerprint}/revoke`

Revoke a device.

**Response:** `204` (no content), or `404` if not found.

#### `POST /admin/v1/devices/{fingerprint}/reinstate`

Reinstate a revoked device.

**Response:** `204` (no content), or `404` if not found.

### Audit

#### `GET /admin/v1/audit`

Query the audit log.

**Query parameters:**

| Param | Type | Default | Max |
|---|---|---|---|
| `subject` | `Option<String>` | — | — |
| `limit` | `Option<u32>` | `100` | `1000` (clamped) |
| `offset` | `Option<u32>` | `0` | — |

Results are ordered newest first. `offset` skips that many newest entries;
pagination is applied in the database rather than loading the entire audit
table.

**Response:** `200` — JSON array of audit entries with fields: `id`,
`user_subject`, `identity_id`, `email`, `groups`, `model`, `backend`,
`endpoint`, `request_id`, `status`, `latency_ms`, `stream`,
`prompt_tokens`, `completion_tokens`, `total_tokens`,
`permission_decision`, `denial_reason`, `cost_usd`, `created_at`
(formatted `YYYY-MM-DD HH:MM:SS`). When the token saver ran on a request,
entries also carry `token_saver_applied`, `tokens_saved`, `messages_dropped`,
and `saver_reasons`.

### Usage

#### `GET /admin/v1/usage`

Query usage counters.

**Query parameters:**

| Param | Type | Default |
|---|---|---|
| `subject` | `Option<String>` | — (all users) |

**Response:** `200` — JSON array of [`UsageResponse`](#usageresponse).

### Quotas

#### `GET /admin/v1/quotas/{subject}`

Get quota status for a user.

**Response:** `200` — [`QuotaResponse`](#quotaresponse).

The response includes the groups snapshot from the user's most recent usage
record and resolves `daily_request_quota` and `daily_token_quota` using the
same most-permissive-wins policy merge used for enforcement. If the user has
not made a request today, the groups are unknown and both quotas are `null`.

---

### MCP servers

MCP (Model Context Protocol) servers are runtime-managed, like providers.
No MCP server URL or auth header is stored in the central TOML configuration.

#### `GET /admin/v1/mcp/servers`

List configured MCP servers. Response bodies contain metadata only — never
any auth header.

#### `POST /admin/v1/mcp/servers`

Create or update an MCP server.

```json
{
  "id": "github",
  "name": "GitHub",
  "base_url": "https://mcp.example.com/mcp",
  "enabled": true,
  "auth_header": "Authorization: Bearer <token>"
}
```

`auth_header` is optional. When present it is attached to every request that
central forwards to this server and is **encrypted at rest** (AES-256-GCM)
with the master encryption key. It is never returned by any API and never
logged.

> **Naming constraint:** a server `id` must not contain `__` (double
> underscore). The hub reserves `__` as the separator between a server id
> and a tool name (`github__list_files`).

#### `GET|PUT|DELETE /admin/v1/mcp/servers/{id}`

Get, update, or delete an MCP server. `PUT` matches the `POST` body except
`id` is taken from the path. Deleting a server removes it from the registry;
existing per-group policies that reference it become inert.

### MCP policies

MCP policies grant a group permission to call specific tools on specific
MCP servers. Policy entries are written as **`"server:tool"`** (colon form).
When a user's agent uses the combined `/mcp` hub, the same tool is exposed
with a **`server__tool`** prefix; an admin's policy key and the agent's tool
name refer to the same pair.

#### `GET /admin/v1/mcp/policies/{group}`

Get a group's MCP policy.

**Response body:**
```json
{ "group_name": "engineering", "allowed_tools": ["github:list_files"] }
```

`allowed_tools: null` means **all tools allowed** on all configured servers.
`allowed_tools: []` means **no tools allowed**.

#### `PUT /admin/v1/mcp/policies/{group}`

Set (replace) a group's MCP policy.

```json
{ "allowed_tools": ["fs:read_file"] }
```

#### `DELETE /admin/v1/mcp/policies/{group}`

Delete the group's policy. A group with no policy and no allow-all policy on
a relevant group **cannot call any tools** (tools are deny-by-default).

---

## Response shapes

### `GroupPolicyResponse`

```json
{
  "group_name": "engineering",
  "allowed_models": ["gpt-4o", "gpt-4o-mini"],
  "allowed_endpoints": ["/v1/chat/completions"],
  "daily_token_quota": 1000000,
  "daily_request_quota": 1000,
  "token_saver_enabled": false,
  "max_input_tokens": null,
  "collapse_repeated_lines": false,
  "strip_ansi": false
}
```

| Field | Type | Notes |
|---|---|---|
| `group_name` | `String` | Group name |
| `allowed_models` | `Vec<String>` or `null` | `null` = all models allowed |
| `allowed_endpoints` | `Vec<String>` or `null` | `null` = all endpoints allowed |
| `daily_token_quota` | `i64` or `null` | `null` = unlimited |
| `daily_request_quota` | `i64` or `null` | `null` = unlimited |
| `token_saver_enabled` | `bool` | Whether the safe token saver is enabled |
| `max_input_tokens` | `i64` or `null` | Per-request budget; `null` = no trimming |
| `collapse_repeated_lines` | `bool` | RTK-adapted repeated-line collapse; `false` = off |
| `strip_ansi` | `bool` | ANSI colour/control-code stripping; `false` = off |

### `UpsertPolicyRequest`

```json
{
  "allowed_models": ["gpt-4o"],
  "allowed_endpoints": ["/v1/chat/completions"],
  "daily_token_quota": 1000000,
  "daily_request_quota": 1000,
  "token_saver_enabled": true,
  "max_input_tokens": 8000,
  "collapse_repeated_lines": true,
  "strip_ansi": true
}
```

All fields are optional (`null` = all/unlimited).

### Token saver

#### `GET /admin/v1/token-saver`

Aggregate token-saver engagement so admins can observe what the saver is
doing across groups.

**Response:** `200` — an object with:

```json
{
  "groups": [
    {
      "group": "engineering",
      "enabled": true,
      "max_input_tokens": 8000,
      "requests_optimized": 12,
      "tokens_saved": 3400,
      "messages_dropped": 24
    }
  ],
  "total_requests_optimized": 12,
  "total_tokens_saved": 3400,
  "total_messages_dropped": 24
}
```

`requests_optimized` counts audit rows where the saver applied; `tokens_saved`
and `messages_dropped` are sums across those rows. The `enabled` and
`max_input_tokens` fields reflect the *current* policy configuration. This
endpoint returns metrics only — never prompt content.

### `DeviceResponse`

```json
{
  "cert_fingerprint": "ab:cd:...",
  "user_subject": "user-123",
  "user_email": "user@example.com",
  "revoked": false
}
```

### `UsageResponse`

```json
{
  "user_subject": "user-123",
  "period_date": "2026-08-25",
  "request_count": 42,
  "token_count": 15000,
  "cost_usd": 0.0375
}
```

### `QuotaResponse`

```json
{
  "user_subject": "user-123",
  "groups": null,
  "daily_request_quota": null,
  "daily_token_quota": null,
  "request_count": 42,
  "token_count": 15000,
  "cost_usd": 0.0375
}
```

---

## Policy resolution

When a user makes a request, the central proxy resolves the user's
effective policy by merging all policies for the user's groups. The merge
semantics are **most-permissive-wins**:

- **Models**: union of all groups' allowed models. If any group has `null`
  (all allowed), the result is `null` (all allowed).
- **Endpoints**: union. If any group has `null`, the result is `null`.
- **Quotas**: `max` of all groups' quotas. If any group has `null`
  (unlimited), the result is `null` (unlimited).

If no policies exist for any of the user's groups, the default policy is
**all allowed, unlimited**.

---

## Admin audit logging

All mutations (`upsert_policy`, `delete_policy`, `revoke_device`,
`reinstate_device`) are recorded in the `admin_audit_log` table, which is
append-only (enforced by SQLite triggers that abort UPDATE/DELETE).

---

## CLI equivalents

All admin API operations are available via the `oac-central admin` CLI.
See [CLI Reference](./cli-reference.md#admin) for the full command list.
