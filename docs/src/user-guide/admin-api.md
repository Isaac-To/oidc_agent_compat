# Admin API

The central proxy exposes an admin API at `/admin/v1/` for managing group
policies, devices, audit logs, usage, and quotas. The admin API is only
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
  "daily_request_quota": 1000
}
```

All fields are optional (`null` means "all allowed" / "unlimited").

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

**Response:** `200` — JSON array of audit entries with fields: `id`,
`user_subject`, `identity_id`, `email`, `groups`, `model`, `backend`,
`endpoint`, `request_id`, `status`, `latency_ms`, `stream`,
`prompt_tokens`, `completion_tokens`, `total_tokens`,
`permission_decision`, `denial_reason`, `cost_usd`, `created_at`
(formatted `YYYY-MM-DD HH:MM:SS`).

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

> **Note:** `groups`, `daily_request_quota`, and `daily_token_quota` are
> always `null` in the response because the admin API doesn't receive the
> target user's groups. Only current usage counts are populated.

---

## Response shapes

### `GroupPolicyResponse`

```json
{
  "group_name": "engineering",
  "allowed_models": ["gpt-4o", "gpt-4o-mini"],
  "allowed_endpoints": ["/v1/chat/completions"],
  "daily_token_quota": 1000000,
  "daily_request_quota": 1000
}
```

| Field | Type | Notes |
|---|---|---|
| `group_name` | `String` | Group name |
| `allowed_models` | `Vec<String>` or `null` | `null` = all models allowed |
| `allowed_endpoints` | `Vec<String>` or `null` | `null` = all endpoints allowed |
| `daily_token_quota` | `i64` or `null` | `null` = unlimited |
| `daily_request_quota` | `i64` or `null` | `null` = unlimited |

### `UpsertPolicyRequest`

```json
{
  "allowed_models": ["gpt-4o"],
  "allowed_endpoints": ["/v1/chat/completions"],
  "daily_token_quota": 1000000,
  "daily_request_quota": 1000
}
```

All fields are optional (`null` = all/unlimited).

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
