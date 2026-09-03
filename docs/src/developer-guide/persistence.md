# Persistence

Both the relay and central proxy use Sea-ORM with SQLite (or Postgres for
central in production). This page documents the database schemas,
migrations, and append-only enforcement.

## Relay database

### Migrations (`crates/relay/src/migration.rs`)

#### `m000001_initial_schema`

Creates two tables:

**`identities`**

| Column | Type | Null |
|---|---|---|
| `id` | string PK | no |
| `issuer` | string | no |
| `subject` | string | no |
| `email` | string | yes |
| `display_name` | string | yes |
| `groups` | string | yes |
| `created_at` | timestamptz | no |

**`api_keys`**

| Column | Type | Null |
|---|---|---|
| `id` | string PK | no |
| `identity_id` | string | no |
| `key_hash` | binary(32) | no |
| `label` | string | no |
| `created_at` | timestamptz | no |
| `last_used_at` | timestamptz | yes |

FK `fk_api_keys_identity_id` → `identities.id` `ON DELETE CASCADE`.

#### `m000002_relay_activity_log`

Creates `relay_activity_log` (see below) plus two triggers:

```sql
CREATE TRIGGER relay_activity_log_no_update
BEFORE UPDATE ON relay_activity_log
BEGIN
    SELECT RAISE(ABORT, 'relay_activity_log is append-only');
END;

CREATE TRIGGER relay_activity_log_no_delete
BEFORE DELETE ON relay_activity_log
BEGIN
    SELECT RAISE(ABORT, 'relay_activity_log is append-only');
END;
```

**`relay_activity_log`**

| Column | Type | Null |
|---|---|---|
| `id` | string PK | no |
| `identity_id` | string | no |
| `key_id` | string | no |
| `method` | string | no |
| `endpoint` | string | no |
| `model` | string | yes |
| `central_status` | integer | yes |
| `latency_ms` | bigint | no |
| `request_id` | string | yes |
| `created_at` | timestamptz | no |
| `mcp_server` | string | yes (m000004) |
| `mcp_tool` | string | yes (m000004) |
| `mcp_method` | string | yes (m000004) |

#### `m000003_api_key_expiry`

Adds nullable `expires_at` (timestamptz) to `api_keys`. Keys minted by
`oac-relay login` expire per `session_ttl_hours` (default 24h); an expired
key is rejected with `session_expired` and deleted on first use. The
dev-mode seeded key is exempt (`NULL` = no expiry).

#### `m000004_mcp_activity`

Adds nullable MCP columns `mcp_server`, `mcp_tool`, `mcp_method` to
`relay_activity_log` (see the table above), populated for `/mcp*` traffic.

### File permissions

On Unix, the SQLite file is tightened to `0600` via
`persistence::enforce_db_perms` so other local users can't read key
hashes.

---

## Central database

### Migrations (`crates/central/src/migration.rs`)

#### `m000001_initial_schema`

Creates:

**`devices`**

| Column | Type | Null |
|---|---|---|
| `id` | string PK | no |
| `cert_fingerprint` | string | no |
| `user_subject` | string | no |
| `user_email` | string | yes |
| `revoked` | boolean | no |
| `created_at` | timestamptz | no |
| `last_seen_at` | timestamptz | yes |

**`audit_log`** + append-only triggers (`audit_log_no_update`,
`audit_log_no_delete`):

| Column | Type | Null |
|---|---|---|
| `id` | string PK | no |
| `device_id` | string | no |
| `user_subject` | string | no |
| `model` | string | yes |
| `backend` | string | no |
| `status` | integer | no |
| `latency_ms` | bigint | no |
| `stream` | boolean | no |
| `prompt_tokens` | integer | yes |
| `completion_tokens` | integer | yes |
| `total_tokens` | integer | yes |
| `created_at` | timestamptz | no |

#### `m000002_audit_enrichment`

Adds nullable columns to `audit_log`:

| Column | Type |
|---|---|
| `identity_id` | string |
| `email` | string |
| `groups` | string |
| `endpoint` | string |
| `request_id` | string |
| `permission_decision` | string |
| `denial_reason` | string |
| `cost_usd` | real |

#### `m000003_group_policies`

Creates:

**`group_policies`**

| Column | Type | Null |
|---|---|---|
| `id` | string PK | no |
| `group_name` | string (unique) | no |
| `allowed_models` | string (JSON) | yes |
| `allowed_endpoints` | string (JSON) | yes |
| `daily_token_quota` | bigint | yes |
| `daily_request_quota` | bigint | yes |
| `created_at` | timestamptz | no |
| `updated_at` | timestamptz | no |

**`admin_audit_log`** + append-only triggers:

| Column | Type | Null |
|---|---|---|
| `id` | string PK | no |
| `admin_subject` | string | no |
| `action` | string | no |
| `target` | string | no |
| `payload` | string | yes |
| `created_at` | timestamptz | no |

#### `m000004_usage_counters`

Creates:

**`usage_counters`** (unique index on `(user_subject, period_date, period_kind)`)

| Column | Type | Null |
|---|---|---|
| `id` | string PK | no |
| `user_subject` | string | no |
| `group_name` | string | yes |
| `period_date` | string | no |
| `period_kind` | string | no |
| `request_count` | bigint | no |
| `token_count` | bigint | no |
| `cost_usd` | real | no |

#### `m000005_providers`

Creates the runtime provider/key registry:

- **`providers`** — `id`, `name`, `base_url`, `enabled`, `is_default`,
  `models` (nullable JSON array of model names this provider serves),
  `created_at`/`updated_at`.
- **`provider_keys`** — `id`, `provider_id` (FK `ON DELETE CASCADE`),
  `label`, `priority`, `key_ciphertext` + `key_nonce` (AES-256-GCM),
  `key_digest` (SHA-256, for rotation identification), `enabled`,
  `created_at`/`updated_at`.
- **`provider_key_access`** — optional group ACL rows per key: when rows
  exist, only members of the listed groups may use that key.

#### `m000006_token_saver`

Adds token-saver columns to `group_policies` (`token_saver_enabled`,
  `max_input_tokens`) and saver-accounting columns to `audit_log`
  (`token_saver_applied`, `tokens_saved`, `messages_dropped`,
  `saver_reasons`).

#### `m000007_collapse_repeated_lines`

Adds the opt-in `collapse_repeated_lines` toggle to `group_policies`.

#### `m000008_strip_ansi`

Adds the `strip_ansi` toggle to `group_policies` (pre-optimization ANSI
escape stripping).

#### `m000009_mcp`

Creates the MCP registry and policies:

- **`mcp_servers`** — `id`, `name`, `base_url`, `enabled`,
  `auth_ciphertext` + `auth_nonce` (AES-256-GCM), timestamps.
- **`mcp_server_policies`** — `group_name`, `allowed_tools` (JSON array
  of `"server:tool"` entries; `NULL` = allow-all).
- Adds MCP columns to `audit_log` (`mcp_server`, `mcp_tool`, `mcp_method`,
  `mcp_args_preview`).

---

## Append-only enforcement

Three tables are append-only, enforced by SQLite triggers that abort any
UPDATE or DELETE:

- `relay_activity_log` (relay DB)
- `audit_log` (central DB)
- `admin_audit_log` (central DB)

This makes the audit trail tamper-evident at the database level — even if
an attacker gains DB access, they cannot modify or delete audit entries
without dropping the triggers first.

## Sea-ORM entities

### Relay entities (`crates/relay/src/entity/`)

- `identity::Model` — `identities` table.
- `api_key::Model` — `api_keys` table. `key_hash` is `Binary(32)`.
- `relay_activity_log::Model` — `relay_activity_log` table.

### Central entities (`crates/central/src/entity/`)

- `device::Model` — `devices` table.
- `audit_log::Model` — `audit_log` table.
- `group_policy::Model` — `group_policies` table.
- `admin_audit_log::Model` — `admin_audit_log` table.
- `usage_counter::Model` — `usage_counters` table.
- `provider::Model` — `providers` table.
- `provider_key::Model` — `provider_keys` table (encrypted key material).
- `provider_key_access::Model` — `provider_key_access` table (group ACL).
- `mcp_server::Model` — `mcp_servers` table (encrypted auth header).
- `mcp_server_policy::Model` — `mcp_server_policies` table.

All entities derive `DeriveEntityModel`, have no relations (except
relay's `api_key` → `identity`), and use default `ActiveModelBehavior`.
