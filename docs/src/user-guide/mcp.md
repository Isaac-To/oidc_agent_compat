# MCP Support

This server can expose **Model Context Protocol (MCP)** servers to your
agents, with **per-server, per-tool permissions** and **full audit logging**.

## What is MCP?

[MCP](https://modelcontextprotocol.io) is an open protocol that lets an agent
(e.g. Gemini CLI, Claude Desktop, Goose) call external tools from a server.
The agent speaks JSON-RPC 2.0 over the **Streamable HTTP** transport. The two
endpoints this server exposes support different method sets:

- **The combined hub (`/mcp`)** handles only `tools/call`, `tools/list`,
  `initialize`, and `ping` (answered locally with an empty result), plus
  `notifications/*` (best-effort broadcast to reachable servers, HTTP `202`).
  Every other method — including `resources/list`, `resources/read`, and
  `prompts/list` — gets HTTP `200` with a JSON-RPC `-32601` "method not
  found" error.
- **The per-server endpoint (`/mcp/{server}`)** forwards all recognized
  request methods: `initialize`, `tools/list`, `tools/call`,
  `resources/list`, `resources/read`, `prompts/list`, and `ping`.

## Data flow

```
Agent ── MCP JSON-RPC over HTTP ──> relay (:8787) /mcp
  relay authenticates the user, adds identity headers
  ── mTLS ──> central proxy (:8443)
    central resolves the caller's group policy, fans out to the enabled
    upstream MCP servers it may reach, aggregates/prefixes tools, enforces
    per-tool allowlists, adds per-server auth headers
    ──> upstream MCP servers (configured in central)
```

- The relay simply tunnels the JSON-RPC bytes with verified identity headers.
- The central proxy **combines every centrally-hosted MCP server into one
  namespace**, enforces the per-team per-tool policy, and records an audit
  entry with the server, tool, method, and a redacted argument preview.

## Exposed endpoints

There are two ways to reach MCP from the relay:

| Endpoint | What it gives you |
|---|---|
| **`http://127.0.0.1:<relay-port>/mcp`** | **The combined hub.** One MCP "server" that surfaces the tools of all **enabled** centrally-hosted servers your policy allows. **This is the one to configure in your agent.** |
| `http://127.0.0.1:<relay-port>/mcp/{server}` | A single, specific MCP server (the `id` you registered), for power users who want isolation. Also the only endpoint that forwards `resources/*` and `prompts/*` methods. |

Because many upstream servers can expose tools with the same name, the hub
**prefixes every tool with its server id** using a double underscore:

```
github__list_files      # the `list_files` tool on server `github`
github__open_issue      # the `open_issue` tool on server `github`
```

The same `"server:tool"` pair is how you write policy keys — see below.

The hub route accepts `POST` only (`GET`/`DELETE` → `405`); the per-server
route accepts any HTTP method.

Hub tool names are split on the **first** `__`, so a tool whose own name
contains `__` (e.g. `fs__read__file` → server `fs`, tool `read__file`)
round-trips correctly; server ids containing `__` are rejected at
registration to keep the split unambiguous.

## Enabling MCP

MCP servers and per-group tool policies are configured at runtime through the
[Admin API](./admin-api.md) (there is nothing to add to the TOML config):

1. **Register an MCP server**
   `POST /admin/v1/mcp/servers` with a required non-empty `id` and `name`,
   a required `base_url`, optional `enabled` (defaults `true`), and an
   optional `auth_header` (stored encrypted at rest). Alternatively, create
   or replace a server with `PUT /admin/v1/mcp/servers/{id}`.
2. **Grant a group access to its tools**
   `PUT /admin/v1/mcp/policies/{group}` with `allowed_tools` like
   `["github:list_files"]`.

Then configure your agent to use **one** MCP server:

```
URL:      http://127.0.0.1:<relay-port>/mcp
Auth:     Authorization: Bearer <local key>
```

The local key is the same `Authorization: Bearer <local key>` obtained from
`oac-relay login`. Tool names shown by your agent will carry the
`server__` prefix.

## Permission model

| State | Effect |
|---|---|
| No policy for the group | **Deny all tools** (opt-in; the hub's `tools/list` returns nothing) |
| Caller with no groups | **Deny all** MCP access (deny-by-default) |
| `allowed_tools: null` | Allow all tools on all servers |
| `allowed_tools: ["github:list_files"]` | Allow only `list_files` on server `github` (exposed as `github__list_files`) |
| User in multiple groups | Union of each group's allowlists (most permissive) |

If a member of any group has an allow-all (`NULL`) policy, allow-all wins.
Policy keys always use the colon form `"server:tool"` (what admins write).
The hub exposes the underscore form `server__tool` (what agents see), and the
two refer to the same underlying pair.

Matching is **exact**: an `allowed_tools` entry must equal the full
`"server:tool"` string — no wildcards or prefixes.

On the per-server endpoint, non-`tools/call` request methods (`initialize`,
`tools/list`, `ping`, `resources/list`, `resources/read`, `prompts/list`)
are allowed only when the caller's groups have **at least one allowed tool**
on that server; a deny-all/empty allowlist or no policy yields `403`. These
requests are audited with the method recorded and no tool name.

## Batch requests

JSON-RPC **batch requests** (arrays) are rejected at both endpoints — a
batch could smuggle `tools/call` requests past per-tool permission
enforcement. The per-server endpoint answers `403` with JSON-RPC `-32001`
"batch JSON-RPC messages are not supported"; the hub answers HTTP `200`
with `-32600` "invalid request".

## Error codes

| Situation | Per-server `/mcp/{server}` | Hub `/mcp` |
|---|---|---|
| Malformed JSON-RPC body | `400` / `-32700` | `400` / `-32700` |
| Batch (array) request | `403` / `-32001` | `200` / `-32600` |
| Tool denied by policy | `403` / `-32001` "tool 'X' is not allowed on MCP server 'Y'" | same |
| Tool name missing the `{server}__` prefix | — | `400` / `-32602` |
| Unknown or disabled server | `404` / `-32602` | `404` / `-32602` |
| Upstream failure | `502` / `-32603` | `502` / `-32603` |
| Policy-store error (fails closed) | `403` / `-32001` "policy resolution failed" | same |
| Method not in the hub's set | forwarded upstream | `200` / `-32601` "method not found" |

## Security

- **Deny by default**: a group with no MCP policy — and any caller with no
  groups at all — cannot call any tool.
- **Enforced on the central proxy** after mTLS + identity auth, so a
  compromised relay cannot bypass it.
- **Auth headers encrypted at rest** (AES-256-GCM with the provider
  encryption key, `OAC_PROVIDER_ENCRYPTION_KEY`), decrypted into `Zeroizing`
  memory only during forwarding, never logged, never sent to a laptop, never
  returned by any API (only a `has_auth` flag).
- **Audit logging**: every MCP request records `mcp_server`, `mcp_tool`,
  `mcp_method`, the permission decision, and a **redacted, length-capped**
  preview of the tool arguments. The per-server endpoint records the server,
  tool, method, and decision for every request; the hub records the same for
  `tools/call` (with the real target server and the unprefixed tool name)
  and records the server as `"hub"` with no tool for hub-wide methods
  (`tools/list`, `initialize`, `ping`, unknown methods). In the preview,
  values of known-sensitive keys (`api_key`, `token`, `password`, `secret`,
  `authorization`, `credentials`, `private_key`, `client_secret`, …) are
  replaced with `"[REDACTED]"` and the whole preview is capped at 512
  characters (with a `…[truncated]` suffix). Full arguments are never stored.
- Hop-by-hop headers are stripped (RFC 7230 §6.1) on both relay and central.