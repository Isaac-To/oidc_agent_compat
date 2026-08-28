# MCP Support

This server can expose **Model Context Protocol (MCP)** servers to your
agents, with **per-server, per-tool permissions** and **full audit logging**.

## What is MCP?

[MCP](https://modelcontextprotocol.io) is an open protocol that lets an agent
(e.g. Gemini CLI, Claude Desktop, Goose) call external tools from a server.
The agent speaks JSON-RPC 2.0 over the **Streamable HTTP** transport; the
server answers `initialize`, `tools/list`, `resources/*`, `prompts/*`, and
`tools/call` requests.

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
| **`http://127.0.0.1:<relay-port>/mcp`** | **The combined hub.** One MCP "server" that surfaces **all** tools from **all** centrally-hosted servers. **This is the one to configure in your agent.** |
| `http://127.0.0.1:<relay-port>/mcp/{server}` | A single, specific MCP server (the `id` you registered), for power users who want isolation. |

Because many upstream servers can expose tools with the same name, the hub
**prefixes every tool with its server id** using a double underscore:

```
github__list_files      # the `list_files` tool on server `github`
github__open_issue      # the `open_issue` tool on server `github`
```

The same `"server:tool"` pair is how you write policy keys — see below.

## Enabling MCP

MCP servers and per-group tool policies are configured at runtime through the
[Admin API](./admin-api.md) (there is nothing to add to the TOML config):

1. **Register an MCP server**
   `POST /admin/v1/mcp/servers` with `id`, `base_url`, and an optional
   `auth_header` (stored encrypted at rest).
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
| `allowed_tools: null` | Allow all tools on all servers |
| `allowed_tools: ["github:list_files"]` | Allow only `list_files` on server `github` (exposed as `github__list_files`) |
| User in multiple groups | Union of each group's allowlists (most permissive) |

If a member of any group has an allow-all (`NULL`) policy, allow-all wins.
Policy keys always use the colon form `"server:tool"` (what admins write).
The hub exposes the underscore form `server__tool` (what agents see), and the
two refer to the same underlying pair.

## Security

- **Deny by default**: a group with no MCP policy cannot call any tool.
- **Enforced on the central proxy** after mTLS + identity auth, so a
  compromised relay cannot bypass it.
- **Auth headers encrypted at rest** (AES-256-GCM with the master key),
  never logged, never sent to a laptop, never returned by any API.
- **Audit logging**: every MCP request records `mcp_server`, `mcp_tool`,
  `mcp_method`, the permission decision, and a **redacted, length-capped**
  preview of the tool arguments. Full arguments are never stored.
- Hop-by-hop headers are stripped (RFC 7230 §6.1) on both relay and central.