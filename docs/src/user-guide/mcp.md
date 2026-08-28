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
Agent ── MCP JSON-RPC over HTTP ──> relay (:8787)
  relay authenticates the user, adds identity headers
  ── mTLS ──> central proxy (:8443)
    central checks the per-group MCP policy for the requested tool
    ──> upstream MCP server (configured in central)
```

- The relay simply tunnels the JSON-RPC bytes with verified identity headers.
- The central proxy resolves the caller's group policy, enforces the
  per-tool allowlist, adds any per-server auth header, and records an audit
  entry with the server, tool, method, and a redacted argument preview.

## Enabling MCP

MCP servers and per-group tool policies are configured at runtime through the
[Admin API](./admin-api.md) (there is nothing to add to the TOML config):

1. **Register an MCP server**
   `POST /admin/v1/mcp/servers` with `id`, `base_url`, and an optional
   `auth_header` (stored encrypted at rest).
2. **Grant a group access to its tools**
   `PUT /admin/v1/mcp/policies/{group}` with `allowed_tools` like
   `["fs:read_file"]`.

Your agent connects to `http://127.0.0.1:<relay-port>/mcp/{server}` using the
same `Authorization: Bearer <local key>` obtained from `oac-relay login`.

## Permission model

| State | Effect |
|---|---|
| No policy for the group | **Deny all tools** (opt-in) |
| `allowed_tools: null` | Allow all tools on all servers |
| `allowed_tools: ["fs:read_file"]` | Allow only `read_file` on server `fs` |
| User in multiple groups | Union of each group's allowlists (most permissive) |

If a member of any group has an allow-all (`NULL`) policy, allow-all wins.

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