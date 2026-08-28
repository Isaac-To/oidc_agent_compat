//! Combined "hub" endpoint helpers.
//!
//! The relay exposes a single MCP endpoint (`/mcp`) that aggregates tools
//! from many upstream MCP servers into one namespace. To keep tool names
//! unambiguous when multiple servers expose the same tool name, each tool is
//! exposed under a **server-prefixed** name of the form
//! `{server}__{tool}` (for example `github__list_files`). This is the same
//! convention used by Gemini CLI's MCP hub.
//!
//! # Invariant
//!
//! Because the delimiter is the first `__`, a server id must never contain
//! `__`. The central proxy enforces this when registering servers.

/// The delimiter joining a server id and a tool name in the hub namespace.
pub const SERVER_TOOL_SEPARATOR: &str = "__";

/// Joins a server id and a tool name into the hub-prefixed name.
///
/// # Panics
///
/// Never panics; the caller is responsible for ensuring `server` does not
/// contain the separator (the registry validates this).
#[must_use]
pub fn join_tool_name(server: &str, tool: &str) -> String {
    format!("{server}{SERVER_TOOL_SEPARATOR}{tool}")
}

/// Splits a hub-prefixed tool name into `(server, tool)` on the first
/// separator. Returns `None` if no separator is present.
///
/// A tool name that itself contains `__` is preserved after the first
/// split (e.g. `fs__read__file` → `("fs", "read__file")`).
#[must_use]
pub fn split_tool_name(name: &str) -> Option<(&str, &str)> {
    match name.find(SERVER_TOOL_SEPARATOR) {
        Some(idx) => Some((&name[..idx], &name[idx + SERVER_TOOL_SEPARATOR.len()..])),
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joins_and_splits_round_trips() {
        let name = join_tool_name("github", "list_files");
        assert_eq!(name, "github__list_files");
        let (server, tool) = split_tool_name(&name).expect("split");
        assert_eq!(server, "github");
        assert_eq!(tool, "list_files");
    }

    #[test]
    fn splits_on_first_separator_only() {
        let (server, tool) = split_tool_name("fs__read__file").expect("split");
        assert_eq!(server, "fs");
        assert_eq!(tool, "read__file");
    }

    #[test]
    fn missing_separator_returns_none() {
        assert!(split_tool_name("no_separator_here_raw").is_none());
        assert!(split_tool_name("plain").is_none());
    }
}
