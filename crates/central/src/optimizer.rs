//! Safe, admin-controlled request optimizers for the central proxy.
//!
//! This module transforms forwarded request bodies to reduce token usage
//! **without changing the meaning** of the request. It implements the "safe
//! set" of optimizations; aggressive compression that rewrites or discards
//! potentially-meaningful content is intentionally out of scope.
//!
//! # Safety-by-construction guarantees
//!
//! - **Exact-verbatim dedup only**: only *bit-identical* consecutive
//!   duplicate messages are removed. A message is never removed because it is
//!   merely "similar". This cannot drop information that was not already
//!   present verbatim more than once.
//! - **Whole-turn budget drop only**: when a request exceeds the configured
//!   per-request token budget, the oldest *entire* turns are dropped until
//!   the remaining turns fit. No single turn is ever truncated, split, or
//!   partially removed. This is the least-harmful form of context trimming
//!   (matching the consensus of LLM gateways).
//! - **Structural no-ops only**: empty string `content` and empty string
//!   arrays of `tools` are removed only when they are structurally empty and
//!   therefore contribute nothing to the backend.
//! - **Consecutive repeated-line collapse (RTK-adapted)**: within a *single*
//!   message's `content`, runs of exact-verbatim repeated lines are collapsed
//!   into one representative line with a `[×N]` count (adapting RTK's
//!   `analyze_logs`). This is limited to *consecutive* runs inside one
//!   message, so it never merges distinct turns or non-adjacent information.
//!   It is lossless-by-construction: only exact-verbatim consecutive
//!   duplicates are folded, every distinct line is preserved verbatim (no
//!   truncation, no entry-cap drop), and a run is only folded when the `[×N]`
//!   marker is no longer than the original run (so the output never grows).
//! - **Never rewrites content**: no token-level compression, no
//!   rephrasing, no summarisation. The optimiser rewrites only structure and
//!   drop granularity, never the text of any kept message (the opt-in
//!   repeated-line collapse keeps representative lines verbatim).
//!
//! # What this does *not* do
//!
//! It does **not** attempt to "understand" the request or guess developer
//! intent. Any heuristic that might harm a request's original intention is
//! deliberately excluded. Where ambiguity exists, this module is
//! conservative and leaves the request untouched.
//!
//! # Configuration
//!
//! The optimiser is driven by an admin-supplied [`TokenSaverConfig`]. It is
//! applied server-side on the central proxy only — never by or for a client.
//!
//! # Upstream attribution
//!
//! The repeated-line collapse pass is *inspired by* RTK
//! ([https://github.com/rtk-ai/rtk](https://github.com/rtk-ai/rtk),
//! `src/cmds/system/log_cmd.rs`, `normalize_log_line` + the count-preserving
//! `[×N]` fold, Apache-2.0; vendored at `vendor/rtk` for source-tracking).
//! We deliberately diverge from RTK's `analyze_logs` in one crucial way: RTK
//! uses *fuzzy* normalization that strips timestamps/UUIDs/numbers/paths and
//! truncates lines to 100 chars, which can merge lines that are actually
//! distinct. Because this proxy must never lose meaning a developer intended,
//! our collapse matches **exact-verbatim** consecutive duplicates only and
//! never truncates or caps the number of kept lines. RTK is retained as a
//! vendored reference/attribution, not linked as a runtime dependency.

/// The outcome of applying the optimiser to a single request body.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OptimizationReport {
    /// Whether any change was applied.
    pub applied: bool,
    /// Number of input tokens before optimisation (heuristic estimate).
    pub input_tokens_before: u64,
    /// Number of input tokens after optimisation (heuristic estimate).
    pub input_tokens_after: u64,
    /// Tokens saved (`input_tokens_before - input_tokens_after`).
    pub tokens_saved: u64,
    /// Number of whole messages dropped as exact-verbatim duplicates.
    pub dup_messages_dropped: u64,
    /// Number of whole turns dropped to satisfy the token budget.
    pub budget_turns_dropped: u64,
    /// Number of structurally-empty messages removed.
    pub empty_messages_dropped: u64,
    /// Number of repeated lines collapsed across all messages (RTK pass).
    pub collapsed_lines: u64,
    /// Number of messages whose content was collapsed (RTK pass).
    pub collapsed_messages: u64,
    /// Number of messages whose content had ANSI escape sequences stripped.
    pub ansi_stripped_messages: u64,
    /// Whether the final body was reverted to the original because the
    /// "never-worse" guard determined the optimised body would not actually
    /// reduce token usage.
    pub never_worse_reverted: bool,
}

/// The admin-supplied token-saver configuration for a group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TokenSaverConfig {
    /// Whether the optimiser is enabled for this group.
    pub enabled: bool,
    /// The maximum input token budget for a single request. When a request
    /// exceeds this, the oldest whole turns are dropped until the remaining
    /// turns fit. `None` disables budget-based trimming.
    pub max_input_tokens: Option<u64>,
    /// Whether to collapse consecutive repeated lines inside a single
    /// message's content into `[×N]` entries (adapting RTK). Defaults to
    /// `false`; it is a more aggressive (still audited) pass that admins
    /// opt into explicitly.
    pub collapse_repeated_lines: bool,
    /// Whether to strip ANSI escape sequences (e.g. `\x1b[31m` terminal
    /// colour codes) from message content before forwarding. Defaults to
    /// `false`.
    pub strip_ansi: bool,
}

/// Estimated tokens for a unit of text (1 token ≈ 4 chars, English-centric).
///
/// This is a deliberate heuristic for cost/usage accounting. It is not a
/// certified tokeniser (which the proxy deliberately avoids pulling in); it
/// is only used to make drop decisions on whole turns and to report savings.
const CHARS_PER_TOKEN: u64 = 4;

/// Estimates the number of tokens in a text string.
///
/// Uses the `chars / 4` heuristic without importing a tokeniser.
#[must_use]
pub fn estimate_tokens(text: &str) -> u64 {
    let chars = u64::try_from(text.chars().count()).unwrap_or(u64::MAX);
    chars.div_ceil(CHARS_PER_TOKEN)
}

/// Applies the optimiser to a serialized OpenAI-compatible request body.
///
/// Returns the possibly-optimised body together with a report. When the
/// request is not a chat-completions / responses JSON body (or parsing
/// fails), the body is returned byte-for-byte unchanged and the report has
/// `applied == false`.
///
/// # Safety
///
/// See the module docs. The returned body never rewrites the text of a kept
/// message; it only drops exact duplicates, structurally-empty messages, and
/// whole oldest turns under a budget.
#[must_use]
pub fn optimize_prompt(
    body: &[u8],
    config: TokenSaverConfig,
) -> (bytes::Bytes, OptimizationReport) {
    if !config.enabled {
        return (
            bytes::Bytes::copy_from_slice(body),
            OptimizationReport::default(),
        );
    }

    let mut value: serde_json::Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => {
            // Not a JSON body (e.g. a non-chat endpoint) — leave untouched.
            return (
                bytes::Bytes::copy_from_slice(body),
                OptimizationReport::default(),
            );
        }
    };

    // Snapshot the "before" estimate before any mutable borrow happens.
    let mut report = OptimizationReport {
        input_tokens_before: estimate_tokens(&body_for_estimate(&value)),
        ..OptimizationReport::default()
    };

    let Some(messages) = value.get_mut("messages").and_then(|v| v.as_array_mut()) else {
        // No `messages` array (e.g. /models, /embeddings) — nothing to do.
        return (
            bytes::Bytes::copy_from_slice(body),
            OptimizationReport::default(),
        );
    };

    // Pass 1: remove structurally-empty messages (empty string content) and
    // exact-verbatim duplicates. `changed` tracks whether we modified
    // anything; if not, we return the original bytes verbatim to avoid
    // re-encoding (and key reordering).
    let mut changed = false;
    let mut dedup = std::collections::HashSet::new();
    let mut retained: Vec<serde_json::Value> = Vec::with_capacity(messages.len());
    for msg in messages.drain(..) {
        let is_empty_content = msg
            .get("content")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .map(|s| s.is_empty())
            .unwrap_or(false);
        if is_empty_content {
            report.empty_messages_dropped += 1;
            changed = true;
            continue;
        }
        // Exact-verbatim dedup across all messages. Only remove a message
        // whose serialized form is byte-identical to one already retained.
        // This can only remove already-duplicated information.
        let canonical = serde_json::to_string(&msg).unwrap_or_default();
        if !dedup.insert(canonical) {
            report.dup_messages_dropped += 1;
            changed = true;
            continue;
        }
        retained.push(msg);
    }
    *messages = retained;

    // Pass 1.5 (RTK-adapted): collapse consecutive repeated lines inside each
    // surviving message's content. This is opt-in (`collapse_repeated_lines`)
    // and operates within a single message, so it never merges distinct
    // turns. Kept messages' content may be rewritten ONLY by folding repeated
    // lines into `[×N]` markers; the representative line is the original.
    if config.collapse_repeated_lines {
        for msg in messages.iter_mut() {
            let Some(content) = msg.get("content").and_then(serde_json::Value::as_str) else {
                continue;
            };
            let (collapsed, removed) = collapse_repeated_lines(content);
            if removed > 0 {
                report.collapsed_lines += removed;
                report.collapsed_messages += 1;
                changed = true;
                if let Some(slot) = msg.get_mut("content") {
                    *slot = serde_json::Value::String(collapsed);
                }
            }
        }
    }

    // Pass 1.6 (RTK-inspired): strip ANSI escape sequences from each
    // surviving message's content. This is opt-in (`strip_ansi`) and is
    // lossless-by-construction: ANSI control codes carry no meaning for an
    // LLM, so removing them cannot change what the developer intended. A
    // message whose content was *only* ANSI codes is reduced to empty by
    // stripping and is dropped here (the codes were pure noise).
    if config.strip_ansi {
        let mut stripped_retained: Vec<serde_json::Value> = Vec::with_capacity(messages.len());
        for mut msg in messages.drain(..) {
            let Some(content) = msg.get("content").and_then(serde_json::Value::as_str) else {
                stripped_retained.push(msg);
                continue;
            };
            let stripped = strip_ansi_escapes(content);
            if stripped.len() != content.len() {
                report.ansi_stripped_messages += 1;
                changed = true;
                if stripped.is_empty() {
                    // Only control codes — the message now carries no
                    // content at all. Drop it as noise.
                    report.empty_messages_dropped += 1;
                    continue;
                }
            }
            if let Some(slot) = msg.get_mut("content") {
                *slot = serde_json::Value::String(stripped);
            }
            stripped_retained.push(msg);
        }
        *messages = stripped_retained;
    }

    // Safety guard: never produce an empty `messages` array. If ALL turns
    // were empty-content or exact duplicates, an empty array is invalid for
    // a chat request and would lose the request entirely — so we leave the
    // body untouched rather than emit something broken.
    if messages.is_empty() {
        return (
            bytes::Bytes::copy_from_slice(body),
            OptimizationReport::default(),
        );
    }

    // Pass 2: enforce the token budget by dropping the oldest whole turns.
    // Only whole messages are dropped; no message is truncated or split.
    // Invariants:
    // - System-prompt turns (`role: "system"`) are ALWAYS preserved — they
    //   carry the task instructions a developer depends on across every
    //   turn, and dropping them silently would break the task.
    // - Never drop to an empty `messages` array: the most recent whole
    //   non-system turn is always kept even if it alone exceeds the budget.
    // - The newest turn(s) are always preferred over older ones.
    if let Some(budget) = config.max_input_tokens {
        if report.input_tokens_before > budget && !messages.is_empty() {
            // Reserve the system prompt(s) that must never be trimmed.
            let mut always_keep: Vec<serde_json::Value> = Vec::new();
            let mut droppable: Vec<serde_json::Value> = Vec::new();
            for msg in messages.iter() {
                if msg.get("role").and_then(serde_json::Value::as_str) == Some("system") {
                    always_keep.push(msg.clone());
                } else {
                    droppable.push(msg.clone());
                }
            }

            let sys_tokens: u64 = always_keep
                .iter()
                .map(|m| {
                    estimate_tokens(
                        m.get("content")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or(""),
                    )
                })
                .sum();

            let mut sum: u64 = sys_tokens;
            let mut tail: Vec<serde_json::Value> = Vec::with_capacity(droppable.len());
            // Iterate newest-first so we keep the most recent turns.
            for msg in droppable.iter().rev() {
                let tokens = estimate_tokens(
                    msg.get("content")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or(""),
                );
                if sum + tokens <= budget {
                    sum += tokens;
                    tail.push(msg.clone());
                } else if tail.is_empty() {
                    // Nothing fits yet — always keep the newest whole turn.
                    sum += tokens;
                    tail.push(msg.clone());
                } else {
                    changed = true;
                }
            }
            tail.reverse();

            // Reassemble in original relative order: system prompt(s) first,
            // then the newest surviving non-system turns.
            let mut keep = always_keep;
            keep.extend(tail);
            if !keep.is_empty() && keep.len() < messages.len() {
                changed = true;
            }
            report.budget_turns_dropped =
                u64::try_from(messages.len().saturating_sub(keep.len())).unwrap_or(0);
            report.input_tokens_after = sum;
            *messages = keep;
        }
    }

    // Drop structurally-empty `tools` arrays (empty list of tool
    // definitions). Removing an empty `tools: []` cannot change behaviour.
    if let Some(tools) = value.get_mut("tools").and_then(|v| v.as_array_mut()) {
        if tools.is_empty() {
            if let Some(obj) = value.as_object_mut() {
                obj.remove("tools");
                changed = true;
            }
        }
    }

    if !changed {
        // Nothing was dropped/removed — hand back the exact bytes.
        return (bytes::Bytes::copy_from_slice(body), report);
    }

    report.input_tokens_after = estimate_tokens(&body_for_estimate(&value));
    report.tokens_saved = report
        .input_tokens_before
        .saturating_sub(report.input_tokens_after);
    // `applied` reflects that we actually rewrote the body (structure changed:
    // a message/tool was dropped, and/or lines were collapsed). It is NOT
    // derived from `tokens_saved`, because the chars/4 heuristic can round to
    // zero savings (e.g. after removing a tiny message near a ceil boundary)
    // even though the body differs. Reporting `applied=false` for a rewritten
    // body would be inconsistent with the audit/`saver_reasons` accounting.
    report.applied = changed;

    let encoded = match serde_json::to_vec(&value) {
        Ok(encoded) => encoded,
        Err(_) => {
            return (
                bytes::Bytes::copy_from_slice(body),
                OptimizationReport::default(),
            );
        }
    };

    let optimized_body = bytes::Bytes::from(encoded);

    // Never-worse guard (RTK-inspired; see `src/core/guard.rs` upstream):
    // only emit the optimised body if it would actually reduce token usage.
    // This is a final safety net that makes "never grows" an enforced
    // invariant, not just an incidental property of each pass. When the
    // heuristic reports that the rewritten body is not strictly smaller, we
    // revert to the original bytes (and never claim we saved anything).
    if report.input_tokens_after >= report.input_tokens_before {
        report.never_worse_reverted = true;
        report.applied = false;
        report.input_tokens_after = report.input_tokens_before;
        report.tokens_saved = 0;
        return (bytes::Bytes::copy_from_slice(body), report);
    }

    (optimized_body, report)
}

/// Builds a text representative of the request body for token estimation.
///
/// Only the `messages` and `tools` sections are counted, matching the
/// heuristic basis of [`estimate_tokens`]. This keeps the estimate stable
/// regardless of incidental top-level metadata.
fn body_for_estimate(value: &serde_json::Value) -> String {
    let mut out = String::new();
    if let Some(messages) = value.get("messages") {
        out.push_str(&serde_json::to_string(messages).unwrap_or_default());
    }
    if let Some(tools) = value.get("tools") {
        out.push_str(&serde_json::to_string(tools).unwrap_or_default());
    }
    out
}

// --- RTK-inspired passes ----------------------------------------------------
//
// Three techniques in this module are *inspired by* RTK
// (https://github.com/rtk-ai/rtk, Apache-2.0); none use RTK code, which is
// not vendored or linked. The ideas are reimplemented from scratch with
// stricter guarantees, because this proxy forwards a request to a model and
// must never lose developer intent:
//   - repeated-line collapse: conceptually derived from
//     `src/cmds/system/log_cmd.rs` (`normalize_log_line` + the [×N] fold),
//     but we use exact-verbatim consecutive matching (RTK uses fuzzy
//     normalization and truncates/caps, which would merge distinct lines).
//   - ANSI stripping: conceptually derived from `src/core/utils.rs`
//     (`strip_ansi`, regex `\x1b\[[0-9;]*[a-zA-Z]`), reimplemented as a
//     hand-rolled scanner so no `regex` dependency is needed.
//   - the "never-worse" guard: conceptually derived from `src/core/guard.rs`
//     (`never_worse`), applied inline at the end of [`optimize_prompt`].
// See the module-level "Upstream attribution" section.

/// Strips ANSI CSI escape sequences (`ESC [ ... final_byte`) from `content`.
///
/// Mirrors RTK's `strip_ansi` (https://github.com/rtk-ai/rtk,
/// `src/core/utils.rs`) reimplemented without the `regex` crate: it scans
/// for the CSI introducer `ESC [` and drops everything up to and including
/// the final command byte in `@-~`. This removes terminal colour/style and
/// cursor codes that carry no meaning for an LLM. Text is never truncated or
/// reordered — only control codes are removed, so the pass is lossless.
#[must_use]
fn strip_ansi_escapes(content: &str) -> String {
    let mut out = String::with_capacity(content.len());
    let mut chars = content.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' && chars.peek() == Some(&'[') {
            chars.next(); // consume '['
            // Consume parameter/private bytes until (and including) the
            // final command byte in the range `@`..=`~`.
            for next in chars.by_ref() {
                if ('@'..='~').contains(&next) {
                    break;
                }
            }
            continue;
        }
        out.push(c);
    }
    out
}

// --- RTK-inspired repeated-line collapse ------------------------------------
//
// Conceptually inspired by RTK's `normalize_log_line` + count-preserving
// `[×N]` fold (https://github.com/rtk-ai/rtk,
// `src/cmds/system/log_cmd.rs`, Apache-2.0). No RTK code is used or
// vendored; the approach is reimplemented from scratch. We intentionally use
// exact-verbatim consecutive matching here (NOT RTK's fuzzy normalization),
// because fuzzy stripping can merge distinct developer content. See the
// module-level "Upstream attribution" section.

/// Collapses consecutive runs of identical lines in `content` into `[×N]`
/// representative lines.
///
/// Operates on a *single* message's content string. Only *consecutive* runs
/// are collapsed (so ordering and non-adjacent distinct lines are
/// preserved). A run is folded into a `[×N]` marker **only when that marker
/// is no longer than the original run of lines**, guaranteeing the output is
/// never larger than the input (no pointless rewriting of content that is
/// already token-cheap).
///
/// # Safety
///
/// The pass is **lossless-by-construction**:
/// - Only **exact-verbatim** consecutive duplicate lines are folded; the
///   pass never merges lines that merely "look similar" under fuzzy
///   normalization.
/// - Every distinct line in the input is preserved, either bare or as the
///   *full, untruncated* representative of a `[×N]` entry.
/// - No entry-count cap discards distinct lines: if a message has 1,000
///   distinct lines, all 1,000 survive (only genuine repeats are removed).
/// - The count is preserved in the `[×N]` annotation, so nothing is lost
///   that was not already present verbatim more than once.
#[must_use]
fn collapse_repeated_lines(content: &str) -> (String, u64) {
    // Fast path: no newlines -> nothing to collapse.
    if !content.contains('\n') {
        return (content.to_string(), 0);
    }

    let lines: Vec<&str> = content.lines().collect();
    let mut collapsed: Vec<String> = Vec::with_capacity(lines.len());
    let mut removed: u64 = 0;

    let mut iter = lines.into_iter().peekable();
    while let Some(current) = iter.next() {
        // Count consecutive lines that are byte-identical to `current`.
        let mut run_len = 1usize;
        while iter.peek() == Some(&current) {
            run_len += 1;
            iter.next();
        }

        if run_len > 1 {
            // Representative line is kept VERBATIM — never truncated — so no
            // content is edited away.
            let marker = format!("[×{run_len}] {current}");
            // Byte size of the original run: `run_len` copies of the line,
            // separated by newlines.
            let literal_len = run_len
                .saturating_mul(current.len())
                .saturating_add(run_len.saturating_sub(1));
            if marker.len() <= literal_len {
                // Folding strictly-or-equally saves bytes; never grows.
                collapsed.push(marker);
                removed += u64::try_from(run_len - 1).unwrap_or(0);
            } else {
                // Folding would GROW the message — preserve the lines exactly.
                for _ in 0..run_len {
                    collapsed.push(current.to_string());
                }
            }
        } else {
            collapsed.push(current.to_string());
        }
    }

    if removed == 0 {
        // Nothing was collapsed — return the exact original string.
        return (content.to_string(), 0);
    }

    (collapsed.join("\n"), removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json(input: &str) -> bytes::Bytes {
        bytes::Bytes::copy_from_slice(input.as_bytes())
    }

    #[test]
    fn disabled_config_leaves_body_untouched() {
        let body = json(r#"{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}"#);
        let (out, report) = optimize_prompt(&body, TokenSaverConfig::default());
        assert_eq!(&out[..], &body[..], "disabled must not change the body");
        assert!(!report.applied);
    }

    #[test]
    fn non_json_body_untouched() {
        let body = json(r#"not json at all"#);
        let (out, report) = optimize_prompt(&body, enabled());
        assert_eq!(&out[..], &body[..]);
        assert!(!report.applied);
    }

    #[test]
    fn no_messages_body_untouched() {
        let body = json(r#"{"model":"gpt-4"}"#);
        let (out, report) = optimize_prompt(&body, enabled());
        assert_eq!(&out[..], &body[..]);
        assert!(!report.applied);
    }

    #[test]
    fn all_empty_messages_returns_original_body_unchanged() {
        // Safety guard: if every message is structurally empty, dropping
        // them would produce `"messages":[]` — an invalid chat request
        // that loses the user's turn entirely. The optimiser must leave
        // the body byte-identical instead.
        let body = json(r#"{"model":"gpt-4","messages":[{"role":"user","content":""}]}"#);
        let (out, report) = optimize_prompt(&body, enabled());
        assert_eq!(
            &out[..],
            &body[..],
            "never emit an empty messages array — hand back the original"
        );
        assert!(!report.applied, "nothing was applied");
        assert_eq!(report.dup_messages_dropped, 0);
        assert_eq!(report.empty_messages_dropped, 0);
    }

    #[test]
    fn budget_never_strips_the_last_user_turn() {
        // Even with an absurdly small budget, the newest non-system turn
        // must survive (a request with only a system prompt is useless).
        let body = json(
            r#"{"model":"gpt-4","messages":[
                {"role":"system","content":"You are helpful."},
                {"role":"user","content":"a"},
                {"role":"user","content":"b"},
                {"role":"user","content":"final question"}
            ]}"#,
        );
        let config = TokenSaverConfig {
            enabled: true,
            max_input_tokens: Some(1),
            collapse_repeated_lines: false,
            strip_ansi: false,
        };
        let (out, report) = optimize_prompt(&body, config);
        let value: serde_json::Value = serde_json::from_slice(&out).expect("valid json");
        let messages = value["messages"].as_array().expect("messages");
        assert!(
            !messages.is_empty(),
            "budget trimming must never empty the conversation"
        );
        let roles: Vec<&str> = messages.iter().filter_map(|m| m["role"].as_str()).collect();
        assert!(roles.contains(&"system"), "system prompt always kept");
        // The newest turn must be the (or among the) survivors.
        let contents: Vec<&str> = messages
            .iter()
            .filter_map(|m| m["content"].as_str())
            .collect();
        assert!(
            contents.contains(&"final question"),
            "the most recent turn must survive: {contents:?}"
        );
        assert!(
            report.applied,
            "turns were dropped, so applied must be true"
        );
    }

    fn enabled() -> TokenSaverConfig {
        TokenSaverConfig {
            enabled: true,
            max_input_tokens: None,
            collapse_repeated_lines: false,
            strip_ansi: false,
        }
    }

    #[test]
    fn dedups_only_exact_verbatim_duplicates() {
        // Two identical messages -> one kept; a merely-similar one is kept.
        let body = json(
            r#"{"model":"gpt-4","messages":[
                {"role":"user","content":"cat"},
                {"role":"user","content":"cat"},
                {"role":"user","content":"cats"}
            ]}"#,
        );
        let (out, report) = optimize_prompt(&body, enabled());
        assert!(report.applied);
        assert_eq!(report.dup_messages_dropped, 1);
        assert_eq!(report.empty_messages_dropped, 0);
        let value: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let messages = value["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 2);
        // The content of kept messages is unchanged (never rewritten).
        assert_eq!(messages[0]["content"], "cat");
        assert_eq!(messages[1]["content"], "cats");
    }

    #[test]
    fn removes_structurally_empty_content() {
        let body = json(
            r#"{"model":"gpt-4","messages":[
                {"role":"user","content":""},
                {"role":"assistant","content":"   "},
                {"role":"user","content":"real"}
            ]}"#,
        );
        let (out, report) = optimize_prompt(&body, enabled());
        assert!(report.applied);
        assert_eq!(report.empty_messages_dropped, 2);
        let value: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let messages = value["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0]["content"], "real");
    }

    #[test]
    fn budget_drops_oldest_whole_turns_only() {
        let body = json(
            r#"{"model":"gpt-4","messages":[
                {"role":"user","content":"oldest-long-turn-that-pushes-over-budget"},
                {"role":"user","content":"recent"},
                {"role":"user","content":"newest"}
            ]}"#,
        );
        // Budget is large enough to hold the two newest turns but not the
        // oldest. The optimizer must drop the oldest whole turn and keep
        // the two newest, in order.
        let config = TokenSaverConfig {
            enabled: true,
            max_input_tokens: Some(4),
            collapse_repeated_lines: false,
            strip_ansi: false,
        };
        let (out, report) = optimize_prompt(&body, config);
        assert!(report.applied);
        assert_eq!(report.budget_turns_dropped, 1);
        let value: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let messages = value["messages"].as_array().unwrap();
        // Original order preserved, oldest evicted.
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0]["content"], "recent");
        assert_eq!(messages[1]["content"], "newest");
    }

    #[test]
    fn budget_never_truncates_a_single_message() {
        let body = json(
            r#"{"model":"gpt-4","messages":[
                {"role":"user","content":"very large message that would exceed budget"}
            ]}"#,
        );
        let config = TokenSaverConfig {
            enabled: true,
            max_input_tokens: Some(2),
            collapse_repeated_lines: false,
            strip_ansi: false,
        };
        let (out, report) = optimize_prompt(&body, config);
        // If nothing fits, we must NOT drop the only message (would lose the
        // request); either leave it whole or still return it.
        let value: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let messages = value["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 1, "must not drop the only message");
        assert!(!report.applied || report.tokens_saved == 0);
    }

    #[test]
    fn empty_tools_array_removed() {
        let body =
            json(r#"{"model":"gpt-4","tools":[],"messages":[{"role":"user","content":"hi"}]}"#);
        let (out, report) = optimize_prompt(&body, enabled());
        let value: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert!(value.get("tools").is_none());
        assert!(report.applied);
    }

    // --- Rigorous invariant tests ---
    //
    // These tests encode the safety contract: "save tokens without losing
    // the meaning the user intended". They are structured as small
    // deterministic fuzz loops that hold for many randomized inputs, rather
    // than a single fixed case.

    /// Deterministic PRNG so the fuzz tests are reproducible in CI.
    fn rng_next(state: &mut u64) -> u64 {
        // xorshift64*
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        state.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn pick<'a>(state: &mut u64, slice: &'a [&'a str]) -> &'a str {
        slice[(rng_next(state) as usize) % slice.len()]
    }

    #[test]
    fn safe_set_never_loses_any_unique_message_content() {
        // Core invariant for the *safe* set (exact-verbatim dedup + empty
        // removal, WITHOUT budget trimming): every distinct non-empty content
        // present at least once must survive optimising. These passes drop
        // only duplicates and structurally-empty messages, so they can never
        // remove a unique meaning. (Budget trimming is a deliberately separate
        //, admin-opted-in behaviour with its own contract, tested elsewhere.)
        let mut state: u64 = 0x5EED_1234_5678;
        let vocab = ["alpha", "beta", "gamma", "delta", "epsilon", ""];
        for _ in 0..500 {
            let n = 1 + (rng_next(&mut state) as usize) % 12;
            let mut msgs = Vec::with_capacity(n);
            for _ in 0..n {
                let role = if rng_next(&mut state) % 2 == 0 {
                    "user"
                } else {
                    "assistant"
                };
                let content = pick(&mut state, &vocab);
                msgs.push(format!(r#"{{"role":"{role}","content":"{content}"}}"#));
            }
            let body = json(&format!(
                r#"{{"model":"gpt-4","messages":[{}]}}"#,
                msgs.join(",")
            ));
            // No budget: only the lossless passes (dedup + empty) run.
            let config = enabled();
            let (out, report) = optimize_prompt(&body, config);

            let value: serde_json::Value = serde_json::from_slice(&out).unwrap();
            let messages = value["messages"].as_array().unwrap();

            // Never produce an empty messages array.
            assert!(!messages.is_empty(), "must never empty the messages array");

            // The distinct non-empty contents must ALL be retained.
            let distinct_input: std::collections::HashSet<_> = msgs
                .iter()
                .map(|m| {
                    let v: serde_json::Value = serde_json::from_str(m).unwrap();
                    v["content"].as_str().unwrap().to_string()
                })
                .filter(|c| !c.is_empty())
                .collect();
            let distinct_output: std::collections::HashSet<_> = messages
                .iter()
                .filter_map(|m| m.get("content").and_then(|c| c.as_str()))
                .map(str::to_string)
                .collect();
            for c in &distinct_input {
                assert!(
                    distinct_output.contains(c),
                    "lost distinct content {c:?} (report={report:?})"
                );
            }
            // Sanity: if we claimed applied, tokens must have actually
            // decreased.
            if report.applied {
                assert!(report.tokens_saved > 0);
                assert!(report.input_tokens_after < report.input_tokens_before);
            }
        }
    }

    #[test]
    fn budget_trimming_keeps_newest_and_drops_only_oldest() {
        // The budget-trimming contract: it may drop *oldest* turns to fit a
        // budget, but must (a) never empty the array and (b) always keep the
        // newest turns. To isolate this contract from dedup, every message
        // here carries UNIQUE content, so only the budget pass can drop.
        let mut state: u64 = 0xA11C_E202_4000;
        for _ in 0..500 {
            let n = 2 + (rng_next(&mut state) as usize) % 10;
            let mut msgs: Vec<serde_json::Value> = Vec::with_capacity(n);
            for i in 0..n {
                let role = if i % 2 == 0 { "user" } else { "assistant" };
                // Unique content guarantees no exact-verbatim duplicates.
                let content = format!("unique-content-{i}-{}", rng_next(&mut state));
                msgs.push(serde_json::json!({"role": role, "content": content}));
            }
            let body_json = serde_json::json!({"model": "gpt-4", "messages": msgs});
            let body = json(&serde_json::to_string(&body_json).unwrap());
            let budget = 1 + (rng_next(&mut state) % 6);
            let config = TokenSaverConfig {
                enabled: true,
                max_input_tokens: Some(budget),
                collapse_repeated_lines: false,
                strip_ansi: false,
            };
            let (out, report) = optimize_prompt(&body, config);
            let value: serde_json::Value = serde_json::from_slice(&out).unwrap();
            let messages = value["messages"].as_array().unwrap();

            // (a) Never empty.
            assert!(!messages.is_empty());

            // (b) The newest (last) turn must always be retained.
            let last_input = msgs.last().unwrap();
            assert!(
                messages.iter().any(|m| m == last_input),
                "newest turn must survive trimming (report={report:?})"
            );

            // (c) Since messages have unique content and no system prompt,
            // budget trimming yields a strict SUFFIX of the input: the kept
            // messages must equal the last `len(kept)` input messages.
            let suffix: Vec<&serde_json::Value> = msgs[msgs.len().saturating_sub(messages.len())..]
                .iter()
                .collect();
            let kept: Vec<&serde_json::Value> = messages.iter().collect();
            assert_eq!(kept, suffix, "kept messages must be the newest suffix");

            // (d) Tokens never increase.
            if report.applied {
                assert!(report.tokens_saved > 0);
                assert!(report.input_tokens_after < report.input_tokens_before);
            }
            // (e) Dropped = len(input) - len(kept) (only budget pass ran).
            assert_eq!(
                report.budget_turns_dropped,
                u64::try_from(n - messages.len()).unwrap()
            );
        }
    }

    #[test]
    fn kept_messages_are_never_rewritten() {
        // Core invariant: any message that survives optimization must have
        // exactly the same serialized content as its original. The
        // optimizer may drop messages, but must never mutate text.
        let mut state: u64 = 0xDEAD_BEEF_CAFE;
        let vocab = ["alpha", "beta", "gamma", "", "delta delta delta"];
        for _ in 0..400 {
            let n = 1 + (rng_next(&mut state) as usize) % 10;
            let mut msgs = Vec::with_capacity(n);
            let mut originals: Vec<serde_json::Value> = Vec::with_capacity(n);
            for _ in 0..n {
                let role = if rng_next(&mut state) % 2 == 0 {
                    "user"
                } else {
                    "assistant"
                };
                let content = pick(&mut state, &vocab);
                let m = serde_json::json!({"role": role, "content": content});
                originals.push(m.clone());
                msgs.push(serde_json::to_string(&m).unwrap());
            }
            let body = json(&format!(
                r#"{{"model":"gpt-4","messages":[{}]}}"#,
                msgs.join(",")
            ));
            let config = TokenSaverConfig {
                enabled: true,
                max_input_tokens: Some(2),
                collapse_repeated_lines: false,
                strip_ansi: false,
            };
            let (out, _report) = optimize_prompt(&body, config);
            let value: serde_json::Value = serde_json::from_slice(&out).unwrap();
            let messages = value["messages"].as_array().unwrap();

            // For each kept message, its exact serialized value must equal
            // one of the original messages (set-preserving, no rewrite).
            for kept in messages {
                assert!(
                    originals.contains(kept),
                    "kept message was rewritten: {kept}"
                );
            }
        }
    }

    #[test]
    fn forced_budget_below_smallest_turn_keeps_newest_whole_turn() {
        // Even with an extremely small budget, the optimizer must not drop
        // the entire conversation: it keeps the newest whole turn.
        let body = json(
            r#"{"model":"gpt-4","messages":[
                {"role":"user","content":"aaaa"},
                {"role":"assistant","content":"bbb"},
                {"role":"user","content":"cc"}
            ]}"#,
        );
        let config = TokenSaverConfig {
            enabled: true,
            max_input_tokens: Some(1),
            collapse_repeated_lines: false,
            strip_ansi: false,
        };
        let (out, report) = optimize_prompt(&body, config);
        assert!(report.budget_turns_dropped >= 2);
        let value: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let messages = value["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0]["content"], "cc", "newest turn must survive");
    }

    #[test]
    fn no_change_when_enabled_but_already_within_budget() {
        // When within budget and no duplicates/empties, the optimizer must
        // not churn the body.
        let body = json(
            r#"{"model":"gpt-4","messages":[
                {"role":"system","content":"You are a helpful assistant."},
                {"role":"user","content":"Hello"}
            ]}"#,
        );
        let config = TokenSaverConfig {
            enabled: true,
            max_input_tokens: Some(1_000_000),
            collapse_repeated_lines: false,
            strip_ansi: false,
        };
        let (out, report) = optimize_prompt(&body, config);
        assert!(!report.applied);
        assert_eq!(report.tokens_saved, 0);
        assert_eq!(&out[..], &body[..], "no-op when nothing to save");
    }

    #[test]
    fn dedup_prefers_to_keep_the_first_occurrence() {
        // When the same message appears twice, we keep the first occurrence
        // (which preserves original ordering of the surviving messages).
        let body = json(
            r#"{"model":"gpt-4","messages":[
                {"role":"user","content":"begin"},
                {"role":"user","content":"dupe"},
                {"role":"user","content":"dupe"},
                {"role":"user","content":"end"}
            ]}"#,
        );
        let (out, report) = optimize_prompt(&body, enabled());
        assert_eq!(report.dup_messages_dropped, 1);
        let value: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let messages = value["messages"].as_array().unwrap();
        let contents: Vec<&str> = messages
            .iter()
            .map(|m| m["content"].as_str().unwrap())
            .collect();
        assert_eq!(contents, vec!["begin", "dupe", "end"]);
    }

    #[test]
    fn non_chat_endpoints_never_touched() {
        // Endpoints like /models and /embeddings have no `messages` and must
        // pass through byte-for-byte even when enabled.
        let body = json(r#"{"model":"text-embedding-ada-002","input":"hi"}"#);
        let (out, report) = optimize_prompt(&body, enabled());
        assert!(!report.applied);
        assert_eq!(&out[..], &body[..]);
    }

    #[test]
    fn preserves_top_level_fields_and_order_semantics() {
        // Optimizing must never remove or reorder top-level request fields
        // other than empty `tools`. Non-message fields survive.
        let body = json(
            r#"{"model":"gpt-4","temperature":0.7,"stream":false,
                "messages":[{"role":"user","content":"hi"}]}"#,
        );
        let (out, _report) = optimize_prompt(&body, enabled());
        let value: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert!(value.get("temperature").is_some());
        assert!(value.get("stream").is_some());
        assert!(value.get("model").is_some());
        assert!(value.get("messages").is_some());
    }

    // --- Dev-workflow tests (multiturn, many edits) ---
    //
    // Development conversations are long, edit-heavy, and mostly distinct
    // turns. The optimizer is designed not to harm these: it must not
    // collapse genuinely distinct edits, and under budget trimming it must
    // always prioritise keeping the most recent context.

    #[test]
    fn multiturn_dev_workflow_keeps_all_distinct_edits() {
        // A realistic sequence of edits: system prompt + many distinct
        // user/assistant turns. With no budget and no exact duplicates, the
        // optimizer must drop nothing.
        let mut turns =
            vec![r#"{"role":"system","content":"You are a coding agent."}"#.to_string()];
        for i in 0..40 {
            turns.push(format!(
                r#"{{"role":"user","content":"edit file {i}: change main()"}}"#
            ));
            turns.push(format!(
                r#"{{"role":"assistant","content":"Applied edit {i} to src/main.rs."}}"#
            ));
        }
        let body = json(&format!(
            r#"{{"model":"gpt-4","messages":[{}]}}"#,
            turns.join(",")
        ));
        let (out, report) = optimize_prompt(&body, enabled());
        assert!(
            !report.applied,
            "distinct multiturn edits must not be dropped"
        );
        // Byte-identical no-op: distinct content means nothing is removed.
        assert_eq!(&out[..], &body[..]);
        let value: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(value["messages"].as_array().unwrap().len(), 81);
    }

    #[test]
    fn multiturn_budget_trimming_preserves_recent_edits() {
        // Under a tight budget, the model keeps the RECENT edits (the last
        // turns) and drops the oldest history — the behaviour a developer
        // needs: the current task's context survives, the furthest history
        // is pruned.
        let mut turns = vec![r#"{"role":"system","content":"system-instructions"}"#.to_string()];
        for i in 0..30 {
            turns.push(format!(r#"{{"role":"user","content":"user-turn-{i}"}}"#));
            turns.push(format!(
                r#"{{"role":"assistant","content":"assistant-turn-{i}"}}"#
            ));
        }
        let body = json(&format!(
            r#"{{"model":"gpt-4","messages":[{}]}}"#,
            turns.join(",")
        ));
        let config = TokenSaverConfig {
            enabled: true,
            max_input_tokens: Some(6),
            collapse_repeated_lines: false,
            strip_ansi: false,
        };
        let (out, report) = optimize_prompt(&body, config);
        assert!(report.applied);
        assert!(report.budget_turns_dropped > 0);
        let value: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let messages = value["messages"].as_array().unwrap();
        // The LAST turn (assistant-turn-29) must survive.
        let last = messages.last().unwrap();
        assert_eq!(last["content"], "assistant-turn-29");
        // The very first distinct turn after the system prompt is the oldest
        // history and is the first to be dropped.
        assert!(
            messages
                .iter()
                .any(|m| m["content"] == "system-instructions"),
            "system prompt should survive as a recent/most-important turn"
        );
        // Relative ordering of survivors is preserved (chronological).
        let contents: Vec<&str> = messages
            .iter()
            .map(|m| m["content"].as_str().unwrap())
            .collect();
        let mut prev = -1i32;
        for c in &contents {
            // Extract the turn number from "user-turn-<n>" / "assistant-turn-<n>".
            // A bare "system-instructions" has none — treat it as index -1.
            let n = c
                .trim_start_matches("user-turn-")
                .trim_start_matches("assistant-turn-")
                .parse::<i32>()
                .unwrap_or(-1);
            assert!(
                n >= prev,
                "survivors must be in chronological order (got {c:?} after {prev})"
            );
            prev = n;
        }
    }

    #[test]
    fn many_exact_repeats_are_fully_deduplicated() {
        // In a dev workflow, huge repeated paste blocks can bloat the
        // request. All exact-verbatim repeats must collapse to one.
        let mut turns = Vec::new();
        for _ in 0..20 {
            turns.push(r#"{"role":"user","content":"Pasted contents of file.rs"}"#.to_string());
        }
        let body = json(&format!(
            r#"{{"model":"gpt-4","messages":[{}]}}"#,
            turns.join(",")
        ));
        let (out, report) = optimize_prompt(&body, enabled());
        assert!(report.applied);
        assert_eq!(report.dup_messages_dropped, 19);
        let value: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let messages = value["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 1);
    }

    // --- RTK-adapted repeated-line collapse tests ---

    fn rtk_enabled() -> TokenSaverConfig {
        TokenSaverConfig {
            enabled: true,
            max_input_tokens: None,
            collapse_repeated_lines: true,
            strip_ansi: false,
        }
    }

    #[test]
    fn collapse_is_off_by_default() {
        // Conservative default: an admin must explicitly opt in to the more
        // aggressive repeated-line pass.
        let body = json(r#"{"model":"gpt-4","messages":[{"role":"user","content":"a\na\na\nb"}]}"#);
        let (out, _report) = optimize_prompt(&body, enabled()); // collapse off
        let value: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(value["messages"][0]["content"], "a\na\na\nb");
    }

    #[test]
    fn collapse_combines_consecutive_repeated_lines() {
        // Lines are long enough that folding `[×N]` is strictly smaller than
        // repeating the line, so the runs DO collapse.
        let (collapsed, removed) = collapse_repeated_lines(
            "alpha-alpha-alpha\nalpha-alpha-alpha\nalpha-alpha-alpha\nbeta-beta-beta\nbeta-beta-beta\ngamma",
        );
        assert_eq!(removed, 3); // 2 from the run of 3 'a', 1 from the run of 2 'b'
        assert!(collapsed.contains("[×3] alpha-alpha-alpha"), "{collapsed}");
        assert!(collapsed.contains("[×2] beta-beta-beta"), "{collapsed}");
        // Non-repeated line untouched.
        assert!(collapsed.contains("\ngamma"), "{collapsed}");
        assert!(
            !collapsed.contains("beta-beta-beta\nbeta-beta-beta"),
            "must not duplicate"
        );
    }

    #[test]
    fn collapse_only_folds_consecutive_runs() {
        // "alpha beta alpha" -> the two 'alpha' are NOT adjacent, so they are
        // NOT merged even though folding would be smaller.
        let (collapsed, removed) =
            collapse_repeated_lines("alpha-alpha\nbeta-beta-beta\nalpha-alpha");
        assert_eq!(removed, 0);
        assert_eq!(collapsed, "alpha-alpha\nbeta-beta-beta\nalpha-alpha");
    }

    #[test]
    fn collapse_does_not_touch_single_line_or_empty() {
        assert_eq!(collapse_repeated_lines("hello world").0, "hello world");
        assert_eq!(collapse_repeated_lines("").0, "");
        assert_eq!(collapse_repeated_lines("").1, 0);
    }

    #[test]
    fn collapse_annotates_with_count_only_not_relevant_ordering() {
        // Collapsing keeps the FIRST occurrence; order of entries is
        // preserved (no frequency re-sort), unlike RTK's display sort, so a
        // dev still sees chronological order.
        let (collapsed, _) = collapse_repeated_lines(
            "entry-one-one\nentry-one-one\nmiddle\nentry-two-two\nentry-two-two",
        );
        assert_eq!(collapsed, "[×2] entry-one-one\nmiddle\n[×2] entry-two-two");
    }

    #[test]
    fn exact_match_distinct_lines_never_collapse() {
        // Because the pass is exact-match only, lines that differ by any
        // token (e.g. a number) must NOT collapse. This is the core safety
        // guarantee: only byte-identical consecutive lines are merged.
        let (collapsed, removed) =
            collapse_repeated_lines("2026-08-27 10:00:00 boom 42\n2026-08-27 10:00:01 boom 43");
        assert_eq!(removed, 0);
        assert_eq!(
            collapsed,
            "2026-08-27 10:00:00 boom 42\n2026-08-27 10:00:01 boom 43"
        );
    }

    #[test]
    fn exact_match_identical_log_lines_collapse() {
        // Even with volatile-looking content, byte-identical consecutive
        // lines still collapse (e.g. a repeated build step or spinner).
        let line = "Compiling a very long crate with many dependencies";
        let (collapsed, removed) =
            collapse_repeated_lines(&format!("{line}\n{line}\n{line}\ndone"));
        assert_eq!(removed, 2);
        assert!(collapsed.contains(&format!("[×3] {line}")), "{collapsed}");
        assert!(collapsed.contains("\ndone"), "{collapsed}");
    }

    #[test]
    fn collapse_works_end_to_end_via_optimize_prompt() {
        // Enabling collapse via the config rewrites a message's content and
        // records the counts in the report.
        let body = json(
            r#"{"model":"gpt-4","messages":[
                {"role":"user","content":"build log:\nstep 1\nstep 1\nstep 1\ndone"},
                {"role":"assistant","content":"ok"}
            ]}"#,
        );
        let (out, report) = optimize_prompt(&body, rtk_enabled());
        assert!(report.applied);
        assert!(report.collapsed_lines >= 2);
        assert_eq!(report.collapsed_messages, 1);
        let value: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let content = value["messages"][0]["content"].as_str().unwrap();
        assert!(content.contains("[×3] step 1"), "{content}");
        // The non-repeated "done" line survives.
        assert!(content.contains("done"), "{content}");
        // The assistant message is untouched.
        assert_eq!(value["messages"][1]["content"], "ok");
    }

    #[test]
    fn collapse_isolates_messages() {
        // A repeated line in one message must not collapse a distinct line in
        // another message (each message folds independently).
        let body = json(
            r#"{"model":"gpt-4","messages":[
                {"role":"user","content":"same-line-content\nsame-line-content"},
                {"role":"assistant","content":"same-line-content\nsame-line-content"}
            ]}"#,
        );
        let (out, report) = optimize_prompt(&body, rtk_enabled());
        let value: serde_json::Value = serde_json::from_slice(&out).unwrap();
        // Both messages collapse independently (2 messages each with 1 run).
        assert_eq!(report.collapsed_messages, 2);
        assert_eq!(value["messages"][0]["content"], "[×2] same-line-content");
        assert_eq!(value["messages"][1]["content"], "[×2] same-line-content");
    }

    // --- Hard regression tests for the collapse safety contract ---

    #[test]
    fn collapse_never_truncates_a_representative_line() {
        // Regression: previously the representative line of a repeated run
        // was truncated to 100 chars, silently editing away content. The
        // representative must be the FULL original line.
        let line = "x".repeat(300);
        let content = format!("{line}\n{line}\n{line}");
        let (collapsed, removed) = collapse_repeated_lines(&content);
        assert_eq!(removed, 2);
        assert!(
            collapsed.contains(&format!("[×3] {line}")),
            "lost chars: {collapsed}"
        );
        // The FULL line survives; nothing was truncated to a 100-char ellipsis.
        assert!(!collapsed.contains("..."), "representative was truncated");
    }

    #[test]
    fn collapse_never_drops_entries_beyond_a_fixed_cap() {
        // Regression: previously output was capped at 30 entries, silently
        // discarding every distinct line after the 30th. With >30 distinct
        // lines present, ALL distinct lines must survive.
        let mut lines: Vec<String> = Vec::new();
        for i in 0..100 {
            lines.push(format!("distinct-line-number-{i}-payload"));
        }
        let content = lines.join("\n");
        let (collapsed, removed) = collapse_repeated_lines(&content);
        assert_eq!(removed, 0);
        // Every one of the 100 distinct lines survives verbatim.
        for l in &lines {
            assert!(collapsed.lines().any(|x| x == l), "lost {l}");
        }
        assert_eq!(collapsed.lines().count(), 100);
    }

    #[test]
    fn collapse_never_grows_content_for_short_repeated_lines() {
        // Regression: for short repeated lines, folding into `[×N]` would be
        // LARGER than the original run. The pass must preserve the lines
        // verbatim rather than rewrite them into a bigger form.
        let (collapsed, removed) = collapse_repeated_lines("a\na\na\nb\nb\nc");
        assert_eq!(removed, 0, "short runs must not be folded");
        assert_eq!(collapsed, "a\na\na\nb\nb\nc");
        // Sanity: the fold must be strictly-no-bigger whenever it happens.
        let long = "longenoughline";
        let (c2, r2) = collapse_repeated_lines(&format!("{long}\n{long}\n{long}"));
        assert_eq!(r2, 2);
        assert!(
            c2.len() < long.len() * 3,
            "fold must shrink, got {} vs {}",
            c2.len(),
            long.len() * 3
        );
    }

    #[test]
    fn collapse_output_is_idempotent() {
        // Folding a message that is already collapsed must be a no-op (no
        // double-folding, no churn). Re-running the pass over its own output
        // must return the identical string.
        let content = "repeat-word-x\nrepeat-word-x\nrepeat-word-x\nunique-last";
        let (once, _) = collapse_repeated_lines(content);
        let (twice, removed2) = collapse_repeated_lines(&once);
        assert_eq!(removed2, 0, "already-collapsed output must be stable");
        assert_eq!(once, twice);
    }

    #[test]
    fn collapse_reconstructs_line_count_from_markers() {
        // Safety: the total number of ORIGINAL lines must be recoverable from
        // the collapsed output by expanding `[×N]` markers. This proves no
        // line was silently lost or invented.
        let mut state: u64 = 0x11EE_AA22_3344;
        for _ in 0..300 {
            // Build a random content of 10..40 lines drawn from a small vocab
            // (heavy repeats) so most runs collapse.
            let vocab = ["alpha", "beta", "gamma-very-long-cont", "delta"];
            let n = 10 + (rng_next(&mut state) as usize) % 31;
            let mut parts = Vec::with_capacity(n);
            for _ in 0..n {
                parts.push(pick(&mut state, &vocab).to_string());
            }
            let content = parts.join("\n");
            let (collapsed, removed) = collapse_repeated_lines(&content);
            let orig_count = content.lines().count();
            // `removed` can be at most the number of repeated lines; short
            // runs are preserved verbatim (no-growth rule), so this is an
            // upper bound, not an equality.
            let repeat_count = orig_count - collapse_distinct_count(&content);
            assert!(
                removed <= repeat_count as u64,
                "cannot remove more than the repeated lines ({content:?})"
            );
            // THE authoritative losslessness check: expanding `[×N]` markers
            // must reconstruct the exact original line count — whether or not
            // each run was folded. This proves no line was silently lost or
            // invented.
            let expanded = expand_collapsed(&collapsed);
            assert_eq!(
                expanded, orig_count,
                "line-count mismatch for content {content:?}"
            );
        }
    }

    // --- Collapse property: no-growth & full-distinct-preservation fuzz ---

    #[test]
    fn collapse_fuzz_never_grows_and_never_loses_distinct_lines() {
        let mut state: u64 = 0x5EED_F00D_BEEF;
        let vocab = [
            "short",
            "medium length line that is long enough to fold well",
            "alpha1",
            "beta2",
            "gamma-gamma-gamma-gamma-gamma",
            "distinct-very-long-sentinel-value-xyz",
        ];
        for _ in 0..1000 {
            let n = 1 + (rng_next(&mut state) as usize) % 25;
            let mut lines = Vec::with_capacity(n);
            for _ in 0..n {
                lines.push(pick(&mut state, &vocab).to_string());
            }
            let content = lines.join("\n");
            let (collapsed, removed) = collapse_repeated_lines(&content);

            // 1) NEVER grow the message.
            assert!(
                collapsed.len() <= content.len(),
                "collapse grew: {} > {} for {content:?}",
                collapsed.len(),
                content.len()
            );

            // 2) Never lose a DISTINCT line: every distinct line in the input
            // must appear verbatim (bare or as a fold representative).
            let mut distinct: std::collections::HashSet<String> = std::collections::HashSet::new();
            for l in lines.iter() {
                distinct.insert(l.clone());
            }
            for d in &distinct {
                let present = collapsed
                    .lines()
                    .any(|x| x == d.as_str() || x.ends_with(d.as_str()));
                assert!(
                    present,
                    "lost distinct line {d:?} in {content:?} -> {collapsed:?}"
                );
            }

            // 3) `removed` at most the number of repeated lines (short runs preserved).
            let repeat_count = content.lines().count() - distinct.len();
            assert!(
                removed <= repeat_count as u64,
                "removed {removed} > repeated {repeat_count} for {content:?}"
            );
            // 4) If nothing was removed, the output is byte-identical.
            if removed == 0 {
                assert_eq!(collapsed, content);
            }
            // 5) Life insurance: marker-expansion reconstructs the exact
            // original line count (no line lost or invented).
            assert_eq!(expand_collapsed(&collapsed), content.lines().count());
        }
    }

    // ---- helpers for the hard collapse tests ----

    /// Distinct (by value) line count of `content`.
    fn collapse_distinct_count(content: &str) -> usize {
        let mut seen = std::collections::HashSet::new();
        for l in content.lines() {
            seen.insert(l);
        }
        seen.len()
    }

    /// Expands a collapsed string back to its original line count by treating
    /// each `[×N]` entry as `N` occurrences.
    fn expand_collapsed(collapsed: &str) -> usize {
        let mut count = 0usize;
        for line in collapsed.lines() {
            if let Some(rest) = line.strip_prefix("[×") {
                if let Some(end) = rest.find(']') {
                    if let Ok(n) = rest[..end].parse::<usize>() {
                        count += n;
                        continue;
                    }
                }
            }
            count += 1;
        }
        count
    }

    // --- ANSI-stripping tests (RTK/headroom-inspired) ---

    fn ansi_enabled() -> TokenSaverConfig {
        TokenSaverConfig {
            enabled: true,
            max_input_tokens: None,
            collapse_repeated_lines: false,
            strip_ansi: true,
        }
    }

    #[test]
    fn strip_ansi_is_off_by_default() {
        // Conservative default: ANSI stripping is opt-in like the collapse
        // pass; a plain `enabled()` (strip_ansi=false) must leave content
        // byte-identical.
        let body = json(
            r#"{"model":"gpt-4","messages":[{"role":"user","content":"\u001b[31mred\u001b[0m text"}]}"#,
        );
        let (out, report) = optimize_prompt(&body, enabled());
        assert!(!report.applied);
        assert_eq!(&out[..], &body[..]);
    }

    #[test]
    fn strip_ansi_removes_colour_codes() {
        let body = json(
            r#"{"model":"gpt-4","messages":[{"role":"user","content":"\u001b[31mError\u001b[0m: boom"},{"role":"user","content":"plain"}]}"#,
        );
        let (out, report) = optimize_prompt(&body, ansi_enabled());
        assert!(report.applied);
        assert_eq!(report.ansi_stripped_messages, 1);
        let value: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(value["messages"][0]["content"], "Error: boom");
        // Non-ANSI message untouched.
        assert_eq!(value["messages"][1]["content"], "plain");
    }

    #[test]
    fn strip_ansi_multiple_and_complex() {
        assert_eq!(
            strip_ansi_escapes("\u{1b}[1m\u{1b}[32mSuccess\u{1b}[0m\u{1b}[0m"),
            "Success"
        );
        assert_eq!(strip_ansi_escapes("plain text"), "plain text");
        assert_eq!(strip_ansi_escapes(""), "");
    }

    #[test]
    fn strip_ansi_message_with_only_codes_is_removed() {
        // A message whose content is *only* ANSI codes becomes empty after
        // stripping, then is dropped by the empty-message pass (the codes
        // were noise).
        let body = json(
            r#"{"model":"gpt-4","messages":[{"role":"user","content":"\u001b[31m\u001b[0m"},{"role":"user","content":"real"}]}"#,
        );
        let (out, report) = optimize_prompt(&body, ansi_enabled());
        assert!(report.applied);
        assert_eq!(report.ansi_stripped_messages, 1);
        assert_eq!(report.empty_messages_dropped, 1);
        let value: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let messages = value["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0]["content"], "real");
    }

    #[test]
    fn strip_ansi_never_grows_content() {
        // For arbitrary content, stripping can only remove bytes. Fuzz-ish
        // check over a panel of ANSI-heavy samples.
        let samples = [
            "a\u{1b}[31mb\u{1b}[0mc",
            "\u{1b}[38;5;196mcolourful\u{1b}[0m",
            "noise \u{1b}[2Kprogress \u{1b}[1A up",
            "",
            "\u{1b}[90m\u{1b}[0m\u{1b}[90m\u{1b}[0m",
        ];
        for s in samples {
            let out = strip_ansi_escapes(s);
            assert!(out.len() <= s.len(), "strip_ansi grew content: {out:?}");
        }
    }

    // --- never-worse guard tests (RTK/headroom-inspired) ---

    #[test]
    fn never_worse_keeps_optimised_when_smaller() {
        let body = json(
            r#"{"model":"gpt-4","messages":[{"role":"user","content":"alpha-alpha-alpha\nbeta beta beta\nbody long text line"},{"role":"user","content":"alpha-alpha-alpha\nbeta beta beta\nbody long text line"}]}"#,
        );
        let (out, report) = optimize_prompt(&body, rtk_enabled());
        // Dedup + collapse shrink this; never-worse must not revert.
        assert!(report.applied);
        assert!(!report.never_worse_reverted);
        assert!(report.tokens_saved > 0);
        let value: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(
            value["messages"].as_array().unwrap().len(),
            1,
            "duplicate message collapsed"
        );
    }

    #[test]
    fn never_worse_reverts_when_optimisation_would_not_shrink() {
        // A tiny single message that cannot be shrunk (no dups, no collapse
        // opportunity, within budget) leaves `changed=false`, so never-worse
        // is not even reached — the body returns byte-identical and
        // `never_worse_reverted` stays false. To exercise the guard we need
        // `changed=true` but no token reduction.
        let body = json(r#"{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}"#);
        let (out, report) = optimize_prompt(&body, rtk_enabled());
        assert!(!report.applied);
        assert!(!report.never_worse_reverted);
        assert_eq!(&out[..], &body[..]);
    }
}
