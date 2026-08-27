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
//!   message's `content`, runs of normalized-identical lines are collapsed
//!   into one representative line with a `[×N]` count (adapting RTK's
//!   `analyze_logs`). This is limited to *consecutive* runs inside one
//!   message, so it never merges distinct turns or non-adjacent information.
//! - **Never rewrites content**: no token-level compression, no
//!   rephrasing, no summarisation. The optimiser rewrites only structure and
//!   drop granularity, never the text of any kept message.
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
//! The repeated-line collapse pass adapts the line-normalization + collapse
//! approach from [RTK](https://github.com/rtk-ai/rtk)
//! (`src/cmds/system/log_cmd.rs`, Apache-2.0). The normalization
//! (`normalize_log_line`) and count-preserving collapse are ported here with
//! the upstream Apache-2.0 attribution retained.

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
    report.applied = report.tokens_saved > 0;

    match serde_json::to_vec(&value) {
        Ok(encoded) => (bytes::Bytes::from(encoded), report),
        Err(_) => (
            bytes::Bytes::copy_from_slice(body),
            OptimizationReport::default(),
        ),
    }
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

// --- RTK-adapted repeated-line collapse ------------------------------------
//
// The following adapt RTK's `normalize_log_line` + `analyze_logs`
// (https://github.com/rtk-ai/rtk, `src/cmds/system/log_cmd.rs`, Apache-2.0)
// to collapse consecutive repeated lines inside a single message's content.
// Attribution retained per Apache-2.0.

/// Maximum distinct collapsed entries to retain within a single message.
const MAX_COLLAPSED_ENTRIES: usize = 30;
/// Long lines are truncated to this many chars (RTK uses 100).
const MAX_LINE_CHARS: usize = 100;

/// Collapses consecutive runs of identical lines in `content` into `[×N]`
/// representative lines.
///
/// Operates on a *single* message's content string. Iff no run of length > 1
/// is found, returns the original string unchanged. Only consecutive runs are
/// collapsed (so ordering and non-adjacent distinct lines are preserved), and
/// the count is preserved in the `[×N]` annotation.
///
/// # Safety
///
/// Only **exact-verbatim** consecutive duplicate lines are collapsed, so the
/// pass is lossless-by-construction: it can only remove a line that was
/// already present byte-for-byte in the immediately preceding line. It never
/// merges lines that merely "look similar" under fuzzy normalization.
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
            // Collapse the run, keeping the first line with a count marker.
            let representative = truncate_to_chars(current, MAX_LINE_CHARS);
            collapsed.push(format!("[×{run_len}] {representative}"));
            removed += u64::try_from(run_len - 1).unwrap_or(0);
        } else {
            collapsed.push(current.to_string());
        }
    }

    if removed == 0 {
        // Nothing was collapsed — return the exact original string.
        return (content.to_string(), 0);
    }

    // Cap the collapsed output to the most relevant (first) entries.
    if collapsed.len() > MAX_COLLAPSED_ENTRIES {
        let extra = collapsed.len() - MAX_COLLAPSED_ENTRIES;
        collapsed.truncate(MAX_COLLAPSED_ENTRIES);
        collapsed.push(format!("… +{extra} more collapsed entries"));
    }

    (collapsed.join("\n"), removed)
}

/// Truncates `s` to at most `limit` chars, appending `...` when truncated.
#[must_use]
fn truncate_to_chars(s: &str, limit: usize) -> String {
    if s.chars().count() <= limit {
        return s.to_string();
    }
    let mut out: String = s.chars().take(limit.saturating_sub(3)).collect();
    out.push_str("...");
    out
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

    fn enabled() -> TokenSaverConfig {
        TokenSaverConfig {
            enabled: true,
            max_input_tokens: None,
            collapse_repeated_lines: false,
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
        let (collapsed, removed) = collapse_repeated_lines("a\na\na\nb\nb\nc");
        assert_eq!(removed, 3); // 2 from the run of 3 'a', 1 from the run of 2 'b'
        assert!(collapsed.contains("[×3] a"), "{collapsed}");
        assert!(collapsed.contains("[×2] b"), "{collapsed}");
        // Non-repeated line untouched.
        assert!(collapsed.contains("\nc"), "{collapsed}");
        assert!(!collapsed.contains("c\nc"), "must not duplicate");
    }

    #[test]
    fn collapse_only_folds_consecutive_runs() {
        // "a b a" -> the two 'a' are NOT adjacent, so they are NOT merged.
        let (collapsed, removed) = collapse_repeated_lines("a\nb\na");
        assert_eq!(removed, 0);
        assert_eq!(collapsed, "a\nb\na");
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
        let (collapsed, _) = collapse_repeated_lines("x1\nx2\nx2\nx3");
        assert_eq!(collapsed, "x1\n[×2] x2\nx3");
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
        let (collapsed, removed) =
            collapse_repeated_lines("Compiling thing\nCompiling thing\nCompiling thing\ndone");
        assert_eq!(removed, 2);
        assert!(collapsed.contains("[×3] Compiling thing"), "{collapsed}");
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
        // another message.
        let body = json(
            r#"{"model":"gpt-4","messages":[
                {"role":"user","content":"a\na"},
                {"role":"assistant","content":"a\na"}
            ]}"#,
        );
        let (out, report) = optimize_prompt(&body, rtk_enabled());
        let value: serde_json::Value = serde_json::from_slice(&out).unwrap();
        // Both messages collapse independently (2 messages each with 1 run).
        assert_eq!(report.collapsed_messages, 2);
        assert_eq!(value["messages"][0]["content"], "[×2] a");
        assert_eq!(value["messages"][1]["content"], "[×2] a");
    }

    #[test]
    fn collapse_fuzz_never_looses_unique_lines() {
        // Safety invariant: collapse is lossless for *distinct* lines — every
        // distinct line is preserved either bare or as the representative of a
        // [×N] entry, up to the MAX_COLLAPSED_ENTRIES cap (which truncates
        // only the tail and reports the overflow count, never silently).
        // Using fully unique lines, no two collapse together.
        let lines: Vec<String> = (0..20).map(|i| format!("distinct-{i}-xyzzy")).collect();
        let mut content = String::new();
        for l in &lines {
            // Some lines appear once, some repeat twice consecutively.
            content.push_str(l);
            content.push('\n');
            if l == "distinct-3-xyzzy" || l == "distinct-9-xyzzy" {
                content.push_str(l);
                content.push('\n');
            }
        }
        let (collapsed, removed) = collapse_repeated_lines(&content);
        // Two repeated lines mean 2 removed (run of 2 -> 1 surviving each).
        assert_eq!(removed, 2, "removed={removed}");
        for l in &lines {
            // Every unique line must appear either bare or as a [×N] rep.
            let present = collapsed
                .lines()
                .any(|x| x == l.as_str() || x.contains(l.as_str()));
            assert!(present, "lost unique line {l:?} in collapse output");
        }
        // The collapse markers carry the correct counts.
        assert!(collapsed.contains("[×2] distinct-3-xyzzy"), "{collapsed}");
        assert!(collapsed.contains("distinct-9-xyzzy"), "{collapsed}");
    }
}
