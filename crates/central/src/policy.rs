//! Group policy store and resolution.
//!
//! This module loads per-group authorization policies from the central
//! database and resolves the effective policy for a user by merging the
//! policies of all groups the user belongs to.
//!
//! # Merge semantics
//!
//! When a user belongs to multiple groups, the most-permissive policy wins:
//! - **Model allowlists**: union of all groups' allowed models. If any group
//!   has `None` (all allowed), the result is `None` (all allowed).
//! - **Endpoint allowlists**: union of all groups' allowed endpoints. If any
//!   group has `None`, the result is `None`.
//! - **Quotas**: maximum of all groups' quotas (most generous). If any group
//!   has `None` (unlimited), the result is `None` (unlimited).

use std::collections::HashSet;

use sea_orm::{ConnectionTrait, DatabaseConnection, Statement, Value};
use uuid::Uuid;

use oidc_agent_common::error::{Error, Result};
use oidc_agent_common::time_util;

use crate::entity::group_policy;
use crate::optimizer::TokenSaverConfig;

/// A resolved policy for a user, merging all their groups' policies.
///
/// The default value is the most-permissive policy: all models and endpoints
/// allowed, no quotas, and the token saver disabled.
#[derive(Debug, Clone, Default)]
pub struct ResolvedPolicy {
    /// The set of allowed models. `None` means all models are allowed.
    pub allowed_models: Option<HashSet<String>>,
    /// The set of allowed endpoints. `None` means all endpoints are allowed.
    pub allowed_endpoints: Option<HashSet<String>>,
    /// The daily token quota. `None` means unlimited.
    pub daily_token_quota: Option<i64>,
    /// The daily request quota. `None` means unlimited.
    pub daily_request_quota: Option<i64>,
    /// The admin-controlled token-saver configuration. Defaults to disabled.
    pub token_saver: TokenSaverConfig,
}

impl ResolvedPolicy {
    /// Returns `true` if the given model is allowed by this policy.
    #[must_use]
    pub fn is_model_allowed(&self, model: &str) -> bool {
        match &self.allowed_models {
            None => true,
            Some(models) => models.contains(model),
        }
    }

    /// Returns `true` if the given endpoint is allowed by this policy.
    #[must_use]
    pub fn is_endpoint_allowed(&self, endpoint: &str) -> bool {
        match &self.allowed_endpoints {
            None => true,
            Some(endpoints) => endpoints.contains(endpoint),
        }
    }
}

/// The policy store, backed by the central proxy's database.
#[derive(Clone)]
pub struct PolicyStore {
    db: DatabaseConnection,
}

impl PolicyStore {
    /// Creates a new `PolicyStore`.
    #[must_use]
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    /// Returns a reference to the underlying database connection.
    #[must_use]
    pub fn db(&self) -> &DatabaseConnection {
        &self.db
    }

    /// Resolves the effective policy for a user belonging to the given
    /// groups.
    ///
    /// Loads all group policies matching the user's groups and merges them
    /// with most-permissive-wins semantics. If no policies exist for any of
    /// the user's groups, returns the default (all-allowed) policy.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Database`] on query failure.
    pub async fn resolve_policy(&self, groups: &[String]) -> Result<ResolvedPolicy> {
        if groups.is_empty() {
            return Ok(ResolvedPolicy::default());
        }

        // Load all policies for the user's groups.
        let placeholders: Vec<String> = groups
            .iter()
            .enumerate()
            .map(|(i, _)| format!("${}", i + 1))
            .collect();
        let placeholder_str = placeholders.join(", ");
        let sql = format!(
            "SELECT group_name, allowed_models, allowed_endpoints, \
             daily_token_quota, daily_request_quota, \
             token_saver_enabled, max_input_tokens, collapse_repeated_lines \
             FROM group_policies WHERE group_name IN ({placeholder_str})"
        );

        let params: Vec<Value> = groups
            .iter()
            .map(|g| Value::String(Some(Box::new(g.clone()))))
            .collect();

        let rows = self
            .db
            .query_all(Statement::from_sql_and_values(
                self.db.get_database_backend(),
                &sql,
                params,
            ))
            .await
            .map_err(|e| Error::Database(format!("query group policies: {e}")))?;

        if rows.is_empty() {
            return Ok(ResolvedPolicy::default());
        }

        let mut allowed_models: Option<HashSet<String>> = Some(HashSet::new());
        let mut allowed_endpoints: Option<HashSet<String>> = Some(HashSet::new());
        let mut daily_token_quota: Option<i64> = None;
        let mut daily_request_quota: Option<i64> = None;
        // Token saver: enabled if ANY group enables it; the budget is the
        // most generous (largest) across groups, so a member of multiple
        // groups is never more aggressively trimmed than their most
        // permissive group allows.
        let mut token_saver_enabled = false;
        let mut max_input_tokens: Option<i64> = None;
        // RTK collapse: enabled if ANY group enables it (most permissive).
        let mut collapse_repeated_lines = false;

        for row in rows {
            let row_models: Option<String> = row.try_get("", "allowed_models").ok();
            let row_endpoints: Option<String> = row.try_get("", "allowed_endpoints").ok();
            let row_token_quota: Option<i64> = row.try_get("", "daily_token_quota").ok();
            let row_request_quota: Option<i64> = row.try_get("", "daily_request_quota").ok();
            let row_saver_enabled: Option<bool> = row.try_get("", "token_saver_enabled").ok();
            let row_max_input: Option<i64> = row.try_get("", "max_input_tokens").ok();
            let row_collapse: Option<bool> = row.try_get("", "collapse_repeated_lines").ok();

            // Models: union. None = all allowed.
            match (row_models, &mut allowed_models) {
                (None, _) => {
                    allowed_models = None;
                }
                (Some(json), Some(acc)) => {
                    if let Ok(models) = parse_json_array(&json) {
                        acc.extend(models);
                    }
                }
                (Some(_), None) => {} // already all-allowed
            }

            // Endpoints: union. None = all allowed.
            match (row_endpoints, &mut allowed_endpoints) {
                (None, _) => {
                    allowed_endpoints = None;
                }
                (Some(json), Some(acc)) => {
                    if let Ok(endpoints) = parse_json_array(&json) {
                        acc.extend(endpoints);
                    }
                }
                (Some(_), None) => {} // already all-allowed
            }

            // Quotas: max (most generous). None = unlimited.
            daily_token_quota = match (daily_token_quota, row_token_quota) {
                (None, Some(q)) => Some(q),
                (Some(a), Some(b)) => Some(a.max(b)),
                (a, None) => a,
            };
            daily_request_quota = match (daily_request_quota, row_request_quota) {
                (None, Some(q)) => Some(q),
                (Some(a), Some(b)) => Some(a.max(b)),
                (a, None) => a,
            };

            // Token saver: any group enabling it turns it on; budget is max.
            // A NULL max_input_tokens row means "no budget" (unlimited),
            // which is the most permissive and therefore wins over any
            // numeric cap.
            if row_saver_enabled.unwrap_or(false) {
                token_saver_enabled = true;
            }
            // RTK collapse: any group enabling it turns it on.
            if row_collapse.unwrap_or(false) {
                collapse_repeated_lines = true;
            }
            // If any group grants an unlimited budget, the merged result is
            // unlimited (None) — most permissive wins.
            if row_max_input.is_none() {
                max_input_tokens = None;
            } else if let Some(row_budget) = row_max_input {
                match max_input_tokens {
                    None => max_input_tokens = Some(row_budget),
                    Some(acc) => max_input_tokens = Some(acc.max(row_budget)),
                }
            }
        }

        Ok(ResolvedPolicy {
            allowed_models,
            allowed_endpoints,
            daily_token_quota,
            daily_request_quota,
            token_saver: TokenSaverConfig {
                enabled: token_saver_enabled,
                max_input_tokens: max_input_tokens.map(|v| v as u64),
                collapse_repeated_lines,
            },
        })
    }

    /// Lists all group policies.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Database`] on query failure.
    pub async fn list_policies(&self) -> Result<Vec<group_policy::Model>> {
        use sea_orm::EntityTrait;
        group_policy::Entity::find()
            .all(&self.db)
            .await
            .map_err(|e| Error::Database(format!("list group policies: {e}")))
    }

    /// Gets a single group policy by group name.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Database`] on query failure.
    pub async fn get_policy(&self, group_name: &str) -> Result<Option<group_policy::Model>> {
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
        group_policy::Entity::find()
            .filter(group_policy::Column::GroupName.eq(group_name))
            .one(&self.db)
            .await
            .map_err(|e| Error::Database(format!("get group policy: {e}")))
    }

    /// Upserts a group policy. If a policy for the group exists, it is
    /// updated; otherwise a new one is inserted.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Database`] on insert/update failure.
    pub async fn upsert_policy(
        &self,
        group_name: &str,
        allowed_models: Option<&str>,
        allowed_endpoints: Option<&str>,
        daily_token_quota: Option<i64>,
        daily_request_quota: Option<i64>,
    ) -> Result<group_policy::Model> {
        // The token-saver fields default to disabled/unbounded and are set
        // via `set_token_saver`. Keeping this method's signature stable
        // avoids churn across callers that only manage access/quotas.
        self.upsert_policy_full(
            group_name,
            allowed_models,
            allowed_endpoints,
            daily_token_quota,
            daily_request_quota,
            false,
            None,
            false,
        )
        .await
    }

    /// Upserts a group policy including the admin-controlled token-saver
    /// fields (`token_saver_enabled`, `max_input_tokens`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Database`] on insert/update failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn upsert_policy_full(
        &self,
        group_name: &str,
        allowed_models: Option<&str>,
        allowed_endpoints: Option<&str>,
        daily_token_quota: Option<i64>,
        daily_request_quota: Option<i64>,
        token_saver_enabled: bool,
        max_input_tokens: Option<i64>,
        collapse_repeated_lines: bool,
    ) -> Result<group_policy::Model> {
        let existing = self.get_policy(group_name).await?;
        let now = time_util::now_utc();
        let now_str = time_util::format_time(&now);

        let models_val = allowed_models
            .map(|v| Value::String(Some(Box::new(v.to_string()))))
            .unwrap_or(Value::String(None));
        let endpoints_val = allowed_endpoints
            .map(|v| Value::String(Some(Box::new(v.to_string()))))
            .unwrap_or(Value::String(None));
        let token_quota_val = daily_token_quota
            .map(|v| Value::BigInt(Some(v)))
            .unwrap_or(Value::BigInt(None));
        let request_quota_val = daily_request_quota
            .map(|v| Value::BigInt(Some(v)))
            .unwrap_or(Value::BigInt(None));
        let saver_enabled_val = Value::Bool(Some(token_saver_enabled));
        let max_input_val = max_input_tokens
            .map(|v| Value::BigInt(Some(v)))
            .unwrap_or(Value::BigInt(None));
        let collapse_val = Value::Bool(Some(collapse_repeated_lines));

        if let Some(model) = existing {
            // Update existing.
            let sql = "UPDATE group_policies SET allowed_models = $1, \
                 allowed_endpoints = $2, daily_token_quota = $3, \
                 daily_request_quota = $4, token_saver_enabled = $5, \
                 max_input_tokens = $6, collapse_repeated_lines = $7, \
                 updated_at = $8 WHERE id = $9";
            self.db
                .execute(Statement::from_sql_and_values(
                    self.db.get_database_backend(),
                    sql,
                    vec![
                        models_val,
                        endpoints_val,
                        token_quota_val,
                        request_quota_val,
                        saver_enabled_val,
                        max_input_val,
                        collapse_val,
                        now_str.into(),
                        model.id.clone().into(),
                    ],
                ))
                .await
                .map_err(|e| Error::Database(format!("update group policy: {e}")))?;
            Ok(group_policy::Model {
                id: model.id,
                group_name: group_name.to_string(),
                allowed_models: allowed_models.map(String::from),
                allowed_endpoints: allowed_endpoints.map(String::from),
                daily_token_quota,
                daily_request_quota,
                token_saver_enabled,
                max_input_tokens,
                collapse_repeated_lines,
                created_at: model.created_at,
                updated_at: now,
            })
        } else {
            // Insert new.
            let id = Uuid::new_v4().to_string();
            let sql = "INSERT INTO group_policies \
                 (id, group_name, allowed_models, allowed_endpoints, \
                 daily_token_quota, daily_request_quota, \
                 token_saver_enabled, max_input_tokens, collapse_repeated_lines, \
                 created_at, updated_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)";
            self.db
                .execute(Statement::from_sql_and_values(
                    self.db.get_database_backend(),
                    sql,
                    vec![
                        id.clone().into(),
                        group_name.to_string().into(),
                        models_val,
                        endpoints_val,
                        token_quota_val,
                        request_quota_val,
                        saver_enabled_val,
                        max_input_val,
                        collapse_val,
                        now_str.clone().into(),
                        now_str.into(),
                    ],
                ))
                .await
                .map_err(|e| Error::Database(format!("insert group policy: {e}")))?;
            Ok(group_policy::Model {
                id,
                group_name: group_name.to_string(),
                allowed_models: allowed_models.map(String::from),
                allowed_endpoints: allowed_endpoints.map(String::from),
                daily_token_quota,
                daily_request_quota,
                token_saver_enabled,
                max_input_tokens,
                collapse_repeated_lines,
                created_at: now,
                updated_at: now,
            })
        }
    }

    /// Deletes a group policy by group name.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Database`] on delete failure.
    pub async fn delete_policy(&self, group_name: &str) -> Result<bool> {
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
        let result = group_policy::Entity::delete_many()
            .filter(group_policy::Column::GroupName.eq(group_name))
            .exec(&self.db)
            .await
            .map_err(|e| Error::Database(format!("delete group policy: {e}")))?;
        Ok(result.rows_affected > 0)
    }
}

/// Parses a JSON array string into a `Vec<String>`.
fn parse_json_array(json: &str) -> std::result::Result<Vec<String>, serde_json::Error> {
    serde_json::from_str(json)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn setup_test_db() -> PolicyStore {
        let url = oidc_agent_common::persistence::temp_sqlite_url("policy");
        let db = crate::db::setup(&url).await.expect("db setup");
        PolicyStore::new(db)
    }

    #[tokio::test]
    async fn resolve_policy_no_groups_returns_default() {
        let store = setup_test_db().await;
        let policy = store.resolve_policy(&[]).await.expect("resolve");
        assert!(policy.allowed_models.is_none());
        assert!(policy.allowed_endpoints.is_none());
        assert!(policy.daily_token_quota.is_none());
        assert!(policy.daily_request_quota.is_none());
    }

    #[tokio::test]
    async fn resolve_policy_no_matching_policies_returns_default() {
        let store = setup_test_db().await;
        let policy = store
            .resolve_policy(&["nonexistent".into()])
            .await
            .expect("resolve");
        assert!(policy.allowed_models.is_none());
    }

    #[tokio::test]
    async fn resolve_policy_single_group_model_allowlist() {
        let store = setup_test_db().await;
        store
            .upsert_policy(
                "engineering",
                Some(r#"["gpt-4o", "gpt-4o-mini"]"#),
                None,
                None,
                None,
            )
            .await
            .expect("upsert");

        let policy = store
            .resolve_policy(&["engineering".into()])
            .await
            .expect("resolve");
        assert!(policy.is_model_allowed("gpt-4o"));
        assert!(policy.is_model_allowed("gpt-4o-mini"));
        assert!(!policy.is_model_allowed("o1"));
        assert!(policy.allowed_endpoints.is_none());
    }

    #[tokio::test]
    async fn resolve_policy_multiple_groups_unions_models() {
        let store = setup_test_db().await;
        store
            .upsert_policy("engineering", Some(r#"["gpt-4o"]"#), None, None, None)
            .await
            .expect("upsert eng");
        store
            .upsert_policy("research", Some(r#"["o1"]"#), None, None, None)
            .await
            .expect("upsert res");

        let policy = store
            .resolve_policy(&["engineering".into(), "research".into()])
            .await
            .expect("resolve");
        assert!(policy.is_model_allowed("gpt-4o"));
        assert!(policy.is_model_allowed("o1"));
        assert!(!policy.is_model_allowed("gpt-3.5"));
    }

    #[tokio::test]
    async fn resolve_policy_none_models_means_all_allowed() {
        let store = setup_test_db().await;
        store
            .upsert_policy("engineering", Some(r#"["gpt-4o"]"#), None, None, None)
            .await
            .expect("upsert eng");
        store
            .upsert_policy("admin", None, None, None, None)
            .await
            .expect("upsert admin");

        let policy = store
            .resolve_policy(&["engineering".into(), "admin".into()])
            .await
            .expect("resolve");
        // admin has None = all allowed, so union is all allowed.
        assert!(policy.allowed_models.is_none());
        assert!(policy.is_model_allowed("anything"));
    }

    #[tokio::test]
    async fn resolve_policy_endpoint_restrictions() {
        let store = setup_test_db().await;
        store
            .upsert_policy(
                "restricted",
                None,
                Some(r#"["/v1/chat/completions"]"#),
                None,
                None,
            )
            .await
            .expect("upsert");

        let policy = store
            .resolve_policy(&["restricted".into()])
            .await
            .expect("resolve");
        assert!(policy.is_endpoint_allowed("/v1/chat/completions"));
        assert!(!policy.is_endpoint_allowed("/v1/embeddings"));
    }

    #[tokio::test]
    async fn resolve_policy_quotas_take_max() {
        let store = setup_test_db().await;
        store
            .upsert_policy("group-a", None, None, Some(1000), Some(100))
            .await
            .expect("upsert a");
        store
            .upsert_policy("group-b", None, None, Some(5000), Some(50))
            .await
            .expect("upsert b");

        let policy = store
            .resolve_policy(&["group-a".into(), "group-b".into()])
            .await
            .expect("resolve");
        assert_eq!(policy.daily_token_quota, Some(5000));
        assert_eq!(policy.daily_request_quota, Some(100));
    }

    #[tokio::test]
    async fn upsert_policy_updates_existing() {
        let store = setup_test_db().await;
        store
            .upsert_policy("engineering", Some(r#"["gpt-4o"]"#), None, None, None)
            .await
            .expect("upsert 1");

        store
            .upsert_policy("engineering", Some(r#"["gpt-4o", "o1"]"#), None, None, None)
            .await
            .expect("upsert 2");

        let policies = store.list_policies().await.expect("list");
        assert_eq!(policies.len(), 1, "upsert must not duplicate");
        let policy = store
            .get_policy("engineering")
            .await
            .expect("get")
            .expect("exists");
        let models =
            parse_json_array(policy.allowed_models.as_deref().unwrap_or("[]")).expect("parse");
        assert!(models.contains(&"gpt-4o".to_string()));
        assert!(models.contains(&"o1".to_string()));
    }

    #[tokio::test]
    async fn delete_policy_removes_row() {
        let store = setup_test_db().await;
        store
            .upsert_policy("engineering", None, None, None, None)
            .await
            .expect("upsert");

        let deleted = store.delete_policy("engineering").await.expect("delete");
        assert!(deleted);

        let deleted_again = store.delete_policy("engineering").await.expect("delete");
        assert!(!deleted_again);
    }

    #[tokio::test]
    async fn token_saver_defaults_to_disabled() {
        let store = setup_test_db().await;
        store
            .upsert_policy("engineering", None, None, None, None)
            .await
            .expect("upsert");
        let policy = store
            .resolve_policy(&["engineering".into()])
            .await
            .expect("resolve");
        // Default-off: the saver must NOT apply unless an admin enables it.
        assert!(!policy.token_saver.enabled);
        assert!(policy.token_saver.max_input_tokens.is_none());
    }

    #[tokio::test]
    async fn token_saver_enabled_single_group() {
        let store = setup_test_db().await;
        store
            .upsert_policy_full(
                "engineering",
                None,
                None,
                None,
                None,
                true,
                Some(8000),
                false,
            )
            .await
            .expect("upsert");
        let policy = store
            .resolve_policy(&["engineering".into()])
            .await
            .expect("resolve");
        assert!(policy.token_saver.enabled);
        assert_eq!(policy.token_saver.max_input_tokens, Some(8000));
    }

    #[tokio::test]
    async fn token_saver_merge_any_enabled_wins_budget_is_max() {
        let store = setup_test_db().await;
        // Group A enables with a small budget; Group B disables but has a
        // large budget.
        store
            .upsert_policy_full("group-a", None, None, None, None, true, Some(2000), false)
            .await
            .expect("upsert a");
        store
            .upsert_policy_full("group-b", None, None, None, None, false, Some(5000), false)
            .await
            .expect("upsert b");

        let policy = store
            .resolve_policy(&["group-a".into(), "group-b".into()])
            .await
            .expect("resolve");
        // Any group enabling it turns it on.
        assert!(policy.token_saver.enabled);
        // The budget is the most generous (largest), so no member is more
        // aggressively trimmed than their most permissive group allows.
        assert_eq!(policy.token_saver.max_input_tokens, Some(5000));
    }

    #[tokio::test]
    async fn token_saver_all_disabled_stays_off() {
        let store = setup_test_db().await;
        store
            .upsert_policy_full("group-a", None, None, None, None, false, Some(1000), false)
            .await
            .expect("upsert a");
        store
            .upsert_policy_full("group-b", None, None, None, None, false, None, false)
            .await
            .expect("upsert b");
        let policy = store
            .resolve_policy(&["group-a".into(), "group-b".into()])
            .await
            .expect("resolve");
        assert!(!policy.token_saver.enabled);
    }

    #[tokio::test]
    async fn collapse_repeated_lines_any_group_enables_wins() {
        let store = setup_test_db().await;
        // Group A does NOT enable collapse; Group B does. The merge must
        // turn collapse on because any group enabling it wins.
        store
            .upsert_policy_full("group-a", None, None, None, None, true, Some(1000), false)
            .await
            .expect("upsert a");
        store
            .upsert_policy_full("group-b", None, None, None, None, true, Some(1000), true)
            .await
            .expect("upsert b");

        let policy = store
            .resolve_policy(&["group-a".into(), "group-b".into()])
            .await
            .expect("resolve");
        assert!(policy.token_saver.collapse_repeated_lines);
    }

    #[tokio::test]
    async fn collapse_repeated_lines_all_disabled_stays_off() {
        let store = setup_test_db().await;
        store
            .upsert_policy_full("group-a", None, None, None, None, true, Some(1000), false)
            .await
            .expect("upsert a");
        store
            .upsert_policy_full("group-b", None, None, None, None, true, Some(1000), false)
            .await
            .expect("upsert b");

        let policy = store
            .resolve_policy(&["group-a".into(), "group-b".into()])
            .await
            .expect("resolve");
        // No group opted into collapse, so it must remain off even though
        // the token saver itself is enabled.
        assert!(!policy.token_saver.collapse_repeated_lines);
    }
}
