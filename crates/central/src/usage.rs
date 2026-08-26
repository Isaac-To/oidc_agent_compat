//! Usage tracking for per-user quota enforcement and cost reporting.
//!
//! The `UsageTracker` increments per-user cumulative counters (request count,
//! token count, cost) for the current period (daily). These counters are
//! used by the permissions middleware to enforce quotas and by the admin API
//! to report usage.

use sea_orm::{ConnectionTrait, DatabaseConnection, Statement, Value};
use uuid::Uuid;

use oidc_agent_common::error::{Error, Result};

/// The period kind for usage tracking.
pub const PERIOD_DAILY: &str = "daily";

/// The usage tracker, backed by the central proxy's database.
#[derive(Clone)]
pub struct UsageTracker {
    db: DatabaseConnection,
}

/// A snapshot of a user's usage for a period.
#[derive(Debug, Clone)]
pub struct UsageSnapshot {
    /// The user subject.
    pub user_subject: String,
    /// The period date (e.g. `2026-08-25`).
    pub period_date: String,
    /// The period kind (`daily`).
    pub period_kind: String,
    /// Cumulative request count.
    pub request_count: i64,
    /// Cumulative token count.
    pub token_count: i64,
    /// Cumulative cost in USD.
    pub cost_usd: f64,
}

impl UsageTracker {
    /// Creates a new `UsageTracker`.
    #[must_use]
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    /// Returns a reference to the underlying database connection.
    #[must_use]
    pub fn db(&self) -> &DatabaseConnection {
        &self.db
    }

    /// Increments the usage counters for a user. Uses UPSERT semantics:
    /// if a row exists for the user + period, the counters are incremented;
    /// otherwise a new row is inserted.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Database`] on insert/update failure.
    pub async fn increment(
        &self,
        user_subject: &str,
        group_name: Option<&str>,
        request_count_delta: i64,
        token_count_delta: i64,
        cost_delta: f64,
    ) -> Result<()> {
        let id = Uuid::new_v4().to_string();
        let period_date = today_date();
        let group_val = group_name
            .map(|g| Value::String(Some(Box::new(g.to_string()))))
            .unwrap_or(Value::String(None));

        // SQLite UPSERT: INSERT ... ON CONFLICT DO UPDATE.
        // The unique index is on (user_subject, period_date, period_kind).
        let sql = "INSERT INTO usage_counters \
             (id, user_subject, group_name, period_date, period_kind, \
             request_count, token_count, cost_usd) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
             ON CONFLICT(user_subject, period_date, period_kind) DO UPDATE SET \
             request_count = request_count + $6, \
             token_count = token_count + $7, \
             cost_usd = cost_usd + $8";

        self.db
            .execute(Statement::from_sql_and_values(
                self.db.get_database_backend(),
                sql,
                vec![
                    id.into(),
                    user_subject.to_string().into(),
                    group_val,
                    period_date.clone().into(),
                    PERIOD_DAILY.into(),
                    Value::BigInt(Some(request_count_delta)),
                    Value::BigInt(Some(token_count_delta)),
                    Value::Float(Some(cost_delta as f32)),
                ],
            ))
            .await
            .map_err(|e| Error::Database(format!("usage increment: {e}")))?;

        Ok(())
    }

    /// Gets the current usage snapshot for a user for today.
    ///
    /// Returns `None` if no usage has been recorded for the period.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Database`] on query failure.
    pub async fn get_usage(&self, user_subject: &str) -> Result<Option<UsageSnapshot>> {
        let period_date = today_date();
        let sql = "SELECT user_subject, period_date, period_kind, \
             request_count, token_count, cost_usd \
             FROM usage_counters \
             WHERE user_subject = $1 AND period_date = $2 AND period_kind = $3";

        let rows = self
            .db
            .query_all(Statement::from_sql_and_values(
                self.db.get_database_backend(),
                sql,
                vec![
                    user_subject.to_string().into(),
                    period_date.into(),
                    PERIOD_DAILY.into(),
                ],
            ))
            .await
            .map_err(|e| Error::Database(format!("get usage: {e}")))?;

        if rows.is_empty() {
            return Ok(None);
        }

        let row = rows
            .first()
            .ok_or_else(|| Error::Database("usage row vanished after empty check".into()))?;
        Ok(Some(UsageSnapshot {
            user_subject: row.try_get("", "user_subject").unwrap_or_default(),
            period_date: row.try_get("", "period_date").unwrap_or_default(),
            period_kind: row.try_get("", "period_kind").unwrap_or_default(),
            request_count: row.try_get("", "request_count").unwrap_or(0),
            token_count: row.try_get("", "token_count").unwrap_or(0),
            cost_usd: row.try_get("", "cost_usd").unwrap_or(0.0),
        }))
    }

    /// Gets the usage for all users for today (for admin reporting).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Database`] on query failure.
    pub async fn get_all_usage(&self) -> Result<Vec<UsageSnapshot>> {
        let period_date = today_date();
        let sql = "SELECT user_subject, period_date, period_kind, \
             request_count, token_count, cost_usd \
             FROM usage_counters \
             WHERE period_date = $1 AND period_kind = $2";

        let rows = self
            .db
            .query_all(Statement::from_sql_and_values(
                self.db.get_database_backend(),
                sql,
                vec![period_date.into(), PERIOD_DAILY.into()],
            ))
            .await
            .map_err(|e| Error::Database(format!("get all usage: {e}")))?;

        let mut snapshots = Vec::new();
        for row in rows {
            snapshots.push(UsageSnapshot {
                user_subject: row.try_get("", "user_subject").unwrap_or_default(),
                period_date: row.try_get("", "period_date").unwrap_or_default(),
                period_kind: row.try_get("", "period_kind").unwrap_or_default(),
                request_count: row.try_get("", "request_count").unwrap_or(0),
                token_count: row.try_get("", "token_count").unwrap_or(0),
                cost_usd: row.try_get("", "cost_usd").unwrap_or(0.0),
            });
        }
        Ok(snapshots)
    }
}

/// Returns today's date as a `YYYY-MM-DD` string (UTC).
fn today_date() -> String {
    let now = time::OffsetDateTime::now_utc();
    now.format(time::macros::format_description!("[year]-[month]-[day]"))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn setup_test_db() -> UsageTracker {
        let url = oidc_agent_common::persistence::temp_sqlite_url("usage");
        let db = crate::db::setup(&url).await.expect("db setup");
        UsageTracker::new(db)
    }

    #[tokio::test]
    async fn increment_creates_row() {
        let tracker = setup_test_db().await;
        tracker
            .increment("user-1", Some("engineering"), 1, 100, 0.01)
            .await
            .expect("increment");

        let usage = tracker
            .get_usage("user-1")
            .await
            .expect("get")
            .expect("exists");
        assert_eq!(usage.user_subject, "user-1");
        assert_eq!(usage.request_count, 1);
        assert_eq!(usage.token_count, 100);
        assert!((usage.cost_usd - 0.01).abs() < 0.001);
    }

    #[tokio::test]
    async fn increment_accumulates() {
        let tracker = setup_test_db().await;
        tracker
            .increment("user-2", None, 1, 50, 0.005)
            .await
            .expect("increment 1");
        tracker
            .increment("user-2", None, 1, 75, 0.0075)
            .await
            .expect("increment 2");

        let usage = tracker
            .get_usage("user-2")
            .await
            .expect("get")
            .expect("exists");
        assert_eq!(usage.request_count, 2);
        assert_eq!(usage.token_count, 125);
        assert!((usage.cost_usd - 0.0125).abs() < 0.001);
    }

    #[tokio::test]
    async fn get_usage_nonexistent_returns_none() {
        let tracker = setup_test_db().await;
        let usage = tracker.get_usage("nonexistent").await.expect("get");
        assert!(usage.is_none());
    }

    #[tokio::test]
    async fn get_all_usage_returns_all_users() {
        let tracker = setup_test_db().await;
        tracker
            .increment("user-a", None, 1, 10, 0.0)
            .await
            .expect("increment a");
        tracker
            .increment("user-b", None, 2, 20, 0.0)
            .await
            .expect("increment b");

        let all = tracker.get_all_usage().await.expect("get all");
        assert_eq!(all.len(), 2);
    }
}
