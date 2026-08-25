//! Pricing table for computing request costs.
//!
//! The `PriceTable` maps model names to per-1K-token prices (input and
//! output). Prices come from two sources:
//!
//! 1. **Auto-fetched from the backend** — if the backend exposes a
//!    `/v1/models` endpoint with pricing fields (e.g. OpenRouter's
//!    `pricing.prompt` / `pricing.completion` per-token), the central proxy
//!    fetches them at startup and refreshes periodically.
//! 2. **Manual config overrides** — the `[central.pricing]` TOML table.
//!    Manual prices **always take precedence** over fetched prices, so
//!    admins can pin or override specific models.
//!
//! # OpenRouter format
//!
//! OpenRouter's `GET /api/v1/models` returns:
//! ```json
//! {"data": [{"id": "openai/gpt-4o", "pricing": {"prompt": "0.0000025", "completion": "0.00001"}}]}
//! ```
//! Prices are per-token in USD (as strings). We convert to per-1K-tokens:
//! `per_1k = per_token * 1000`.
//!
//! Some backends (OpenAI, Azure) don't expose pricing — for those, only
//! manual config prices are used.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

use oidc_agent_common::config::PricingConfig;
use oidc_agent_common::error::{Error, Result};

/// A price entry for a single model.
#[derive(Debug, Clone)]
pub struct ModelPrice {
    /// Price per 1K input (prompt) tokens in USD.
    pub input_per_1k_usd: f64,
    /// Price per 1K output (completion) tokens in USD.
    pub output_per_1k_usd: f64,
}

/// The source of a price entry (for debugging/auditing).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PriceSource {
    /// Price was auto-fetched from the backend.
    Fetched,
    /// Price was manually configured (override).
    Override,
}

/// A price entry with its source.
#[derive(Debug, Clone)]
struct PricedModel {
    price: ModelPrice,
    source: PriceSource,
}

/// A table of model prices, supporting auto-fetch with manual overrides.
///
/// Thread-safe via `RwLock`. The `compute_cost` method is cheap (read lock).
/// The `refresh_fetched` method updates fetched prices (write lock) without
/// touching overrides.
#[derive(Debug, Clone)]
pub struct PriceTable {
    inner: Arc<RwLock<HashMap<String, PricedModel>>>,
}

impl PriceTable {
    /// Builds a `PriceTable` from the pricing config. These entries are
    /// stored as overrides (they take precedence over any fetched prices).
    #[must_use]
    pub fn from_config(config: &PricingConfig) -> Self {
        let mut prices = HashMap::new();
        for m in &config.models {
            prices.insert(
                m.model.clone(),
                PricedModel {
                    price: ModelPrice {
                        input_per_1k_usd: m.input_per_1k_usd,
                        output_per_1k_usd: m.output_per_1k_usd,
                    },
                    source: PriceSource::Override,
                },
            );
        }
        Self {
            inner: Arc::new(RwLock::new(prices)),
        }
    }

    /// Creates an empty `PriceTable` (no pricing configured).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Computes the cost of a request in USD.
    ///
    /// Returns `0.0` if the model is not in the price table (unknown model
    /// or no pricing configured). Overrides take precedence over fetched
    /// prices.
    #[must_use]
    pub async fn compute_cost(
        &self,
        model: &str,
        prompt_tokens: Option<i32>,
        completion_tokens: Option<i32>,
    ) -> f64 {
        let prices = self.inner.read().await;
        let Some(entry) = prices.get(model) else {
            return 0.0;
        };
        let prompt = f64::from(prompt_tokens.unwrap_or(0));
        let completion = f64::from(completion_tokens.unwrap_or(0));
        (prompt / 1000.0) * entry.price.input_per_1k_usd
            + (completion / 1000.0) * entry.price.output_per_1k_usd
    }

    /// Returns the number of models in the table.
    pub async fn len(&self) -> usize {
        self.inner.read().await.len()
    }

    /// Returns `true` if the table is empty.
    pub async fn is_empty(&self) -> bool {
        self.inner.read().await.is_empty()
    }

    /// Returns the source of a model's price (for debugging).
    pub async fn price_source(&self, model: &str) -> Option<PriceSource> {
        self.inner.read().await.get(model).map(|e| e.source)
    }

    /// Fetches prices from the backend's `/v1/models` endpoint and merges
    /// them into the table. Fetched prices do **not** overwrite existing
    /// override entries — only models without a manual override are updated.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`] on network or parse failure.
    pub async fn fetch_from_backend(
        &self,
        client: &reqwest::Client,
        base_url: &str,
    ) -> Result<usize> {
        let url = format!("{}/v1/models", base_url.trim_end_matches('/'));
        let resp = client
            .get(&url)
            .send()
            .await
            .map_err(|e| Error::Http(format!("fetch pricing: {e}")))?;

        if !resp.status().is_success() {
            return Err(Error::Http(format!(
                "fetch pricing: backend returned {}",
                resp.status()
            )));
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| Error::Http(format!("fetch pricing: parse JSON: {e}")))?;

        let fetched = parse_models_response(&body);
        if fetched.is_empty() {
            return Ok(0);
        }

        // Merge: only update models that don't already have an override.
        let mut prices = self.inner.write().await;
        let mut count = 0;
        for (model, price) in fetched {
            // Don't overwrite overrides.
            if let Some(existing) = prices.get(&model) {
                if existing.source == PriceSource::Override {
                    continue;
                }
            }
            prices.insert(
                model,
                PricedModel {
                    price,
                    source: PriceSource::Fetched,
                },
            );
            count += 1;
        }

        Ok(count)
    }

    /// Starts a background task that periodically refreshes fetched prices
    /// from the backend. Returns immediately; the task runs until the
    /// process exits.
    pub fn spawn_refresh_task(
        &self,
        client: reqwest::Client,
        base_url: String,
        interval: std::time::Duration,
    ) {
        let table = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                match table.fetch_from_backend(&client, &base_url).await {
                    Ok(count) => {
                        if count > 0 {
                            tracing::info!("refreshed {count} model prices from backend");
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to refresh model prices");
                    }
                }
            }
        });
    }
}

/// Parses a `/v1/models` response (OpenRouter/OpenAI format) into a map of
/// model → price.
///
/// OpenRouter format:
/// ```json
/// {"data": [{"id": "model-name", "pricing": {"prompt": "0.0000025", "completion": "0.00001"}}]}
/// ```
///
/// Prices are per-token (as strings); we convert to per-1K-tokens.
/// Models without pricing fields are skipped.
fn parse_models_response(body: &serde_json::Value) -> HashMap<String, ModelPrice> {
    let mut result = HashMap::new();
    let Some(data) = body.get("data").and_then(|d| d.as_array()) else {
        return result;
    };
    for model in data {
        let Some(id) = model.get("id").and_then(|v| v.as_str()) else {
            continue;
        };
        let pricing = model.get("pricing");
        let Some(pricing) = pricing else {
            continue;
        };
        // OpenRouter uses string-valued per-token prices.
        let prompt_per_token = pricing
            .get("prompt")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<f64>().ok());
        let completion_per_token = pricing
            .get("completion")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<f64>().ok());

        match (prompt_per_token, completion_per_token) {
            (Some(p), Some(c)) => {
                // Convert per-token to per-1K-tokens.
                result.insert(
                    id.to_string(),
                    ModelPrice {
                        input_per_1k_usd: p * 1000.0,
                        output_per_1k_usd: c * 1000.0,
                    },
                );
            }
            _ => {
                // Some backends might use numeric fields instead of strings.
                let prompt_num = pricing.get("prompt").and_then(|v| v.as_f64());
                let completion_num = pricing.get("completion").and_then(|v| v.as_f64());
                if let (Some(p), Some(c)) = (prompt_num, completion_num) {
                    result.insert(
                        id.to_string(),
                        ModelPrice {
                            input_per_1k_usd: p * 1000.0,
                            output_per_1k_usd: c * 1000.0,
                        },
                    );
                }
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use oidc_agent_common::config::{ModelPriceConfig, PricingConfig};

    fn test_config() -> PricingConfig {
        PricingConfig {
            models: vec![
                ModelPriceConfig {
                    model: "gpt-4o".into(),
                    input_per_1k_usd: 0.0025,
                    output_per_1k_usd: 0.01,
                },
                ModelPriceConfig {
                    model: "gpt-4o-mini".into(),
                    input_per_1k_usd: 0.00015,
                    output_per_1k_usd: 0.0006,
                },
            ],
            fetch_interval_secs: 3600,
        }
    }

    #[tokio::test]
    async fn compute_cost_known_model() {
        let table = PriceTable::from_config(&test_config());
        let cost = table.compute_cost("gpt-4o", Some(1000), Some(500)).await;
        // 1000/1000 * 0.0025 + 500/1000 * 0.01 = 0.0025 + 0.005 = 0.0075
        assert!((cost - 0.0075).abs() < 0.0001, "cost was {cost}");
    }

    #[tokio::test]
    async fn compute_cost_unknown_model_returns_zero() {
        let table = PriceTable::from_config(&test_config());
        let cost = table
            .compute_cost("unknown-model", Some(1000), Some(500))
            .await;
        assert_eq!(cost, 0.0);
    }

    #[tokio::test]
    async fn compute_cost_no_tokens_returns_zero() {
        let table = PriceTable::from_config(&test_config());
        let cost = table.compute_cost("gpt-4o", None, None).await;
        assert_eq!(cost, 0.0);
    }

    #[tokio::test]
    async fn compute_cost_empty_table() {
        let table = PriceTable::empty();
        let cost = table.compute_cost("gpt-4o", Some(1000), Some(500)).await;
        assert_eq!(cost, 0.0);
    }

    #[test]
    fn parse_models_response_openrouter_format() {
        let json = serde_json::json!({
            "data": [
                {
                    "id": "openai/gpt-4o",
                    "pricing": {"prompt": "0.0000025", "completion": "0.00001"}
                },
                {
                    "id": "openai/gpt-4o-mini",
                    "pricing": {"prompt": "0.00000015", "completion": "0.0000006"}
                },
                {
                    "id": "no-pricing-model",
                    "pricing": {}
                }
            ]
        });
        let prices = parse_models_response(&json);
        assert_eq!(prices.len(), 2);
        let gpt4o = &prices["openai/gpt-4o"];
        // per-token 0.0000025 → per-1k 0.0025
        assert!((gpt4o.input_per_1k_usd - 0.0025).abs() < 0.0001);
        assert!((gpt4o.output_per_1k_usd - 0.01).abs() < 0.0001);
    }

    #[test]
    fn parse_models_response_numeric_format() {
        let json = serde_json::json!({
            "data": [
                {
                    "id": "test-model",
                    "pricing": {"prompt": 0.0000025, "completion": 0.00001}
                }
            ]
        });
        let prices = parse_models_response(&json);
        assert_eq!(prices.len(), 1);
        assert!((prices["test-model"].input_per_1k_usd - 0.0025).abs() < 0.0001);
    }

    #[test]
    fn parse_models_response_empty_data() {
        let json = serde_json::json!({"data": []});
        let prices = parse_models_response(&json);
        assert!(prices.is_empty());
    }

    #[test]
    fn parse_models_response_no_data_field() {
        let json = serde_json::json!({});
        let prices = parse_models_response(&json);
        assert!(prices.is_empty());
    }

    #[tokio::test]
    async fn override_takes_precedence_over_fetched() {
        // Config has gpt-4o at 0.0025/1K input.
        let table = PriceTable::from_config(&test_config());

        // Simulate a fetch that would set gpt-4o to a different price.
        let fetched = HashMap::from([(
            "gpt-4o".to_string(),
            ModelPrice {
                input_per_1k_usd: 0.999,
                output_per_1k_usd: 0.999,
            },
        )]);

        // Merge manually (simulating fetch_from_backend's merge logic).
        {
            let mut prices = table.inner.write().await;
            for (model, price) in fetched {
                if let Some(existing) = prices.get(&model) {
                    if existing.source == PriceSource::Override {
                        continue;
                    }
                }
                prices.insert(
                    model,
                    PricedModel {
                        price,
                        source: PriceSource::Fetched,
                    },
                );
            }
        }

        // The override price should still be used.
        let cost = table.compute_cost("gpt-4o", Some(1000), Some(0)).await;
        assert!(
            (cost - 0.0025).abs() < 0.0001,
            "override must take precedence, cost was {cost}"
        );
        assert_eq!(
            table.price_source("gpt-4o").await,
            Some(PriceSource::Override)
        );
    }

    #[tokio::test]
    async fn fetched_price_used_when_no_override() {
        let table = PriceTable::empty();

        // Simulate a fetch.
        {
            let mut prices = table.inner.write().await;
            prices.insert(
                "fetched-model".into(),
                PricedModel {
                    price: ModelPrice {
                        input_per_1k_usd: 0.005,
                        output_per_1k_usd: 0.015,
                    },
                    source: PriceSource::Fetched,
                },
            );
        }

        let cost = table
            .compute_cost("fetched-model", Some(1000), Some(500))
            .await;
        // 1000/1000 * 0.005 + 500/1000 * 0.015 = 0.005 + 0.0075 = 0.0125
        assert!((cost - 0.0125).abs() < 0.0001);
        assert_eq!(
            table.price_source("fetched-model").await,
            Some(PriceSource::Fetched)
        );
    }
}
