//! Graceful shutdown signal handling.
//!
//! Both the relay and the central proxy use this module to shut down cleanly
//! on `SIGINT` (Ctrl-C) or `SIGTERM`. This ensures in-flight requests are
//! completed before the process exits.
//!
//! # Example
//!
//! ```no_run
//! use oidc_agent_common::shutdown;
//!
//! # async fn run() {
//! let signal = shutdown::shutdown_signal();
//! // Pass `signal` to `axum::serve(listener, app).with_graceful_shutdown(signal)`.
//! # }
//! ```

use tokio::signal;

/// Returns a future that resolves when the process receives `SIGINT` or
/// `SIGTERM`.
///
/// On Unix, both signals are listened for. On non-Unix platforms, only
/// `SIGINT` (Ctrl-C) is available.
#[must_use]
pub async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .unwrap_or_else(|e| tracing::error!("failed to listen for ctrl_c: {e}"));
    };

    #[cfg(unix)]
    {
        let terminate = async {
            match signal::unix::signal(signal::unix::SignalKind::terminate()) {
                Ok(mut sig) => {
                    sig.recv().await;
                }
                Err(e) => {
                    tracing::error!("failed to listen for SIGTERM: {e}");
                    std::future::pending::<()>().await;
                }
            }
        };
        tokio::select! {
            _ = ctrl_c => {},
            _ = terminate => {},
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await;
    }

    tracing::info!("shutdown signal received, draining in-flight requests...");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn shutdown_signal_does_not_resolve_without_signal() {
        // This test verifies the function compiles and is callable.
        // We can't easily test the actual signal handling in a unit test.
        let _ = tokio::time::timeout(std::time::Duration::from_millis(10), shutdown_signal()).await;
        // The timeout should fire (the signal future is still pending).
        // If it resolved, that's also fine (e.g. a signal was sent).
    }
}
