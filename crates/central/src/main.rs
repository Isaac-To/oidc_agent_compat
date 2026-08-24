//! The central proxy component of the OIDC agent compatibility server.
//!
//! The central proxy is company-hosted (cloud/VPC). It holds the master
//! backend key in a managed secret store (Vault / AWS Secrets Manager / etc.),
//! authenticates relay requests via mTLS + user-token validation, and forwards
//! approved requests to the OpenAI-compatible backend with SSE streaming.
//! The master key **never** leaves this process and never touches any laptop.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

fn main() {
    println!("oac-central — central proxy (skeleton)");
}
