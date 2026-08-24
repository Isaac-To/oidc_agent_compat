//! The laptop relay component of the OIDC agent compatibility server.
//!
//! The relay listens on `127.0.0.1`, authenticates the employee via OIDC
//! against the enterprise IdP, mints a local API key that is auto-injected
//! into the agent's config, and forwards agent requests to the central proxy
//! over mTLS. It holds **no master backend key** — only a short-lived user
//! token and an mTLS client certificate.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

fn main() {
    println!("oac-relay — laptop relay (skeleton)");
}
