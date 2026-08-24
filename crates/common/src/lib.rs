//! Shared primitives for the OIDC agent compatibility server.
//!
//! This crate contains security-critical code shared by the laptop relay and
//! the central proxy. Each module is independently testable and documented.
//!
//! # Modules
//!
//! - [`error`] — the unified [`Error`] type for all error kinds.
//! - [`keys`] — local API key generation, hashing, and constant-time verification.
//! - [`config`] — configuration structs and validation for both components.
//! - [`oidc`] — OIDC relying-party client builder.
//! - [`mtls`] — rustls mTLS client and server configuration builders.
//! - [`logging`] — structured JSON logging with secret redaction.
//!
//! # Security
//!
//! This crate is compiled with `#![forbid(unsafe_code)]`. No `unsafe` blocks
//! are permitted anywhere in the shared code path.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
// In tests, `unwrap`/`expect` are acceptable for brevity and clarity.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod config;
pub mod error;
pub mod keys;
pub mod logging;
pub mod mtls;
pub mod oidc;
