//! Library crate for the relay, exposing modules for integration tests.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
#![cfg_attr(
    any(test, feature = "test-utils"),
    allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)
)]

pub mod activity;
pub mod agent_config;
pub mod db;
pub mod entity;
pub mod keystore;
pub mod login;
pub mod migration;
pub mod proxy;
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;
