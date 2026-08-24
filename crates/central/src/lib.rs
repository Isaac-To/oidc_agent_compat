//! Library crate for the central proxy, exposing modules for integration tests.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)
)]

pub mod audit;
pub mod db;
pub mod entity;
pub mod migration;
pub mod proxy;
pub mod secrets;
