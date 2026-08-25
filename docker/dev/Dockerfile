FROM rust:1.98-slim AS builder
WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev ca-certificates && \
    rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY tests/ tests/
RUN cargo build --release -p oac-central -p oac-relay

# Use trixie-slim to match the glibc version in the rust:1.98-slim builder
# (rust 1.98 is based on Debian trixie, glibc 2.41; bookworm has glibc 2.36).
FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 curl && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/oac-central /usr/local/bin/oac-central
COPY --from=builder /build/target/release/oac-relay /usr/local/bin/oac-relay
