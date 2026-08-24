FROM rust:1.98-slim AS builder
WORKDIR /build
# Install needed system libs for rustls + sqlite
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev ca-certificates && \
    rm -rf /var/lib/apt/lists/*
# Copy workspace
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY tests/ tests/
# Build release binaries
RUN cargo build --release -p oac-central -p oac-relay

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/oac-central /usr/local/bin/oac-central
COPY --from=builder /build/target/release/oac-relay /usr/local/bin/oac-relay
