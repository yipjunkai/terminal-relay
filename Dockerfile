# Build stage
FROM rust:1.92-slim-bookworm AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

# Copy workspace manifests first for layer caching
COPY Cargo.toml Cargo.lock ./
COPY crates/protocol/Cargo.toml crates/protocol/Cargo.toml
COPY crates/relay/Cargo.toml crates/relay/Cargo.toml
COPY crates/cli/Cargo.toml crates/cli/Cargo.toml

# Create dummy source files to cache dependency compilation
RUN mkdir -p crates/protocol/src && echo "pub fn _dummy() {}" > crates/protocol/src/lib.rs \
    && mkdir -p crates/relay/src && echo "fn main() {}" > crates/relay/src/main.rs \
    && mkdir -p crates/cli/src && echo "fn main() {}" > crates/cli/src/main.rs

RUN cargo build --release --package relay

# Remove dummy artifacts so real source gets compiled
RUN rm -rf crates/*/src target/release/.fingerprint/relay-* target/release/.fingerprint/protocol-* target/release/.fingerprint/cli-*

# Copy real source
COPY crates/ crates/

RUN cargo build --release --package relay

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/relay /usr/local/bin/relay

EXPOSE 8080

ENTRYPOINT ["relay"]
