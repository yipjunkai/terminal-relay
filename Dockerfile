# Build stage
# Base images pinned by digest (tag kept in the comment for readability).
# Dependabot's docker ecosystem bumps these; a digest is immutable, so the
# build is reproducible and can't be swapped under a moved tag.
FROM rust:1.98-slim-bookworm@sha256:94e9efa4033213dbb70d4f665527e7ece3944ddb7ba1dd2e43f6fd6e2490af58 AS builder

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
FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/relay /usr/local/bin/relay

EXPOSE 8080

ENTRYPOINT ["relay"]
