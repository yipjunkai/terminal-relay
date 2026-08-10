# Build stage
# Base images pinned by digest (tag kept in the comment for readability).
# Dependabot's docker ecosystem bumps these; a digest is immutable, so the
# build is reproducible and can't be swapped under a moved tag.
FROM rust:1.92-slim-bookworm@sha256:f1f73538ebe623fd3673a35aff3df358ae1084c64c55646516e5b17b321b6c9b AS builder

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
FROM debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/relay /usr/local/bin/relay

EXPOSE 8080

ENTRYPOINT ["relay"]
