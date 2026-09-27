# Multi-stage Dockerfile for Deslop Platform
# Build stage
FROM rust:1.85-bookworm AS builder

WORKDIR /usr/src/deslop

# Copy workspace manifests
COPY Cargo.toml ./
COPY crates ./crates

# Build release binaries with full optimizations
RUN cargo build --release -p deslop-cli

# Final minimal runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy the compiled binary
COPY --from=builder /usr/src/deslop/target/release/deslop /usr/local/bin/deslop

WORKDIR /workspace

# Default command shows help; user mounts volume at /workspace
ENTRYPOINT ["deslop"]
CMD ["--help"]
