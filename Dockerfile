# syntax=docker/dockerfile:1

# Stage 1: Build
FROM rust:1.94-slim AS builder

WORKDIR /build

# Install build dependencies for aws-lc-rs (reqwest's TLS provider)
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake \
    clang \
    && rm -rf /var/lib/apt/lists/*

# Cache dependencies by copying manifests first
COPY Cargo.toml Cargo.lock ./

# Build a dummy main to pre-compile dependencies
RUN mkdir src && echo 'fn main() {}' > src/main.rs \
    && cargo build --release --no-default-features \
    && rm -rf src

# Build the real binary
COPY src ./src
RUN touch src/main.rs && cargo build --release --no-default-features

# Stage 2: Runtime
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/camoflage /usr/local/bin/camoflage

EXPOSE 8081

ENTRYPOINT ["/usr/local/bin/camoflage"]
