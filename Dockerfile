# Feature #86: Docker image for aikido
# Pre-built container for CI without Rust toolchain
#
# Build: docker build -t aikido .
# Usage: docker run --rm -v $(pwd):/project aikido /project
# CI:    docker run --rm -v $(pwd):/project aikido /project --format sarif > results.sarif

FROM rust:1.88-slim AS builder

WORKDIR /build
COPY . .

RUN cargo build --release --bin aikido

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    git \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/aikido /usr/local/bin/aikido

ENTRYPOINT ["aikido"]
CMD ["--help"]
