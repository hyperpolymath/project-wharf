# SPDX-License-Identifier: PMPL-1.0
# SPDX-FileCopyrightText: 2025 hyperpolymath

# Multi-stage Dockerfile for Project Wharf
# Builds both wharf-cli and yacht-agent binaries

FROM rust:1.85-slim-bookworm AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY bin/ bin/

# Build release binaries
RUN cargo build --release

# Runtime image for wharf-cli
FROM debian:bookworm-slim AS wharf-cli

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/wharf /usr/local/bin/wharf

ENTRYPOINT ["wharf"]
CMD ["--help"]

# Runtime image for yacht-agent
FROM debian:bookworm-slim AS yacht-agent

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/yacht-agent /usr/local/bin/yacht-agent

EXPOSE 3306 33060 9001

ENTRYPOINT ["yacht-agent"]
CMD ["--help"]
