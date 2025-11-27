# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Jonathan D. A. Jewell <hyperpolymath>
#
# Yacht Agent Container for Project Wharf
# ========================================
# TRUE DISTROLESS - No shell, no libc, no attack surface.
# Just the statically-linked Rust binary.
#
# Build: podman build -t yacht-agent:latest -f infra/containers/agent.Dockerfile .
# Run:   podman run -d -p 3306:3306 -p 9001:9001 yacht-agent:latest

# -----------------------------------------------------------------------------
# Stage 1: Build the Rust binary (fully static with musl)
# -----------------------------------------------------------------------------
FROM docker.io/library/rust:1.75-alpine AS builder

RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static pkgconf

# Add musl target for fully static binary
RUN rustup target add x86_64-unknown-linux-musl

WORKDIR /build

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY crates/wharf-core ./crates/wharf-core
COPY bin/yacht-agent ./bin/yacht-agent
COPY bin/wharf-cli ./bin/wharf-cli

# Build release binary with static linking for musl
ENV RUSTFLAGS="-C target-feature=+crt-static -C link-self-contained=yes"
ENV OPENSSL_STATIC=1
ENV OPENSSL_LIB_DIR=/usr/lib
ENV OPENSSL_INCLUDE_DIR=/usr/include

RUN cargo build --release --bin yacht-agent --target x86_64-unknown-linux-musl

# Strip the binary for smaller size
RUN strip target/x86_64-unknown-linux-musl/release/yacht-agent

# Verify it's static
RUN file target/x86_64-unknown-linux-musl/release/yacht-agent | grep -q "statically linked"

# -----------------------------------------------------------------------------
# Stage 2: TRUE DISTROLESS - Chainguard static image
# -----------------------------------------------------------------------------
# This image contains NOTHING - no shell, no package manager, no libc
# Attack surface: essentially zero
FROM cgr.dev/chainguard/static:latest

LABEL org.opencontainers.image.title="Yacht Agent"
LABEL org.opencontainers.image.description="Database proxy and security enforcer for Project Wharf"
LABEL org.opencontainers.image.vendor="Hyperpolymath"
LABEL org.opencontainers.image.source="https://gitlab.com/hyperpolymath/wharf"

# Copy the static binary
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/yacht-agent /yacht-agent

# Database proxy port (masquerade as MySQL)
EXPOSE 3306
# Agent API port (health checks, metrics, mooring)
EXPOSE 9001

# Chainguard static runs as nonroot (65532) by default
# No USER directive needed - it's baked into the base image

# No healthcheck in distroless (no wget/curl)
# Use Kubernetes/Podman liveness probe with TCP or HTTP check instead

ENTRYPOINT ["/yacht-agent"]
CMD ["--listen-port", "3306", "--shadow-port", "33060", "--api-port", "9001"]
