# SPDX-License-Identifier: PMPL-1.0-or-later
# SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell (hyperpolymath) <jonathan.jewell@open.ac.uk>

# Multi-stage Containerfile for Project Wharf
# Builds both wharf-cli and yacht-agent binaries
# Uses Chainguard images for minimal attack surface

# Builder stage — Wolfi-base with Rust toolchain
FROM cgr.dev/chainguard/wolfi-base:latest AS builder

RUN apk add --no-cache rust pkgconf openssl-dev gcc glibc-dev

WORKDIR /build

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY bin/ bin/
# Dummy xtask for workspace resolution
RUN mkdir -p xtask/src && echo 'fn main() {}' > xtask/src/main.rs
COPY xtask/Cargo.toml xtask/Cargo.toml

# Build release binaries
RUN cargo build --release --bin wharf --bin yacht-agent

# Runtime image for wharf-cli
FROM cgr.dev/chainguard/wolfi-base:latest AS wharf-cli

COPY --from=builder /build/target/release/wharf /usr/local/bin/wharf

ENTRYPOINT ["wharf"]
CMD ["--help"]

# Runtime image for yacht-agent (distroless — zero attack surface)
FROM cgr.dev/chainguard/static:latest AS yacht-agent

COPY --from=builder /build/target/release/yacht-agent /yacht-agent

EXPOSE 3306 33060 9001

ENTRYPOINT ["/yacht-agent"]
CMD ["--help"]
