# SPDX-License-Identifier: PMPL-1.0
# SPDX-FileCopyrightText: 2025 Jonathan D. A. Jewell <hyperpolymath>
#
# Nginx Container for Project Wharf
# ==================================
# Hardened reverse proxy with security headers.
#
# Build: podman build -t yacht-nginx:latest -f infra/containers/nginx.Dockerfile .
# Run:   podman run -d -p 8080:8080 -v ./html:/var/www/html:ro yacht-nginx:latest

ARG BASE_IMAGE=docker.io/library/nginx:alpine

FROM ${BASE_IMAGE}

LABEL org.opencontainers.image.title="Yacht Nginx"
LABEL org.opencontainers.image.description="Hardened Nginx for Project Wharf"
LABEL org.opencontainers.image.vendor="Hyperpolymath"

# Remove default config
RUN rm -rf /etc/nginx/conf.d/*

# Copy our hardened configuration
COPY infra/config/nginx.conf /etc/nginx/nginx.conf
COPY infra/config/wordpress-rules.conf /etc/nginx/conf.d/default.conf

# Create required directories
RUN mkdir -p /tmp/nginx \
    && mkdir -p /var/www/html \
    && mkdir -p /var/cache/nginx

# Create non-root user and fix permissions
RUN addgroup -g 1000 wharf 2>/dev/null || true \
    && adduser -u 1000 -G wharf -s /bin/false -D wharf 2>/dev/null || true \
    && chown -R wharf:wharf /var/www/html \
    && chown -R wharf:wharf /var/cache/nginx \
    && chown -R wharf:wharf /tmp/nginx \
    && chown -R wharf:wharf /var/log/nginx \
    && touch /var/run/nginx.pid \
    && chown wharf:wharf /var/run/nginx.pid

USER wharf
WORKDIR /var/www/html

# Non-privileged port (use eBPF or iptables to redirect 80->8080)
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -q --spider http://localhost:8080/health || exit 1

CMD ["nginx", "-g", "daemon off;"]
