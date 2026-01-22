# SPDX-License-Identifier: PMPL-1.0
# SPDX-FileCopyrightText: 2025 Jonathan D. A. Jewell <hyperpolymath>
#
# OpenLiteSpeed + PHP Container for Project Wharf
# ================================================
# High-performance web server with native PHP LSAPI (faster than FastCGI).
# Includes WordPress-optimized configuration and LiteSpeed Cache support.
#
# Legacy build (development only). Production images should be built with
# Cerro Torre manifests in infra/cerro/.
# Build: podman build -t yacht-web:latest -f infra/containers/openlitespeed.Dockerfile .
# Run:   podman run -d -p 8080:8080 -v ./html:/var/www/html:ro yacht-web:latest

# -----------------------------------------------------------------------------
# OpenLiteSpeed official image with PHP 8.3
# -----------------------------------------------------------------------------
FROM litespeedtech/openlitespeed:1.7.19-lsphp83

LABEL org.opencontainers.image.title="Yacht Web Server"
LABEL org.opencontainers.image.description="OpenLiteSpeed + PHP 8.3 for Project Wharf"
LABEL org.opencontainers.image.vendor="Hyperpolymath"
LABEL org.opencontainers.image.source="https://gitlab.com/hyperpolymath/wharf"

# Install additional PHP extensions for CMS compatibility
RUN apt-get update && apt-get install -y --no-install-recommends \
    lsphp83-mysql \
    lsphp83-curl \
    lsphp83-gd \
    lsphp83-intl \
    lsphp83-mbstring \
    lsphp83-xml \
    lsphp83-zip \
    lsphp83-bcmath \
    lsphp83-redis \
    lsphp83-imagick \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# -----------------------------------------------------------------------------
# Security Hardening
# -----------------------------------------------------------------------------

# Harden PHP configuration
RUN { \
    echo '[PHP]'; \
    echo 'expose_php = Off'; \
    echo 'display_errors = Off'; \
    echo 'log_errors = On'; \
    echo 'error_log = /dev/stderr'; \
    echo 'memory_limit = 256M'; \
    echo 'max_execution_time = 60'; \
    echo 'upload_max_filesize = 64M'; \
    echo 'post_max_size = 64M'; \
    echo 'allow_url_fopen = Off'; \
    echo 'allow_url_include = Off'; \
    echo 'session.cookie_httponly = 1'; \
    echo 'session.cookie_secure = 1'; \
    echo 'session.use_strict_mode = 1'; \
    echo ''; \
    echo '[opcache]'; \
    echo 'opcache.enable = 1'; \
    echo 'opcache.memory_consumption = 128'; \
    echo 'opcache.max_accelerated_files = 10000'; \
    echo 'opcache.revalidate_freq = 0'; \
    echo 'opcache.validate_timestamps = 0'; \
    echo ''; \
    echo '; Disable dangerous functions (comment for debugging)'; \
    echo 'disable_functions = exec,passthru,shell_exec,system,proc_open,popen,parse_ini_file,show_source'; \
} > /usr/local/lsws/lsphp83/etc/php/8.3/litespeed/conf.d/99-wharf-security.ini

# Copy OpenLiteSpeed configuration
COPY infra/config/openlitespeed/ /usr/local/lsws/conf/

# Copy WordPress-specific rewrite rules
COPY infra/config/wordpress-ols.conf /usr/local/lsws/conf/vhosts/wordpress/rewrite.conf

# -----------------------------------------------------------------------------
# Directory Setup
# -----------------------------------------------------------------------------

# Web root (will be mounted read-only)
RUN mkdir -p /var/www/html \
    && mkdir -p /var/www/html/wp-content/uploads \
    && mkdir -p /var/www/html/wp-content/cache

# Temp directories (RAM disk in production)
RUN mkdir -p /tmp/lshttpd \
    && mkdir -p /dev/shm/lscache

# Create non-root user for web server
RUN groupadd -g 1000 wharf \
    && useradd -u 1000 -g wharf -s /bin/false -M wharf \
    && chown -R wharf:wharf /var/www/html \
    && chown -R wharf:wharf /tmp/lshttpd \
    && chown -R wharf:wharf /dev/shm/lscache

# Fix permissions for OLS
RUN chown -R lsadm:lsadm /usr/local/lsws/conf \
    && chown -R lsadm:lsadm /usr/local/lsws/logs \
    && chown -R lsadm:lsadm /usr/local/lsws/tmp

# -----------------------------------------------------------------------------
# Runtime
# -----------------------------------------------------------------------------

# Non-privileged ports (use eBPF/iptables to redirect 80->8080, 443->8443)
EXPOSE 8080 8443

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -sf http://localhost:8080/health || exit 1

WORKDIR /var/www/html

# OLS runs its own process management
ENTRYPOINT ["/usr/local/lsws/bin/lswsctrl"]
CMD ["start"]
