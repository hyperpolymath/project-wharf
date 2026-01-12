# SPDX-License-Identifier: PMPL-1.0
# SPDX-FileCopyrightText: 2025 Jonathan D. A. Jewell <hyperpolymath>
#
# PHP-FPM Container for Project Wharf
# ====================================
# Hardened PHP runtime for CMS workloads.
#
# Build: podman build -t yacht-php:latest -f infra/containers/php.Dockerfile .
# Run:   podman run -d -p 9000:9000 -v ./html:/var/www/html:ro yacht-php:latest

# Use Chainguard if available, fallback to Alpine
ARG BASE_IMAGE=docker.io/library/php:8.3-fpm-alpine

FROM ${BASE_IMAGE}

LABEL org.opencontainers.image.title="Yacht PHP"
LABEL org.opencontainers.image.description="Hardened PHP-FPM for Project Wharf"
LABEL org.opencontainers.image.vendor="Hyperpolymath"

# Install required PHP extensions for CMS compatibility
RUN apk add --no-cache \
    # Core extensions
    php83-mysqli \
    php83-pdo_mysql \
    php83-pdo_pgsql \
    php83-mbstring \
    php83-gd \
    php83-xml \
    php83-curl \
    php83-zip \
    php83-intl \
    php83-bcmath \
    php83-sodium \
    php83-opcache \
    php83-exif \
    php83-fileinfo \
    php83-session \
    php83-tokenizer \
    # For Redis sessions
    php83-pecl-redis \
    2>/dev/null || true

# If using official PHP image, install via docker-php-ext
RUN docker-php-ext-install mysqli pdo pdo_mysql opcache 2>/dev/null || true

# Harden PHP configuration
RUN { \
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
    # OPcache for performance
    echo 'opcache.enable = 1'; \
    echo 'opcache.memory_consumption = 128'; \
    echo 'opcache.max_accelerated_files = 10000'; \
    echo 'opcache.revalidate_freq = 0'; \
    echo 'opcache.validate_timestamps = 0'; \
    # Disable dangerous functions (comment out for debugging)
    echo 'disable_functions = exec,passthru,shell_exec,system,proc_open,popen'; \
} > /usr/local/etc/php/conf.d/wharf-security.ini

# Copy FPM pool configuration
COPY infra/config/php-fpm.conf /usr/local/etc/php-fpm.d/www.conf

# Create web directories
RUN mkdir -p /var/www/html/wp-content/uploads \
    && mkdir -p /var/www/html/wp-content/cache

# Create non-root user
RUN addgroup -g 1000 wharf && adduser -u 1000 -G wharf -s /bin/false -D wharf \
    && chown -R wharf:wharf /var/www/html

USER wharf
WORKDIR /var/www/html

EXPOSE 9000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD php-fpm -t 2>/dev/null || exit 1

CMD ["php-fpm", "-F"]
