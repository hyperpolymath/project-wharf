# SPDX-License-Identifier: PMPL-1.0-or-later
# SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell (hyperpolymath) <jonathan.jewell@open.ac.uk>
#
# PHP-FPM Container for Project Wharf
# ====================================
# Hardened PHP runtime for CMS workloads.
# Uses Chainguard PHP for minimal attack surface.
#
# Build: podman build -t yacht-php:latest -f infra/containers/Containerfile.php .
# Run:   podman run -d -p 9000:9000 -v ./html:/var/www/html:ro yacht-php:latest

FROM cgr.dev/chainguard/php:latest-fpm

LABEL org.opencontainers.image.title="Yacht PHP"
LABEL org.opencontainers.image.description="Hardened PHP-FPM for Project Wharf"
LABEL org.opencontainers.image.vendor="Hyperpolymath"

# Harden PHP configuration
COPY infra/config/php-fpm.conf /usr/local/etc/php-fpm.d/www.conf

WORKDIR /var/www/html

EXPOSE 9000

CMD ["php-fpm", "-F"]
