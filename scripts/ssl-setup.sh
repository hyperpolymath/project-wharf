#!/bin/bash
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Jonathan D. A. Jewell <hyperpolymath>
#
# SSL/TLS Certificate Setup for Project Wharf
# ============================================
# This script helps set up Let's Encrypt certificates for Yacht deployments.
#
# Usage:
#   ./ssl-setup.sh init <domain>           # First-time setup
#   ./ssl-setup.sh renew                   # Renew all certificates
#   ./ssl-setup.sh status                  # Check certificate status
#   ./ssl-setup.sh install <yacht>         # Push certs to a yacht

set -euo pipefail

# Configuration
CERT_DIR="${WHARF_CERT_DIR:-/opt/wharf/certs}"
ACME_EMAIL="${WHARF_ACME_EMAIL:-admin@example.com}"
ACME_SERVER="${WHARF_ACME_SERVER:-https://acme-v02.api.letsencrypt.org/directory}"
# Use staging for testing: https://acme-staging-v02.api.letsencrypt.org/directory

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check for required tools
check_requirements() {
    local missing=()

    if ! command -v certbot &> /dev/null; then
        missing+=("certbot")
    fi

    if ! command -v openssl &> /dev/null; then
        missing+=("openssl")
    fi

    if [ ${#missing[@]} -gt 0 ]; then
        log_error "Missing required tools: ${missing[*]}"
        echo ""
        echo "Install with:"
        echo "  Debian/Ubuntu: apt install certbot openssl"
        echo "  Fedora/RHEL:   dnf install certbot openssl"
        echo "  Alpine:        apk add certbot openssl"
        echo "  macOS:         brew install certbot openssl"
        exit 1
    fi
}

# Initialize certificates for a domain
init_cert() {
    local domain="$1"

    if [ -z "$domain" ]; then
        log_error "Domain required. Usage: $0 init <domain>"
        exit 1
    fi

    log_info "Initializing SSL certificate for: $domain"

    # Create certificate directory
    mkdir -p "$CERT_DIR"

    # Check if we can use HTTP challenge (port 80 available)
    if ss -tlnp | grep -q ':80 '; then
        log_warn "Port 80 is in use. Using DNS challenge instead."
        CHALLENGE="--preferred-challenges dns"
    else
        CHALLENGE="--preferred-challenges http"
    fi

    # Request certificate
    log_info "Requesting certificate from Let's Encrypt..."

    certbot certonly \
        --standalone \
        $CHALLENGE \
        --non-interactive \
        --agree-tos \
        --email "$ACME_EMAIL" \
        --server "$ACME_SERVER" \
        -d "$domain" \
        --cert-path "$CERT_DIR/$domain/cert.pem" \
        --key-path "$CERT_DIR/$domain/privkey.pem" \
        --fullchain-path "$CERT_DIR/$domain/fullchain.pem" \
        --config-dir "$CERT_DIR/letsencrypt" \
        --work-dir "$CERT_DIR/work" \
        --logs-dir "$CERT_DIR/logs"

    if [ $? -eq 0 ]; then
        log_info "Certificate obtained successfully!"
        log_info "Certificate: $CERT_DIR/$domain/fullchain.pem"
        log_info "Private key: $CERT_DIR/$domain/privkey.pem"

        # Create symlinks for OpenLiteSpeed
        mkdir -p "$CERT_DIR/live/default"
        ln -sf "$CERT_DIR/letsencrypt/live/$domain/fullchain.pem" "$CERT_DIR/live/default/fullchain.pem"
        ln -sf "$CERT_DIR/letsencrypt/live/$domain/privkey.pem" "$CERT_DIR/live/default/privkey.pem"

        log_info "Symlinks created in $CERT_DIR/live/default/"
    else
        log_error "Failed to obtain certificate"
        exit 1
    fi
}

# Renew all certificates
renew_certs() {
    log_info "Renewing certificates..."

    certbot renew \
        --config-dir "$CERT_DIR/letsencrypt" \
        --work-dir "$CERT_DIR/work" \
        --logs-dir "$CERT_DIR/logs" \
        --quiet

    if [ $? -eq 0 ]; then
        log_info "Renewal check complete"
    else
        log_error "Renewal failed"
        exit 1
    fi
}

# Check certificate status
status_certs() {
    log_info "Certificate status:"

    if [ -d "$CERT_DIR/letsencrypt/live" ]; then
        for domain_dir in "$CERT_DIR/letsencrypt/live"/*; do
            if [ -d "$domain_dir" ]; then
                domain=$(basename "$domain_dir")
                cert_file="$domain_dir/cert.pem"

                if [ -f "$cert_file" ]; then
                    expiry=$(openssl x509 -enddate -noout -in "$cert_file" | cut -d= -f2)
                    expiry_epoch=$(date -d "$expiry" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$expiry" +%s 2>/dev/null)
                    now_epoch=$(date +%s)
                    days_left=$(( (expiry_epoch - now_epoch) / 86400 ))

                    if [ $days_left -lt 7 ]; then
                        log_error "$domain: Expires in $days_left days! ($expiry)"
                    elif [ $days_left -lt 30 ]; then
                        log_warn "$domain: Expires in $days_left days ($expiry)"
                    else
                        log_info "$domain: Valid for $days_left days ($expiry)"
                    fi
                fi
            fi
        done
    else
        log_warn "No certificates found in $CERT_DIR"
    fi
}

# Install certificates to a yacht
install_cert() {
    local yacht="$1"

    if [ -z "$yacht" ]; then
        log_error "Yacht name required. Usage: $0 install <yacht>"
        exit 1
    fi

    # Load fleet config to get yacht details
    local fleet_file="${WHARF_CONFIG:-./configs}/fleet.toml"

    if [ ! -f "$fleet_file" ]; then
        log_error "Fleet config not found: $fleet_file"
        exit 1
    fi

    log_info "Installing certificates to yacht: $yacht"
    log_warn "This will sync certificates to /opt/wharf/certs on the yacht"

    # Use wharf CLI to sync certs
    if command -v wharf &> /dev/null; then
        # wharf moor would handle this, but we can do direct rsync for certs
        log_info "Use 'wharf moor $yacht' to sync all files including certificates"
    else
        log_warn "wharf CLI not found. Use rsync manually:"
        echo "  rsync -avz $CERT_DIR/ user@yacht-ip:/opt/wharf/certs/"
    fi
}

# Generate self-signed certificate (for development)
generate_self_signed() {
    local domain="${1:-localhost}"

    log_warn "Generating self-signed certificate for: $domain"
    log_warn "This is NOT suitable for production!"

    mkdir -p "$CERT_DIR/live/default"

    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$CERT_DIR/live/default/privkey.pem" \
        -out "$CERT_DIR/live/default/fullchain.pem" \
        -subj "/CN=$domain/O=Wharf Development/C=US" \
        -addext "subjectAltName=DNS:$domain,DNS:*.$domain,IP:127.0.0.1"

    log_info "Self-signed certificate created:"
    log_info "  Certificate: $CERT_DIR/live/default/fullchain.pem"
    log_info "  Private key: $CERT_DIR/live/default/privkey.pem"
}

# Setup automatic renewal via cron/systemd
setup_auto_renew() {
    log_info "Setting up automatic certificate renewal..."

    # Check if systemd timer exists
    if systemctl list-timers 2>/dev/null | grep -q certbot; then
        log_info "Certbot systemd timer already active"
        return
    fi

    # Create cron job as fallback
    local cron_cmd="0 3 * * * $0 renew >> /var/log/wharf-ssl-renew.log 2>&1"

    if crontab -l 2>/dev/null | grep -q "wharf.*ssl-setup.*renew"; then
        log_info "Cron job already exists"
    else
        (crontab -l 2>/dev/null; echo "$cron_cmd") | crontab -
        log_info "Cron job added for daily renewal check at 3 AM"
    fi
}

# Main
main() {
    check_requirements

    case "${1:-help}" in
        init)
            init_cert "${2:-}"
            ;;
        renew)
            renew_certs
            ;;
        status)
            status_certs
            ;;
        install)
            install_cert "${2:-}"
            ;;
        self-signed)
            generate_self_signed "${2:-localhost}"
            ;;
        auto-renew)
            setup_auto_renew
            ;;
        help|--help|-h)
            echo "Wharf SSL/TLS Certificate Manager"
            echo ""
            echo "Usage: $0 <command> [options]"
            echo ""
            echo "Commands:"
            echo "  init <domain>     Request new Let's Encrypt certificate"
            echo "  renew             Renew all certificates"
            echo "  status            Show certificate status"
            echo "  install <yacht>   Push certificates to a yacht"
            echo "  self-signed       Generate self-signed cert (dev only)"
            echo "  auto-renew        Setup automatic renewal"
            echo ""
            echo "Environment variables:"
            echo "  WHARF_CERT_DIR    Certificate directory (default: /opt/wharf/certs)"
            echo "  WHARF_ACME_EMAIL  Email for Let's Encrypt (required)"
            echo "  WHARF_ACME_SERVER ACME server URL (default: production)"
            echo ""
            echo "Examples:"
            echo "  WHARF_ACME_EMAIL=admin@example.com $0 init example.com"
            echo "  $0 status"
            echo "  $0 renew"
            ;;
        *)
            log_error "Unknown command: $1"
            echo "Use '$0 help' for usage information"
            exit 1
            ;;
    esac
}

main "$@"
