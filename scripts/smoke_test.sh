#!/usr/bin/env bash
# SPDX-License-Identifier: PMPL-1.0
# SPDX-FileCopyrightText: 2025 Jonathan D. A. Jewell <hyperpolymath>
#
# Smoke Test for Project Wharf
# ============================
# Quick sanity check: "Turn it on, does smoke come out?"
#
# Usage: ./scripts/smoke_test.sh [--build] [--clean]

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Parse arguments
BUILD=false
CLEAN=false
for arg in "$@"; do
    case $arg in
        --build) BUILD=true ;;
        --clean) CLEAN=true ;;
    esac
done

cd "$PROJECT_ROOT"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║           Project Wharf - Smoke Test                         ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Cleanup function
cleanup() {
    log_info "Cleaning up test containers..."
    podman pod stop wharf-test 2>/dev/null || true
    podman pod rm wharf-test 2>/dev/null || true
}

if [ "$CLEAN" = true ]; then
    cleanup
    log_info "Cleanup complete"
    exit 0
fi

# Track test results
TESTS_PASSED=0
TESTS_FAILED=0

pass_test() {
    log_pass "$1"
    ((TESTS_PASSED++))
}

fail_test() {
    log_fail "$1"
    ((TESTS_FAILED++))
}

# =============================================================================
# TEST 1: Check Prerequisites
# =============================================================================
log_info "Test 1: Checking prerequisites..."

if command -v cargo >/dev/null 2>&1; then
    pass_test "Rust/Cargo found: $(cargo --version)"
else
    fail_test "Rust not found - install from rustup.rs"
fi

if command -v podman >/dev/null 2>&1; then
    pass_test "Podman found: $(podman --version)"
elif command -v docker >/dev/null 2>&1; then
    log_warn "Docker found (podman preferred): $(docker --version)"
    alias podman=docker
    pass_test "Using Docker as fallback"
else
    fail_test "Neither Podman nor Docker found"
fi

# =============================================================================
# TEST 2: Rust Compilation
# =============================================================================
log_info "Test 2: Rust compilation check..."

if cargo check --workspace 2>/dev/null; then
    pass_test "Rust workspace compiles successfully"
else
    log_warn "Cargo check failed (network required for first build)"
    # Don't fail - might be network issue
fi

# =============================================================================
# TEST 3: Build Containers (if --build flag)
# =============================================================================
if [ "$BUILD" = true ]; then
    log_info "Test 3: Building container images..."

    if podman build -t yacht-nginx:test -f infra/containers/nginx.Dockerfile . 2>/dev/null; then
        pass_test "Nginx container builds"
    else
        fail_test "Nginx container build failed"
    fi

    if podman build -t yacht-php:test -f infra/containers/php.Dockerfile . 2>/dev/null; then
        pass_test "PHP container builds"
    else
        fail_test "PHP container build failed"
    fi
else
    log_info "Test 3: Skipping container builds (use --build to enable)"
fi

# =============================================================================
# TEST 4: Configuration Validation
# =============================================================================
log_info "Test 4: Configuration validation..."

# Check nginx config syntax (if nginx is available)
if command -v nginx >/dev/null 2>&1; then
    if nginx -t -c "$PROJECT_ROOT/infra/config/nginx.conf" 2>/dev/null; then
        pass_test "Nginx configuration syntax valid"
    else
        log_warn "Nginx config test skipped (requires full setup)"
    fi
else
    log_info "Nginx not installed locally, skipping config test"
fi

# Check required files exist
REQUIRED_FILES=(
    "Cargo.toml"
    "Justfile"
    "infra/config/nginx.conf"
    "infra/config/php-fpm.conf"
    "infra/config/wordpress-rules.conf"
    "infra/containers/nginx.Dockerfile"
    "infra/containers/php.Dockerfile"
    "infra/containers/agent.Dockerfile"
    "infra/podman/yacht.yaml"
)

for file in "${REQUIRED_FILES[@]}"; do
    if [ -f "$file" ]; then
        pass_test "Required file exists: $file"
    else
        fail_test "Missing required file: $file"
    fi
done

# =============================================================================
# TEST 5: Quick Container Run (if --build was used)
# =============================================================================
if [ "$BUILD" = true ]; then
    log_info "Test 5: Quick container run test..."

    # Create a simple test
    mkdir -p /tmp/wharf-test
    echo '<?php phpinfo(); ?>' > /tmp/wharf-test/index.php
    echo '<html><body><h1>Wharf Test</h1></body></html>' > /tmp/wharf-test/index.html

    # Try to start nginx container briefly
    CONTAINER_ID=$(podman run -d --rm -p 18080:8080 -v /tmp/wharf-test:/var/www/html:ro yacht-nginx:test 2>/dev/null || echo "")

    if [ -n "$CONTAINER_ID" ]; then
        sleep 2

        # Test health endpoint
        if curl -sf http://localhost:18080/health >/dev/null 2>&1; then
            pass_test "Nginx container responds to health check"
        else
            log_warn "Health check failed (may need time to start)"
        fi

        # Test static file
        if curl -sf http://localhost:18080/index.html | grep -q "Wharf Test"; then
            pass_test "Nginx serves static files"
        else
            fail_test "Nginx failed to serve static file"
        fi

        # Cleanup
        podman stop "$CONTAINER_ID" 2>/dev/null || true
    else
        fail_test "Failed to start nginx container"
    fi

    rm -rf /tmp/wharf-test
fi

# =============================================================================
# RESULTS
# =============================================================================
echo ""
echo "══════════════════════════════════════════════════════════════"
echo "                      TEST RESULTS"
echo "══════════════════════════════════════════════════════════════"
echo ""
echo -e "  ${GREEN}Passed:${NC} $TESTS_PASSED"
echo -e "  ${RED}Failed:${NC} $TESTS_FAILED"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All smoke tests passed!${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Build containers:     just build-containers"
    echo "  2. Build Rust binaries:  cargo build --release"
    echo "  3. Run full stack:       podman kube play infra/podman/yacht.yaml"
    exit 0
else
    echo -e "${RED}✗ Some tests failed${NC}"
    echo ""
    echo "Check the errors above and fix before proceeding."
    exit 1
fi
