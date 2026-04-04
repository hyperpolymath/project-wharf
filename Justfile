# wharf - Rust Development Tasks
set shell := ["bash", "-uc"]
set dotenv-load := true

project := "wharf"

# Show all recipes
default:
    @just --list --unsorted

# Build debug
build:
    cargo build

# Build release
build-release:
    cargo build --release

# Run tests
test:
    cargo test

# Run tests verbose
test-verbose:
    cargo test -- --nocapture

# Format code
fmt:
    cargo fmt

# Check formatting
fmt-check:
    cargo fmt -- --check

# Run clippy lints
lint:
    cargo clippy -- -D warnings

# Check without building
check:
    cargo check

# Clean build artifacts
clean:
    cargo clean

# Run the project
run *ARGS:
    cargo run -p wharf-cli -- {{ARGS}}

# Generate docs
doc:
    cargo doc --no-deps --open

# Update dependencies
update:
    cargo update

# Audit dependencies
audit:
    cargo audit

# All checks before commit
pre-commit: fmt-check lint test
    @echo "All checks passed!"

# Build container images with Podman
container-build target="all":
    @if [ "{{target}}" = "all" ] || [ "{{target}}" = "agent" ]; then \
        echo "Building yacht-agent..."; \
        podman build -t yacht-agent:latest -f infra/containers/Containerfile.agent .; \
    fi
    @if [ "{{target}}" = "all" ] || [ "{{target}}" = "nginx" ]; then \
        echo "Building yacht-nginx..."; \
        podman build -t yacht-nginx:latest -f infra/containers/Containerfile.nginx .; \
    fi
    @if [ "{{target}}" = "all" ] || [ "{{target}}" = "php" ]; then \
        echo "Building yacht-php..."; \
        podman build -t yacht-php:latest -f infra/containers/Containerfile.php .; \
    fi
    @if [ "{{target}}" = "all" ] || [ "{{target}}" = "web" ]; then \
        echo "Building yacht-web (OpenLiteSpeed)..."; \
        podman build -t yacht-web:latest -f infra/containers/Containerfile.openlitespeed .; \
    fi

# Deploy with selur-compose
deploy-selur:
    selur-compose -f infra/selur-compose.yaml up -d

# Sign images with cerro-torre
sign-images:
    cerro-torre sign yacht-agent:latest
    cerro-torre sign yacht-nginx:latest

# Seal images with selur
seal-images:
    selur seal yacht-agent:latest
    selur seal yacht-nginx:latest

# Run the demo script
demo:
    bash scripts/demo.sh

# [AUTO-GENERATED] Multi-arch / RISC-V target
build-riscv:
	@echo "Building for RISC-V..."
	cross build --target riscv64gc-unknown-linux-gnu

# Run panic-attacker pre-commit scan
assail:
    @command -v panic-attack >/dev/null 2>&1 && panic-attack assail . || echo "panic-attack not found — install from https://github.com/hyperpolymath/panic-attacker"

# Self-diagnostic — checks dependencies, permissions, paths
doctor:
    @echo "Running diagnostics for project-wharf..."
    @echo "Checking required tools..."
    @command -v just >/dev/null 2>&1 && echo "  [OK] just" || echo "  [FAIL] just not found"
    @command -v git >/dev/null 2>&1 && echo "  [OK] git" || echo "  [FAIL] git not found"
    @echo "Checking for hardcoded paths..."
    @grep -rn '$HOME\|$ECLIPSE_DIR' --include='*.rs' --include='*.ex' --include='*.res' --include='*.gleam' --include='*.sh' . 2>/dev/null | head -5 || echo "  [OK] No hardcoded paths"
    @echo "Diagnostics complete."

# Auto-repair common issues
heal:
    @echo "Attempting auto-repair for project-wharf..."
    @echo "Fixing permissions..."
    @find . -name "*.sh" -exec chmod +x {} \; 2>/dev/null || true
    @echo "Cleaning stale caches..."
    @rm -rf .cache/stale 2>/dev/null || true
    @echo "Repair complete."

# Guided tour of key features
tour:
    @echo "=== project-wharf Tour ==="
    @echo ""
    @echo "1. Project structure:"
    @ls -la
    @echo ""
    @echo "2. Available commands: just --list"
    @echo ""
    @echo "3. Read README.adoc for full overview"
    @echo "4. Read EXPLAINME.adoc for architecture decisions"
    @echo "5. Run 'just doctor' to check your setup"
    @echo ""
    @echo "Tour complete! Try 'just --list' to see all available commands."

# Open feedback channel with diagnostic context
help-me:
    @echo "=== project-wharf Help ==="
    @echo "Platform: $(uname -s) $(uname -m)"
    @echo "Shell: $SHELL"
    @echo ""
    @echo "To report an issue:"
    @echo "  https://github.com/hyperpolymath/project-wharf/issues/new"
    @echo ""
    @echo "Include the output of 'just doctor' in your report."
