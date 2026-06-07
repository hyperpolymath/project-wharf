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
    cargo run -- {{ARGS}}

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
