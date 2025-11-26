# ============================================================================
# Project Wharf - The Sovereign Web Hypervisor
# ============================================================================
# The Ultimate Justfile for managing immutable CMS infrastructure
#
# Core Concepts:
# - Wharf: The offline controller (your machine) - holds keys, makes decisions
# - Yacht: The online runtime (the server) - read-only, enforces state
# - Mooring: The secure connection process via Nebula mesh
#
# Usage:
#   just init           # Initialize a new Wharf configuration
#   just build          # Compile all artifacts
#   just moor primary   # Connect to a yacht and sync state
#   just audit primary  # Audit a yacht's security posture

# Global Settings
set shell := ["/usr/bin/env", "bash"]
set dotenv-load := true

# Default recipe - show help
default:
    @just --list

# ============================================================================
# 1. BOOTSTRAP & SETUP
# ============================================================================

# Initialize a new Wharf environment
init:
    @echo ">>> Initializing Project Wharf..."
    @echo ">>> Creating directory structure..."
    mkdir -p dist vars
    @echo ">>> Checking dependencies..."
    @just check-deps
    @echo ">>> Building Rust workspace..."
    cargo build
    @echo ">>> Wharf initialized successfully!"
    @echo ""
    @echo "Next steps:"
    @echo "  1. Edit configs/fleet.ncl to add your yachts"
    @echo "  2. Run 'just gen-nebula-ca' to create mesh certificates"
    @echo "  3. Run 'just build' to compile deployment artifacts"

# Check for required dependencies
check-deps:
    @echo "Checking dependencies..."
    @command -v cargo >/dev/null 2>&1 || { echo "ERROR: Rust not found. Install from rustup.rs"; exit 1; }
    @command -v jq >/dev/null 2>&1 || echo "WARNING: jq not found (optional, for JSON processing)"
    @command -v nebula-cert >/dev/null 2>&1 || echo "WARNING: nebula-cert not found (required for mesh networking)"
    @command -v named-checkzone >/dev/null 2>&1 || echo "WARNING: named-checkzone not found (optional, for DNS validation)"
    @echo "Dependency check complete."

# Install dependencies (Fedora/rpm-ostree aware)
install-deps:
    @echo ">>> Installing dependencies..."
    @if [ -f /run/ostree-booted ]; then \
        echo "Detected immutable OS (rpm-ostree)..."; \
        rpm-ostree install bind-utils jq nebula; \
    elif command -v nala >/dev/null 2>&1; then \
        sudo nala install -y bind9-utils jq nebula; \
    elif command -v apt >/dev/null 2>&1; then \
        sudo apt install -y bind9-utils jq; \
        echo "Note: Install Nebula from https://github.com/slackhq/nebula/releases"; \
    elif command -v dnf >/dev/null 2>&1; then \
        sudo dnf install -y bind-utils jq nebula; \
    else \
        echo "Unknown package manager. Please install: bind-utils, jq, nebula"; \
    fi

# ============================================================================
# 2. BUILD & COMPILE
# ============================================================================

# Build all artifacts (Rust binaries, zone files, configs)
build: build-rust build-zones
    @echo ">>> Build complete!"

# Build Rust workspace (release mode)
build-rust:
    @echo ">>> Building Rust binaries..."
    cargo build --release --workspace

# Build only debug binaries (faster iteration)
build-debug:
    @echo ">>> Building Rust binaries (debug)..."
    cargo build --workspace

# Build DNS zone files from templates
build-zones:
    @echo ">>> Building DNS zone files..."
    @for vars_file in vars/*.json; do \
        if [ -f "$$vars_file" ]; then \
            domain=$$(basename "$$vars_file" .json); \
            echo "Building zone for $$domain..."; \
            just render-zone maximalist "$$vars_file" "dist/$$domain.db"; \
        fi; \
    done

# Render a single zone template
render-zone template vars_file output:
    @echo "Rendering {{template}}.tpl with {{vars_file}}..."
    ./target/release/wharf render-zone templates/{{template}}.tpl {{vars_file}} -o {{output}} 2>/dev/null || \
        scripts/render_zone.sh templates/{{template}}.tpl {{vars_file}} > {{output}}

# ============================================================================
# 3. THE MOORING (Secure Connection)
# ============================================================================

# Connect to a yacht and synchronize state
moor target *args:
    @echo ">>> Initiating Mooring Sequence for {{target}}..."
    @echo ""
    @echo "╔══════════════════════════════════════════════════════════════╗"
    @echo "║  >>> TOUCH YOUR FIDO2 KEY NOW <<<                            ║"
    @echo "╚══════════════════════════════════════════════════════════════╝"
    @echo ""
    ./target/release/wharf moor {{target}} {{args}}

# Push state to a yacht (after mooring)
push target:
    @just moor {{target}} --push

# Pull state from a yacht (backup)
pull target:
    @just moor {{target}} --pull

# ============================================================================
# 4. SECURITY AUDIT
# ============================================================================

# Audit a yacht's security configuration
audit target:
    @echo ">>> Auditing security posture of {{target}}..."
    ./target/release/wharf audit {{target}}

# Audit a DNS zone file for security issues
audit-zone zone_file domain:
    @echo ">>> Auditing DNS zone {{zone_file}} for {{domain}}..."
    @scripts/audit_zone.sh {{zone_file}} {{domain}}

# Check all zone files for OWASP compliance
audit-all-zones:
    @echo ">>> Auditing all zone files..."
    @for zone in dist/*.db; do \
        if [ -f "$$zone" ]; then \
            domain=$$(basename "$$zone" .db); \
            just audit-zone "$$zone" "$$domain"; \
        fi; \
    done

# Validate Nickel configurations
check-config:
    @echo ">>> Validating Nickel configurations..."
    @for ncl in configs/*.ncl configs/policies/*.ncl; do \
        if [ -f "$$ncl" ]; then \
            echo "Checking $$ncl..."; \
            nickel export "$$ncl" > /dev/null 2>&1 || echo "WARNING: $$ncl may have issues"; \
        fi; \
    done

# ============================================================================
# 5. CRYPTOGRAPHIC KEY GENERATION
# ============================================================================

# Generate Nebula CA (do this ONCE, store offline!)
gen-nebula-ca:
    @echo ">>> Generating Nebula Certificate Authority..."
    @echo "WARNING: Store ca.key in a secure offline location!"
    mkdir -p infra/nebula
    nebula-cert ca -name "Wharf Fleet Command" -out-crt infra/nebula/ca.crt -out-key infra/nebula/ca.key
    @echo ">>> CA generated at infra/nebula/ca.{crt,key}"

# Generate Nebula certificate for a yacht
gen-yacht-cert name ip groups="server":
    @echo ">>> Generating certificate for yacht {{name}}..."
    nebula-cert sign \
        -ca-crt infra/nebula/ca.crt \
        -ca-key infra/nebula/ca.key \
        -name "{{name}}" \
        -ip "{{ip}}/24" \
        -groups "{{groups}}" \
        -out-crt infra/nebula/{{name}}.crt \
        -out-key infra/nebula/{{name}}.key
    @echo ">>> Certificate generated for {{name}}"

# Generate Nebula certificate for a captain (admin)
gen-captain-cert name ip:
    @echo ">>> Generating certificate for captain {{name}}..."
    nebula-cert sign \
        -ca-crt infra/nebula/ca.crt \
        -ca-key infra/nebula/ca.key \
        -name "{{name}}" \
        -ip "{{ip}}/24" \
        -groups "captain,admin" \
        -out-crt infra/nebula/{{name}}.crt \
        -out-key infra/nebula/{{name}}.key
    @echo ">>> Captain certificate generated for {{name}}"

# Generate DKIM, SPF, DMARC records for a domain
gen-email-records domain selector="default":
    @echo ">>> Generating email authentication records for {{domain}}..."
    ./target/release/wharf gen-keys {{domain}} --selector {{selector}}

# Generate SSH fingerprint records (run on the yacht)
gen-sshfp domain:
    @echo ">>> Generating SSHFP records for {{domain}}..."
    @echo "Run this on the target server:"
    @echo "ssh-keygen -r {{domain}}"

# ============================================================================
# 6. ADAPTER MANAGEMENT
# ============================================================================

# Package WordPress adapter for deployment
pack-wordpress:
    @echo ">>> Packaging WordPress adapter..."
    mkdir -p dist/adapters
    tar -czf dist/adapters/wharf-wordpress.tar.gz adapters/wordpress/
    @echo ">>> Adapter packaged at dist/adapters/wharf-wordpress.tar.gz"

# Package Drupal adapter for deployment
pack-drupal:
    @echo ">>> Packaging Drupal adapter..."
    mkdir -p dist/adapters
    tar -czf dist/adapters/wharf-drupal.tar.gz adapters/drupal/
    @echo ">>> Adapter packaged at dist/adapters/wharf-drupal.tar.gz"

# Package all adapters
pack-adapters: pack-wordpress pack-drupal
    @echo ">>> All adapters packaged!"

# ============================================================================
# 7. DEPLOYMENT
# ============================================================================

# Deploy yacht agent to a server (initial setup)
deploy-yacht target_ip:
    @echo ">>> Deploying Yacht Agent to {{target_ip}}..."
    @scripts/deploy_yacht.sh {{target_ip}}

# Deploy zone file to a nameserver
deploy-zone zone_file destination:
    @echo ">>> Deploying zone {{zone_file}} to {{destination}}..."
    sudo cp {{zone_file}} {{destination}}
    @echo ">>> Zone deployed. Reload your nameserver."

# ============================================================================
# 8. TESTING & VALIDATION
# ============================================================================

# Run all tests
test:
    @echo ">>> Running tests..."
    cargo test --workspace

# Run tests with coverage
test-coverage:
    @echo ">>> Running tests with coverage..."
    cargo tarpaulin --workspace --out Html

# Lint the codebase
lint:
    @echo ">>> Linting..."
    cargo clippy --workspace -- -D warnings

# Format code
fmt:
    @echo ">>> Formatting..."
    cargo fmt --all

# Check formatting without changing
fmt-check:
    @echo ">>> Checking format..."
    cargo fmt --all -- --check

# ============================================================================
# 9. DEVELOPMENT
# ============================================================================

# Watch for changes and rebuild
watch:
    @echo ">>> Watching for changes..."
    cargo watch -x build

# Run the CLI in development mode
run *args:
    cargo run --bin wharf -- {{args}}

# Run the yacht agent in development mode
run-agent:
    cargo run --bin yacht-agent

# Clean build artifacts
clean:
    @echo ">>> Cleaning..."
    cargo clean
    rm -rf dist/

# ============================================================================
# 10. DOCUMENTATION
# ============================================================================

# Generate documentation
docs:
    @echo ">>> Generating documentation..."
    cargo doc --workspace --no-deps --open

# Show version information
version:
    @echo "Wharf - The Sovereign Web Hypervisor"
    @./target/release/wharf version 2>/dev/null || cargo run --bin wharf -- version

# ============================================================================
# 11. ENVIRONMENT DETECTION
# ============================================================================

# Detect if a domain is on shared or dedicated infrastructure
detect-env domain ip:
    @echo ">>> Detecting environment for {{domain}} on {{ip}}..."
    @scripts/detect_env.sh {{domain}} {{ip}}

# Recommend template based on environment
recommend-template domain ip:
    @echo ">>> Analyzing {{domain}} on {{ip}}..."
    @just detect-env {{domain}} {{ip}}

# ============================================================================
# 12. RSR COMPLIANCE (Rhodium Standard Repository)
# ============================================================================

# Run all RSR compliance checks
validate: validate-docs validate-spdx validate-security validate-wellknown
    @echo ""
    @echo "✅ RSR compliance validation complete!"

# Check required documentation files
validate-docs:
    @echo ">>> Checking RSR documentation requirements..."
    @FAILED=0; \
    for file in README.adoc LICENSE.txt SECURITY.md CODE_OF_CONDUCT.adoc \
                CONTRIBUTING.adoc FUNDING.yml GOVERNANCE.adoc MAINTAINERS.md \
                .gitignore .gitattributes REVERSIBILITY.md CHANGELOG.md ROADMAP.md; do \
        if [ -f "$$file" ]; then \
            echo "  ✓ $$file"; \
        else \
            echo "  ✗ $$file (MISSING)"; \
            FAILED=1; \
        fi; \
    done; \
    if [ $$FAILED -eq 1 ]; then exit 1; fi

# Check SPDX headers in source files
validate-spdx:
    @echo ">>> Checking SPDX headers..."
    @FAILED=0; \
    for file in $$(find . -name "*.rs" -o -name "*.sh" -o -name "*.nix" 2>/dev/null | grep -v target); do \
        if ! head -5 "$$file" | grep -q "SPDX-License-Identifier"; then \
            echo "  ✗ Missing SPDX: $$file"; \
            FAILED=1; \
        fi; \
    done; \
    if [ $$FAILED -eq 0 ]; then echo "  ✓ All source files have SPDX headers"; fi

# Audit SPDX license compliance
audit-licence:
    @echo ">>> Auditing license compliance..."
    @just validate-spdx
    @echo ">>> Checking for incompatible licenses in dependencies..."
    @cargo tree --prefix none 2>/dev/null | head -20 || echo "Run 'cargo build' first"

# Check security-related files
validate-security:
    @echo ">>> Checking security requirements..."
    @test -f SECURITY.md && echo "  ✓ SECURITY.md present" || echo "  ✗ SECURITY.md missing"
    @test -f .well-known/security.txt && echo "  ✓ .well-known/security.txt present" || echo "  ✗ .well-known/security.txt missing"
    @grep -q "Response SLA" SECURITY.md 2>/dev/null && echo "  ✓ SECURITY.md has Response SLA" || echo "  ✗ SECURITY.md missing Response SLA"

# Check .well-known directory
validate-wellknown:
    @echo ">>> Checking .well-known directory..."
    @for file in security.txt ai.txt consent-required.txt provenance.json humans.txt; do \
        if [ -f ".well-known/$$file" ]; then \
            echo "  ✓ .well-known/$$file"; \
        else \
            echo "  ✗ .well-known/$$file (MISSING)"; \
        fi; \
    done

# Check link integrity (requires lychee)
check-links:
    @echo ">>> Checking link integrity..."
    @if command -v lychee >/dev/null 2>&1; then \
        lychee --verbose docs/ *.md *.adoc 2>/dev/null || echo "Some links may need attention"; \
    else \
        echo "  SKIP: lychee not installed (cargo install lychee)"; \
    fi

# Generate SBOM (Software Bill of Materials)
sbom-generate:
    @echo ">>> Generating SBOM..."
    @mkdir -p dist
    @if command -v cargo-sbom >/dev/null 2>&1; then \
        cargo sbom > dist/sbom.spdx.json; \
        echo "  ✓ SBOM generated at dist/sbom.spdx.json"; \
    else \
        echo "  SKIP: cargo-sbom not installed"; \
        echo "  Install with: cargo install cargo-sbom"; \
    fi

# Full RSR audit report
rsr-report:
    @echo "╔══════════════════════════════════════════════════════════════╗"
    @echo "║           RSR COMPLIANCE REPORT - Project Wharf              ║"
    @echo "╚══════════════════════════════════════════════════════════════╝"
    @echo ""
    @echo "Category 1: Foundational Infrastructure"
    @test -f flake.nix && echo "  ✓ Nix flakes" || echo "  ✗ Nix flakes"
    @test -f Justfile && echo "  ✓ Justfile present" || echo "  ✗ Justfile missing"
    @test -d configs && echo "  ✓ Nickel configs" || echo "  ✗ Nickel configs"
    @echo ""
    @echo "Category 2: Documentation"
    @just validate-docs 2>/dev/null || true
    @echo ""
    @echo "Category 3: Security"
    @just validate-security 2>/dev/null || true
    @echo ""
    @echo "Category 4: Architecture"
    @test -f REVERSIBILITY.md && echo "  ✓ Reversibility documented" || echo "  ✗ Missing REVERSIBILITY.md"
    @test -f docs/ARCHITECTURE.md && echo "  ✓ Architecture documented" || echo "  ✗ Missing ARCHITECTURE.md"
    @echo ""
    @echo "Category 7: Licensing"
    @test -f LICENSE.txt && echo "  ✓ LICENSE.txt present" || echo "  ✗ Missing LICENSE.txt"
    @grep -q "SPDX" LICENSE.txt 2>/dev/null && echo "  ✓ SPDX identified" || echo "  ✗ Not SPDX identified"
    @echo ""
    @echo "Category 10: Governance"
    @test -f GOVERNANCE.adoc && echo "  ✓ Governance documented" || echo "  ✗ Missing GOVERNANCE.adoc"
    @test -f CONTRIBUTING.adoc && echo "  ✓ Contributing guide" || echo "  ✗ Missing CONTRIBUTING.adoc"
    @grep -q "Perimeter" CONTRIBUTING.adoc 2>/dev/null && echo "  ✓ TPCF documented" || echo "  ✗ TPCF not documented"
    @echo ""
    @echo "══════════════════════════════════════════════════════════════"

# Setup git hooks
setup-hooks:
    @echo ">>> Setting up git hooks..."
    git config core.hooksPath .githooks
    @echo "  ✓ Git hooks configured to use .githooks/"

# ============================================================================
# 13. CI/CD SUPPORT
# ============================================================================

# Run CI pipeline locally
ci: fmt-check lint test validate
    @echo ">>> CI pipeline complete!"

# Pre-release checklist
pre-release version:
    @echo ">>> Pre-release checklist for {{version}}..."
    @just ci
    @just rsr-report
    @echo ""
    @echo "Ready for release {{version}}? Run: git tag -s v{{version}}"
