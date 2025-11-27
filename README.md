# Project Wharf

**The Sovereign Web Hypervisor** - Immutable CMS infrastructure for WordPress and beyond.

## What is Wharf?

Wharf separates CMS **administration** (offline, secure) from **runtime** (online, hardened). Think of it like a ship:

- **Wharf** = The dock where you build and maintain your ship (your local machine)
- **Yacht** = The ship at sea serving visitors (your production server)
- **Mooring** = The secure channel connecting them (rsync over SSH + Nebula mesh)

### Why?

Traditional WordPress hosting is vulnerable because:
- `/wp-admin` is exposed to the internet
- Plugins can be installed/modified live
- Database can be corrupted by attackers
- No separation between admin and runtime

Wharf fixes this by making the runtime **read-only** and moving all administration offline.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    YOUR MACHINE (Wharf)                      │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │  WordPress   │  │   wharf-cli  │  │  Fleet Config    │  │
│  │  (editable)  │  │              │  │  (TOML/JSON)     │  │
│  └──────────────┘  └──────────────┘  └──────────────────┘  │
│                            │                                 │
│                     `wharf moor`                            │
│                     (SSH + rsync)                           │
└────────────────────────────┼────────────────────────────────┘
                             │
                     ┌───────▼───────┐
                     │  Nebula Mesh  │
                     │  (Zero Trust) │
                     └───────┬───────┘
                             │
┌────────────────────────────┼────────────────────────────────┐
│                  PRODUCTION SERVER (Yacht)                   │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │                   Yacht Pod                           │  │
│  │  ┌─────────────────┐     ┌─────────────────────┐     │  │
│  │  │  OpenLiteSpeed  │     │    Yacht Agent      │     │  │
│  │  │  + PHP 8.3      │     │  (Distroless Rust)  │     │  │
│  │  │                 │     │                     │     │  │
│  │  │  - /wp-admin    │────▶│  - DB Proxy (AST)   │     │  │
│  │  │    BLOCKED      │     │  - Integrity Check  │     │  │
│  │  │  - Read-only FS │     │  - nftables/eBPF    │     │  │
│  │  └─────────────────┘     └─────────────────────┘     │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              MariaDB (Shadow Port 33060)              │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Rust 1.75+ (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)
- Podman (`apt install podman` or equivalent)
- rsync and SSH client

### 1. Build Wharf CLI

```bash
git clone https://gitlab.com/hyperpolymath/wharf.git
cd wharf
cargo build --release --bin wharf
```

### 2. Initialize Your Fleet

```bash
# Create a new fleet configuration
./target/release/wharf init --path ./my-fleet

# Edit the configuration
nano ./my-fleet/fleet.toml
```

### 3. Add a Yacht

Edit `fleet.toml`:

```toml
[yachts.production]
name = "production"
ip = "your-server-ip"
domain = "example.com"
ssh_user = "deploy"
adapter = "wordpress"
```

### 4. Prepare Your WordPress Site

Place your WordPress files in `./my-fleet/site/`:

```bash
# Copy existing WordPress
cp -r /path/to/wordpress/* ./my-fleet/site/

# Or download fresh
wget https://wordpress.org/latest.tar.gz
tar -xzf latest.tar.gz
mv wordpress/* ./my-fleet/site/
```

### 5. Deploy (Moor) to Production

```bash
./target/release/wharf moor production
```

This will:
1. Generate a BLAKE3 integrity manifest
2. Sync files via rsync over SSH
3. Verify the deployment

### 6. Build and Deploy Containers (on the Yacht)

On your production server:

```bash
# Build containers
podman build -t yacht-web:latest -f infra/containers/openlitespeed.Dockerfile .
podman build -t yacht-agent:latest -f infra/containers/agent.Dockerfile .

# Deploy the pod
podman kube play infra/podman/yacht.yaml
```

## Configuration

### Fleet Configuration (TOML)

```toml
# configs/fleet.toml

version = 1
name = "my-fleet"

sync_excludes = [
    ".git",
    "node_modules",
    ".env",
    "*.log",
]

[yachts.production]
name = "production"
ip = "10.0.1.10"
domain = "example.com"
ssh_port = 22
ssh_user = "deploy"
adapter = "wordpress"
enabled = true

[yachts.production.database]
variant = "mariadb"
shadow_port = 33060
public_port = 3306
```

### Database Policy (Nickel)

The database proxy uses AST-based SQL parsing to enforce security policies:

```nickel
# configs/policies/database.ncl
{
  default_policy = "audit",

  # Content tables - can be written by the website
  allow_write = [
    "wp_comments",
    "wp_commentmeta",
  ],

  # Config tables - can ONLY be changed via Wharf
  lock_down = [
    "wp_users",
    "wp_options",
  ],

  # Structural operations are always blocked
  blocked_operations = ["DROP", "ALTER", "TRUNCATE", "CREATE"],
}
```

## Security Model

### The "Dark Matter" Concept

`/wp-admin` exists on disk but is **blocked at the web server level**. It's there (so WordPress works), but attackers can't reach it. Administration happens offline on your Wharf machine.

### Database Virtual Sharding

The Yacht Agent proxies all database connections and:

1. **Parses SQL using AST** (not regex - can't be bypassed)
2. **Classifies queries** as Allow, Audit, or Block
3. **Blocks dangerous operations** (DROP, ALTER, etc.)
4. **Logs everything** for forensics

### Integrity Verification

Every deployment generates a BLAKE3 manifest of all files. The agent continuously verifies the filesystem hasn't been tampered with.

### Firewall Options

| Mode | Description | Requirements |
|------|-------------|--------------|
| `nftables` | Standard Linux firewall (default) | Linux kernel 3.13+ |
| `ebpf` | XDP packet filtering at NIC level | Linux kernel 5.2+, CAP_BPF |
| `none` | No firewall (not recommended) | - |

## CLI Reference

```bash
wharf init                    # Initialize fleet configuration
wharf build                   # Compile zone files and artifacts
wharf moor <yacht>            # Deploy to a yacht
wharf moor <yacht> --dry-run  # Preview what would be synced

wharf fleet list              # List all yachts
wharf fleet add <name>        # Add a yacht
wharf fleet status            # Show fleet status

wharf sec verify <yacht>      # Verify file integrity
wharf sec audit               # Security audit

wharf state freeze            # Create a snapshot
wharf state thaw <id>         # Restore a snapshot
wharf state diff <yacht>      # Compare local vs remote
```

## SSL/TLS Certificates

```bash
# Set your email for Let's Encrypt
export WHARF_ACME_EMAIL=admin@example.com

# Initialize certificate
./scripts/ssl-setup.sh init example.com

# Check status
./scripts/ssl-setup.sh status

# Auto-renewal
./scripts/ssl-setup.sh auto-renew
```

## Monitoring

The Yacht Agent exposes Prometheus metrics at `/metrics`:

```
yacht_queries_total{status="allowed"} 1234
yacht_queries_total{status="blocked"} 5
yacht_integrity_status 1
yacht_db_proxy_connections 3
```

## Supported CMS

| CMS | Adapter | Status |
|-----|---------|--------|
| WordPress | `wordpress` | Primary support |
| Drupal | `drupal` | Adapter exists |
| Moodle | `moodle` | Adapter exists |
| Joomla | `joomla` | Adapter exists |
| Custom | `custom` | Manual config |

## Container Images

| Image | Base | Purpose |
|-------|------|---------|
| `yacht-web` | OpenLiteSpeed | Web server + PHP 8.3 |
| `yacht-agent` | Chainguard static (distroless) | Security enforcer |
| `mariadb` | Chainguard MariaDB | Database |

## Development

```bash
# Run tests
cargo test

# Build all binaries
cargo build --release

# Build containers
podman build -t yacht-web:latest -f infra/containers/openlitespeed.Dockerfile .
podman build -t yacht-agent:latest -f infra/containers/agent.Dockerfile .

# Run smoke test
./scripts/smoke_test.sh
```

## License

MIT License - See [LICENSE](LICENSE) for details.

## Contributing

Contributions welcome! Please read the architecture docs before submitting PRs.

## Support

- Issues: https://gitlab.com/hyperpolymath/wharf/-/issues
- Discussions: https://gitlab.com/hyperpolymath/wharf/-/discussions

---

**Wharf** - Because your CMS deserves sovereign security.
