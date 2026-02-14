# Architecture

This document describes the technical architecture of Project Wharf.

## Overview

Wharf implements a **Split-Brain** security model where administrative
capabilities are physically separated from runtime execution.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              SECURITY BOUNDARY                           │
├─────────────────────────────────┬───────────────────────────────────────┤
│         WHARF (Offline)         │           YACHT (Online)              │
│                                 │                                       │
│  ┌─────────────────────────┐   │   ┌─────────────────────────────────┐ │
│  │     Configuration       │   │   │         Rust Agent              │ │
│  │  ┌─────────────────┐    │   │   │  ┌──────────────────────────┐  │ │
│  │  │   Nickel        │    │   │   │  │    Database Proxy        │  │ │
│  │  │   Schemas       │────┼───┼──▶│  │    (AST Filtering)       │  │ │
│  │  └─────────────────┘    │   │   │  └──────────────────────────┘  │ │
│  │                         │   │   │  ┌──────────────────────────┐  │ │
│  │  ┌─────────────────┐    │   │   │  │    Header Airlock        │  │ │
│  │  │   Nebula CA     │    │   │   │  │    (HTTP Filtering)      │  │ │
│  │  │   (Offline)     │    │   │   │  └──────────────────────────┘  │ │
│  │  └─────────────────┘    │   │   │  ┌──────────────────────────┐  │ │
│  │                         │   │   │  │    File Integrity        │  │ │
│  │  ┌─────────────────┐    │   │   │  │    (BLAKE3)              │  │ │
│  │  │   FIDO2 Keys    │    │   │   │  └──────────────────────────┘  │ │
│  │  │   (Hardware)    │    │   │   └─────────────────────────────────┘ │
│  │  └─────────────────┘    │   │                                       │
│  └─────────────────────────┘   │   ┌─────────────────────────────────┐ │
│                                 │   │         CMS Runtime             │ │
│  ┌─────────────────────────┐   │   │  ┌──────────────────────────┐  │ │
│  │     Rust CLI            │   │   │  │    WordPress/Drupal      │  │ │
│  │  ┌─────────────────┐    │   │   │  │    (Read-Only FS)        │  │ │
│  │  │   wharf-cli     │────┼───┼──▶│  └──────────────────────────┘  │ │
│  │  └─────────────────┘    │   │   │  ┌──────────────────────────┐  │ │
│  └─────────────────────────┘   │   │  │    MariaDB               │  │ │
│                                 │   │  │    (Policy Enforced)     │  │ │
└─────────────────────────────────┴───┴──┴──────────────────────────┴──┴─┘
                                  │
                          NEBULA MESH
                     (Encrypted, Certificate-Based)
```

## Components

### Wharf Controller (`bin/wharf-cli`)

The offline administrative interface.

**Location**: Your local machine or secure workstation

**Components**:
- `wharf-cli`: Command-line interface (Rust, clap)
- `wharf-core`: Shared library — crypto, fleet, integrity, mooring, sync
- `MooringClient`: HTTP client for the four-phase mooring protocol
- Nickel schemas: Declarative configuration
- Nebula CA: Certificate authority for mesh networking
- FIDO2 keys: Hardware authentication

**Responsibilities**:
- Ed448 + ML-DSA-87 hybrid keypair management
- Configuration authoring and validation
- Certificate generation
- State synchronization via mooring protocol
- Security auditing and integrity manifests

### Yacht Agent (`bin/yacht-agent`)

The runtime enforcement agent.

**Location**: Production server

**Components**:
- Database Proxy: AST-based SQL query filtering (not regex)
- Header Airlock: HTTP header sanitization
- File Integrity Monitor: BLAKE3 verification
- Mooring API: Secure sync endpoint (HTTP on port 9001)
- eBPF XDP Firewall: Optional kernel-level packet filtering

**Responsibilities**:
- Hybrid signature verification on all mooring requests
- Policy enforcement (database, filesystem, HTTP)
- Query filtering by table zone (Blue/Red/Grey)
- Header stripping and injection
- Integrity verification and snapshot management

### Nebula Mesh

Zero-trust network overlay.

**Topology**:
```
┌─────────────┐
│  Lighthouse │  (NAT Traversal)
└──────┬──────┘
       │
   ┌───┴───┐
   │  UDP  │
   │ 4242  │
   └───┬───┘
       │
┌──────┴──────┬──────────────┐
│             │              │
▼             ▼              ▼
┌─────┐   ┌───────┐   ┌──────────┐
│Wharf│   │ Yacht │   │  Yacht   │
│     │   │  #1   │   │   #2     │
└─────┘   └───────┘   └──────────┘
```

## Cryptographic Architecture

### Hybrid Signature Scheme

All mooring operations use an Ed448 + ML-DSA-87 (Dilithium5) hybrid signature:

```
Message ──┬── Ed448 Sign ──────────── Ed448 Signature (114 bytes)
          │
          └── ML-DSA-87 Sign ──────── ML-DSA-87 Signature (4627 bytes)
                                              │
                                   HybridSignature { ed448_sig, mldsa87_sig }
```

**Verification**: Both signatures must verify independently. If either fails, the
entire operation is rejected. This provides post-quantum safety — an attacker must
break both Ed448 AND ML-DSA-87 to forge a signature.

### Cryptographic Primitives

| Layer | Algorithm | Usage |
|-------|-----------|-------|
| Signatures | Ed448 + ML-DSA-87 | Mooring init/commit, fleet attestation |
| File Integrity | BLAKE3 | Filesystem manifests, content hashing |
| Provenance | SHAKE3-512 | Long-term provenance hashing, KDF input |
| Encryption | XChaCha20-Poly1305 | Secrets in transit (AEAD) |
| Key Derivation | HKDF-SHAKE512 | Per-session key derivation |
| Password | Argon2id (512 MiB) | Stored keypair protection (Wharf only) |
| CSPRNG | ChaCha20-DRBG | All key generation and nonces |

## Mooring Protocol

The four-phase HTTP protocol for Wharf → Yacht state synchronization:

```
Phase 1: INIT
  Wharf ──POST /mooring/init──▶ Yacht
         { layers, force, dry_run, signature: HybridSignature }
         ◀── { session_id, accepted_layers, yacht_pubkey }

Phase 2: VERIFY (per layer)
  Wharf ──POST /mooring/verify──▶ Yacht
         { session_id, layer, manifest: BLAKE3[] }
         ◀── { delta: [files needing sync] }

Phase 3: RSYNC
  Wharf ──SSH/rsync──▶ Yacht
         (delta transfer with identity file from fleet config)

Phase 4: COMMIT
  Wharf ──POST /mooring/commit──▶ Yacht
         { session_id, layers, signature: HybridSignature }
         ◀── { snapshot_id, integrity_hash, yacht_signature }
```

**Identity File Resolution** (Phase 3 rsync):
1. Per-yacht SSH key (`yacht.ssh_identity_file`)
2. Fleet-wide default (`mooring_config.ssh_identity`)
3. `~/.ssh/id_ed448`
4. SSH agent (fallback)

## Data Flow

### Read Path (Public)

```
User → CDN → Nginx → PHP → Database
                         ↑
                   (Read-Only)
```

### Write Path (Content)

```
User → CDN → Nginx → PHP → Yacht Agent → Database
                              │
                    (Policy Check: Allow Content)
```

### Admin Path (Configuration)

```
Admin → FIDO2 → Wharf CLI → Nebula → Yacht Agent → Database
                  │                        │
            (Ed448+ML-DSA-87)    (Verify Hybrid Sig)
```

## Security Layers

### Layer 1: Network (Nebula)

- Certificate-based authentication
- Encrypted UDP transport
- Invisible admin ports
- No public attack surface

### Layer 2: Database (AST Proxy)

- SQL parsing (not regex)
- Table-level access control
- Column-level filtering
- Operation blocking (DROP, ALTER)

### Layer 3: HTTP (Header Airlock)

- Header stripping
- Header injection
- CSP enforcement
- Request sanitization

### Layer 4: Filesystem (Integrity)

- BLAKE3 checksums
- OverlayFS sandboxing
- Automatic rollback
- RAM disk for temp files

### Layer 5: Authentication (FIDO2)

- Hardware key requirement
- Challenge-response
- Session management
- No passwords

## Configuration Schema

```nickel
# Fleet configuration
{
  yachts = {
    "production" = {
      ip = "192.168.100.1",
      adapter = "wordpress",
      policy = "strict",
    }
  },

  policies = {
    database = import "policies/database.ncl",
    airlock = import "policies/airlock.ncl",
    filesystem = import "policies/filesystem.ncl",
  }
}
```

## Deployment Models

### Single Server

```
┌─────────────────────────────┐
│         Server              │
│  ┌───────────────────────┐  │
│  │    Yacht Agent        │  │
│  └───────────────────────┘  │
│  ┌───────────────────────┐  │
│  │    WordPress          │  │
│  └───────────────────────┘  │
│  ┌───────────────────────┐  │
│  │    MariaDB            │  │
│  └───────────────────────┘  │
└─────────────────────────────┘
```

### Multi-Server (Recommended)

```
┌──────────────────┐   ┌──────────────────┐
│   Web Server     │   │   DB Server      │
│  ┌────────────┐  │   │  ┌────────────┐  │
│  │Yacht Agent │  │   │  │Yacht Agent │  │
│  └────────────┘  │   │  └────────────┘  │
│  ┌────────────┐  │   │  ┌────────────┐  │
│  │ WordPress  │──┼───┼──│  MariaDB   │  │
│  └────────────┘  │   │  └────────────┘  │
└──────────────────┘   └──────────────────┘
```

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: wordpress-yacht
spec:
  template:
    spec:
      containers:
      - name: yacht-agent
        image: cgr.dev/chainguard/wolfi-base
      - name: wordpress
        image: wordpress:latest
        volumeMounts:
        - name: webroot
          mountPath: /var/www/html
          readOnly: true
```

## Performance

### Overhead

| Component | Latency | CPU | Memory |
|-----------|---------|-----|--------|
| DB Proxy | <1ms | ~2% | ~50MB |
| Header Airlock | <0.5ms | ~1% | ~20MB |
| File Monitor | N/A | ~1% | ~30MB |
| Nebula | ~2ms | ~1% | ~15MB |

### Benchmarks

Tested on: 4-core VM, 8GB RAM, SSD

| Metric | Without Wharf | With Wharf | Overhead |
|--------|---------------|------------|----------|
| Requests/sec | 1000 | 950 | 5% |
| P99 latency | 50ms | 55ms | 10% |
| Memory | 500MB | 615MB | 23% |

## Threat Model

### In Scope

- SQL injection leading to data exfiltration
- File upload leading to code execution
- Configuration tampering
- Admin credential theft
- Man-in-the-middle attacks

### Out of Scope

- Physical server compromise
- Kernel vulnerabilities
- Side-channel attacks
- Social engineering

## Container Architecture

All container images use Chainguard bases (zero-CVE, SBOM provenance):

| Container | Base Image | Purpose |
|-----------|-----------|---------|
| Builder | `cgr.dev/chainguard/wolfi-base:latest` | Compilation stage |
| wharf-cli | `cgr.dev/chainguard/wolfi-base:latest` | Offline admin CLI |
| yacht-agent | `cgr.dev/chainguard/static:latest` | Distroless runtime agent |
| nginx | `cgr.dev/chainguard/nginx:latest` | Hardened web server |
| php-fpm | `cgr.dev/chainguard/php:latest-fpm` | PHP runtime |
| mariadb | `cgr.dev/chainguard/mariadb:latest` | Database |
| openlitespeed | `litespeedtech/openlitespeed` | Exception: no Chainguard OLS image |

### Container Toolchain

| Tool | Purpose |
|------|---------|
| `selur-compose` | Orchestration (replaces docker-compose) |
| `vordr` | Formally verified container runtime |
| `rokur` | Secrets management |
| `cerro-torre` | Image signing (Ed25519 + .ctp bundles) |
| `selur seal` | Zero-copy IPC bridge |

### Deployment

```
selur-compose -f infra/selur-compose.yaml up -d
```

The `selur-compose.yaml` defines: web (nginx), agent (yacht-agent), and db (mariadb)
services with read-only filesystems, capability restrictions, and rokur-managed secrets.

## Related Documents

- [SECURITY.md](../SECURITY.md) - Security policy
- [REVERSIBILITY.md](../REVERSIBILITY.md) - Undo capabilities
- [configs/policies/](../configs/policies/) - Policy schemas
