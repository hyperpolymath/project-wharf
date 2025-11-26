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

### Wharf Controller

The offline administrative interface.

**Location**: Your local machine or secure workstation

**Components**:
- `wharf-cli`: Command-line interface
- Nickel schemas: Declarative configuration
- Nebula CA: Certificate authority for mesh networking
- FIDO2 keys: Hardware authentication

**Responsibilities**:
- Configuration authoring
- Certificate generation
- State synchronization
- Security auditing

### Yacht Agent

The runtime enforcement agent.

**Location**: Production server

**Components**:
- Database Proxy: SQL query filtering
- Header Airlock: HTTP sanitization
- File Integrity Monitor: BLAKE3 verification
- Mooring API: Secure sync endpoint

**Responsibilities**:
- Policy enforcement
- Query filtering
- Header sanitization
- Integrity verification

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
                                          │
                               (Policy Check: Signed by Wharf)
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

## Related Documents

- [SECURITY.md](../SECURITY.md) - Security policy
- [REVERSIBILITY.md](../REVERSIBILITY.md) - Undo capabilities
- [configs/policies/](../configs/policies/) - Policy schemas
