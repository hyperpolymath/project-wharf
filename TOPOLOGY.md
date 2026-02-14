<!-- SPDX-License-Identifier: PMPL-1.0-or-later -->
# TOPOLOGY.md - Project Wharf

## System Architecture

```
                     THE WHARF (Offline Controller)
                    +---------------------------------+
                    |  wharf-cli                      |
                    |  +-----------+  +-----------+   |
                    |  | moor.rs   |  | fleet.rs  |   |
                    |  | (keypair  |  | (yacht    |   |
                    |  |  persist) |  |  config)  |   |
                    |  +-----+-----+  +-----+-----+   |
                    |        |              |          |
                    |  +-----v--------------v-----+   |
                    |  |       wharf-core          |   |
                    |  | crypto | integrity | sync |   |
                    |  | mooring_client | config   |   |
                    |  | db_policy | fleet         |   |
                    |  +-------------+-------------+   |
                    +-----------------|--+--------------+
                                     |  |
              Mooring Protocol (HTTP) |  | rsync (SSH)
              Ed448+ML-DSA-87 signed  |  |
                                     |  |
                    +-----------------|--+--------------+
                    |  THE YACHT (Online Runtime)       |
                    |  yacht-agent                      |
                    |  +-----------+  +-------------+  |
                    |  | Mooring   |  | DB Proxy    |  |
                    |  | API       |  | (sqlparser  |  |
                    |  | (init/    |  |  AST filter)|  |
                    |  |  verify/  |  +------+------+  |
                    |  |  commit)  |         |         |
                    |  +-----+-----+  +------v------+  |
                    |        |        | Shadow DB   |  |
                    |  +-----v-----+  +-------------+  |
                    |  | Integrity |                    |
                    |  | (BLAKE3)  |  +-------------+  |
                    |  +-----------+  | Firewall    |  |
                    |                 | eBPF/nftab  |  |
                    |  +-----------+  +-------------+  |
                    |  | Metrics   |                    |
                    |  | /metrics  |  +-------------+  |
                    |  | /stats    |  | Nebula Mesh |  |
                    |  +-----------+  +-------------+  |
                    +----------------------------------+

    +-----------------------------------------------------------+
    |  wharf-ebpf (optional, excluded from default build)       |
    |  XDP kernel program + userspace loader (aya 0.12)         |
    +-----------------------------------------------------------+

    LOCAL DEPLOYMENT (deploy/compose.yaml)
    +-----------------------------------------------------------+
    |                                                           |
    |  Browser :8080 → OLS (web) → PHP/WordPress                |
    |                       ↓                                   |
    |              agent:3306 (yacht-agent proxy)                |
    |                   ↓           ↑                           |
    |              AST SQL parser   /stats /status /health      |
    |              (sqlparser 0.39) (API :9001)                  |
    |                   ↓                                       |
    |              db:3306 (MariaDB 10.11)                       |
    |                                                           |
    |  Blocked: INSERT wp_users, DROP, ALTER, TRUNCATE, UNION   |
    +-----------------------------------------------------------+
```

## Completion Dashboard

| Component              | Progress                     | Status |
|------------------------|------------------------------|--------|
| **wharf-core**         | `[██████████]` 100%          | Complete |
| - crypto (Ed448+ML-DSA)| `[██████████]` 100%         | Hybrid sigs, HKDF, XChaCha20, Argon2id, keypair serialization |
| - db_policy (AST)      | `[██████████]` 100%         | sqlparser 0.39, policy engine |
| - integrity (BLAKE3)   | `[██████████]` 100%         | Manifest gen/verify, remote SSH verify |
| - mooring protocol     | `[██████████]` 100%         | Init/verify/commit/abort, canonical signing |
| - mooring_client       | `[██████████]` 100%         | HTTP client with timeouts + pooling |
| - fleet/sync/config    | `[██████████]` 100%         | Fleet TOML, rsync, config hierarchy |
| **wharf-cli**          | `[█████████░]` 95%           | Near-complete |
| - moor operations      | `[██████████]` 100%         | Full mooring flow, persistent keypairs |
| - fleet management     | `[██████████]` 100%         | Add/remove/list yachts |
| - integrity audit      | `[████████░░]` 80%          | Local + remote SSH, API mode pending |
| - signature scheme     | `[██████████]` 100%         | MlDsa87Only (default) / Hybrid (opt-in) |
| **yacht-agent**        | `[█████████░]` 95%           | Near-complete |
| - DB proxy             | `[██████████]` 100%         | MySQL + PostgreSQL wire protocol |
| - mooring API          | `[██████████]` 100%         | Init/verify/commit with sig verification |
| - integrity verify     | `[██████████]` 100%         | BLAKE3 manifest verification wired |
| - firewall (nftables)  | `[██████████]` 100%         | Rule generation, validation, runtime updates |
| - metrics/stats        | `[██████████]` 100%         | Prometheus + JSON with real counters |
| - keypair persistence  | `[██████████]` 100%         | /etc/wharf/keys/yacht.key |
| - signature scheme     | `[██████████]` 100%         | CLI flag --signature-scheme, config support |
| **wharf-ebpf**         | `[████████░░]` 80%           | XDP program + loader, needs production testing |
| **nebula.rs**          | `[██████████]` 100%          | CA, cert signing, IP allocation, revocation |
| **wordpress-adapter**  | `[██████████]` 100%          | GPL-2.0 dashboard widget + admin bar indicator (stats/status fixed) |
| **deployment**         | `[██████████]` 100%          | setup.sh, DEPLOY.adoc, systemd unit, selur-compose |
| **local-deploy**       | `[██████████]` 100%          | compose.yaml, local-test.sh, verify-sqli.sh — E2E proven |
| **Overall**            | `[█████████░]` 95%           | ed448 audit pending, otherwise shipping |

## Key Dependencies

| Dependency | Version | Purpose |
|------------|---------|---------|
| ed448-goldilocks | 0.14.0-pre.10 | Classical hybrid signature component (UNAUDITED) |
| pqcrypto-mldsa | 0.1 | Post-quantum ML-DSA-87 signatures |
| sqlparser | 0.39 | AST-based SQL query analysis |
| axum | 0.7 | Yacht agent HTTP API |
| reqwest | 0.12 | Mooring HTTP client |
| blake3 | 1.5 | File integrity hashing |
| chacha20poly1305 | 0.10 | Symmetric encryption |
| aya | 0.12 | eBPF userspace loader |
| tokio | 1.x | Async runtime |
| clap | 4.4 | CLI argument parsing |
