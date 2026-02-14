;; SPDX-License-Identifier: PMPL-1.0-or-later
(state (metadata (version "0.1.0") (last-updated "2026-02-14") (status active))
  (project-context
    (name "project-wharf")
    (purpose "Sovereign Web Hypervisor — immutable CMS infrastructure with offline admin (Wharf) and online runtime (Yacht)")
    (completion-percentage 90))
  (route-to-mvp
    (milestone "crypto-overhaul" (status complete) (description "Ed448 + ML-DSA-87 hybrid signatures, SHAKE3-512, XChaCha20-Poly1305, HKDF, Argon2id"))
    (milestone "http-mooring-client" (status complete) (description "MooringClient HTTP API: init → verify → rsync → commit"))
    (milestone "identity-file" (status complete) (description "SSH identity resolution: yacht → fleet → ~/.ssh/id_ed448 → agent"))
    (milestone "container-compliance" (status complete) (description "Chainguard bases, Containerfile naming, selur-compose orchestration"))
    (milestone "demo-script" (status complete) (description "End-to-end mooring + SQL injection blocking + file tampering detection"))
    (milestone "production-hardening" (status in-progress) (description "Production hardening milestone")
      (sub-milestone "keypair-persistence" (status complete) (description "Persistent hybrid keypairs for CLI and yacht-agent with file permissions"))
      (sub-milestone "ebpf-loader" (status complete) (description "Full XDP kernel program + userspace loader in crates/wharf-ebpf/"))
      (sub-milestone "database-proxy" (status complete) (description "Full AST parser via sqlparser 0.39 in db_policy.rs"))
      (sub-milestone "certificate-management" (status complete) (description "1024-line Nebula module in nebula.rs with CA, cert signing, IP allocation, revocation"))
      (sub-milestone "metrics" (status complete) (description "Prometheus metrics and stats endpoints wired to real counters"))
      (sub-milestone "http-resilience" (status complete) (description "Timeouts, connection pooling on mooring HTTP client"))
      (sub-milestone "integrity-verification" (status complete) (description "Yacht agent mooring verify wired to BLAKE3 manifest verification"))
      (sub-milestone "ed448-audit" (status pending) (description "ed448-goldilocks v0.14.0-pre.10 needs third-party audit before production"))))
  (components
    (component "wharf-core" (path "crates/wharf-core") (role "shared library: crypto, fleet, integrity, mooring, sync"))
    (component "wharf-cli" (path "bin/wharf-cli") (role "offline admin CLI: moor, integrity, fleet management"))
    (component "yacht-agent" (path "bin/yacht-agent") (role "online runtime: HTTP API, DB proxy, firewall, integrity enforcement"))
    (component "wharf-ebpf" (path "crates/wharf-ebpf") (role "eBPF programs for XDP firewall (optional, excluded from default build)"))
    (component "xtask" (path "xtask") (role "build tasks: eBPF compilation")))
  (blockers-and-issues
    (blocker "ed448-goldilocks-pre-release" (severity medium) (description "v0.14.0-pre.10 is unaudited; needs third-party audit before production deployment"))))
