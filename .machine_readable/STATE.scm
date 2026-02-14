;; SPDX-License-Identifier: PMPL-1.0-or-later
(state (metadata (version "0.1.0") (last-updated "2026-02-14") (status active))
  (project-context
    (name "project-wharf")
    (purpose "Sovereign Web Hypervisor — immutable CMS infrastructure with offline admin (Wharf) and online runtime (Yacht)")
    (completion-percentage 75))
  (route-to-mvp
    (milestone "crypto-overhaul" (status complete) (description "Ed448 + ML-DSA-87 hybrid signatures, SHAKE3-512, XChaCha20-Poly1305, HKDF, Argon2id"))
    (milestone "http-mooring-client" (status complete) (description "MooringClient HTTP API: init → verify → rsync → commit"))
    (milestone "identity-file" (status complete) (description "SSH identity resolution: yacht → fleet → ~/.ssh/id_ed448 → agent"))
    (milestone "container-compliance" (status complete) (description "Chainguard bases, Containerfile naming, selur-compose orchestration"))
    (milestone "demo-script" (status complete) (description "End-to-end mooring + SQL injection blocking + file tampering detection"))
    (milestone "production-hardening" (status pending) (description "Persist keypairs, eBPF loader, real database proxy, certificate management")))
  (components
    (component "wharf-core" (path "crates/wharf-core") (role "shared library: crypto, fleet, integrity, mooring, sync"))
    (component "wharf-cli" (path "bin/wharf-cli") (role "offline admin CLI: moor, integrity, fleet management"))
    (component "yacht-agent" (path "bin/yacht-agent") (role "online runtime: HTTP API, DB proxy, firewall, integrity enforcement"))
    (component "wharf-ebpf" (path "crates/wharf-ebpf") (role "eBPF programs for XDP firewall (optional, excluded from default build)"))
    (component "xtask" (path "xtask") (role "build tasks: eBPF compilation")))
  (blockers-and-issues
    (blocker "ed448-goldilocks-pre-release" (severity medium) (description "v0.14.0-pre.10 is unaudited; needs audit before production"))
    (blocker "keypair-persistence" (severity medium) (description "CLI generates ephemeral keypairs; need disk persistence with file permissions"))))
