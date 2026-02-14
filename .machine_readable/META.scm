;; SPDX-License-Identifier: PMPL-1.0-or-later
(meta (metadata (version "0.1.0") (last-updated "2026-02-14"))
  (project-info
    (type workspace)
    (languages (rust))
    (license "PMPL-1.0-or-later")
    (description "The Sovereign Web Hypervisor — immutable CMS infrastructure"))
  (architecture-decisions
    (adr "hybrid-signatures"
      (status accepted)
      (description "Ed448 + ML-DSA-87 hybrid for post-quantum safety. Both must verify.")
      (rationale "Ed448 provides classical security; ML-DSA-87 provides quantum resistance. Hybrid ensures neither can be bypassed."))
    (adr "offline-admin-model"
      (status accepted)
      (description "Wharf (offline CLI) controls Yacht (online agent). No admin interface on the live server.")
      (rationale "Eliminates entire class of admin-panel attacks. Dark Matter approach."))
    (adr "chainguard-containers"
      (status accepted)
      (description "All container images use cgr.dev/chainguard bases. Distroless for runtime.")
      (rationale "Zero CVE base images with SBOM provenance. Minimal attack surface."))
    (adr "ast-aware-sql-proxy"
      (status accepted)
      (description "Database proxy parses SQL AST to enforce table allowlists and block dangerous operations.")
      (rationale "Prevents SQL injection at the wire protocol level, not just application level."))
    (adr "persistent-hybrid-keypairs"
      (status accepted)
      (description "CLI and agent persist Ed448+ML-DSA-87 keypairs to disk with restrictive file permissions.")
      (rationale "Stable identity is required for trust establishment. Ephemeral keys prevent the yacht from recognizing returning controllers."))
    (adr "ebpf-xdp-firewall"
      (status accepted)
      (description "Kernel-level packet filtering via eBPF XDP with nftables fallback.")
      (rationale "XDP processes packets before the kernel network stack for lowest latency. Cascade to nftables ensures protection without CAP_BPF."))))
