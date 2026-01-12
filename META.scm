;; SPDX-License-Identifier: PMPL-1.0
;; SPDX-FileCopyrightText: 2025 Jonathan D. A. Jewell <hyperpolymath>
;;
;; META.scm - Project metadata and architectural decisions
;; Schema: hyperpolymath/META-FORMAT-SPEC v1.0

(define project-meta
  `((version . "1.0.0")

    (architecture-decisions
      ((adr-001
         ((title . "Use eBPF XDP for packet filtering with nftables fallback")
          (status . "accepted")
          (date . "2025-01-01")
          (context . "Need kernel-level packet filtering for security. Not all systems support eBPF.")
          (decision . "Implement XDP-based firewall using aya-bpf, with automatic nftables fallback for non-eBPF systems")
          (consequences . ("Maximum performance on modern kernels"
                          "Broader compatibility via fallback"
                          "Two code paths to maintain"))))

       (adr-002
         ((title . "SQL AST-based policy enforcement")
          (status . "accepted")
          (date . "2025-01-01")
          (context . "Need to classify database queries into security zones without regex pattern matching")
          (decision . "Use sqlparser-rs to parse SQL into AST, then analyze table references and operation types")
          (consequences . ("Accurate query classification"
                          "Dialect-aware parsing (MySQL, PostgreSQL)"
                          "Performance overhead for AST parsing"))))

       (adr-003
         ((title . "BLAKE3 for file integrity")
          (status . "accepted")
          (date . "2025-01-01")
          (context . "Need fast, secure hashing for file integrity manifests")
          (decision . "Use BLAKE3 instead of SHA-256 for integrity checksums")
          (consequences . ("10x faster than SHA-256"
                          "Modern cryptographic security"
                          "Less widespread tooling support"))))

       (adr-004
         ((title . "Rust-first architecture")
          (status . "accepted")
          (date . "2025-01-01")
          (context . "Security-critical system needs memory safety and performance")
          (decision . "Write all components in Rust (wharf-core, yacht-agent, wharf-cli, wharf-ebpf)")
          (consequences . ("Memory safety without GC"
                          "Single language across stack"
                          "Steeper learning curve"))))

       (adr-005
         ((title . "Nebula mesh VPN for Mooring")
          (status . "proposed")
          (date . "2025-01-10")
          (context . "Wharf (offline) and Yacht (online) need secure communication channel")
          (decision . "Use Nebula overlay network for Mooring protocol between controller and agents")
          (consequences . ("End-to-end encryption"
                          "NAT traversal capability"
                          "Certificate-based identity"))))))

    (development-practices
      ((code-style . "rustfmt + clippy")
       (security . "openssf-scorecard")
       (testing . "cargo-test + cargo-fuzz")
       (versioning . "semver")
       (documentation . "asciidoc")
       (branching . "trunk-based")
       (ci-cd . "github-actions")
       (licensing . "PMPL-1.0")))

    (design-rationale
      ((why-database-virtual-sharding
         "CMS platforms like WordPress mix user content with admin config in shared databases. Virtual sharding enforces zone separation at the SQL level without schema changes.")
       (why-offline-online-split
         "Separating the controller (Wharf) from runtime (Yacht) allows air-gapped administration. Changes only sync during explicit Mooring sessions.")
       (why-ebpf-over-iptables
         "eBPF XDP processes packets before they enter the network stack, providing lower latency and higher throughput than iptables/nftables.")
       (why-blake3-over-sha256
         "BLAKE3 is SIMD-optimized and 10x faster than SHA-256 while providing equivalent security. Critical for large file manifests.")))))
