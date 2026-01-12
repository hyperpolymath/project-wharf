;; SPDX-License-Identifier: PMPL-1.0
;; SPDX-FileCopyrightText: 2025 Jonathan D. A. Jewell <hyperpolymath>
;;
;; STATE.scm - Project Wharf State Tracking
;; Schema: hyperpolymath/state.scm v1.0

(define project-state
  `((metadata
      ((version . "1.0.0")
       (schema-version . "1")
       (created . "2025-01-10T13:50:29+00:00")
       (updated . "2025-01-12T08:00:00+00:00")
       (project . "project-wharf")
       (repo . "https://github.com/hyperpolymath/project-wharf")))

    (project-context
      ((name . "Project Wharf")
       (tagline . "Sovereign Web Hypervisor - Database Virtual Sharding")
       (tech-stack . (rust aya-ebpf sqlparser blake3 tokio axum))))

    (current-position
      ((phase . "Alpha Development")
       (overall-completion . 65)
       (components
         ((wharf-core
            ((status . "functional")
             (completion . 75)
             (notes . "PolicyEngine, IntegrityChecker, SyncManager, ConfigLoader, Mooring protocol")))
          (yacht-agent
            ((status . "in-progress")
             (completion . 70)
             (notes . "DB proxy, API, eBPF loader, nftables, config, mooring endpoints complete")))
          (wharf-cli
            ((status . "in-progress")
             (completion . 35)
             (notes . "Basic commands implemented")))
          (wharf-ebpf
            ((status . "functional")
             (completion . 80)
             (notes . "XDP shield complete, xtask build automation added")))))
       (working-features
         ("Database virtual sharding policy engine"
          "SQL AST parsing for zone classification"
          "BLAKE3 file integrity manifests"
          "eBPF XDP firewall loader (userspace)"
          "nftables fallback firewall"
          "rsync-based file synchronization"
          "Configuration file loading (TOML)"
          "Mooring protocol definition (init/verify/commit)"
          "Mooring API endpoints in yacht-agent"))))

    (route-to-mvp
      ((milestones
        ((core-hardening
           ((target-completion . 70)
            (items . ("Wire integrity ops in CLI"
                      "Add config loading to wharf-cli"))
            (status . "in-progress")))
         (nebula-integration
           ((target-completion . 85)
            (items . ("Wire mooring protocol to CLI"
                      "Nebula mesh VPN coordination"
                      "Certificate management"
                      "Ed25519 signature verification"))
            (status . "in-progress")))
         (production-ready
           ((target-completion . 100)
            (items . ("Performance optimization"
                      "Comprehensive test suite"
                      "Documentation and examples"))
            (status . "pending")))))))

    (blockers-and-issues
      ((critical . ())
       (high . ())
       (medium . ("CLI integrity commands not wired"))
       (low . ("Some unused function warnings in wharf-cli"))))

    (critical-next-actions
      ((immediate . ("Wire integrity commands in CLI"
                     "Start Nebula/Mooring integration"))
       (this-week . ("Test nftables on production system"
                     "Test eBPF compilation with bpf-linker"))
       (this-month . ("Implement Mooring protocol"
                      "Performance optimization"))))

    (session-history
      (((timestamp . "2025-01-12T08:00:00Z")
        (session-id . "mooring-protocol")
        (accomplishments
          ("Created wharf-core mooring module with protocol types"
           "Defined MooringLayer, MooringSession, SessionState enums"
           "Added request/response types for init/verify/commit"
           "Implemented mooring endpoints in yacht-agent API"
           "Session management with expiration and state tracking"
           "MVP mooring protocol ready for CLI integration")))
       ((timestamp . "2025-01-12T07:00:00Z")
        (session-id . "config-support")
        (accomplishments
          ("Created wharf-core config module with TOML support"
           "Added ConfigLoader for hierarchical config discovery"
           "Defined YachtAgentConfig and WharfCliConfig structs"
           "Integrated config loading into yacht-agent main"
           "Config merges with CLI args (CLI takes precedence)"
           "Created example config files in examples/")))
       ((timestamp . "2025-01-12T06:00:00Z")
        (session-id . "firewall-blockers")
        (accomplishments
          ("Implemented NftablesManager with full runtime API"
           "Fixed critical bug: nftables rules now actually applied"
           "Added Firewall enum to unify eBPF and nftables"
           "Created xtask crate for eBPF build automation"
           "Added cargo xtask build-ebpf command"
           "Both high-priority blockers resolved")))
       ((timestamp . "2025-01-12T05:00:00Z")
        (session-id . "scm-and-fuzzing")
        (accomplishments
          ("Updated STATE.scm with detailed project state"
           "Updated META.scm with 5 ADRs and development practices"
           "Updated ECOSYSTEM.scm with related projects"
           "Added ClusterFuzzLite fuzzing setup"
           "Created fuzz targets for SQL policy and integrity")))
       ((timestamp . "2025-01-12T04:45:00Z")
        (session-id . "security-and-cleanup")
        (accomplishments
          ("Fixed SPDX headers across all workflow files"
           "Fixed compiler warnings in wharf-core and yacht-agent"
           "Deleted duplicate rust.yml workflow")))))))

;; Helper functions
(define (get-completion-percentage state)
  (cdr (assoc 'overall-completion
              (cdr (assoc 'current-position (cdr state))))))

(define (get-blockers state priority)
  (cdr (assoc priority
              (cdr (assoc 'blockers-and-issues (cdr state))))))
