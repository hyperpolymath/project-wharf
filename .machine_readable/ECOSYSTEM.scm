;; SPDX-License-Identifier: PMPL-1.0-or-later
(ecosystem (metadata (version "0.1.0") (last-updated "2026-02-14"))
  (project
    (name "project-wharf")
    (purpose "Sovereign Web Hypervisor — immutable CMS infrastructure separating offline admin from online runtime")
    (role security-infrastructure))
  (related-projects
    (project "selur" (relationship runtime-dependency) (description "Container sealing via zero-copy IPC bridge"))
    (project "selur-compose" (relationship orchestration) (description "Container orchestration replacing docker-compose"))
    (project "vordr" (relationship runtime-dependency) (description "Formally verified container execution runtime"))
    (project "svalinn" (relationship runtime-dependency) (description "HTTP edge gateway with policy enforcement"))
    (project "cerro-torre" (relationship build-dependency) (description "Container image signing with Ed25519 + .ctp bundles"))
    (project "rokur" (relationship runtime-dependency) (description "Secrets management for container deployments"))
    (project "panic-attacker" (relationship quality-tool) (description "Security scanning for weak points"))
    (project "echidna" (relationship quality-tool) (description "Formal proofing and fuzzing"))
    (project "hypatia" (relationship ci-cd-tool) (description "Neurosymbolic CI/CD security intelligence"))
    (project "gitbot-fleet" (relationship automation) (description "Bot orchestration: rhodibot, echidnabot, sustainabot, glambot, seambot, finishbot"))
    (project "verisimdb-data" (relationship quality-data) (description "Security scan data ingestion for weak point tracking"))
    (project "wordpress" (relationship adapter-target) (description "Primary CMS adapter — GPL-2.0 dashboard plugin in adapters/wordpress-wharf/"))))
