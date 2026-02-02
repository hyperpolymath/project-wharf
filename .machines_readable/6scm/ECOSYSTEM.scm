;; SPDX-License-Identifier: PMPL-1.0-or-later
;; SPDX-FileCopyrightText: 2025 Jonathan D. A. Jewell <hyperpolymath>
;;
;; ECOSYSTEM.scm - Project relationship mapping
;; Media-Type: application/vnd.ecosystem+scm

(ecosystem
  (version "1.0")
  (name "project-wharf")
  (type "security-infrastructure")
  (purpose "Sovereign web hypervisor providing database virtual sharding and file integrity for CMS platforms")

  (position-in-ecosystem
    (role "security-layer")
    (layer "infrastructure")
    (description "Sits between web application and database/filesystem, enforcing security zones and integrity constraints"))

  (related-projects
    ((nebula
       ((relationship . "integration-target")
        (description . "Mesh VPN for Mooring protocol between Wharf controller and Yacht agents")
        (url . "https://github.com/slackhq/nebula")))

     (wordpress
       ((relationship . "primary-consumer")
        (description . "Initial target CMS platform for database virtual sharding")
        (url . "https://wordpress.org")))

     (aya-rs
       ((relationship . "dependency")
        (description . "Rust eBPF library for XDP firewall implementation")
        (url . "https://github.com/aya-rs/aya")))

     (sqlparser-rs
       ((relationship . "dependency")
        (description . "SQL parsing for policy engine AST analysis")
        (url . "https://github.com/sqlparser-rs/sqlparser-rs")))

     (januskey
       ((relationship . "sibling-project")
        (description . "Hardware security key standard - potential integration for Mooring authentication")
        (url . "https://github.com/hyperpolymath/januskey")))

     (bunsenite
       ((relationship . "sibling-project")
        (description . "Configuration language - could provide Nickel-based policy definitions")
        (url . "https://github.com/hyperpolymath/bunsenite")))))

  (what-this-is
    ("A security layer between CMS applications and their databases")
    ("Database virtual sharding using SQL AST analysis")
    ("File integrity verification with BLAKE3 manifests")
    ("Offline controller (Wharf) + online agent (Yacht) architecture")
    ("eBPF XDP packet filtering with nftables fallback"))

  (what-this-is-not
    ("A replacement for database replication")
    ("A web application firewall (WAF)")
    ("A full CMS platform")
    ("A general-purpose database proxy")))
