K9!
# SPDX-License-Identifier: PMPL-1.0-or-later
# K9 Kennel-level: Yacht Agent configuration data
# Security Level: Kennel (data-only, no execution)
# No signature required - safe for any use

{
  pedigree = {
    schema_version = "1.0.0",
    component_type = "agent-configuration",
    security = {
      leash = 'Kennel,
      trust_level = "data-only",
      allow_network = false,
      allow_filesystem_write = false,
      allow_subprocess = false,
    },
    metadata = {
      name = "yacht-agent-config",
      version = "1.0.0",
      description = "Yacht Agent runtime configuration for Project Wharf",
      author = "Jonathan D.A. Jewell <jonathan.jewell@open.ac.uk>",
    },
  },

  config = {
    # Network ports
    listen_port = 3306,
    shadow_port = 33060,
    api_port = 9001,
    db_protocol = "mysql",

    # Security defaults
    firewall_mode = "nftables",
    metrics_enabled = true,

    # File integrity
    integrity_check_interval_secs = 300,
    integrity_hash_algorithm = "blake3",

    # Mooring protocol
    mooring = {
      protocol_version = "1.0.0",
      signature_scheme = "ed448+mldsa87",
      nonce_length = 32,
    },

    # Paths
    paths = {
      key_store = "/etc/wharf/keys",
      site_root = "/var/www/html",
      integrity_db = "/var/lib/wharf/integrity",
      config_dir = "/etc/wharf",
    },

    # Database proxy policy
    db_policy = {
      allowed_tables = [
        "wp_posts",
        "wp_postmeta",
        "wp_options",
        "wp_users",
        "wp_usermeta",
        "wp_terms",
        "wp_term_taxonomy",
        "wp_term_relationships",
        "wp_comments",
        "wp_commentmeta",
        "wp_links",
      ],
      blocked_operations = [
        "DROP",
        "TRUNCATE",
        "ALTER",
        "CREATE",
        "GRANT",
        "REVOKE",
      ],
      audit_all_queries = true,
    },
  },

  export = {
    format = "json",
    destination = "yacht-agent.json",
  },
}
