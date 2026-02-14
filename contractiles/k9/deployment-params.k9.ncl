K9!
# SPDX-License-Identifier: PMPL-1.0-or-later
# K9 Yard-level: Deployment parameters with validation
# Security Level: Yard (Nickel evaluation with contracts)
# Signature recommended but not required

{
  pedigree = {
    schema_version = "1.0.0",
    component_type = "deployment-parameters",
    security = {
      leash = 'Yard,
      trust_level = "validated-config",
      allow_network = false,
      allow_filesystem_write = false,
      allow_subprocess = false,
    },
    metadata = {
      name = "wharf-deployment-params",
      version = "1.0.0",
      description = "Validated deployment parameters for Project Wharf stack",
      author = "Jonathan D.A. Jewell <jonathan.jewell@open.ac.uk>",
    },
  },

  config = {
    # Target environment
    environment
      | [| 'Development, 'Staging, 'Production |]
      = 'Production,

    # Container image tags
    agent_image
      | String
      | std.string.NonEmpty
      = "yacht-agent:latest",

    nginx_image
      | String
      | std.string.NonEmpty
      = "yacht-nginx:latest",

    db_image
      | String
      | std.string.NonEmpty
      = "cgr.dev/chainguard/mariadb:latest",

    # Network configuration
    listen_port
      | Number
      | std.contract.from_predicate (fun p => p > 0 && p < 65536)
      = 3306,

    api_port
      | Number
      | std.contract.from_predicate (fun p => p > 0 && p < 65536)
      = 9001,

    web_http_port
      | Number
      | std.contract.from_predicate (fun p => p > 0 && p < 65536)
      = 8080,

    web_https_port
      | Number
      | std.contract.from_predicate (fun p => p > 0 && p < 65536)
      = 8443,

    # Firewall mode
    firewall_mode
      | [| 'Nftables, 'Ebpf, 'None |]
      = 'Nftables,

    # Capabilities
    enable_metrics | Bool = true,
    enable_ebpf | Bool = false,
    read_only_rootfs | Bool = true,

    # Paths on the host
    host_paths = {
      site_root
        | String
        | std.string.NonEmpty
        = "/opt/wharf/sites/default/html",

      uploads
        | String
        | std.string.NonEmpty
        = "/opt/wharf/sites/default/uploads",

      config
        | String
        | std.string.NonEmpty
        = "/opt/wharf/config",

      integrity_db
        | String
        | std.string.NonEmpty
        = "/opt/wharf/integrity",

      certs
        | String
        | std.string.NonEmpty
        = "/opt/wharf/certs",

      db_data
        | String
        | std.string.NonEmpty
        = "/opt/wharf/data/mysql",
    },
  },

  validation = {
    # Production must have metrics
    check_production_metrics =
      if config.environment == 'Production then
        config.enable_metrics == true
      else
        true,

    # eBPF requires nftables fallback
    check_ebpf_fallback =
      if config.enable_ebpf then
        config.firewall_mode == 'Nftables || config.firewall_mode == 'Ebpf
      else
        true,

    # API port must differ from listen port
    check_port_conflict = config.api_port != config.listen_port,
  },
}
