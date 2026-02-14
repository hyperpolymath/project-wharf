K9!
# SPDX-License-Identifier: PMPL-1.0-or-later
# K9 Hunt-level: Full Wharf deployment automation
# Security Level: Hunt (full system access)
# SIGNATURE REQUIRED - Review carefully before use

{
  pedigree = {
    schema_version = "1.0.0",
    component_type = "deployment-automation",
    security = {
      leash = 'Hunt,
      trust_level = "full-system-access",
      allow_network = true,
      allow_filesystem_write = true,
      allow_subprocess = true,
      signature_required = true,
    },
    metadata = {
      name = "deploy-wharf",
      version = "1.0.0",
      description = "Deploy Project Wharf stack (yacht-agent + nginx + database)",
      author = "Jonathan D.A. Jewell <jonathan.jewell@open.ac.uk>",
    },
    warnings = [
      "This component creates directories and starts containers",
      "Requires podman and selur-compose on the target host",
      "Review all recipes before execution",
      "Use dry-run mode first: ./must --dry-run run deploy-wharf.k9.ncl",
    ],
    side_effects = [
      "Creates /opt/wharf/ directory tree",
      "Builds container images via podman",
      "Starts services via selur-compose",
      "Generates yacht-agent keypair if not present",
      "Opens firewall ports 3306, 8080, 8443, 9001",
    ],
  },

  config = {
    target_dir
      | String
      | std.string.NonEmpty
      = "/opt/wharf",

    compose_file
      | String
      | std.string.NonEmpty
      = "infra/selur-compose.yaml",

    dry_run | Bool = false,
  },

  recipes = {
    default = {
      recipe = "deploy",
      description = "Full deployment: prepare dirs, build images, start services",
    },

    "deploy" = {
      dependencies = ["check-prerequisites", "prepare-dirs", "build-images"],
      commands = [
        "echo 'Starting Wharf stack...'",
        "selur-compose -f %{config.compose_file} up -d",
        "echo 'Waiting for services to become healthy...'",
        "sleep 5",
        "selur-compose -f %{config.compose_file} ps",
        "echo 'Wharf stack deployed successfully'",
      ],
    },

    "check-prerequisites" = {
      description = "Verify required tools and permissions",
      commands = [
        "command -v podman || (echo 'ERROR: podman not found' && exit 1)",
        "command -v selur-compose || (echo 'ERROR: selur-compose not found' && exit 1)",
        "command -v cerro-torre || echo 'WARNING: cerro-torre not found — image signing disabled'",
        "echo 'Prerequisites checked'",
      ],
    },

    "prepare-dirs" = {
      description = "Create required host directories",
      commands = [
        "mkdir -p %{config.target_dir}/sites/default/html",
        "mkdir -p %{config.target_dir}/sites/default/uploads",
        "mkdir -p %{config.target_dir}/config/keys",
        "mkdir -p %{config.target_dir}/integrity",
        "mkdir -p %{config.target_dir}/certs",
        "mkdir -p %{config.target_dir}/data/mysql",
        "chmod 700 %{config.target_dir}/config/keys",
        "echo 'Host directories prepared'",
      ],
    },

    "build-images" = {
      description = "Build container images with podman",
      commands = [
        "podman build -t yacht-agent:latest -f infra/containers/Containerfile.agent .",
        "podman build -t yacht-nginx:latest -f infra/containers/Containerfile.nginx .",
        "echo 'Images built'",
      ],
    },

    "stop" = {
      description = "Stop the Wharf stack",
      commands = [
        "selur-compose -f %{config.compose_file} down",
        "echo 'Wharf stack stopped'",
      ],
    },

    "status" = {
      description = "Check service status and health",
      commands = [
        "selur-compose -f %{config.compose_file} ps",
        "echo '---'",
        "curl -sf http://localhost:9001/health || echo 'Agent unhealthy'",
        "echo '---'",
        "curl -sf http://localhost:9001/stats || echo 'Stats unavailable'",
      ],
    },
  },

  validation = {
    check_target_dir = std.string.length config.target_dir > 0,
  },
}
