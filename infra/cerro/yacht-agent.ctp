# Project Wharf — Cerro Torre manifest for Yacht Agent

ctp_version = "1.0"

[metadata]
name = "yacht-agent"
version = "0.1.0"
revision = 1
kind = "container_image"
summary = "Wharf Yacht Agent (DB proxy, integrity, eBPF)"
license = "NOASSERTION"
homepage = "https://github.com/hyperpolymath/project-wharf"
maintainer = "wharf:ops"

[provenance]
import_date = 2026-01-19T00:00:00Z

[security]
suite_id = "CT-SIG-01"
payload_binding = "manifest.canonical_bytes_sha256"

[[inputs.sources]]
id = "wharf_source"
type = "git"
name = "project-wharf"
version = "main"

[[inputs.sources.artifacts]]
filename = "project-wharf.git"
uri = "https://github.com/hyperpolymath/project-wharf.git"
sha256 = "TO_BE_FILLED_WITH_REAL_HASH"

[build]
system = "cerro_image"

[build.environment]
arch = "amd64"
os = "linux"
reproducible = true

[[build.plan]]
step = "import"
using = "git"
sources = ["wharf_source"]

[[build.plan]]
step = "assemble_rootfs"
strip_docs = true
strip_locales = true

[[build.plan]]
step = "emit_oci_image"

[build.plan.image]
entrypoint = ["/usr/local/bin/yacht-agent"]

[build.plan.image.labels]
"org.opencontainers.image.title" = "yacht-agent"
"org.opencontainers.image.source" = "https://github.com/hyperpolymath/project-wharf"
"org.opencontainers.image.description" = "Wharf Yacht Agent"

[outputs]
primary = "yacht-agent"

[[outputs.artifacts]]
type = "oci_image"
name = "yacht-agent"
tag = "0.1.0"

[[outputs.artifacts]]
type = "sbom_spdx_json"
name = "yacht-agent.sbom.spdx.json"

[[outputs.artifacts]]
type = "in_toto_provenance"
name = "yacht-agent.provenance.jsonl"
