# Project Wharf — Cerro Torre manifest for Yacht Memcached

ctp_version = "1.0"

[metadata]
name = "yacht-memcached"
version = "0.1.0"
revision = 1
kind = "container_image"
summary = "Memcached cache for Project Wharf"
license = "BSD-3-Clause"
homepage = "https://memcached.org"
maintainer = "wharf:ops"

[provenance]
import_date = 2026-01-19T00:00:00Z

[security]
suite_id = "CT-SIG-01"
payload_binding = "manifest.canonical_bytes_sha256"

[[inputs.sources]]
id = "memcached_source"
type = "upstream_tar"
name = "memcached"
version = "1.6.x"

[[inputs.sources.artifacts]]
filename = "memcached-1.6.x.tar.gz"
uri = "https://memcached.org/files/memcached-1.6.x.tar.gz"
sha256 = "TO_BE_FILLED_WITH_REAL_HASH"

[build]
system = "cerro_image"

[build.environment]
arch = "amd64"
os = "linux"
reproducible = true

[[build.plan]]
step = "import"
using = "upstream"
sources = ["memcached_source"]

[[build.plan]]
step = "assemble_rootfs"
strip_docs = true
strip_locales = true

[[build.plan]]
step = "emit_oci_image"

[build.plan.image]
entrypoint = ["memcached"]
cmd = ["-m", "512", "-p", "11211", "-U", "0", "-l", "0.0.0.0"]

[build.plan.image.labels]
"org.opencontainers.image.title" = "yacht-memcached"
"org.opencontainers.image.source" = "https://memcached.org"
"org.opencontainers.image.description" = "Memcached cache for Project Wharf"

[outputs]
primary = "yacht-memcached"

[[outputs.artifacts]]
type = "oci_image"
name = "yacht-memcached"
tag = "0.1.0"

[[outputs.artifacts]]
type = "sbom_spdx_json"
name = "yacht-memcached.sbom.spdx.json"

[[outputs.artifacts]]
type = "in_toto_provenance"
name = "yacht-memcached.provenance.jsonl"
