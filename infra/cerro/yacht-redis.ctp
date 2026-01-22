# Project Wharf — Cerro Torre manifest for Yacht Redis

ctp_version = "1.0"

[metadata]
name = "yacht-redis"
version = "0.1.0"
revision = 1
kind = "container_image"
summary = "Redis cache for Project Wharf"
license = "BSD-3-Clause"
homepage = "https://redis.io"
maintainer = "wharf:ops"

[provenance]
import_date = 2026-01-19T00:00:00Z

[security]
suite_id = "CT-SIG-01"
payload_binding = "manifest.canonical_bytes_sha256"

[[inputs.sources]]
id = "redis_source"
type = "upstream_tar"
name = "redis"
version = "7.2.x"

[[inputs.sources.artifacts]]
filename = "redis-7.2.x.tar.gz"
uri = "https://download.redis.io/releases/redis-7.2.x.tar.gz"
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
sources = ["redis_source"]

[[build.plan]]
step = "assemble_rootfs"
strip_docs = true
strip_locales = true

[[build.plan]]
step = "emit_oci_image"

[build.plan.image]
entrypoint = ["redis-server"]

[build.plan.image.labels]
"org.opencontainers.image.title" = "yacht-redis"
"org.opencontainers.image.source" = "https://redis.io"
"org.opencontainers.image.description" = "Redis cache for Project Wharf"

[outputs]
primary = "yacht-redis"

[[outputs.artifacts]]
type = "oci_image"
name = "yacht-redis"
tag = "0.1.0"

[[outputs.artifacts]]
type = "sbom_spdx_json"
name = "yacht-redis.sbom.spdx.json"

[[outputs.artifacts]]
type = "in_toto_provenance"
name = "yacht-redis.provenance.jsonl"
