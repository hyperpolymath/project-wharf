# Project Wharf — Cerro Torre manifest for Yacht MariaDB

ctp_version = "1.0"

[metadata]
name = "yacht-mariadb"
version = "0.1.0"
revision = 1
kind = "container_image"
summary = "MariaDB database for WordPress Yacht"
license = "GPL-2.0-or-later"
homepage = "https://mariadb.org"
maintainer = "wharf:ops"

[provenance]
import_date = 2026-01-19T00:00:00Z

[security]
suite_id = "CT-SIG-01"
payload_binding = "manifest.canonical_bytes_sha256"

[[inputs.sources]]
id = "mariadb_source"
type = "upstream_tar"
name = "mariadb"
version = "10.11.x"

[[inputs.sources.artifacts]]
filename = "mariadb-10.11.x.tar.gz"
uri = "https://downloads.mariadb.org/rest-api/mariadb/10.11.x/mariadb-10.11.x.tar.gz"
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
sources = ["mariadb_source"]

[[build.plan]]
step = "assemble_rootfs"
strip_docs = true
strip_locales = true

[[build.plan]]
step = "emit_oci_image"

[build.plan.image]
entrypoint = ["/usr/sbin/mariadbd"]

[build.plan.image.labels]
"org.opencontainers.image.title" = "yacht-mariadb"
"org.opencontainers.image.source" = "https://mariadb.org"
"org.opencontainers.image.description" = "MariaDB for Project Wharf"

[outputs]
primary = "yacht-mariadb"

[[outputs.artifacts]]
type = "oci_image"
name = "yacht-mariadb"
tag = "0.1.0"

[[outputs.artifacts]]
type = "sbom_spdx_json"
name = "yacht-mariadb.sbom.spdx.json"

[[outputs.artifacts]]
type = "in_toto_provenance"
name = "yacht-mariadb.provenance.jsonl"
