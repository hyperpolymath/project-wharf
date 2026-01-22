# Project Wharf — Cerro Torre manifest for Yacht Web

ctp_version = "1.0"

[metadata]
name = "yacht-web"
version = "0.1.0"
revision = 1
kind = "container_image"
summary = "OpenLiteSpeed + PHP runtime for Project Wharf"
license = "NOASSERTION"
homepage = "https://openlitespeed.org"
maintainer = "wharf:ops"

[provenance]
import_date = 2026-01-19T00:00:00Z

[security]
suite_id = "CT-SIG-01"
payload_binding = "manifest.canonical_bytes_sha256"

[[inputs.sources]]
id = "openlitespeed_source"
type = "upstream_tar"
name = "openlitespeed"
version = "1.7.19"

[[inputs.sources.artifacts]]
filename = "openlitespeed-1.7.19.tgz"
uri = "https://openlitespeed.org/packages/openlitespeed-1.7.19.tgz"
sha256 = "TO_BE_FILLED_WITH_REAL_HASH"

[[inputs.sources]]
id = "php_source"
type = "upstream_tar"
name = "php"
version = "8.3.x"

[[inputs.sources.artifacts]]
filename = "php-8.3.x.tar.xz"
uri = "https://www.php.net/distributions/php-8.3.x.tar.xz"
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
sources = ["openlitespeed_source", "php_source"]

[[build.plan]]
step = "assemble_rootfs"
strip_docs = true
strip_locales = true

[[build.plan]]
step = "emit_oci_image"

[build.plan.image]
entrypoint = ["/usr/local/lsws/bin/lswsctrl"]
cmd = ["start"]

[build.plan.image.labels]
"org.opencontainers.image.title" = "yacht-web"
"org.opencontainers.image.source" = "https://github.com/hyperpolymath/project-wharf"
"org.opencontainers.image.description" = "OpenLiteSpeed + PHP for Project Wharf"

[outputs]
primary = "yacht-web"

[[outputs.artifacts]]
type = "oci_image"
name = "yacht-web"
tag = "0.1.0"

[[outputs.artifacts]]
type = "sbom_spdx_json"
name = "yacht-web.sbom.spdx.json"

[[outputs.artifacts]]
type = "in_toto_provenance"
name = "yacht-web.provenance.jsonl"
