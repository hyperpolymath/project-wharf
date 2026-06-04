<!--
SPDX-License-Identifier: MPL-2.0
Copyright (c) Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
-->
# Wharf Roadmap

## Vision

Make CMS security as reliable as containerized infrastructure by separating
administration from runtime.

---

## Current Status: v1.0.0 (Foundation) ✅

Production-ready sovereign web hypervisor with:

- ✅ Offline admin (Wharf) + read-only runtime (Yacht) architecture
- ✅ File sync with BLAKE3 integrity verification
- ✅ Remote integrity verification via SSH
- ✅ Fleet management with TOML configuration
- ✅ eBPF XDP firewall with nftables fallback
- ✅ Distroless containers (Chainguard)
- ✅ OpenLiteSpeed + LSAPI PHP
- ✅ Prometheus metrics endpoint
- ✅ Let's Encrypt SSL automation
- ✅ SQL query filtering proxy
- ✅ WordPress adapter

---

## v1.1 - Observability & Reliability

**Focus**: Production monitoring, alerting, and operational resilience

### Monitoring
- [ ] Grafana dashboard templates for Yacht metrics
- [ ] Alertmanager integration with sensible defaults
- [ ] Structured logging with JSON output option
- [ ] Log aggregation support (Loki/Elasticsearch)
- [ ] Health check endpoints with degradation reporting
- [ ] Automatic SSL certificate renewal monitoring

### Reliability
- [ ] Backup verification (restore testing)
- [ ] Disaster recovery runbook automation
- [ ] Performance benchmarking suite
- [ ] Load testing integration (k6/locust)

### Technical Debt
- [ ] Comprehensive test coverage (unit + integration)
- [ ] CI/CD pipeline templates (GitHub Actions, GitLab CI)
- [ ] Documentation site (mdBook)
- [ ] Security fuzzing

---

## v1.2 - Multi-tenancy & Scale

**Focus**: Multiple sites per yacht, horizontal scaling

### Multi-Site
- [ ] Multiple WordPress sites on single yacht
- [ ] Site isolation (separate users, namespaces)
- [ ] Resource quotas per site (CPU, memory, I/O)
- [ ] Per-site integrity manifests

### Scaling
- [ ] Automatic yacht provisioning (Terraform modules)
- [ ] Load balancer integration (HAProxy, Traefik)
- [ ] Geographic distribution support
- [ ] CDN integration (Cloudflare, Fastly, Bunny)
- [ ] Edge caching configuration

### Security
- [ ] Rate limiting per site
- [ ] DDoS mitigation integration
- [ ] Geo-blocking support

### Operations
- [ ] Rolling updates with zero downtime
- [ ] Canary deployments
- [ ] Automatic failover between yachts
- [ ] Fleet-wide configuration drift detection

---

## v2.0 - ArangoDB & Graph Intelligence

**Focus**: Replace MySQL with ArangoDB, enable graph-based security analysis

### Core Changes
- [ ] ArangoDB as primary database option
- [ ] WordPress adapter for ArangoDB (WP-Arango plugin)
- [ ] MySQL-to-ArangoDB migration tool
- [ ] AQL query proxy (replace SQL proxy)
- [ ] Graph-based audit trails

### Security Intelligence
- [ ] Attack pattern graph detection
- [ ] User behavior anomaly detection
- [ ] Content relationship mapping
- [ ] Permission inheritance visualization
- [ ] Automated threat correlation
- [ ] Security event graph queries

### Developer Experience
- [ ] Graph query builder UI
- [ ] Visual audit trail explorer
- [ ] Relationship impact analysis
- [ ] Schema migration tools

---

## v2.1 - Team Collaboration

**Focus**: Multi-operator access and workflow management

### Access Control
- [ ] RBAC (Role-Based Access Control)
- [ ] Multiple operator SSH keys
- [ ] Audit logging for all operations
- [ ] SSO integration (OIDC, SAML)
- [ ] FIDO2/WebAuthn authentication option
- [ ] Session management and revocation

### Workflows
- [ ] Change approval workflows
- [ ] Deployment scheduling
- [ ] Team notifications (Slack, Discord, Email)
- [ ] Content staging environments
- [ ] Preview deployments
- [ ] Rollback with one command
- [ ] Change diff visualization
- [ ] Deployment history and blame

---

## v2.2 - Content Intelligence

**Focus**: AI-assisted content and security analysis

### Content Quality
- [ ] Content quality scoring
- [ ] SEO analysis integration
- [ ] Broken link detection
- [ ] Image optimization pipeline
- [ ] Accessibility audit (WCAG)

### Security Scanning
- [ ] Security content scanning (leaked secrets, PII)
- [ ] Malware signature detection in uploads
- [ ] Plugin/theme vulnerability scanning
- [ ] Dependency audit (CVE checking)

---

## v3.0 - Platform

**Focus**: Self-service platform for managed hosting

### Self-Service
- [ ] Web dashboard for fleet management
- [ ] Self-service site provisioning
- [ ] Customer portal
- [ ] API for third-party integrations

### Business
- [ ] Billing and metering integration
- [ ] White-label support
- [ ] Marketplace for approved plugins/themes
- [ ] Custom SLA management

### Enterprise
- [ ] Private cloud deployment
- [ ] Air-gapped operation mode
- [ ] Compliance reporting (SOC2, GDPR, HIPAA)
- [ ] Priority support integration
- [ ] Automated security patching

---

## Future Considerations

### Beyond WordPress
- [ ] Drupal support
- [ ] Static site generators (Hugo, Jekyll, Astro)
- [ ] Custom PHP applications
- [ ] Laravel/Symfony support
- [ ] Joomla adapter
- [ ] Magento e-commerce
- [ ] MediaWiki

### Infrastructure
- [ ] Kubernetes operator
- [ ] Nomad job specifications
- [ ] ARM64 support
- [ ] RISC-V exploration
- [ ] Unikernel deployment option

### Security Research
- [ ] Formal verification of sync protocol
- [ ] eBPF program verification
- [ ] Supply chain attestation (SLSA)
- [ ] Reproducible builds

---

## Version Support Policy

| Version | Support Status | Support Duration |
|---------|---------------|------------------|
| 1.x | LTS | 3 years from release |
| 2.x | Current | Until 3.0 + 1 year |

### Sunset Procedure

When a version reaches end-of-life:

1. **6 months before**: Deprecation warning in CLI
2. **3 months before**: Migration guide published
3. **At EOL**: Security fixes only
4. **6 months after EOL**: Version archived

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to propose features.

## Versioning

Wharf follows [Semantic Versioning](https://semver.org/):
- **MAJOR**: Breaking changes to sync protocol or config format
- **MINOR**: New features, backward compatible
- **PATCH**: Bug fixes, security patches

---

## Version History

| Version | Date | Status |
|---------|------|--------|
| 1.0.0 | 2025-11-27 | Current |
| 0.1.0 | 2025-11-26 | Development |

*This roadmap is subject to change based on community feedback and priorities.*
