# Project Wharf Roadmap

This document outlines the planned development roadmap for Project Wharf.

## Vision

Make CMS security as reliable as containerized infrastructure by separating
administration from runtime.

## Current Status: v0.1.0 (Foundation)

✅ Completed:
- Core architecture design
- Rust workspace structure
- DNS zone templates
- Nickel policy schemas
- CMS adapter stubs

## Roadmap

### v0.2.0 - Core Functionality (Q1 2026)

**Database Proxy**
- [ ] MySQL/MariaDB protocol implementation
- [ ] AST-based query filtering (production-ready)
- [ ] Policy hot-reloading
- [ ] Query logging and auditing

**Filesystem Monitor**
- [ ] BLAKE3 integrity checking
- [ ] OverlayFS integration
- [ ] Real-time change detection
- [ ] Automatic rollback on tampering

**Testing**
- [ ] Unit test coverage >80%
- [ ] Integration test suite
- [ ] Security fuzzing

### v0.3.0 - Networking (Q2 2026)

**Nebula Integration**
- [ ] Certificate generation CLI
- [ ] Automatic mesh discovery
- [ ] Firewall rule compilation
- [ ] Health monitoring

**HTTP Airlock**
- [ ] Header sanitization proxy
- [ ] CSP injection
- [ ] Request logging
- [ ] Rate limiting

### v0.4.0 - Authentication (Q3 2026)

**FIDO2/WebAuthn**
- [ ] Hardware key registration
- [ ] Challenge-response authentication
- [ ] Session management
- [ ] Emergency recovery

**Mooring Protocol**
- [ ] Secure state synchronization
- [ ] Incremental updates
- [ ] Conflict resolution
- [ ] Audit logging

### v0.5.0 - CMS Adapters (Q4 2026)

**WordPress**
- [ ] Production-ready db.php
- [ ] wp-config.php hardening
- [ ] Plugin compatibility layer
- [ ] WooCommerce support

**Drupal**
- [ ] Settings.php integration
- [ ] Drush compatibility
- [ ] Config sync support

**Others**
- [ ] Joomla adapter
- [ ] Moodle adapter
- [ ] Generic LAMP adapter

### v1.0.0 - Production Ready (Q1 2027)

**Stability**
- [ ] Security audit (third-party)
- [ ] Performance benchmarks
- [ ] Documentation complete
- [ ] Migration guides

**Operations**
- [ ] Monitoring integration (Prometheus)
- [ ] Alerting configuration
- [ ] Backup/restore procedures
- [ ] Disaster recovery

## Future Considerations

### Post-1.0 Features

- **eBPF Integration**: Kernel-level packet filtering
- **WASM Plugins**: Extensible policy engine
- **Multi-tenant**: Manage multiple fleets
- **GUI**: Web-based Wharf interface
- **Mobile**: iOS/Android mooring apps

### Platform Expansion

- **Magento**: E-commerce adapter
- **Ghost**: Publishing platform
- **Discourse**: Forum adapter
- **MediaWiki**: Wiki adapter

### Integration

- **Cloudflare**: CDN integration
- **Let's Encrypt**: Automatic certificates
- **Grafana**: Dashboard templates
- **PagerDuty**: Alerting integration

## End-of-Life Planning

### Version Support Policy

| Version | Support Status | End of Support |
|---------|---------------|----------------|
| 0.x | Development | Until 1.0 release |
| 1.x | LTS | 1.0 + 3 years |

### Sunset Procedure

When a version reaches end-of-life:

1. **6 months before**: Deprecation warning in CLI
2. **3 months before**: Migration guide published
3. **At EOL**: Security fixes only
4. **6 months after EOL**: Version archived

### Succession Planning

If the project is no longer maintained:

1. Repository transferred to Software Freedom Conservancy
2. Community fork encouraged
3. All documentation archived
4. Security contacts updated

## Contributing to the Roadmap

We welcome input on the roadmap:

1. Open a GitLab Issue with `roadmap` label
2. Describe the feature/change
3. Explain the use case
4. Discuss in community meeting

## Version History

| Version | Date | Status |
|---------|------|--------|
| 0.1.0 | 2025-11-26 | Current |

---

*This roadmap is subject to change based on community feedback and priorities.*
