# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please report it responsibly.

### Reporting Channel

**DO NOT** open a public GitHub/GitLab issue for security vulnerabilities.

Instead, please report via:
- **Email**: security@hyperpolymath.net
- **Encrypted**: Use our PGP key (see `.well-known/security.txt`)

### Response SLA

| Severity | Acknowledgement | Resolution Target |
|----------|-----------------|-------------------|
| Critical | 24 hours        | 72 hours          |
| High     | 48 hours        | 1 week            |
| Medium   | 72 hours        | 2 weeks           |
| Low      | 1 week          | 1 month           |

### What to Include

Please include the following in your report:

1. **Description**: Clear description of the vulnerability
2. **Impact**: What could an attacker achieve?
3. **Reproduction**: Step-by-step instructions to reproduce
4. **Affected Components**: Which files/functions are affected?
5. **Suggested Fix**: If you have one (optional)

### What to Expect

1. **Acknowledgement**: We will confirm receipt within the SLA
2. **Assessment**: We will assess severity and impact
3. **Communication**: We will keep you informed of progress
4. **Fix**: We will develop and test a fix
5. **Disclosure**: We will coordinate disclosure with you
6. **Credit**: We will credit you (unless you prefer anonymity)

## Security Architecture

Wharf is designed with security as a foundational principle:

### Defense in Depth

1. **Database Proxy**: AST-based SQL filtering prevents injection at the wire protocol level
2. **Filesystem Immutability**: Read-only root with OverlayFS prevents code injection
3. **Header Airlock**: Strips dangerous HTTP headers, injects security headers
4. **Zero Trust Network**: Nebula mesh with certificate-based auth
5. **Hardware 2FA**: FIDO2/WebAuthn for authentication
6. **Post-Quantum Cryptography**: Ed448 + ML-DSA-87 hybrid signatures

### Cryptographic Primitives

| Primitive | Algorithm | Standard | Purpose |
|-----------|-----------|----------|---------|
| Hybrid Signatures | Ed448 + ML-DSA-87 (Dilithium5) | EdDSA + FIPS 204 | All mooring requests — both must verify |
| File Integrity | BLAKE3 | — | Filesystem manifest checksums |
| Provenance Hashing | SHAKE3-512 | FIPS 202 | Long-term provenance, KDF input |
| Symmetric Encryption | XChaCha20-Poly1305 | — | AEAD for secrets in transit |
| Key Derivation | HKDF-SHAKE512 | RFC 5869 | Per-session key derivation |
| Password Hashing | Argon2id (512 MiB, 8 iter, 4 lanes) | RFC 9106 | Stored key protection (Wharf only) |
| Random Generation | ChaCha20-DRBG (512-bit seed) | — | Key generation and nonces |

**Hybrid Signature Model**: Both Ed448 (classical) and ML-DSA-87 (post-quantum) signatures
must verify for any mooring operation. An attacker must break *both* algorithms to forge a signature.
This protects against both classical and quantum computing attacks.

**Note**: The `ed448-goldilocks` dependency is pre-release (v0.14.0-pre.10) and has not been
independently audited. Production deployments should await a stable, audited release.

### Threat Model

We assume:
- The live server (Yacht) is hostile territory
- Network is untrusted (including internal networks)
- Attackers may have application-level vulnerabilities

### Security Boundaries

| Component | Trust Level | Access |
|-----------|-------------|--------|
| Wharf Controller | High | Offline, hardware-secured |
| Yacht Agent | Medium | Limited, enforces policy |
| WordPress/CMS | Low | Sandboxed, read-only |
| Public Network | None | Zero Trust |

### Container Supply Chain

All container images use [Chainguard](https://www.chainguard.dev/) bases for provenance:

- **Build stage**: `cgr.dev/chainguard/wolfi-base:latest` (zero-CVE base)
- **Runtime (agent)**: `cgr.dev/chainguard/static:latest` (distroless)
- **Runtime (web)**: `cgr.dev/chainguard/nginx:latest`
- **Database**: `cgr.dev/chainguard/mariadb:latest`

Images are signed with `cerro-torre` (Ed25519), sealed with `selur`, and executed
via the `vordr` formally verified container runtime. Secrets are managed by `rokur`.

## Security Updates

Security updates are released as:
- **Patch versions** for fixes (e.g., 0.1.1)
- **Security advisories** via GitLab
- **Announcements** on our blog

Subscribe to security notifications:
- Watch the repository on GitLab
- Follow `@hyperpolymath` for announcements

## Secure Development

All contributors must:
- Sign commits with GPG
- Follow secure coding guidelines
- Pass security-focused code review
- Run `just audit` before submitting

## Compliance

This project adheres to:
- OWASP Security Guidelines
- CIS Benchmarks (where applicable)
- Rhodium Standard Repository (RSR) requirements
