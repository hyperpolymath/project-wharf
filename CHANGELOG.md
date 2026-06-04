<!--
SPDX-License-Identifier: MPL-2.0
Copyright (c) Jonathan D.A. Jewell <j.d.a.jewell@open.ac.uk>
-->
# Changelog

All notable changes to `project-wharf` will be documented in this file.

This file is generated from conventional commits by the
[`changelog-reusable.yml`](https://github.com/hyperpolymath/standards/blob/main/.github/workflows/changelog-reusable.yml)
workflow (`hyperpolymath/standards#206`). Adopt the workflow in this repo's CI to keep this file in sync automatically — see
[`templates/cliff.toml`](https://github.com/hyperpolymath/standards/blob/main/templates/cliff.toml)
for the canonical config.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- feat(snapshot): implement create_snapshot / restore over StateConfig contract
- feat(core+bin): adopt WP-edition source — mooring client, integrity updates, config layer
- feat(deploy): containerization + WP-specific deploy + config examples
- feat(adapters): add WordPress integration adapter
- feat(workspace): add xtask + fuzz + ClusterFuzzLite from WP-edition fork
- feat: Add remote integrity verification and eBPF XDP loader
- feat: Release v1.0.0 - Production-ready Sovereign Web Hypervisor
- feat: Implement v1.0 core functionality - sync, integrity, and fleet management
- feat: Add Rust eBPF firewall, Wolfi containers, and expanded CLI
- feat: Add RSR (Rhodium Standard Repository) compliance

### Fixed

- fix(licence): #3 Tranche 1 — clear scaffold-placeholder leak (project-wharf) (#28)
- fix(ci): sync hypatia-scan.yml to canonical (#26)
- fix(ci): rsr-antipattern.yml duplicate heredoc (#25)
- fix: Restore original README content
- fix: Make containers buildable and add smoke test

### Documentation

- docs(flake): annotate KEEP+DEP rationale (standards#102) (#30)
- docs(readme): add SPDX header and/or standard badges
- docs: Update roadmap for v1.0+ with detailed version plans

### CI

- ci(antipattern): fix top-level dir + benchmark/lsp filename matching (#20)
- ci(antipattern): TS check reads .claude/CLAUDE.md exemption table (#19)
- ci(antipattern): broaden TS allowlist (cli, mod.ts, lsp-server, *vscode*, deno-*) (#18)
- ci(antipattern): allowlist legit TS bridge/adapter paths (#17)

## Pre-history

Prior commits to this file's introduction are recorded in git history but not formally classified into Keep-a-Changelog sections. To backfill, run `git cliff -o CHANGELOG.md` locally using the canonical [`cliff.toml`](https://github.com/hyperpolymath/standards/blob/main/templates/cliff.toml) — this is one-shot mechanical work.

---

<!-- This file was seeded by the 2026-05-26 estate tech-debt audit follow-up (Row-2 Phase 3); see [`hyperpolymath/standards/docs/audits/2026-05-26-estate-documentation-debt.md`](https://github.com/hyperpolymath/standards/blob/main/docs/audits/2026-05-26-estate-documentation-debt.md). -->
