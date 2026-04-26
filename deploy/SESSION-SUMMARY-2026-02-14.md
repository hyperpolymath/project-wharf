# Project Wharf — Local Deployment Session Summary
<!-- SPDX-License-Identifier: PMPL-1.0-or-later -->

**Date:** 2026-02-14
**Status:** COMMITTED TO GITHUB. GitLab push pending (broken pack object).

---

## What Was Done

### Bug Fixes (3 files)

| File | Bug | Fix |
|------|-----|-----|
| `infra/containers/Containerfile.agent` | Wolfi doesn't have `musl-dev`, `cargo`, or `rustup` packages | Switched to glibc build: `rust pkgconf openssl-dev gcc glibc-dev`, removed musl target/RUSTFLAGS, build from `target/release/`, runtime `wolfi-base` |
| `Containerfile` (line 35) | yacht-agent stage uses `static` image but binary is glibc-linked → segfault | Changed to `cgr.dev/chainguard/wolfi-base:latest` |
| `adapters/wordpress-wharf/wharf-adapter.php` | Reads flat `$stats['queries_allowed']` but `/stats` returns nested `{"queries":{"allowed":N}}`. Also reads `moored`/`firewall_mode` from `/stats` but they're on `/status` | Rewrote `wharf_fetch_agent_stats()` to fetch both `/stats` and `/status`, maps nested JSON to flat format |

### New Files (4 files)

| File | Purpose |
|------|---------|
| `deploy/Containerfile.ols-local` | OLS 1.8.5 + lsphp83 with mysql/curl/intl/imagick/redis extensions |
| `deploy/compose.yaml` | 3-service podman compose: db (MariaDB 10.11), agent (yacht-agent), web (OLS) |
| `deploy/local-test.sh` | Automated: create dirs, download WP, fetch real salt keys, write wp-config.php (DB_HOST=agent:3306), copy adapter plugin, build containers, start stack, health check |
| `deploy/verify-sqli.sh` | 6 SQL injection tests via `podman exec` through agent proxy |

### Documentation Updated (8 files)

| File | Changes |
|------|---------|
| `CHANGELOG.adoc` | Added "Local Deployment Proof" section |
| `TOPOLOGY.md` | Added local deployment architecture diagram + `local-deploy` row in dashboard |
| `AI.a2ml` | Added "Local Deployment" section |
| `deploy/DEPLOY.adoc` | Added local dev instructions, architecture diagram, services table |
| `.machine_readable/STATE.scm` | Added `local-deployment-proof` milestone with 5 sub-milestones |
| `.machine_readable/ECOSYSTEM.scm` | Added `openlitespeed` and `mariadb` as related projects |
| `.machine_readable/META.scm` | Added 2 ADRs: `glibc-runtime-containers`, `ols-local-deployment` |
| `.gitignore` | Added `deploy/wharf-local/` |

### Verification Results

- **cargo test**: 63/63 passed (40 wharf-core + 19 wharf-cli + 4 yacht-agent)
- **Stack**: All 3 containers healthy, WordPress installation wizard served at :8080
- **Agent**: `/health` → OK, `/stats` → real counters (321 allowed, 3 blocked), `/status` → active
- **verify-sqli.sh**: 6/6 passed
  - SELECT → PASS (forwarded)
  - INSERT INTO wp_users → BLOCKED
  - DROP TABLE → BLOCKED
  - ALTER TABLE → BLOCKED
  - TRUNCATE TABLE → BLOCKED
  - UNION SELECT injection → BLOCKED

---

## Commit

```
ece13ac feat: local E2E deployment proof — WordPress behind yacht-agent SQL proxy
```

15 files changed, 578 insertions(+), 38 deletions(-)

**Pushed to:** GitHub ✅
**Pushed to:** GitLab ❌ (see below)

---

## Remaining: GitLab Push

**Two issues blocking GitLab push:**

### Issue 1: Diverged history
GitLab has 3 old MR-based commits not in GitHub's history (`64fc965`, `5827c3f`, `bf1aac3`). Needs force-push to overwrite with canonical GitHub history.

### Issue 2: `main` branch is protected + API token expired
- GitLab `main` branch is protected (no force push allowed)
- GitLab API token (`glpat-dYz2_j--...`) is **EXPIRED**
- SSH auth works but can't change branch protection via SSH
- `glab` CLI also uses the expired token

### Fix (manual steps required)

```bash
# Step 1: Refresh GitLab token
# Go to: https://gitlab.com/-/user_settings/personal_access_tokens
# Create new token with api + write_repository scopes
# Update ~/.netrc with new token

# Step 2: Unprotect main
GL_TOKEN="<new-token>"
PROJECT_ID=$(curl -sf --header "PRIVATE-TOKEN: $GL_TOKEN" \
  "https://gitlab.com/api/v4/projects?search=project-wharf&owned=true" | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['id'])")
curl --request DELETE --header "PRIVATE-TOKEN: $GL_TOKEN" \
  "https://gitlab.com/api/v4/projects/$PROJECT_ID/protected_branches/main"

# Step 3: Force push from clean clone (already at /tmp/wharf-push.git)
cd /tmp/wharf-push.git
git push --force git@gitlab.com:hyperpolymath/project-wharf.git main

# Step 4: Re-protect main
curl --request POST --header "PRIVATE-TOKEN: $GL_TOKEN" \
  "https://gitlab.com/api/v4/projects/$PROJECT_ID/protected_branches?name=main&push_access_level=40&merge_access_level=40"

# Step 5: Clean up
rm -rf /tmp/wharf-push.git
```

### Also fix the local repo's broken pack (optional)

The local `.git` has a broken pack object (`501faf18`) from the old GitLab fetch. Not urgent — local repo works fine for everything except `git gc`.

```bash
cd /var$REPOS_DIR/project-wharf
git remote remove gitlab
git remote add gitlab git@gitlab.com:hyperpolymath/project-wharf.git
# After GitLab is force-pushed with clean history:
git fetch gitlab
```

---

## How to Use the Local Stack

```bash
cd /var$REPOS_DIR/project-wharf/deploy

# Start everything (downloads WP, builds containers, starts stack)
bash local-test.sh

# WordPress setup wizard
# http://localhost:8080

# Agent API
curl http://localhost:9001/health
curl http://localhost:9001/stats

# Prove SQL injection blocked
bash verify-sqli.sh

# Tear down
podman compose down
rm -rf wharf-local/   # removes all runtime data
```

### Key Architecture Detail

```
Browser :8080 → OLS (port 80) → PHP/WordPress → agent:3306 (yacht-agent) → db:3306 (MariaDB)
                                                      ↑
                                             AST SQL parser (sqlparser 0.39)
                                             Blocks: INSERT wp_users, DROP, ALTER, TRUNCATE, UNION
```

WordPress `wp-config.php` has `DB_HOST = 'agent:3306'` — all SQL goes through the proxy.
MariaDB is NOT exposed to the host network.

---

## Next Steps (Future Sessions)

1. **GitLab push** — use the fix above
2. **Production VPS** — deploy to stamp-protocol.org with real TLS
3. **WordPress setup** — complete the install wizard, activate Wharf adapter plugin
4. **Bitbucket/Codeberg** — mirror when those forges are unblocked
