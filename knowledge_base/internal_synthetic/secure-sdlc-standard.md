---
title: Secure SDLC Standard
doc_type: standard
authority: internal
trust_tag: HIGH / internal authority
policy_version: 1.6
effective_date: 2026-01-15
control_family: secure-development
visibility: internal
---

# Secure SDLC Standard

**Version 1.6 — effective 15 January 2026**

## 1. Dependency management

All services maintain a committed lockfile. Builds that cannot resolve a
lockfile fail. A software bill of materials is generated at build time and
published to the inventory service.

## 2. Build gates

| Gate | Condition | Action |
|------|-----------|--------|
| Critical dependency vulnerability with a fix available | CVSS >= 9.0 | Build fails |
| KEV-listed dependency vulnerability | Any severity | Build fails |
| High dependency vulnerability with a fix available | CVSS >= 7.0 | Build warns; blocks release after 14 days |
| No fix available | Any severity | Build warns; finding routed to risk acceptance |

## 3. Transitive dependencies

Transitive dependencies are in scope. Where a direct dependency pins a
vulnerable transitive package, the owning team either upgrades the direct
dependency or applies a documented override with an expiry date.

## 4. Base images

Container base images are rebuilt at least every 30 days. Images older than 90
days are blocked from production deployment.
