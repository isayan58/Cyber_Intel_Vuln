---
title: Cloud Platform Hardening Guidance
doc_type: guidance
authority: internal
trust_tag: HIGH / enterprise context
policy_version: 1.2
effective_date: 2026-01-15
control_family: platform
visibility: internal
---

# Cloud Platform Hardening Guidance

**Version 1.2 — effective 15 January 2026**

## 1. Ingress

All internet-facing services terminate TLS at the edge proxy. Direct exposure
of application ports to the internet is prohibited. Exceptions require a
documented architecture review.

## 2. Segmentation

Production, staging and development run in separate accounts with no peering
between production and development. Data may not flow from production into
development without masking.

## 3. Managed service patching

For managed database and cache services, the platform team owns the engine
version. Application teams own the client library version. Findings against
the engine are routed to the platform team automatically.

## 4. Container runtime

Containers run with a read-only root filesystem and a non-root user unless a
documented exception exists. Runtime detection is deployed on every production
node.
