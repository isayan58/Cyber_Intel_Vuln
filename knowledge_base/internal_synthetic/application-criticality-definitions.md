---
title: Application Criticality and Environment Definitions
doc_type: standard
authority: internal
trust_tag: HIGH / enterprise context
policy_version: 1.3
effective_date: 2026-01-15
control_family: asset-management
visibility: internal
---

# Application Criticality and Environment Definitions

**Version 1.3 — effective 15 January 2026**

## 1. Application tiers

| Tier | Definition | Examples |
|------|------------|----------|
| Tier 1 | Revenue-critical or regulator-visible. Unavailability is a reportable event. | Payments, Mobile Banking API, Core Banking Ledger, Customer Identity, Fraud Detection |
| Tier 2 | Significant customer or operational impact; degraded service tolerable for hours. | Customer Portal, Partner Integrations, Data Platform, Notification Service |
| Tier 3 | Limited external impact; tolerable for a working day. | Marketing Site, Internal HR Tools, Reporting and BI |
| Tier 4 | Internal convenience only. | Developer Tooling |

## 2. Asset business criticality

Asset criticality is derived from the owning application tier and the
environment. Production Tier-1 assets are *critical*; production Tier-2 are
*high*; production Tier-3 are *medium*; everything else is *low* or *medium*
depending on tier.

## 3. Environment definitions

- **Production** — serves live customer or business traffic.
- **Staging** — pre-production, holds masked or synthetic data only.
- **Development** — engineer-controlled, must never hold production data.

## 4. Internet-facing definition

An asset is internet-facing when it is reachable from an untrusted network
without first traversing a VPN or a zero-trust proxy. Assets behind the
public-facing WAF are still classified as internet-facing.

## 5. Data classification

- **Restricted** — payment card data, credentials, full customer records.
- **Confidential** — internal financial data, partial customer records.
- **Internal** — operational data not intended for publication.
- **Public** — approved for publication.
