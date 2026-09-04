---
title: Runbook: Handling Findings With No Available Fix
doc_type: runbook
authority: internal
trust_tag: Operational guidance
policy_version: 1.1
effective_date: 2026-01-15
control_family: vulnerability-management
visibility: internal
---

# Runbook: Handling Findings With No Available Fix

**Version 1.1 — effective 15 January 2026**

## 1. Confirm there is genuinely no fix

Check the vendor advisory, the distribution security tracker and the upstream
repository. A fix that exists but has not been packaged for the distribution
in use still counts as "no fix available" for the purposes of this runbook,
and the reason is recorded.

## 2. Apply mitigation in preference order

1. Remove or disable the vulnerable component.
2. Restrict network reachability to the affected service.
3. Apply a virtual patch at the WAF or API gateway.
4. Increase detection coverage and alert on exploitation indicators.

## 3. Record a risk acceptance

Follow the Risk Acceptance Standard Operating Procedure. The mitigation
applied in section 2 is the compensating control.

## 4. Set a review cadence

KEV-listed findings with no fix are reviewed weekly. All others are reviewed
monthly until a fix becomes available.
