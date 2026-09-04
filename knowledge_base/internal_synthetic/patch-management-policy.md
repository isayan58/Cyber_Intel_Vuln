---
title: Patch Management Policy
doc_type: policy
authority: internal
trust_tag: HIGH / internal authority
policy_version: 2.4
effective_date: 2026-01-15
control_family: patch-management
visibility: internal
---

# Patch Management Policy

**Version 2.4 — effective 15 January 2026**

## 1. Patching cadence

| Environment | Routine cadence | Emergency change window |
|-------------|-----------------|-------------------------|
| Production | Monthly, second Tuesday | Any time, with CAB-on-call approval |
| Staging | Fortnightly | Any time |
| Development | Continuous | Not applicable |

## 2. Emergency patching

An emergency patch is authorised without waiting for the routine cadence when
any of the following holds:

1. The vulnerability appears in the CISA Known Exploited Vulnerabilities catalogue.
2. The EPSS probability is at or above 0.10 and the asset is internet-facing.
3. The vendor has published an advisory rated Critical for an internet-facing service.
4. The Security Operations Centre has observed exploitation attempts against the estate.

Emergency patches require a retrospective change record within two business
days. They do not require pre-approval from the Change Advisory Board.

## 3. Change freeze

A change freeze operates from 15 December to 5 January and during declared
peak trading events. Emergency patches under section 2 are **exempt** from the
freeze. Routine patching is deferred and the deferral is recorded.

## 4. Verification

Patch application must be verified by a follow-up scan within seven days. The
finding remains open until verification succeeds; a change record alone is not
evidence of remediation.

## 5. Rollback

Every emergency patch requires a documented rollback plan before deployment.
For containerised workloads, the previous image digest is retained for 30 days.
