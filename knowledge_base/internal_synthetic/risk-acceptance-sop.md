---
title: Risk Acceptance Standard Operating Procedure
doc_type: policy
authority: internal
trust_tag: HIGH / internal authority
policy_version: 1.9
effective_date: 2026-01-15
control_family: governance
visibility: internal
---

# Risk Acceptance Standard Operating Procedure

**Version 1.9 — effective 15 January 2026**

## 1. When a risk acceptance is required

A risk acceptance is required whenever a finding will remain open beyond the
service level defined in the Vulnerability Management Standard section 2.

## 2. Approval authority

| Finding profile | Approver |
|-----------------|----------|
| KEV-listed, internet-facing | Chief Information Security Officer only |
| KEV-listed, internal | Head of Security Operations |
| Enterprise priority score >= 80 | Head of Security Operations |
| Enterprise priority score 60-79 | Application owner and Security Manager jointly |
| Enterprise priority score < 60 | Application owner |

A risk acceptance for a KEV-listed vulnerability on an internet-facing asset
may not be delegated under any circumstances.

## 3. Mandatory content

Every risk acceptance records the business justification, the compensating
control, the named approver, the approval date and an explicit expiry date.

## 4. Duration

The maximum initial duration is 90 days for findings with a priority score at
or above 80, and 180 days otherwise. Acceptances do not auto-renew. An expired
acceptance returns the finding to its original service level immediately, and
the remediation clock is treated as never having stopped.

## 5. Review

The Security Manager reviews all open risk acceptances monthly. Any acceptance
whose compensating control has lapsed is revoked immediately.
