---
title: Security Incident Escalation Standard
doc_type: standard
authority: internal
trust_tag: HIGH / internal authority
policy_version: 2.1
effective_date: 2026-01-15
control_family: incident-response
visibility: internal
---

# Security Incident Escalation Standard

**Version 2.1 — effective 15 January 2026**

## 1. Severity definitions

| Severity | Definition | Initial response | Executive notification |
|----------|------------|------------------|------------------------|
| SEV-1 | Confirmed exploitation of a production system, or confirmed data exfiltration | 15 minutes | CTO and CISO immediately |
| SEV-2 | Credible exploitation attempt against an internet-facing production asset | 1 hour | CISO within 2 hours |
| SEV-3 | KEV-listed vulnerability confirmed present on a production asset | 4 hours | Security Manager, daily digest |
| SEV-4 | All other confirmed vulnerabilities | Next business day | Weekly report |

## 2. Escalation to the CTO

The CTO is notified directly for any SEV-1, and for any SEV-2 that remains
unresolved after four hours. The weekly risk brief additionally summarises the
five highest-priority open issues.

## 3. Content of an executive notification

An executive notification states: what is affected, whether exploitation has
been observed, the business services at risk, what has already been done, and
what decision is being requested. Technical detail belongs in the appendix.

## 4. Regulatory reporting

Where a SEV-1 involves personal data, the Data Protection Officer is engaged
within one hour to assess notification obligations.
