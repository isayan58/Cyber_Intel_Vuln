"""Synthetic internal knowledge corpus.

The Vulnerability Management Standard is *generated from* ``risk.policy`` rather
than written by hand. That is the point: when RAG answers "policy requires
remediation within 7 days", the scorer used the same 7 because both read the
same table. Hand-written policy prose next to a hand-written scorer is the
most likely place for a system like this to quietly start lying.

Documents carry front-matter metadata (authority, policy_version,
effective_date, superseded_by) so the retriever can filter on policy version
and the evaluation suite can test the outdated-policy case.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

from vulnintel.config import get_settings
from vulnintel.logging_setup import get_logger
from vulnintel.risk.policy import (
    CRITICALITY_SCALE,
    DATA_CLASSIFICATION_SCALE,
    DEFAULT_WEIGHTS,
    SLA_RULES,
)

log = get_logger(__name__)

EFFECTIVE_DATE = date(2026, 1, 15)
SUPERSEDED_DATE = date(2024, 6, 1)


def _front_matter(**fields: object) -> str:
    lines = ["---"]
    for key, value in fields.items():
        if value is None:
            continue
        lines.append(f"{key}: {value}")
    lines.append("---")
    return "\n".join(lines)


def vulnerability_management_standard() -> str:
    """Generated from risk.policy.SLA_RULES — the SLA table cannot drift."""
    rows = "\n".join(
        f"| {rule.rule_id} | {rule.label} | {rule.condition} | {rule.days} days |"
        for rule in SLA_RULES
    )
    rationales = "\n".join(
        f"- **{rule.rule_id} — {rule.label}.** {rule.rationale}" for rule in SLA_RULES
    )
    weights = "\n".join(f"| {name} | {weight:.2f} |" for name, weight in DEFAULT_WEIGHTS.items())
    criticality = "\n".join(f"| {k} | {v:.2f} |" for k, v in CRITICALITY_SCALE.items())
    classification = "\n".join(f"| {k} | {v:.2f} |" for k, v in DATA_CLASSIFICATION_SCALE.items())

    return f"""{
        _front_matter(
            title="Vulnerability Management Standard",
            doc_type="standard",
            authority="internal",
            trust_tag="HIGH / internal authority",
            policy_version="3.2",
            effective_date=EFFECTIVE_DATE,
            control_family="vulnerability-management",
            visibility="internal",
        )
    }

# Vulnerability Management Standard

**Version 3.2 — effective {EFFECTIVE_DATE:%d %B %Y}**

## 1. Purpose and scope

This standard defines how the organisation identifies, prioritises and
remediates software vulnerabilities across all production, staging and
development environments. It applies to every asset recorded in the
configuration management database, including containerised workloads and
managed platform services.

## 2. Remediation service levels

Remediation clocks start at the point of detection, defined as the timestamp
recorded on the vulnerability finding. Rules are evaluated in order and the
first matching rule determines the applicable service level.

| Rule | Condition name | Condition | Remediation window |
|------|----------------|-----------|--------------------|
{rows}

### 2.1 Rationale for each service level

{rationales}

### 2.2 Precedence

Where more than one rule could apply, the **earliest matching rule wins**. In
particular, membership of the CISA Known Exploited Vulnerabilities catalogue
takes precedence over CVSS-derived severity bands. A vulnerability with a
CVSS base score of 6.5 that appears in the KEV catalogue is remediated on the
KEV timeline, not the medium-severity timeline.

## 3. Enterprise priority score

Prioritisation uses a documented, deterministic score. The score is advisory
for sequencing work; it does not replace the service levels in section 2.

Enterprise Priority Score = 100 x the weighted sum of the following normalised
components:

| Component | Weight |
|-----------|--------|
{weights}

### 3.1 Business criticality mapping

| Criticality | Value |
|-------------|-------|
{criticality}

Values are multiplied by an environment factor: production 1.00, staging 0.60,
development 0.35.

### 3.2 Data classification mapping

| Classification | Value |
|----------------|-------|
{classification}

### 3.3 Urgency adjustments

- An asset with no recorded patching activity for more than 180 days receives
  a 0.20 increase to the sensitivity component.
- An asset with no recorded patching activity for more than 90 days receives a
  0.10 increase.
- A finding with a documented compensating control receives a 0.15 reduction.

### 3.4 Score governance

The score is a project-specific prioritisation model. It is **not** an
industry standard and must not be presented as one. Every reported score must
be accompanied by its component breakdown. Automated systems may explain a
score but must not recalculate or adjust it.

## 4. Evidence requirements

A finding may only be reported as *affected* where the installed version has
been compared against the vulnerable version range by a deterministic version
comparison. Where the comparison cannot be performed — an unparseable version,
a wildcard CPE with no range bounds, or a missing package version — the finding
is recorded as **unknown** and escalated for manual confirmation. It must not
be reported as affected.

## 5. Exceptions

Any deviation from section 2 requires a documented risk acceptance under the
Risk Acceptance Standard Operating Procedure. Risk acceptances expire and do
not renew automatically.
"""


def patch_management_policy() -> str:
    return f"""{
        _front_matter(
            title="Patch Management Policy",
            doc_type="policy",
            authority="internal",
            trust_tag="HIGH / internal authority",
            policy_version="2.4",
            effective_date=EFFECTIVE_DATE,
            control_family="patch-management",
            visibility="internal",
        )
    }

# Patch Management Policy

**Version 2.4 — effective {EFFECTIVE_DATE:%d %B %Y}**

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
"""


def risk_acceptance_sop() -> str:
    return f"""{
        _front_matter(
            title="Risk Acceptance Standard Operating Procedure",
            doc_type="policy",
            authority="internal",
            trust_tag="HIGH / internal authority",
            policy_version="1.9",
            effective_date=EFFECTIVE_DATE,
            control_family="governance",
            visibility="internal",
        )
    }

# Risk Acceptance Standard Operating Procedure

**Version 1.9 — effective {EFFECTIVE_DATE:%d %B %Y}**

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
"""


def incident_escalation_standard() -> str:
    return f"""{
        _front_matter(
            title="Security Incident Escalation Standard",
            doc_type="standard",
            authority="internal",
            trust_tag="HIGH / internal authority",
            policy_version="2.1",
            effective_date=EFFECTIVE_DATE,
            control_family="incident-response",
            visibility="internal",
        )
    }

# Security Incident Escalation Standard

**Version 2.1 — effective {EFFECTIVE_DATE:%d %B %Y}**

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
"""


def secure_sdlc_standard() -> str:
    return f"""{
        _front_matter(
            title="Secure SDLC Standard",
            doc_type="standard",
            authority="internal",
            trust_tag="HIGH / internal authority",
            policy_version="1.6",
            effective_date=EFFECTIVE_DATE,
            control_family="secure-development",
            visibility="internal",
        )
    }

# Secure SDLC Standard

**Version 1.6 — effective {EFFECTIVE_DATE:%d %B %Y}**

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
"""


def application_criticality_definitions() -> str:
    return f"""{
        _front_matter(
            title="Application Criticality and Environment Definitions",
            doc_type="standard",
            authority="internal",
            trust_tag="HIGH / enterprise context",
            policy_version="1.3",
            effective_date=EFFECTIVE_DATE,
            control_family="asset-management",
            visibility="internal",
        )
    }

# Application Criticality and Environment Definitions

**Version 1.3 — effective {EFFECTIVE_DATE:%d %B %Y}**

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
"""


def remediation_runbook() -> str:
    return f"""{
        _front_matter(
            title="Runbook: Responding to a Newly Published Critical CVE",
            doc_type="runbook",
            authority="internal",
            trust_tag="Operational guidance",
            policy_version="1.4",
            effective_date=EFFECTIVE_DATE,
            control_family="vulnerability-management",
            visibility="internal",
        )
    }

# Runbook: Responding to a Newly Published Critical CVE

**Version 1.4 — effective {EFFECTIVE_DATE:%d %B %Y}**

## Step 1 — Establish the facts

Record the CVE identifier, the affected product and the affected version
ranges from the vendor advisory and NVD. Note both, and record any
disagreement between them rather than choosing one silently.

## Step 2 — Determine exposure

Query the inventory for the affected product. For each match, compare the
installed version against the vulnerable range using the version comparison
service. Record assets where the comparison is inconclusive separately; they
are neither affected nor safe until confirmed.

## Step 3 — Determine exploitation status

Check the KEV catalogue and the current EPSS score. A KEV listing moves the
finding to the SLA-1 or SLA-2 service level immediately.

## Step 4 — Decide the response

| Situation | Action |
|-----------|--------|
| KEV-listed and internet-facing | Emergency patch now; notify the CISO; consider taking the service offline if no patch exists |
| KEV-listed, internal only | Emergency patch within 7 days |
| Not KEV-listed, EPSS >= 0.10 | Schedule within 14 days |
| No fix available | Apply mitigation, open a risk acceptance, set a review date |

## Step 5 — Communicate

Notify affected application owners with: the finding, the fixed version, the
deadline, and the evidence. Include the score breakdown so the owner can see
why it was prioritised.

## Step 6 — Verify

Confirm remediation by rescan, not by change record. Close the finding only
after verification.
"""


def exception_handling_runbook() -> str:
    return f"""{
        _front_matter(
            title="Runbook: Handling Findings With No Available Fix",
            doc_type="runbook",
            authority="internal",
            trust_tag="Operational guidance",
            policy_version="1.1",
            effective_date=EFFECTIVE_DATE,
            control_family="vulnerability-management",
            visibility="internal",
        )
    }

# Runbook: Handling Findings With No Available Fix

**Version 1.1 — effective {EFFECTIVE_DATE:%d %B %Y}**

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
"""


def superseded_vulnerability_standard() -> str:
    """A deliberately outdated policy, retained for the retrieval evaluation.

    Design doc §8.4 asks for adversarial retrieval tests including outdated
    policy. This document exists so that test has something real to fail on:
    its numbers contradict the current standard, and a correct retriever must
    prefer version 3.2 and surface the conflict rather than average them.
    """
    return f"""{
        _front_matter(
            title="Vulnerability Management Standard (SUPERSEDED)",
            doc_type="standard",
            authority="internal",
            trust_tag="SUPERSEDED — retained for audit",
            policy_version="2.0",
            effective_date=SUPERSEDED_DATE,
            superseded_by="Vulnerability Management Standard v3.2",
            control_family="vulnerability-management",
            visibility="internal",
        )
    }

# Vulnerability Management Standard (SUPERSEDED)

**Version 2.0 — effective {SUPERSEDED_DATE:%d %B %Y}. Superseded by version 3.2.**

> This document is retained for audit purposes only. It must not be used to
> determine current remediation obligations.

## 2. Remediation service levels

| Severity | Remediation window |
|----------|--------------------|
| Critical | 14 days |
| High | 60 days |
| Medium | 120 days |
| Low | 365 days |

Version 2.0 made no distinction for known-exploited vulnerabilities and did
not reference EPSS. Both were introduced in version 3.0.
"""


def third_party_guidance() -> str:
    return f"""{
        _front_matter(
            title="Cloud Platform Hardening Guidance",
            doc_type="guidance",
            authority="internal",
            trust_tag="HIGH / enterprise context",
            policy_version="1.2",
            effective_date=EFFECTIVE_DATE,
            control_family="platform",
            visibility="internal",
        )
    }

# Cloud Platform Hardening Guidance

**Version 1.2 — effective {EFFECTIVE_DATE:%d %B %Y}**

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
"""


DOCUMENT_BUILDERS = {
    "vulnerability-management-standard.md": vulnerability_management_standard,
    "patch-management-policy.md": patch_management_policy,
    "risk-acceptance-sop.md": risk_acceptance_sop,
    "incident-escalation-standard.md": incident_escalation_standard,
    "secure-sdlc-standard.md": secure_sdlc_standard,
    "application-criticality-definitions.md": application_criticality_definitions,
    "runbook-critical-cve-response.md": remediation_runbook,
    "runbook-no-fix-available.md": exception_handling_runbook,
    "cloud-platform-hardening.md": third_party_guidance,
    "SUPERSEDED-vulnerability-management-standard-v2.md": superseded_vulnerability_standard,
}


def write_corpus(target: Path | None = None) -> list[Path]:
    """Write every synthetic internal document to knowledge_base/internal_synthetic."""
    target = target or (get_settings().knowledge_dir / "internal_synthetic")
    target.mkdir(parents=True, exist_ok=True)

    written: list[Path] = []
    for filename, builder in DOCUMENT_BUILDERS.items():
        path = target / filename
        path.write_text(builder().strip() + "\n", encoding="utf-8")
        written.append(path)

    log.info("wrote %d synthetic policy documents to %s", len(written), target)
    return written
