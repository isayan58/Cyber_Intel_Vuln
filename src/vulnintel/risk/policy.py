"""Remediation policy as data.

This module is the single source of truth for the SLA rules. Two consumers
read it:

  * ``risk.scoring`` — to compute ``sla_days`` / ``sla_due_date`` / ``sla_breached``
  * ``rag.corpus``   — to *generate* the Vulnerability Management Standard prose

That matters because the platform's most embarrassing possible failure is
telling an analyst "policy requires 7 days" while the scorer used 30. Deriving
both from one table makes drift impossible rather than merely unlikely.
"""

from __future__ import annotations

from dataclasses import dataclass

MODEL_VERSION = "enterprise-priority-v1"


@dataclass(frozen=True)
class SlaRule:
    rule_id: str
    label: str
    days: int
    condition: str
    rationale: str


# Evaluated top to bottom; the first match wins.
SLA_RULES: tuple[SlaRule, ...] = (
    SlaRule(
        rule_id="SLA-1",
        label="Actively exploited, internet-facing",
        days=3,
        condition="KEV listed AND the affected asset is internet-facing",
        rationale=(
            "A vulnerability with confirmed in-the-wild exploitation on an externally "
            "reachable asset is the highest-urgency case the standard recognises."
        ),
    ),
    SlaRule(
        rule_id="SLA-2",
        label="Actively exploited",
        days=7,
        condition="KEV listed (any environment)",
        rationale=(
            "CISA KEV membership is treated as authoritative evidence of exploitation "
            "and overrides CVSS-derived severity bands."
        ),
    ),
    SlaRule(
        rule_id="SLA-3",
        label="Critical severity on a Tier-1 production asset",
        days=7,
        condition="CVSS base >= 9.0 AND business criticality is critical AND environment is production",
        rationale="Critical technical severity combined with maximum business impact.",
    ),
    SlaRule(
        rule_id="SLA-4",
        label="High likelihood of exploitation",
        days=14,
        condition="EPSS probability >= 0.10",
        rationale=(
            "An EPSS probability at or above 10% indicates materially elevated "
            "near-term exploitation likelihood."
        ),
    ),
    SlaRule(
        rule_id="SLA-5",
        label="Critical severity",
        days=30,
        condition="CVSS base >= 9.0",
        rationale="Standard critical-severity remediation window.",
    ),
    SlaRule(
        rule_id="SLA-6",
        label="High severity",
        days=30,
        condition="CVSS base >= 7.0",
        rationale="Standard high-severity remediation window.",
    ),
    SlaRule(
        rule_id="SLA-7",
        label="Medium severity",
        days=90,
        condition="CVSS base >= 4.0",
        rationale="Standard medium-severity remediation window.",
    ),
    SlaRule(
        rule_id="SLA-8",
        label="Low severity",
        days=180,
        condition="All remaining findings",
        rationale="Routine hygiene window; may be batched into scheduled maintenance.",
    ),
)


# Score weights. Sum to 1.0 and are checked by a unit test.
DEFAULT_WEIGHTS: dict[str, float] = {
    "cvss": 0.20,
    "epss": 0.25,
    "kev": 0.20,
    "criticality": 0.15,
    "exposure": 0.10,
    "sensitivity": 0.10,
}

CRITICALITY_SCALE: dict[str, float] = {
    "critical": 1.0,
    "high": 0.75,
    "medium": 0.45,
    "low": 0.2,
}

DATA_CLASSIFICATION_SCALE: dict[str, float] = {
    "restricted": 1.0,
    "confidential": 0.75,
    "internal": 0.45,
    "public": 0.15,
}

ENVIRONMENT_MULTIPLIER: dict[str, float] = {
    "production": 1.0,
    "staging": 0.6,
    "development": 0.35,
}

# Score -> priority band, used for the executive view.
PRIORITY_BANDS: tuple[tuple[float, str], ...] = (
    (80.0, "P1"),
    (60.0, "P2"),
    (40.0, "P3"),
    (0.0, "P4"),
)


def select_sla(
    *,
    kev: bool,
    internet_facing: bool,
    cvss_base: float | None,
    epss: float | None,
    business_criticality: str | None,
    environment: str | None,
) -> SlaRule:
    """First matching rule wins. Always returns a rule."""
    cvss = cvss_base or 0.0
    probability = epss or 0.0
    criticality = (business_criticality or "").lower()
    env = (environment or "").lower()

    if kev and internet_facing:
        return SLA_RULES[0]
    if kev:
        return SLA_RULES[1]
    if cvss >= 9.0 and criticality == "critical" and env == "production":
        return SLA_RULES[2]
    if probability >= 0.10:
        return SLA_RULES[3]
    if cvss >= 9.0:
        return SLA_RULES[4]
    if cvss >= 7.0:
        return SLA_RULES[5]
    if cvss >= 4.0:
        return SLA_RULES[6]
    return SLA_RULES[7]


def priority_band(score: float) -> str:
    for threshold, band in PRIORITY_BANDS:
        if score >= threshold:
            return band
    return "P4"


def validate_weights(weights: dict[str, float]) -> None:
    total = sum(weights.values())
    if abs(total - 1.0) > 1e-9:
        raise ValueError(f"Risk weights must sum to 1.0, got {total}")
    missing = set(DEFAULT_WEIGHTS) - set(weights)
    if missing:
        raise ValueError(f"Missing risk weight components: {sorted(missing)}")
