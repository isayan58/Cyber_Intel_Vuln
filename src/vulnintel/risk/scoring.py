"""Deterministic enterprise priority scoring.

Design doc §11. The formula is explicitly a project-specific prioritisation
model, not an industry standard.

    score = 100 x (0.20*cvss_norm + 0.25*epss + 0.20*kev
                 + 0.15*criticality + 0.10*exposure + 0.10*sensitivity)

Two properties are load-bearing for the whole project:

  * The LLM never computes this. It reads ``finding_score`` rows and explains
    them; ``contributions`` is persisted so the explanation can be checked.
  * Components, weights and model version are stored alongside the result, so
    re-weighting is a diffable experiment and "why was A above B?" is a SELECT.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from typing import Any

from vulnintel.data.db import Database, get_db
from vulnintel.logging_setup import get_logger
from vulnintel.risk.policy import (
    CRITICALITY_SCALE,
    DATA_CLASSIFICATION_SCALE,
    DEFAULT_WEIGHTS,
    ENVIRONMENT_MULTIPLIER,
    MODEL_VERSION,
    SlaRule,
    priority_band,
    select_sla,
    validate_weights,
)

log = get_logger(__name__)


@dataclass
class ScoreInput:
    """Everything the formula consumes. No other state may influence the score."""

    finding_id: int
    cvss_base: float | None = None
    epss: float | None = None
    epss_percentile: float | None = None
    kev: bool = False
    business_criticality: str | None = None
    environment: str | None = None
    internet_facing: bool = False
    data_classification: str | None = None
    last_patch_date: date | None = None
    detected_at: datetime | None = None
    has_compensating_control: bool = False
    risk_accepted: bool = False


@dataclass
class ScoreResult:
    finding_id: int
    score: float
    components: dict[str, float]
    contributions: dict[str, float]
    weights: dict[str, float]
    model_version: str
    sla: SlaRule
    sla_due_date: date | None
    sla_breached: bool
    age_days: int | None
    band: str
    notes: list[str] = field(default_factory=list)

    def explain(self) -> str:
        """One-line human-readable breakdown, as required by §11."""
        parts = ", ".join(
            f"{name}={self.components[name]:.2f}x{self.weights[name]:.2f}"
            f"={self.contributions[name]:.1f}"
            for name in self.weights
        )
        return f"{self.score:.0f}/100 [{self.band}] = {parts}"

    def to_row(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "model_version": self.model_version,
            "score": self.score,
            "cvss_base": self.components.get("_cvss_base"),
            "cvss_norm": self.components["cvss"],
            "epss": self.components["epss"],
            "epss_percentile": self.components.get("_epss_percentile"),
            "kev_flag": int(self.components["kev"]),
            "criticality": self.components["criticality"],
            "exposure": int(self.components["exposure"]),
            "sensitivity": self.components["sensitivity"],
            "weights": json.dumps(self.weights),
            "contributions": json.dumps(
                {**self.contributions, "notes": self.notes, "band": self.band}
            ),
            "sla_days": self.sla.days,
            "sla_due_date": self.sla_due_date,
            "sla_breached": self.sla_breached,
            "age_days": self.age_days,
            "scored_at": datetime.now(UTC).replace(tzinfo=None),
        }


class RiskScorer:
    """Pure function object — same inputs always produce the same score."""

    def __init__(self, weights: dict[str, float] | None = None, today: date | None = None) -> None:
        self.weights = dict(weights or DEFAULT_WEIGHTS)
        validate_weights(self.weights)
        self.today = today or datetime.now(UTC).date()

    # -- components -----------------------------------------------------------

    def _cvss_component(self, value: float | None) -> float:
        if value is None:
            return 0.5  # neutral prior when severity is genuinely unknown
        return max(0.0, min(value, 10.0)) / 10.0

    def _epss_component(self, value: float | None) -> float:
        if value is None:
            return 0.0
        return max(0.0, min(value, 1.0))

    def _criticality_component(self, criticality: str | None, environment: str | None) -> float:
        base = CRITICALITY_SCALE.get((criticality or "").lower(), 0.45)
        multiplier = ENVIRONMENT_MULTIPLIER.get((environment or "").lower(), 0.6)
        return round(base * multiplier, 4)

    def _sensitivity_component(self, inputs: ScoreInput) -> tuple[float, list[str]]:
        """Data classification, patch age and compensating controls."""
        notes: list[str] = []
        sensitivity = DATA_CLASSIFICATION_SCALE.get(
            (inputs.data_classification or "").lower(), 0.45
        )

        if inputs.last_patch_date:
            stale_days = (self.today - inputs.last_patch_date).days
            if stale_days > 180:
                sensitivity = min(1.0, sensitivity + 0.20)
                notes.append(f"asset unpatched for {stale_days} days (+0.20 urgency)")
            elif stale_days > 90:
                sensitivity = min(1.0, sensitivity + 0.10)
                notes.append(f"asset unpatched for {stale_days} days (+0.10 urgency)")

        if inputs.has_compensating_control:
            sensitivity = max(0.0, sensitivity - 0.15)
            notes.append("compensating control recorded (-0.15 urgency)")

        return round(sensitivity, 4), notes

    # -- scoring --------------------------------------------------------------

    def score(self, inputs: ScoreInput) -> ScoreResult:
        sensitivity, notes = self._sensitivity_component(inputs)

        components = {
            "cvss": self._cvss_component(inputs.cvss_base),
            "epss": self._epss_component(inputs.epss),
            "kev": 1.0 if inputs.kev else 0.0,
            "criticality": self._criticality_component(
                inputs.business_criticality, inputs.environment
            ),
            "exposure": 1.0 if inputs.internet_facing else 0.0,
            "sensitivity": sensitivity,
        }

        contributions = {
            name: round(100.0 * components[name] * weight, 4)
            for name, weight in self.weights.items()
        }
        total = round(sum(contributions.values()), 2)

        if inputs.cvss_base is None:
            notes.append("CVSS unavailable; neutral 0.5 prior applied")
        if inputs.epss is None:
            notes.append("no EPSS score for this CVE")
        if inputs.risk_accepted:
            notes.append("an approved risk acceptance covers this finding")

        sla = select_sla(
            kev=inputs.kev,
            internet_facing=inputs.internet_facing,
            cvss_base=inputs.cvss_base,
            epss=inputs.epss,
            business_criticality=inputs.business_criticality,
            environment=inputs.environment,
        )

        detected = inputs.detected_at.date() if inputs.detected_at else None
        age_days = (self.today - detected).days if detected else None
        due_date = detected + timedelta(days=sla.days) if detected else None
        breached = bool(due_date and due_date < self.today)

        # Keep the raw inputs alongside the normalised ones for auditability.
        components["_cvss_base"] = inputs.cvss_base if inputs.cvss_base is not None else None
        components["_epss_percentile"] = inputs.epss_percentile

        return ScoreResult(
            finding_id=inputs.finding_id,
            score=total,
            components=components,
            contributions=contributions,
            weights=self.weights,
            model_version=MODEL_VERSION,
            sla=sla,
            sla_due_date=due_date,
            sla_breached=breached,
            age_days=age_days,
            band=priority_band(total),
            notes=notes,
        )


SCORE_INPUT_SQL = """
SELECT
    f.finding_id,
    f.detected_at,
    f.cve_id,
    f.status,
    a.business_criticality,
    a.environment,
    a.internet_facing,
    a.data_classification,
    a.last_patch_date,
    a.compensating_controls,
    eff.base_score            AS cvss_base,
    e.probability             AS epss,
    e.percentile              AS epss_percentile,
    CASE WHEN k.cve_id IS NULL THEN 0 ELSE 1 END AS kev_flag,
    CASE WHEN ra.acceptance_id IS NULL THEN 0 ELSE 1 END AS risk_accepted
FROM vulnerability_finding f
LEFT JOIN assets a           ON a.asset_id = f.asset_id
LEFT JOIN v_cve_cvss_effective eff ON eff.cve_id = f.cve_id
LEFT JOIN epss_current e     ON e.cve_id = f.cve_id
LEFT JOIN kev k              ON k.cve_id = f.cve_id AND k.valid_to IS NULL
LEFT JOIN risk_acceptances ra
       ON ra.finding_id = f.finding_id
      AND (ra.expiration_date IS NULL OR ra.expiration_date >= ?)
WHERE f.version_verdict = 'affected'
  AND f.status <> 'remediated'
"""


def score_all_findings(
    db: Database | None = None,
    weights: dict[str, float] | None = None,
    today: date | None = None,
) -> int:
    """Recompute ``finding_score`` for every open, affected finding."""
    db = db or get_db()
    scorer = RiskScorer(weights=weights, today=today)
    rows = db.query(SCORE_INPUT_SQL, [scorer.today])

    results: list[dict[str, Any]] = []
    for row in rows:
        inputs = ScoreInput(
            finding_id=int(row["finding_id"]),
            cvss_base=row.get("cvss_base"),
            epss=row.get("epss"),
            epss_percentile=row.get("epss_percentile"),
            kev=bool(row.get("kev_flag")),
            business_criticality=row.get("business_criticality"),
            environment=row.get("environment"),
            internet_facing=bool(row.get("internet_facing")),
            data_classification=row.get("data_classification"),
            last_patch_date=_as_date(row.get("last_patch_date")),
            detected_at=row.get("detected_at"),
            has_compensating_control=bool(row.get("compensating_controls")),
            risk_accepted=bool(row.get("risk_accepted")),
        )
        results.append(scorer.score(inputs).to_row())

    db.execute("DELETE FROM finding_score")
    written = db.insert_many("finding_score", results)
    log.info("scored %d findings with %s", written, MODEL_VERSION)
    return written


def _as_date(value: Any) -> date | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    try:
        return datetime.strptime(str(value)[:10], "%Y-%m-%d").date()
    except ValueError:
        return None
