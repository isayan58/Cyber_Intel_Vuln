"""Risk-model evaluation.

Property and case tests on the deterministic layer. No model, no network, no
warehouse state — so this suite is fast, hermetic, and the one that must never
be allowed to fail.

The cases encode the design doc's §14.1 requirement directly: a high-CVSS
finding with low enterprise relevance must rank *below* a lower-CVSS finding
that is known-exploited on an exposed Tier-1 asset. That inversion is the
whole thesis of the project, so it is asserted rather than asserted about.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from vulnintel.config import get_settings
from vulnintel.logging_setup import get_logger
from vulnintel.risk.policy import DEFAULT_WEIGHTS, validate_weights
from vulnintel.risk.scoring import RiskScorer, ScoreInput
from vulnintel.risk.versions import Verdict, in_cpe_range, in_osv_range

log = get_logger(__name__)

DATASET = "risk.yaml"
TODAY = date(2026, 9, 4)


def load_dataset() -> dict[str, Any]:
    path = get_settings().evals_dir / "datasets" / DATASET
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def run(limit: int | None = None) -> dict[str, Any]:
    dataset = load_dataset()
    rows: list[dict[str, Any]] = []

    scores = _scoring_cases(dataset.get("scoring_cases", []), rows)
    _ordering_cases(dataset.get("scoring_cases", []), scores, rows)
    _version_cases(dataset.get("version_cases", []), rows)
    _cpe_cases(dataset.get("cpe_cases", []), rows)
    _property_cases(rows)

    passed = [r for r in rows if r["passed"]]
    return {
        "cases": rows,
        "columns": ["id", "kind", "expected", "actual", "passed"],
        "summary": {
            "cases": len(rows),
            "passed": len(passed),
            "failed": len(rows) - len(passed),
            "pass_rate": round(len(passed) / len(rows), 4) if rows else 0.0,
        },
        "passed": len(passed) == len(rows),
    }


# --------------------------------------------------------------------------


def _score_for(case: dict[str, Any]):
    inputs = case["inputs"]
    last_patch = None
    if inputs.get("last_patch_days_ago"):
        last_patch = TODAY - timedelta(days=int(inputs["last_patch_days_ago"]))

    return RiskScorer(today=TODAY).score(
        ScoreInput(
            finding_id=0,
            cvss_base=inputs.get("cvss_base"),
            epss=inputs.get("epss"),
            kev=bool(inputs.get("kev")),
            business_criticality=inputs.get("business_criticality"),
            environment=inputs.get("environment"),
            internet_facing=bool(inputs.get("internet_facing")),
            data_classification=inputs.get("data_classification"),
            last_patch_date=last_patch,
            has_compensating_control=bool(inputs.get("has_compensating_control")),
            detected_at=datetime(2026, 9, 1, tzinfo=UTC).replace(tzinfo=None),
        )
    )


def _scoring_cases(cases: list[dict[str, Any]], rows: list[dict[str, Any]]) -> dict[str, float]:
    scores: dict[str, float] = {}

    for case in cases:
        result = _score_for(case)
        scores[case["id"]] = result.score

        if "expect_score_between" in case:
            low, high = case["expect_score_between"]
            rows.append(_row(case["id"], "score-range", f"{low}–{high}",
                             f"{result.score:.1f}", low <= result.score <= high))

        if "expect_band" in case:
            expected = case["expect_band"]
            expected = expected if isinstance(expected, list) else [expected]
            rows.append(_row(case["id"], "band", "/".join(expected),
                             result.band, result.band in expected))

        if "expect_sla_days" in case:
            rows.append(_row(case["id"], "sla-days", case["expect_sla_days"],
                             result.sla.days, result.sla.days == case["expect_sla_days"]))

        if "expect_sla_rule" in case:
            rows.append(_row(case["id"], "sla-rule", case["expect_sla_rule"],
                             result.sla.rule_id, result.sla.rule_id == case["expect_sla_rule"]))

        if "expect_note_contains" in case:
            needle = case["expect_note_contains"].lower()
            found = any(needle in note.lower() for note in result.notes)
            rows.append(_row(case["id"], "note", needle,
                             "; ".join(result.notes)[:50] or "(none)", found))

    return scores


def _ordering_cases(
    cases: list[dict[str, Any]], scores: dict[str, float], rows: list[dict[str, Any]]
) -> None:
    """The inversion that justifies the whole enterprise-context layer."""
    for case in cases:
        target = case.get("must_outrank")
        if not target:
            continue
        mine, theirs = scores.get(case["id"], 0), scores.get(target, 0)
        rows.append(
            _row(
                f"{case['id']}>{target}",
                "ordering",
                f"{case['id']} above {target}",
                f"{mine:.1f} vs {theirs:.1f}",
                mine > theirs,
            )
        )


def _version_cases(cases: list[dict[str, Any]], rows: list[dict[str, Any]]) -> None:
    for case in cases:
        result = in_osv_range(
            case["version"],
            introduced=case.get("introduced"),
            fixed=case.get("fixed"),
            last_affected=case.get("last_affected"),
            ecosystem=case.get("ecosystem"),
        )
        rows.append(_row(case["id"], "osv-range", case["expect"],
                         result.verdict.value, result.verdict.value == case["expect"]))


def _cpe_cases(cases: list[dict[str, Any]], rows: list[dict[str, Any]]) -> None:
    for case in cases:
        result = in_cpe_range(
            case["version"],
            version_start_including=case.get("start_including"),
            version_start_excluding=case.get("start_excluding"),
            version_end_including=case.get("end_including"),
            version_end_excluding=case.get("end_excluding"),
        )
        rows.append(_row(case["id"], "cpe-range", case["expect"],
                         result.verdict.value, result.verdict.value == case["expect"]))


def _property_cases(rows: list[dict[str, Any]]) -> None:
    """Invariants that must hold for any inputs."""

    # 1. Weights sum to exactly 1.0.
    try:
        validate_weights(DEFAULT_WEIGHTS)
        ok, actual = True, f"{sum(DEFAULT_WEIGHTS.values()):.6f}"
    except ValueError as exc:
        ok, actual = False, str(exc)
    rows.append(_row("weights-sum-to-one", "property", "1.0", actual, ok))

    # 2. Scoring is reproducible — same inputs, same score, every time.
    sample = ScoreInput(
        finding_id=1, cvss_base=7.7, epss=0.31, kev=True,
        business_criticality="high", environment="production",
        internet_facing=True, data_classification="confidential",
    )
    values = {RiskScorer(today=TODAY).score(sample).score for _ in range(25)}
    rows.append(_row("score-reproducible", "property", "1 distinct value",
                     f"{len(values)} distinct", len(values) == 1))

    # 3. Monotonic in CVSS: raising severity alone never lowers the score.
    scorer = RiskScorer(today=TODAY)
    series = [
        scorer.score(
            ScoreInput(finding_id=1, cvss_base=cvss, epss=0.1, kev=False,
                       business_criticality="high", environment="production")
        ).score
        for cvss in (2.0, 5.0, 7.5, 9.8)
    ]
    rows.append(_row("monotonic-in-cvss", "property", "non-decreasing",
                     " ≤ ".join(f"{s:.1f}" for s in series),
                     all(a <= b for a, b in zip(series, series[1:], strict=False))))

    # 4. Monotonic in EPSS.
    series = [
        scorer.score(
            ScoreInput(finding_id=1, cvss_base=7.0, epss=epss, kev=False,
                       business_criticality="high", environment="production")
        ).score
        for epss in (0.0, 0.1, 0.5, 0.99)
    ]
    rows.append(_row("monotonic-in-epss", "property", "non-decreasing",
                     " ≤ ".join(f"{s:.1f}" for s in series),
                     all(a <= b for a, b in zip(series, series[1:], strict=False))))

    # 5. KEV always raises the score, never lowers it.
    base = ScoreInput(finding_id=1, cvss_base=6.0, epss=0.05, kev=False,
                      business_criticality="medium", environment="production")
    with_kev = ScoreInput(**{**base.__dict__, "kev": True})
    without = scorer.score(base).score
    withk = scorer.score(with_kev).score
    rows.append(_row("kev-raises-score", "property", "kev ≥ no-kev",
                     f"{withk:.1f} vs {without:.1f}", withk > without))

    # 6. Bounded to 0–100 across the extremes.
    extremes = [
        ScoreInput(finding_id=1, cvss_base=0.0, epss=0.0, kev=False,
                   business_criticality="low", environment="development",
                   data_classification="public"),
        ScoreInput(finding_id=1, cvss_base=10.0, epss=1.0, kev=True,
                   business_criticality="critical", environment="production",
                   internet_facing=True, data_classification="restricted"),
    ]
    values = [scorer.score(e).score for e in extremes]
    rows.append(_row("score-bounded", "property", "0 ≤ s ≤ 100",
                     " / ".join(f"{v:.1f}" for v in values),
                     all(0.0 <= v <= 100.0 for v in values)))

    # 7. An unparseable version is never reported as affected.
    verdicts = [
        in_osv_range("not-a-version", introduced="0", fixed="1.0", ecosystem="PyPI").verdict,
        in_cpe_range("nightly", version_end_excluding="2.0").verdict,
    ]
    rows.append(_row("unparseable-never-affected", "property", "never affected",
                     "/".join(v.value for v in verdicts),
                     all(v is not Verdict.AFFECTED for v in verdicts)))


def _row(case_id: str, kind: str, expected: Any, actual: Any, passed: bool) -> dict[str, Any]:
    return {"id": case_id, "kind": kind, "expected": expected, "actual": actual, "passed": passed}
