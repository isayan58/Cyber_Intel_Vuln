"""Deterministic risk logic: version comparison, matching, scoring, policy."""

from vulnintel.risk.matching import FindingMatcher, build_cpe23, build_purl
from vulnintel.risk.policy import DEFAULT_WEIGHTS, MODEL_VERSION, SLA_RULES, select_sla
from vulnintel.risk.scoring import RiskScorer, ScoreInput, ScoreResult, score_all_findings
from vulnintel.risk.versions import Verdict, compare, in_cpe_range, in_osv_range

__all__ = [
    "DEFAULT_WEIGHTS",
    "MODEL_VERSION",
    "SLA_RULES",
    "FindingMatcher",
    "RiskScorer",
    "ScoreInput",
    "ScoreResult",
    "Verdict",
    "build_cpe23",
    "build_purl",
    "compare",
    "in_cpe_range",
    "in_osv_range",
    "score_all_findings",
    "select_sla",
]
