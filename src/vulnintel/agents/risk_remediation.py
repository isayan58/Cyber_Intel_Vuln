"""Agent 6 — Risk & Remediation.

Calls the deterministic ranking tools, then asks the model to turn the stored
score breakdown into a plan. The scores it passes in are the scores that come
out: ``verify_no_mutation`` re-checks the numbers the model echoed against the
stored ones, and any drift is recorded rather than accepted.
"""

from __future__ import annotations

import re
from typing import Any

from vulnintel.agents.base import Agent, AgentResult, as_json
from vulnintel.agents.state import GraphState
from vulnintel.logging_setup import get_logger

log = get_logger(__name__)


class RiskRemediationAgent(Agent):
    name = "risk_remediation"
    prompt_name = "risk_remediation"

    def gather(self, state: GraphState) -> dict[str, Any]:
        entities = state.get("entities") or {}
        intent = state.get("intent", "general")
        limit = state.get("result_limit", 5)

        if intent == "patch_queue":
            queue = self.tools.call("patch_queue", capacity=max(limit, 20))
            findings = queue["queue"]
            ranking = {"mode": "patch_queue", "count": len(findings), "findings": findings}
        elif entities.get("cve_ids"):
            findings = []
            for cve_id in entities["cve_ids"][:10]:
                result = self.tools.call("rank_findings", cve_id=cve_id, limit=limit)
                findings.extend(result["findings"])
            ranking = {"mode": "by_cve_filter", "count": len(findings), "findings": findings}
            queue = None
        elif entities.get("application_names"):
            findings = []
            for name in entities["application_names"][:5]:
                result = self.tools.call("rank_findings", application_name=name, limit=limit)
                findings.extend(result["findings"])
            ranking = {"mode": "by_application", "count": len(findings), "findings": findings}
            queue = None
        else:
            # Executive framing: one row per CVE, since an executive cares
            # about issues, not about 400 instances of the same issue.
            group = state.get("response_mode") == "executive" or intent == "executive_brief"
            ranking = self.tools.call("rank_findings", limit=limit, group_by_cve=group)
            findings = ranking["findings"]
            queue = None

        explanations = {}
        for finding in findings[: min(limit, 10)]:
            # Grouped rows have no finding_id of their own; they carry an
            # exemplar so the score breakdown is always obtainable.
            finding_id = finding.get("finding_id") or finding.get("exemplar_finding_id")
            if finding_id is not None:
                key = str(finding.get("cve_id") or finding_id)
                explanations[key] = self.tools.call(
                    "explain_score", finding_id=int(finding_id)
                )

        return {
            "ranking_mode": ranking.get("mode"),
            "findings": findings,
            "score_explanations": explanations,
            "portfolio": self.tools.call("portfolio_summary"),
            "patch_queue": queue,
            "skip_llm": not findings,
        }

    def interpret(self, state: GraphState, gathered: dict[str, Any]) -> dict[str, Any]:
        result = AgentResult(agent=self.name)
        evidence = state.get("evidence") or {}

        interpretation = self._ask_structured(
            result,
            question=state.get("question", ""),
            response_mode=state.get("response_mode", "analyst"),
            scored_findings=as_json(
                {
                    "findings": gathered.get("findings"),
                    "score_explanations": gathered.get("score_explanations"),
                    "portfolio": gathered.get("portfolio"),
                },
                limit=14000,
            ),
            asset_context=as_json(
                (evidence.get("asset_exposure") or {}).get("interpretation")
                or (evidence.get("asset_exposure") or {}).get("aggregates"),
                limit=3500,
            ),
            vulnerability_context=as_json(
                (evidence.get("vulnerability_intel") or {}).get("interpretation"), limit=6000
            ),
            threat_context=as_json(
                (evidence.get("threat_intel") or {}).get("interpretation")
                or (evidence.get("threat_intel") or {}).get("signals_summary"),
                limit=3500,
            ),
            policy_context=as_json(
                {
                    "obligations": (evidence.get("policy_rag") or {})
                    .get("interpretation", {})
                    .get("obligations"),
                    "sla_rules": (evidence.get("policy_rag") or {}).get("sla_rules"),
                    "conflicts": (evidence.get("policy_rag") or {}).get("conflicts"),
                },
                limit=5000,
            ),
        )

        drift = verify_no_mutation(interpretation, gathered.get("findings", []))
        if drift:
            log.warning("risk_remediation: %d score value(s) in the plan are not stored values", len(drift))
            interpretation["score_drift_detected"] = drift

        self._last_usage = result.usage
        self._last_prompt_version = result.prompt_version
        return interpretation

    def run(self, state: GraphState) -> AgentResult:
        result = super().run(state)
        result.prompt_version = getattr(self, "_last_prompt_version", None)
        result.usage = getattr(self, "_last_usage", {})
        result.span.update({
            "input_tokens": result.usage.get("input_tokens"),
            "output_tokens": result.usage.get("output_tokens"),
            "tier": result.usage.get("tier"),
        })
        return result


SCORE_PATTERN = re.compile(r"\b(\d{1,3}(?:\.\d+)?)\s*/\s*100\b")


def verify_no_mutation(
    interpretation: dict[str, Any], findings: list[dict[str, Any]]
) -> list[str]:
    """Check that any ``NN/100`` in the plan matches a stored score.

    The prompt forbids recomputing scores. This checks rather than trusts —
    which is the whole difference between a claim about determinism and an
    enforced one.
    """
    stored = {round(float(f["score"]), 2) for f in findings if f.get("score") is not None}
    if not stored:
        return []

    text_fields: list[str] = []
    for value in interpretation.values():
        if isinstance(value, str):
            text_fields.append(value)
        elif isinstance(value, list):
            text_fields.extend(v for v in value if isinstance(v, str))

    drift: list[str] = []
    for text in text_fields:
        for match in SCORE_PATTERN.findall(text):
            quoted = round(float(match), 2)
            if not any(abs(quoted - s) < 0.51 for s in stored):
                drift.append(f"'{match}/100' does not match any stored finding score")
    return sorted(set(drift))
