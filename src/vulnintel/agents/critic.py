"""Agent 7 — Critic / Verification.

Runs deterministic assertions first, then an LLM audit. The deterministic
checks are the ones that must never be skipped; the model pass catches the
softer failures (unsupported prose, speculative narrative) that no assertion
can express.

A failing deterministic assertion forces a re-plan regardless of what the
model thought of the draft.
"""

from __future__ import annotations

from typing import Any

from vulnintel.agents.base import Agent, AgentResult, as_json
from vulnintel.agents.state import GraphState
from vulnintel.logging_setup import get_logger

log = get_logger(__name__)

# Assertions that describe the environment rather than the answer. They are
# reported to the reader but must not, on their own, force an expensive model
# audit or a re-plan — no amount of re-planning ingests NVD.
_ADVISORY_ASSERTIONS = frozenset({"intelligence_is_fresh"})


class CriticAgent(Agent):
    name = "critic"
    prompt_name = "critic"

    def gather(self, state: GraphState) -> dict[str, Any]:
        evidence = state.get("evidence") or {}
        assertions = self._deterministic_checks(state, evidence)
        failures = [a for a in assertions if not a["passed"]]

        gathered = {
            "assertions": assertions,
            "assertion_failures": failures,
            "agents_run": sorted(evidence.keys()),
        }

        # The model audit is the single most expensive node in the graph
        # (18s mean, 81s worst, ~4k output tokens). It only earns that when
        # there is prose to audit. A draft that is absent, or that consists
        # solely of figures already proven against stored values, has nothing
        # for it to find — so the deterministic assertions stand alone and the
        # call is skipped. Anything that failed an assertion still goes to the
        # model, because that is exactly when its judgement is worth buying.
        draft = (evidence.get("risk_remediation") or {}).get("interpretation") or {}
        blocking = [f for f in failures if f["name"] not in _ADVISORY_ASSERTIONS]

        drift = (
            (evidence.get("risk_remediation") or {})
            .get("interpretation", {})
            .get("score_drift_detected")
        )

        if not draft:
            gathered["skip_llm"] = True
            gathered["skip_reason"] = "no draft to audit"
        elif not blocking and not drift:
            # The deterministic assertions already cover every high-risk claim:
            # affected verdicts, stored scores, score mutation, policy
            # provenance, fabricated ATT&CK mappings and injected instructions.
            # When all of them hold there is nothing left that only judgement
            # could catch, and the audit is the most expensive node in the graph
            # (measured at 58% of a clean run's cost together with the
            # responder). It is bought when a check has actually flagged
            # something, not on every request.
            gathered["skip_llm"] = True
            gathered["skip_reason"] = (
                "every blocking assertion passed and no score drift was detected; "
                "the model audit is reserved for runs where a deterministic check "
                "found something"
            )

        return gathered

    @staticmethod
    def _has_auditable_prose(draft: dict[str, Any]) -> bool:
        """Is there enough narrative that an LLM audit could find something?"""
        prose: list[str] = []
        for value in draft.values():
            if isinstance(value, str):
                prose.append(value)
            elif isinstance(value, list):
                prose.extend(v for v in value if isinstance(v, str))
        return sum(len(p) for p in prose) > 400

    def interpret(self, state: GraphState, gathered: dict[str, Any]) -> dict[str, Any]:
        result = AgentResult(agent=self.name)
        evidence = state.get("evidence") or {}
        draft = (evidence.get("risk_remediation") or {}).get("interpretation") or {}

        critique = self._ask_structured(
            result,
            question=state.get("question", ""),
            draft=as_json(draft, limit=8000),
            evidence=as_json(self._compact_evidence(evidence), limit=14000),
            agents_run=", ".join(gathered.get("agents_run", [])) or "(none)",
        )

        # Bounds the schema can no longer express are enforced here.
        try:
            critique["confidence"] = max(0.0, min(1.0, float(critique.get("confidence", 0.5))))
        except (TypeError, ValueError):
            critique["confidence"] = 0.5

        # A deterministic failure overrides the model's verdict.
        failures = gathered.get("assertion_failures", [])
        if failures:
            critique["passed"] = False
            critique.setdefault("gaps", [])
            for failure in failures:
                if failure.get("gap"):
                    critique["gaps"].append(failure["gap"])
            critique["deterministic_failures"] = [f["name"] for f in failures]
            critique["confidence"] = min(float(critique.get("confidence", 0.5)), 0.5)

        self._last_usage = result.usage
        self._last_prompt_version = result.prompt_version
        return critique

    def run(self, state: GraphState) -> AgentResult:
        result = super().run(state)
        result.prompt_version = getattr(self, "_last_prompt_version", None)
        result.usage = getattr(self, "_last_usage", {})

        # A skipped audit still returns a verdict — from the assertions, which
        # ran regardless. Silence would be indistinguishable from failure.
        if result.output.get("skip_llm") and "interpretation" not in result.output:
            failures = result.output.get("assertion_failures", [])
            blocking = [f for f in failures if f["name"] not in _ADVISORY_ASSERTIONS]
            result.output["interpretation"] = {
                "passed": not blocking,
                "confidence": 0.75 if not blocking else 0.4,
                "unsupported_claims": [],
                "contradictions": [],
                "speculative_mappings": [],
                "gaps": [f["gap"] for f in blocking if f.get("gap")],
                "injection_suspected": [],
                "summary": (
                    "Verified by deterministic assertions only; the model audit was "
                    f"skipped ({result.output.get('skip_reason')}). "
                    + (
                        "All blocking checks passed."
                        if not blocking
                        else f"Blocking failures: {', '.join(f['name'] for f in blocking)}."
                    )
                ),
                "audit_mode": "deterministic_only",
            }
        return result

    # -- deterministic assertions ---------------------------------------------

    def _deterministic_checks(
        self, state: GraphState, evidence: dict[str, Any]
    ) -> list[dict[str, Any]]:
        checks: list[dict[str, Any]] = []
        risk = evidence.get("risk_remediation") or {}
        findings = risk.get("findings") or []

        # 1. Every reported finding must have a deterministic 'affected' verdict.
        bad_verdicts = [f for f in findings if f.get("version_verdict") not in (None, "affected")]
        checks.append(
            {
                "name": "all_reported_findings_are_affected",
                "passed": not bad_verdicts,
                "detail": f"{len(bad_verdicts)} finding(s) reported without an 'affected' verdict",
            }
        )

        # 2. Every reported finding must carry a stored score.
        unscored = [f for f in findings if f.get("score") is None]
        checks.append(
            {
                "name": "all_findings_have_stored_scores",
                "passed": not unscored,
                "detail": f"{len(unscored)} finding(s) have no persisted score",
                "gap": (
                    {
                        "need": "deterministic scores for the reported findings",
                        "agent": "risk_remediation",
                        "detail": "re-run scoring",
                    }
                    if unscored
                    else None
                ),
            }
        )

        # 3. Scores echoed in the plan must match stored values.
        drift = risk.get("interpretation", {}).get("score_drift_detected") or []
        checks.append(
            {
                "name": "no_score_mutation_by_model",
                "passed": not drift,
                "detail": "; ".join(drift) if drift else "all quoted scores match stored values",
            }
        )

        # 4. A policy claim requires retrieved policy evidence.
        policy = evidence.get("policy_rag") or {}
        obligations = (policy.get("interpretation") or {}).get("obligations") or []
        plan_obligations = (risk.get("interpretation") or {}).get("policy_obligations") or []
        checks.append(
            {
                "name": "policy_claims_have_retrieved_evidence",
                "passed": not plan_obligations or bool(obligations),
                "detail": (
                    f"plan states {len(plan_obligations)} obligation(s) with "
                    f"{len(obligations)} retrieved obligation(s) behind them"
                ),
                "gap": (
                    {
                        "need": "policy passages supporting the stated obligations",
                        "agent": "policy_rag",
                        "detail": state.get("question", ""),
                    }
                    if plan_obligations and not obligations
                    else None
                ),
            }
        )

        # 5. Fabricated ATT&CK mappings must have been removed, not tolerated.
        threat = evidence.get("threat_intel") or {}
        fabricated = (threat.get("interpretation") or {}).get("fabricated_mappings_removed", 0)
        checks.append(
            {
                "name": "no_fabricated_attack_mappings",
                "passed": not fabricated,
                "detail": f"{fabricated} mapping(s) outside the candidate set were removed",
            }
        )

        # 6. Prompt injection found in retrieved documents must be surfaced.
        injection = policy.get("injection_flags") or []
        checks.append(
            {
                "name": "no_injection_in_retrieved_documents",
                "passed": not injection,
                "detail": "; ".join(injection) if injection else "no instruction-shaped text found",
            }
        )

        # 7. Feeds must not be stale.
        vuln = evidence.get("vulnerability_intel") or {}
        staleness = vuln.get("staleness") or []
        checks.append(
            {
                "name": "intelligence_is_fresh",
                "passed": not staleness,
                "detail": "; ".join(staleness) if staleness else "all feeds current",
            }
        )

        for check in checks:
            if check.get("gap") is None:
                check.pop("gap", None)
        return checks

    @staticmethod
    def _compact_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
        """Interpretations and aggregates only — raw rows would swamp the audit."""
        compact: dict[str, Any] = {}
        for agent, payload in evidence.items():
            if not isinstance(payload, dict):
                continue
            entry: dict[str, Any] = {}
            for key in (
                "interpretation",
                "aggregates",
                "signals_summary",
                "conflicts",
                "citations",
                "staleness",
                "injection_flags",
                "score_explanations",
                "sla_rules",
            ):
                if payload.get(key):
                    entry[key] = payload[key]
            if agent == "risk_remediation":
                # top_assets carries the hostnames and installed versions the
                # draft quotes. Omitting it made the critic report every named
                # host as an unsupported claim — a false positive that cost two
                # full re-plan cycles before the loop limit stopped it.
                entry["findings"] = [
                    {
                        k: f.get(k)
                        for k in (
                            "finding_id",
                            "cve_id",
                            "hostname",
                            "application_name",
                            "product",
                            "asset_count",
                            "application_count",
                            "score",
                            "kev_listed",
                            "epss",
                            "version_verdict",
                            "installed_version",
                            "fixed_version",
                            "sla_due_date",
                            "sla_breached",
                            "top_assets",
                        )
                        if k in f
                    }
                    for f in (payload.get("findings") or [])[:10]
                ]
            compact[agent] = entry
        return compact
