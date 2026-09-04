"""Agent 1 — Supervisor / Planner.

Interprets the question, extracts entities and decides which specialists run
and in what groups. It is the only agent with a view of the whole workflow.

On re-plan it produces a *narrowed* plan containing only the agents the critic
asked for, so a gap costs one extra node rather than a full re-run.
"""

from __future__ import annotations

from typing import Any

from vulnintel.agents.base import Agent, AgentResult, as_json
from vulnintel.agents.state import GraphState
from vulnintel.logging_setup import get_logger

log = get_logger(__name__)

ALL_SPECIALISTS = [
    "asset_exposure",
    "vulnerability_intel",
    "threat_intel",
    "policy_rag",
    "risk_remediation",
]

# Deterministic fallback plans, used when the model is unavailable or returns
# something unusable. A planner outage degrades the answer; it must not stop it.
FALLBACK_PLANS: dict[str, list[str]] = {
    "executive_brief": ALL_SPECIALISTS,
    "cve_investigation": ALL_SPECIALISTS,
    "application_assessment": ALL_SPECIALISTS,
    "patch_queue": ["asset_exposure", "threat_intel", "policy_rag", "risk_remediation"],
    "policy_question": ["policy_rag"],
    "asset_lookup": ["asset_exposure"],
    "general": ["asset_exposure", "threat_intel", "risk_remediation"],
}

# Agents whose absence would make an answer to this intent structurally
# impossible, whatever the planner decided.
REQUIRED_AGENTS_BY_INTENT: dict[str, tuple[str, ...]] = {
    "executive_brief": ("asset_exposure", "threat_intel", "risk_remediation"),
    "cve_investigation": ("asset_exposure", "vulnerability_intel", "risk_remediation"),
    "application_assessment": ("asset_exposure", "risk_remediation"),
    "patch_queue": ("risk_remediation",),
    "general": ("risk_remediation",),
    # A policy question genuinely needs only the corpus.
    "policy_question": ("policy_rag",),
    "asset_lookup": ("asset_exposure",),
}


class SupervisorAgent(Agent):
    name = "supervisor"
    prompt_name = "supervisor"

    def gather(self, state: GraphState) -> dict[str, Any]:
        """Give the planner the application names so it can match entities."""
        summary = self.tools.call("get_inventory_summary")
        from vulnintel.data.db import get_db

        names = [
            row["name"]
            for row in get_db().query(
                "SELECT DISTINCT name FROM applications ORDER BY tier, name LIMIT 60"
            )
        ]
        return {"inventory_summary": summary, "application_names": names}

    def interpret(self, state: GraphState, gathered: dict[str, Any]) -> dict[str, Any]:
        result = AgentResult(agent=self.name)
        plan = self._ask_structured(
            result,
            question=state["question"],
            user_role=state.get("user_role", "analyst"),
            application_names=", ".join(gathered.get("application_names", [])) or "(none loaded)",
        )
        self._last_usage = result.usage
        self._last_prompt_version = result.prompt_version
        return plan

    def run(self, state: GraphState) -> AgentResult:
        result = super().run(state)
        plan = result.output.get("interpretation") or {}
        plan = self._validate(plan, state)
        result.output["plan"] = plan
        result.prompt_version = getattr(self, "_last_prompt_version", None)
        result.usage = getattr(self, "_last_usage", {})
        return result

    # -- validation -----------------------------------------------------------

    def _validate(self, plan: dict[str, Any], state: GraphState) -> dict[str, Any]:
        """Never trust the plan blindly — a malformed plan must still execute."""
        intent = plan.get("intent") or self._guess_intent(state["question"])

        agents = [a for a in plan.get("required_agents", []) if a in ALL_SPECIALISTS]
        if not agents:
            agents = FALLBACK_PLANS.get(intent, FALLBACK_PLANS["general"])
            log.info("supervisor: using fallback plan for intent '%s'", intent)

        # Structural requirements the planner is not permitted to omit. You
        # cannot answer "our top five risks" without ranking, and you cannot
        # rank without asset context — so an under-specified plan is topped up
        # rather than executed as given.
        for required in REQUIRED_AGENTS_BY_INTENT.get(intent, ()):
            if required not in agents:
                log.info(
                    "supervisor: intent '%s' requires '%s'; adding it to the plan",
                    intent,
                    required,
                )
                agents.append(required)

        # risk_remediation depends on the others, so it is always last and alone.
        specialists = [a for a in agents if a != "risk_remediation"]
        groups: list[list[str]] = []
        if specialists:
            groups.append(specialists)
        if "risk_remediation" in agents:
            groups.append(["risk_remediation"])

        entities = plan.get("entities") or {}
        normalised_entities = {
            key: [str(v).strip() for v in entities.get(key, []) if str(v).strip()]
            for key in (
                "cve_ids",
                "advisory_ids",
                "application_names",
                "asset_hostnames",
                "products",
            )
        }
        normalised_entities["cve_ids"] = [c.upper() for c in normalised_entities["cve_ids"]]

        limit = plan.get("result_limit") or 5
        try:
            limit = max(1, min(int(limit), 50))
        except (TypeError, ValueError):
            limit = 5

        return {
            "intent": intent,
            "response_mode": plan.get("response_mode") or self._mode_for(state.get("user_role")),
            "reasoning": plan.get("reasoning", ""),
            "entities": normalised_entities,
            "required_agents": agents,
            "parallel_groups": groups,
            "policy_questions": [
                str(q) for q in plan.get("policy_questions", []) if str(q).strip()
            ],
            "result_limit": limit,
        }

    @staticmethod
    def _guess_intent(question: str) -> str:
        text = question.lower()
        if any(k in text for k in ("cve-", "ghsa-", "are we affected", "blast radius")):
            return "cve_investigation"
        if any(k in text for k in ("policy", "sla", "required", "who approves", "standard")):
            return "policy_question"
        if any(k in text for k in ("patch", "capacity", "schedule", "today", "only")):
            return "patch_queue"
        if any(k in text for k in ("cto", "executive", "board", "this week", "most concerned")):
            return "executive_brief"
        return "general"

    @staticmethod
    def _mode_for(role: str | None) -> str:
        mapping = {
            "cto": "executive",
            "executive": "executive",
            "ciso": "executive",
            "manager": "executive",
            "application_owner": "application_owner",
            "app_owner": "application_owner",
        }
        return mapping.get((role or "").lower(), "analyst")


class ReplanSupervisor(SupervisorAgent):
    """Targeted re-plan: only the agents the critic named, nothing else."""

    uses_llm = False

    def gather(self, state: GraphState) -> dict[str, Any]:
        gaps = state.get("gaps") or []
        agents = []
        hints: dict[str, list[str]] = {}
        for gap in gaps:
            agent = gap.get("agent")
            if agent in ALL_SPECIALISTS and agent not in agents:
                agents.append(agent)
            if agent and gap.get("detail"):
                hints.setdefault(agent, []).append(str(gap["detail"]))

        # Re-scoring is cheap and the ranking may shift once gaps are filled.
        if agents and "risk_remediation" not in agents:
            agents.append("risk_remediation")

        log.info("re-plan targeting %s (from %d gaps)", agents or "nothing", len(gaps))
        return {
            "replan_agents": agents,
            "replan_hints": hints,
            "gap_summary": as_json(gaps, limit=4000),
            "skip_llm": True,
        }
