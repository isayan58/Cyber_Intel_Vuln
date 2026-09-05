"""LangGraph workflow.

    START
      |
      v
    plan ------------------------------.
      | (conditional fan-out)          |  (no evidence needed)
      v            v         v         |
  asset_exposure  vuln    threat   policy_rag
      \\           |        |        /
       `----------+--------+-------'
                  v
             synthesize            <- risk & remediation, the join point
                  v
               critic
                  |
        .---------+---------.
        v                   v
     replan               respond -> END
        |                    ^
        `-- (targeted re-run)'

Three properties this graph is built to demonstrate, all visible in a trace:

  * **Real parallelism.** The evidence specialists are separate LangGraph
    nodes fanned out by a conditional edge, not a loop inside one node. They
    execute concurrently and each produces its own span.
  * **Selective routing.** "What is CVE-X?" does not invoke the full system.
    The planner picks the subset, and unselected nodes never run.
  * **Targeted re-planning.** The critic emits a narrow gap list, and the
    replan node re-runs only the agents named in it — a cycle in the graph,
    bounded by ``max_replans``.
"""

from __future__ import annotations

import time
import uuid
from typing import Any

from langgraph.graph import END, START, StateGraph

from vulnintel.agents import SPECIALIST_AGENTS, GraphState, initial_state
from vulnintel.agents.critic import CriticAgent
from vulnintel.agents.responder import ResponderAgent
from vulnintel.agents.supervisor import ReplanSupervisor, SupervisorAgent
from vulnintel.config import get_settings
from vulnintel.logging_setup import get_logger
from vulnintel.observability.tracing import RunTracer

log = get_logger(__name__)

EVIDENCE_AGENTS = ["asset_exposure", "vulnerability_intel", "threat_intel", "policy_rag"]


# --------------------------------------------------------------------------
# Nodes
# --------------------------------------------------------------------------


def plan_node(state: GraphState) -> dict[str, Any]:
    agent = SupervisorAgent(run_id=state.get("run_id"))
    result = agent.run(state)
    plan = result.output.get("plan", {})

    log.info(
        "plan: intent=%s mode=%s agents=%s",
        plan.get("intent"),
        plan.get("response_mode"),
        plan.get("required_agents"),
    )
    return {
        "plan": plan,
        "intent": plan.get("intent", "general"),
        "response_mode": plan.get("response_mode", "analyst"),
        "entities": plan.get("entities", {}),
        "required_agents": plan.get("required_agents", []),
        "parallel_groups": plan.get("parallel_groups", []),
        "policy_questions": plan.get("policy_questions", []),
        "result_limit": plan.get("result_limit", 5),
        "spans": [result.span],
        "errors": result.errors,
        "prompt_versions": {"supervisor": result.prompt_version},
        "usage": {"supervisor": result.usage},
    }


def _specialist_node(agent_name: str):
    """Build a graph node for one specialist agent."""

    def node(state: GraphState) -> dict[str, Any]:
        agent = SPECIALIST_AGENTS[agent_name](run_id=state.get("run_id"))
        result = agent.run(state)
        return {
            "evidence": {agent_name: result.output},
            "citations": result.citations,
            "spans": [result.span],
            "errors": result.errors,
            "prompt_versions": {agent_name: result.prompt_version},
            "usage": {agent_name: result.usage},
        }

    node.__name__ = f"{agent_name}_node"
    return node


def synthesize_node(state: GraphState) -> dict[str, Any]:
    """Risk & remediation — always the join point after evidence gathering."""
    required = state.get("required_agents") or []
    if required and "risk_remediation" not in required:
        # A pure policy question needs no ranking; skip rather than return
        # the global top-5, which would be noise dressed up as an answer.
        log.info("synthesize: risk_remediation not in plan; skipping ranking")
        return {"evidence": {"risk_remediation": {"skipped": True, "findings": []}}}

    agent = SPECIALIST_AGENTS["risk_remediation"](run_id=state.get("run_id"))
    result = agent.run(state)
    return {
        "evidence": {"risk_remediation": result.output},
        "scored_findings": result.output.get("findings", []),
        "spans": [result.span],
        "errors": result.errors,
        "prompt_versions": {"risk_remediation": result.prompt_version},
        "usage": {"risk_remediation": result.usage},
    }


def critic_node(state: GraphState) -> dict[str, Any]:
    agent = CriticAgent(run_id=state.get("run_id"))
    result = agent.run(state)
    critique = result.output.get("interpretation") or {}
    critique.setdefault("assertions", result.output.get("assertions", []))

    gaps = critique.get("gaps") or []
    log.info(
        "critic: passed=%s confidence=%s gaps=%d",
        critique.get("passed"),
        critique.get("confidence"),
        len(gaps),
    )
    return {
        "critique": critique,
        "gaps": gaps,
        "spans": [result.span],
        "errors": result.errors,
        "prompt_versions": {"critic": result.prompt_version},
        "usage": {"critic": result.usage},
    }


def replan_node(state: GraphState) -> dict[str, Any]:
    agent = ReplanSupervisor(run_id=state.get("run_id"))
    result = agent.run(state)
    targeted = result.output.get("replan_agents", [])
    count = state.get("replan_count", 0) + 1

    log.info("replan #%d targeting %s", count, targeted or "(nothing actionable)")
    return {
        "replan_count": count,
        "required_agents": targeted or state.get("required_agents", []),
        "spans": [result.span],
    }


def respond_node(state: GraphState) -> dict[str, Any]:
    agent = ResponderAgent(run_id=state.get("run_id"))
    result = agent.run(state)
    return {
        "final_answer": result.output.get("final_answer", ""),
        "spans": [result.span],
        "errors": result.errors,
        "prompt_versions": {"responder": result.prompt_version},
        "usage": {"responder": result.usage},
    }


# --------------------------------------------------------------------------
# Routing
# --------------------------------------------------------------------------


def route_after_plan(state: GraphState) -> list[str]:
    """Fan out to the evidence agents the plan selected — in parallel."""
    required = state.get("required_agents") or []
    selected = [a for a in EVIDENCE_AGENTS if a in required]
    if not selected:
        # Nothing to gather; go straight to the join node.
        return ["synthesize"]
    return selected


def route_after_critic(state: GraphState) -> str:
    critique = state.get("critique") or {}
    gaps = state.get("gaps") or []
    replans = state.get("replan_count", 0)
    limit = get_settings().max_replans

    if critique.get("passed", True):
        return "respond"
    if not gaps:
        # Failed but with nothing actionable — re-running would change nothing.
        log.info("critic failed with no actionable gaps; responding with caveats")
        return "respond"
    if replans >= limit:
        log.info("re-plan limit (%d) reached; responding with caveats", limit)
        return "respond"
    return "replan"


def route_after_replan(state: GraphState) -> list[str]:
    required = state.get("required_agents") or []
    selected = [a for a in EVIDENCE_AGENTS if a in required]
    return selected or ["synthesize"]


# --------------------------------------------------------------------------
# Graph
# --------------------------------------------------------------------------


def build_graph(checkpointer: Any | None = None):
    """Compile the investigation graph."""
    graph = StateGraph(GraphState)

    graph.add_node("plan", plan_node)
    for agent_name in EVIDENCE_AGENTS:
        graph.add_node(agent_name, _specialist_node(agent_name))
    graph.add_node("synthesize", synthesize_node)
    graph.add_node("critic", critic_node)
    graph.add_node("replan", replan_node)
    graph.add_node("respond", respond_node)

    graph.add_edge(START, "plan")

    # Conditional fan-out: returning a list schedules those nodes in parallel.
    graph.add_conditional_edges("plan", route_after_plan, [*EVIDENCE_AGENTS, "synthesize"])
    for agent_name in EVIDENCE_AGENTS:
        graph.add_edge(agent_name, "synthesize")

    graph.add_edge("synthesize", "critic")
    graph.add_conditional_edges("critic", route_after_critic, ["replan", "respond"])
    graph.add_conditional_edges("replan", route_after_replan, [*EVIDENCE_AGENTS, "synthesize"])
    graph.add_edge("respond", END)

    return graph.compile(checkpointer=checkpointer)


_COMPILED: Any | None = None


def get_graph():
    global _COMPILED
    if _COMPILED is None:
        _COMPILED = build_graph()
    return _COMPILED


def run_investigation(
    question: str,
    user_role: str = "analyst",
    *,
    run_id: str | None = None,
    persist: bool = True,
    recursion_limit: int = 40,
) -> GraphState:
    """Execute one investigation end to end."""
    run_id = run_id or str(uuid.uuid4())
    state = initial_state(question, user_role, run_id)
    tracer = RunTracer(run_id, question, user_role, persist=persist)
    tracer.start()

    started = time.perf_counter()
    try:
        final = get_graph().invoke(state, config={"recursion_limit": recursion_limit})
    except Exception as exc:
        log.exception("investigation failed")
        tracer.finish(state, status="failed", error=str(exc), latency_ms=_ms(started))
        raise

    final["latency_ms"] = _ms(started)
    tracer.finish(final, status="succeeded", latency_ms=final["latency_ms"])
    log.info(
        "investigation complete in %dms (%d spans, %d re-plans)",
        final["latency_ms"],
        len(final.get("spans", [])),
        final.get("replan_count", 0),
    )
    return final


def _ms(started: float) -> int:
    return int((time.perf_counter() - started) * 1000)


def graph_topology() -> dict[str, Any]:
    """Node/edge description for the UI's live graph view."""
    return {
        "nodes": [
            {"id": "plan", "label": "Supervisor / Planner", "kind": "supervisor"},
            {"id": "asset_exposure", "label": "Asset Exposure", "kind": "specialist"},
            {"id": "vulnerability_intel", "label": "Vulnerability Intel", "kind": "specialist"},
            {"id": "threat_intel", "label": "Threat Intel", "kind": "specialist"},
            {"id": "policy_rag", "label": "Policy & Knowledge RAG", "kind": "specialist"},
            {"id": "synthesize", "label": "Risk & Remediation", "kind": "deterministic"},
            {"id": "critic", "label": "Critic / Verification", "kind": "critic"},
            {"id": "replan", "label": "Targeted Re-plan", "kind": "supervisor"},
            {"id": "respond", "label": "Response", "kind": "output"},
        ],
        "edges": [{"from": "plan", "to": a, "kind": "conditional"} for a in EVIDENCE_AGENTS]
        + [{"from": a, "to": "synthesize", "kind": "join"} for a in EVIDENCE_AGENTS]
        + [
            {"from": "plan", "to": "synthesize", "kind": "conditional"},
            {"from": "synthesize", "to": "critic", "kind": "direct"},
            {"from": "critic", "to": "replan", "kind": "conditional"},
            {"from": "critic", "to": "respond", "kind": "conditional"},
            {"from": "replan", "to": "synthesize", "kind": "cycle"},
        ]
        + [{"from": "replan", "to": a, "kind": "cycle"} for a in EVIDENCE_AGENTS],
    }
