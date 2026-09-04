"""LangGraph state definition.

The graph carries one typed state object. Specialist agents write structured
results into it and never compose the final answer themselves — that is the
supervisor/responder's job, and keeping it that way is what makes the critic's
job tractable.

Evidence accumulates rather than being overwritten so that a targeted re-plan
adds to what is known instead of discarding it.
"""

from __future__ import annotations

import operator
from typing import Annotated, Any, TypedDict


def merge_dicts(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    """Reducer for parallel branches writing disjoint keys into one dict."""
    merged = dict(left or {})
    merged.update(right or {})
    return merged


class GraphState(TypedDict, total=False):
    # --- request ---------------------------------------------------------
    run_id: str
    question: str
    user_role: str

    # --- plan ------------------------------------------------------------
    plan: dict[str, Any]
    intent: str
    response_mode: str
    entities: dict[str, list[str]]
    required_agents: list[str]
    parallel_groups: list[list[str]]
    policy_questions: list[str]
    result_limit: int

    # --- evidence (written by specialists, merged across parallel branches)
    evidence: Annotated[dict[str, Any], merge_dicts]
    citations: Annotated[list[dict[str, Any]], operator.add]

    # --- synthesis -------------------------------------------------------
    scored_findings: list[dict[str, Any]]
    plan_draft: dict[str, Any]
    final_answer: str

    # --- verification ----------------------------------------------------
    critique: dict[str, Any]
    replan_count: int
    gaps: list[dict[str, Any]]

    # --- observability ---------------------------------------------------
    spans: Annotated[list[dict[str, Any]], operator.add]
    errors: Annotated[list[str], operator.add]
    prompt_versions: Annotated[dict[str, Any], merge_dicts]
    usage: Annotated[dict[str, Any], merge_dicts]


def initial_state(question: str, user_role: str, run_id: str) -> GraphState:
    return GraphState(
        run_id=run_id,
        question=question,
        user_role=user_role,
        evidence={},
        citations=[],
        scored_findings=[],
        spans=[],
        errors=[],
        prompt_versions={},
        usage={},
        replan_count=0,
        gaps=[],
        result_limit=5,
        response_mode="analyst",
    )
