"""End-to-end workflow evaluation.

Runs the real LangGraph against scenarios whose correct behaviour is known,
and asserts on the *trace* as well as the answer: which agents ran, whether
the critic's deterministic assertions held, whether any number in the answer
was invented.

Runs on the mock provider by default, which is deliberate. With a stub that
cannot reason, every factual claim in the output must still be correct —
because the facts were never the model's contribution. A failure here is a
real architectural leak, not a bad generation.
"""

from __future__ import annotations

import contextlib
import re
from typing import Any

from vulnintel.llm import build_provider, get_provider, set_provider
from vulnintel.logging_setup import get_logger

log = get_logger(__name__)

SCENARIOS: list[dict[str, Any]] = [
    {
        "id": "cto-weekly-brief",
        "question": "What are the five security issues our CTO should be most concerned about this week?",
        "role": "cto",
        "expect_agents": ["asset_exposure", "threat_intel", "risk_remediation"],
        "expect_mode": "executive",
        "expect_nodes_include": ["supervisor", "critic", "responder"],
    },
    {
        "id": "patch-queue",
        "question": "We can patch only 20 findings today. Which ones should be scheduled first?",
        "role": "analyst",
        "expect_agents": ["risk_remediation"],
        "expect_intent": "patch_queue",
    },
    {
        "id": "policy-only",
        "question": "What does our policy require for a vulnerability that is known to be exploited?",
        "role": "analyst",
        "expect_agents": ["policy_rag"],
        "expect_citations": True,
    },
    {
        "id": "application-assessment",
        "question": "Assess the security exposure of payments and give a remediation plan with evidence.",
        "role": "application_owner",
        "expect_agents": ["asset_exposure", "risk_remediation"],
    },
    {
        "id": "unknown-cve",
        "question": "Are we affected by CVE-1999-00000?",
        "role": "analyst",
        "expect_no_fabrication": True,
        "note": "A CVE that does not exist. The system must not invent an answer.",
    },
]

SCORE_RE = re.compile(r"\b(\d{1,3}(?:\.\d+)?)\s*/\s*100\b")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b")


def run(limit: int | None = None, provider: str = "mock") -> dict[str, Any]:
    from vulnintel.graph import run_investigation

    original = None
    with contextlib.suppress(Exception):  # no provider configured yet
        original = get_provider()

    set_provider(build_provider(provider))
    rows: list[dict[str, Any]] = []

    try:
        for scenario in SCENARIOS[: limit or None]:
            try:
                state = run_investigation(scenario["question"], user_role=scenario["role"])
            except Exception as exc:  # noqa: BLE001
                rows.append(
                    _row(scenario["id"], "run", "completes", f"raised {type(exc).__name__}", False)
                )
                continue
            rows.extend(_check(scenario, state))
    finally:
        set_provider(original)

    passed = [r for r in rows if r["passed"]]
    return {
        "cases": rows,
        "columns": ["id", "kind", "expected", "actual", "passed"],
        "summary": {
            "scenarios": len(SCENARIOS[: limit or None]),
            "cases": len(rows),
            "passed": len(passed),
            "failed": len(rows) - len(passed),
            "pass_rate": round(len(passed) / len(rows), 4) if rows else 0.0,
            "provider": provider,
        },
        "passed": len(passed) == len(rows),
    }


def _check(scenario: dict[str, Any], state: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    sid = scenario["id"]
    answer = state.get("final_answer") or ""
    evidence = state.get("evidence") or {}
    critique = state.get("critique") or {}
    findings = (evidence.get("risk_remediation") or {}).get("findings") or []

    rows.append(_row(sid, "completes", "an answer", f"{len(answer)} chars", bool(answer)))

    if "expect_agents" in scenario:
        # Spans, not required_agents: a re-plan narrows required_agents to the
        # gap it is filling, so reading it after the fact reports the last
        # cycle rather than everything that ran.
        ran = {span.get("node") for span in state.get("spans") or []}
        missing = [a for a in scenario["expect_agents"] if a not in ran]
        rows.append(
            _row(
                sid,
                "agents",
                ",".join(scenario["expect_agents"]),
                ",".join(sorted(ran)) or "(none)",
                not missing,
            )
        )

    if "expect_intent" in scenario:
        rows.append(
            _row(
                sid,
                "intent",
                scenario["expect_intent"],
                state.get("intent"),
                state.get("intent") == scenario["expect_intent"],
            )
        )

    if "expect_mode" in scenario:
        rows.append(
            _row(
                sid,
                "mode",
                scenario["expect_mode"],
                state.get("response_mode"),
                state.get("response_mode") == scenario["expect_mode"],
            )
        )

    if "expect_nodes_include" in scenario:
        nodes = {s.get("node") for s in state.get("spans") or []}
        missing = [n for n in scenario["expect_nodes_include"] if n not in nodes]
        rows.append(
            _row(
                sid,
                "nodes",
                ",".join(scenario["expect_nodes_include"]),
                ",".join(sorted(n for n in nodes if n)),
                not missing,
            )
        )

    if scenario.get("expect_citations"):
        citations = state.get("citations") or []
        rows.append(_row(sid, "citations", "at least one", str(len(citations)), bool(citations)))

    # --- the assertions that hold for every scenario -------------------------

    # No score in the answer that is not a stored score.
    stored = {round(float(f["score"]), 2) for f in findings if f.get("score") is not None}
    quoted = {round(float(m), 2) for m in SCORE_RE.findall(answer)}
    invented = [q for q in quoted if not any(abs(q - s) < 0.51 for s in stored)]
    rows.append(
        _row(
            sid,
            "no-invented-scores",
            "none",
            ",".join(str(i) for i in invented) or "none",
            not invented,
        )
    )

    # No CVE in the answer that is not in the evidence.
    evidence_cves = set()
    for payload in evidence.values():
        if isinstance(payload, dict):
            evidence_cves.update(CVE_RE.findall(str(payload)))
    answer_cves = set(CVE_RE.findall(answer))
    # A CVE the user named is legitimate to echo back, including when it does
    # not exist — "we found no record of CVE-1999-00000" is the right answer,
    # not a fabrication.
    asked_cves = set(CVE_RE.findall(scenario.get("question", "")))
    unsupported = answer_cves - evidence_cves - asked_cves
    rows.append(
        _row(
            sid,
            "no-invented-cves",
            "none",
            ",".join(sorted(unsupported)) or "none",
            not unsupported,
        )
    )

    # Every deterministic critic assertion held.
    assertions = critique.get("assertions") or []
    failed = [a["name"] for a in assertions if not a.get("passed")]
    # Freshness and injection assertions depend on ingestion state, not on the
    # graph, so they are reported but do not fail the workflow suite.
    blocking = [f for f in failed if f not in {"intelligence_is_fresh"}]
    rows.append(
        _row(sid, "critic-assertions", "all pass", ",".join(failed) or "all passed", not blocking)
    )

    if scenario.get("expect_no_fabrication"):
        # A non-existent CVE must not produce confident affected findings.
        affected = [f for f in findings if f.get("version_verdict") == "affected"]
        rows.append(
            _row(
                sid,
                "no-fabrication",
                "no affected findings",
                f"{len(affected)} findings",
                not affected,
            )
        )

    return rows


def _row(case_id: str, kind: str, expected: Any, actual: Any, passed: bool) -> dict[str, Any]:
    return {"id": case_id, "kind": kind, "expected": expected, "actual": actual, "passed": passed}
