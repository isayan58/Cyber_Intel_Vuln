"""FastAPI application: JSON API + server-rendered HTMX UI.

No build step. Templates render HTML fragments that HTMX swaps into the page,
and the investigation endpoint streams Server-Sent Events so the agent graph
lights up node by node as LangGraph executes it.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Form, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from vulnintel import __version__
from vulnintel.agents import initial_state
from vulnintel.config import get_settings
from vulnintel.data.db import get_db
from vulnintel.graph import get_graph, graph_topology, run_investigation
from vulnintel.logging_setup import get_logger, setup_logging
from vulnintel.observability import (
    get_run,
    node_latency_summary,
    recent_runs,
    replan_rate,
    tool_usage_summary,
)
from vulnintel.prompts import get_registry
from vulnintel.tools import TOOL_SPECS, risk_tools
from vulnintel.tools import enterprise_assets as assets_tools
from vulnintel.tools import knowledge as knowledge_tools
from vulnintel.tools import security_intel as intel_tools

setup_logging()
log = get_logger(__name__)

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

app = FastAPI(
    title="VulnIntel AI",
    version=__version__,
    description="Enterprise vulnerability and cyber-risk intelligence platform",
)

STATIC_DIR = BASE_DIR / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# --------------------------------------------------------------------------
# Template filters
# --------------------------------------------------------------------------


def _band(score: Any) -> str:
    try:
        value = float(score)
    except (TypeError, ValueError):
        return "unknown"
    if value >= 80:
        return "p1"
    if value >= 60:
        return "p2"
    if value >= 40:
        return "p3"
    return "p4"


def _pct(value: Any) -> str:
    try:
        return f"{float(value) * 100:.1f}%"
    except (TypeError, ValueError):
        return "—"


def _num(value: Any, digits: int = 0) -> str:
    try:
        return f"{float(value):,.{digits}f}"
    except (TypeError, ValueError):
        return "—"


templates.env.filters["band"] = _band
templates.env.filters["pct"] = _pct
templates.env.filters["num"] = _num
templates.env.globals["app_version"] = lambda: __version__
templates.env.globals["llm_provider"] = lambda: get_settings().llm_provider


# --------------------------------------------------------------------------
# Pages
# --------------------------------------------------------------------------


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    from datetime import UTC, datetime

    summary = risk_tools.portfolio_summary()
    inventory = assets_tools.get_inventory_summary()
    top = risk_tools.rank_findings(limit=5, group_by_cve=True)
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "page": "dashboard",
            "summary": summary,
            "inventory": inventory,
            "posture": risk_tools.executive_posture(),
            "proof": risk_tools.value_proof(limit=8),
            "top_risks": top["findings"],
            "freshness": intel_tools.get_feed_freshness(),
            "today": datetime.now(UTC).strftime("%d %B %Y"),
        },
    )


@app.get("/ask", response_class=HTMLResponse)
def ask_page(request: Request):
    return templates.TemplateResponse(
        request,
        "ask.html",
        {
            "page": "ask",
            "topology": graph_topology(),
            "examples": [
                (
                    "What are the five security issues our CTO should be most "
                    "concerned about this week?",
                    "cto",
                ),
                (
                    "We can patch only 20 findings today. Which ones should be "
                    "scheduled first?",
                    "analyst",
                ),
                (
                    "Assess the security exposure of payments and give a remediation "
                    "plan with evidence.",
                    "application_owner",
                ),
                (
                    "What does our policy require for a vulnerability that is known "
                    "to be exploited?",
                    "analyst",
                ),
            ],
        },
    )


@app.get("/findings", response_class=HTMLResponse)
def findings_page(
    request: Request,
    limit: int = Query(50, ge=1, le=500),
    kev_only: bool = False,
    internet_facing_only: bool = False,
    application_name: str | None = None,
):
    result = risk_tools.rank_findings(
        limit=limit,
        kev_only=kev_only,
        internet_facing_only=internet_facing_only,
        application_name=application_name,
    )
    return templates.TemplateResponse(
        request,
        "findings.html",
        {
            "page": "findings",
            "findings": result["findings"],
            "filters": {
                "kev_only": kev_only,
                "internet_facing_only": internet_facing_only,
                "application_name": application_name or "",
                "limit": limit,
            },
        },
    )


@app.get("/findings/{finding_id}", response_class=HTMLResponse)
def finding_detail(request: Request, finding_id: int):
    explanation = risk_tools.explain_score(finding_id)
    row = get_db().query_one(
        "SELECT * FROM v_finding_enriched WHERE finding_id = ?", [finding_id]
    )
    return templates.TemplateResponse(
        request,
        "finding_detail.html",
        {
            "page": "findings",
            "finding": row or {},
            "explanation": explanation,
        },
    )


@app.get("/traces", response_class=HTMLResponse)
def traces_page(request: Request):
    return templates.TemplateResponse(
        request,
        "traces.html",
        {
            "page": "traces",
            "runs": recent_runs(30),
            "node_latency": node_latency_summary(),
            "tool_usage": tool_usage_summary(),
            "replan": replan_rate(),
        },
    )


@app.get("/traces/{run_id}", response_class=HTMLResponse)
def trace_detail(request: Request, run_id: str):
    run = get_run(run_id)
    return templates.TemplateResponse(
        request,
        "trace_detail.html",
        {
            "page": "traces", "run": run or {}, "run_id": run_id},
    )


@app.get("/knowledge", response_class=HTMLResponse)
def knowledge_page(request: Request, q: str | None = None):
    results = knowledge_tools.search_policy(q, top_k=8) if q else None
    return templates.TemplateResponse(
        request,
        "knowledge.html",
        {
            "page": "knowledge",
            "documents": knowledge_tools.list_policy_versions(),
            "sla_rules": knowledge_tools.get_sla_rules(),
            "query": q or "",
            "results": results,
        },
    )


@app.get("/system", response_class=HTMLResponse)
def system_page(request: Request):
    settings = get_settings()
    return templates.TemplateResponse(
        request,
        "system.html",
        {
            "page": "system",
            "settings": {
                "db_backend": settings.db_backend,
                "llm_provider": settings.llm_provider,
                "llm_model": settings.llm_model,
                "llm_effort": settings.llm_effort,
                "embedding_provider": settings.embedding_provider,
                "max_replans": settings.max_replans,
                "synthetic_seed": settings.synthetic_seed,
            },
            "prompts": get_registry().describe(),
            "tools": [
                {"name": t.name, "server": t.server, "description": t.description}
                for t in TOOL_SPECS
            ],
            "tables": get_db().table_counts(),
            "freshness": intel_tools.get_feed_freshness(),
        },
    )


# --------------------------------------------------------------------------
# HTMX fragments
# --------------------------------------------------------------------------


@app.post("/fragments/prompts/reload", response_class=HTMLResponse)
def reload_prompts(request: Request):
    """Hot-reload every prompt file without restarting the server."""
    registry = get_registry()
    registry.reload_all()
    return templates.TemplateResponse(
        request,
        "fragments/prompt_table.html",
        {
            "prompts": registry.describe(), "reloaded": True},
    )


@app.get("/fragments/score/{finding_id}", response_class=HTMLResponse)
def score_fragment(request: Request, finding_id: int):
    return templates.TemplateResponse(
        request,
        "fragments/score_breakdown.html",
        {
            "explanation": risk_tools.explain_score(finding_id)},
    )


@app.get("/fragments/citation/{chunk_id}", response_class=HTMLResponse)
def citation_fragment(request: Request, chunk_id: str):
    return templates.TemplateResponse(
        request,
        "fragments/citation.html",
        {
            "chunk": knowledge_tools.retrieve_chunk(chunk_id)},
    )


# --------------------------------------------------------------------------
# Investigation — SSE streaming
# --------------------------------------------------------------------------


def _sse(event: str, data: dict[str, Any]) -> str:
    return f"event: {event}\ndata: {json.dumps(data, default=str)}\n\n"


@app.post("/api/ask/stream")
async def ask_stream(question: str = Form(...), user_role: str = Form("analyst")):
    """Stream graph progress as Server-Sent Events.

    LangGraph's ``stream(stream_mode='updates')`` yields one payload per node
    completion, which is exactly the granularity the UI wants: nodes light up
    as they finish, and the re-plan cycle is visible as nodes re-entering.
    """
    run_id = str(uuid.uuid4())

    async def generate():
        from vulnintel.observability.tracing import RunTracer

        state = initial_state(question, user_role, run_id)
        tracer = RunTracer(run_id, question, user_role)
        tracer.start()

        yield _sse("start", {"run_id": run_id, "question": question, "user_role": user_role})

        final: dict[str, Any] = dict(state)
        queue: asyncio.Queue = asyncio.Queue()

        def worker() -> None:
            try:
                for update in get_graph().stream(
                    state, config={"recursion_limit": 40}, stream_mode="updates"
                ):
                    for node, payload in update.items():
                        queue.put_nowait(("node", node, payload))
                queue.put_nowait(("done", None, None))
            except Exception as exc:  # noqa: BLE001
                queue.put_nowait(("error", None, str(exc)))

        task = asyncio.get_running_loop().run_in_executor(None, worker)

        while True:
            kind, node, payload = await queue.get()
            if kind == "error":
                tracer.finish(final, status="failed", latency_ms=0, error=str(payload))
                yield _sse("error", {"message": str(payload)})
                break
            if kind == "done":
                tracer.finish(final, status="succeeded", latency_ms=0)
                yield _sse(
                    "final",
                    {
                        "run_id": run_id,
                        "answer": final.get("final_answer", ""),
                        "citations": final.get("citations", []),
                        "critique": final.get("critique", {}),
                        "replan_count": final.get("replan_count", 0),
                        "findings": final.get("scored_findings", [])[:10],
                    },
                )
                break

            for key, value in (payload or {}).items():
                if key in ("spans", "citations", "errors"):
                    final.setdefault(key, [])
                    final[key] = list(final[key]) + list(value or [])
                elif key in ("evidence", "prompt_versions", "usage"):
                    merged = dict(final.get(key) or {})
                    merged.update(value or {})
                    final[key] = merged
                else:
                    final[key] = value

            yield _sse(
                "node",
                {
                    "node": node,
                    "summary": _node_summary(node, payload or {}),
                    "spans": [
                        {"node": s.get("node"), "latency_ms": s.get("latency_ms"),
                         "status": s.get("status"), "tool_calls": s.get("tool_calls", [])}
                        for s in (payload or {}).get("spans", [])
                    ],
                },
            )

        await task

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


def _node_summary(node: str, payload: dict[str, Any]) -> str:
    if node == "plan":
        plan = payload.get("plan") or {}
        agents = ", ".join(plan.get("required_agents", []))
        return f"intent={plan.get('intent')} · mode={plan.get('response_mode')} · agents: {agents}"
    if node == "critic":
        critique = payload.get("critique") or {}
        return (
            f"passed={critique.get('passed')} · confidence={critique.get('confidence')} "
            f"· gaps={len(critique.get('gaps') or [])}"
        )
    if node == "replan":
        return f"re-plan #{payload.get('replan_count')} targeting {payload.get('required_agents')}"
    if node == "synthesize":
        findings = payload.get("scored_findings") or []
        return f"{len(findings)} scored finding(s) ranked deterministically"
    if node == "respond":
        return "final answer composed"

    evidence = payload.get("evidence") or {}
    for agent, data in evidence.items():
        calls = len((payload.get("spans") or [{}])[0].get("tool_calls", []))
        return f"{agent}: {calls} tool call(s)"
    return ""


# --------------------------------------------------------------------------
# JSON API
# --------------------------------------------------------------------------


@app.get("/api/health")
def health():
    counts = get_db().table_counts()
    return {
        "status": "ok",
        "version": __version__,
        "backend": get_settings().db_backend,
        "llm_provider": get_settings().llm_provider,
        "assets": counts.get("assets", 0),
        "cves": counts.get("cve", 0),
        "findings": counts.get("vulnerability_finding", 0),
        "kb_chunks": counts.get("kb_chunk", 0),
    }


@app.post("/api/ask")
def ask(question: str = Form(...), user_role: str = Form("analyst")):
    state = run_investigation(question, user_role)
    return JSONResponse(
        {
            "run_id": state.get("run_id"),
            "answer": state.get("final_answer"),
            "intent": state.get("intent"),
            "response_mode": state.get("response_mode"),
            "agents_run": state.get("required_agents"),
            "replan_count": state.get("replan_count"),
            "critique": state.get("critique"),
            "citations": state.get("citations"),
            "findings": state.get("scored_findings", [])[:20],
            "latency_ms": state.get("latency_ms"),
            "prompt_versions": state.get("prompt_versions"),
        }
    )


@app.get("/api/findings")
def api_findings(
    limit: int = Query(20, ge=1, le=200),
    kev_only: bool = False,
    application_name: str | None = None,
    group_by_cve: bool = False,
):
    return risk_tools.rank_findings(
        limit=limit,
        kev_only=kev_only,
        application_name=application_name,
        group_by_cve=group_by_cve,
    )


@app.get("/api/findings/{finding_id}/score")
def api_score(finding_id: int):
    return risk_tools.explain_score(finding_id)


@app.get("/api/posture")
def api_posture():
    """Executive framing: what needs a decision, and what it puts at risk."""
    return {"posture": risk_tools.executive_posture(), "proof": risk_tools.value_proof()}


@app.get("/api/patch-queue")
def api_patch_queue(capacity: int = Query(20, ge=1, le=200)):
    return risk_tools.patch_queue(capacity=capacity)


@app.get("/api/cve/{cve_id}")
def api_cve(cve_id: str):
    return {
        "intelligence": intel_tools.get_cve(cve_id),
        "kev": intel_tools.get_kev_status([cve_id]),
        "epss": intel_tools.get_epss([cve_id]),
        "blast_radius": assets_tools.get_findings_for_cve(cve_id),
        "attack": intel_tools.get_attack_context(cve_ids=[cve_id]),
    }


@app.get("/api/policy/search")
def api_policy_search(q: str, top_k: int = Query(6, ge=1, le=20)):
    return knowledge_tools.search_policy(q, top_k=top_k)


@app.get("/api/graph/topology")
def api_topology():
    return graph_topology()


@app.get("/api/traces")
def api_traces(limit: int = Query(25, ge=1, le=200)):
    return {
        "runs": recent_runs(limit),
        "node_latency": node_latency_summary(),
        "tool_usage": tool_usage_summary(),
        "replan": replan_rate(),
    }


@app.get("/api/traces/{run_id}")
def api_trace(run_id: str):
    run = get_run(run_id)
    if run is None:
        return JSONResponse({"error": "run not found"}, status_code=404)
    return run


@app.get("/api/prompts")
def api_prompts():
    return {"prompts": get_registry().describe()}


@app.post("/api/prompts/reload")
def api_reload_prompts():
    cleared = get_registry().reload_all()
    return {"reloaded": True, "cleared": cleared, "prompts": get_registry().describe()}
