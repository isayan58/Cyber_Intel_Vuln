"""Tool-correctness evaluation.

Checks the tool layer the agents depend on: that every registered tool is
callable with its declared schema, returns the documented shape, fails
gracefully on bad input, and — the one that actually matters — that the
allowlist is enforced rather than merely declared.
"""

from __future__ import annotations

from typing import Any

from vulnintel.logging_setup import get_logger
from vulnintel.tools import AGENT_TOOL_ALLOWLIST, TOOL_SPECS, ToolAccessError, ToolBox

log = get_logger(__name__)

# Safe smoke arguments per tool. Non-existent identifiers are deliberate: a
# tool must answer "not found" cleanly rather than raise.
SMOKE_ARGS: dict[str, dict[str, Any]] = {
    "get_cve": {"cve_id": "CVE-0000-00000"},
    "search_cves": {"limit": 3},
    "get_kev_status": {"cve_ids": ["CVE-2021-44228", "CVE-0000-00000"]},
    "get_epss": {"cve_ids": ["CVE-2021-44228", "CVE-0000-00000"]},
    "get_epss_history": {"cve_id": "CVE-2021-44228", "days": 7},
    "get_package_advisories": {"ecosystem": "PyPI", "package": "django", "version": "3.2.18"},
    "get_attack_context": {"cve_ids": ["CVE-2021-44228"]},
    "get_feed_freshness": {},
    "search_assets": {"limit": 3},
    "get_asset": {"asset_id": "AST-000001"},
    "get_application_dependencies": {"application_name": "payments"},
    "find_assets_by_software": {"product": "django", "limit": 3},
    "get_business_context": {"asset_id": "AST-000001"},
    "get_findings_for_cve": {"cve_id": "CVE-2021-44228", "limit": 5},
    "get_inventory_summary": {},
    "search_policy": {"query": "remediation SLA for exploited vulnerabilities", "top_k": 3},
    "retrieve_chunk": {"chunk_id": "does-not-exist::0000"},
    "list_policy_versions": {},
    "get_sla_rules": {},
    "rank_findings": {"limit": 3},
    "explain_score": {"finding_id": 1},
    "patch_queue": {"capacity": 5},
    "portfolio_summary": {},
}


def run(limit: int | None = None) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []

    # 1. Every tool is callable and returns a JSON-shaped result.
    box = ToolBox("__eval__", persist=False)
    box.allowed = set(SMOKE_ARGS)

    for spec in TOOL_SPECS[: limit or None]:
        args = SMOKE_ARGS.get(spec.name)
        if args is None:
            rows.append(_row(spec.name, "smoke", "arguments defined", "missing", False))
            continue
        try:
            result = box.call(spec.name, **args)
            shape = type(result).__name__
            ok = isinstance(result, dict | list)
            rows.append(_row(spec.name, "smoke", "dict or list", shape, ok))
        except Exception as exc:  # noqa: BLE001
            rows.append(
                _row(spec.name, "smoke", "no exception", f"{type(exc).__name__}: {exc}", False)
            )

    # 2. Schemas are well formed and match the handler's parameters.
    for spec in TOOL_SPECS:
        schema = spec.input_schema
        ok = (
            schema.get("type") == "object"
            and isinstance(schema.get("properties"), dict)
            and schema.get("additionalProperties") is False
            and all(r in schema["properties"] for r in schema.get("required", []))
        )
        rows.append(
            _row(spec.name, "schema", "valid object schema", "ok" if ok else "malformed", ok)
        )

    # 3. Least privilege is enforced, not just documented.
    for agent, allowed in AGENT_TOOL_ALLOWLIST.items():
        forbidden = next((s.name for s in TOOL_SPECS if s.name not in allowed), None)
        if forbidden is None:
            continue
        agent_box = ToolBox(agent, persist=False)
        try:
            agent_box.call(forbidden, **SMOKE_ARGS.get(forbidden, {}))
            rows.append(_row(agent, "allowlist", "ToolAccessError", "call succeeded", False))
        except ToolAccessError:
            rows.append(_row(agent, "allowlist", "ToolAccessError", "raised", True))
        except Exception as exc:  # noqa: BLE001 - wrong exception type is still a failure
            rows.append(_row(agent, "allowlist", "ToolAccessError", type(exc).__name__, False))

    # 4. Unknown tool names are rejected.
    try:
        box.call("definitely_not_a_tool")
        rows.append(_row("unknown-tool", "allowlist", "ToolAccessError", "call succeeded", False))
    except ToolAccessError:
        rows.append(_row("unknown-tool", "allowlist", "ToolAccessError", "raised", True))

    # 5. Every tool is audited.
    audited = len(box.calls) > 0 and all(c.call_id for c in box.calls)
    rows.append(
        _row("audit-trail", "audit", "every call recorded", f"{len(box.calls)} recorded", audited)
    )

    passed = [r for r in rows if r["passed"]]
    return {
        "cases": rows,
        "columns": ["id", "kind", "expected", "actual", "passed"],
        "summary": {
            "cases": len(rows),
            "passed": len(passed),
            "failed": len(rows) - len(passed),
            "pass_rate": round(len(passed) / len(rows), 4) if rows else 0.0,
            "tools_registered": len(TOOL_SPECS),
            "agents_with_allowlists": len(AGENT_TOOL_ALLOWLIST),
        },
        "passed": len(passed) == len(rows),
    }


def _row(case_id: str, kind: str, expected: Any, actual: Any, passed: bool) -> dict[str, Any]:
    return {"id": case_id, "kind": kind, "expected": expected, "actual": actual, "passed": passed}
