"""Tool registry, allowlisting and audit logging.

One registry describes every tool once — its name, owning server, JSON schema
and implementation. Two consumers read it:

  * ``ToolBox`` — the in-process path used by the agent graph
  * ``mcp_servers`` — which turns the same specs into MCP tool definitions

That single definition is what stops the MCP servers and the agents drifting
apart, which is the usual failure mode when a project bolts MCP on afterwards.

Two controls from design doc §15 live here:

  * **Tool allowlisting** — each agent is constructed with only the tools its
    role needs. Calling outside the allowlist raises rather than silently
    working, so least privilege is enforced, not merely documented.
  * **Auditability** — every call is persisted to ``tool_call`` with its
    arguments, row count, latency and outcome.
"""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from vulnintel.data.db import Database, get_db
from vulnintel.logging_setup import get_logger
from vulnintel.tools import enterprise_assets as assets_tools
from vulnintel.tools import knowledge as knowledge_tools
from vulnintel.tools import risk_tools
from vulnintel.tools import security_intel as intel_tools

log = get_logger(__name__)


@dataclass(frozen=True)
class ToolSpec:
    name: str
    server: str
    description: str
    handler: Callable[..., Any]
    input_schema: dict[str, Any]
    read_only: bool = True

    def mcp_schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
        }


def _schema(properties: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties,
        "required": required or [],
        "additionalProperties": False,
    }


_STR = {"type": "string"}
_INT = {"type": "integer"}
_NUM = {"type": "number"}
_BOOL = {"type": "boolean"}
_STR_LIST = {"type": "array", "items": {"type": "string"}}


TOOL_SPECS: list[ToolSpec] = [
    # ---- security-intel-mcp -------------------------------------------------
    ToolSpec(
        "get_cve",
        "security-intel",
        "Full normalised record for one CVE: description, every provider's CVSS metrics, "
        "the effective score under a stated precedence, provider disagreements, CWEs, "
        "CPE version ranges, references and advisory aliases.",
        intel_tools.get_cve,
        _schema({"cve_id": _STR}, ["cve_id"]),
    ),
    ToolSpec(
        "search_cves",
        "security-intel",
        "Search CVEs by product, vendor, minimum CVSS, minimum EPSS, CWE or KEV membership.",
        intel_tools.search_cves,
        _schema(
            {
                "product": _STR, "vendor": _STR, "min_cvss": _NUM, "min_epss": _NUM,
                "cwe": _STR, "kev_only": _BOOL, "limit": _INT,
            }
        ),
    ),
    ToolSpec(
        "get_kev_status",
        "security-intel",
        "CISA KEV membership for a list of CVEs, with the date each entered the catalogue. "
        "Returns both the listed and not-listed sets so absence is explicit.",
        intel_tools.get_kev_status,
        _schema({"cve_ids": _STR_LIST}, ["cve_ids"]),
    ),
    ToolSpec(
        "get_epss",
        "security-intel",
        "Current EPSS probability and percentile for a list of CVEs. CVEs with no score are "
        "returned under 'unscored' — unscored is not the same as low risk.",
        intel_tools.get_epss,
        _schema({"cve_ids": _STR_LIST}, ["cve_ids"]),
    ),
    ToolSpec(
        "get_epss_history",
        "security-intel",
        "EPSS trend for one CVE over the retained rolling window.",
        intel_tools.get_epss_history,
        _schema({"cve_id": _STR, "days": _INT}, ["cve_id"]),
    ),
    ToolSpec(
        "get_package_advisories",
        "security-intel",
        "OSV/GHSA advisories for an ecosystem package. When a version is supplied, each "
        "advisory carries a deterministic version verdict (affected / not_affected / unknown).",
        intel_tools.get_package_advisories,
        _schema({"ecosystem": _STR, "package": _STR, "version": _STR}, ["ecosystem", "package"]),
    ),
    ToolSpec(
        "get_attack_context",
        "security-intel",
        "Candidate ATT&CK techniques for CVEs, each with its derivation basis and confidence, "
        "plus related mitigations. Mappings are derived, never asserted as fact.",
        intel_tools.get_attack_context,
        _schema({"cve_ids": _STR_LIST, "attack_ids": _STR_LIST}),
    ),
    ToolSpec(
        "get_feed_freshness",
        "security-intel",
        "Last successful ingestion per feed, for detecting stale intelligence.",
        intel_tools.get_feed_freshness,
        _schema({}),
    ),
    # ---- enterprise-assets-mcp ---------------------------------------------
    ToolSpec(
        "search_assets",
        "enterprise-assets",
        "Search the enterprise inventory by application, environment, exposure, criticality, "
        "tier or installed product.",
        assets_tools.search_assets,
        _schema(
            {
                "application_name": _STR, "environment": _STR, "internet_facing": _BOOL,
                "business_criticality": _STR, "tier": _INT, "product": _STR, "limit": _INT,
            }
        ),
    ),
    ToolSpec(
        "get_asset",
        "enterprise-assets",
        "One asset with its full software inventory and open findings.",
        assets_tools.get_asset,
        _schema({"asset_id": _STR}, ["asset_id"]),
    ),
    ToolSpec(
        "get_application_dependencies",
        "enterprise-assets",
        "Dependency manifest for an application, resolvable by id or name.",
        assets_tools.get_application_dependencies,
        _schema({"application_id": _STR, "application_name": _STR}),
    ),
    ToolSpec(
        "find_assets_by_software",
        "enterprise-assets",
        "Which assets run a given product, optionally pinned to one version, with the "
        "installed-version distribution across the estate.",
        assets_tools.find_assets_by_software,
        _schema({"product": _STR, "version": _STR, "ecosystem": _STR, "limit": _INT}, ["product"]),
    ),
    ToolSpec(
        "get_business_context",
        "enterprise-assets",
        "Business context for one asset: service, tier, owner, exposure, classification.",
        assets_tools.get_business_context,
        _schema({"asset_id": _STR}, ["asset_id"]),
    ),
    ToolSpec(
        "get_findings_for_cve",
        "enterprise-assets",
        "Blast radius for one CVE across the estate, with counts of unknown verdicts kept "
        "separate from confirmed-affected.",
        assets_tools.get_findings_for_cve,
        _schema({"cve_id": _STR, "only_affected": _BOOL, "limit": _INT}, ["cve_id"]),
    ),
    ToolSpec(
        "get_inventory_summary",
        "enterprise-assets",
        "Estate-level inventory counts.",
        assets_tools.get_inventory_summary,
        _schema({}),
    ),
    # ---- knowledge ----------------------------------------------------------
    ToolSpec(
        "search_policy",
        "knowledge",
        "Hybrid (BM25 + vector) search over internal policy and external guidance, returning "
        "quote-sized passages with citation metadata and any version conflicts detected.",
        knowledge_tools.search_policy,
        _schema(
            {
                "query": _STR, "authority": _STR, "doc_type": _STR, "control_family": _STR,
                "include_superseded": _BOOL, "top_k": _INT,
            },
            ["query"],
        ),
    ),
    ToolSpec(
        "retrieve_chunk",
        "knowledge",
        "Fetch one knowledge-base chunk verbatim by id, to verify a citation.",
        knowledge_tools.retrieve_chunk,
        _schema({"chunk_id": _STR}, ["chunk_id"]),
    ),
    ToolSpec(
        "list_policy_versions",
        "knowledge",
        "Every indexed document with its policy version and supersession status.",
        knowledge_tools.list_policy_versions,
        _schema({}),
    ),
    ToolSpec(
        "get_sla_rules",
        "knowledge",
        "The remediation SLA rule table as structured data — the same table the deterministic "
        "scorer uses, so a quoted obligation always matches the computed deadline.",
        knowledge_tools.get_sla_rules,
        _schema({}),
    ),
    # ---- risk ---------------------------------------------------------------
    ToolSpec(
        "rank_findings",
        "risk",
        "Top findings by stored enterprise priority score, filterable by application, CVE, "
        "environment, exposure, KEV or tier. Reads persisted scores; computes nothing.",
        risk_tools.rank_findings,
        _schema(
            {
                "limit": _INT, "application_name": _STR, "cve_id": _STR, "environment": _STR,
                "internet_facing_only": _BOOL, "kev_only": _BOOL, "tier": _INT,
                "exclude_risk_accepted": _BOOL, "group_by_cve": _BOOL,
            }
        ),
    ),
    ToolSpec(
        "explain_score",
        "risk",
        "Component-level breakdown for one finding exactly as stored: normalised value, "
        "weight and contribution per component, plus SLA derivation.",
        risk_tools.explain_score,
        _schema({"finding_id": _INT}, ["finding_id"]),
    ),
    ToolSpec(
        "patch_queue",
        "risk",
        "Deterministic scheduling under limited capacity: SLA breaches first, then descending "
        "priority score, then oldest.",
        risk_tools.patch_queue,
        _schema({"capacity": _INT, "one_per_application": _BOOL}),
    ),
    ToolSpec(
        "portfolio_summary",
        "risk",
        "Estate-level risk roll-up for the dashboard.",
        risk_tools.portfolio_summary,
        _schema({}),
    ),
]

TOOLS: dict[str, ToolSpec] = {spec.name: spec for spec in TOOL_SPECS}


def tools_for_server(server: str) -> list[ToolSpec]:
    return [spec for spec in TOOL_SPECS if spec.server == server]


# Least privilege: each agent gets only what its role needs (§15).
AGENT_TOOL_ALLOWLIST: dict[str, set[str]] = {
    "supervisor": {"get_inventory_summary", "list_policy_versions"},
    "asset_exposure": {
        "search_assets", "get_asset", "get_application_dependencies",
        "find_assets_by_software", "get_business_context", "get_findings_for_cve",
        "get_inventory_summary",
    },
    "vulnerability_intel": {"get_cve", "search_cves", "get_package_advisories", "get_feed_freshness"},
    "threat_intel": {
        "get_kev_status", "get_epss", "get_epss_history", "get_attack_context",
        "get_feed_freshness",
    },
    "policy_rag": {"search_policy", "retrieve_chunk", "list_policy_versions", "get_sla_rules"},
    "risk_remediation": {"rank_findings", "explain_score", "patch_queue", "portfolio_summary"},
    "critic": {"retrieve_chunk", "explain_score", "get_kev_status", "get_feed_freshness"},
}


class ToolAccessError(PermissionError):
    """Raised when an agent calls a tool outside its allowlist."""


@dataclass
class ToolCallRecord:
    call_id: str
    tool_name: str
    server: str
    arguments: dict[str, Any]
    row_count: int
    latency_ms: int
    status: str
    error: str | None = None


class ToolBox:
    """Allowlisted, audited access to the tool registry."""

    def __init__(
        self,
        agent: str,
        run_id: str | None = None,
        span_id: str | None = None,
        db: Database | None = None,
        persist: bool = True,
    ) -> None:
        self.agent = agent
        self.run_id = run_id
        self.span_id = span_id
        self.db = db or get_db()
        self.persist = persist
        self.allowed = AGENT_TOOL_ALLOWLIST.get(agent, set())
        self.calls: list[ToolCallRecord] = field(default_factory=list)  # type: ignore[assignment]
        self.calls = []

    def available(self) -> list[str]:
        return sorted(self.allowed)

    def describe(self) -> list[dict[str, Any]]:
        return [
            {"name": name, "server": TOOLS[name].server, "description": TOOLS[name].description}
            for name in sorted(self.allowed)
            if name in TOOLS
        ]

    def call(self, tool_name: str, **arguments: Any) -> Any:
        if tool_name not in TOOLS:
            raise ToolAccessError(f"unknown tool '{tool_name}'")
        if tool_name not in self.allowed:
            raise ToolAccessError(
                f"agent '{self.agent}' is not permitted to call '{tool_name}'. "
                f"Permitted: {', '.join(sorted(self.allowed)) or 'none'}"
            )

        spec = TOOLS[tool_name]
        started = time.perf_counter()
        status, error, result = "ok", None, None
        try:
            result = spec.handler(**arguments)
            return result
        except Exception as exc:
            status, error = "error", str(exc)
            raise
        finally:
            latency_ms = int((time.perf_counter() - started) * 1000)
            record = ToolCallRecord(
                call_id=str(uuid.uuid4()),
                tool_name=tool_name,
                server=spec.server,
                arguments=arguments,
                row_count=_row_count(result),
                latency_ms=latency_ms,
                status=status,
                error=error,
            )
            self.calls.append(record)
            if self.persist and self.run_id:
                self._persist(record)

    def _persist(self, record: ToolCallRecord) -> None:
        try:
            self.db.insert_many(
                "tool_call",
                [
                    {
                        "call_id": record.call_id,
                        "run_id": self.run_id,
                        "span_id": self.span_id,
                        "tool_name": record.tool_name,
                        "server": record.server,
                        "arguments": json.dumps(record.arguments, default=str),
                        "row_count": record.row_count,
                        "latency_ms": record.latency_ms,
                        "status": record.status,
                        "error": record.error,
                        "called_at": datetime.now(UTC).replace(tzinfo=None),
                    }
                ],
            )
        except Exception as exc:  # noqa: BLE001 - audit must never break a query
            log.warning("could not persist tool_call audit row: %s", exc)


def _row_count(result: Any) -> int:
    if result is None:
        return 0
    if isinstance(result, list):
        return len(result)
    if isinstance(result, dict):
        for key in ("findings", "assets", "advisories", "evidence", "queue", "mappings"):
            value = result.get(key)
            if isinstance(value, list):
                return len(value)
        return 1
    return 1
