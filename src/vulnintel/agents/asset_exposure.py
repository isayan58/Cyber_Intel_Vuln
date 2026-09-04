"""Agent 2 — Asset Exposure.

Answers "what of ours does this touch?" using exact SQL filters. The model is
given the result set and asked only to summarise it in business terms; it
never decides membership, never compares versions and never infers criticality
from a hostname.
"""

from __future__ import annotations

from typing import Any

from vulnintel.agents.base import Agent, AgentResult, as_json
from vulnintel.agents.state import GraphState
from vulnintel.logging_setup import get_logger

log = get_logger(__name__)

ROW_SAMPLE = 60


class AssetExposureAgent(Agent):
    name = "asset_exposure"
    prompt_name = "asset_exposure"

    def gather(self, state: GraphState) -> dict[str, Any]:
        entities = state.get("entities") or {}
        evidence: dict[str, Any] = {
            "inventory_summary": self.tools.call("get_inventory_summary"),
            "by_cve": {},
            "by_application": {},
            "by_product": {},
        }

        for cve_id in entities.get("cve_ids", [])[:10]:
            evidence["by_cve"][cve_id] = self.tools.call(
                "get_findings_for_cve", cve_id=cve_id, only_affected=False, limit=200
            )

        for name in entities.get("application_names", [])[:5]:
            dependencies = self.tools.call("get_application_dependencies", application_name=name)
            assets = self.tools.call("search_assets", application_name=name, limit=100)
            evidence["by_application"][name] = {
                "dependencies": dependencies,
                "asset_count": len(assets),
                "assets": assets[:ROW_SAMPLE],
                "truncated": len(assets) > ROW_SAMPLE,
            }

        for product in entities.get("products", [])[:5]:
            evidence["by_product"][product] = self.tools.call(
                "find_assets_by_software", product=product, limit=200
            )

        # With no named entity — the flagship "top issues this week" case — the
        # question is still about specific vulnerabilities, just ones the user
        # has not named yet. Sampling generic production assets answers nothing,
        # so derive the currently top-ranked CVEs and resolve *their* blast
        # radius. Without this the asset agent contributes no asset context to
        # the single most important question the platform answers.
        if not any(
            (evidence["by_cve"], evidence["by_application"], evidence["by_product"])
        ):
            for cve_id in self._top_ranked_cves(limit=state.get("result_limit", 5)):
                evidence["by_cve"][cve_id] = self.tools.call(
                    "get_findings_for_cve", cve_id=cve_id, only_affected=False, limit=200
                )
            evidence["derived_from_ranking"] = True

            evidence["exposed_production"] = self.tools.call(
                "search_assets",
                environment="production",
                internet_facing=True,
                limit=ROW_SAMPLE,
            )
            evidence["tier1_assets"] = self.tools.call("search_assets", tier=1, limit=ROW_SAMPLE)

        evidence["aggregates"] = self._aggregates(evidence)
        return evidence

    def interpret(self, state: GraphState, gathered: dict[str, Any]) -> dict[str, Any]:
        result = AgentResult(agent=self.name)
        interpretation = self._ask_structured(
            result,
            need=state.get("question", ""),
            rows=as_json(
                {
                    "by_cve": gathered.get("by_cve"),
                    "by_application": gathered.get("by_application"),
                    "by_product": gathered.get("by_product"),
                    "exposed_production": gathered.get("exposed_production"),
                    "tier1_assets": gathered.get("tier1_assets"),
                }
            ),
            aggregates=as_json(gathered.get("aggregates"), limit=6000),
        )
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

    @staticmethod
    def _top_ranked_cves(limit: int = 5) -> list[str]:
        """Currently highest-scoring CVEs, read straight from the serving view.

        Deliberately not a tool call: ranking belongs to the risk agent, which
        runs *after* this one in the fan-out, so this reads the stored scores
        directly rather than creating a dependency that would serialise the
        parallel group.
        """
        from vulnintel.data.db import get_db

        return [
            row["cve_id"]
            for row in get_db().query(
                "SELECT cve_id FROM v_executive_top_risks "
                "ORDER BY top_score DESC NULLS LAST LIMIT ?",
                [int(limit)],
            )
        ]

    @staticmethod
    def _aggregates(evidence: dict[str, Any]) -> dict[str, Any]:
        """Counts computed from full result sets, before any row truncation."""
        aggregates: dict[str, Any] = {"per_cve": {}, "per_application": {}, "per_product": {}}

        for cve_id, payload in evidence.get("by_cve", {}).items():
            findings = payload.get("findings", [])
            # Counts come from the tool's authoritative aggregate, never from
            # the returned rows: those are capped at the query limit, so
            # recounting them disagrees with the ranking agent's SQL and the
            # critic correctly flags the answer as contradictory.
            totals = payload.get("authoritative_counts") or {}
            aggregates["per_cve"][cve_id] = {
                "affected_findings": totals.get("affected_count", 0),
                "unknown_findings": totals.get("unknown_count", 0),
                "distinct_assets": totals.get("distinct_assets", 0),
                "distinct_applications": totals.get("distinct_applications", 0),
                "internet_facing": totals.get("internet_facing", 0),
                "production": totals.get("production", 0),
                "tier1": totals.get("tier1", 0),
                "counts_are_authoritative": bool(totals),
                "business_services": sorted(
                    {f.get("business_service") for f in findings if f.get("business_service")}
                ),
                "owner_teams": sorted(
                    {f.get("owner_team") for f in findings if f.get("owner_team")}
                ),
                "truncated": payload.get("truncated", False),
            }

        for name, payload in evidence.get("by_application", {}).items():
            aggregates["per_application"][name] = {
                "asset_count": payload.get("asset_count", 0),
                "dependency_count": len(
                    payload.get("dependencies", {}).get("dependencies", []) or []
                ),
                "found": payload.get("dependencies", {}).get("found", False),
            }

        for product, payload in evidence.get("by_product", {}).items():
            assets = payload.get("assets", [])
            aggregates["per_product"][product] = {
                "install_count": payload.get("match_count", 0),
                "version_distribution": payload.get("version_distribution", [])[:10],
                "internet_facing": sum(1 for a in assets if a.get("internet_facing")),
                "tier1": sum(1 for a in assets if a.get("tier") == 1),
                "truncated": payload.get("truncated", False),
            }

        return aggregates
