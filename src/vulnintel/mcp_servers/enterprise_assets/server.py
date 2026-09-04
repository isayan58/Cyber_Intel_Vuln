"""enterprise-assets-mcp — read-only access to the enterprise inventory.

Run standalone over stdio:

    python -m vulnintel.mcp_servers.enterprise_assets.server

This is the boundary that would, in a real deployment, front a CMDB. Keeping
it behind MCP is what lets asset access be authenticated, rate limited and
audited in one place — and it is why the inventory schema can change without
touching agent code.

All matching is exact SQL. No tool here asks a model to decide what is
affected, and every tool is read-only.
"""

from __future__ import annotations

from typing import Any

from mcp.server.mcpserver import MCPServer

from vulnintel.tools import enterprise_assets as impl

SERVER_NAME = "enterprise-assets-mcp"

server = MCPServer(
    name=SERVER_NAME,
    version="0.1.0",
    instructions=(
        "Read-only enterprise inventory: assets, applications, software and package "
        "dependencies, business criticality, environment, internet exposure, "
        "ownership and open vulnerability findings. Findings carry a deterministic "
        "version verdict and a match path (purl or cpe) with a confidence, so an "
        "unresolved comparison is visible rather than assumed. This inventory is "
        "synthetic, generated from a fixed seed."
    ),
)


def search_assets(
    application_name: str | None = None,
    environment: str | None = None,
    internet_facing: bool | None = None,
    business_criticality: str | None = None,
    tier: int | None = None,
    product: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Search assets by application, environment, exposure, criticality, tier or product.

    `environment` is one of production, staging, development. `tier` is the
    owning application's tier, where 1 is most business-critical.
    """
    return impl.search_assets(
        application_name=application_name,
        environment=environment,
        internet_facing=internet_facing,
        business_criticality=business_criticality,
        tier=tier,
        product=product,
        limit=limit,
    )


def get_asset(asset_id: str) -> dict[str, Any]:
    """One asset with its full software inventory and open findings."""
    return impl.get_asset(asset_id)


def get_application_dependencies(
    application_id: str | None = None, application_name: str | None = None
) -> dict[str, Any]:
    """Dependency manifest for an application, resolvable by id or by name.

    Returns direct and transitive packages with their purls, the asset count,
    and the environment breakdown.
    """
    return impl.get_application_dependencies(application_id, application_name)


def find_assets_by_software(
    product: str, version: str | None = None, ecosystem: str | None = None, limit: int = 200
) -> dict[str, Any]:
    """Which assets run a given product, optionally pinned to one version.

    Also returns the installed-version distribution across the whole estate,
    which is what makes "how much of our fleet is on the old version?"
    answerable without a second call.
    """
    return impl.find_assets_by_software(product, version, ecosystem, limit)


def get_business_context(asset_id: str) -> dict[str, Any]:
    """Business context for one asset: service, tier, owner, exposure, data classification."""
    return impl.get_business_context(asset_id)


def get_findings_for_cve(
    cve_id: str, only_affected: bool = True, limit: int = 200
) -> dict[str, Any]:
    """Enterprise blast radius for one CVE.

    Counts of `unknown` version verdicts are returned separately from
    confirmed-affected findings, so unresolved comparisons are never folded
    into the affected total.
    """
    return impl.get_findings_for_cve(cve_id, only_affected, limit)


def get_inventory_summary() -> dict[str, Any]:
    """Estate-level counts: assets, applications, software records, tier-1 apps, exposure."""
    return impl.get_inventory_summary()


TOOLS = [
    search_assets,
    get_asset,
    get_application_dependencies,
    find_assets_by_software,
    get_business_context,
    get_findings_for_cve,
    get_inventory_summary,
]

for _tool in TOOLS:
    server.add_tool(_tool)


def main() -> None:
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
