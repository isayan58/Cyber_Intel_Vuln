"""security-intel-mcp — read-only access to normalised public security intelligence.

Run it standalone over stdio:

    python -m vulnintel.mcp_servers.security_intel.server

Or point any MCP client at it (Claude Desktop, an IDE agent, another LLM
client). That reusability is the point of the boundary: the same typed tools
the LangGraph agents call are available to anything that speaks MCP, with
authentication, rate limiting and audit logging able to sit behind one server
rather than being reimplemented per caller.

Every tool here is read-only. The server cannot patch, deploy, scan a target,
or mutate any table.
"""

from __future__ import annotations

from typing import Any

from mcp.server.mcpserver import MCPServer

from vulnintel.tools import security_intel as impl

SERVER_NAME = "security-intel-mcp"

server = MCPServer(
    name=SERVER_NAME,
    version="0.1.0",
    instructions=(
        "Read-only vulnerability and threat intelligence: CVE records with every "
        "provider's CVSS metrics, CISA KEV membership, FIRST EPSS scores, OSV/GHSA "
        "package advisories with deterministic version verdicts, and derived MITRE "
        "ATT&CK context. Version comparisons and risk scoring are performed by "
        "deterministic functions, never by a model. This server never returns "
        "exploitation guidance."
    ),
)


def get_cve(cve_id: str) -> dict[str, Any]:
    """Full normalised record for one CVE.

    Returns the description, every provider's CVSS metrics, the effective score
    under a stated precedence (newest spec version, then Primary, then NVD),
    any provider disagreement, CWEs, vulnerable CPE version ranges, references
    and advisory aliases. Provider disagreement is reported rather than
    resolved silently.
    """
    return impl.get_cve(cve_id)


def search_cves(
    product: str | None = None,
    vendor: str | None = None,
    min_cvss: float | None = None,
    min_epss: float | None = None,
    cwe: str | None = None,
    kev_only: bool = False,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Search CVEs by product, vendor, minimum CVSS, minimum EPSS, CWE or KEV membership."""
    return impl.search_cves(
        product=product,
        vendor=vendor,
        min_cvss=min_cvss,
        min_epss=min_epss,
        cwe=cwe,
        kev_only=kev_only,
        limit=limit,
    )


def get_kev_status(cve_ids: list[str]) -> dict[str, Any]:
    """CISA KEV membership for a list of CVEs.

    Returns `listed`, `not_listed` and per-CVE detail including the date each
    entry was added and its required action. Absence from KEV is returned
    explicitly rather than as a missing key.
    """
    return impl.get_kev_status(cve_ids)


def get_epss(cve_ids: list[str]) -> dict[str, Any]:
    """Current FIRST EPSS probability and percentile for a list of CVEs.

    CVEs with no EPSS score are returned under `unscored`. Unscored is not the
    same as low risk and must not be treated as zero.
    """
    return impl.get_epss(cve_ids)


def get_epss_history(cve_id: str, days: int = 90) -> list[dict[str, Any]]:
    """EPSS probability trend for one CVE over the retained rolling window."""
    return impl.get_epss_history(cve_id, days)


def get_package_advisories(
    ecosystem: str, package: str, version: str | None = None
) -> dict[str, Any]:
    """OSV/GHSA advisories affecting an ecosystem package.

    When `version` is supplied, each advisory carries a deterministic version
    verdict — `affected`, `not_affected` or `unknown` — plus the reason and the
    fixed version. `unknown` means the comparison could not be performed and
    must not be reported as affected.
    """
    return impl.get_package_advisories(ecosystem, package, version)


def get_attack_context(
    cve_ids: list[str] | None = None, attack_ids: list[str] | None = None
) -> dict[str, Any]:
    """Candidate MITRE ATT&CK techniques and related mitigations.

    ATT&CK does not publish CVE-to-technique links, so every mapping returned
    here is *derived* and carries a `basis` and a `confidence`. Callers are
    expected to drop weak mappings rather than present them as fact.
    """
    return impl.get_attack_context(cve_ids, attack_ids)


def get_feed_freshness() -> list[dict[str, Any]]:
    """Last successful ingestion time per feed, for stale-intelligence checks."""
    return impl.get_feed_freshness()


TOOLS = [
    get_cve,
    search_cves,
    get_kev_status,
    get_epss,
    get_epss_history,
    get_package_advisories,
    get_attack_context,
    get_feed_freshness,
]

for _tool in TOOLS:
    server.add_tool(_tool)


def main() -> None:
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
