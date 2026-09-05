"""Enterprise inventory tools — read-only access to the synthetic estate.

These are the functions behind ``enterprise-assets-mcp``. All matching is done
with exact SQL filters; no tool here asks a model to decide what is affected.
"""

from __future__ import annotations

from typing import Any

from vulnintel.data.db import Database, get_db

MAX_ROWS = 500


def _db(db: Database | None) -> Database:
    return db or get_db()


def search_assets(
    *,
    application_name: str | None = None,
    environment: str | None = None,
    internet_facing: bool | None = None,
    business_criticality: str | None = None,
    tier: int | None = None,
    product: str | None = None,
    limit: int = 100,
    db: Database | None = None,
) -> list[dict[str, Any]]:
    conn = _db(db)
    clauses: list[str] = []
    params: list[Any] = []

    sql = [
        "SELECT DISTINCT a.asset_id, a.hostname, a.environment, a.region, a.internet_facing,",
        "       a.business_criticality, a.data_classification, a.os_platform, a.owner,",
        "       a.last_patch_date, a.compensating_controls,",
        "       app.application_id, app.name AS application_name, app.business_service,",
        "       app.tier, app.owner_team, app.external_customer_facing",
        "FROM assets a",
        "LEFT JOIN applications app ON app.application_id = a.application_id",
    ]

    if product:
        sql.append("JOIN software_inventory sw ON sw.asset_id = a.asset_id")
        clauses.append("lower(sw.product) = ?")
        params.append(product.strip().lower())

    if application_name:
        clauses.append("lower(app.name) LIKE ?")
        params.append(f"%{application_name.strip().lower()}%")
    if environment:
        clauses.append("a.environment = ?")
        params.append(environment.strip().lower())
    if internet_facing is not None:
        clauses.append("a.internet_facing = ?")
        params.append(bool(internet_facing))
    if business_criticality:
        clauses.append("a.business_criticality = ?")
        params.append(business_criticality.strip().lower())
    if tier is not None:
        clauses.append("app.tier = ?")
        params.append(int(tier))

    if clauses:
        sql.append("WHERE " + " AND ".join(clauses))
    sql.append("ORDER BY app.tier NULLS LAST, a.internet_facing DESC, a.hostname")
    sql.append(f"LIMIT {min(int(limit), MAX_ROWS)}")

    return conn.query("\n".join(sql), params)


def get_asset(asset_id: str, db: Database | None = None) -> dict[str, Any]:
    conn = _db(db)
    asset = conn.query_one(
        "SELECT a.*, app.name AS application_name, app.business_service, app.tier, "
        "app.owner_team, app.revenue_impact_band, app.external_customer_facing "
        "FROM assets a LEFT JOIN applications app ON app.application_id = a.application_id "
        "WHERE a.asset_id = ?",
        [asset_id.strip()],
    )
    if asset is None:
        return {"asset_id": asset_id, "found": False}

    asset["found"] = True
    asset["software"] = conn.query(
        "SELECT sw_id, ecosystem, vendor, product, version, purl, cpe23, "
        "purl_confidence, cpe23_confidence FROM software_inventory "
        "WHERE asset_id = ? ORDER BY ecosystem, product",
        [asset_id.strip()],
    )
    asset["open_findings"] = conn.query(
        "SELECT finding_id, cve_id, advisory_id, product, installed_version, fixed_version, "
        "score, kev_listed, epss, sla_due_date, sla_breached, version_verdict, match_path "
        "FROM v_finding_enriched WHERE asset_id = ? AND status <> 'remediated' "
        "ORDER BY score DESC NULLS LAST LIMIT 50",
        [asset_id.strip()],
    )
    return asset


def get_application_dependencies(
    application_id: str | None = None,
    application_name: str | None = None,
    db: Database | None = None,
) -> dict[str, Any]:
    """Dependency manifest for an application, resolvable by id or name."""
    conn = _db(db)
    app = None
    if application_id:
        app = conn.query_one(
            "SELECT * FROM applications WHERE application_id = ?", [application_id.strip()]
        )
    elif application_name:
        app = conn.query_one(
            "SELECT * FROM applications WHERE lower(name) = ? "
            "OR lower(name) LIKE ? ORDER BY name LIMIT 1",
            [application_name.strip().lower(), f"%{application_name.strip().lower()}%"],
        )
    if app is None:
        return {
            "found": False,
            "application_id": application_id,
            "application_name": application_name,
        }

    app_id = app["application_id"]
    return {
        "found": True,
        "application": app,
        "dependencies": conn.query(
            "SELECT ecosystem, package, version, purl, direct_or_transitive "
            "FROM dependencies WHERE application_id = ? ORDER BY ecosystem, package",
            [app_id],
        ),
        "asset_count": conn.scalar(
            "SELECT count(*) FROM assets WHERE application_id = ?", [app_id]
        ),
        "environments": conn.query(
            "SELECT environment, count(*) AS asset_count FROM assets "
            "WHERE application_id = ? GROUP BY environment",
            [app_id],
        ),
    }


def find_assets_by_software(
    product: str,
    version: str | None = None,
    ecosystem: str | None = None,
    limit: int = 200,
    db: Database | None = None,
) -> dict[str, Any]:
    """Which assets run a product, optionally pinned to one version."""
    conn = _db(db)
    clauses = ["lower(sw.product) = ?"]
    params: list[Any] = [product.strip().lower()]

    if version:
        clauses.append("sw.version = ?")
        params.append(version.strip())
    if ecosystem:
        clauses.append("lower(sw.ecosystem) = ?")
        params.append(ecosystem.strip().lower())

    rows = conn.query(
        "SELECT sw.sw_id, sw.ecosystem, sw.vendor, sw.product, sw.version, sw.purl, sw.cpe23, "
        "a.asset_id, a.hostname, a.environment, a.internet_facing, a.business_criticality, "
        "app.application_id, app.name AS application_name, app.tier, app.owner_team "
        "FROM software_inventory sw "
        "JOIN assets a ON a.asset_id = sw.asset_id "
        "LEFT JOIN applications app ON app.application_id = a.application_id "
        f"WHERE {' AND '.join(clauses)} "
        "ORDER BY app.tier NULLS LAST, a.internet_facing DESC "
        f"LIMIT {min(int(limit), MAX_ROWS)}",
        params,
    )

    versions = conn.query(
        "SELECT sw.version, count(*) AS install_count FROM software_inventory sw "
        "WHERE lower(sw.product) = ? GROUP BY sw.version ORDER BY install_count DESC",
        [product.strip().lower()],
    )

    return {
        "product": product,
        "version": version,
        "match_count": len(rows),
        "truncated": len(rows) >= min(int(limit), MAX_ROWS),
        "version_distribution": versions,
        "assets": rows,
    }


def get_business_context(asset_id: str, db: Database | None = None) -> dict[str, Any]:
    conn = _db(db)
    row = conn.query_one(
        "SELECT a.asset_id, a.hostname, a.environment, a.internet_facing, "
        "a.business_criticality, a.data_classification, a.owner, a.last_patch_date, "
        "a.compensating_controls, app.application_id, app.name AS application_name, "
        "app.business_service, app.tier, app.owner_team, app.owner_email, "
        "app.revenue_impact_band, app.external_customer_facing "
        "FROM assets a LEFT JOIN applications app ON app.application_id = a.application_id "
        "WHERE a.asset_id = ?",
        [asset_id.strip()],
    )
    return row or {"asset_id": asset_id, "found": False}


def get_findings_for_cve(
    cve_id: str, only_affected: bool = True, limit: int = 200, db: Database | None = None
) -> dict[str, Any]:
    """Blast radius for one CVE across the estate."""
    conn = _db(db)
    clauses = ["cve_id = ?", "status <> 'remediated'"]
    params: list[Any] = [cve_id.strip().upper()]
    if only_affected:
        clauses.append("version_verdict = 'affected'")

    rows = conn.query(
        "SELECT finding_id, asset_id, hostname, application_id, application_name, "
        "business_service, tier, environment, internet_facing, business_criticality, "
        "product, installed_version, fixed_version, version_verdict, match_path, "
        "match_confidence, score, sla_due_date, sla_breached, owner_team "
        f"FROM v_finding_enriched WHERE {' AND '.join(clauses)} "
        "ORDER BY score DESC NULLS LAST "
        f"LIMIT {min(int(limit), MAX_ROWS)}",
        params,
    )
    # Authoritative counts, computed over the whole result set rather than the
    # truncated row sample the caller receives. Callers must use these and never
    # recount the rows: the sample is capped at `limit`, so recounting silently
    # under-reports and puts two agents into disagreement.
    totals = (
        conn.query_one(
            """
        SELECT count(*)                                            AS total_findings,
               count(DISTINCT asset_id)                            AS distinct_assets,
               count(DISTINCT application_id)                      AS distinct_applications,
               sum(CASE WHEN internet_facing THEN 1 ELSE 0 END)    AS internet_facing,
               sum(CASE WHEN environment = 'production' THEN 1 ELSE 0 END) AS production,
               sum(CASE WHEN tier = 1 THEN 1 ELSE 0 END)           AS tier1,
               sum(CASE WHEN version_verdict = 'unknown' THEN 1 ELSE 0 END) AS unknown_count,
               sum(CASE WHEN version_verdict = 'affected' THEN 1 ELSE 0 END) AS affected_count
        FROM v_finding_enriched
        WHERE cve_id = ? AND status <> 'remediated'
        """,
            [cve_id.strip().upper()],
        )
        or {}
    )

    return {
        "cve_id": cve_id.strip().upper(),
        "authoritative_counts": {k: int(v or 0) for k, v in totals.items()},
        "affected_count": int(totals.get("affected_count") or 0),
        "unknown_count": int(totals.get("unknown_count") or 0),
        "rows_returned": len(rows),
        "truncated": len(rows) >= min(int(limit), MAX_ROWS),
        "findings": rows,
    }


def get_inventory_summary(db: Database | None = None) -> dict[str, Any]:
    conn = _db(db)
    return {
        "assets": conn.scalar("SELECT count(*) FROM assets"),
        "applications": conn.scalar("SELECT count(*) FROM applications"),
        "software_records": conn.scalar("SELECT count(*) FROM software_inventory"),
        "tier1_applications": conn.scalar("SELECT count(*) FROM applications WHERE tier = 1"),
        "internet_facing_assets": conn.scalar(
            "SELECT count(*) FROM assets WHERE internet_facing = TRUE"
        ),
        "by_environment": conn.query(
            "SELECT environment, count(*) AS n FROM assets GROUP BY environment ORDER BY n DESC"
        ),
    }
