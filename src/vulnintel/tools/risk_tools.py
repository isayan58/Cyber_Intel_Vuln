"""Risk tools — ranking and score explanation.

These read ``finding_score`` rows written by the deterministic scorer. Nothing
here computes a score; ``explain_score`` reformats stored components, and
``rank_findings`` sorts by a stored column.
"""

from __future__ import annotations

import json
from typing import Any

from vulnintel.data.db import Database, get_db


def _db(db: Database | None) -> Database:
    return db or get_db()


def rank_findings(
    *,
    limit: int = 5,
    application_name: str | None = None,
    cve_id: str | None = None,
    environment: str | None = None,
    internet_facing_only: bool = False,
    kev_only: bool = False,
    tier: int | None = None,
    exclude_risk_accepted: bool = True,
    group_by_cve: bool = False,
    db: Database | None = None,
) -> dict[str, Any]:
    """Top findings by stored enterprise priority score."""
    conn = _db(db)
    clauses = ["version_verdict = 'affected'", "status <> 'remediated'", "score IS NOT NULL"]
    params: list[Any] = []

    if application_name:
        clauses.append("lower(application_name) LIKE ?")
        params.append(f"%{application_name.strip().lower()}%")
    if cve_id:
        clauses.append("cve_id = ?")
        params.append(cve_id.strip().upper())
    if environment:
        clauses.append("environment = ?")
        params.append(environment.strip().lower())
    if internet_facing_only:
        clauses.append("internet_facing = TRUE")
    if kev_only:
        clauses.append("kev_listed = TRUE")
    if tier is not None:
        clauses.append("tier = ?")
        params.append(int(tier))
    if exclude_risk_accepted:
        clauses.append("risk_accepted = FALSE")

    where = " AND ".join(clauses)

    if group_by_cve:
        # One row per CVE, keeping the worst-affected asset as the exemplar.
        rows = conn.query(
            f"""
            SELECT cve_id,
                   max(score)                     AS score,
                   count(*)                       AS finding_count,
                   count(DISTINCT asset_id)       AS asset_count,
                   count(DISTINCT application_id) AS application_count,
                   max(cvss_base)                 AS cvss_base,
                   max(epss)                      AS epss,
                   max(epss_percentile)           AS epss_percentile,
                   bool_or(kev_listed)            AS kev_listed,
                   bool_or(internet_facing)       AS any_internet_facing,
                   min(tier)                      AS best_tier,
                   min(sla_due_date)              AS earliest_due_date,
                   sum(CASE WHEN sla_breached THEN 1 ELSE 0 END) AS breached_count,
                   max(fixed_version)             AS fixed_version,
                   max(cve_description)           AS cve_description,
                   max(product)                   AS product
            FROM v_finding_enriched
            WHERE {where}
            GROUP BY cve_id
            ORDER BY score DESC
            LIMIT {int(limit)}
            """,
            params,
        )
        for row in rows:
            row["top_assets"] = conn.query(
                f"SELECT hostname, application_name, environment, internet_facing, "
                f"installed_version, fixed_version, score FROM v_finding_enriched "
                f"WHERE {where} AND cve_id = ? ORDER BY score DESC LIMIT 5",
                [*params, row["cve_id"]],
            )
        return {"mode": "by_cve", "count": len(rows), "findings": rows}

    rows = conn.query(
        f"""
        SELECT finding_id, cve_id, advisory_id, asset_id, hostname, application_id,
               application_name, business_service, tier, owner_team, environment,
               internet_facing, business_criticality, data_classification,
               product, ecosystem, installed_version, fixed_version,
               version_verdict, match_path, match_confidence,
               cvss_base, cvss_severity, cvss_provider, epss, epss_percentile,
               kev_listed, kev_date_added, known_ransomware_use,
               score, model_version, contributions, weights,
               sla_days, sla_due_date, sla_breached, age_days,
               cve_description
        FROM v_finding_enriched
        WHERE {where}
        ORDER BY score DESC
        LIMIT {int(limit)}
        """,
        params,
    )
    for row in rows:
        row["score_breakdown"] = _decode(row.get("contributions"))
        row["weights"] = _decode(row.get("weights"))
    return {"mode": "by_finding", "count": len(rows), "findings": rows}


def explain_score(finding_id: int, db: Database | None = None) -> dict[str, Any]:
    """Component-level breakdown for one finding, exactly as stored."""
    conn = _db(db)
    row = conn.query_one(
        "SELECT s.*, f.cve_id, f.advisory_id, f.asset_id, f.version_verdict, "
        "f.match_path, f.match_confidence "
        "FROM finding_score s JOIN vulnerability_finding f ON f.finding_id = s.finding_id "
        "WHERE s.finding_id = ?",
        [int(finding_id)],
    )
    if row is None:
        return {"finding_id": finding_id, "found": False}

    weights = _decode(row.get("weights")) or {}
    contributions = _decode(row.get("contributions")) or {}

    components = {
        "cvss": row.get("cvss_norm"),
        "epss": row.get("epss"),
        "kev": row.get("kev_flag"),
        "criticality": row.get("criticality"),
        "exposure": row.get("exposure"),
        "sensitivity": row.get("sensitivity"),
    }
    breakdown = [
        {
            "component": name,
            "normalised_value": components.get(name),
            "weight": weights.get(name),
            "contribution": contributions.get(name),
        }
        for name in weights
    ]

    return {
        "finding_id": finding_id,
        "found": True,
        "score": row.get("score"),
        "model_version": row.get("model_version"),
        "band": contributions.get("band"),
        "raw_cvss_base": row.get("cvss_base"),
        "epss_percentile": row.get("epss_percentile"),
        "breakdown": breakdown,
        "notes": contributions.get("notes", []),
        "sla_days": row.get("sla_days"),
        "sla_due_date": row.get("sla_due_date"),
        "sla_breached": row.get("sla_breached"),
        "age_days": row.get("age_days"),
        "version_verdict": row.get("version_verdict"),
        "match_path": row.get("match_path"),
        "match_confidence": row.get("match_confidence"),
    }


def patch_queue(
    capacity: int = 20,
    *,
    one_per_application: bool = False,
    db: Database | None = None,
) -> dict[str, Any]:
    """Which findings to schedule when capacity is limited (Demo 3).

    A deterministic greedy selection over the stored score, with SLA breaches
    promoted ahead of equal-scoring non-breaches. No model involved.
    """
    conn = _db(db)
    rows = conn.query(
        """
        SELECT finding_id, cve_id, asset_id, hostname, application_id, application_name,
               product, installed_version, fixed_version, score, kev_listed, epss,
               sla_due_date, sla_breached, age_days, environment, internet_facing, tier
        FROM v_finding_enriched
        WHERE version_verdict = 'affected' AND status <> 'remediated'
          AND risk_accepted = FALSE AND score IS NOT NULL
        ORDER BY sla_breached DESC, score DESC, age_days DESC NULLS LAST
        LIMIT 2000
        """
    )

    selected: list[dict[str, Any]] = []
    seen_apps: set[Any] = set()
    for row in rows:
        if len(selected) >= capacity:
            break
        if one_per_application and row["application_id"] in seen_apps:
            continue
        seen_apps.add(row["application_id"])
        selected.append(row)

    deferred = len(rows) - len(selected)
    return {
        "capacity": capacity,
        "selected_count": len(selected),
        "deferred_count": max(deferred, 0),
        "selection_rule": (
            "SLA breaches first, then descending enterprise priority score, "
            "then oldest finding. Deterministic — no model involvement."
        ),
        "queue": selected,
        "deferred_high_score": [r for r in rows[len(selected) :] if (r["score"] or 0) >= 70][:10],
    }


def portfolio_summary(db: Database | None = None) -> dict[str, Any]:
    """Estate-level roll-up for the dashboard."""
    conn = _db(db)
    base = "FROM v_finding_enriched WHERE version_verdict = 'affected' AND status <> 'remediated'"
    return {
        "open_findings": conn.scalar(f"SELECT count(*) {base}"),
        "distinct_cves": conn.scalar(f"SELECT count(DISTINCT cve_id) {base}"),
        "kev_findings": conn.scalar(f"SELECT count(*) {base} AND kev_listed = TRUE"),
        "internet_facing_findings": conn.scalar(f"SELECT count(*) {base} AND internet_facing = TRUE"),
        "sla_breaches": conn.scalar(f"SELECT count(*) {base} AND sla_breached = TRUE"),
        "unknown_verdicts": conn.scalar("SELECT count(*) FROM v_unknown_verdicts"),
        "max_score": conn.scalar(f"SELECT max(score) {base}"),
        "by_band": conn.query(
            f"""
            SELECT CASE
                     WHEN score >= 80 THEN 'P1'
                     WHEN score >= 60 THEN 'P2'
                     WHEN score >= 40 THEN 'P3'
                     ELSE 'P4' END AS band,
                   count(*) AS n
            {base} AND score IS NOT NULL
            GROUP BY band ORDER BY band
            """
        ),
        "top_applications": conn.query(
            "SELECT application_name, business_service, tier, open_findings, max_score, "
            "kev_findings, breached_findings FROM v_app_risk_summary "
            "ORDER BY max_score DESC NULLS LAST LIMIT 10"
        ),
    }


def _decode(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value
