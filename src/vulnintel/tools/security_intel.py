"""Security intelligence tools — read-only access to normalised public feeds.

These are the functions behind ``security-intel-mcp``. They are plain Python
with typed signatures and JSON-serialisable returns, which is what lets the
same implementation serve the in-process agent path and the MCP protocol path
without a second codebase.

Every tool is read-only. Nothing here writes, patches, scans or contacts a
target system.
"""

from __future__ import annotations

from typing import Any

from vulnintel.data.db import Database, get_db

MAX_ROWS = 500


def _db(db: Database | None) -> Database:
    return db or get_db()


def get_cve(cve_id: str, db: Database | None = None) -> dict[str, Any]:
    """Full normalised record for one CVE, including every provider's CVSS."""
    conn = _db(db)
    cve_id = cve_id.strip().upper()

    record = conn.query_one(
        "SELECT cve_id, published_at, last_modified_at, vuln_status, description, "
        "source_identifier, retrieved_at FROM cve WHERE cve_id = ?",
        [cve_id],
    )
    if record is None:
        return {"cve_id": cve_id, "found": False}

    record["found"] = True
    record["cvss_metrics"] = conn.query(
        "SELECT cvss_version, provider, metric_type, vector_string, base_score, base_severity "
        "FROM cve_cvss WHERE cve_id = ? ORDER BY cvss_version DESC, metric_type",
        [cve_id],
    )
    record["cvss_effective"] = conn.query_one(
        "SELECT cvss_version, provider, base_score, base_severity, vector_string "
        "FROM v_cve_cvss_effective WHERE cve_id = ?",
        [cve_id],
    )
    record["disagreements"] = conn.query(
        "SELECT provider_a, score_a, provider_b, score_b, delta "
        "FROM v_cvss_disagreement WHERE cve_id = ?",
        [cve_id],
    )
    record["cwes"] = [
        r["cwe_id"] for r in conn.query("SELECT DISTINCT cwe_id FROM cve_cwe WHERE cve_id = ?", [cve_id])
    ]
    record["references"] = conn.query(
        "SELECT url, source, tags FROM cve_reference WHERE cve_id = ? LIMIT 25", [cve_id]
    )
    record["cpe_ranges"] = conn.query(
        "SELECT cpe_vendor, cpe_product, cpe_version, version_start_including, "
        "version_start_excluding, version_end_including, version_end_excluding "
        "FROM cve_cpe_match WHERE cve_id = ? AND vulnerable = TRUE LIMIT 100",
        [cve_id],
    )
    record["aliases"] = [
        r["advisory_id"]
        for r in conn.query("SELECT advisory_id FROM advisory_alias WHERE alias = ?", [cve_id])
    ]
    return record


def search_cves(
    *,
    product: str | None = None,
    vendor: str | None = None,
    min_cvss: float | None = None,
    kev_only: bool = False,
    min_epss: float | None = None,
    cwe: str | None = None,
    limit: int = 50,
    db: Database | None = None,
) -> list[dict[str, Any]]:
    """Filtered CVE search over the normalised warehouse."""
    conn = _db(db)
    clauses: list[str] = []
    params: list[Any] = []

    sql = [
        "SELECT DISTINCT c.cve_id, c.description, c.published_at, c.last_modified_at,",
        "       eff.base_score, eff.base_severity,",
        "       e.probability AS epss, e.percentile AS epss_percentile,",
        "       CASE WHEN k.cve_id IS NULL THEN FALSE ELSE TRUE END AS kev_listed",
        "FROM cve c",
        "LEFT JOIN v_cve_cvss_effective eff ON eff.cve_id = c.cve_id",
        "LEFT JOIN epss_current e ON e.cve_id = c.cve_id",
        "LEFT JOIN kev k ON k.cve_id = c.cve_id AND k.valid_to IS NULL",
    ]

    if product or vendor:
        sql.append("JOIN cve_cpe_match m ON m.cve_id = c.cve_id AND m.vulnerable = TRUE")
        if product:
            clauses.append("lower(m.cpe_product) = ?")
            params.append(product.strip().lower().replace(" ", "_"))
        if vendor:
            clauses.append("lower(m.cpe_vendor) = ?")
            params.append(vendor.strip().lower().replace(" ", "_"))

    if cwe:
        sql.append("JOIN cve_cwe w ON w.cve_id = c.cve_id")
        clauses.append("w.cwe_id = ?")
        params.append(cwe.strip().upper())

    if min_cvss is not None:
        clauses.append("eff.base_score >= ?")
        params.append(float(min_cvss))
    if min_epss is not None:
        clauses.append("e.probability >= ?")
        params.append(float(min_epss))
    if kev_only:
        clauses.append("k.cve_id IS NOT NULL")

    if clauses:
        sql.append("WHERE " + " AND ".join(clauses))
    sql.append("ORDER BY eff.base_score DESC NULLS LAST, e.probability DESC NULLS LAST")
    sql.append(f"LIMIT {min(int(limit), MAX_ROWS)}")

    return conn.query("\n".join(sql), params)


def get_kev_status(cve_ids: list[str], db: Database | None = None) -> dict[str, Any]:
    """Current KEV membership, plus the date each entry entered the catalogue."""
    conn = _db(db)
    ids = [c.strip().upper() for c in cve_ids if c and c.strip()]
    if not ids:
        return {"listed": [], "not_listed": [], "detail": {}}

    placeholders = ", ".join("?" for _ in ids)
    rows = conn.query(
        f"SELECT cve_id, date_added, due_date, vendor_project, product, required_action, "
        f"known_ransomware_use, valid_from FROM kev "
        f"WHERE cve_id IN ({placeholders}) AND valid_to IS NULL",
        ids,
    )
    detail = {row["cve_id"]: row for row in rows}
    return {
        "listed": sorted(detail),
        "not_listed": sorted(set(ids) - set(detail)),
        "detail": detail,
    }


def get_epss(cve_ids: list[str], db: Database | None = None) -> dict[str, Any]:
    """Current EPSS probability and percentile.

    A CVE absent from the response is *unscored*, which is not the same as
    low risk. The caller is expected to preserve that distinction.
    """
    conn = _db(db)
    ids = [c.strip().upper() for c in cve_ids if c and c.strip()]
    if not ids:
        return {"scores": {}, "unscored": [], "score_date": None}

    placeholders = ", ".join("?" for _ in ids)
    rows = conn.query(
        f"SELECT cve_id, probability, percentile, score_date FROM epss_current "
        f"WHERE cve_id IN ({placeholders})",
        ids,
    )
    scores = {row["cve_id"]: row for row in rows}
    return {
        "scores": scores,
        "unscored": sorted(set(ids) - set(scores)),
        "score_date": rows[0]["score_date"] if rows else None,
    }


def get_epss_history(cve_id: str, days: int = 90, db: Database | None = None) -> list[dict[str, Any]]:
    """EPSS trend from the rolling window kept in the warehouse."""
    conn = _db(db)
    return conn.query(
        "SELECT score_date, probability, percentile FROM epss_history "
        "WHERE cve_id = ? ORDER BY score_date DESC LIMIT ?",
        [cve_id.strip().upper(), int(days)],
    )


def get_package_advisories(
    ecosystem: str, package: str, version: str | None = None, db: Database | None = None
) -> dict[str, Any]:
    """Advisories for a package, with the version verdict when a version is given."""
    from vulnintel.risk.versions import in_osv_range, normalize_ecosystem

    conn = _db(db)
    rows = conn.query(
        "SELECT a.advisory_id, a.summary, a.severity_vector, a.published_at, a.modified_at, "
        "aa.range_type, aa.introduced, aa.fixed, aa.last_affected, aa.explicit_versions "
        "FROM advisory_affected aa "
        "JOIN advisory a ON a.advisory_id = aa.advisory_id "
        "WHERE lower(aa.package_name) = ? AND lower(aa.ecosystem) = lower(?) "
        "AND a.withdrawn_at IS NULL",
        [package.strip().lower(), ecosystem.strip()],
    )

    grouped: dict[str, dict[str, Any]] = {}
    for row in rows:
        entry = grouped.setdefault(
            row["advisory_id"],
            {
                "advisory_id": row["advisory_id"],
                "summary": row["summary"],
                "severity_vector": row["severity_vector"],
                "published_at": row["published_at"],
                "modified_at": row["modified_at"],
                "ranges": [],
                "aliases": [],
            },
        )
        entry["ranges"].append(
            {
                "range_type": row["range_type"],
                "introduced": row["introduced"],
                "fixed": row["fixed"],
                "last_affected": row["last_affected"],
            }
        )

    for advisory_id, entry in grouped.items():
        entry["aliases"] = [
            r["alias"]
            for r in conn.query(
                "SELECT alias FROM advisory_alias WHERE advisory_id = ?", [advisory_id]
            )
        ]
        if version:
            verdicts = [
                in_osv_range(
                    version,
                    introduced=r.get("introduced"),
                    fixed=r.get("fixed"),
                    last_affected=r.get("last_affected"),
                    ecosystem=normalize_ecosystem(ecosystem),
                )
                for r in entry["ranges"]
            ]
            affected = next((v for v in verdicts if v.verdict.value == "affected"), None)
            unknown = next((v for v in verdicts if v.verdict.value == "unknown"), None)
            chosen = affected or unknown or verdicts[0]
            entry["version_verdict"] = chosen.verdict.value
            entry["verdict_reason"] = chosen.reason
            entry["fixed_version"] = chosen.fixed_version

    advisories = list(grouped.values())
    if version:
        advisories = [a for a in advisories if a.get("version_verdict") != "not_affected"]

    return {
        "ecosystem": ecosystem,
        "package": package,
        "version": version,
        "advisory_count": len(advisories),
        "advisories": advisories[:MAX_ROWS],
    }


def get_attack_context(
    cve_ids: list[str] | None = None,
    attack_ids: list[str] | None = None,
    db: Database | None = None,
) -> dict[str, Any]:
    """Candidate ATT&CK techniques with their derivation basis and confidence.

    Mappings are always returned with ``basis`` and ``confidence`` so the
    caller can drop weak ones. The platform never asserts a CVE-to-technique
    link as fact — ATT&CK does not publish one.
    """
    conn = _db(db)
    result: dict[str, Any] = {"mappings": [], "techniques": {}, "mitigations": {}}

    resolved_ids = set(attack_ids or [])
    if cve_ids:
        ids = [c.strip().upper() for c in cve_ids if c and c.strip()]
        if ids:
            placeholders = ", ".join("?" for _ in ids)
            mappings = conn.query(
                f"SELECT cve_id, attack_id, confidence, basis, evidence FROM attack_mapping "
                f"WHERE cve_id IN ({placeholders}) ORDER BY confidence DESC",
                ids,
            )
            result["mappings"] = mappings
            resolved_ids.update(m["attack_id"] for m in mappings)

    for attack_id in sorted(resolved_ids):
        technique = conn.query_one(
            "SELECT stix_id, attack_id, name, description, tactics, platforms, is_subtechnique "
            "FROM attack_object WHERE attack_id = ? AND object_type = 'attack-pattern' "
            "AND revoked = FALSE",
            [attack_id],
        )
        if technique is None:
            continue
        if technique.get("description"):
            technique["description"] = technique["description"][:800]
        result["techniques"][attack_id] = technique

        result["mitigations"][attack_id] = conn.query(
            "SELECT m.attack_id, m.name, substr(m.description, 1, 400) AS description "
            "FROM attack_relationship r "
            "JOIN attack_object m ON m.stix_id = r.source_ref "
            "WHERE r.target_ref = ? AND r.relationship_type = 'mitigates' "
            "AND m.object_type = 'course-of-action' LIMIT 10",
            [technique["stix_id"]],
        )

    return result


def get_feed_freshness(db: Database | None = None) -> list[dict[str, Any]]:
    """Last successful ingestion per feed — used for stale-intelligence checks."""
    return _db(db).query("SELECT * FROM v_feed_freshness ORDER BY source")
