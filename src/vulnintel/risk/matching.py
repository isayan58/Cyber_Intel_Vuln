"""Inventory -> vulnerability matching.

Two independent join paths, and the finding records which one produced it:

    purl  software_inventory.purl  -> advisory_affected  (OSV ranges)
    cpe   software_inventory.cpe23 -> cve_cpe_match      (NVD ranges)

Neither path covers everything, they are not interchangeable, and both can
produce an ``unknown`` verdict. Persisting ``match_path`` and
``match_confidence`` is what lets the critic agent challenge a finding and the
UI show why something is on the list.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from vulnintel.data.db import Database, get_db
from vulnintel.logging_setup import get_logger
from vulnintel.risk.versions import (
    Verdict,
    in_cpe_range,
    in_osv_range,
    lowest_fix,
    normalize_ecosystem,
)

log = get_logger(__name__)


def build_purl(ecosystem: str, name: str, version: str | None = None) -> str:
    """Package URL — the canonical key for OSV matching."""
    eco = normalize_ecosystem(ecosystem)
    type_map = {
        "pypi": "pypi",
        "npm": "npm",
        "maven": "maven",
        "go": "golang",
        "os": "generic",
        "generic": "generic",
    }
    purl = f"pkg:{type_map.get(eco, 'generic')}/{name.lower()}"
    if version:
        purl = f"{purl}@{version}"
    return purl


def build_cpe23(vendor: str, product: str, version: str) -> str:
    """A best-effort CPE 2.3 string for NVD matching."""

    def clean(value: str) -> str:
        return (value or "*").strip().lower().replace(" ", "_")

    return f"cpe:2.3:a:{clean(vendor)}:{clean(product)}:{clean(version)}:*:*:*:*:*:*:*"


def purl_base(purl: str | None) -> str | None:
    """Strip the @version suffix, keeping the qualifier-free base."""
    if not purl:
        return None
    base = purl.split("?", 1)[0].split("#", 1)[0]
    if "@" in base:
        base = base.rsplit("@", 1)[0]
    return base.lower()


class FindingMatcher:
    """Rebuilds ``vulnerability_finding`` from inventory and advisory data."""

    def __init__(self, db: Database | None = None) -> None:
        self.db = db or get_db()

    def rebuild(self, *, keep_history: bool = True) -> dict[str, int]:
        """Recompute all findings. Returns a per-path count."""
        previous: dict[tuple[Any, ...], dict[str, Any]] = {}
        if keep_history:
            for row in self.db.query(
                "SELECT finding_id, asset_id, sw_id, cve_id, advisory_id, first_seen, status "
                "FROM vulnerability_finding"
            ):
                previous[(row["asset_id"], row["sw_id"], row["cve_id"], row["advisory_id"])] = row

        findings = self._match_purl() + self._match_cpe()

        now = datetime.now(UTC).replace(tzinfo=None)
        rows: list[dict[str, Any]] = []
        next_id = 1
        for finding in findings:
            key = (
                finding["asset_id"],
                finding["sw_id"],
                finding.get("cve_id"),
                finding.get("advisory_id"),
            )
            prior = previous.get(key)
            rows.append(
                {
                    **finding,
                    "finding_id": next_id,
                    "detected_at": prior["first_seen"] if prior else now,
                    "first_seen": prior["first_seen"] if prior else now,
                    "last_seen": now,
                    "status": prior["status"] if prior else "open",
                    "scanner_confidence": finding.pop("scanner_confidence", 0.9),
                }
            )
            next_id += 1

        self.db.execute("DELETE FROM vulnerability_finding")
        self.db.insert_many("vulnerability_finding", rows)

        counts = {
            "total": len(rows),
            "purl": sum(1 for r in rows if r["match_path"] == "purl"),
            "cpe": sum(1 for r in rows if r["match_path"] == "cpe"),
            "affected": sum(1 for r in rows if r["version_verdict"] == "affected"),
            "unknown": sum(1 for r in rows if r["version_verdict"] == "unknown"),
            "not_affected": sum(1 for r in rows if r["version_verdict"] == "not_affected"),
        }
        log.info("matcher: %s", counts)
        return counts

    # -- purl / OSV path ------------------------------------------------------

    def _match_purl(self) -> list[dict[str, Any]]:
        inventory = self.db.query(
            "SELECT sw_id, asset_id, application_id, ecosystem, product, version, purl, "
            "purl_confidence FROM software_inventory WHERE purl IS NOT NULL"
        )
        if not inventory:
            return []

        ranges = self.db.query(
            "SELECT aa.advisory_id, aa.ecosystem, aa.package_name, aa.range_type, "
            "aa.introduced, aa.fixed, aa.last_affected, aa.explicit_versions "
            "FROM advisory_affected aa"
        )
        by_package: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for row in ranges:
            key = (normalize_ecosystem(row["ecosystem"]), (row["package_name"] or "").lower())
            by_package.setdefault(key, []).append(row)

        # A GHSA usually aliases one or more CVEs; carry the first CVE through.
        alias_map: dict[str, str] = {}
        for row in self.db.query(
            "SELECT advisory_id, alias FROM advisory_alias WHERE alias LIKE 'CVE-%'"
        ):
            alias_map.setdefault(row["advisory_id"], row["alias"])

        findings: list[dict[str, Any]] = []
        for item in inventory:
            key = (
                normalize_ecosystem(item["ecosystem"]),
                (item["product"] or "").lower(),
            )
            candidates = by_package.get(key, [])
            grouped: dict[str, list[dict[str, Any]]] = {}
            for candidate in candidates:
                grouped.setdefault(candidate["advisory_id"], []).append(candidate)

            for advisory_id, entries in grouped.items():
                verdicts = [
                    in_osv_range(
                        item["version"],
                        introduced=entry.get("introduced"),
                        fixed=entry.get("fixed"),
                        last_affected=entry.get("last_affected"),
                        explicit_versions=entry.get("explicit_versions"),
                        ecosystem=item["ecosystem"],
                    )
                    for entry in entries
                ]
                verdict = _combine(verdicts)
                if verdict.verdict is Verdict.NOT_AFFECTED:
                    continue

                fixes = [e.get("fixed") for e in entries if e.get("fixed")]
                findings.append(
                    {
                        "asset_id": item["asset_id"],
                        "application_id": item["application_id"],
                        "sw_id": item["sw_id"],
                        "cve_id": alias_map.get(advisory_id),
                        "advisory_id": advisory_id,
                        "match_path": "purl",
                        "match_confidence": float(item.get("purl_confidence") or 1.0),
                        "version_verdict": verdict.verdict.value,
                        "fixed_version": lowest_fix(fixes, item["ecosystem"]),
                        "scanner_confidence": 0.95,
                    }
                )
        return findings

    # -- cpe / NVD path -------------------------------------------------------

    def _match_cpe(self) -> list[dict[str, Any]]:
        inventory = self.db.query(
            "SELECT sw_id, asset_id, application_id, ecosystem, vendor, product, version, "
            "cpe23, cpe23_confidence FROM software_inventory WHERE cpe23 IS NOT NULL"
        )
        if not inventory:
            return []

        matches = self.db.query(
            "SELECT cve_id, cpe_vendor, cpe_product, cpe_version, version_start_including, "
            "version_start_excluding, version_end_including, version_end_excluding "
            "FROM cve_cpe_match WHERE vulnerable = TRUE"
        )
        by_product: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for row in matches:
            key = ((row["cpe_vendor"] or "").lower(), (row["cpe_product"] or "").lower())
            by_product.setdefault(key, []).append(row)

        findings: list[dict[str, Any]] = []
        for item in inventory:
            vendor = (item.get("vendor") or "").lower().replace(" ", "_")
            product = (item.get("product") or "").lower().replace(" ", "_")
            candidates = by_product.get((vendor, product), [])
            if not candidates:
                # Vendor strings are unreliable; fall back to product-only.
                candidates = [
                    row
                    for (v, p), rows in by_product.items()
                    if p == product
                    for row in rows
                ]
                confidence = 0.6
            else:
                confidence = float(item.get("cpe23_confidence") or 0.9)

            grouped: dict[str, list[dict[str, Any]]] = {}
            for candidate in candidates:
                grouped.setdefault(candidate["cve_id"], []).append(candidate)

            for cve_id, entries in grouped.items():
                verdicts = [
                    in_cpe_range(
                        item["version"],
                        version_start_including=entry.get("version_start_including"),
                        version_start_excluding=entry.get("version_start_excluding"),
                        version_end_including=entry.get("version_end_including"),
                        version_end_excluding=entry.get("version_end_excluding"),
                        cpe_version=entry.get("cpe_version"),
                        ecosystem=item["ecosystem"],
                    )
                    for entry in entries
                ]
                verdict = _combine(verdicts)
                if verdict.verdict is Verdict.NOT_AFFECTED:
                    continue

                fixes = [v.fixed_version for v in verdicts if v.fixed_version]
                findings.append(
                    {
                        "asset_id": item["asset_id"],
                        "application_id": item["application_id"],
                        "sw_id": item["sw_id"],
                        "cve_id": cve_id,
                        "advisory_id": None,
                        "match_path": "cpe",
                        "match_confidence": confidence,
                        "version_verdict": verdict.verdict.value,
                        "fixed_version": lowest_fix(fixes, item["ecosystem"]),
                        "scanner_confidence": 0.85,
                    }
                )
        return findings


def _combine(results: list) -> Any:
    """Any affected range wins; otherwise unknown beats not-affected."""
    from vulnintel.risk.versions import RangeResult

    if not results:
        return RangeResult(Verdict.NOT_AFFECTED, "no candidate ranges")
    for result in results:
        if result.verdict is Verdict.AFFECTED:
            return result
    for result in results:
        if result.verdict is Verdict.UNKNOWN:
            return result
    return results[0]
