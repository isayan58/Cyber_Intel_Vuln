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
    RangeResult,
    Verdict,
    in_cpe_range,
    in_osv_range,
    normalize_ecosystem,
)

log = get_logger(__name__)

# Ceiling on CPE ranges evaluated per installed component. A widely used
# product accumulates tens of thousands of ranges over its lifetime; the
# version comparison only needs enough to find a match.
MAX_CPE_CANDIDATES = 400

# How much more prolific the leading vendor must be before it is treated as
# the canonical publisher of a product name rather than one of several.
DOMINANT_VENDOR_RATIO = 3.0


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

        findings = _collapse(self._match_purl() + self._match_cpe())

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
                    "evidence_count": finding.pop("evidence_count", 1),
                    "match_paths": finding.pop("match_paths", finding.get("match_path")),
                }
            )
            next_id += 1

        self.db.execute("DELETE FROM vulnerability_finding")
        self.db.insert_many("vulnerability_finding", rows)

        counts = {
            "total": len(rows),
            "collapsed_from": sum(int(r.get("evidence_count") or 1) for r in rows),
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

                # The upgrade target is the fix belonging to the range that
                # actually matched this installed version — not an aggregate
                # over every range in the advisory. An advisory covering
                # several release branches carries several fixes; taking the
                # highest told a lodash 4.17.19 user to move to 4.18.0 when
                # 4.17.21 resolves it.
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
                        "fixed_version": verdict.fixed_version,
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
        # Two indexes, both built once. The product-only index is the important
        # one: vendor strings in an inventory rarely match NVD's vendor exactly,
        # so most rows fall through to it. Deriving that fallback by scanning
        # the vendor-keyed index per inventory row is quadratic — roughly six
        # billion dict visits against a real NVD corpus — and never completes.
        by_vendor_product: dict[tuple[str, str], list[dict[str, Any]]] = {}
        vendors_per_product: dict[str, dict[str, set[str]]] = {}
        for row in matches:
            vendor = (row["cpe_vendor"] or "").lower()
            product = (row["cpe_product"] or "").lower()
            by_vendor_product.setdefault((vendor, product), []).append(row)
            vendors_per_product.setdefault(product, {}).setdefault(vendor, set()).add(row["cve_id"])

        findings: list[dict[str, Any]] = []
        for item in inventory:
            vendor = (item.get("vendor") or "").lower().replace(" ", "_")
            product = (item.get("product") or "").lower().replace(" ", "_")

            candidates = by_vendor_product.get((vendor, product))
            ambiguous_vendor = False
            if candidates:
                confidence = float(item.get("cpe23_confidence") or 0.9)
            else:
                resolved, confidence, ambiguous_vendor = _resolve_vendor(
                    product, vendors_per_product.get(product, {})
                )
                candidates = by_vendor_product.get((resolved, product), []) if resolved else []

            # A single popular product can carry tens of thousands of CPE
            # ranges across its whole history. Comparing every one against one
            # installed version is wasted work, so cap the candidate set.
            if len(candidates) > MAX_CPE_CANDIDATES:
                candidates = candidates[:MAX_CPE_CANDIDATES]

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

                # Several unrelated vendors publish products under the same
                # name — NVD lists eleven distinct vendors for "http_server",
                # and Jenkins ships a plugin called "mongodb". When the vendor
                # could not be resolved, the version comparison may have run
                # against somebody else's software, so the result is reported
                # as unconfirmed rather than asserted as affected.
                if ambiguous_vendor and verdict.verdict is Verdict.AFFECTED:
                    verdict = RangeResult(
                        Verdict.UNKNOWN,
                        f"{verdict.reason}, but several vendors publish a product "
                        f"named '{product}' in NVD — needs manual confirmation",
                        verdict.fixed_version,
                    )

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
                        "fixed_version": verdict.fixed_version,
                        "scanner_confidence": 0.85,
                    }
                )
        return findings


def _resolve_vendor(product: str, vendors: dict[str, set[str]]) -> tuple[str | None, float, bool]:
    """Pick which vendor's ranges apply when inventory names no usable vendor.

    Product names are not unique in NVD. "http_server" is published by eleven
    vendors including Apache, Oracle and IBM; "mongodb" by MongoDB, Jenkins (a
    plugin) and anynines. Matching an installed version against every vendor's
    ranges manufactures findings for software the organisation does not run.

    Returns ``(vendor, confidence, ambiguous)``. Resolution order:

      1. a vendor with the same name as the product — the dominant CPE
         convention for first-party software (openssl/openssl, redis/redis)
      2. the only vendor, when there is exactly one
      3. the vendor with by far the most CVEs for that product, treated as the
         canonical publisher
      4. otherwise the largest, flagged ambiguous so the verdict is reported
         as unconfirmed rather than affected
    """
    if not vendors:
        return None, 0.0, False

    if product in vendors:
        return product, 0.75, False

    ranked = sorted(vendors.items(), key=lambda kv: len(kv[1]), reverse=True)
    if len(ranked) == 1:
        return ranked[0][0], 0.7, False

    top, runner_up = len(ranked[0][1]), len(ranked[1][1])
    if top >= runner_up * DOMINANT_VENDOR_RATIO:
        return ranked[0][0], 0.6, False

    return ranked[0][0], 0.35, True


def _collapse(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One finding per (asset, distinct vulnerability).

    Identity is the advisory, not the CVE. Several advisories can legitimately
    share a CVE alias while describing different flaws with different fixes —
    lodash CVE-2021-23337 aliases both GHSA-35jh-r3h4-6jhm (fixed 4.17.21) and
    GHSA-r5fr-rjxr-66jc (fixed 4.18.0). Collapsing those into one row and
    choosing the cheaper fix would report 4.17.21 as sufficient when it does
    not close the second issue. Under-reporting a fix is worse than showing two
    rows, so distinct advisories stay distinct.

    What does merge is the same advisory reaching an asset by more than one
    route — the purl and CPE paths both detecting it, or several inventory rows
    carrying the same component.

    Resolution rules, in order:
      * an ``affected`` verdict beats an ``unknown`` one
      * the highest match confidence wins the row's provenance
      * the fixed version is the *highest* among the merged rows, because the
        upgrade has to clear every issue folded into that row
    """
    from vulnintel.risk.versions import compare, is_parseable

    grouped: dict[tuple[Any, Any], list[dict[str, Any]]] = {}
    for finding in findings:
        # Advisory first: it is the finest-grained identity available, and two
        # advisories sharing a CVE are two different problems.
        key = (finding["asset_id"], finding.get("advisory_id") or finding.get("cve_id"))
        grouped.setdefault(key, []).append(finding)

    collapsed: list[dict[str, Any]] = []
    for group in grouped.values():
        if len(group) == 1:
            winner = dict(group[0])
            winner["evidence_count"] = 1
            winner["match_paths"] = winner["match_path"]
            collapsed.append(winner)
            continue

        # Prefer a confirmed verdict, then the strongest match.
        winner = dict(
            max(
                group,
                key=lambda f: (
                    f.get("version_verdict") == "affected",
                    float(f.get("match_confidence") or 0),
                    float(f.get("scanner_confidence") or 0),
                ),
            )
        )

        fixes = [f.get("fixed_version") for f in group if is_parseable(f.get("fixed_version"))]
        if fixes:
            # Highest, not lowest: whatever merged into this row must all be
            # cleared by the version we recommend.
            required = fixes[0]
            for candidate in fixes[1:]:
                try:
                    if compare(candidate, required) > 0:
                        required = candidate
                except Exception:  # noqa: BLE001 - an unparseable fix is skipped
                    continue
            winner["fixed_version"] = required

        winner["evidence_count"] = len(group)
        winner["match_paths"] = ",".join(sorted({f["match_path"] for f in group}))
        collapsed.append(winner)

    return collapsed


def _combine(results: list) -> Any:
    """Any affected range wins; otherwise unknown beats not-affected."""

    if not results:
        return RangeResult(Verdict.NOT_AFFECTED, "no candidate ranges")
    for result in results:
        if result.verdict is Verdict.AFFECTED:
            return result
    for result in results:
        if result.verdict is Verdict.UNKNOWN:
            return result
    return results[0]
