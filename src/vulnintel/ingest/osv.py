"""OSV package advisories (design doc D14, with D12/D13 as the bulk source).

Advisories live in their own identity namespace joined to CVEs by aliases —
a GHSA can map to zero, one or several CVEs, so ``advisory_alias`` is a table
rather than a column.

Two access paths, both supported:

    bulk    per-ecosystem ``all.zip`` from the OSV mirror (used for ingestion)
    query   ``/v1/querybatch`` for on-demand package/version lookups (used by
            the vulnerability-intelligence agent when inventory has a package
            the bulk load did not cover)
"""

from __future__ import annotations

import io
import json
import zipfile
from typing import Any

from vulnintel.ingest.base import IngestResult, Pipeline, parse_ts, utcnow
from vulnintel.ingest.http import FeedClient
from vulnintel.logging_setup import get_logger

log = get_logger(__name__)

OSV_BULK = "https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip"
OSV_QUERY_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_QUERY = "https://api.osv.dev/v1/query"

DEFAULT_ECOSYSTEMS = ("PyPI", "npm", "Maven", "Go")


class OsvPipeline(Pipeline):
    source = "osv"

    def fetch(
        self, *, ecosystems: tuple[str, ...] = DEFAULT_ECOSYSTEMS, **kwargs: Any
    ) -> IngestResult:
        partition = self.today_partition()
        run_id = self.start_run(notes={"ecosystems": list(ecosystems)})
        total = 0

        try:
            with FeedClient() as client:
                for ecosystem in ecosystems:
                    url = OSV_BULK.format(ecosystem=ecosystem)
                    log.info("OSV: downloading %s bulk archive", ecosystem)
                    payload = client.get_bytes(url)
                    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                        count = sum(1 for n in archive.namelist() if n.endswith(".json"))
                    self.bronze.write(
                        self.source,
                        partition,
                        f"{ecosystem}.zip",
                        payload,
                        source_url=url,
                        compress=False,
                        record_count=count,
                        run_id=run_id,
                        extra={"ecosystem": ecosystem},
                    )
                    total += count
                    log.info("OSV: %s — %d advisories", ecosystem, count)
        except Exception as exc:
            self.finish_run(run_id, status="failed", error=str(exc))
            raise

        self.finish_run(run_id, rows_in=total)
        return IngestResult(self.source, run_id, partition, rows_in=total)

    def transform(self, partition: str | None = None, **kwargs: Any) -> IngestResult:
        partition = self.resolve_partition(partition)
        archives = self.bronze.files_in(self.source, partition, suffix=".zip")
        if not archives:
            raise FileNotFoundError(f"No OSV archives in bronze partition {partition}")

        run_id = self.start_run(notes={"partition": partition})
        retrieved = utcnow()

        advisories: list[dict[str, Any]] = []
        aliases: list[dict[str, Any]] = []
        affected: list[dict[str, Any]] = []

        for archive_path in archives:
            with zipfile.ZipFile(archive_path) as archive:
                for name in archive.namelist():
                    if not name.endswith(".json"):
                        continue
                    record = json.loads(archive.read(name))
                    parsed = parse_osv_record(record, run_id=run_id, retrieved_at=retrieved)
                    if parsed is None:
                        continue
                    advisories.append(parsed["advisory"])
                    aliases.extend(parsed["aliases"])
                    affected.extend(parsed["affected"])

        written = self._write(advisories, aliases, affected)
        self.finish_run(run_id, rows_in=len(advisories), rows_out=written)
        log.info(
            "OSV: %d advisories, %d aliases, %d affected ranges",
            len(advisories),
            len(aliases),
            len(affected),
        )
        return IngestResult(
            self.source, run_id, partition, rows_in=len(advisories), rows_out=written
        )

    def _write(
        self,
        advisories: list[dict[str, Any]],
        aliases: list[dict[str, Any]],
        affected: list[dict[str, Any]],
    ) -> int:
        if not advisories:
            return 0
        written = self.db.upsert("advisory", advisories, key_columns=("advisory_id",))
        ids = [[a["advisory_id"]] for a in advisories]
        self.db.executemany("DELETE FROM advisory_alias WHERE advisory_id = ?", ids)
        self.db.executemany("DELETE FROM advisory_affected WHERE advisory_id = ?", ids)
        # Child rows inherit the parent's duplicates, so they are written
        # through the key-aware path too.
        self.db.upsert("advisory_alias", aliases, key_columns=("advisory_id", "alias"))
        self.db.upsert(
            "advisory_affected", affected, key_columns=("advisory_id", "range_ordinal")
        )
        return written

    # -- on-demand ------------------------------------------------------------

    def query_packages(
        self, packages: list[tuple[str, str, str]], persist: bool = True
    ) -> list[dict[str, Any]]:
        """Batch-query OSV for ``(ecosystem, name, version)`` triples."""
        if not packages:
            return []
        queries = [
            {"package": {"ecosystem": eco, "name": name}, "version": version}
            for eco, name, version in packages
        ]
        with FeedClient() as client:
            response = client._client.post(  # noqa: SLF001 - single POST use-site
                OSV_QUERY_BATCH, json={"queries": queries}, timeout=60.0
            )
            response.raise_for_status()
            results = response.json().get("results", [])

            ids: list[str] = []
            for entry in results:
                ids.extend(v["id"] for v in entry.get("vulns", []) or [])

            records = []
            for advisory_id in dict.fromkeys(ids):
                detail = client.get_json(f"https://api.osv.dev/v1/vulns/{advisory_id}")
                records.append(detail)

        if persist and records:
            run_id = self.start_run(notes={"mode": "on-demand", "count": len(records)})
            retrieved = utcnow()
            advisories, aliases, affected = [], [], []
            for record in records:
                parsed = parse_osv_record(record, run_id=run_id, retrieved_at=retrieved)
                if parsed:
                    advisories.append(parsed["advisory"])
                    aliases.extend(parsed["aliases"])
                    affected.extend(parsed["affected"])
            self._write(advisories, aliases, affected)
            self.finish_run(run_id, rows_in=len(records), rows_out=len(advisories))

        return records


def parse_osv_record(
    record: dict[str, Any], run_id: int | None, retrieved_at: Any
) -> dict[str, Any] | None:
    """Normalise one OSV JSON record into warehouse rows."""
    advisory_id = record.get("id")
    if not advisory_id:
        return None

    severity_vector, severity_score = _severity(record.get("severity", []))
    advisory = {
        "advisory_id": advisory_id,
        "source": "ghsa" if advisory_id.startswith("GHSA-") else "osv",
        "summary": record.get("summary"),
        "details": record.get("details"),
        "severity_vector": severity_vector,
        "severity_score": severity_score,
        "published_at": parse_ts(record.get("published")),
        "modified_at": parse_ts(record.get("modified")),
        "withdrawn_at": parse_ts(record.get("withdrawn")),
        "raw": json.dumps(record),
        "source_run_id": run_id,
        "retrieved_at": retrieved_at,
    }

    aliases = [
        {"advisory_id": advisory_id, "alias": alias}
        for alias in dict.fromkeys(record.get("aliases", []) or [])
    ]

    affected: list[dict[str, Any]] = []
    ordinal = 0
    for entry in record.get("affected", []) or []:
        package = entry.get("package", {}) or {}
        ecosystem = package.get("ecosystem") or "unknown"
        name = package.get("name") or "unknown"
        purl = package.get("purl")
        explicit = ",".join(entry.get("versions", []) or [])

        ranges = entry.get("ranges", []) or []
        if not ranges:
            # Some records enumerate versions without a range.
            affected.append(
                {
                    "advisory_id": advisory_id,
                    "range_ordinal": ordinal,
                    "ecosystem": ecosystem,
                    "package_name": name,
                    "purl": purl,
                    "range_type": None,
                    "introduced": None,
                    "fixed": None,
                    "last_affected": None,
                    "explicit_versions": explicit,
                }
            )
            ordinal += 1
            continue

        for range_entry in ranges:
            range_type = range_entry.get("type")
            introduced = fixed = last_affected = None
            for event in range_entry.get("events", []) or []:
                if "introduced" in event:
                    # A new introduced event starts a new interval.
                    if introduced is not None:
                        affected.append(
                            {
                                "advisory_id": advisory_id,
                                "range_ordinal": ordinal,
                                "ecosystem": ecosystem,
                                "package_name": name,
                                "purl": purl,
                                "range_type": range_type,
                                "introduced": introduced,
                                "fixed": fixed,
                                "last_affected": last_affected,
                                "explicit_versions": explicit,
                            }
                        )
                        ordinal += 1
                        fixed = last_affected = None
                    introduced = event["introduced"]
                elif "fixed" in event:
                    fixed = event["fixed"]
                elif "last_affected" in event:
                    last_affected = event["last_affected"]

            affected.append(
                {
                    "advisory_id": advisory_id,
                    "range_ordinal": ordinal,
                    "ecosystem": ecosystem,
                    "package_name": name,
                    "purl": purl,
                    "range_type": range_type,
                    "introduced": introduced,
                    "fixed": fixed,
                    "last_affected": last_affected,
                    "explicit_versions": explicit,
                }
            )
            ordinal += 1

    return {"advisory": advisory, "aliases": aliases, "affected": affected}


def _severity(entries: list[dict[str, Any]]) -> tuple[str | None, float | None]:
    for entry in entries or []:
        score = entry.get("score")
        if isinstance(score, str) and score.startswith("CVSS:"):
            return score, None
        if isinstance(score, int | float):
            return None, float(score)
    return None, None
