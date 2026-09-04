"""NIST NVD CVE API 2.0 (design doc D1/D2/D3).

Two modes:

    backfill    paginate the whole corpus (slow — this is the one genuinely
                long step in the project; get a free API key first)
    incremental use ``lastModStartDate``/``lastModEndDate`` windows anchored on
                the previous successful run

NVD caps a modified-date window at 120 days, so incremental runs are chunked.
Each API page is written to bronze verbatim before any parsing happens.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

from vulnintel.config import get_settings
from vulnintel.ingest.base import IngestResult, Pipeline, parse_ts, utcnow
from vulnintel.ingest.http import nvd_client
from vulnintel.logging_setup import get_logger

log = get_logger(__name__)

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

MAX_WINDOW_DAYS = 120

# Preference order when several providers score the same CVE.
CVSS_VERSION_RANK = {"4.0": 0, "3.1": 1, "3.0": 2, "2.0": 3}

_METRIC_KEYS = (
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV2", "2.0"),
)


class NvdPipeline(Pipeline):
    source = "nvd"

    def fetch(
        self,
        *,
        backfill: bool = False,
        since: datetime | None = None,
        max_pages: int | None = None,
        **kwargs: Any,
    ) -> IngestResult:
        settings = get_settings()
        now = datetime.now(UTC)

        if backfill:
            partition = f"backfill={now.date().isoformat()}"
            windows: list[tuple[datetime | None, datetime | None]] = [(None, None)]
        else:
            start = since or self._default_since()
            partition = f"modified_window={start.date().isoformat()}_{now.date().isoformat()}"
            windows = self._chunk_windows(start, now)

        run_id = self.start_run(window_start=windows[0][0], window_end=now)
        total_records = 0
        page_no = 0

        try:
            with nvd_client() as client:
                for window_start, window_end in windows:
                    start_index = 0
                    while True:
                        params: dict[str, str] = {
                            "resultsPerPage": str(settings.nvd_page_size),
                            "startIndex": str(start_index),
                        }
                        if window_start and window_end:
                            params["lastModStartDate"] = _nvd_ts(window_start)
                            params["lastModEndDate"] = _nvd_ts(window_end)

                        response = client.get(NVD_API, params=params)
                        payload = response.content
                        body = json.loads(payload)

                        vulns = body.get("vulnerabilities", [])
                        total = int(body.get("totalResults", 0))
                        self.bronze.write(
                            self.source,
                            partition,
                            f"page_{page_no:05d}.json",
                            payload,
                            source_url=response.url.__str__(),
                            record_count=len(vulns),
                            http_status=response.status_code,
                            run_id=run_id,
                            extra={"start_index": start_index, "total_results": total},
                        )
                        total_records += len(vulns)
                        page_no += 1
                        log.info(
                            "NVD: page %d — %d records (%d/%d)",
                            page_no,
                            len(vulns),
                            start_index + len(vulns),
                            total,
                        )

                        start_index += len(vulns)
                        if not vulns or start_index >= total:
                            break
                        if max_pages and page_no >= max_pages:
                            log.warning("NVD: stopping early at max_pages=%d", max_pages)
                            break
                    if max_pages and page_no >= max_pages:
                        break
        except Exception as exc:
            self.finish_run(run_id, status="failed", error=str(exc))
            raise

        self.finish_run(run_id, rows_in=total_records)
        return IngestResult(self.source, run_id, partition, rows_in=total_records)

    def transform(self, partition: str | None = None, **kwargs: Any) -> IngestResult:
        partition = self.resolve_partition(partition)
        pages = self.bronze.files_in(self.source, partition, suffix=".json.gz")
        pages += self.bronze.files_in(self.source, partition, suffix=".json")
        if not pages:
            raise FileNotFoundError(f"No NVD pages in bronze partition {partition}")

        run_id = self.start_run(notes={"partition": partition})
        retrieved = utcnow()

        cves: list[dict[str, Any]] = []
        cvss: list[dict[str, Any]] = []
        cwes: list[dict[str, Any]] = []
        refs: list[dict[str, Any]] = []
        matches: list[dict[str, Any]] = []
        seen_refs: set[tuple[str, str]] = set()

        for page in sorted(set(pages)):
            body = json.loads(self.bronze.read(self.source, partition, page.name))
            for item in body.get("vulnerabilities", []):
                cve = item.get("cve") or {}
                cve_id = (cve.get("id") or "").strip().upper()
                if not cve_id:
                    continue

                cves.append(
                    {
                        "cve_id": cve_id,
                        "published_at": parse_ts(cve.get("published")),
                        "last_modified_at": parse_ts(cve.get("lastModified")),
                        "vuln_status": cve.get("vulnStatus"),
                        "description": _english(cve.get("descriptions", [])),
                        "source_identifier": cve.get("sourceIdentifier"),
                        "configurations_raw": json.dumps(cve.get("configurations", [])),
                        "source_run_id": run_id,
                        "retrieved_at": retrieved,
                    }
                )
                cvss.extend(_extract_cvss(cve_id, cve.get("metrics", {})))
                cwes.extend(_extract_cwe(cve_id, cve.get("weaknesses", [])))
                for ref in _extract_refs(cve_id, cve.get("references", [])):
                    key = (ref["cve_id"], ref["url"])
                    if key not in seen_refs:
                        seen_refs.add(key)
                        refs.append(ref)
                matches.extend(_extract_cpe(cve_id, cve.get("configurations", [])))

        written = self.db.upsert("cve", cves, key_columns=("cve_id",))

        # Child rows are fully replaced per CVE so a re-parse never duplicates.
        cve_ids = [[c["cve_id"]] for c in cves]
        for table in ("cve_cvss", "cve_cwe", "cve_reference", "cve_cpe_match"):
            self.db.executemany(f"DELETE FROM {table} WHERE cve_id = ?", cve_ids)

        self.db.insert_many("cve_cvss", cvss)
        self.db.insert_many("cve_cwe", cwes)
        self.db.insert_many("cve_reference", refs)
        self.db.insert_many("cve_cpe_match", matches)

        self.finish_run(run_id, rows_in=len(cves), rows_out=written)
        log.info(
            "NVD: %d CVEs, %d CVSS rows, %d CPE matches from %s",
            len(cves),
            len(cvss),
            len(matches),
            partition,
        )
        return IngestResult(self.source, run_id, partition, rows_in=len(cves), rows_out=written)

    # -- helpers --------------------------------------------------------------

    def _default_since(self) -> datetime:
        last = self.last_successful_run()
        if last and last.get("window_end"):
            anchor = last["window_end"]
            if isinstance(anchor, datetime):
                return anchor.replace(tzinfo=UTC) - timedelta(hours=1)
        return datetime.now(UTC) - timedelta(days=7)

    @staticmethod
    def _chunk_windows(
        start: datetime, end: datetime
    ) -> list[tuple[datetime | None, datetime | None]]:
        windows: list[tuple[datetime | None, datetime | None]] = []
        cursor = start
        while cursor < end:
            stop = min(cursor + timedelta(days=MAX_WINDOW_DAYS), end)
            windows.append((cursor, stop))
            cursor = stop
        return windows or [(start, end)]


def _nvd_ts(value: datetime) -> str:
    """NVD wants ISO-8601 with milliseconds and no timezone suffix beyond offset."""
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000")


def _english(descriptions: list[dict[str, Any]]) -> str | None:
    for entry in descriptions:
        if entry.get("lang") == "en":
            return entry.get("value")
    return descriptions[0].get("value") if descriptions else None


def _extract_cvss(cve_id: str, metrics: dict[str, Any]) -> list[dict[str, Any]]:
    """Keep every provider's score. Precedence is applied at query time, not here."""
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for key, version in _METRIC_KEYS:
        for metric in metrics.get(key, []) or []:
            data = metric.get("cvssData", {})
            provider = metric.get("source") or "unknown"
            metric_type = metric.get("type") or "Primary"
            resolved_version = data.get("version") or version
            dedup = (cve_id, resolved_version, provider, metric_type)
            if dedup in seen:
                continue
            seen.add(dedup)
            rows.append(
                {
                    "cve_id": cve_id,
                    "cvss_version": resolved_version,
                    "provider": provider,
                    "metric_type": metric_type,
                    "vector_string": data.get("vectorString"),
                    "base_score": _as_float(data.get("baseScore")),
                    "base_severity": data.get("baseSeverity") or metric.get("baseSeverity"),
                    "exploitability": _as_float(metric.get("exploitabilityScore")),
                    "impact": _as_float(metric.get("impactScore")),
                }
            )
    return rows


def _extract_cwe(cve_id: str, weaknesses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for weakness in weaknesses:
        provider = weakness.get("source") or "unknown"
        for desc in weakness.get("description", []) or []:
            value = (desc.get("value") or "").strip()
            if not value.startswith("CWE-"):
                continue
            key = (cve_id, value, provider)
            if key in seen:
                continue
            seen.add(key)
            rows.append({"cve_id": cve_id, "cwe_id": value, "provider": provider})
    return rows


def _extract_refs(cve_id: str, references: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "cve_id": cve_id,
            "url": ref.get("url"),
            "source": ref.get("source"),
            "tags": ",".join(ref.get("tags", []) or []),
        }
        for ref in references
        if ref.get("url")
    ]


def _extract_cpe(cve_id: str, configurations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Flatten the configuration tree, preserving node/match ordinals.

    The unflattened tree is also kept on ``cve.configurations_raw`` — the first
    time this flattening turns out to be wrong, the fix is a re-parse, not a
    re-download.
    """
    rows: list[dict[str, Any]] = []
    node_ordinal = 0
    for config in configurations or []:
        for node in config.get("nodes", []) or []:
            match_ordinal = 0
            for match in node.get("cpeMatch", []) or []:
                criteria = match.get("criteria") or ""
                parts = criteria.split(":") if criteria.startswith("cpe:2.3:") else []
                rows.append(
                    {
                        "cve_id": cve_id,
                        "node_ordinal": node_ordinal,
                        "match_ordinal": match_ordinal,
                        "operator": node.get("operator"),
                        "negate": bool(node.get("negate", False)),
                        "vulnerable": bool(match.get("vulnerable", False)),
                        "criteria": criteria,
                        "cpe_part": parts[2] if len(parts) > 2 else None,
                        "cpe_vendor": parts[3] if len(parts) > 3 else None,
                        "cpe_product": parts[4] if len(parts) > 4 else None,
                        "cpe_version": parts[5] if len(parts) > 5 else None,
                        "cpe_update": parts[6] if len(parts) > 6 else None,
                        "version_start_including": match.get("versionStartIncluding"),
                        "version_start_excluding": match.get("versionStartExcluding"),
                        "version_end_including": match.get("versionEndIncluding"),
                        "version_end_excluding": match.get("versionEndExcluding"),
                    }
                )
                match_ordinal += 1
            node_ordinal += 1
    return rows


def _as_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
