"""CISA Known Exploited Vulnerabilities (design doc D4/D5/D6).

KEV is small (a few thousand entries) but it is the single strongest urgency
signal in the risk model, so it is stored as a slowly-changing dimension:
``valid_to IS NULL`` means "in the catalog right now", and closed rows record
when an entry left. That history is what makes "this became known-exploited
on Tuesday" answerable instead of guesswork.
"""

from __future__ import annotations

import json
from datetime import UTC, date, datetime
from typing import Any

from vulnintel.ingest.base import IngestResult, Pipeline
from vulnintel.ingest.http import FeedClient
from vulnintel.logging_setup import get_logger

log = get_logger(__name__)

# Primary is CISA itself; the cisagov GitHub mirror is the documented fallback.
KEV_URLS = [
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
]

FILENAME = "known_exploited_vulnerabilities.json"

# Fields that, when changed, close the current row and open a new one.
_TRACKED = (
    "date_added",
    "due_date",
    "vendor_project",
    "product",
    "vulnerability_name",
    "short_description",
    "required_action",
    "known_ransomware_use",
    "notes",
)


def _as_date(value: Any) -> date | None:
    if not value:
        return None
    if isinstance(value, date):
        return value
    try:
        return datetime.strptime(str(value)[:10], "%Y-%m-%d").date()
    except ValueError:
        return None


def _ransomware_flag(value: Any) -> bool:
    return str(value or "").strip().lower() == "known"


class KevPipeline(Pipeline):
    source = "kev"

    def fetch(self, **kwargs: Any) -> IngestResult:
        partition = self.today_partition()
        run_id = self.start_run()
        last_error: Exception | None = None

        with FeedClient() as client:
            for url in KEV_URLS:
                try:
                    response = client.get(url)
                except Exception as exc:  # noqa: BLE001 - try the next mirror
                    log.warning("KEV fetch failed from %s: %s", url, exc)
                    last_error = exc
                    continue

                payload = response.content
                catalog = json.loads(payload)
                count = len(catalog.get("vulnerabilities", []))
                path, manifest = self.bronze.write(
                    self.source,
                    partition,
                    FILENAME,
                    payload,
                    source_url=url,
                    record_count=count,
                    http_status=response.status_code,
                    run_id=run_id,
                    extra={
                        "catalog_version": catalog.get("catalogVersion"),
                        "date_released": catalog.get("dateReleased"),
                    },
                )
                self.finish_run(
                    run_id,
                    rows_in=count,
                    bronze_path=str(path),
                    checksum=manifest.sha256,
                )
                log.info("KEV: fetched %d entries -> %s", count, partition)
                return IngestResult(self.source, run_id, partition, rows_in=count)

        self.finish_run(run_id, status="failed", error=str(last_error))
        raise RuntimeError(f"All KEV sources failed; last error: {last_error}")

    def transform(self, partition: str | None = None, **kwargs: Any) -> IngestResult:
        partition = self.resolve_partition(partition)
        catalog = self.bronze.read_json(self.source, partition, FILENAME)
        entries = catalog.get("vulnerabilities", [])
        run_id = self.start_run(notes={"partition": partition})

        today = datetime.now(UTC).date()
        incoming: dict[str, dict[str, Any]] = {}
        for entry in entries:
            cve_id = (entry.get("cveID") or "").strip().upper()
            if not cve_id:
                continue
            incoming[cve_id] = {
                "cve_id": cve_id,
                "date_added": _as_date(entry.get("dateAdded")),
                "due_date": _as_date(entry.get("dueDate")),
                "vendor_project": entry.get("vendorProject"),
                "product": entry.get("product"),
                "vulnerability_name": entry.get("vulnerabilityName"),
                "short_description": entry.get("shortDescription"),
                "required_action": entry.get("requiredAction"),
                "known_ransomware_use": _ransomware_flag(entry.get("knownRansomwareCampaignUse")),
                "notes": entry.get("notes"),
            }

        open_rows = {
            row["cve_id"]: row for row in self.db.query("SELECT * FROM kev WHERE valid_to IS NULL")
        }

        to_close: list[list[Any]] = []
        to_open: list[dict[str, Any]] = []

        for cve_id, new_row in incoming.items():
            current = open_rows.get(cve_id)
            if current is None:
                to_open.append(new_row)
            elif self._changed(current, new_row):
                to_close.append([today, cve_id, current["valid_from"]])
                to_open.append(new_row)

        # Entries that disappeared from the catalog get closed, not deleted.
        for cve_id, current in open_rows.items():
            if cve_id not in incoming:
                to_close.append([today, cve_id, current["valid_from"]])

        if to_close:
            self.db.executemany(
                "UPDATE kev SET valid_to = ? WHERE cve_id = ? AND valid_from = ?", to_close
            )

        if to_open:
            self.db.insert_many(
                "kev",
                [
                    {
                        **row,
                        "valid_from": today,
                        "valid_to": None,
                        "source_run_id": run_id,
                    }
                    for row in to_open
                ],
            )

        self.finish_run(run_id, rows_in=len(entries), rows_out=len(to_open))
        log.info(
            "KEV: %d in catalog, %d opened, %d closed", len(entries), len(to_open), len(to_close)
        )
        return IngestResult(
            self.source,
            run_id,
            partition,
            rows_in=len(entries),
            rows_out=len(to_open),
            message=f"{len(to_close)} rows closed",
        )

    @staticmethod
    def _changed(current: dict[str, Any], incoming: dict[str, Any]) -> bool:
        for field in _TRACKED:
            old, new = current.get(field), incoming.get(field)
            if isinstance(old, datetime):
                old = old.date()
            if old != new:
                return True
        return False
