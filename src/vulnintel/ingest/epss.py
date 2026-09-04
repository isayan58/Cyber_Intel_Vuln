"""FIRST EPSS daily scores (design doc D7/D8/D9).

The daily bulk CSV is the right synchronisation method — roughly 300k rows,
one gzip download. The full daily series stays in bronze Parquet-adjacent
storage (the raw gz); only the current snapshot and a rolling window land in
the warehouse, because a year of full history would be ~110M rows and would
dominate a laptop-sized database for no analytical gain.
"""

from __future__ import annotations

import csv
import gzip
import io
from datetime import UTC, date, datetime, timedelta
from typing import Any

from vulnintel.ingest.base import IngestResult, Pipeline
from vulnintel.ingest.http import FeedClient
from vulnintel.logging_setup import get_logger

log = get_logger(__name__)

GZIP_MAGIC = b"\x1f\x8b"


def _decode(payload: bytes) -> str:
    """Return CSV text, decompressing first when the payload is a gzip file."""
    if payload[:2] == GZIP_MAGIC:
        payload = gzip.decompress(payload)
    return payload.decode("utf-8", errors="replace")


EPSS_URLS = [
    "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
    "https://epss.cyentia.com/epss_scores-current.csv.gz",
]

FILENAME = "epss_scores.csv"

# How many days of per-CVE history to keep in the warehouse.
HISTORY_WINDOW_DAYS = 90


class EpssPipeline(Pipeline):
    source = "epss"

    def fetch(self, **kwargs: Any) -> IngestResult:
        run_id = self.start_run()
        last_error: Exception | None = None

        with FeedClient() as client:
            for url in EPSS_URLS:
                try:
                    response = client.get(url)
                except Exception as exc:  # noqa: BLE001 - try the next mirror
                    log.warning("EPSS fetch failed from %s: %s", url, exc)
                    last_error = exc
                    continue

                # The URL serves a gzip *file* (Content-Type: application/gzip)
                # rather than a gzip-encoded response, so httpx does not
                # decompress it. Decoding those bytes as text silently
                # corrupts them, so decompress explicitly.
                text = _decode(response.content)
                score_date = self._score_date_from_header(text) or datetime.now(UTC).date()
                partition = f"score_date={score_date.isoformat()}"
                rows = text.count("\n")

                path, manifest = self.bronze.write(
                    self.source,
                    partition,
                    FILENAME,
                    text.encode("utf-8"),
                    source_url=url,
                    record_count=rows,
                    http_status=response.status_code,
                    run_id=run_id,
                    extra={"score_date": score_date.isoformat()},
                )
                self.finish_run(
                    run_id, rows_in=rows, bronze_path=str(path), checksum=manifest.sha256
                )
                log.info("EPSS: fetched %d rows for %s", rows, score_date)
                return IngestResult(self.source, run_id, partition, rows_in=rows)

        self.finish_run(run_id, status="failed", error=str(last_error))
        raise RuntimeError(f"All EPSS sources failed; last error: {last_error}")

    def transform(self, partition: str | None = None, **kwargs: Any) -> IngestResult:
        partition = self.resolve_partition(partition)
        text = _decode(self.bronze.read(self.source, partition, FILENAME))
        run_id = self.start_run(notes={"partition": partition})

        score_date = self._score_date_from_header(text) or self._date_from_partition(partition)
        rows = list(self._parse(text, score_date))

        self.db.execute("DELETE FROM epss_current")
        written = self.db.insert_many(
            "epss_current",
            [
                {
                    "cve_id": r["cve_id"],
                    "probability": r["probability"],
                    "percentile": r["percentile"],
                    "score_date": r["score_date"],
                    "source_run_id": run_id,
                }
                for r in rows
            ],
        )

        # Rolling history window; older days remain available in bronze.
        self.db.upsert(
            "epss_history",
            [
                {
                    "cve_id": r["cve_id"],
                    "score_date": r["score_date"],
                    "probability": r["probability"],
                    "percentile": r["percentile"],
                }
                for r in rows
            ],
            key_columns=("cve_id", "score_date"),
        )
        cutoff = score_date - timedelta(days=HISTORY_WINDOW_DAYS)
        self.db.execute("DELETE FROM epss_history WHERE score_date < ?", [cutoff])

        self.finish_run(run_id, rows_in=len(rows), rows_out=written)
        log.info("EPSS: loaded %d scores for %s", written, score_date)
        return IngestResult(self.source, run_id, partition, rows_in=len(rows), rows_out=written)

    # -- parsing --------------------------------------------------------------

    @staticmethod
    def _parse(text: str, score_date: date):
        """EPSS CSVs open with a ``#model_version...`` comment line."""
        stream = io.StringIO(text)
        lines = (line for line in stream if not line.startswith("#"))
        reader = csv.DictReader(lines)
        for row in reader:
            cve_id = (row.get("cve") or "").strip().upper()
            if not cve_id.startswith("CVE-"):
                continue
            try:
                probability = float(row.get("epss") or 0.0)
                percentile = float(row.get("percentile") or 0.0)
            except ValueError:
                continue
            yield {
                "cve_id": cve_id,
                "probability": probability,
                "percentile": percentile,
                "score_date": score_date,
            }

    @staticmethod
    def _score_date_from_header(text: str) -> date | None:
        """Header looks like ``#model_version:v2025.03.14,score_date:2026-09-04T00:00:00+0000``."""
        first = text.split("\n", 1)[0]
        if "score_date:" not in first:
            return None
        raw = first.split("score_date:", 1)[1].split(",")[0].strip()
        try:
            return datetime.strptime(raw[:10], "%Y-%m-%d").date()
        except ValueError:
            return None

    @staticmethod
    def _date_from_partition(partition: str) -> date:
        raw = partition.split("=", 1)[-1]
        try:
            return datetime.strptime(raw, "%Y-%m-%d").date()
        except ValueError:
            return datetime.now(UTC).date()
