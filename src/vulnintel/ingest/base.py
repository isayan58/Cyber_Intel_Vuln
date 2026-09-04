"""Pipeline base class.

Each feed pipeline splits into two phases that can be run independently:

    fetch()      network -> bronze (immutable raw payloads + manifest)
    transform()  bronze  -> warehouse (normalised silver tables)

Keeping them separate is what makes ``vulnintel ingest all --offline`` work:
re-normalising every feed from disk requires no network at all, so a schema
change or a parsing bug is a re-run rather than a re-download.
"""

from __future__ import annotations

import abc
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from vulnintel.data.db import Database, get_db
from vulnintel.ingest.bronze import BronzeStore
from vulnintel.logging_setup import get_logger

log = get_logger(__name__)


@dataclass
class IngestResult:
    source: str
    run_id: int | None
    partition: str | None
    rows_in: int = 0
    rows_out: int = 0
    skipped: bool = False
    message: str = ""

    def __str__(self) -> str:
        if self.skipped:
            return f"{self.source}: skipped ({self.message})"
        return (
            f"{self.source}: partition={self.partition} "
            f"rows_in={self.rows_in} rows_out={self.rows_out}"
        )


class Pipeline(abc.ABC):
    """Base for every feed pipeline."""

    source: str = "unknown"

    def __init__(self, db: Database | None = None, bronze: BronzeStore | None = None) -> None:
        self.db = db or get_db()
        self.bronze = bronze or BronzeStore()

    # -- lifecycle ------------------------------------------------------------

    def start_run(
        self,
        window_start: datetime | None = None,
        window_end: datetime | None = None,
        notes: dict[str, Any] | None = None,
    ) -> int:
        self.db.execute(
            "INSERT INTO ingest_run (source, status, started_at, window_start, window_end, notes) "
            "VALUES (?, 'running', ?, ?, ?, ?)",
            [
                self.source,
                datetime.now(UTC).replace(tzinfo=None),
                window_start.replace(tzinfo=None) if window_start else None,
                window_end.replace(tzinfo=None) if window_end else None,
                json.dumps(notes or {}),
            ],
        )
        run_id = self.db.scalar(
            "SELECT max(run_id) FROM ingest_run WHERE source = ?", [self.source]
        )
        return int(run_id)

    def finish_run(
        self,
        run_id: int,
        *,
        status: str = "succeeded",
        rows_in: int = 0,
        rows_out: int = 0,
        bronze_path: str | None = None,
        checksum: str | None = None,
        error: str | None = None,
    ) -> None:
        self.db.execute(
            "UPDATE ingest_run SET status = ?, completed_at = ?, rows_in = ?, rows_out = ?, "
            "bronze_path = ?, checksum = ?, error = ? WHERE run_id = ?",
            [
                status,
                datetime.now(UTC).replace(tzinfo=None),
                rows_in,
                rows_out,
                bronze_path,
                checksum,
                error,
                run_id,
            ],
        )

    def last_successful_run(self) -> dict[str, Any] | None:
        return self.db.query_one(
            "SELECT * FROM ingest_run WHERE source = ? AND status = 'succeeded' "
            "ORDER BY completed_at DESC LIMIT 1",
            [self.source],
        )

    # -- phases ---------------------------------------------------------------

    @abc.abstractmethod
    def fetch(self, **kwargs: Any) -> IngestResult:
        """Download from the network into bronze."""

    @abc.abstractmethod
    def transform(self, partition: str | None = None, **kwargs: Any) -> IngestResult:
        """Normalise a bronze partition into the warehouse."""

    def run(self, *, offline: bool = False, **kwargs: Any) -> IngestResult:
        """Fetch (unless offline) then transform."""
        partition: str | None = None
        if not offline:
            fetched = self.fetch(**kwargs)
            if fetched.skipped:
                return fetched
            partition = fetched.partition
        return self.transform(partition=partition, **kwargs)

    # -- helpers --------------------------------------------------------------

    @staticmethod
    def today_partition(prefix: str = "retrieved_date") -> str:
        return f"{prefix}={datetime.now(UTC).date().isoformat()}"

    def resolve_partition(self, partition: str | None) -> str:
        """Fall back to the newest bronze partition for this source."""
        if partition:
            return partition
        latest = self.bronze.latest_partition(self.source)
        if latest is None:
            raise FileNotFoundError(
                f"No bronze data for '{self.source}'. Run the fetch phase first "
                f"(vulnintel ingest {self.source})."
            )
        return latest


def utcnow() -> datetime:
    """Naive UTC timestamp — both backends store TIMESTAMP without zone."""
    return datetime.now(UTC).replace(tzinfo=None)


def parse_ts(value: str | None) -> datetime | None:
    """Parse the ISO-8601 shapes the feeds actually emit."""
    if not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
            try:
                parsed = datetime.strptime(value[:26], fmt)
                break
            except ValueError:
                continue
        else:
            return None
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(UTC).replace(tzinfo=None)
    return parsed
