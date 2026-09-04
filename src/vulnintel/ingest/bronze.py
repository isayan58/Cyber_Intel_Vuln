"""Bronze layer — immutable, replayable raw storage.

Every byte fetched from a public feed lands here before anything parses it,
alongside a manifest recording where it came from and when. The rule the rest
of the system relies on: *the warehouse can be dropped and rebuilt entirely
from bronze without a network call.*

Partition keys use the source's own notion of time (``score_date``,
``modified_window``, ``release``) rather than wall-clock, so re-running an
ingest for the same window overwrites rather than duplicates.
"""

from __future__ import annotations

import gzip
import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from vulnintel.config import get_settings
from vulnintel.fsutil import iter_dirs, iter_files
from vulnintel.logging_setup import get_logger

log = get_logger(__name__)


@dataclass
class BronzeManifest:
    """Provenance record written next to every bronze payload."""

    source: str
    partition: str
    source_url: str
    retrieved_at: str
    sha256: str
    byte_size: int
    record_count: int | None = None
    http_status: int | None = None
    run_id: int | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True)


class BronzeStore:
    """Filesystem-backed raw store: ``data/bronze/<source>/<partition>/``."""

    def __init__(self, root: Path | None = None) -> None:
        self.root = root or get_settings().bronze_dir

    def partition_dir(self, source: str, partition: str) -> Path:
        return self.root / source / partition

    def write(
        self,
        source: str,
        partition: str,
        filename: str,
        payload: bytes,
        source_url: str,
        *,
        compress: bool = True,
        record_count: int | None = None,
        http_status: int | None = None,
        run_id: int | None = None,
        extra: dict[str, Any] | None = None,
    ) -> tuple[Path, BronzeManifest]:
        """Write a payload plus its manifest. Returns (path, manifest)."""
        target_dir = self.partition_dir(source, partition)
        target_dir.mkdir(parents=True, exist_ok=True)

        digest = hashlib.sha256(payload).hexdigest()
        if compress and not filename.endswith(".gz"):
            filename = filename + ".gz"
            body = gzip.compress(payload)
        else:
            body = payload

        path = target_dir / filename
        path.write_bytes(body)

        manifest = BronzeManifest(
            source=source,
            partition=partition,
            source_url=source_url,
            retrieved_at=datetime.now(UTC).isoformat(),
            sha256=digest,
            byte_size=len(payload),
            record_count=record_count,
            http_status=http_status,
            run_id=run_id,
            extra=extra or {},
        )
        self._merge_manifest(target_dir, filename, manifest)
        log.debug("bronze write %s/%s/%s (%d bytes)", source, partition, filename, len(payload))
        return path, manifest

    def _merge_manifest(self, target_dir: Path, filename: str, manifest: BronzeManifest) -> None:
        """A partition may hold many files (e.g. NVD pages); keep one manifest."""
        manifest_path = target_dir / "_manifest.json"
        existing: dict[str, Any] = {}
        if manifest_path.exists():
            try:
                existing = json.loads(manifest_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                existing = {}
        files = existing.get("files", {})
        files[filename] = asdict(manifest)
        payload = {
            "source": manifest.source,
            "partition": manifest.partition,
            "updated_at": manifest.retrieved_at,
            "files": files,
        }
        manifest_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    def read(self, source: str, partition: str, filename: str) -> bytes:
        path = self.partition_dir(source, partition) / filename
        if not path.exists() and not filename.endswith(".gz"):
            path = self.partition_dir(source, partition) / (filename + ".gz")
        raw = path.read_bytes()
        if path.suffix == ".gz":
            return gzip.decompress(raw)
        return raw

    def read_json(self, source: str, partition: str, filename: str) -> Any:
        return json.loads(self.read(source, partition, filename))

    def manifest(self, source: str, partition: str) -> dict[str, Any] | None:
        path = self.partition_dir(source, partition) / "_manifest.json"
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def list_partitions(self, source: str) -> list[str]:
        return [p.name for p in iter_dirs(self.root / source)]

    def latest_partition(self, source: str) -> str | None:
        partitions = self.list_partitions(source)
        return partitions[-1] if partitions else None

    def files_in(self, source: str, partition: str, suffix: str = "") -> list[Path]:
        """Payload files in a partition.

        ``iter_files`` excludes AppleDouble sidecars. That matters here more
        than anywhere: a ``._PyPI.zip`` sitting beside ``PyPI.zip`` matches a
        ``.zip`` suffix filter perfectly and then fails to open, which reads as
        a corrupt download rather than as an OS artefact.
        """
        return [
            p
            for p in iter_files(self.partition_dir(source, partition))
            if p.name != "_manifest.json" and p.name.endswith(suffix)
        ]

    def total_size_bytes(self) -> int:
        return sum(p.stat().st_size for p in iter_files(self.root, recursive=True))
