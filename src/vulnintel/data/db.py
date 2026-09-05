"""Database access.

A single thin abstraction over DuckDB (default — no infrastructure required)
and PostgreSQL (set ``VULNINTEL_DB_BACKEND=postgres`` once Docker is
available). Both backends run the same ``schema.sql`` with a handful of type
tokens substituted.

Query style is deliberately plain SQL with ``?`` placeholders; the connection
translates to ``%s`` for psycopg. No ORM — the joins in this project are the
interesting part and hiding them behind a mapper would defeat the purpose.
"""

from __future__ import annotations

import threading
from collections.abc import Iterable, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from vulnintel.config import Settings, get_settings
from vulnintel.logging_setup import get_logger

log = get_logger(__name__)

SCHEMA_PATH = Path(__file__).with_name("schema.sql")

_DIALECT_TOKENS = {
    "duckdb": {"{{JSON}}": "JSON", "{{VECTOR}}": "FLOAT[]"},
    "postgres": {"{{JSON}}": "JSONB", "{{VECTOR}}": "REAL[]"},
}


def render_schema(backend: str) -> str:
    sql = SCHEMA_PATH.read_text(encoding="utf-8")
    for token, replacement in _DIALECT_TOKENS[backend].items():
        sql = sql.replace(token, replacement)
    return sql


class Database:
    """Connection wrapper with a uniform query surface across backends."""

    def __init__(self, settings: Settings | None = None, read_only: bool | None = None) -> None:
        self.settings = settings or get_settings()
        self.backend = self.settings.db_backend
        self.read_only = self.settings.db_read_only if read_only is None else read_only
        self._lock = threading.RLock()
        self._conn: Any = None

    # -- connection -----------------------------------------------------------

    def connect(self) -> Any:
        if self._conn is not None:
            return self._conn
        with self._lock:
            if self._conn is not None:
                return self._conn
            if self.backend == "duckdb":
                self._conn = self._connect_duckdb()
            else:
                import psycopg

                self._conn = psycopg.connect(self.settings.postgres_dsn, autocommit=True)
            return self._conn

    def _connect_duckdb(self) -> Any:
        """Open the DuckDB file, turning its lock error into a usable message.

        DuckDB allows one writer *or* many readers. That is fine for this
        project — one ingest job, one API process — but the raw error names a
        PID and nothing else, which is a poor first experience. When the file
        is already locked and this handle only needs to read, fall back to a
        read-only connection automatically; otherwise explain the conflict.
        """
        import duckdb

        path = self.settings.duckdb_file
        path.parent.mkdir(parents=True, exist_ok=True)

        try:
            return duckdb.connect(str(path), read_only=self.read_only)
        except duckdb.IOException as exc:
            if "lock" not in str(exc).lower():
                raise
            if not self.read_only:
                try:
                    log.warning(
                        "DuckDB is write-locked by another process; opening read-only. "
                        "Writes from this process will fail."
                    )
                    self.read_only = True
                    return duckdb.connect(str(path), read_only=True)
                except duckdb.IOException:
                    pass
            raise RuntimeError(
                f"Cannot open {path}: another process holds the DuckDB lock.\n"
                "DuckDB permits a single writer. Stop the API server before running "
                "ingestion (or the other way round), or switch to the Postgres backend "
                "with VULNINTEL_DB_BACKEND=postgres for concurrent access."
            ) from exc

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    # -- statement translation ------------------------------------------------

    def _prepare(self, sql: str) -> str:
        if self.backend == "postgres":
            return sql.replace("?", "%s")
        return sql

    # -- execution ------------------------------------------------------------

    def execute(self, sql: str, params: Sequence[Any] | None = None) -> None:
        conn = self.connect()
        stmt = self._prepare(sql)
        with self._lock:
            if self.backend == "duckdb":
                conn.execute(stmt, list(params) if params else None)
            else:
                with conn.cursor() as cur:
                    cur.execute(stmt, list(params) if params else None)

    def executemany(self, sql: str, rows: Iterable[Sequence[Any]]) -> int:
        batch = [list(r) for r in rows]
        if not batch:
            return 0
        conn = self.connect()
        stmt = self._prepare(sql)
        with self._lock:
            if self.backend == "duckdb":
                conn.executemany(stmt, batch)
            else:
                with conn.cursor() as cur:
                    cur.executemany(stmt, batch)
        return len(batch)

    def query(self, sql: str, params: Sequence[Any] | None = None) -> list[dict[str, Any]]:
        """Run a SELECT and return a list of dicts."""
        conn = self.connect()
        stmt = self._prepare(sql)
        with self._lock:
            if self.backend == "duckdb":
                cur = conn.execute(stmt, list(params) if params else None)
                columns = [d[0] for d in cur.description]
                return [dict(zip(columns, row, strict=True)) for row in cur.fetchall()]
            with conn.cursor() as cur:
                cur.execute(stmt, list(params) if params else None)
                columns = [d[0] for d in cur.description]
                return [dict(zip(columns, row, strict=True)) for row in cur.fetchall()]

    def query_one(self, sql: str, params: Sequence[Any] | None = None) -> dict[str, Any] | None:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def scalar(self, sql: str, params: Sequence[Any] | None = None) -> Any:
        row = self.query_one(sql, params)
        if row is None:
            return None
        return next(iter(row.values()))

    # -- schema ---------------------------------------------------------------

    def init_schema(self) -> None:
        """Create every table. Idempotent."""
        sql = render_schema(self.backend)
        conn = self.connect()
        with self._lock:
            if self.backend == "duckdb":
                conn.execute(sql)
            else:
                with conn.cursor() as cur:
                    cur.execute(sql)
        log.info("schema initialised (%s)", self.backend)

    def drop_all(self) -> None:
        """Drop every managed table — used by ``vulnintel db reset``."""
        tables = [
            "eval_result",
            "tool_call",
            "agent_span",
            "agent_run",
            "kb_chunk_embedding",
            "kb_chunk",
            "kb_document",
            "finding_score",
            "risk_acceptances",
            "vulnerability_finding",
            "dependencies",
            "software_inventory",
            "assets",
            "applications",
            "attack_mapping",
            "attack_relationship",
            "attack_object",
            "epss_history",
            "epss_current",
            "kev",
            "advisory_affected",
            "advisory_alias",
            "advisory",
            "cve_cpe_match",
            "cve_reference",
            "cve_cwe",
            "cve_cvss",
            "cve",
            "ingest_run",
        ]
        for table in tables:
            self.execute(f"DROP TABLE IF EXISTS {table}")
        self.execute("DROP SEQUENCE IF EXISTS seq_ingest_run")
        log.info("dropped all tables")

    def table_counts(self) -> dict[str, int]:
        """Row count per table — powers the admin/status view."""
        if self.backend == "duckdb":
            names = [
                r["table_name"]
                for r in self.query(
                    "SELECT table_name FROM information_schema.tables "
                    "WHERE table_schema = 'main' ORDER BY table_name"
                )
            ]
        else:
            names = [
                r["table_name"]
                for r in self.query(
                    "SELECT table_name FROM information_schema.tables "
                    "WHERE table_schema = 'public' ORDER BY table_name"
                )
            ]
        counts: dict[str, int] = {}
        for name in names:
            try:
                counts[name] = int(self.scalar(f"SELECT count(*) FROM {name}") or 0)
            except Exception:  # noqa: BLE001 - a view over a missing table is not fatal
                counts[name] = -1
        return counts

    # -- bulk helpers ---------------------------------------------------------

    def upsert(
        self,
        table: str,
        rows: Sequence[dict[str, Any]],
        key_columns: Sequence[str],
        chunk_size: int = 50_000,
    ) -> int:
        """Insert rows, replacing any that collide on ``key_columns``.

        Row-at-a-time ``executemany`` costs roughly 2ms per row on DuckDB —
        fine for a few hundred rows, fatal for the millions of CPE match rows
        NVD produces. Both the delete and the insert therefore go through a
        registered Arrow table and a single set-based statement.
        """
        if not rows:
            return 0
        columns = list(rows[0].keys())

        # Deduplicate on the key before writing. Source feeds genuinely contain
        # the same record more than once — an OSV bulk archive stores an
        # advisory under several filenames — and a duplicate inside one batch
        # violates the primary key even though the delete-then-insert cleared
        # the pre-existing row. Last occurrence wins.
        if key_columns:
            rows = _dedupe_by_key(rows, key_columns)

        total = 0
        for start in range(0, len(rows), chunk_size):
            batch = rows[start : start + chunk_size]
            if key_columns:
                self._bulk_delete(table, batch, key_columns)
            total += self._bulk_insert(table, batch, columns)
        return total

    def insert_many(
        self, table: str, rows: Sequence[dict[str, Any]], chunk_size: int = 50_000
    ) -> int:
        return self.upsert(table, rows, key_columns=(), chunk_size=chunk_size)

    # -- bulk internals -------------------------------------------------------

    def _bulk_insert(self, table: str, rows: Sequence[dict[str, Any]], columns: list[str]) -> int:
        col_sql = ", ".join(columns)
        if self.backend == "duckdb":
            try:
                conn = self.connect()
                arrow_table = _to_arrow(rows, columns)
                with self._lock:
                    conn.register("_bulk_src", arrow_table)
                    try:
                        conn.execute(
                            f"INSERT INTO {table} ({col_sql}) SELECT {col_sql} FROM _bulk_src"
                        )
                    finally:
                        conn.unregister("_bulk_src")
                return len(rows)
            except Exception as exc:  # noqa: BLE001 - fall back to the slow path
                log.debug("arrow insert into %s failed (%s); using executemany", table, exc)

        placeholders = ", ".join("?" for _ in columns)
        return self.executemany(
            f"INSERT INTO {table} ({col_sql}) VALUES ({placeholders})",
            [[r.get(c) for c in columns] for r in rows],
        )

    def _bulk_delete(
        self, table: str, rows: Sequence[dict[str, Any]], key_columns: Sequence[str]
    ) -> None:
        keys = list(key_columns)
        if self.backend == "duckdb":
            try:
                conn = self.connect()
                # Deduplicate keys so the anti-join stays small.
                seen: set[tuple[Any, ...]] = set()
                unique: list[dict[str, Any]] = []
                for row in rows:
                    key = tuple(row.get(c) for c in keys)
                    if key not in seen:
                        seen.add(key)
                        unique.append({c: row.get(c) for c in keys})
                arrow_table = _to_arrow(unique, keys)
                predicate = " AND ".join(f"t.{c} = k.{c}" for c in keys)
                with self._lock:
                    conn.register("_bulk_keys", arrow_table)
                    try:
                        conn.execute(
                            f"DELETE FROM {table} AS t WHERE EXISTS "
                            f"(SELECT 1 FROM _bulk_keys k WHERE {predicate})"
                        )
                    finally:
                        conn.unregister("_bulk_keys")
                return
            except Exception as exc:  # noqa: BLE001 - fall back to the slow path
                log.debug("arrow delete from %s failed (%s); using executemany", table, exc)

        where = " AND ".join(f"{c} = ?" for c in keys)
        self.executemany(
            f"DELETE FROM {table} WHERE {where}", [[r.get(c) for c in keys] for r in rows]
        )

    def next_id(self, table: str, column: str) -> int:
        """Next integer id for tables whose keys are assigned in Python."""
        current = self.scalar(f"SELECT max({column}) FROM {table}")
        return int(current or 0) + 1


def _dedupe_by_key(
    rows: Sequence[dict[str, Any]], key_columns: Sequence[str]
) -> list[dict[str, Any]]:
    """Keep the last row for each key, preserving first-seen ordering."""
    index: dict[tuple[Any, ...], int] = {}
    output: list[dict[str, Any]] = []
    for row in rows:
        key = tuple(row.get(c) for c in key_columns)
        position = index.get(key)
        if position is None:
            index[key] = len(output)
            output.append(row)
        else:
            output[position] = row
    if len(output) != len(rows):
        log.debug("deduplicated %d rows down to %d", len(rows), len(output))
    return output


def _to_arrow(rows: Sequence[dict[str, Any]], columns: Sequence[str]):
    """Build an Arrow table from row dicts.

    Columns that are entirely NULL become Arrow's null type, which DuckDB
    casts to the target column type on insert. Mixed-type columns would raise,
    which is why the caller falls back to the row-at-a-time path on error.
    """
    import pyarrow as pa

    data = {}
    for column in columns:
        values = [row.get(column) for row in rows]
        if all(v is None for v in values):
            data[column] = pa.nulls(len(values))
        else:
            data[column] = pa.array(values)
    return pa.table(data)


_DB: Database | None = None
_DB_LOCK = threading.Lock()


def get_db() -> Database:
    """Process-wide database handle."""
    global _DB
    if _DB is None:
        with _DB_LOCK:
            if _DB is None:
                _DB = Database()
    return _DB


def reset_db() -> None:
    global _DB
    with _DB_LOCK:
        if _DB is not None:
            _DB.close()
        _DB = None


@contextmanager
def temporary_db(settings: Settings):
    """A throwaway Database for tests."""
    db = Database(settings)
    try:
        yield db
    finally:
        db.close()
