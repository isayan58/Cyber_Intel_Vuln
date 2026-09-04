"""Gold view creation."""

from __future__ import annotations

from pathlib import Path

from vulnintel.data.db import Database, get_db
from vulnintel.logging_setup import get_logger

log = get_logger(__name__)

VIEWS_PATH = Path(__file__).with_name("views.sql")


def create_views(db: Database | None = None) -> int:
    """(Re)create every serving view. Idempotent; safe to run after any load."""
    db = db or get_db()
    sql = VIEWS_PATH.read_text(encoding="utf-8")

    statements = [s.strip() for s in sql.split(";") if s.strip() and not _only_comments(s)]
    for statement in statements:
        db.execute(statement)
    log.info("created %d views", len(statements))
    return len(statements)


def _only_comments(block: str) -> bool:
    return all(
        not line.strip() or line.strip().startswith("--") for line in block.splitlines()
    )
