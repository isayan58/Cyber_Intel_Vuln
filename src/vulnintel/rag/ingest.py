"""Knowledge-base ingestion: documents -> chunks -> embeddings."""

from __future__ import annotations

from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from vulnintel.config import get_settings
from vulnintel.data.db import Database, get_db
from vulnintel.fsutil import iter_files
from vulnintel.logging_setup import get_logger
from vulnintel.rag.chunking import chunk_document, document_id, parse_document
from vulnintel.rag.embeddings import EmbeddingProvider, get_embedding_provider

log = get_logger(__name__)

SUPPORTED_SUFFIXES = {".md", ".markdown", ".txt"}


def _as_date(value: Any) -> date | None:
    if not value:
        return None
    if isinstance(value, date):
        return value
    try:
        return datetime.strptime(str(value)[:10], "%Y-%m-%d").date()
    except ValueError:
        return None


def discover_documents(root: Path | None = None) -> list[Path]:
    root = root or get_settings().knowledge_dir
    if not root.exists():
        return []
    return [
        path
        for path in iter_files(root, recursive=True)
        if path.suffix.lower() in SUPPORTED_SUFFIXES
    ]


def _authority_from_path(path: Path, declared: str | None) -> str:
    if declared:
        return declared
    parts = {p.lower() for p in path.parts}
    if "internal_synthetic" in parts:
        return "internal"
    name = path.name.lower()
    if "nist" in name or "csf" in name or "800-40" in name:
        return "nist"
    if "owasp" in name:
        return "owasp"
    return "vendor"


def ingest_knowledge_base(
    root: Path | None = None,
    db: Database | None = None,
    provider: EmbeddingProvider | None = None,
) -> dict[str, int]:
    """Parse, chunk, embed and store every document under ``root``."""
    db = db or get_db()
    provider = provider or get_embedding_provider()
    paths = discover_documents(root)

    if not paths:
        log.warning(
            "no knowledge-base documents found under %s", root or get_settings().knowledge_dir
        )
        return {"documents": 0, "chunks": 0, "embeddings": 0}

    now = datetime.now(UTC).replace(tzinfo=None)
    documents: list[dict[str, Any]] = []
    chunk_rows: list[dict[str, Any]] = []
    texts: list[str] = []
    chunk_ids: list[str] = []

    for path in paths:
        parsed = parse_document(path)
        doc_id = document_id(path)
        metadata = parsed.metadata

        documents.append(
            {
                "doc_id": doc_id,
                "title": metadata.get("title", path.stem.replace("-", " ").title()),
                "source_url": metadata.get("source_url"),
                "publisher": metadata.get("publisher"),
                "doc_type": metadata.get("doc_type", "guidance"),
                "authority": _authority_from_path(path, metadata.get("authority")),
                "trust_tag": metadata.get("trust_tag"),
                "policy_version": metadata.get("policy_version"),
                "effective_date": _as_date(metadata.get("effective_date")),
                "superseded_by": metadata.get("superseded_by"),
                "visibility": metadata.get("visibility", "internal"),
                "control_family": metadata.get("control_family"),
                "product": metadata.get("product"),
                "sha256": parsed.sha256,
                "source_path": str(path),
                "ingested_at": now,
            }
        )

        for chunk in chunk_document(parsed, doc_id):
            chunk_rows.append(
                {
                    "chunk_id": chunk.chunk_id,
                    "doc_id": chunk.doc_id,
                    "ordinal": chunk.ordinal,
                    "section_path": chunk.section_path,
                    "heading": chunk.heading,
                    "text": chunk.text,
                    "token_count": chunk.token_count,
                }
            )
            texts.append(chunk.text)
            chunk_ids.append(chunk.chunk_id)

    log.info("embedding %d chunks with '%s'", len(texts), provider.name)
    vectors = provider.embed(texts)

    embedding_rows = [
        {
            "chunk_id": chunk_id,
            "dim": int(vectors.shape[1]),
            "provider": provider.name,
            "embedding": [float(x) for x in vectors[index]],
        }
        for index, chunk_id in enumerate(chunk_ids)
    ]

    doc_ids = [[d["doc_id"]] for d in documents]
    db.executemany(
        "DELETE FROM kb_chunk_embedding WHERE chunk_id IN "
        "(SELECT chunk_id FROM kb_chunk WHERE doc_id = ?)",
        doc_ids,
    )
    db.executemany("DELETE FROM kb_chunk WHERE doc_id = ?", doc_ids)
    db.upsert("kb_document", documents, key_columns=("doc_id",))
    db.insert_many("kb_chunk", chunk_rows)
    db.insert_many("kb_chunk_embedding", embedding_rows)

    summary = {
        "documents": len(documents),
        "chunks": len(chunk_rows),
        "embeddings": len(embedding_rows),
    }
    log.info("knowledge base ingested: %s", summary)
    return summary


def reembed(db: Database | None = None, provider: EmbeddingProvider | None = None) -> int:
    """Recompute embeddings for existing chunks with a different provider."""
    db = db or get_db()
    provider = provider or get_embedding_provider()

    rows = db.query("SELECT chunk_id, text FROM kb_chunk ORDER BY doc_id, ordinal")
    if not rows:
        return 0

    vectors = provider.embed([r["text"] for r in rows])
    db.execute("DELETE FROM kb_chunk_embedding WHERE provider = ?", [provider.name])
    db.insert_many(
        "kb_chunk_embedding",
        [
            {
                "chunk_id": row["chunk_id"],
                "dim": int(vectors.shape[1]),
                "provider": provider.name,
                "embedding": [float(x) for x in vectors[index]],
            }
            for index, row in enumerate(rows)
        ],
    )
    log.info("re-embedded %d chunks with '%s'", len(rows), provider.name)
    return len(rows)
