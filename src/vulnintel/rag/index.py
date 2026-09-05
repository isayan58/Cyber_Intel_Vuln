"""Lexical (BM25) and vector indexes.

BM25 is implemented here rather than pulled from Postgres FTS so that the
lexical half of hybrid retrieval behaves identically on both storage backends
— and so the ranking function is inspectable, which matters when the
evaluation suite reports that lexical retrieval beat vector retrieval on
exact-identifier queries.

The vector index is a brute-force cosine scan over an in-memory float32
matrix. At corpus sizes this project targets (tens of documents, low
thousands of chunks) that is sub-millisecond and exact; an ANN index would add
a dependency and an approximation for no measurable gain. Swapping in pgvector
or Qdrant means replacing this class alone.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass
from typing import Any

import numpy as np

from vulnintel.data.db import Database, get_db
from vulnintel.logging_setup import get_logger
from vulnintel.rag.embeddings import EmbeddingProvider, get_embedding_provider, tokenize

log = get_logger(__name__)


@dataclass
class ScoredChunk:
    chunk_id: str
    score: float
    rank: int


class BM25Index:
    """Okapi BM25 over chunk text."""

    def __init__(self, k1: float = 1.5, b: float = 0.75) -> None:
        self.k1 = k1
        self.b = b
        self.chunk_ids: list[str] = []
        self.term_frequencies: list[Counter[str]] = []
        self.doc_lengths: list[int] = []
        self.document_frequency: Counter[str] = Counter()
        self.average_length: float = 0.0
        self._postings: dict[str, list[int]] = {}

    def build(self, chunks: list[tuple[str, str]]) -> None:
        """``chunks`` is a list of (chunk_id, text)."""
        self.chunk_ids = []
        self.term_frequencies = []
        self.doc_lengths = []
        self.document_frequency = Counter()
        self._postings = {}

        for position, (chunk_id, text) in enumerate(chunks):
            tokens = tokenize(text)
            counts = Counter(tokens)
            self.chunk_ids.append(chunk_id)
            self.term_frequencies.append(counts)
            self.doc_lengths.append(len(tokens))
            for term in counts:
                self.document_frequency[term] += 1
                self._postings.setdefault(term, []).append(position)

        total = sum(self.doc_lengths)
        self.average_length = total / len(self.doc_lengths) if self.doc_lengths else 0.0
        log.debug("BM25 index built over %d chunks", len(self.chunk_ids))

    def search(
        self, query: str, top_k: int = 40, allowed: set[str] | None = None
    ) -> list[ScoredChunk]:
        if not self.chunk_ids:
            return []

        terms = tokenize(query)
        if not terms:
            return []

        corpus_size = len(self.chunk_ids)
        scores: dict[int, float] = {}

        for term in set(terms):
            postings = self._postings.get(term)
            if not postings:
                continue
            df = self.document_frequency[term]
            idf = math.log(1.0 + (corpus_size - df + 0.5) / (df + 0.5))
            for position in postings:
                if allowed is not None and self.chunk_ids[position] not in allowed:
                    continue
                freq = self.term_frequencies[position][term]
                length = self.doc_lengths[position] or 1
                denominator = freq + self.k1 * (
                    1 - self.b + self.b * length / (self.average_length or 1.0)
                )
                scores[position] = scores.get(position, 0.0) + idf * (
                    freq * (self.k1 + 1) / denominator
                )

        ranked = sorted(scores.items(), key=lambda item: item[1], reverse=True)[:top_k]
        return [
            ScoredChunk(self.chunk_ids[position], score, rank)
            for rank, (position, score) in enumerate(ranked, start=1)
        ]


class VectorIndex:
    """Exact cosine similarity over an in-memory matrix."""

    def __init__(self, provider: EmbeddingProvider | None = None) -> None:
        self.provider = provider or get_embedding_provider()
        self.chunk_ids: list[str] = []
        self.matrix: np.ndarray = np.zeros((0, self.provider.dim), dtype=np.float32)
        self._positions: dict[str, int] = {}

    def build(self, chunk_ids: list[str], vectors: np.ndarray) -> None:
        self.chunk_ids = list(chunk_ids)
        self.matrix = np.ascontiguousarray(vectors, dtype=np.float32)
        self._positions = {cid: i for i, cid in enumerate(self.chunk_ids)}
        log.debug("vector index built: %s", self.matrix.shape)

    def search(
        self, query: str, top_k: int = 40, allowed: set[str] | None = None
    ) -> list[ScoredChunk]:
        if not self.chunk_ids:
            return []

        query_vector = self.provider.embed_one(query)
        similarities = self.matrix @ query_vector

        if allowed is not None:
            mask = np.full(len(self.chunk_ids), -np.inf, dtype=np.float32)
            for chunk_id in allowed:
                position = self._positions.get(chunk_id)
                if position is not None:
                    mask[position] = 0.0
            similarities = similarities + mask

        count = min(top_k, len(self.chunk_ids))
        top = np.argpartition(-similarities, count - 1)[:count]
        top = top[np.argsort(-similarities[top])]

        return [
            ScoredChunk(self.chunk_ids[int(position)], float(similarities[int(position)]), rank)
            for rank, position in enumerate(top, start=1)
            if math.isfinite(float(similarities[int(position)]))
        ]


class KnowledgeIndex:
    """Both indexes plus the chunk metadata needed for filtering and citation."""

    def __init__(self, db: Database | None = None, provider: EmbeddingProvider | None = None):
        self.db = db or get_db()
        self.provider = provider or get_embedding_provider()
        self.bm25 = BM25Index()
        self.vectors = VectorIndex(self.provider)
        self.chunks: dict[str, dict[str, Any]] = {}
        self.loaded = False

    def load(self) -> int:
        """Load chunks and embeddings from the warehouse into memory."""
        rows = self.db.query(
            """
            SELECT c.chunk_id, c.doc_id, c.ordinal, c.section_path, c.heading, c.text,
                   c.token_count,
                   d.title, d.source_url, d.publisher, d.doc_type, d.authority,
                   d.trust_tag, d.policy_version, d.effective_date, d.superseded_by,
                   d.control_family, d.product, d.visibility
            FROM kb_chunk c
            JOIN kb_document d ON d.doc_id = c.doc_id
            ORDER BY c.doc_id, c.ordinal
            """
        )
        if not rows:
            self.loaded = True
            return 0

        self.chunks = {row["chunk_id"]: row for row in rows}
        self.bm25.build([(row["chunk_id"], row["text"]) for row in rows])

        embeddings = {
            row["chunk_id"]: row["embedding"]
            for row in self.db.query(
                "SELECT chunk_id, embedding FROM kb_chunk_embedding WHERE provider = ?",
                [self.provider.name],
            )
        }

        ordered_ids: list[str] = []
        vectors: list[np.ndarray] = []
        missing: list[str] = []
        for row in rows:
            vector = embeddings.get(row["chunk_id"])
            if vector is None:
                missing.append(row["chunk_id"])
                continue
            ordered_ids.append(row["chunk_id"])
            vectors.append(np.asarray(vector, dtype=np.float32))

        if missing:
            log.warning(
                "%d chunks have no '%s' embedding; run `vulnintel rag index` to backfill",
                len(missing),
                self.provider.name,
            )

        if vectors:
            self.vectors.build(ordered_ids, np.vstack(vectors))

        self.loaded = True
        log.info("knowledge index loaded: %d chunks", len(rows))
        return len(rows)

    def ensure_loaded(self) -> None:
        if not self.loaded:
            self.load()

    def filter_chunks(self, filters: dict[str, Any] | None) -> set[str] | None:
        """Metadata pre-filter. Returns None when no filter applies."""
        if not filters:
            return None

        allowed: set[str] = set()
        for chunk_id, row in self.chunks.items():
            if all(_matches(row.get(key), value) for key, value in filters.items()):
                allowed.add(chunk_id)
        return allowed


def _matches(actual: Any, expected: Any) -> bool:
    if expected is None:
        return True
    if isinstance(expected, list | tuple | set):
        return actual in expected
    if isinstance(expected, str) and isinstance(actual, str):
        return actual.lower() == expected.lower()
    return actual == expected
