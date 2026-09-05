"""Hybrid retrieval with reciprocal-rank fusion, reranking and citations.

Pipeline (design doc §8.2 step 6):

    metadata filter -> BM25 + vector candidates -> RRF fusion
                    -> rerank -> top evidence -> citations

Two behaviours are deliberate rather than incidental:

  * **Superseded policy is demoted, not deleted.** A retrieved chunk from a
    superseded document keeps its place in the result but is flagged, so the
    answer can say "the current standard says X; the superseded v2.0 said Y"
    instead of silently averaging them.

  * **Reranking is optional and measured.** The default reranker is a cheap
    deterministic feature blend (term coverage, authority, recency). An
    LLM reranker is available behind a flag; the eval suite reports both, so
    the added latency has to justify itself.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any

from vulnintel.config import get_settings
from vulnintel.logging_setup import get_logger
from vulnintel.rag.embeddings import tokenize
from vulnintel.rag.index import KnowledgeIndex, ScoredChunk

log = get_logger(__name__)

AUTHORITY_WEIGHT = {
    "internal": 1.00,
    "nist": 0.85,
    "owasp": 0.80,
    "vendor": 0.90,
}


@dataclass
class Evidence:
    """One retrieved passage, with everything needed to cite it."""

    chunk_id: str
    doc_id: str
    title: str
    section_path: str
    text: str
    score: float
    authority: str | None = None
    trust_tag: str | None = None
    policy_version: str | None = None
    effective_date: Any = None
    superseded_by: str | None = None
    source_url: str | None = None
    doc_type: str | None = None
    lexical_rank: int | None = None
    vector_rank: int | None = None
    rerank_score: float | None = None

    @property
    def is_superseded(self) -> bool:
        return bool(self.superseded_by)

    def citation(self) -> str:
        parts = [self.title]
        if self.policy_version:
            parts.append(f"v{self.policy_version}")
        if self.section_path and self.section_path != "root":
            parts.append(self.section_path)
        label = " — ".join(parts)
        if self.is_superseded:
            label += "  [SUPERSEDED]"
        return label

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["citation"] = self.citation()
        data["is_superseded"] = self.is_superseded
        return data


@dataclass
class RetrievalResult:
    query: str
    evidence: list[Evidence] = field(default_factory=list)
    filters: dict[str, Any] = field(default_factory=dict)
    conflicts: list[str] = field(default_factory=list)
    candidate_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "query": self.query,
            "filters": self.filters,
            "conflicts": self.conflicts,
            "candidate_count": self.candidate_count,
            "evidence": [e.to_dict() for e in self.evidence],
        }


class HybridRetriever:
    def __init__(self, index: KnowledgeIndex | None = None) -> None:
        self.index = index or KnowledgeIndex()
        self.settings = get_settings()

    # -- public API -----------------------------------------------------------

    def retrieve(
        self,
        query: str,
        *,
        top_k: int | None = None,
        filters: dict[str, Any] | None = None,
        include_superseded: bool = True,
        rerank: str = "features",
    ) -> RetrievalResult:
        self.index.ensure_loaded()
        settings = self.settings
        top_k = top_k or settings.retrieval_top_k
        candidates = settings.retrieval_candidates

        allowed = self.index.filter_chunks(filters)

        lexical = self.index.bm25.search(query, top_k=candidates, allowed=allowed)
        vector = self.index.vectors.search(query, top_k=candidates, allowed=allowed)

        fused = self._reciprocal_rank_fusion(lexical, vector)
        evidence = [
            self._to_evidence(chunk_id, score, lexical, vector) for chunk_id, score in fused
        ]

        if not include_superseded:
            evidence = [e for e in evidence if not e.is_superseded]

        if rerank == "features":
            evidence = self._rerank_features(query, evidence)
        elif rerank == "llm":
            evidence = self._rerank_llm(query, evidence, top_k)

        selected = evidence[:top_k]
        return RetrievalResult(
            query=query,
            evidence=selected,
            filters=filters or {},
            conflicts=self._detect_conflicts(selected),
            candidate_count=len(fused),
        )

    def policy_search(self, query: str, top_k: int | None = None) -> RetrievalResult:
        """Internal policy only — the §8.3 behaviour for policy questions."""
        return self.retrieve(query, top_k=top_k, filters={"authority": "internal"})

    def vendor_search(
        self, query: str, product: str | None = None, top_k: int | None = None
    ) -> RetrievalResult:
        filters: dict[str, Any] = {"authority": ["vendor", "nist", "owasp"]}
        if product:
            filters["product"] = product
        return self.retrieve(query, top_k=top_k, filters=filters)

    def get_chunk(self, chunk_id: str) -> Evidence | None:
        self.index.ensure_loaded()
        row = self.index.chunks.get(chunk_id)
        if row is None:
            return None
        return self._build_evidence(row, score=1.0)

    # -- fusion & ranking -----------------------------------------------------

    def _reciprocal_rank_fusion(
        self, lexical: list[ScoredChunk], vector: list[ScoredChunk]
    ) -> list[tuple[str, float]]:
        k = self.settings.rrf_k
        scores: dict[str, float] = {}
        for results in (lexical, vector):
            for hit in results:
                scores[hit.chunk_id] = scores.get(hit.chunk_id, 0.0) + 1.0 / (k + hit.rank)
        return sorted(scores.items(), key=lambda item: item[1], reverse=True)

    def _rerank_features(self, query: str, evidence: list[Evidence]) -> list[Evidence]:
        """Deterministic reranking: term coverage x authority x currency."""
        query_terms = set(tokenize(query))
        if not query_terms:
            return evidence

        for item in evidence:
            chunk_terms = set(tokenize(item.text))
            coverage = len(query_terms & chunk_terms) / len(query_terms)

            authority = AUTHORITY_WEIGHT.get((item.authority or "").lower(), 0.7)
            currency = 0.35 if item.is_superseded else 1.0

            # An exact identifier in the text is a very strong signal.
            exact = 1.0
            for identifier in _identifiers(query):
                if identifier.lower() in item.text.lower():
                    exact = 1.6
                    break

            item.rerank_score = round(
                item.score * (0.35 + 0.65 * coverage) * authority * currency * exact, 6
            )

        return sorted(evidence, key=lambda e: e.rerank_score or 0.0, reverse=True)

    def _rerank_llm(self, query: str, evidence: list[Evidence], top_k: int) -> list[Evidence]:
        """Optional LLM reranker. Falls back to feature reranking on any error."""
        from vulnintel.llm import get_provider

        shortlist = evidence[: max(top_k * 3, 12)]
        if not shortlist:
            return evidence

        listing = "\n\n".join(
            f"[{i}] {item.citation()}\n{item.text[:600]}" for i, item in enumerate(shortlist)
        )
        schema = {
            "type": "object",
            "properties": {
                "ranking": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "index": {"type": "integer"},
                            "relevance": {"type": "number"},
                        },
                        "required": ["index", "relevance"],
                        "additionalProperties": False,
                    },
                }
            },
            "required": ["ranking"],
            "additionalProperties": False,
        }
        try:
            response = get_provider().complete_structured(
                system=(
                    "You rank retrieved passages by how directly they answer the question. "
                    "Score 0.0-1.0. Judge relevance only; do not answer the question."
                ),
                prompt=f"Question: {query}\n\nPassages:\n{listing}",
                schema=schema,
                effort="low",
                max_tokens=2000,
            )
            ranking = (response.structured or {}).get("ranking", [])
            scores = {int(r["index"]): float(r["relevance"]) for r in ranking}
            for index, item in enumerate(shortlist):
                item.rerank_score = scores.get(index, 0.0)
            reranked = sorted(shortlist, key=lambda e: e.rerank_score or 0.0, reverse=True)
            return reranked + evidence[len(shortlist) :]
        except Exception as exc:  # noqa: BLE001 - reranking must never break retrieval
            log.warning("LLM reranking failed (%s); using feature reranking", exc)
            return self._rerank_features(query, evidence)

    # -- conflict detection ---------------------------------------------------

    def _detect_conflicts(self, evidence: list[Evidence]) -> list[str]:
        """Surface conflicts rather than silently averaging guidance (§8.3)."""
        conflicts: list[str] = []
        by_title: dict[str, list[Evidence]] = {}
        for item in evidence:
            base = item.title.replace(" (SUPERSEDED)", "").strip()
            by_title.setdefault(base, []).append(item)

        for title, items in by_title.items():
            versions = {i.policy_version for i in items if i.policy_version}
            if len(versions) > 1:
                current = [i for i in items if not i.is_superseded]
                superseded = [i for i in items if i.is_superseded]
                if current and superseded:
                    conflicts.append(
                        f"'{title}' matched both the current version "
                        f"(v{current[0].policy_version}) and a superseded version "
                        f"(v{superseded[0].policy_version}). The current version governs."
                    )
        return conflicts

    # -- construction ---------------------------------------------------------

    def _to_evidence(
        self,
        chunk_id: str,
        score: float,
        lexical: list[ScoredChunk],
        vector: list[ScoredChunk],
    ) -> Evidence:
        row = self.index.chunks[chunk_id]
        evidence = self._build_evidence(row, score)
        evidence.lexical_rank = next((h.rank for h in lexical if h.chunk_id == chunk_id), None)
        evidence.vector_rank = next((h.rank for h in vector if h.chunk_id == chunk_id), None)
        return evidence

    @staticmethod
    def _build_evidence(row: dict[str, Any], score: float) -> Evidence:
        return Evidence(
            chunk_id=row["chunk_id"],
            doc_id=row["doc_id"],
            title=row.get("title") or row["doc_id"],
            section_path=row.get("section_path") or "",
            text=row["text"],
            score=round(float(score), 6),
            authority=row.get("authority"),
            trust_tag=row.get("trust_tag"),
            policy_version=row.get("policy_version"),
            effective_date=row.get("effective_date"),
            superseded_by=row.get("superseded_by"),
            source_url=row.get("source_url"),
            doc_type=row.get("doc_type"),
        )


IDENTIFIER_RE = re.compile(
    r"\b(CVE-\d{4}-\d{4,7}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})\b", re.I
)


def _identifiers(text: str) -> list[str]:
    return IDENTIFIER_RE.findall(text)
