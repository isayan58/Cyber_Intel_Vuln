"""Knowledge/RAG tools — policy retrieval with citation metadata."""

from __future__ import annotations

from typing import Any

from vulnintel.data.db import Database, get_db
from vulnintel.rag.retriever import HybridRetriever

_RETRIEVER: HybridRetriever | None = None


def get_retriever() -> HybridRetriever:
    global _RETRIEVER
    if _RETRIEVER is None:
        _RETRIEVER = HybridRetriever()
    return _RETRIEVER


def reset_retriever() -> None:
    """Drop the cached index — call after re-ingesting the knowledge base."""
    global _RETRIEVER
    _RETRIEVER = None


def search_policy(
    query: str,
    *,
    authority: str | None = None,
    doc_type: str | None = None,
    control_family: str | None = None,
    include_superseded: bool = True,
    top_k: int = 6,
) -> dict[str, Any]:
    """Hybrid search over the knowledge base with citation metadata."""
    filters: dict[str, Any] = {}
    if authority:
        filters["authority"] = authority
    if doc_type:
        filters["doc_type"] = doc_type
    if control_family:
        filters["control_family"] = control_family

    result = get_retriever().retrieve(
        query,
        top_k=top_k,
        filters=filters or None,
        include_superseded=include_superseded,
    )
    return result.to_dict()


def retrieve_chunk(chunk_id: str) -> dict[str, Any]:
    """Fetch one chunk verbatim by id — used to verify a citation."""
    evidence = get_retriever().get_chunk(chunk_id)
    if evidence is None:
        return {"chunk_id": chunk_id, "found": False}
    payload = evidence.to_dict()
    payload["found"] = True
    return payload


def list_policy_versions(db: Database | None = None) -> list[dict[str, Any]]:
    """Every indexed document with its version and supersession status."""
    conn = db or get_db()
    return conn.query(
        "SELECT doc_id, title, doc_type, authority, policy_version, effective_date, "
        "superseded_by, control_family, source_url, "
        "(SELECT count(*) FROM kb_chunk c WHERE c.doc_id = d.doc_id) AS chunk_count "
        "FROM kb_document d ORDER BY authority, title"
    )


def get_sla_rules() -> list[dict[str, Any]]:
    """The SLA table as data.

    Exposed as a tool so an agent can state an obligation without paraphrasing
    retrieved prose — and so the value it quotes is provably the same one the
    scorer used, since both read ``risk.policy``.
    """
    from vulnintel.risk.policy import SLA_RULES

    return [
        {
            "rule_id": rule.rule_id,
            "label": rule.label,
            "condition": rule.condition,
            "days": rule.days,
            "rationale": rule.rationale,
        }
        for rule in SLA_RULES
    ]
