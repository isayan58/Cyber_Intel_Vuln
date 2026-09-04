"""Retrieval-augmented generation over policy and guidance documents."""

from vulnintel.rag.corpus import write_corpus
from vulnintel.rag.index import KnowledgeIndex
from vulnintel.rag.ingest import ingest_knowledge_base, reembed
from vulnintel.rag.retriever import Evidence, HybridRetriever, RetrievalResult

__all__ = [
    "Evidence",
    "HybridRetriever",
    "KnowledgeIndex",
    "RetrievalResult",
    "ingest_knowledge_base",
    "reembed",
    "write_corpus",
]
