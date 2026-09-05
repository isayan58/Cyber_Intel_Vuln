"""Embedding providers.

Two implementations behind one interface:

``hash``
    A hashed bag-of-words projection. Deterministic, offline, no model
    download, and — importantly — not a placeholder that returns noise: it is
    a real hashed term-frequency vector with sublinear scaling and L2
    normalisation, so cosine similarity approximates lexical overlap. Paired
    with BM25 in the hybrid retriever this gives a system that genuinely works
    with zero setup, which is what makes the whole project cloneable and
    runnable by someone else in one command.

``sentence-transformers``
    A real dense encoder for when retrieval quality is being measured. Install
    with ``pip install -e '.[embeddings]'`` and set
    ``VULNINTEL_EMBEDDING_PROVIDER=sentence-transformers``.

The retrieval evaluation suite reports scores per provider, so the cost of the
offline default is measured rather than assumed.
"""

from __future__ import annotations

import abc
import hashlib
import math
import re
from functools import lru_cache

import numpy as np

from vulnintel.config import get_settings
from vulnintel.logging_setup import get_logger

log = get_logger(__name__)

TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9._-]*")

STOPWORDS = {
    "a",
    "an",
    "and",
    "are",
    "as",
    "at",
    "be",
    "by",
    "for",
    "from",
    "has",
    "have",
    "in",
    "is",
    "it",
    "its",
    "of",
    "on",
    "or",
    "that",
    "the",
    "to",
    "was",
    "were",
    "what",
    "when",
    "which",
    "with",
    "our",
    "we",
    "this",
    "these",
    "those",
}


def tokenize(text: str) -> list[str]:
    return [t for t in TOKEN_RE.findall(text.lower()) if t not in STOPWORDS and len(t) > 1]


class EmbeddingProvider(abc.ABC):
    name: str = "base"
    dim: int = 0

    @abc.abstractmethod
    def embed(self, texts: list[str]) -> np.ndarray:
        """Return an (n, dim) float32 array of L2-normalised vectors."""

    def embed_one(self, text: str) -> np.ndarray:
        return self.embed([text])[0]


class HashingEmbeddingProvider(EmbeddingProvider):
    name = "hash"

    def __init__(self, dim: int | None = None) -> None:
        self.dim = dim or get_settings().embedding_dim

    def _bucket(self, token: str) -> tuple[int, float]:
        digest = hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest()
        value = int.from_bytes(digest, "big")
        # Signed hashing reduces collision bias between unrelated terms.
        sign = 1.0 if value & 1 else -1.0
        return (value >> 1) % self.dim, sign

    def embed(self, texts: list[str]) -> np.ndarray:
        matrix = np.zeros((len(texts), self.dim), dtype=np.float32)
        for row, text in enumerate(texts):
            counts: dict[str, int] = {}
            for token in tokenize(text):
                counts[token] = counts.get(token, 0) + 1
                # Bigrams add a little word-order sensitivity.
            tokens = tokenize(text)
            for first, second in zip(tokens, tokens[1:], strict=False):
                bigram = f"{first}_{second}"
                counts[bigram] = counts.get(bigram, 0) + 1

            for token, count in counts.items():
                index, sign = self._bucket(token)
                matrix[row, index] += sign * (1.0 + math.log(count))

            norm = float(np.linalg.norm(matrix[row]))
            if norm > 0:
                matrix[row] /= norm
        return matrix


class SentenceTransformerProvider(EmbeddingProvider):
    name = "sentence-transformers"

    def __init__(self, model_name: str | None = None) -> None:
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "sentence-transformers is not installed. "
                "Install it with: pip install -e '.[embeddings]'"
            ) from exc

        settings = get_settings()
        self.model_name = model_name or settings.sentence_transformer_model
        log.info("loading embedding model %s", self.model_name)
        self.model = SentenceTransformer(self.model_name)
        self.dim = int(self.model.get_sentence_embedding_dimension())

    def embed(self, texts: list[str]) -> np.ndarray:
        vectors = self.model.encode(
            texts, normalize_embeddings=True, show_progress_bar=False, batch_size=32
        )
        return np.asarray(vectors, dtype=np.float32)


@lru_cache(maxsize=4)
def get_embedding_provider(name: str | None = None) -> EmbeddingProvider:
    resolved = name or get_settings().embedding_provider
    if resolved == "hash":
        return HashingEmbeddingProvider()
    if resolved == "sentence-transformers":
        return SentenceTransformerProvider()
    raise ValueError(f"unknown embedding provider: {resolved}")
