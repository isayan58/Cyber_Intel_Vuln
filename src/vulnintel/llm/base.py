"""LLM provider interface.

A deliberately small surface — two calls — so the provider stays swappable and
so it is obvious from the interface alone that the model never computes
anything. It reads evidence and writes prose or structured plans; the numbers
come from ``vulnintel.risk``.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_creation_tokens: int = 0

    def __add__(self, other: Usage) -> Usage:
        return Usage(
            self.input_tokens + other.input_tokens,
            self.output_tokens + other.output_tokens,
            self.cache_read_tokens + other.cache_read_tokens,
            self.cache_creation_tokens + other.cache_creation_tokens,
        )


@dataclass
class LLMResponse:
    text: str
    usage: Usage = field(default_factory=Usage)
    model: str = ""
    stop_reason: str | None = None
    structured: dict[str, Any] | None = None
    latency_ms: int = 0


class LLMProvider(abc.ABC):
    """Every provider implements exactly these two calls."""

    name: str = "base"

    @abc.abstractmethod
    def complete(
        self,
        *,
        system: str,
        prompt: str,
        max_tokens: int | None = None,
        effort: str | None = None,
        cache_system: bool = True,
        tier: str = "deep",
    ) -> LLMResponse:
        """Free-form text completion."""

    @abc.abstractmethod
    def complete_structured(
        self,
        *,
        system: str,
        prompt: str,
        schema: dict[str, Any],
        max_tokens: int | None = None,
        effort: str | None = None,
        cache_system: bool = True,
        tier: str = "deep",
    ) -> LLMResponse:
        """Completion constrained to a JSON schema. ``structured`` is populated."""


class LLMError(RuntimeError):
    """Raised when a provider fails in a way the caller should surface."""
