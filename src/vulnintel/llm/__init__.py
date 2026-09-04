"""LLM provider abstraction."""

from __future__ import annotations

import threading

from vulnintel.config import get_settings
from vulnintel.llm.base import LLMError, LLMProvider, LLMResponse, Usage
from vulnintel.llm.mock import MockProvider

__all__ = [
    "LLMError",
    "LLMProvider",
    "LLMResponse",
    "MockProvider",
    "Usage",
    "get_provider",
    "set_provider",
]

_PROVIDER: LLMProvider | None = None
_LOCK = threading.Lock()


def build_provider(name: str | None = None) -> LLMProvider:
    resolved = name or get_settings().llm_provider
    if resolved == "mock":
        return MockProvider()
    if resolved == "anthropic":
        from vulnintel.llm.anthropic_provider import AnthropicProvider

        return AnthropicProvider()
    raise ValueError(f"unknown LLM provider: {resolved}")


def get_provider() -> LLMProvider:
    global _PROVIDER
    if _PROVIDER is None:
        with _LOCK:
            if _PROVIDER is None:
                _PROVIDER = build_provider()
    return _PROVIDER


def set_provider(provider: LLMProvider | None) -> None:
    """Override the process-wide provider — used by tests and the CLI."""
    global _PROVIDER
    with _LOCK:
        _PROVIDER = provider
