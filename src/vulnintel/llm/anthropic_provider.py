"""Anthropic Claude provider.

Notes on the API surface used here:

  * ``thinking={"type": "adaptive"}`` — the current mechanism. ``budget_tokens``
    is removed on Opus 5 and returns a 400.
  * ``output_config={"effort": ...}`` — effort lives inside ``output_config``,
    not at the top level. Defaults to ``medium`` for routing/extraction nodes
    and is raised per-call for synthesis.
  * ``output_config.format`` with a JSON schema for structured agent output,
    so the planner and critic return parseable state rather than prose we then
    have to regex.
  * The system prompt is cached — it is identical across every call for a given
    agent, which is exactly the stable-prefix shape prompt caching wants.
"""

from __future__ import annotations

import json
import time
from typing import Any

from vulnintel.config import get_settings
from vulnintel.llm.base import LLMError, LLMProvider, LLMResponse, Usage
from vulnintel.logging_setup import get_logger

log = get_logger(__name__)


# Validation keywords the structured-output schema validator rejects. They are
# stripped rather than passed through, because the failure mode is a 400 that
# makes an agent silently fall back to its non-model path — the run still
# reports success and the degradation is invisible. Bounds are enforced in
# code instead (see the agents' _validate methods).
_UNSUPPORTED_NUMERIC_KEYWORDS = frozenset(
    {"minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "multipleOf"}
)


# Model families that accept ``thinking`` and ``output_config.effort``.
# Matched on prefix so dated snapshots (claude-opus-5-20260401) resolve too.
_ADAPTIVE_THINKING_PREFIXES = ("claude-opus-", "claude-sonnet-", "claude-fable-", "claude-mythos-")


def _supports_adaptive_thinking(model: str) -> bool:
    return any(model.startswith(prefix) for prefix in _ADAPTIVE_THINKING_PREFIXES)


def sanitise_schema(node: Any) -> Any:
    """Recursively drop schema keywords the API does not accept."""
    if isinstance(node, list):
        return [sanitise_schema(item) for item in node]
    if not isinstance(node, dict):
        return node

    node_type = node.get("type")
    types = node_type if isinstance(node_type, list) else [node_type]
    numeric = any(t in ("integer", "number") for t in types)

    cleaned: dict[str, Any] = {}
    for key, value in node.items():
        if numeric and key in _UNSUPPORTED_NUMERIC_KEYWORDS:
            log.debug("stripped unsupported schema keyword '%s'", key)
            continue
        cleaned[key] = sanitise_schema(value)
    return cleaned


class AnthropicProvider(LLMProvider):
    name = "anthropic"

    def __init__(self, model: str | None = None, api_key: str | None = None) -> None:
        try:
            import anthropic
        except ImportError as exc:  # pragma: no cover
            raise LLMError("the 'anthropic' package is required for this provider") from exc

        settings = get_settings()
        self.settings = settings
        self.model = model or settings.llm_model
        self._anthropic = anthropic

        key = api_key or settings.anthropic_api_key
        # A bare client also resolves ANTHROPIC_AUTH_TOKEN or an `ant auth login`
        # profile, so an unset key is not necessarily an error.
        self.client = (
            anthropic.Anthropic(api_key=key, timeout=settings.llm_timeout_seconds)
            if key
            else anthropic.Anthropic(timeout=settings.llm_timeout_seconds)
        )

    # -- public API -----------------------------------------------------------

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
        return self._call(
            system=system,
            prompt=prompt,
            max_tokens=max_tokens,
            effort=effort,
            cache_system=cache_system,
            tier=tier,
        )

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
        response = self._call(
            system=system,
            prompt=prompt,
            max_tokens=max_tokens,
            effort=effort,
            cache_system=cache_system,
            schema=schema,
            tier=tier,
        )
        try:
            response.structured = json.loads(response.text)
        except json.JSONDecodeError as exc:
            # max_tokens covers thinking as well as output, so an adaptive-thinking
            # call at high effort can spend the budget reasoning and be cut off
            # mid-JSON. Reporting that as "non-JSON" sends the reader hunting for
            # a schema bug that does not exist.
            if response.stop_reason == "max_tokens":
                raise LLMError(
                    f"output truncated at max_tokens={max_tokens or self.settings.llm_max_tokens} "
                    f"before the JSON closed ({len(response.text)} chars produced). "
                    "Raise max_tokens for this prompt or lower its effort."
                ) from exc
            raise LLMError(
                f"model returned non-JSON despite a json_schema format "
                f"(stop_reason={response.stop_reason}): {response.text[:300]}"
            ) from exc
        return response

    # -- internals ------------------------------------------------------------

    def _call(
        self,
        *,
        system: str,
        prompt: str,
        max_tokens: int | None,
        effort: str | None,
        cache_system: bool,
        schema: dict[str, Any] | None = None,
        tier: str = "deep",
    ) -> LLMResponse:
        settings = self.settings
        output_config: dict[str, Any] = {"effort": effort or settings.llm_effort}
        if schema is not None:
            output_config["format"] = {"type": "json_schema", "schema": sanitise_schema(schema)}

        # A cached system block keeps the stable prefix out of per-call cost.
        system_param: Any = (
            [{"type": "text", "text": system, "cache_control": {"type": "ephemeral", "ttl": "1h"}}]
            if cache_system
            else system
        )

        model = self.model
        if settings.llm_tiering_enabled:
            model = {
                "fast": settings.llm_model_fast,
                "mid": settings.llm_model_mid,
            }.get(tier, self.model)

        kwargs: dict[str, Any] = {
            "model": model,
            "max_tokens": max_tokens or settings.llm_max_tokens,
            "system": system_param,
            "messages": [{"role": "user", "content": prompt}],
            "output_config": output_config,
        }

        # Request shape follows the model, not the caller. Adaptive thinking and
        # the effort control are frontier-model features; sending them to Haiku
        # returns "adaptive thinking is not supported on this model" and the
        # agent silently falls back to its non-model path. The fast tier is
        # deliberately used for extraction and summarisation, which do not need
        # either feature.
        if _supports_adaptive_thinking(model):
            kwargs["thinking"] = {"type": "adaptive"}
        else:
            output_config.pop("effort", None)
            if not output_config:
                kwargs.pop("output_config")

        started = time.perf_counter()
        try:
            # Streaming avoids HTTP timeouts on long synthesis turns; the
            # helper returns the assembled message.
            with self.client.messages.stream(**kwargs) as stream:
                message = stream.get_final_message()
        except self._anthropic.APIStatusError as exc:
            raise LLMError(f"Anthropic API error {exc.status_code}: {exc.message}") from exc
        except self._anthropic.APIConnectionError as exc:
            raise LLMError(f"could not reach the Anthropic API: {exc}") from exc
        latency_ms = int((time.perf_counter() - started) * 1000)

        if message.stop_reason == "refusal":
            detail = getattr(message, "stop_details", None)
            category = getattr(detail, "category", None) if detail else None
            raise LLMError(f"request declined by safety classifier (category={category})")

        text = "".join(block.text for block in message.content if block.type == "text")
        usage = message.usage
        return LLMResponse(
            text=text.strip(),
            usage=Usage(
                input_tokens=getattr(usage, "input_tokens", 0) or 0,
                output_tokens=getattr(usage, "output_tokens", 0) or 0,
                cache_read_tokens=getattr(usage, "cache_read_input_tokens", 0) or 0,
                cache_creation_tokens=getattr(usage, "cache_creation_input_tokens", 0) or 0,
            ),
            model=message.model,
            stop_reason=message.stop_reason,
            latency_ms=latency_ms,
        )
