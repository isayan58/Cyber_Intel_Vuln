"""Base class for every specialist agent.

Each agent owns three things and nothing else:

  * an externalised prompt (``prompts/<name>.yaml``)
  * an allowlisted ToolBox
  * a ``run(state)`` that gathers evidence deterministically, optionally asks
    the model to interpret it, and writes structured output back to state

The ordering matters: **tools first, model second**. An agent that queried
nothing has nothing for the model to interpret, and a model asked to fill that
silence will oblige.
"""

from __future__ import annotations

import abc
import json
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from vulnintel.agents.state import GraphState
from vulnintel.llm import LLMError, get_provider
from vulnintel.logging_setup import get_logger
from vulnintel.prompts import get_prompt
from vulnintel.tools import ToolBox

log = get_logger(__name__)


@dataclass
class AgentResult:
    agent: str
    output: dict[str, Any] = field(default_factory=dict)
    citations: list[dict[str, Any]] = field(default_factory=list)
    span: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    prompt_version: str | None = None
    usage: dict[str, int] = field(default_factory=dict)


class Agent(abc.ABC):
    """A specialist agent."""

    name: str = "agent"
    prompt_name: str | None = None
    uses_llm: bool = True

    def __init__(self, run_id: str | None = None, persist: bool = True) -> None:
        self.run_id = run_id
        self.span_id = str(uuid.uuid4())
        self.tools = ToolBox(self.name, run_id=run_id, span_id=self.span_id, persist=persist)

    # -- interface ------------------------------------------------------------

    @abc.abstractmethod
    def gather(self, state: GraphState) -> dict[str, Any]:
        """Deterministic evidence collection. No model involvement."""

    def interpret(self, state: GraphState, gathered: dict[str, Any]) -> dict[str, Any]:
        """Optional model pass over the gathered evidence."""
        return {}

    def run(self, state: GraphState) -> AgentResult:
        started = time.perf_counter()
        result = AgentResult(agent=self.name)

        try:
            gathered = self.gather(state)
        except Exception as exc:
            log.exception("%s: evidence gathering failed", self.name)
            result.errors.append(f"{self.name}: {exc}")
            gathered = {"error": str(exc)}

        interpretation: dict[str, Any] = {}
        if self.uses_llm and self.prompt_name and not gathered.get("skip_llm"):
            try:
                interpretation = self.interpret(state, gathered)
            except LLMError as exc:
                log.warning("%s: model interpretation failed: %s", self.name, exc)
                result.errors.append(f"{self.name} interpretation: {exc}")
            except Exception as exc:
                log.exception("%s: model interpretation raised", self.name)
                result.errors.append(f"{self.name} interpretation: {exc}")

        result.output = {
            **gathered,
            **({"interpretation": interpretation} if interpretation else {}),
        }
        result.span = {
            "span_id": self.span_id,
            "node": self.name,
            "latency_ms": int((time.perf_counter() - started) * 1000),
            "status": "error" if result.errors else "ok",
            "tool_calls": [
                {
                    "tool": call.tool_name,
                    "server": call.server,
                    "rows": call.row_count,
                    "latency_ms": call.latency_ms,
                    "status": call.status,
                }
                for call in self.tools.calls
            ],
            "started_at": datetime.now(UTC).replace(tzinfo=None),
            **self._usage_fields(result),
        }
        if result.prompt_version:
            result.span["prompt_version"] = result.prompt_version
        return result

    # -- helpers --------------------------------------------------------------

    def _usage_fields(self, result: AgentResult) -> dict[str, Any]:
        """The token half of a span.

        Agents that override ``interpret`` run the model against a *private*
        AgentResult and stash the usage on ``self._last_usage``, so by the time
        the span is built the outer result is still empty. Reading through to
        the stash here is what stops those nodes reporting zero tokens — and a
        node reporting zero tokens is worse than no cost figure at all, because
        the run cost still adds up and simply excludes them.
        """
        usage = result.usage or getattr(self, "_last_usage", {}) or {}
        return {
            "input_tokens": usage.get("input_tokens"),
            "output_tokens": usage.get("output_tokens"),
            "cache_read_tokens": usage.get("cache_read_tokens"),
            "cache_creation_tokens": usage.get("cache_creation_tokens"),
            "tier": usage.get("tier"),
        }

    def _ask_structured(self, result: AgentResult, **variables: Any) -> dict[str, Any]:
        """Run this agent's prompt with its declared output schema."""
        prompt = get_prompt(self.prompt_name)  # type: ignore[arg-type]
        result.prompt_version = prompt.label

        if not prompt.output_schema:
            raise ValueError(f"prompt '{prompt.name}' has no output_schema")

        response = get_provider().complete_structured(
            system=prompt.system,
            prompt=prompt.render(**variables),
            schema=prompt.output_schema,
            effort=prompt.effort,
            max_tokens=prompt.max_tokens,
            tier=prompt.model_tier,
        )
        result.usage = {
            "input_tokens": response.usage.input_tokens,
            "output_tokens": response.usage.output_tokens,
            "cache_read_tokens": response.usage.cache_read_tokens,
            "cache_creation_tokens": response.usage.cache_creation_tokens,
            "tier": prompt.model_tier,
        }
        return response.structured or {}

    def _ask_text(self, result: AgentResult, **variables: Any) -> str:
        prompt = get_prompt(self.prompt_name)  # type: ignore[arg-type]
        result.prompt_version = prompt.label

        response = get_provider().complete(
            system=prompt.system,
            prompt=prompt.render(**variables),
            effort=prompt.effort,
            max_tokens=prompt.max_tokens,
            tier=prompt.model_tier,
        )
        result.usage = {
            "input_tokens": response.usage.input_tokens,
            "output_tokens": response.usage.output_tokens,
            "cache_read_tokens": response.usage.cache_read_tokens,
            "cache_creation_tokens": response.usage.cache_creation_tokens,
            "tier": prompt.model_tier,
        }
        return response.text


def as_json(value: Any, limit: int = 24000) -> str:
    """Serialise evidence for a prompt, truncating with an explicit marker.

    Silent truncation is dangerous here: an agent that receives 50 of 900 rows
    and is not told so will report the 50 as the whole picture.
    """
    text = json.dumps(value, indent=2, default=str, ensure_ascii=False)
    if len(text) <= limit:
        return text
    return (
        text[:limit] + f"\n\n... [TRUNCATED: {len(text) - limit} more characters were omitted. "
        "Counts stated in the aggregates above remain authoritative; do not infer "
        "totals from the rows shown here.]"
    )
