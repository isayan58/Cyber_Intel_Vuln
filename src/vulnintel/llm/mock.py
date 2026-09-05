"""Deterministic offline provider.

Not a toy. Three things depend on it:

  * unit and workflow tests run with no API key and no network, and assert on
    exact output because the provider is deterministic
  * the agent graph, MCP servers and UI can be demonstrated end-to-end without
    spending anything
  * it proves the boundary the design doc insists on — with the LLM replaced by
    a stub that cannot reason at all, every number in the final answer is still
    correct, because the numbers were never the model's job

Structured calls are satisfied by walking the requested JSON schema and
emitting schema-valid values, seeded from the prompt so repeated runs match.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from vulnintel.llm.base import LLMProvider, LLMResponse, Usage


class MockProvider(LLMProvider):
    name = "mock"

    def __init__(self, model: str = "mock-deterministic") -> None:
        self.model = model
        self.calls: list[dict[str, Any]] = []

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
        self.calls.append({"system": system, "prompt": prompt, "structured": False})
        digest = _digest(system, prompt)
        text = (
            "[mock provider] Deterministic response. "
            "Every figure in this answer came from the deterministic risk "
            f"functions and the evidence supplied above (trace {digest[:8]})."
        )
        return LLMResponse(text=text, usage=Usage(120, 48), model=self.model)

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
        self.calls.append({"system": system, "prompt": prompt, "structured": True})
        seed = int(_digest(system, prompt)[:8], 16)
        value = _from_schema(schema, seed=seed, prompt=prompt)
        text = json.dumps(value)
        return LLMResponse(text=text, usage=Usage(120, 64), model=self.model, structured=value)


def _digest(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


# Sensible values for well-known fields, so a mock run produces a coherent
# investigation rather than a hash-picked one. Keyed on property name, which
# keeps the mock schema-driven rather than hard-coded to one agent.
_FIELD_DEFAULTS: dict[str, Any] = {
    "required_agents": [
        "asset_exposure",
        "vulnerability_intel",
        "threat_intel",
        "policy_rag",
        "risk_remediation",
    ],
    "parallel_groups": [
        ["asset_exposure", "vulnerability_intel", "threat_intel", "policy_rag"],
        ["risk_remediation"],
    ],
    "passed": True,
    "confidence": 0.9,
    "unsupported_claims": [],
    "contradictions": [],
    "speculative_mappings": [],
    "gaps": [],
    "injection_suspected": [],
    "unanswered": [],
    "conflicts": [],
    "dropped_mappings": [],
    "retained_mappings": [],
    "staleness_warnings": [],
    "result_limit": 5,
    "cve_ids": [],
    "advisory_ids": [],
    "application_names": [],
    "asset_hostnames": [],
    "products": [],
    "missing_data": [],
}


def _from_schema(
    schema: dict[str, Any],
    seed: int,
    prompt: str,
    depth: int = 0,
    field_name: str | None = None,
) -> Any:
    """Emit a schema-valid value. Honours enum, const, defaults and required."""
    if depth > 6:
        return None

    if field_name in _FIELD_DEFAULTS:
        return _FIELD_DEFAULTS[field_name]
    if "const" in schema:
        return schema["const"]
    if schema.get("enum"):
        options = schema["enum"]
        return options[seed % len(options)]
    if "default" in schema:
        return schema["default"]

    schema_type = schema.get("type")
    if isinstance(schema_type, list):
        schema_type = next((t for t in schema_type if t != "null"), "string")

    if schema_type == "object":
        properties = schema.get("properties", {})
        required = schema.get("required", list(properties))
        return {
            key: _from_schema(properties[key], seed + index, prompt, depth + 1, key)
            for index, key in enumerate(properties)
            if key in required
        }
    if schema_type == "array":
        item_schema = schema.get("items", {"type": "string"})
        count = max(int(schema.get("minItems", 1)), 1)
        return [_from_schema(item_schema, seed + i, prompt, depth + 1) for i in range(count)]
    if schema_type == "integer":
        return int(schema.get("minimum", 1))
    if schema_type == "number":
        return float(schema.get("minimum", 0.5))
    if schema_type == "boolean":
        return bool(seed % 2)
    return "mock"
