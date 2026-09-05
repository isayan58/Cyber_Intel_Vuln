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
import re
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


_INTENT_HINTS: tuple[tuple[str, tuple[str, ...]], ...] = (
    # Most specific first: the rendered prompt carries the question plus
    # surrounding context, so loose keywords collide with each other.
    ("cve_investigation", ("cve-", "ghsa-", "are we affected", "blast radius")),
    ("patch_queue", ("can patch only", "patch only", "scheduled first", "capacity")),
    ("executive_brief", ("cto", "executive", "board", "most concerned")),
    ("application_assessment", ("exposure of", "assess the security")),
    ("policy_question", ("what does our policy", "policy require", "sla for")),
)

_MODE_HINTS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("executive", ("user role: cto", "user role: ciso", "user role: executive")),
    ("application_owner", ("user role: application_owner", "user role: app_owner")),
)


def _guess_intent(prompt: str) -> str:
    """Keyword intent, mirroring the supervisor's own fallback heuristic."""
    text = prompt.lower()
    for intent, hints in _INTENT_HINTS:
        if any(hint in text for hint in hints):
            return intent
    return "general"


def _guess_mode(prompt: str) -> str:
    """Response mode from the stated role, as a real planner would."""
    text = prompt.lower()
    for mode, hints in _MODE_HINTS:
        if any(hint in text for hint in hints):
            return mode
    return "analyst"


_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_GHSA_RE = re.compile(r"\bGHSA(?:-[23456789cfghjmpqrvwx]{4}){3}\b", re.IGNORECASE)


def _extract(pattern: re.Pattern[str], prompt: str) -> list[str]:
    """Entity extraction the stand-in can actually do.

    Without this the mock returns no entities at all, so every question falls
    through to the unscoped ranking branch — and "are we affected by
    CVE-1999-00000?" comes back with the global top five, which is precisely
    the fabrication the suite is meant to catch.
    """
    seen: list[str] = []
    for match in pattern.findall(prompt):
        value = match.upper()
        if value not in seen:
            seen.append(value)
    return seen[:10]


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
    "advisory_ids": [],
    "application_names": [],
    "asset_hostnames": [],
    "products": [],
    "missing_data": [],
    # A stand-in cannot cite a real chunk, so it claims no obligations rather
    # than inventing one that the citation check then correctly discards —
    # which would leave the plan asserting policy with no evidence behind it.
    "obligations": [],
    "policy_obligations": [],
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

    if field_name == "response_mode":
        return _guess_mode(prompt)
    if field_name == "cve_ids":
        return _extract(_CVE_RE, prompt)
    if field_name == "advisory_ids":
        return _extract(_GHSA_RE, prompt)
    if field_name == "intent":
        # Derived from the prompt rather than picked from the enum by hash.
        # A stand-in that routes "we can only patch 20 today" to an asset
        # lookup is not exercising the workflow the question describes.
        return _guess_intent(prompt)
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
