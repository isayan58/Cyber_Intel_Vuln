"""LLM provider schema handling.

Regression cover for a live-only failure: the structured-output validator
rejects numeric ``minimum``/``maximum``, which made two agents fall back to
their non-model path while the run still reported success. Silent degradation
is the worst kind, so the sanitiser is tested directly.
"""

from __future__ import annotations

from vulnintel.llm.anthropic_provider import sanitise_schema


class TestSanitiseSchema:
    def test_strips_numeric_bounds(self):
        cleaned = sanitise_schema(
            {"type": "object",
             "properties": {"confidence": {"type": "number", "minimum": 0, "maximum": 1}}}
        )
        assert cleaned["properties"]["confidence"] == {"type": "number"}

    def test_strips_integer_minimum(self):
        cleaned = sanitise_schema({"type": "integer", "minimum": 1, "description": "keep me"})
        assert "minimum" not in cleaned
        assert cleaned["description"] == "keep me"

    def test_keeps_bounds_on_non_numeric_types(self):
        """minItems on an array is a different keyword and must survive."""
        cleaned = sanitise_schema({"type": "array", "minItems": 2, "items": {"type": "string"}})
        assert cleaned["minItems"] == 2

    def test_recurses_into_nested_structures(self):
        cleaned = sanitise_schema({
            "type": "object",
            "properties": {
                "gaps": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {"weight": {"type": "number", "minimum": 0}},
                    },
                }
            },
        })
        assert "minimum" not in cleaned["properties"]["gaps"]["items"]["properties"]["weight"]

    def test_preserves_enum_required_and_additional_properties(self):
        schema = {
            "type": "object",
            "properties": {"mode": {"type": "string", "enum": ["a", "b"]}},
            "required": ["mode"],
            "additionalProperties": False,
        }
        assert sanitise_schema(schema) == schema

    def test_handles_union_types(self):
        cleaned = sanitise_schema({"type": ["number", "null"], "minimum": 0})
        assert "minimum" not in cleaned

    def test_every_shipped_prompt_schema_survives_sanitising(self):
        """No prompt in the repo may carry a keyword the API rejects."""
        from vulnintel.prompts import get_registry

        registry = get_registry()
        for name in registry.available():
            schema = registry.get(name).output_schema
            if schema is None:
                continue
            assert sanitise_schema(schema) == schema, (
                f"prompts/{name}.yaml carries a schema keyword the API rejects"
            )
