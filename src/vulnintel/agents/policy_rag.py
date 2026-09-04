"""Agent 5 — Policy & Knowledge RAG.

Retrieves policy obligations with citations. Two behaviours worth noting:

  * It calls ``get_sla_rules`` alongside the text search. That tool returns the
    same table the deterministic scorer reads, so a quoted obligation and a
    computed deadline provably agree.
  * Retrieved text is sanitised for injection markers before it reaches the
    model, and anything suspicious is reported rather than silently stripped.
"""

from __future__ import annotations

import re
from typing import Any

from vulnintel.agents.base import Agent, AgentResult, as_json
from vulnintel.agents.state import GraphState
from vulnintel.logging_setup import get_logger

log = get_logger(__name__)

# Patterns that have no business appearing inside a policy document.
INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions", re.I),
    re.compile(r"disregard\s+(the\s+)?(system|above|previous)", re.I),
    re.compile(r"you\s+are\s+now\s+", re.I),
    re.compile(r"</?(system|assistant|instructions?)>", re.I),
    re.compile(r"new\s+instructions?\s*:", re.I),
]

DEFAULT_QUESTIONS = [
    "What is the remediation SLA for a vulnerability that is known to be exploited?",
    "What does the standard require before reporting an asset as affected?",
    "Who must approve a risk acceptance and for how long can it run?",
]


class PolicyRagAgent(Agent):
    name = "policy_rag"
    prompt_name = "policy_rag"

    def gather(self, state: GraphState) -> dict[str, Any]:
        questions = list(state.get("policy_questions") or [])
        if not questions:
            questions = DEFAULT_QUESTIONS[:2]
            # Anchor at least one query to the actual question asked.
            questions.insert(0, state.get("question", ""))

        passages: list[dict[str, Any]] = []
        conflicts: list[str] = []
        seen: set[str] = set()

        for question in questions[:5]:
            if not question.strip():
                continue
            result = self.tools.call("search_policy", query=question, top_k=6)
            conflicts.extend(result.get("conflicts", []))
            for item in result.get("evidence", []):
                if item["chunk_id"] in seen:
                    continue
                seen.add(item["chunk_id"])
                item["matched_question"] = question
                passages.append(item)

        sanitised, injection_flags = self._sanitise(passages)

        return {
            "questions": questions,
            "passages": sanitised,
            "passage_count": len(sanitised),
            "conflicts": sorted(set(conflicts)),
            "injection_flags": injection_flags,
            "sla_rules": self.tools.call("get_sla_rules"),
            "policy_versions": self.tools.call("list_policy_versions"),
            "citations": [
                {
                    "chunk_id": p["chunk_id"],
                    "title": p["title"],
                    "citation": p["citation"],
                    "policy_version": p.get("policy_version"),
                    "section": p.get("section_path"),
                    "source_url": p.get("source_url"),
                    "authority": p.get("authority"),
                    "superseded": p.get("is_superseded", False),
                }
                for p in sanitised
            ],
            "skip_llm": not sanitised,
        }

    def interpret(self, state: GraphState, gathered: dict[str, Any]) -> dict[str, Any]:
        result = AgentResult(agent=self.name)
        compact = [
            {
                "chunk_id": p["chunk_id"],
                "title": p["title"],
                "policy_version": p.get("policy_version"),
                "section": p.get("section_path"),
                "superseded": p.get("is_superseded"),
                "authority": p.get("authority"),
                "text": p["text"],
            }
            for p in gathered.get("passages", [])
        ]
        interpretation = self._ask_structured(
            result,
            need=state.get("question", ""),
            questions="\n".join(f"- {q}" for q in gathered.get("questions", [])),
            passages=as_json(compact, limit=26000),
        )

        # An obligation must cite a chunk that was actually retrieved.
        valid_chunks = {p["chunk_id"] for p in gathered.get("passages", [])}
        obligations = interpretation.get("obligations", []) or []
        kept = [o for o in obligations if o.get("chunk_id") in valid_chunks]
        if len(kept) != len(obligations):
            log.warning(
                "policy_rag: dropped %d obligation(s) citing an unretrieved chunk",
                len(obligations) - len(kept),
            )
            interpretation["uncited_obligations_removed"] = len(obligations) - len(kept)
        interpretation["obligations"] = kept

        self._last_usage = result.usage
        self._last_prompt_version = result.prompt_version
        return interpretation

    def run(self, state: GraphState) -> AgentResult:
        result = super().run(state)
        result.citations = result.output.get("citations", [])
        result.prompt_version = getattr(self, "_last_prompt_version", None)
        result.usage = getattr(self, "_last_usage", {})
        result.span.update({
            "input_tokens": result.usage.get("input_tokens"),
            "output_tokens": result.usage.get("output_tokens"),
            "tier": result.usage.get("tier"),
        })
        return result

    @staticmethod
    def _sanitise(passages: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
        """Neutralise instruction-shaped text inside retrieved documents (§15).

        The text is kept — an analyst needs to see what the document says — but
        the matched span is wrapped so it reads as quoted data, and the
        occurrence is reported so the critic can raise it.
        """
        flags: list[str] = []
        cleaned: list[dict[str, Any]] = []

        for passage in passages:
            text = passage.get("text", "")
            hits = [p.pattern for p in INJECTION_PATTERNS if p.search(text)]
            if hits:
                flags.append(
                    f"{passage.get('title')} ({passage.get('chunk_id')}) contains "
                    f"instruction-shaped text matching: {', '.join(hits)}"
                )
                for pattern in INJECTION_PATTERNS:
                    text = pattern.sub(lambda m: f"[QUOTED DOCUMENT TEXT: {m.group(0)}]", text)
                passage = {**passage, "text": text, "injection_flagged": True}
            cleaned.append(passage)

        return cleaned, flags
