"""Agent 4 — Threat Intelligence.

KEV membership, EPSS scores and ATT&CK context. All three are looked up
deterministically; the model's only job is interpretation, and specifically
deciding which candidate ATT&CK mappings are defensible enough to keep.

Design doc §7.4: *does not invent ATT&CK mappings when evidence is weak*. The
mechanism here is that the agent can only ever retain mappings that the
deterministic CWE bridge already produced, each carrying its basis and
confidence — the model can drop, but it cannot add.
"""

from __future__ import annotations

from typing import Any

from vulnintel.agents.base import Agent, AgentResult, as_json
from vulnintel.agents.state import GraphState
from vulnintel.logging_setup import get_logger

log = get_logger(__name__)

MIN_MAPPING_CONFIDENCE = 0.6


class ThreatIntelAgent(Agent):
    name = "threat_intel"
    prompt_name = "threat_intel"

    def gather(self, state: GraphState) -> dict[str, Any]:
        entities = state.get("entities") or {}
        cve_ids = list(entities.get("cve_ids", []))[:25]

        if not cve_ids:
            evidence_bucket = (state.get("evidence") or {}).get("vulnerability_intel") or {}
            cve_ids = list(evidence_bucket.get("cve_ids", []))[:25]

        if not cve_ids:
            from vulnintel.data.db import get_db

            cve_ids = [
                row["cve_id"]
                for row in get_db().query(
                    "SELECT cve_id FROM v_executive_top_risks "
                    "ORDER BY top_score DESC NULLS LAST LIMIT 15"
                )
            ]

        kev = self.tools.call("get_kev_status", cve_ids=cve_ids) if cve_ids else {}
        epss = self.tools.call("get_epss", cve_ids=cve_ids) if cve_ids else {}
        attack = self.tools.call("get_attack_context", cve_ids=cve_ids) if cve_ids else {}

        # Filter weak mappings before the model ever sees them.
        raw_mappings = attack.get("mappings", []) if attack else []
        candidates = [
            m for m in raw_mappings if float(m.get("confidence") or 0) >= MIN_MAPPING_CONFIDENCE
        ]
        dropped_low_confidence = [
            {
                "attack_id": m.get("attack_id"),
                "cve_id": m.get("cve_id"),
                "confidence": m.get("confidence"),
                "reason": f"confidence below the {MIN_MAPPING_CONFIDENCE} threshold",
            }
            for m in raw_mappings
            if float(m.get("confidence") or 0) < MIN_MAPPING_CONFIDENCE
        ]

        trends = {}
        for cve_id in (kev.get("listed") or [])[:5]:
            history = self.tools.call("get_epss_history", cve_id=cve_id, days=30)
            if history:
                trends[cve_id] = history

        return {
            "cve_ids": cve_ids,
            "kev": kev,
            "epss": epss,
            "epss_trends": trends,
            "attack_candidates": candidates,
            "attack_techniques": attack.get("techniques", {}) if attack else {},
            "attack_mitigations": attack.get("mitigations", {}) if attack else {},
            "dropped_low_confidence": dropped_low_confidence,
            "signals_summary": self._summarise(kev, epss),
            "skip_llm": not cve_ids,
        }

    def interpret(self, state: GraphState, gathered: dict[str, Any]) -> dict[str, Any]:
        result = AgentResult(agent=self.name)
        interpretation = self._ask_structured(
            result,
            cve_ids=", ".join(gathered.get("cve_ids", [])) or "(none)",
            signals=as_json(
                {
                    "kev": gathered.get("kev"),
                    "epss": gathered.get("epss"),
                    "summary": gathered.get("signals_summary"),
                },
                limit=10000,
            ),
            attack_candidates=as_json(
                {
                    "candidates": gathered.get("attack_candidates"),
                    "techniques": gathered.get("attack_techniques"),
                },
                limit=8000,
            ),
        )

        # Enforce the contract: retained mappings must exist in the candidates.
        allowed = {
            (m.get("cve_id"), m.get("attack_id")) for m in gathered.get("attack_candidates", [])
        }
        retained = interpretation.get("retained_mappings", []) or []
        filtered = [m for m in retained if (m.get("cve_id"), m.get("attack_id")) in allowed]
        if len(filtered) != len(retained):
            log.warning(
                "threat_intel: dropped %d ATT&CK mapping(s) not present in the candidate set",
                len(retained) - len(filtered),
            )
            interpretation["fabricated_mappings_removed"] = len(retained) - len(filtered)
        interpretation["retained_mappings"] = filtered

        self._last_usage = result.usage
        self._last_prompt_version = result.prompt_version
        return interpretation

    def run(self, state: GraphState) -> AgentResult:
        result = super().run(state)
        result.prompt_version = getattr(self, "_last_prompt_version", None)
        result.usage = getattr(self, "_last_usage", {})
        result.span.update(
            {
                "input_tokens": result.usage.get("input_tokens"),
                "output_tokens": result.usage.get("output_tokens"),
                "tier": result.usage.get("tier"),
            }
        )
        return result

    @staticmethod
    def _summarise(kev: dict[str, Any], epss: dict[str, Any]) -> dict[str, Any]:
        scores = (epss or {}).get("scores", {})
        probabilities = [float(v["probability"]) for v in scores.values()]
        return {
            "kev_listed_count": len((kev or {}).get("listed", [])),
            "kev_not_listed_count": len((kev or {}).get("not_listed", [])),
            "epss_scored_count": len(scores),
            "epss_unscored_count": len((epss or {}).get("unscored", [])),
            "epss_max": max(probabilities) if probabilities else None,
            "epss_above_10pct": sum(1 for p in probabilities if p >= 0.10),
            "score_date": (epss or {}).get("score_date"),
        }
