"""Final response composition.

Not one of the seven core agents — it holds no tools and gathers no evidence.
It renders the verified plan for the intended reader, which is deliberately
kept separate from the risk agent so that "what should we do" and "how do we
say it" fail independently.
"""

from __future__ import annotations

from typing import Any

from vulnintel.agents.base import Agent, AgentResult, as_json
from vulnintel.agents.state import GraphState
from vulnintel.logging_setup import get_logger

log = get_logger(__name__)


class ResponderAgent(Agent):
    name = "responder"
    prompt_name = "responder"

    def __init__(self, run_id: str | None = None, persist: bool = True) -> None:
        super().__init__(run_id=run_id, persist=persist)
        self.tools.allowed = set()  # renders only; touches nothing

    def gather(self, state: GraphState) -> dict[str, Any]:
        return {}

    def run(self, state: GraphState) -> AgentResult:
        import time
        from datetime import UTC, datetime

        started = time.perf_counter()
        result = AgentResult(agent=self.name)
        evidence = state.get("evidence") or {}

        def finish(answer: str) -> AgentResult:
            result.output = {"final_answer": answer}
            result.span = {
                "span_id": self.span_id,
                "node": self.name,
                "latency_ms": int((time.perf_counter() - started) * 1000),
                "status": "error" if result.errors else "ok",
                "tool_calls": [],
                "started_at": datetime.now(UTC).replace(tzinfo=None),
                "prompt_version": result.prompt_version,
            }
            return result

        risk = evidence.get("risk_remediation") or {}
        plan = risk.get("interpretation") or {}
        findings = risk.get("findings") or []
        critique = state.get("critique") or {}

        if not plan and not findings:
            return finish(self._nothing_found(state))

        try:
            answer = self._ask_text(
                result,
                question=state.get("question", ""),
                response_mode=state.get("response_mode", "analyst"),
                plan=as_json(plan, limit=12000),
                scored_findings=as_json(
                    _presentable(findings, state.get("result_limit", 5)), limit=20000
                ),
                citations=as_json(state.get("citations") or [], limit=6000),
                critic_notes=as_json(
                    {
                        "passed": critique.get("passed"),
                        "confidence": critique.get("confidence"),
                        "unsupported_claims": critique.get("unsupported_claims"),
                        "contradictions": critique.get("contradictions"),
                        "summary": critique.get("summary"),
                        "deterministic_failures": critique.get("deterministic_failures"),
                    },
                    limit=6000,
                ),
            )
        except Exception as exc:
            log.exception("responder failed; falling back to a deterministic rendering")
            result.errors.append(f"responder: {exc}")
            answer = render_deterministic(state)

        return finish(_with_degradation_notice(answer, state))

    @staticmethod
    def _nothing_found(state: GraphState) -> str:
        return (
            "## No matching findings\n\n"
            f"I could not find any scored, affected findings for: "
            f"_{state.get('question', '')}_\n\n"
            "This usually means one of:\n\n"
            "- the vulnerability feeds have not been ingested yet "
            "(`vulnintel ingest all`)\n"
            "- the synthetic estate has not been generated (`vulnintel generate`)\n"
            "- findings have not been matched and scored (`vulnintel score`)\n\n"
            "Run `vulnintel status` to see which stage is missing."
        )


def _with_degradation_notice(answer: str, state: GraphState) -> str:
    """Append a visible notice when any agent's model call failed.

    Three separate live runs completed while agents were silently dead — the
    run reported success and only the log showed otherwise. An answer produced
    from partial reasoning must say so on its face, because the reader has no
    other way to know.
    """
    errors = [e for e in (state.get("errors") or []) if "interpretation" in e]
    if not errors:
        return answer

    agents = sorted({e.split(" ", 1)[0].rstrip(":") for e in errors})
    lines = [
        answer,
        "",
        "---",
        "",
        f"> **Degraded run.** {len(errors)} agent(s) could not complete their model "
        f"pass: `{'`, `'.join(agents)}`. Deterministic evidence, scoring and "
        "verification assertions are unaffected — every figure above still comes "
        "from stored values — but the narrative synthesis for those agents is "
        "missing, so this answer is less complete than usual.",
    ]
    for error in errors[:4]:
        lines.append(f">   - {error[:180]}")
    return "\n".join(lines)


def _presentable(findings: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    keep = (
        "finding_id",
        "cve_id",
        "advisory_id",
        "hostname",
        "asset_count",
        "finding_count",
        "application_name",
        "application_count",
        "business_service",
        "tier",
        "owner_team",
        "environment",
        "internet_facing",
        "product",
        "installed_version",
        "fixed_version",
        "score",
        "score_breakdown",
        "cvss_base",
        "cvss_severity",
        "epss",
        "epss_percentile",
        "kev_listed",
        "sla_days",
        "sla_due_date",
        "sla_breached",
        "version_verdict",
        "match_path",
        "match_confidence",
        "cve_description",
    )
    return [{k: f.get(k) for k in keep if k in f} for f in findings[:limit]]


def render_deterministic(state: GraphState) -> str:
    """Model-free rendering of the ranked findings.

    Used when the responder fails and by ``vulnintel rank``. It exists to make
    a specific point demonstrable: with the language model removed entirely,
    the platform still produces a correct, cited, prioritised answer — because
    the ranking was never the model's contribution.
    """
    evidence = state.get("evidence") or {}
    findings = (evidence.get("risk_remediation") or {}).get("findings") or []
    if not findings:
        return "No affected, scored findings matched this question."

    # rank_findings returns two row shapes: one per finding, or one per CVE
    # when the question is executive. They carry different columns, so the
    # renderer picks its scope column rather than emitting a table of dashes.
    grouped = any("asset_count" in f for f in findings)

    lines = [
        "## Prioritised findings",
        "",
        "_Rendered deterministically from stored scores; no model involvement._",
        "",
        "| # | CVE | Component | "
        + ("Blast radius" if grouped else "Asset / application")
        + " | Score | KEV | EPSS | Installed | Fix | Due |",
        "|---|-----|-----------|" + "-" * 14 + "|-------|-----|------|-----------|-----|-----|",
    ]
    for index, finding in enumerate(findings[: state.get("result_limit", 5)], start=1):
        if grouped:
            scope = (
                f"{finding.get('asset_count') or 0} assets"
                f" / {finding.get('application_count') or 0} apps"
            )
            exemplar = (finding.get("top_assets") or [{}])[0]
            installed = exemplar.get("installed_version") or "various"
        else:
            scope = (
                " / ".join(
                    part
                    for part in (finding.get("hostname"), finding.get("application_name"))
                    if part
                )
                or "—"
            )
            installed = finding.get("installed_version") or "—"

        due = finding.get("sla_due_date") or finding.get("earliest_due_date") or "—"

        lines.append(
            "| {n} | {cve} | {product} | {scope} | {score} | {kev} | {epss} | {inst} | {fix} | {due} |".format(
                n=index,
                cve=finding.get("cve_id") or finding.get("advisory_id") or "—",
                product=finding.get("product") or "—",
                scope=scope,
                score=f"{finding['score']:.0f}" if finding.get("score") is not None else "—",
                kev="yes" if finding.get("kev_listed") else "no",
                epss=f"{finding['epss']:.3f}" if finding.get("epss") is not None else "—",
                inst=installed,
                fix=finding.get("fixed_version") or "none known",
                due=due,
            )
        )

    if grouped:
        lines += ["", "### Most exposed assets per issue", ""]
        for finding in findings[: state.get("result_limit", 5)]:
            exemplars = finding.get("top_assets") or []
            if not exemplars:
                continue
            # One CVE can produce several findings on the same asset (multiple
            # affected ranges in one advisory), so exemplars are deduplicated
            # by host before display.
            seen: set[str] = set()
            unique = []
            for asset in exemplars:
                host = asset.get("hostname")
                if host and host not in seen:
                    seen.add(host)
                    unique.append(asset)
            names = ", ".join(
                f"`{a.get('hostname')}` ({a.get('installed_version')})" for a in unique[:3]
            )
            lines.append(f"- **{finding.get('cve_id')}** — {names}")

    explanations = (evidence.get("risk_remediation") or {}).get("score_explanations") or {}
    if explanations:
        lines += ["", "### How these scores were calculated", ""]
        for finding_id, detail in list(explanations.items())[:5]:
            parts = ", ".join(
                f"{c['component']}={c['normalised_value']}x{c['weight']}={c['contribution']}"
                for c in detail.get("breakdown", [])
                if c.get("contribution") is not None
            )
            lines.append(
                f"- **Finding {finding_id}** — {detail.get('score')}/100 "
                f"({detail.get('model_version')}): {parts}"
            )
            for note in detail.get("notes", []) or []:
                lines.append(f"  - {note}")

    citations = state.get("citations") or []
    if citations:
        lines += ["", "### Sources", ""]
        for citation in citations[:10]:
            lines.append(f"- {citation.get('citation')} (`{citation.get('chunk_id')}`)")

    return "\n".join(lines)
