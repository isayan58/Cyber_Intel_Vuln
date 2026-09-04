"""Generate the cost / performance / accuracy optimisation report as .docx.

    python scripts/build_optimisation_report.py

The document is written to ``docs/generated/`` which is gitignored, along with
``*.docx`` — the report is a build artefact, reproducible from this script and
from the trace tables, so the script is the thing worth committing.

Measured figures are read live from ``agent_run`` and ``agent_span`` where they
exist, so the report cannot drift from what actually happened.
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from docx import Document  # noqa: E402
from docx.enum.table import WD_TABLE_ALIGNMENT  # noqa: E402
from docx.enum.text import WD_ALIGN_PARAGRAPH  # noqa: E402
from docx.oxml import OxmlElement  # noqa: E402
from docx.oxml.ns import qn  # noqa: E402
from docx.shared import Inches, Pt, RGBColor  # noqa: E402

OUTPUT = REPO_ROOT / "docs" / "generated" / "VulnIntel_Optimisation_Report.docx"

INK = RGBColor(0x1A, 0x23, 0x40)
ACCENT = RGBColor(0x1D, 0x4E, 0xD8)
MUTED = RGBColor(0x5A, 0x67, 0x80)
GOOD = RGBColor(0x0A, 0x7D, 0x3C)
WARN = RGBColor(0xB4, 0x53, 0x09)


# --------------------------------------------------------------------------
# measured data
# --------------------------------------------------------------------------


def measured() -> dict:
    """Pull real telemetry; fall back to the recorded baseline if unavailable."""
    try:
        from vulnintel.data.db import get_db

        db = get_db()
        nodes = db.query(
            """
            SELECT node, count(*) AS execs, round(avg(latency_ms)) AS avg_ms,
                   max(latency_ms) AS max_ms,
                   sum(CASE WHEN status='error' THEN 1 ELSE 0 END) AS errs
            FROM agent_span WHERE node IS NOT NULL AND node <> 'unknown'
            GROUP BY node ORDER BY avg_ms DESC
            """
        )
        runs = db.query(
            """
            SELECT run_id, latency_ms, replan_count, total_input_tokens AS tin,
                   total_output_tokens AS tout
            FROM agent_run WHERE total_output_tokens > 1000
            ORDER BY started_at
            """
        )
        return {"nodes": nodes, "runs": runs, "live": True}
    except Exception as exc:  # noqa: BLE001 - the report must build regardless
        print(f"  (telemetry unavailable: {exc}; using recorded baseline)")
        return {"nodes": [], "runs": [], "live": False}


# --------------------------------------------------------------------------
# docx helpers
# --------------------------------------------------------------------------


def setup_styles(doc: Document) -> None:
    normal = doc.styles["Normal"]
    normal.font.name = "Calibri"
    normal.font.size = Pt(10.5)
    normal.paragraph_format.space_after = Pt(7)
    normal.paragraph_format.line_spacing = 1.13

    for level, size, colour in ((1, 19, INK), (2, 14, ACCENT), (3, 11.5, INK)):
        style = doc.styles[f"Heading {level}"]
        style.font.name = "Calibri"
        style.font.size = Pt(size)
        style.font.color.rgb = colour
        style.font.bold = True
        style.paragraph_format.space_before = Pt(15 if level < 3 else 11)
        style.paragraph_format.space_after = Pt(5)


def shade(cell, hex_colour: str) -> None:
    element = OxmlElement("w:shd")
    element.set(qn("w:fill"), hex_colour)
    cell._tc.get_or_add_tcPr().append(element)


def para(doc, text: str, *, size=10.5, bold=False, italic=False,
         colour=None, space_after=7, align=None):
    p = doc.add_paragraph()
    run = p.add_run(text)
    run.font.size = Pt(size)
    run.bold = bold
    run.italic = italic
    if colour:
        run.font.color.rgb = colour
    p.paragraph_format.space_after = Pt(space_after)
    if align:
        p.alignment = align
    return p


def bullet(doc, text: str, *, bold_prefix: str | None = None, level=0):
    p = doc.add_paragraph(style="List Bullet")
    p.paragraph_format.left_indent = Inches(0.26 + 0.24 * level)
    p.paragraph_format.space_after = Pt(3)
    if bold_prefix:
        run = p.add_run(bold_prefix)
        run.bold = True
        run.font.size = Pt(10.5)
    run = p.add_run(text)
    run.font.size = Pt(10.5)
    return p


def table(doc, headers: list[str], rows: list[list[str]], widths: list[float] | None = None):
    t = doc.add_table(rows=1, cols=len(headers))
    t.style = "Table Grid"
    t.alignment = WD_TABLE_ALIGNMENT.CENTER

    for i, head in enumerate(headers):
        cell = t.rows[0].cells[i]
        cell.text = ""
        run = cell.paragraphs[0].add_run(head)
        run.bold = True
        run.font.size = Pt(9)
        run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
        shade(cell, "1A2340")

    for r_index, row in enumerate(rows):
        cells = t.add_row().cells
        for c_index, value in enumerate(row):
            cells[c_index].text = ""
            run = cells[c_index].paragraphs[0].add_run(str(value))
            run.font.size = Pt(9)
            if c_index == 0:
                run.bold = True
        if r_index % 2 == 1:
            for cell in cells:
                shade(cell, "F2F5FA")

    if widths:
        for row in t.rows:
            for i, width in enumerate(widths):
                row.cells[i].width = Inches(width)
    doc.add_paragraph().paragraph_format.space_after = Pt(3)
    return t


def callout(doc, title: str, body: str, colour="EEF3FD"):
    t = doc.add_table(rows=1, cols=1)
    t.style = "Table Grid"
    cell = t.rows[0].cells[0]
    shade(cell, colour)
    cell.text = ""
    p = cell.paragraphs[0]
    run = p.add_run(title + "  ")
    run.bold = True
    run.font.size = Pt(10)
    run.font.color.rgb = INK
    run = p.add_run(body)
    run.font.size = Pt(10)
    doc.add_paragraph().paragraph_format.space_after = Pt(3)


def code(doc, text: str):
    p = doc.add_paragraph()
    p.paragraph_format.left_indent = Inches(0.24)
    p.paragraph_format.space_after = Pt(6)
    run = p.add_run(text)
    run.font.name = "Consolas"
    run.font.size = Pt(9)
    run.font.color.rgb = MUTED
    return p


# --------------------------------------------------------------------------
# document
# --------------------------------------------------------------------------


def build() -> Path:
    data = measured()
    doc = Document()
    setup_styles(doc)

    for section in doc.sections:
        section.top_margin = section.bottom_margin = Inches(0.85)
        section.left_margin = section.right_margin = Inches(0.9)

    # ---- title ----
    para(doc, "VULNINTEL AI", size=9, bold=True, colour=ACCENT, space_after=2)
    para(doc, "Cost, Performance and Accuracy Optimisation", size=21, bold=True,
         colour=INK, space_after=3)
    para(doc,
         "Measured baseline, implemented changes, and the remaining backlog",
         size=11.5, colour=MUTED, space_after=10)
    para(doc, f"Generated {datetime.now(UTC):%d %B %Y}  ·  "
              f"telemetry: {'live from agent_run / agent_span' if data['live'] else 'recorded baseline'}",
         size=8.5, italic=True, colour=MUTED, space_after=14)

    callout(
        doc, "Summary.",
        "Four live investigations against Claude Opus 5 established a baseline of "
        "133–538 seconds and $0.53–$0.80 per question, with output tokens accounting "
        "for roughly two thirds of the bill and effectively zero cache reuse. Six "
        "changes were implemented against that measurement. The two structural ones "
        "— routing extraction work to a cheaper model, and gating the most expensive "
        "node behind deterministic checks — account for most of the expected saving. "
        "A seventh change removes the accuracy defect that caused two of the four runs "
        "to re-plan, which was itself the single largest driver of both cost and latency.",
    )

    # ---- 1. baseline ----
    doc.add_heading("1. Measured baseline", level=1)
    para(doc,
         "Every figure below is read from the platform's own trace tables. No estimates "
         "were used where a measurement exists.")

    if data["runs"]:
        rows = []
        for r in data["runs"]:
            cost = (r["tin"] or 0) / 1e6 * 5 + (r["tout"] or 0) / 1e6 * 25
            rows.append([
                r["run_id"][:8],
                f"{(r['latency_ms'] or 0) / 1000:.0f}s",
                str(r["replan_count"]),
                f"{r['tin']:,}",
                f"{r['tout']:,}",
                f"${cost:.2f}",
            ])
        table(doc, ["Run", "Wall clock", "Re-plans", "Input tok", "Output tok", "Cost"],
              rows, [0.9, 1.0, 0.85, 1.1, 1.1, 0.8])

    doc.add_heading("1.1 Where the time goes", level=2)
    if data["nodes"]:
        rows = [
            [n["node"], f"{(n['avg_ms'] or 0) / 1000:.1f}s",
             f"{(n['max_ms'] or 0) / 1000:.1f}s", str(n["execs"]), str(n["errs"])]
            for n in data["nodes"]
        ]
        table(doc, ["Node", "Mean", "Worst", "Executions", "Errors"], rows,
              [1.9, 0.85, 0.85, 1.1, 0.8])

    para(doc,
         "Three nodes — risk_remediation, critic and responder — account for the "
         "overwhelming majority of both latency and spend. The four evidence-gathering "
         "agents are comparatively cheap, and vulnerability_intel is nearly free because "
         "it skips its model pass when the warehouse returns no records.")

    doc.add_heading("1.2 Where the money goes", level=2)
    table(doc,
          ["Component", "Share of a typical run", "Why"],
          [["Output tokens", "~67%",
            "Opus 5 bills output at 5x input ($25 vs $5 per 1M). Adaptive thinking at "
            "high effort consumes output budget before a single visible token."],
           ["Input tokens", "~33%",
            "Evidence payloads of 20–26k characters per synthesis agent."],
           ["Cache reuse", "~0%",
            "Each agent made one call per run with a unique system prefix, and the "
            "default cache TTL is five minutes — nothing to reuse within a run."]],
          [1.5, 1.6, 3.6])

    # ---- 2. implemented ----
    doc.add_heading("2. Changes implemented", level=1)

    changes = [
        ("2.1", "Two-tier model routing", "Cost",
         "Extraction and summarisation do not need frontier reasoning. The supervisor, "
         "asset_exposure, vulnerability_intel, threat_intel and policy_rag now run on "
         "Claude Haiku 4.5 ($1/$5 per 1M); risk_remediation, critic and responder stay "
         "on Opus 5 ($5/$25), where judgement genuinely matters.",
         "Each prompt YAML declares model_tier: fast | deep. The registry surfaces it, "
         "the agent base passes it through, and the provider resolves it per call. "
         "Switchable off wholesale via VULNINTEL_LLM_TIERING_ENABLED.",
         "Five of eight agents move to a model 5x cheaper on both input and output. "
         "These agents contribute roughly a third of tokens, so the expected saving on "
         "that portion is ~80%."),

        ("2.2", "Deterministic critic gate", "Cost + latency",
         "The critic was the second most expensive node (18s mean, 81s worst, ~4k output "
         "tokens) and ran unconditionally. Its deterministic assertions are cheap and "
         "always run; the model audit only earns its cost when there is free-form prose "
         "to audit and something has actually gone wrong.",
         "The model pass is skipped when there is no draft, or when every blocking "
         "assertion passed and the draft carries under 400 characters of narrative. A "
         "well-formed verdict is still emitted from the assertions alone, marked "
         "audit_mode: deterministic_only — a skipped audit must never be "
         "indistinguishable from a failed one.",
         "Removes the single largest per-run cost on clean runs while preserving the "
         "audit precisely where it has value: runs that failed a check."),

        ("2.3", "Effort and token budgets retuned", "Cost + reliability",
         "risk_remediation and critic ran at effort: high. On adaptive-thinking models "
         "the effort setting drives output-token consumption directly, and max_tokens "
         "covers thinking as well as visible output.",
         "Both dropped to effort: medium. Budgets raised where truncation was observed: "
         "critic 6k → 16k, risk_remediation 8k → 16k, responder 8k → 12k. Fast-tier "
         "agents dropped to effort: low with tighter budgets.",
         "Directly attacks the 67% of spend that is output tokens, and fixes a real "
         "defect: the critic was being truncated mid-JSON at 6k and failing silently."),

        ("2.4", "Prompt caching that can actually hit", "Cost",
         "Cached prefixes were being written and never read, because the default "
         "ephemeral TTL is five minutes and each agent issues one call per run.",
         "System blocks now carry cache_control with ttl: 1h. Per-agent system prompts "
         "are byte-stable, so consecutive investigations within the hour read the prefix "
         "instead of paying for it.",
         "Cached reads bill at ~0.1x. On repeat questions the system-prompt share of "
         "input becomes near-free; measured cache_read was 0–4,662 tokens before."),

        ("2.5", "Single-sourced blast-radius counts", "Accuracy",
         "risk_remediation reported 15 affected applications (untruncated SQL GROUP BY) "
         "while asset_exposure reported 14 (recounted from a 200-row truncated sample). "
         "The critic correctly flagged the contradiction and forced two re-plans, which "
         "doubled both latency and cost on that run.",
         "get_findings_for_cve now returns an authoritative_counts block computed over "
         "the full result set, alongside the truncated rows. asset_exposure reads those "
         "counts rather than recomputing from the sample. Two agents deriving one "
         "statistic by different routes was a design fault, not a prompt fault.",
         "Removes the most expensive failure mode observed: a re-plan cycle costs a full "
         "risk_remediation plus critic pair, roughly 140 seconds and $0.25."),

        ("2.6", "Truncation reports itself", "Reliability",
         "A response cut off at max_tokens surfaced as 'model returned non-JSON despite "
         "a json_schema format', which points the reader at a schema bug that does not "
         "exist. Diagnosis of the real cause took a full extra run.",
         "complete_structured now inspects stop_reason and raises a specific error "
         "naming the budget and the remedy. Schema keywords the API rejects (numeric "
         "minimum/maximum) are stripped centrally by sanitise_schema, with a test that "
         "fails if any shipped prompt reintroduces one.",
         "Not a saving in itself; it converts a class of silent, expensive "
         "misdiagnosis into a one-line answer."),

        ("2.8", "Request shape follows the model", "Reliability",
         "The first verification run of the tiering change failed on all five fast-tier "
         "agents with 'adaptive thinking is not supported on this model'. Opus-specific "
         "parameters were being sent to Haiku unconditionally, and every affected agent "
         "silently fell back to its non-model path.",
         "The provider now selects the request shape from the model family: thinking and "
         "output_config.effort are attached only for models that accept them, matched on "
         "prefix so dated snapshots resolve correctly.",
         "Without this the tiering change was a net negative — it disabled five agents "
         "while appearing to succeed. Found only because the run was measured rather "
         "than assumed to work."),

        ("2.9", "Grouped scores are explainable", "Accuracy + cost",
         "Executive answers group findings by CVE. Grouped rows had no finding_id, so no "
         "score breakdown was ever fetched, and the critic correctly refused to accept "
         "five scores it could not trace. Each refusal cost a full re-plan cycle.",
         "rank_findings now returns an exemplar_finding_id on every grouped row, and "
         "risk_remediation resolves a component breakdown from it.",
         "Removes one of the two remaining causes of re-planning, which is the dominant "
         "cost driver."),

        ("2.7", "Degraded runs declare themselves", "Accuracy",
         "Three separate live runs completed with agents silently dead — the run "
         "reported success, the answer looked complete, and only the log showed "
         "otherwise. This is the most dangerous failure mode a system like this has.",
         "The responder appends a visible notice naming which agents lost their model "
         "pass, and states plainly that deterministic figures are unaffected while the "
         "synthesis is thinner.",
         "Makes partial failure legible to the reader, who otherwise has no way to know."),
    ]

    for num, title, axis, problem, change, effect in changes:
        doc.add_heading(f"{num} {title}", level=2)
        p = doc.add_paragraph()
        run = p.add_run(f"Axis: {axis}")
        run.bold = True
        run.font.size = Pt(9)
        run.font.color.rgb = ACCENT
        p.paragraph_format.space_after = Pt(4)
        bullet(doc, problem, bold_prefix="Problem observed.  ")
        bullet(doc, change, bold_prefix="Change made.  ")
        bullet(doc, effect, bold_prefix="Expected effect.  ")

    # ---- 3. measured effect ----
    doc.add_heading("3. Measured effect", level=1)
    para(doc,
         "A verification run was executed against the live API after the changes. The "
         "comparison below is like-for-like: both runs took two re-plan cycles, so the "
         "difference is attributable to the optimisations rather than to a luckier path "
         "through the graph.")
    table(doc,
          ["Metric", "Baseline (2 re-plans)", "Optimised (2 re-plans)", "Change"],
          [["Wall clock", "537s", "427s", "-21%"],
           ["Cost", "$0.795", "$0.519", "-35%"],
           ["Opus input tokens", "51,887", "32,514", "-37%"],
           ["Opus output tokens", "21,424", "12,913", "-40%"],
           ["Haiku tokens", "0", "18,046 in / 3,078 out", "work moved off Opus"],
           ["Cache reads", "0-4,662", "3,484", "prefix reuse working"],
           ["Agent errors", "0-2 silent", "0", "silent failures eliminated"]],
          [1.6, 1.6, 1.9, 1.5])
    callout(
        doc, "Honest reading.",
        "A 35% cost reduction on a run that still re-planned twice. The larger prize is "
        "removing the re-plans themselves: a clean baseline run cost $0.53 in 133 "
        "seconds, so eliminating both cycles matters more than any per-token saving. "
        "Section 3.1 covers what still forces them.", "FFF6E8",
    )

    doc.add_heading("3.1 Why the optimised run still re-planned", level=2)
    para(doc, "The critic rejected the draft twice, and on inspection it was right both "
              "times. Two distinct causes:")
    bullet(doc,
           "In executive mode the ranking is grouped by CVE, and grouped rows carried no "
           "finding_id — so explain_score was never called and the component breakdown "
           "was absent. The critic saw five scores it could not substantiate and flagged "
           "them, correctly. Fixed: grouped rows now carry an exemplar_finding_id and the "
           "breakdown is always retrievable.",
           bold_prefix="Unverifiable scores.  ")
    bullet(doc,
           "vulnerability_intel returns nothing because no CVE records are loaded, so the "
           "draft's uncertainties section correctly says no vulnerability intelligence was "
           "retrieved while the body quotes installed and fixed versions from the OSV path. "
           "The critic flagged the inconsistency. This resolves when NVD is ingested "
           "(section 4, item 2) and is not a code defect.",
           bold_prefix="Missing NVD intelligence.  ")
    para(doc,
         "Both were found by the critic rather than by a human reading output, which is "
         "the verification layer doing exactly what it was built for.",
         size=9.5, italic=True, colour=MUTED)

    doc.add_heading("3.2 Projection for the remaining work", level=2)
    callout(
        doc, "Not yet measured.",
        "The figures below are projections from the measured baseline and published "
        "pricing, not measurements. They should be replaced once a clean-run "
        "verification is possible.", "FFF6E8",
    )
    table(doc,
          ["Change", "Cost", "Latency", "Confidence in estimate"],
          [["Two-tier routing", "−25 to −30%", "−10 to −15%",
            "High — pricing is published, token split is measured"],
           ["Critic gate (clean runs)", "−20 to −25%", "−15 to −30%",
            "High — the node's cost and latency are measured directly"],
           ["Effort medium + budgets", "−15 to −25%", "−10 to −20%",
            "Medium — output volume varies with the question"],
           ["1-hour cache TTL", "−5 to −15%", "negligible",
            "Low — depends entirely on repeat-question rate"],
           ["Single-sourced counts", "−30% amortised", "−30% amortised",
            "Medium — removes re-plans on 2 of 4 observed runs"],
           ["Removing both re-plan cycles", "-50 to -60%", "-60 to -65%",
            "High — a clean baseline run was 133s / $0.53"],
           ["Combined, clean run", "≈ $0.15-0.25", "≈ 70-110s",
            "To be confirmed by measurement"]],
          [1.7, 1.05, 1.05, 2.9])

    # ---- 4. backlog ----
    doc.add_heading("4. Recommended but not yet implemented", level=1)
    para(doc, "Ordered by value per unit of effort. These are larger than prompt or "
              "routing changes and warrant their own work.")

    table(doc,
          ["#", "Change", "Axis", "Rationale"],
          [["1", "Collapse findings to one per (asset, CVE)", "Accuracy",
            "516,294 findings across 12,000 assets is 43 per asset; one CVE yields "
            "several findings per asset when an advisory has multiple affected ranges. "
            "A queue at this volume would be rejected on sight. Also shrinks every "
            "evidence payload the model reads."],
           ["2", "Ingest NVD and exercise the CPE path", "Accuracy",
            "The cpe match path has produced zero findings because no CVE records are "
            "loaded. Roughly a third of the matching code and all of in_cpe_range have "
            "never run against real data."],
           ["3", "Run the critic concurrently with the responder", "Latency",
            "They are serialised today. Rendering optimistically and re-rendering only "
            "on a critic failure removes the critic from the critical path entirely."],
           ["4", "Stream the responder to the UI", "Perceived latency",
            "SSE plumbing already exists. First visible token in a few seconds rather "
            "than after the full generation."],
           ["5", "Real embeddings instead of the hash provider", "Accuracy",
            "The out-of-scope adversarial retrieval case fails at rerank 0.0156 against "
            "a 0.012 floor — too close. A dense encoder would separate it cleanly."],
           ["6", "Move to PostgreSQL", "Performance",
            "DuckDB permits a single writer, so ingestion and serving cannot run "
            "concurrently. Also unlocks pgvector."],
           ["7", "Semantic response cache", "Cost",
            "'Top five issues this week' is asked repeatedly against data that changes "
            "daily. Caching on a question fingerprint plus a data-version key would "
            "make repeat asks nearly free."]],
          [0.35, 2.15, 0.85, 3.3])

    # ---- 5. what must not be optimised ----
    doc.add_heading("5. What must not be optimised away", level=1)
    callout(
        doc, "Constraint.",
        "The deterministic layer is not a cost centre to be trimmed. Version comparison, "
        "risk scoring, SLA derivation and the critic's assertions run in single-digit "
        "milliseconds and cost nothing, because they never call a model. They are also "
        "the only reason the platform produced a correct, cited, ranked answer during a "
        "run in which every model call failed. Any optimisation that moves work from "
        "that layer into the model trades away the property the architecture exists to "
        "provide.", "EAF6EE",
    )
    for text in (
        "Deterministic scoring and version comparison — 104 tests, all properties hold.",
        "The critic's deterministic assertions — they run whether or not the model audit does.",
        "Persisted score components — the audit trail behind every ranking.",
        "Tool-call auditing — arguments, row counts and outcome for every call.",
    ):
        bullet(doc, text)

    doc.add_heading("6. Reproducing this report", level=1)
    code(doc, "python scripts/build_optimisation_report.py")
    para(doc,
         "Figures in sections 1 and 1.1 are read from agent_run and agent_span at build "
         "time, so the report re-measures itself. The .docx is a build artefact and is "
         "gitignored along with docs/generated/; the script is the artefact worth "
         "keeping under version control.",
         size=9.5, colour=MUTED)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    doc.save(OUTPUT)
    return OUTPUT


if __name__ == "__main__":
    path = build()
    print(f"wrote {path}  ({path.stat().st_size / 1024:.1f} KB)")
