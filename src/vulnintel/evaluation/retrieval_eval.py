"""Retrieval evaluation.

Reports Recall@k, MRR and metadata-filter accuracy, and — separately — the
adversarial cases: a superseded policy that must not rank first, a conflict
that must be surfaced, and an out-of-scope question that must return nothing
confident.

The adversarial block is the part that says something. Recall@5 on questions
written against your own corpus is easy; refusing to answer from a superseded
document is not.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from vulnintel.config import get_settings
from vulnintel.logging_setup import get_logger
from vulnintel.rag.retriever import COVERAGE_FLOOR, HybridRetriever

log = get_logger(__name__)

DATASET = "retrieval.yaml"
# The retriever decides what "confident" means (see COVERAGE_FLOOR); the suite
# asserts on that decision rather than on a second, independently tuned
# threshold. A fused relevance score cannot serve here — for an out-of-scope
# question it lands inside the same band as a genuine hit.


def load_dataset() -> dict[str, Any]:
    path = get_settings().evals_dir / "datasets" / DATASET
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def run(limit: int | None = None) -> dict[str, Any]:
    dataset = load_dataset()
    retriever = HybridRetriever()

    cases = dataset.get("cases", [])[: limit or None]
    rows: list[dict[str, Any]] = []
    reciprocal_ranks: list[float] = []

    for case in cases:
        result = retriever.retrieve(case["query"], top_k=10)
        doc_ids = [item.doc_id for item in result.evidence]
        expected = case["expect_doc"]

        rank = doc_ids.index(expected) + 1 if expected in doc_ids else 0
        reciprocal_ranks.append(1.0 / rank if rank else 0.0)

        # Did the expected wording actually come back, not just the document?
        top_text = " ".join(item.text for item in result.evidence[:5]).lower()
        phrases = case.get("expect_text", [])
        matched = [p for p in phrases if p.lower() in top_text]

        rows.append(
            {
                "id": case["id"],
                "rank": rank or "—",
                "recall@5": rank != 0 and rank <= 5,
                "recall@10": rank != 0,
                "phrases": f"{len(matched)}/{len(phrases)}" if phrases else "—",
                "passed": (rank != 0 and rank <= 5) and (not phrases or bool(matched)),
            }
        )

    adversarial = _adversarial(retriever, dataset.get("adversarial", []))
    rows.extend(adversarial)

    graded = [r for r in rows if "passed" in r]
    recall5 = [r for r in rows if "recall@5" in r]
    summary = {
        "cases": len(rows),
        "recall@5": _rate(r["recall@5"] for r in recall5),
        "recall@10": _rate(r["recall@10"] for r in recall5),
        "mrr": round(sum(reciprocal_ranks) / len(reciprocal_ranks), 4) if reciprocal_ranks else 0.0,
        "phrase_match_rate": _rate(
            r["phrases"] != "—" and not r["phrases"].startswith("0") for r in recall5
        ),
        "adversarial_passed": f"{sum(1 for r in adversarial if r['passed'])}/{len(adversarial)}",
        "pass_rate": _rate(r["passed"] for r in graded),
        "embedding_provider": get_settings().embedding_provider,
    }

    return {
        "cases": rows,
        "columns": ["id", "rank", "recall@5", "recall@10", "phrases", "passed", "note"],
        "summary": summary,
        "passed": all(r["passed"] for r in graded),
    }


def _adversarial(retriever: HybridRetriever, cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    for case in cases:
        result = retriever.retrieve(case["query"], top_k=10)
        passed = True
        note = ""

        if "must_not_rank_first" in case:
            top = result.evidence[0].doc_id if result.evidence else None
            passed = top != case["must_not_rank_first"]
            note = f"top={top}"

        elif case.get("expect_conflict"):
            passed = bool(result.conflicts)
            note = f"{len(result.conflicts)} conflict(s) reported"

        elif case.get("expect_no_confident_match"):
            passed = not result.is_confident
            note = f"coverage {result.confidence:.3f} vs floor {COVERAGE_FLOOR}"

        rows.append({"id": case["id"], "rank": "—", "phrases": "—", "passed": passed, "note": note})

    return rows


def _rate(values) -> float:
    values = list(values)
    if not values:
        return 0.0
    return round(sum(1 for v in values if v) / len(values), 4)
