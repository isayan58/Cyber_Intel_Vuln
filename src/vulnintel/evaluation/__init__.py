"""Evaluation suites.

Four layers evaluated separately, because a single end-to-end score tells you
something broke but not where:

    retrieval   Recall@k, MRR, and the adversarial policy cases
    risk        deterministic scoring and version-comparison properties
    tools       tool correctness, schemas, allowlist enforcement, audit trail
    end_to_end  full graph runs against known-answer scenarios

Results are persisted to ``eval_result`` so trends are queryable.
"""

from __future__ import annotations

import inspect
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from vulnintel.logging_setup import get_logger

log = get_logger(__name__)

SUITES = ("retrieval", "risk", "tools", "end_to_end")


def run_suite(
    suite: str,
    limit: int | None = None,
    persist: bool = True,
    provider: str | None = None,
) -> dict[str, Any]:
    if suite == "all":
        return _run_all(limit=limit, persist=persist, provider=provider)

    if suite == "retrieval":
        from vulnintel.evaluation import retrieval_eval as module
    elif suite == "risk":
        from vulnintel.evaluation import risk_eval as module
    elif suite == "tools":
        from vulnintel.evaluation import tool_eval as module
    elif suite == "end_to_end":
        from vulnintel.evaluation import end_to_end_eval as module
    else:
        raise ValueError(f"unknown suite: {suite}")

    kwargs: dict[str, Any] = {"limit": limit}
    if provider is not None and "provider" in inspect.signature(module.run).parameters:
        kwargs["provider"] = provider
    result = module.run(**kwargs)
    if persist:
        _persist(suite, result)
    return result


def _run_all(limit: int | None, persist: bool, provider: str | None = None) -> dict[str, Any]:
    cases: list[dict[str, Any]] = []
    summary: dict[str, Any] = {}
    all_passed = True

    for suite in SUITES:
        try:
            result = run_suite(suite, limit=limit, persist=persist, provider=provider)
        except Exception as exc:  # noqa: BLE001 - one suite failing must not hide the rest
            log.warning("suite '%s' failed to run: %s", suite, exc)
            summary[f"{suite}.error"] = str(exc)
            all_passed = False
            continue
        for row in result["cases"]:
            cases.append({**row, "suite": suite})
        for key, value in result["summary"].items():
            summary[f"{suite}.{key}"] = value
        all_passed = all_passed and result["passed"]

    return {
        "cases": cases,
        "columns": ["suite", "id", "kind", "expected", "actual", "passed"],
        "summary": summary,
        "passed": all_passed,
    }


def _persist(suite: str, result: dict[str, Any]) -> None:
    try:
        from vulnintel.data.db import get_db

        db = get_db()
        now = datetime.now(UTC).replace(tzinfo=None)
        db.insert_many(
            "eval_result",
            [
                {
                    "eval_id": str(uuid.uuid4()),
                    "suite": suite,
                    "case_id": str(row.get("id", "?")),
                    "metric": str(row.get("kind", "case")),
                    "value": 1.0 if row.get("passed") else 0.0,
                    "passed": bool(row.get("passed")),
                    "detail": json.dumps(row, default=str),
                    "run_at": now,
                }
                for row in result["cases"]
            ],
        )
    except Exception as exc:  # noqa: BLE001 - never let persistence fail a run
        log.warning("could not persist eval results: %s", exc)


__all__ = ["SUITES", "run_suite"]
