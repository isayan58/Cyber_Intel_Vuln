"""Run and span persistence.

Traces go to the warehouse rather than only to a hosted tool, so the
evaluation suite can query them: "how often does the critic force a re-plan?",
"which node dominates latency?", "did this answer's tool calls actually
happen?" are all SQL here.

``VULNINTEL_LANGSMITH`` style hosted tracing can sit alongside this — but the
project must not depend on a SaaS account to show its own reliability.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

from vulnintel.data.db import Database, get_db
from vulnintel.logging_setup import get_logger

log = get_logger(__name__)


class RunTracer:
    def __init__(
        self,
        run_id: str,
        question: str,
        user_role: str,
        db: Database | None = None,
        persist: bool = True,
    ) -> None:
        self.run_id = run_id
        self.question = question
        self.user_role = user_role
        self.db = db or get_db()
        self.persist = persist

    def start(self) -> None:
        if not self.persist:
            return
        try:
            self.db.insert_many(
                "agent_run",
                [
                    {
                        "run_id": self.run_id,
                        "question": self.question,
                        "user_role": self.user_role,
                        "response_mode": None,
                        "started_at": _now(),
                        "completed_at": None,
                        "status": "running",
                        "replan_count": 0,
                        "total_input_tokens": 0,
                        "total_output_tokens": 0,
                        "latency_ms": None,
                        "model": None,
                        "final_answer": None,
                        "error": None,
                    }
                ],
            )
        except Exception as exc:  # noqa: BLE001 - tracing must never break a run
            log.warning("could not open trace for run %s: %s", self.run_id, exc)

    def finish(
        self,
        state: dict[str, Any],
        status: str,
        latency_ms: int,
        error: str | None = None,
    ) -> None:
        if not self.persist:
            return
        try:
            usage = state.get("usage") or {}
            input_tokens = sum(int(u.get("input_tokens", 0) or 0) for u in usage.values())
            output_tokens = sum(int(u.get("output_tokens", 0) or 0) for u in usage.values())

            from vulnintel.config import get_settings

            self.db.execute(
                "UPDATE agent_run SET status = ?, completed_at = ?, replan_count = ?, "
                "response_mode = ?, total_input_tokens = ?, total_output_tokens = ?, "
                "latency_ms = ?, model = ?, final_answer = ?, error = ? WHERE run_id = ?",
                [
                    status,
                    _now(),
                    int(state.get("replan_count", 0)),
                    state.get("response_mode"),
                    input_tokens,
                    output_tokens,
                    latency_ms,
                    get_settings().llm_model,
                    json.dumps(
                        {
                            "answer": state.get("final_answer", ""),
                            "citations": state.get("citations", []),
                            "critique": state.get("critique", {}),
                            "prompt_versions": state.get("prompt_versions", {}),
                        },
                        default=str,
                    ),
                    error,
                    self.run_id,
                ],
            )
            self._write_spans(state.get("spans") or [])
        except Exception as exc:  # noqa: BLE001
            log.warning("could not close trace for run %s: %s", self.run_id, exc)

    def _write_spans(self, spans: list[dict[str, Any]]) -> None:
        rows = []
        for seq, span in enumerate(spans):
            rows.append(
                {
                    "span_id": span.get("span_id") or str(uuid.uuid4()),
                    "run_id": self.run_id,
                    "node": span.get("node", "unknown"),
                    "seq": seq,
                    "started_at": span.get("started_at") or _now(),
                    "completed_at": _now(),
                    "latency_ms": span.get("latency_ms"),
                    "status": span.get("status", "ok"),
                    "input_tokens": None,
                    "output_tokens": None,
                    "detail": json.dumps(
                        {
                            "tool_calls": span.get("tool_calls", []),
                            "prompt_version": span.get("prompt_version"),
                        },
                        default=str,
                    ),
                    "error": span.get("error"),
                }
            )
        if rows:
            self.db.insert_many("agent_span", rows)


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


# -- read-side helpers used by the API and the eval suite ---------------------


def get_run(run_id: str, db: Database | None = None) -> dict[str, Any] | None:
    conn = db or get_db()
    run = conn.query_one("SELECT * FROM agent_run WHERE run_id = ?", [run_id])
    if run is None:
        return None
    run["spans"] = conn.query(
        "SELECT * FROM agent_span WHERE run_id = ? ORDER BY seq", [run_id]
    )
    run["tool_calls"] = conn.query(
        "SELECT * FROM tool_call WHERE run_id = ? ORDER BY called_at", [run_id]
    )
    if run.get("final_answer"):
        try:
            run["final_answer"] = json.loads(run["final_answer"])
        except (json.JSONDecodeError, TypeError):
            pass
    return run


def recent_runs(limit: int = 25, db: Database | None = None) -> list[dict[str, Any]]:
    conn = db or get_db()
    return conn.query(
        "SELECT run_id, question, user_role, response_mode, status, replan_count, "
        "latency_ms, total_input_tokens, total_output_tokens, started_at "
        "FROM agent_run ORDER BY started_at DESC LIMIT ?",
        [int(limit)],
    )


def node_latency_summary(db: Database | None = None) -> list[dict[str, Any]]:
    conn = db or get_db()
    return conn.query(
        "SELECT node, count(*) AS executions, "
        "       round(avg(latency_ms), 1) AS avg_latency_ms, "
        "       max(latency_ms) AS max_latency_ms, "
        "       sum(CASE WHEN status = 'error' THEN 1 ELSE 0 END) AS errors "
        "FROM agent_span GROUP BY node ORDER BY avg_latency_ms DESC"
    )


def tool_usage_summary(db: Database | None = None) -> list[dict[str, Any]]:
    conn = db or get_db()
    return conn.query(
        "SELECT tool_name, server, count(*) AS calls, "
        "       round(avg(latency_ms), 1) AS avg_latency_ms, "
        "       sum(CASE WHEN status = 'error' THEN 1 ELSE 0 END) AS errors, "
        "       round(avg(row_count), 1) AS avg_rows "
        "FROM tool_call GROUP BY tool_name, server ORDER BY calls DESC"
    )


def replan_rate(db: Database | None = None) -> dict[str, Any]:
    conn = db or get_db()
    row = conn.query_one(
        "SELECT count(*) AS runs, "
        "       sum(CASE WHEN replan_count > 0 THEN 1 ELSE 0 END) AS runs_with_replan, "
        "       round(avg(replan_count), 3) AS avg_replans, "
        "       round(avg(latency_ms), 0) AS avg_latency_ms "
        "FROM agent_run WHERE status = 'succeeded'"
    )
    return row or {}
