"""API response tests.

These assert on the shape of what leaves the process. A handler that computes
the right answer and then fails to serialise it is indistinguishable, from the
caller's side, from one that computed nothing — and on ``/api/ask`` the model
has already been called and billed by the time serialisation runs.
"""

from __future__ import annotations

import datetime
import json

import pytest
from fastapi.testclient import TestClient


class TestAskEndpoint:
    """``/api/ask`` builds its own JSONResponse, so it does not get FastAPI's
    encoder for free the way every other endpoint here does."""

    @pytest.fixture
    def state_with_dates(self) -> dict:
        """The shape the graph really returns.

        A scored finding carries ``kev_date_added`` and ``sla_due_date`` as
        ``datetime.date``. Reproduced explicitly rather than by scoring a
        fixture estate, because a test that depends on the fixture happening to
        produce a KEV-listed finding passes for the wrong reason when it does
        not.
        """
        return {
            "run_id": "11111111-2222-3333-4444-555555555555",
            "final_answer": "## Top risks\n\nOne finding.",
            "intent": "executive_brief",
            "response_mode": "executive",
            "required_agents": ["asset_exposure", "risk_remediation"],
            "replan_count": 0,
            "critique": {"passed": True, "confidence": 0.8},
            "citations": [],
            "scored_findings": [
                {
                    "finding_id": "f-1",
                    "cve_id": "CVE-2024-0001",
                    "score": 91.2,
                    "kev_date_added": datetime.date(2023, 9, 13),
                    "sla_due_date": datetime.date(2026, 9, 6),
                }
            ],
            "latency_ms": 1234,
            "prompt_versions": {"responder": "responder@v3"},
        }

    def test_ask_serialises_a_state_containing_dates(self, monkeypatch, state_with_dates):
        """Found by running a live investigation through the running server:
        the graph completed in 93 seconds and the endpoint then returned 500."""
        import api.main as api_main

        monkeypatch.setattr(api_main, "run_investigation", lambda *a, **k: state_with_dates)
        client = TestClient(api_main.app)

        response = client.post(
            "/api/ask", data={"question": "What are our top risks?", "user_role": "cto"}
        )

        assert response.status_code == 200, response.text
        payload = response.json()
        assert payload["answer"]
        json.dumps(payload)  # the property that actually broke

    def test_dates_arrive_as_strings(self, monkeypatch, state_with_dates):
        import api.main as api_main

        monkeypatch.setattr(api_main, "run_investigation", lambda *a, **k: state_with_dates)
        finding = (
            TestClient(api_main.app)
            .post("/api/ask", data={"question": "What are our top risks?"})
            .json()["findings"][0]
        )

        assert finding["kev_date_added"] == "2023-09-13"
        assert finding["sla_due_date"] == "2026-09-06"
