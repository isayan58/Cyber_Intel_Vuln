"""API authentication and rate limiting.

Both controls are off or permissive by default so a local clone stays a
one-command demo. These tests pin the behaviour in both states, because
"secure when configured" is only a claim if the unconfigured case is also
known and deliberate.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.security import Budget, RateLimiter, SecurityMiddleware, limiter


@pytest.fixture
def app_factory(monkeypatch):
    def build(**env):
        for key, value in env.items():
            monkeypatch.setenv(key, str(value))
        from vulnintel.config import reload_settings

        reload_settings()
        limiter.reset()

        app = FastAPI()
        app.add_middleware(SecurityMiddleware)

        @app.get("/api/health")
        def health():
            return {"status": "ok"}

        @app.get("/api/findings")
        def findings():
            return {"findings": []}

        @app.post("/api/ask")
        def ask():
            return {"answer": "..."}

        return TestClient(app)

    yield build
    from vulnintel.config import reload_settings

    reload_settings()
    limiter.reset()


class TestAuthentication:
    def test_open_by_default(self, app_factory):
        client = app_factory(VULNINTEL_API_KEY="", VULNINTEL_RATE_LIMIT_ENABLED="false")
        assert client.get("/api/findings").status_code == 200

    def test_key_required_once_configured(self, app_factory):
        client = app_factory(VULNINTEL_API_KEY="s3cret", VULNINTEL_RATE_LIMIT_ENABLED="false")
        assert client.get("/api/findings").status_code == 401

    def test_accepts_x_api_key_header(self, app_factory):
        client = app_factory(VULNINTEL_API_KEY="s3cret", VULNINTEL_RATE_LIMIT_ENABLED="false")
        r = client.get("/api/findings", headers={"X-API-Key": "s3cret"})
        assert r.status_code == 200

    def test_accepts_bearer_token(self, app_factory):
        client = app_factory(VULNINTEL_API_KEY="s3cret", VULNINTEL_RATE_LIMIT_ENABLED="false")
        r = client.get("/api/findings", headers={"Authorization": "Bearer s3cret"})
        assert r.status_code == 200

    def test_rejects_a_wrong_key(self, app_factory):
        client = app_factory(VULNINTEL_API_KEY="s3cret", VULNINTEL_RATE_LIMIT_ENABLED="false")
        assert client.get("/api/findings", headers={"X-API-Key": "guess"}).status_code == 401

    def test_health_stays_reachable_for_probes(self, app_factory):
        """A liveness check that needs a secret is not a liveness check."""
        client = app_factory(VULNINTEL_API_KEY="s3cret", VULNINTEL_RATE_LIMIT_ENABLED="false")
        assert client.get("/api/health").status_code == 200

    def test_security_headers_are_set(self, app_factory):
        client = app_factory(VULNINTEL_API_KEY="", VULNINTEL_RATE_LIMIT_ENABLED="false")
        headers = client.get("/api/findings").headers
        assert headers["X-Content-Type-Options"] == "nosniff"
        assert headers["X-Frame-Options"] == "DENY"


class TestRateLimiting:
    def test_reads_are_limited(self, app_factory):
        client = app_factory(
            VULNINTEL_API_KEY="",
            VULNINTEL_RATE_LIMIT_ENABLED="true",
            VULNINTEL_RATE_LIMIT_DEFAULT="3",
        )
        codes = [client.get("/api/findings").status_code for _ in range(5)]
        assert codes[:3] == [200, 200, 200]
        assert codes[3] == 429

    def test_model_endpoints_get_a_tighter_budget(self, app_factory):
        """/api/ask spends money per call, so it must not share the read budget."""
        client = app_factory(
            VULNINTEL_API_KEY="",
            VULNINTEL_RATE_LIMIT_ENABLED="true",
            VULNINTEL_RATE_LIMIT_DEFAULT="100",
            VULNINTEL_RATE_LIMIT_EXPENSIVE="2",
        )
        assert client.post("/api/ask").status_code == 200
        assert client.post("/api/ask").status_code == 200
        assert client.post("/api/ask").status_code == 429
        # the read budget is untouched by the expensive bucket
        assert client.get("/api/findings").status_code == 200

    def test_429_tells_the_caller_when_to_retry(self, app_factory):
        client = app_factory(
            VULNINTEL_API_KEY="",
            VULNINTEL_RATE_LIMIT_ENABLED="true",
            VULNINTEL_RATE_LIMIT_DEFAULT="1",
        )
        client.get("/api/findings")
        r = client.get("/api/findings")
        assert r.status_code == 429
        assert int(r.headers["Retry-After"]) >= 1


class TestLimiterUnit:
    def test_window_rolls_forward(self):
        rl = RateLimiter()
        budget = Budget(requests=2, per_seconds=60.0)
        assert rl.check("c", "b", budget)[0]
        assert rl.check("c", "b", budget)[0]
        assert not rl.check("c", "b", budget)[0]

    def test_clients_have_separate_budgets(self):
        rl = RateLimiter()
        budget = Budget(requests=1, per_seconds=60.0)
        assert rl.check("client-a", "b", budget)[0]
        assert rl.check("client-b", "b", budget)[0]
        assert not rl.check("client-a", "b", budget)[0]
