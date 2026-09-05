"""API authentication and rate limiting.

Two controls, both off by default so a local clone stays a one-command demo,
and both switched on by setting a single environment variable.

  * **Authentication** — an API key, compared in constant time, accepted from
    ``X-API-Key`` or ``Authorization: Bearer``. Enabled by setting
    ``VULNINTEL_API_KEY``. When it is unset the app logs a warning at startup
    rather than pretending to be secure.

  * **Rate limiting** — a per-client token bucket, with a much tighter budget on
    the investigation endpoints because those spend money. An unbounded
    ``/api/ask`` is a bill, not just a load problem.

The limiter keeps counters in memory, which is correct for one process and
wrong for several. That is stated here rather than discovered later: a
multi-process deployment needs Redis, and the interface is small enough to swap.
"""

from __future__ import annotations

import hmac
import time
from collections import defaultdict, deque
from dataclasses import dataclass

from fastapi import Request, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from vulnintel.config import get_settings
from vulnintel.logging_setup import get_logger

log = get_logger(__name__)

# Paths that must stay reachable without a key: liveness checks and the assets
# the browser needs to render the login-less pages at all.
PUBLIC_PATHS = ("/api/health", "/static/", "/favicon.ico")

# Endpoints that cost money per call, limited far more tightly than reads.
EXPENSIVE_PATHS = ("/api/ask", "/fragments/run-cost")


@dataclass
class Budget:
    """Requests allowed per rolling window."""

    requests: int
    per_seconds: float


DEFAULT_BUDGET = Budget(requests=120, per_seconds=60.0)
EXPENSIVE_BUDGET = Budget(requests=6, per_seconds=60.0)


class RateLimiter:
    """In-memory sliding-window counter, keyed by client."""

    def __init__(self) -> None:
        self._hits: dict[tuple[str, str], deque[float]] = defaultdict(deque)

    def check(self, client: str, bucket: str, budget: Budget) -> tuple[bool, int]:
        """Return ``(allowed, retry_after_seconds)``."""
        now = time.monotonic()
        window = self._hits[(client, bucket)]
        cutoff = now - budget.per_seconds
        while window and window[0] <= cutoff:
            window.popleft()

        if len(window) >= budget.requests:
            return False, max(1, int(window[0] + budget.per_seconds - now) + 1)

        window.append(now)
        return True, 0

    def reset(self) -> None:
        self._hits.clear()


limiter = RateLimiter()


def _client_id(request: Request) -> str:
    """Identify the caller.

    Prefers the API key so a shared NAT does not put unrelated users in one
    bucket, and falls back to the peer address. ``X-Forwarded-For`` is
    deliberately ignored: it is trivially spoofed, and trusting it would let a
    caller mint a fresh bucket per request.
    """
    key = request.headers.get("x-api-key") or ""
    if not key:
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            key = auth[7:]
    if key:
        return f"key:{key[:12]}"
    return f"ip:{request.client.host if request.client else 'unknown'}"


def _presented_key(request: Request) -> str | None:
    key = request.headers.get("x-api-key")
    if key:
        return key
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:]
    return None


class SecurityMiddleware(BaseHTTPMiddleware):
    """Applies authentication then rate limiting to every request."""

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        if path.startswith(PUBLIC_PATHS):
            return await call_next(request)

        settings = get_settings()
        configured = settings.api_key

        if configured:
            presented = _presented_key(request)
            # compare_digest to keep the comparison time independent of how
            # much of the key the caller guessed correctly.
            if not presented or not hmac.compare_digest(presented, configured):
                # Returned, not raised. Starlette's exception handler sits
                # inside the middleware stack, so an HTTPException raised here
                # escapes it and surfaces as a 500 rather than a 401.
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={"detail": "A valid API key is required. Send it as X-API-Key."},
                    headers={"WWW-Authenticate": "Bearer"},
                )

        if settings.rate_limit_enabled:
            expensive = path.startswith(EXPENSIVE_PATHS)
            budget = Budget(
                settings.rate_limit_expensive if expensive else settings.rate_limit_default,
                60.0,
            )

            allowed, retry_after = limiter.check(
                _client_id(request), "expensive" if expensive else "default", budget
            )
            if not allowed:
                log.warning("rate limit hit on %s by %s", path, _client_id(request))
                return JSONResponse(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    content={
                        "detail": (
                            f"Rate limit exceeded ({budget.requests} requests per minute "
                            f"for this endpoint). Retry in {retry_after}s."
                        )
                    },
                    headers={"Retry-After": str(retry_after)},
                )

        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        return response


def warn_if_unprotected() -> None:
    """Say plainly, at startup, when the API is open."""
    settings = get_settings()
    if not settings.api_key:
        log.warning(
            "VULNINTEL_API_KEY is not set — every endpoint is reachable without "
            "authentication. Fine for a local demo; set it before exposing this "
            "on any network."
        )
    if not settings.rate_limit_enabled:
        log.warning("Rate limiting is disabled; /api/ask spends money per call.")
