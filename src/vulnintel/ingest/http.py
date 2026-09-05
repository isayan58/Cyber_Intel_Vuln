"""HTTP client for public feeds.

Centralises the things every feed client would otherwise re-implement badly:
retry with exponential backoff, honouring ``Retry-After``, a descriptive
User-Agent, and a token-bucket rate limiter so NVD's published limits are
respected rather than discovered the hard way.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

import httpx

from vulnintel.config import get_settings
from vulnintel.logging_setup import get_logger

log = get_logger(__name__)

USER_AGENT = "vulnintel-ai/0.1 (portfolio research project)"

RETRYABLE_STATUS = {408, 425, 429, 500, 502, 503, 504}


@dataclass
class RateLimit:
    """Simple token bucket: ``requests`` per ``per_seconds`` window."""

    requests: int
    per_seconds: float

    def __post_init__(self) -> None:
        self._timestamps: list[float] = []

    def acquire(self) -> None:
        now = time.monotonic()
        window_start = now - self.per_seconds
        self._timestamps = [t for t in self._timestamps if t > window_start]
        if len(self._timestamps) >= self.requests:
            sleep_for = self._timestamps[0] + self.per_seconds - now
            if sleep_for > 0:
                log.debug("rate limit: sleeping %.2fs", sleep_for)
                time.sleep(sleep_for)
            self._timestamps = self._timestamps[1:]
        self._timestamps.append(time.monotonic())


class FeedClient:
    """A retrying HTTP client with an optional rate limit."""

    def __init__(
        self,
        *,
        rate_limit: RateLimit | None = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        max_retries: int | None = None,
    ) -> None:
        settings = get_settings()
        self.rate_limit = rate_limit
        self.max_retries = max_retries if max_retries is not None else settings.http_max_retries
        merged = {"User-Agent": USER_AGENT, "Accept-Encoding": "gzip"}
        merged.update(headers or {})
        self._client = httpx.Client(
            timeout=timeout or settings.http_timeout_seconds,
            headers=merged,
            follow_redirects=True,
        )

    def __enter__(self) -> FeedClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    def get(self, url: str, params: dict[str, str] | None = None) -> httpx.Response:
        last_error: Exception | None = None
        for attempt in range(self.max_retries + 1):
            if self.rate_limit:
                self.rate_limit.acquire()
            try:
                response = self._client.get(url, params=params)
            except httpx.HTTPError as exc:
                last_error = exc
                delay = self._backoff(attempt)
                log.warning("GET %s failed (%s); retrying in %.1fs", url, exc, delay)
                time.sleep(delay)
                continue

            if response.status_code in RETRYABLE_STATUS and attempt < self.max_retries:
                delay = self._retry_after(response) or self._backoff(attempt)
                log.warning("GET %s -> %d; retrying in %.1fs", url, response.status_code, delay)
                time.sleep(delay)
                continue

            response.raise_for_status()
            return response

        raise RuntimeError(
            f"GET {url} failed after {self.max_retries + 1} attempts"
        ) from last_error

    def get_bytes(self, url: str, params: dict[str, str] | None = None) -> bytes:
        return self.get(url, params=params).content

    def get_json(self, url: str, params: dict[str, str] | None = None):
        return self.get(url, params=params).json()

    @staticmethod
    def _backoff(attempt: int) -> float:
        return min(2.0**attempt, 30.0)

    @staticmethod
    def _retry_after(response: httpx.Response) -> float | None:
        raw = response.headers.get("retry-after")
        if not raw:
            return None
        try:
            return float(raw)
        except ValueError:
            return None


def nvd_client() -> FeedClient:
    """NVD allows ~5 requests/30s anonymously, ~50/30s with a free API key."""
    settings = get_settings()
    headers = {}
    if settings.nvd_api_key:
        headers["apiKey"] = settings.nvd_api_key
        limit = RateLimit(requests=45, per_seconds=30.0)
    else:
        limit = RateLimit(requests=4, per_seconds=30.0)
        log.warning(
            "No NVD_API_KEY set — falling back to the anonymous rate limit. "
            "A free key at https://nvd.nist.gov/developers/request-an-api-key "
            "makes the backfill roughly 10x faster."
        )
    return FeedClient(rate_limit=limit, headers=headers)


def github_client() -> FeedClient:
    settings = get_settings()
    headers = {"Accept": "application/vnd.github+json"}
    if settings.github_token:
        headers["Authorization"] = f"Bearer {settings.github_token}"
        limit = RateLimit(requests=4500, per_seconds=3600.0)
    else:
        limit = RateLimit(requests=55, per_seconds=3600.0)
    return FeedClient(rate_limit=limit, headers=headers)
