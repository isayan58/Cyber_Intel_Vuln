"""Central configuration.

Every tunable lives here so that ingestion, scoring, retrieval and the agent
graph can be reconfigured without touching code. Values come from the
environment (``.env`` is read automatically) with conservative defaults that
work on a laptop with no external infrastructure.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=REPO_ROOT / ".env",
        env_prefix="VULNINTEL_",
        extra="ignore",
    )

    # --- storage -------------------------------------------------------------
    db_backend: Literal["duckdb", "postgres"] = "duckdb"
    # DuckDB allows one writer or many readers. Set this for a process that
    # only needs to read (a second UI instance, a reporting job) so it can run
    # alongside an ingestion job.
    db_read_only: bool = False
    duckdb_path: Path = Path("data/warehouse/vulnintel.duckdb")
    postgres_dsn: str = "postgresql://vulnintel:vulnintel@localhost:5432/vulnintel"
    bronze_root: Path = Path("data/bronze")

    # --- llm -----------------------------------------------------------------
    llm_provider: Literal["anthropic", "mock"] = "anthropic"
    # Three tiers, chosen from measured per-node cost. Extraction and
    # presentation run on Haiku; structured synthesis over already-computed
    # numbers runs on Sonnet; only verification stays on Opus, and only when a
    # deterministic check has flagged something worth its judgement.
    llm_model: str = "claude-opus-5"
    llm_model_mid: str = "claude-sonnet-5"
    llm_model_fast: str = "claude-haiku-4-5-20251001"
    llm_tiering_enabled: bool = True
    llm_effort: Literal["low", "medium", "high", "xhigh", "max"] = "medium"
    llm_max_tokens: int = 16000
    llm_timeout_seconds: float = 120.0

    # --- embeddings ----------------------------------------------------------
    embedding_provider: Literal["hash", "sentence-transformers"] = "hash"
    embedding_dim: int = 384
    sentence_transformer_model: str = "sentence-transformers/all-MiniLM-L6-v2"

    # --- retrieval -----------------------------------------------------------
    retrieval_top_k: int = 8
    retrieval_candidates: int = 40
    rrf_k: int = 60
    chunk_target_tokens: int = 700
    chunk_overlap_tokens: int = 80

    # --- agent behaviour -----------------------------------------------------
    max_replans: int = 2
    agent_timeout_seconds: float = 180.0
    prompts_dir: Path = Path("prompts")

    # --- data generation -----------------------------------------------------
    synthetic_seed: int = 20260904
    synthetic_assets: int = 12000
    synthetic_applications: int = 180

    # --- feeds ---------------------------------------------------------------
    nvd_api_key: str = Field(default="", validation_alias="NVD_API_KEY")
    github_token: str = Field(default="", validation_alias="GITHUB_TOKEN")
    anthropic_api_key: str = Field(default="", validation_alias="ANTHROPIC_API_KEY")

    nvd_page_size: int = 2000
    http_timeout_seconds: float = 60.0
    http_max_retries: int = 4

    # --- api security --------------------------------------------------------
    # Unset by default so a local clone is a one-command demo. Setting it turns
    # on authentication for every endpoint except health and static assets.
    api_key: str = ""
    rate_limit_enabled: bool = True
    rate_limit_default: int = 120  # requests per minute, read endpoints
    rate_limit_expensive: int = 6  # requests per minute, endpoints that call a model

    # --- misc ----------------------------------------------------------------
    log_level: str = "INFO"

    # --- derived paths -------------------------------------------------------
    @property
    def repo_root(self) -> Path:
        return REPO_ROOT

    def resolve(self, p: Path) -> Path:
        """Resolve a possibly-relative configured path against the repo root."""
        return p if p.is_absolute() else (REPO_ROOT / p)

    @property
    def duckdb_file(self) -> Path:
        return self.resolve(self.duckdb_path)

    @property
    def bronze_dir(self) -> Path:
        return self.resolve(self.bronze_root)

    @property
    def prompts_path(self) -> Path:
        return self.resolve(self.prompts_dir)

    @property
    def knowledge_dir(self) -> Path:
        return REPO_ROOT / "knowledge_base"

    @property
    def evals_dir(self) -> Path:
        return REPO_ROOT / "evals"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def reload_settings() -> Settings:
    """Drop the cached settings — used by tests and the admin endpoint."""
    get_settings.cache_clear()
    return get_settings()
