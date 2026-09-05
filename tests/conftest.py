"""Shared fixtures.

Every test runs against a throwaway DuckDB file with the mock LLM provider, so
the suite needs no network, no API key and no prior ingestion.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

os.environ.setdefault("VULNINTEL_LLM_PROVIDER", "mock")
os.environ.setdefault("VULNINTEL_EMBEDDING_PROVIDER", "hash")


@pytest.fixture
def settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from vulnintel.config import get_settings, reload_settings

    monkeypatch.setenv("VULNINTEL_DUCKDB_PATH", str(tmp_path / "test.duckdb"))
    monkeypatch.setenv("VULNINTEL_BRONZE_ROOT", str(tmp_path / "bronze"))
    monkeypatch.setenv("VULNINTEL_LLM_PROVIDER", "mock")
    monkeypatch.setenv("VULNINTEL_EMBEDDING_PROVIDER", "hash")
    monkeypatch.setenv("VULNINTEL_SYNTHETIC_SEED", "424242")

    reload_settings()
    yield get_settings()
    reload_settings()


@pytest.fixture
def db(settings):
    from vulnintel.data.db import Database, reset_db
    from vulnintel.data.views import create_views

    database = Database(settings)
    database.init_schema()
    create_views(database)
    yield database
    database.close()
    reset_db()


@pytest.fixture
def seeded_db(db):
    """A small estate plus a handful of advisories, enough to match and score."""
    from datetime import UTC, datetime

    from vulnintel.generator import SyntheticGenerator

    SyntheticGenerator(db=db, asset_count=60, application_count=8).generate()

    now = datetime.now(UTC).replace(tzinfo=None)
    db.insert_many(
        "advisory",
        [
            {
                "advisory_id": "SYNTHETIC-TEST-0001",
                "source": "osv",
                "summary": "Synthetic test advisory for django",
                "details": "Fixture data. Not a real advisory.",
                "severity_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "severity_score": None,
                "published_at": now,
                "modified_at": now,
                "withdrawn_at": None,
                "raw": "{}",
                "source_run_id": None,
                "retrieved_at": now,
            }
        ],
    )
    db.insert_many(
        "advisory_alias",
        [{"advisory_id": "SYNTHETIC-TEST-0001", "alias": "CVE-2999-00001"}],
    )
    db.insert_many(
        "advisory_affected",
        [
            {
                "advisory_id": "SYNTHETIC-TEST-0001",
                "range_ordinal": 0,
                "ecosystem": "PyPI",
                "package_name": "django",
                "purl": "pkg:pypi/django",
                "range_type": "ECOSYSTEM",
                "introduced": "0",
                "fixed": "5.0.0",
                "last_affected": None,
                "explicit_versions": "",
            }
        ],
    )
    db.insert_many(
        "cve",
        [
            {
                "cve_id": "CVE-2999-00001",
                "published_at": now,
                "last_modified_at": now,
                "vuln_status": "Analyzed",
                "description": "Synthetic test CVE used by the test suite.",
                "source_identifier": "test",
                "configurations_raw": "[]",
                "source_run_id": None,
                "retrieved_at": now,
            }
        ],
    )
    db.insert_many(
        "cve_cvss",
        [
            {
                "cve_id": "CVE-2999-00001",
                "cvss_version": "3.1",
                "provider": "nvd@nist.gov",
                "metric_type": "Primary",
                "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "base_score": 9.8,
                "base_severity": "CRITICAL",
                "exploitability": 3.9,
                "impact": 5.9,
            }
        ],
    )
    db.insert_many(
        "epss_current",
        [
            {
                "cve_id": "CVE-2999-00001",
                "probability": 0.72,
                "percentile": 0.99,
                "score_date": now.date(),
                "source_run_id": None,
            }
        ],
    )
    db.insert_many(
        "kev",
        [
            {
                "cve_id": "CVE-2999-00001",
                "valid_from": now.date(),
                "valid_to": None,
                "date_added": now.date(),
                "due_date": None,
                "vendor_project": "Test",
                "product": "django",
                "vulnerability_name": "Synthetic",
                "short_description": "Fixture",
                "required_action": "Upgrade",
                "known_ransomware_use": False,
                "notes": None,
                "source_run_id": None,
            }
        ],
    )
    return db


@pytest.fixture
def knowledge_db(db, tmp_path):
    from vulnintel.rag.corpus import write_corpus
    from vulnintel.rag.ingest import ingest_knowledge_base
    from vulnintel.tools.knowledge import reset_retriever

    corpus = tmp_path / "kb"
    write_corpus(corpus)
    ingest_knowledge_base(root=corpus, db=db)
    reset_retriever()
    yield db
    reset_retriever()
