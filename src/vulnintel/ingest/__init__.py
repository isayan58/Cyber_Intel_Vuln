"""Feed ingestion: network -> bronze -> warehouse."""

from vulnintel.ingest.base import IngestResult, Pipeline
from vulnintel.ingest.bronze import BronzeStore

__all__ = ["BronzeStore", "IngestResult", "Pipeline"]
