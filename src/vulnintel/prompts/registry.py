"""Prompt registry — every prompt lives in ``prompts/*.yaml``, never in code.

Prompts are loaded at *call* time, not import time, and the loader compares
file mtimes on each access. Editing a YAML file and re-running a query picks
up the change with no restart, which is what makes prompt iteration a
tight loop instead of a deploy cycle.

Each file carries a ``version`` that is recorded on the agent span, so a trace
says which prompt version produced an answer. Without that, "the output got
worse yesterday" is unanswerable.

File shape::

    name: supervisor
    version: 3
    description: Plans the investigation and routes to specialist agents.
    effort: medium
    max_tokens: 4000
    system: |
      ...
    user_template: |
      Question: {question}
    output_schema:
      type: object
      ...
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from pathlib import Path
from string import Template
from typing import Any

import yaml

from vulnintel.config import get_settings
from vulnintel.fsutil import iter_files
from vulnintel.logging_setup import get_logger

log = get_logger(__name__)


class PromptError(RuntimeError):
    pass


@dataclass
class Prompt:
    name: str
    version: int
    system: str
    user_template: str = "$question"
    description: str = ""
    effort: str | None = None
    max_tokens: int | None = None
    output_schema: dict[str, Any] | None = None
    model_tier: str = "deep"
    path: Path | None = None
    mtime: float = 0.0
    extras: dict[str, Any] = field(default_factory=dict)

    def render(self, **variables: Any) -> str:
        """Render the user template.

        ``string.Template`` is used rather than ``str.format`` because prompt
        bodies contain JSON braces constantly, and escaping every one of them
        is exactly the kind of papercut that makes people give up on
        externalised prompts.
        """
        try:
            return Template(self.user_template).substitute(**variables)
        except KeyError as exc:
            raise PromptError(
                f"prompt '{self.name}' needs variable {exc} which was not supplied"
            ) from exc

    @property
    def label(self) -> str:
        return f"{self.name}@v{self.version}"


class PromptRegistry:
    """Loads and hot-reloads prompt files."""

    def __init__(self, directory: Path | None = None) -> None:
        self.directory = directory or get_settings().prompts_path
        self._cache: dict[str, Prompt] = {}
        self._lock = threading.RLock()

    def path_for(self, name: str) -> Path:
        return self.directory / f"{name}.yaml"

    def get(self, name: str) -> Prompt:
        path = self.path_for(name)
        if not path.exists():
            raise PromptError(
                f"prompt '{name}' not found at {path}. "
                f"Available: {', '.join(self.available()) or 'none'}"
            )

        mtime = path.stat().st_mtime
        with self._lock:
            cached = self._cache.get(name)
            if cached is not None and cached.mtime == mtime:
                return cached

            prompt = self._load(path, name, mtime)
            if cached is not None:
                log.info("reloaded prompt %s (was v%d)", prompt.label, cached.version)
            self._cache[name] = prompt
            return prompt

    def _load(self, path: Path, name: str, mtime: float) -> Prompt:
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise PromptError(f"prompt '{name}' is not valid YAML: {exc}") from exc

        if "system" not in raw:
            raise PromptError(f"prompt '{name}' has no 'system' block")

        known = {
            "name", "version", "system", "user_template", "description",
            "effort", "max_tokens", "output_schema", "model_tier",
        }
        return Prompt(
            name=raw.get("name", name),
            version=int(raw.get("version", 1)),
            system=str(raw["system"]).strip(),
            user_template=str(raw.get("user_template", "$question")),
            description=str(raw.get("description", "")),
            effort=raw.get("effort"),
            max_tokens=raw.get("max_tokens"),
            output_schema=raw.get("output_schema"),
            model_tier=str(raw.get("model_tier", "deep")),
            path=path,
            mtime=mtime,
            extras={k: v for k, v in raw.items() if k not in known},
        )

    def available(self) -> list[str]:
        if not self.directory.exists():
            return []
        return [p.stem for p in iter_files(self.directory, "*.yaml")]

    def reload_all(self) -> int:
        """Drop the cache — used by the UI's 'reload prompts' action."""
        with self._lock:
            count = len(self._cache)
            self._cache.clear()
        log.info("prompt cache cleared (%d entries)", count)
        return count

    def describe(self) -> list[dict[str, Any]]:
        rows = []
        for name in self.available():
            prompt = self.get(name)
            rows.append(
                {
                    "name": prompt.name,
                    "version": prompt.version,
                    "description": prompt.description,
                    "effort": prompt.effort,
                    "has_schema": prompt.output_schema is not None,
                    "model_tier": prompt.model_tier,
                    "path": str(prompt.path),
                    "system_tokens": len(prompt.system) // 4,
                }
            )
        return rows


_REGISTRY: PromptRegistry | None = None
_LOCK = threading.Lock()


def get_registry() -> PromptRegistry:
    global _REGISTRY
    if _REGISTRY is None:
        with _LOCK:
            if _REGISTRY is None:
                _REGISTRY = PromptRegistry()
    return _REGISTRY


def get_prompt(name: str) -> Prompt:
    return get_registry().get(name)
