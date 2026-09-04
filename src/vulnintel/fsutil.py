"""Filesystem helpers.

macOS stores extended attributes in AppleDouble sidecar files — ``._name`` next
to ``name`` — on any filesystem that cannot hold them natively (exFAT, FAT32,
most external drives, many network shares). Those sidecars are binary, they
match every glob their partner matches, and the OS recreates them the moment
anything writes to the directory again.

That makes "delete them once" an unreliable fix, and it makes any code that
globs a data directory a latent bug on those volumes. Every directory scan in
this project therefore goes through here.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

APPLEDOUBLE_PREFIX = "._"


def is_hidden_sidecar(path: Path | str) -> bool:
    """True for AppleDouble sidecars and other OS metadata files."""
    name = path.name if isinstance(path, Path) else str(path)
    return name.startswith(APPLEDOUBLE_PREFIX) or name in {".DS_Store", "Thumbs.db"}


def clean_paths(paths: Iterable[Path]) -> list[Path]:
    """Drop OS metadata files from a directory listing."""
    return [p for p in paths if not is_hidden_sidecar(p)]


def iter_files(directory: Path, pattern: str = "*", recursive: bool = False) -> list[Path]:
    """Sorted real files under ``directory``, sidecars excluded."""
    if not directory.exists():
        return []
    matches = directory.rglob(pattern) if recursive else directory.glob(pattern)
    return sorted(p for p in matches if p.is_file() and not is_hidden_sidecar(p))


def iter_dirs(directory: Path) -> list[Path]:
    if not directory.exists():
        return []
    return sorted(p for p in directory.iterdir() if p.is_dir() and not is_hidden_sidecar(p))


def purge_sidecars(root: Path) -> int:
    """Delete every AppleDouble sidecar under ``root``. Returns the count.

    Convenience for ``make clean-osx``; the guards above are the real fix,
    because the files come straight back.
    """
    removed = 0
    for path in root.rglob("*"):
        if path.is_file() and is_hidden_sidecar(path):
            try:
                path.unlink()
                removed += 1
            except OSError:
                pass
    return removed
