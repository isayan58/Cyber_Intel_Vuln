"""Document parsing and heading-aware chunking.

Design doc §8.2: *use document-aware splitting rather than fixed 500-character
chunks only*. Policy prose is highly structured — the unit that answers "what
does policy require for an exploited critical vulnerability?" is a numbered
section, not an arbitrary character window. Chunks therefore follow the
heading tree, and only oversized sections are split further, on paragraph
boundaries, with overlap.

Markdown tables are never split mid-table: an SLA table cut in half retrieves
as confidently as a whole one and answers wrongly.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from vulnintel.config import get_settings

FRONT_MATTER = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)
HEADING = re.compile(r"^(#{1,6})\s+(.*)$")


@dataclass
class ParsedDocument:
    path: Path
    metadata: dict[str, Any]
    body: str
    sha256: str


@dataclass
class Chunk:
    chunk_id: str
    doc_id: str
    ordinal: int
    section_path: str
    heading: str
    text: str
    token_count: int
    metadata: dict[str, Any] = field(default_factory=dict)


def estimate_tokens(text: str) -> int:
    """Cheap, dependency-free estimate: ~4 characters per token."""
    return max(1, len(text) // 4)


def parse_document(path: Path) -> ParsedDocument:
    raw = path.read_text(encoding="utf-8")
    metadata: dict[str, Any] = {}

    match = FRONT_MATTER.match(raw)
    body = raw
    if match:
        for line in match.group(1).splitlines():
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
            metadata[key.strip()] = value.strip()
        body = raw[match.end() :]

    return ParsedDocument(
        path=path,
        metadata=metadata,
        body=body.strip(),
        sha256=hashlib.sha256(raw.encode("utf-8")).hexdigest(),
    )


def _sections(body: str) -> list[tuple[str, str, str]]:
    """Split into (section_path, heading, text) following the heading tree."""
    lines = body.splitlines()
    stack: list[str] = []
    sections: list[tuple[str, str, str]] = []
    current_heading = ""
    current_path = ""
    buffer: list[str] = []

    def flush() -> None:
        text = "\n".join(buffer).strip()
        if text:
            sections.append((current_path or "root", current_heading or "Introduction", text))

    for line in lines:
        match = HEADING.match(line)
        if not match:
            buffer.append(line)
            continue

        flush()
        buffer = []
        level = len(match.group(1))
        title = match.group(2).strip()
        stack = stack[: level - 1]
        while len(stack) < level - 1:
            stack.append("")
        stack.append(title)
        current_heading = title
        current_path = " > ".join(part for part in stack if part)

    flush()
    return sections


def _split_oversized(text: str, target: int, overlap: int) -> list[str]:
    """Split a long section on paragraph boundaries, keeping tables intact."""
    paragraphs = re.split(r"\n\s*\n", text)
    parts: list[str] = []
    buffer: list[str] = []
    size = 0

    for paragraph in paragraphs:
        tokens = estimate_tokens(paragraph)
        is_table = paragraph.lstrip().startswith("|")

        # A table that alone exceeds the target still stays whole.
        if size and size + tokens > target and not (is_table and not buffer):
            parts.append("\n\n".join(buffer).strip())
            if overlap and buffer:
                tail = buffer[-1]
                buffer = [tail] if estimate_tokens(tail) <= overlap else []
                size = estimate_tokens(buffer[0]) if buffer else 0
            else:
                buffer, size = [], 0

        buffer.append(paragraph)
        size += tokens

    if buffer:
        parts.append("\n\n".join(buffer).strip())
    return [p for p in parts if p]


def chunk_document(
    document: ParsedDocument,
    doc_id: str,
    target_tokens: int | None = None,
    overlap_tokens: int | None = None,
) -> list[Chunk]:
    settings = get_settings()
    target = target_tokens or settings.chunk_target_tokens
    overlap = overlap_tokens or settings.chunk_overlap_tokens

    title = document.metadata.get("title", document.path.stem)
    chunks: list[Chunk] = []
    ordinal = 0

    for section_path, heading, text in _sections(document.body):
        pieces = (
            [text]
            if estimate_tokens(text) <= target
            else _split_oversized(text, target, overlap)
        )
        for piece in pieces:
            # Prefixing the heading path keeps a chunk self-describing, which
            # measurably improves both lexical and vector retrieval.
            body = f"{title} — {section_path}\n\n{piece}"
            chunk_id = f"{doc_id}::{ordinal:04d}"
            chunks.append(
                Chunk(
                    chunk_id=chunk_id,
                    doc_id=doc_id,
                    ordinal=ordinal,
                    section_path=section_path,
                    heading=heading,
                    text=body,
                    token_count=estimate_tokens(body),
                    metadata=document.metadata,
                )
            )
            ordinal += 1

    return chunks


def document_id(path: Path) -> str:
    return path.stem.lower().replace(" ", "-")
