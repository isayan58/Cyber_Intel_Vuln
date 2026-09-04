"""Deterministic version comparison.

Design doc §7.2: *the LLM does not decide whether an exact software version is
inside a vulnerable version interval; a version-comparison function does.*
This module is that function.

Two range models are supported natively rather than forced into one shape:

    CPE ranges   NVD's versionStartIncluding / versionEndExcluding pairs
    OSV ranges   introduced / fixed / last_affected event triples

Every comparison returns a verdict with an explicit reason, and ``UNKNOWN`` is
a first-class outcome. Guessing "affected" when the version cannot be parsed is
how a vulnerability platform earns a reputation for crying wolf.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from functools import total_ordering

# Version strings that carry no information.
_WILDCARDS = {"", "*", "-", "any", "unknown", "none", "n/a"}

# A comparable version has at least one numeric component. Moving tags
# (latest, stable, main, edge, nightly) deliberately fail this test.
_HAS_DIGIT = re.compile(r"\d")


class Verdict(str, Enum):
    AFFECTED = "affected"
    NOT_AFFECTED = "not_affected"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class RangeResult:
    verdict: Verdict
    reason: str
    fixed_version: str | None = None

    @property
    def affected(self) -> bool:
        return self.verdict is Verdict.AFFECTED


@total_ordering
class GenericVersion:
    """A permissive, ordered version.

    Splits into numeric and alphabetic runs and compares component-wise. Numeric
    runs compare numerically, alphabetic runs lexically, and a numeric run sorts
    above an alphabetic one at the same position so ``1.0`` > ``1.0rc1``.
    """

    _TOKEN = re.compile(r"(\d+|[A-Za-z]+)")
    _PRERELEASE = {"alpha": -5, "a": -5, "beta": -4, "b": -4, "rc": -3, "pre": -3, "dev": -6}

    __slots__ = ("raw", "parts")

    def __init__(self, raw: str) -> None:
        self.raw = raw
        self.parts = self._tokenize(raw)

    @classmethod
    def _tokenize(cls, raw: str) -> tuple[tuple[int, int | str], ...]:
        tokens: list[tuple[int, int | str]] = []
        for token in cls._TOKEN.findall(raw.strip().lower()):
            if token.isdigit():
                tokens.append((1, int(token)))
            elif token in cls._PRERELEASE:
                tokens.append((0, cls._PRERELEASE[token]))
            else:
                tokens.append((0, token))
        return tuple(tokens)

    def _key(self, length: int) -> list[tuple[int, int | str]]:
        padded = list(self.parts)
        while len(padded) < length:
            padded.append((1, 0))
        return padded

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, GenericVersion):
            return NotImplemented
        size = max(len(self.parts), len(other.parts))
        return self._key(size) == other._key(size)

    def __lt__(self, other: GenericVersion) -> bool:
        size = max(len(self.parts), len(other.parts))
        for mine, theirs in zip(self._key(size), other._key(size), strict=True):
            if mine == theirs:
                continue
            # Numeric beats alphabetic at the same position (1.0 > 1.0rc1).
            if mine[0] != theirs[0]:
                return mine[0] < theirs[0]
            if isinstance(mine[1], int) and isinstance(theirs[1], int):
                return mine[1] < theirs[1]
            return str(mine[1]) < str(theirs[1])
        return False

    def __hash__(self) -> int:
        return hash(self.parts)

    def __repr__(self) -> str:
        return f"GenericVersion({self.raw!r})"


def _pep440(raw: str):
    try:
        from packaging.version import InvalidVersion, Version

        try:
            return Version(raw)
        except InvalidVersion:
            return None
    except ImportError:  # pragma: no cover - packaging is a hard dependency
        return None


def _semver(raw: str) -> tuple | None:
    """Parse a SemVer string into a comparable tuple, prerelease included."""
    match = re.match(
        r"^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$", raw.strip()
    )
    if not match:
        return None
    major, minor, patch, prerelease = match.groups()
    if prerelease is None:
        # No prerelease sorts above any prerelease.
        return (int(major), int(minor), int(patch), (1,))
    identifiers: list[tuple[int, object]] = []
    for part in prerelease.split("."):
        if part.isdigit():
            identifiers.append((0, int(part)))
        else:
            identifiers.append((1, part))
    return (int(major), int(minor), int(patch), (0, tuple(identifiers)))


def normalize_ecosystem(ecosystem: str | None) -> str:
    value = (ecosystem or "").strip().lower()
    if value in {"pypi", "pip", "python"}:
        return "pypi"
    if value in {"npm", "node", "javascript"}:
        return "npm"
    if value in {"maven", "java"}:
        return "maven"
    if value in {"go", "golang"}:
        return "go"
    if value in {"debian", "ubuntu", "alpine", "rocky", "rhel", "os"}:
        return "os"
    return "generic"


def compare(left: str, right: str, ecosystem: str | None = None) -> int:
    """Return -1, 0 or 1. Falls back to generic comparison when parsing fails."""
    eco = normalize_ecosystem(ecosystem)

    if eco == "pypi":
        a, b = _pep440(left), _pep440(right)
        if a is not None and b is not None:
            return (a > b) - (a < b)
    elif eco in {"npm", "go"}:
        a, b = _semver(left), _semver(right)
        if a is not None and b is not None:
            return (a > b) - (a < b)

    ga, gb = GenericVersion(left), GenericVersion(right)
    if ga == gb:
        return 0
    return -1 if ga < gb else 1


def is_parseable(version: str | None) -> bool:
    """Whether a string carries enough information to be ordered.

    A version MUST contain a digit. Without that rule, moving tags like
    ``latest``, ``stable``, ``main`` and ``edge`` — which are everywhere in
    real container inventory — tokenize as pure alphabetic, sort below every
    numeric version, and are therefore declared "below the fixed version" for
    every advisory affecting that package. That is a silent false-positive
    generator, and false "affected" verdicts are the failure mode this whole
    module exists to prevent.
    """
    if version is None:
        return False
    cleaned = version.strip().lower()
    if cleaned in _WILDCARDS:
        return False
    return bool(_HAS_DIGIT.search(cleaned))


def in_cpe_range(
    version: str,
    *,
    version_start_including: str | None = None,
    version_start_excluding: str | None = None,
    version_end_including: str | None = None,
    version_end_excluding: str | None = None,
    cpe_version: str | None = None,
    ecosystem: str | None = None,
) -> RangeResult:
    """Evaluate an NVD CPE match against a concrete installed version."""
    if not is_parseable(version):
        return RangeResult(Verdict.UNKNOWN, f"installed version {version!r} is not comparable")

    # An exact pinned version in the CPE and no range bounds: equality decides.
    bounds = (
        version_start_including,
        version_start_excluding,
        version_end_including,
        version_end_excluding,
    )
    if not any(is_parseable(b) for b in bounds):
        if cpe_version and cpe_version not in {"*", "-"}:
            if not is_parseable(cpe_version):
                return RangeResult(Verdict.UNKNOWN, f"CPE version {cpe_version!r} not comparable")
            equal = compare(version, cpe_version, ecosystem) == 0
            return RangeResult(
                Verdict.AFFECTED if equal else Verdict.NOT_AFFECTED,
                f"exact CPE version match {cpe_version}" if equal
                else f"installed {version} != pinned {cpe_version}",
            )
        return RangeResult(
            Verdict.UNKNOWN, "CPE match has a wildcard version and no range bounds"
        )

    reasons: list[str] = []

    if is_parseable(version_start_including):
        if compare(version, version_start_including, ecosystem) < 0:
            return RangeResult(
                Verdict.NOT_AFFECTED, f"{version} < start-including {version_start_including}"
            )
        reasons.append(f">= {version_start_including}")

    if is_parseable(version_start_excluding):
        if compare(version, version_start_excluding, ecosystem) <= 0:
            return RangeResult(
                Verdict.NOT_AFFECTED, f"{version} <= start-excluding {version_start_excluding}"
            )
        reasons.append(f"> {version_start_excluding}")

    fixed: str | None = None

    if is_parseable(version_end_including):
        if compare(version, version_end_including, ecosystem) > 0:
            return RangeResult(
                Verdict.NOT_AFFECTED, f"{version} > end-including {version_end_including}"
            )
        reasons.append(f"<= {version_end_including}")

    if is_parseable(version_end_excluding):
        if compare(version, version_end_excluding, ecosystem) >= 0:
            return RangeResult(
                Verdict.NOT_AFFECTED, f"{version} >= end-excluding {version_end_excluding}"
            )
        reasons.append(f"< {version_end_excluding}")
        fixed = version_end_excluding

    return RangeResult(Verdict.AFFECTED, f"{version} satisfies {' and '.join(reasons)}", fixed)


def in_osv_range(
    version: str,
    *,
    introduced: str | None = None,
    fixed: str | None = None,
    last_affected: str | None = None,
    explicit_versions: str | None = None,
    ecosystem: str | None = None,
) -> RangeResult:
    """Evaluate an OSV affected-range against a concrete installed version."""
    # An explicit version list is the strongest signal OSV gives.
    if explicit_versions:
        listed = [v.strip() for v in explicit_versions.split(",") if v.strip()]
        if listed:
            if version.strip() in listed:
                return RangeResult(Verdict.AFFECTED, "version appears in the affected list", fixed)
            if not introduced and not fixed and not last_affected:
                return RangeResult(
                    Verdict.NOT_AFFECTED, "version absent from the explicit affected list"
                )

    if not is_parseable(version):
        return RangeResult(Verdict.UNKNOWN, f"installed version {version!r} is not comparable")

    reasons: list[str] = []

    if introduced and introduced != "0":
        if not is_parseable(introduced):
            return RangeResult(Verdict.UNKNOWN, f"introduced {introduced!r} is not comparable")
        if compare(version, introduced, ecosystem) < 0:
            return RangeResult(Verdict.NOT_AFFECTED, f"{version} < introduced {introduced}")
        reasons.append(f">= {introduced}")
    elif introduced == "0":
        reasons.append(">= 0")

    if fixed:
        if not is_parseable(fixed):
            return RangeResult(Verdict.UNKNOWN, f"fixed {fixed!r} is not comparable")
        if compare(version, fixed, ecosystem) >= 0:
            return RangeResult(Verdict.NOT_AFFECTED, f"{version} >= fixed {fixed}")
        reasons.append(f"< {fixed}")

    if last_affected:
        if not is_parseable(last_affected):
            return RangeResult(Verdict.UNKNOWN, f"last_affected {last_affected!r} not comparable")
        if compare(version, last_affected, ecosystem) > 0:
            return RangeResult(
                Verdict.NOT_AFFECTED, f"{version} > last_affected {last_affected}"
            )
        reasons.append(f"<= {last_affected}")

    if not reasons:
        return RangeResult(Verdict.UNKNOWN, "range carries no usable bounds")

    return RangeResult(Verdict.AFFECTED, f"{version} satisfies {' and '.join(reasons)}", fixed)


def lowest_fix(candidates: list[str], ecosystem: str | None = None) -> str | None:
    """Smallest version that resolves every supplied range — the upgrade target."""
    usable = [c for c in candidates if c and is_parseable(c)]
    if not usable:
        return None
    best = usable[0]
    for candidate in usable[1:]:
        if compare(candidate, best, ecosystem) > 0:
            best = candidate
    return best
