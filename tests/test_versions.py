"""Version comparison — the function the LLM is forbidden from performing.

These are the tests that matter most in the whole suite. A wrong answer here
means telling a security team an asset is safe when it is not.
"""

from __future__ import annotations

import pytest

from vulnintel.risk.versions import (
    GenericVersion,
    Verdict,
    compare,
    in_cpe_range,
    in_osv_range,
    is_parseable,
    lowest_fix,
)


class TestCompare:
    @pytest.mark.parametrize(
        ("left", "right", "expected"),
        [
            ("1.0.0", "1.0.1", -1),
            ("1.0.1", "1.0.0", 1),
            ("1.0.0", "1.0.0", 0),
            ("2.0", "10.0", -1),          # numeric, not lexical
            ("1.9.0", "1.10.0", -1),
            ("1.0", "1.0.0", 0),          # trailing zeros are equal
            ("1.0.0", "1.0.0.0", 0),
        ],
    )
    def test_generic_ordering(self, left, right, expected):
        assert compare(left, right) == expected

    @pytest.mark.parametrize(
        ("left", "right", "expected"),
        [
            ("1.0.0", "1.0.0-beta", 1),      # release beats prerelease
            ("1.0.0-alpha", "1.0.0-beta", -1),
            ("1.0.0-rc.1", "1.0.0", -1),
            ("2.0.0-rc.1", "1.9.9", 1),
        ],
    )
    def test_semver_prerelease(self, left, right, expected):
        assert compare(left, right, "npm") == expected

    @pytest.mark.parametrize(
        ("left", "right", "expected"),
        [
            ("1.0.0", "1.0.0.post1", -1),
            ("1.0.0rc1", "1.0.0", -1),
            ("2.0.0", "2.0", 0),
            ("1.0.0a1", "1.0.0b1", -1),
        ],
    )
    def test_pep440(self, left, right, expected):
        assert compare(left, right, "PyPI") == expected

    def test_ordering_is_transitive(self):
        versions = ["1.0.0", "1.0.1", "1.2.0", "1.10.0", "2.0.0"]
        for a, b in zip(versions, versions[1:], strict=False):
            assert compare(a, b) == -1

    def test_generic_version_is_hashable_and_sortable(self):
        values = sorted({GenericVersion("1.10.0"), GenericVersion("1.9.0")})
        assert values[0].raw == "1.9.0"


class TestParseable:
    @pytest.mark.parametrize("value", ["1.0", "9.8p1", "4.2.11", "2.4.59"])
    def test_real_versions(self, value):
        assert is_parseable(value)

    @pytest.mark.parametrize("value", [None, "", "*", "-", "unknown", "n/a"])
    def test_wildcards_are_not_parseable(self, value):
        assert not is_parseable(value)


class TestOsvRange:
    def test_below_fix_is_affected(self):
        result = in_osv_range("4.2.3", introduced="0", fixed="4.2.11", ecosystem="PyPI")
        assert result.verdict is Verdict.AFFECTED
        assert result.fixed_version == "4.2.11"

    def test_at_fix_is_not_affected(self):
        assert in_osv_range("4.2.11", introduced="0", fixed="4.2.11",
                            ecosystem="PyPI").verdict is Verdict.NOT_AFFECTED

    def test_above_fix_is_not_affected(self):
        assert in_osv_range("5.0.2", introduced="0", fixed="4.2.11",
                            ecosystem="PyPI").verdict is Verdict.NOT_AFFECTED

    def test_below_introduced_is_not_affected(self):
        assert in_osv_range("3.2.0", introduced="4.0.0", fixed="4.2.11",
                            ecosystem="PyPI").verdict is Verdict.NOT_AFFECTED

    def test_last_affected_is_inclusive(self):
        assert in_osv_range("1.5.0", introduced="1.0.0",
                            last_affected="1.5.0").verdict is Verdict.AFFECTED
        assert in_osv_range("1.5.1", introduced="1.0.0",
                            last_affected="1.5.0").verdict is Verdict.NOT_AFFECTED

    def test_explicit_version_list(self):
        assert in_osv_range("1.2.3", explicit_versions="1.2.3,1.2.4").verdict is Verdict.AFFECTED
        assert in_osv_range("1.2.5", explicit_versions="1.2.3,1.2.4").verdict is Verdict.NOT_AFFECTED

    def test_unparseable_version_is_unknown_never_affected(self):
        result = in_osv_range("latest", introduced="0", fixed="1.0.0")
        assert result.verdict is Verdict.UNKNOWN
        assert result.verdict is not Verdict.AFFECTED

    def test_no_bounds_is_unknown(self):
        assert in_osv_range("1.0.0").verdict is Verdict.UNKNOWN

    def test_every_result_states_a_reason(self):
        for result in [
            in_osv_range("1.0.0", introduced="0", fixed="2.0.0"),
            in_osv_range("3.0.0", introduced="0", fixed="2.0.0"),
            in_osv_range("bad", introduced="0", fixed="2.0.0"),
        ]:
            assert result.reason


class TestCpeRange:
    def test_within_range(self):
        assert in_cpe_range("1.24.0", version_end_excluding="1.26.1").verdict is Verdict.AFFECTED

    def test_at_exclusive_upper_bound(self):
        assert in_cpe_range("1.26.1",
                            version_end_excluding="1.26.1").verdict is Verdict.NOT_AFFECTED

    def test_inclusive_upper_bound(self):
        assert in_cpe_range("2.4.59", version_end_including="2.4.59").verdict is Verdict.AFFECTED

    def test_below_lower_bound(self):
        result = in_cpe_range(
            "1.18.0", version_start_including="1.22.0", version_end_excluding="1.26.1"
        )
        assert result.verdict is Verdict.NOT_AFFECTED

    def test_exclusive_lower_bound(self):
        assert in_cpe_range("1.22.0", version_start_excluding="1.22.0",
                            version_end_excluding="2.0").verdict is Verdict.NOT_AFFECTED

    def test_exact_pinned_version(self):
        assert in_cpe_range("9.6p1", cpe_version="9.6p1").verdict is Verdict.AFFECTED
        assert in_cpe_range("9.8p1", cpe_version="9.6p1").verdict is Verdict.NOT_AFFECTED

    def test_wildcard_with_no_bounds_is_unknown(self):
        """A wildcard CPE with no range says nothing about a specific install."""
        assert in_cpe_range("9.6p1", cpe_version="*").verdict is Verdict.UNKNOWN

    def test_fixed_version_reported_from_exclusive_end(self):
        assert in_cpe_range("1.24.0", version_end_excluding="1.26.1").fixed_version == "1.26.1"


class TestLowestFix:
    def test_picks_the_highest_required_fix(self):
        assert lowest_fix(["1.2.0", "1.5.0", "1.3.0"]) == "1.5.0"

    def test_ignores_unparseable_candidates(self):
        assert lowest_fix(["", None, "unknown", "2.0.0"]) == "2.0.0"

    def test_returns_none_when_nothing_usable(self):
        assert lowest_fix(["", None, "*"]) is None
