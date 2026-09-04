"""Deterministic risk scoring.

The central claim of this project is that the ranking is computed, auditable
and reproducible, and that the language model cannot influence it. These tests
are what turn that from a claim into a property.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta

import pytest

from vulnintel.risk.policy import DEFAULT_WEIGHTS, SLA_RULES, select_sla, validate_weights
from vulnintel.risk.scoring import RiskScorer, ScoreInput

TODAY = date(2026, 9, 4)


@pytest.fixture
def scorer() -> RiskScorer:
    return RiskScorer(today=TODAY)


def make(**overrides) -> ScoreInput:
    base = {
        "finding_id": 1,
        "cvss_base": 7.5,
        "epss": 0.1,
        "kev": False,
        "business_criticality": "high",
        "environment": "production",
        "internet_facing": False,
        "data_classification": "internal",
        "detected_at": datetime(2026, 9, 1, tzinfo=UTC).replace(tzinfo=None),
    }
    base.update(overrides)
    return ScoreInput(**base)


class TestWeights:
    def test_weights_sum_to_one(self):
        assert sum(DEFAULT_WEIGHTS.values()) == pytest.approx(1.0)
        validate_weights(DEFAULT_WEIGHTS)

    def test_missing_component_is_rejected(self):
        with pytest.raises(ValueError, match="Missing risk weight"):
            validate_weights({"cvss": 1.0})

    def test_weights_not_summing_to_one_are_rejected(self):
        bad = {**DEFAULT_WEIGHTS, "cvss": 0.9}
        with pytest.raises(ValueError, match="must sum to 1.0"):
            validate_weights(bad)


class TestDeterminism:
    def test_identical_inputs_give_identical_scores(self, scorer):
        values = {scorer.score(make()).score for _ in range(50)}
        assert len(values) == 1

    def test_independent_scorers_agree(self):
        a = RiskScorer(today=TODAY).score(make())
        b = RiskScorer(today=TODAY).score(make())
        assert a.score == b.score
        assert a.contributions == b.contributions

    def test_contributions_sum_to_the_score(self, scorer):
        result = scorer.score(make())
        assert sum(result.contributions.values()) == pytest.approx(result.score, abs=0.01)


class TestMonotonicity:
    @pytest.mark.parametrize("field,values", [
        ("cvss_base", [0.0, 3.0, 6.0, 9.0, 10.0]),
        ("epss", [0.0, 0.1, 0.5, 0.9, 1.0]),
    ])
    def test_raising_a_component_never_lowers_the_score(self, scorer, field, values):
        scores = [scorer.score(make(**{field: v})).score for v in values]
        assert scores == sorted(scores)

    def test_kev_strictly_raises_the_score(self, scorer):
        assert scorer.score(make(kev=True)).score > scorer.score(make(kev=False)).score

    def test_internet_exposure_strictly_raises_the_score(self, scorer):
        assert (
            scorer.score(make(internet_facing=True)).score
            > scorer.score(make(internet_facing=False)).score
        )

    def test_production_outranks_development(self, scorer):
        production = scorer.score(make(environment="production", business_criticality="critical"))
        development = scorer.score(make(environment="development", business_criticality="critical"))
        assert production.score > development.score


class TestBounds:
    def test_score_never_exceeds_100(self, scorer):
        result = scorer.score(make(
            cvss_base=10.0, epss=1.0, kev=True, business_criticality="critical",
            environment="production", internet_facing=True, data_classification="restricted",
            last_patch_date=TODAY - timedelta(days=900),
        ))
        assert 0.0 <= result.score <= 100.0

    def test_score_never_below_zero(self, scorer):
        result = scorer.score(make(
            cvss_base=0.0, epss=0.0, kev=False, business_criticality="low",
            environment="development", data_classification="public",
            has_compensating_control=True,
        ))
        assert result.score >= 0.0


class TestEnterpriseContextInversion:
    """The design's central claim, asserted directly."""

    def test_kev_on_exposed_tier1_outranks_higher_cvss_on_a_dev_box(self, scorer):
        exposed = scorer.score(make(
            cvss_base=6.5, epss=0.55, kev=True, business_criticality="critical",
            environment="production", internet_facing=True, data_classification="restricted",
        ))
        dev_box = scorer.score(make(
            cvss_base=9.8, epss=0.02, kev=False, business_criticality="low",
            environment="development", internet_facing=False, data_classification="public",
        ))
        assert exposed.score > dev_box.score, (
            "A CVSS-ordered queue would invert these. Enterprise context is the "
            "entire reason this platform exists."
        )


class TestMissingData:
    def test_absent_cvss_uses_a_neutral_prior_not_zero(self, scorer):
        result = scorer.score(make(cvss_base=None))
        assert result.components["cvss"] == 0.5
        assert any("CVSS unavailable" in note for note in result.notes)

    def test_absent_epss_contributes_nothing_but_is_noted(self, scorer):
        result = scorer.score(make(epss=None))
        assert result.components["epss"] == 0.0
        assert any("no EPSS score" in note for note in result.notes)

    def test_compensating_control_reduces_urgency_and_is_recorded(self, scorer):
        plain = scorer.score(make(internet_facing=True))
        mitigated = scorer.score(make(internet_facing=True, has_compensating_control=True))
        assert mitigated.score < plain.score
        assert any("compensating control" in note for note in mitigated.notes)

    def test_stale_asset_increases_urgency(self, scorer):
        fresh = scorer.score(make(last_patch_date=TODAY - timedelta(days=10)))
        stale = scorer.score(make(last_patch_date=TODAY - timedelta(days=400)))
        assert stale.score > fresh.score
        assert any("unpatched" in note for note in stale.notes)


class TestSlaSelection:
    def test_kev_and_internet_facing_is_the_tightest_window(self):
        rule = select_sla(kev=True, internet_facing=True, cvss_base=5.0, epss=0.0,
                          business_criticality="high", environment="production")
        assert rule.rule_id == "SLA-1"
        assert rule.days == 3

    def test_kev_overrides_the_cvss_band(self):
        """A medium-CVSS KEV entry must not fall into the medium window."""
        kev_rule = select_sla(kev=True, internet_facing=False, cvss_base=5.5, epss=0.0,
                              business_criticality="medium", environment="production")
        plain_rule = select_sla(kev=False, internet_facing=False, cvss_base=5.5, epss=0.0,
                                business_criticality="medium", environment="production")
        assert kev_rule.days == 7
        assert plain_rule.days == 90
        assert kev_rule.days < plain_rule.days

    def test_epss_threshold_tightens_the_window(self):
        high = select_sla(kev=False, internet_facing=False, cvss_base=7.5, epss=0.15,
                          business_criticality="high", environment="production")
        low = select_sla(kev=False, internet_facing=False, cvss_base=7.5, epss=0.01,
                         business_criticality="high", environment="production")
        assert high.days == 14
        assert low.days == 30

    def test_every_finding_matches_some_rule(self):
        rule = select_sla(kev=False, internet_facing=False, cvss_base=0.0, epss=0.0,
                          business_criticality=None, environment=None)
        assert rule.rule_id == "SLA-8"

    def test_rule_ids_are_unique(self):
        ids = [r.rule_id for r in SLA_RULES]
        assert len(ids) == len(set(ids))


class TestSlaDeadlines:
    def test_due_date_is_detection_plus_window(self, scorer):
        detected = datetime(2026, 9, 1, tzinfo=UTC).replace(tzinfo=None)
        result = scorer.score(make(kev=True, internet_facing=True, detected_at=detected))
        assert result.sla_due_date == date(2026, 9, 4)

    def test_breach_is_computed_not_guessed(self, scorer):
        old = datetime(2026, 1, 1, tzinfo=UTC).replace(tzinfo=None)
        assert scorer.score(make(detected_at=old)).sla_breached is True
        recent = datetime(2026, 9, 3, tzinfo=UTC).replace(tzinfo=None)
        assert scorer.score(make(detected_at=recent)).sla_breached is False


class TestExplainability:
    def test_explain_names_every_component(self, scorer):
        text = scorer.score(make()).explain()
        for component in DEFAULT_WEIGHTS:
            assert component in text

    def test_row_carries_the_model_version_and_weights(self, scorer):
        row = scorer.score(make()).to_row()
        assert row["model_version"]
        assert "cvss" in row["weights"]
        assert row["scored_at"] is not None
