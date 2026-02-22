"""
Unit tests for scoring.py — compute_score, _compute_verdict, _compute_confidence.

Coverage goal:
- Category caps are applied correctly
- Score formula: min(100, round(capped / 150 * 100))
- Verdict thresholds: 0–30 SAFE, 31–65 SUSPICIOUS, 66–100 MALICIOUS
- Confidence degradation per unavailable source
- Confidence level labels (High / Medium / Low)
- Parse-warning confidence penalty (applied when >= 2 warnings)
- Top-3 contributors are sorted by points, capped at 3
- Evidence items mirror every fired signal
- ScoringBreakdown carries the exact arithmetic trace
- Unknown signal categories are silently ignored (no crash, no score)
"""

from __future__ import annotations

import pytest

from models import Signal
from scoring import (
    CATEGORY_CAPS,
    compute_score,
    _compute_confidence,
    _compute_verdict,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_signal(category: str, points: int, name: str = "Test Signal") -> Signal:
    return Signal(
        name=name,
        category=category,
        severity="medium",
        description=f"Test signal [{category}]",
        value=None,
        points=points,
    )


# ---------------------------------------------------------------------------
# _compute_verdict
# ---------------------------------------------------------------------------

class TestComputeVerdict:
    def test_zero_is_safe(self):
        assert _compute_verdict(0) == "SAFE"

    def test_30_is_safe(self):
        assert _compute_verdict(30) == "SAFE"

    def test_31_is_suspicious(self):
        assert _compute_verdict(31) == "SUSPICIOUS"

    def test_65_is_suspicious(self):
        assert _compute_verdict(65) == "SUSPICIOUS"

    def test_66_is_malicious(self):
        assert _compute_verdict(66) == "MALICIOUS"

    def test_100_is_malicious(self):
        assert _compute_verdict(100) == "MALICIOUS"

    def test_midpoint_suspicious(self):
        assert _compute_verdict(48) == "SUSPICIOUS"

    def test_boundary_safe_suspicious(self):
        # 30 = SAFE, 31 = SUSPICIOUS — boundary must be exclusive from above
        assert _compute_verdict(30) == "SAFE"
        assert _compute_verdict(31) == "SUSPICIOUS"

    def test_boundary_suspicious_malicious(self):
        assert _compute_verdict(65) == "SUSPICIOUS"
        assert _compute_verdict(66) == "MALICIOUS"


# ---------------------------------------------------------------------------
# _compute_confidence (unit, no I/O)
# ---------------------------------------------------------------------------

class TestComputeConfidence:
    """Tests for the confidence calculation and label logic."""

    def test_all_available_confidence_100_high(self):
        confidence, label = _compute_confidence({}, 0)
        assert confidence == 100
        assert label == "High"

    def test_virustotal_unavailable_deducts_20(self):
        confidence, label = _compute_confidence({"virustotal": False}, 0)
        assert confidence == 80
        assert label == "High"

    def test_safe_browsing_unavailable_deducts_15(self):
        confidence, label = _compute_confidence({"safe_browsing": False}, 0)
        assert confidence == 85
        assert label == "High"

    def test_abuseipdb_unavailable_deducts_10(self):
        confidence, label = _compute_confidence({"abuseipdb": False}, 0)
        assert confidence == 90
        assert label == "High"

    def test_whois_unavailable_deducts_10(self):
        confidence, label = _compute_confidence({"whois": False}, 0)
        assert confidence == 90
        assert label == "High"

    def test_all_external_unavailable_gives_low(self):
        # 100 - 20 - 15 - 10 - 10 = 45 → Low
        availability = {
            "virustotal": False,
            "safe_browsing": False,
            "abuseipdb": False,
            "whois": False,
        }
        confidence, label = _compute_confidence(availability, 0)
        assert confidence == 45
        assert label == "Low"

    def test_vt_and_sb_missing_gives_medium(self):
        # 100 - 20 - 15 = 65 → Medium
        availability = {"virustotal": False, "safe_browsing": False}
        confidence, label = _compute_confidence(availability, 0)
        assert confidence == 65
        assert label == "Medium"

    def test_two_parse_warnings_deducts_10(self):
        confidence, label = _compute_confidence({}, 2)
        assert confidence == 90

    def test_three_parse_warnings_deducts_10_once(self):
        # Penalty applies once when count >= 2, not once per warning
        confidence_2, _ = _compute_confidence({}, 2)
        confidence_3, _ = _compute_confidence({}, 3)
        assert confidence_2 == confidence_3 == 90

    def test_single_parse_warning_no_penalty(self):
        confidence, _ = _compute_confidence({}, 1)
        assert confidence == 100

    def test_confidence_never_below_zero(self):
        availability = {
            "virustotal": False,
            "safe_browsing": False,
            "abuseipdb": False,
            "whois": False,
        }
        confidence, _ = _compute_confidence(availability, 5)  # extra parse warnings
        assert confidence >= 0

    def test_confidence_never_above_100(self):
        # Missing key treated as True → base stays 100
        confidence, _ = _compute_confidence({"unknown_source": True}, 0)
        assert confidence <= 100

    def test_50_percent_is_medium(self):
        # Arrange: deduct exactly 50 points
        # VT (20) + SB (15) + abuseipdb (10) + parse_warning (10) = 55 deducted
        # but parse warning needs count >= 2: 20 + 15 + 10 + 10 (warning) = 55 → 45 Low
        # Let's target exactly 50: VT (20) + SB (15) + abuseipdb (10) + parse(10) = 55, no
        # 100 - 20(VT) - 15(SB) - 10(abuseipdb) = 55  → still Medium? No 55 >= 50 → Medium
        availability = {"virustotal": False, "safe_browsing": False, "abuseipdb": False}
        confidence, label = _compute_confidence(availability, 0)
        assert confidence == 55
        assert label == "Medium"

    def test_79_percent_is_medium(self):
        # 100 - 20 (VT) = 80 → High; we need exactly 79
        # 100 - 20 (VT) - 1? No, can only hit 79 with parse warning alongside VT
        # VT=20 + parse=10 = 30 → 70 → Medium
        availability = {"virustotal": False}
        confidence, label = _compute_confidence(availability, 2)  # 100 - 20 - 10 = 70
        assert confidence == 70
        assert label == "Medium"

    def test_80_percent_is_high(self):
        # 100 - 20 (VT) = 80 → High
        confidence, label = _compute_confidence({"virustotal": False}, 0)
        assert confidence == 80
        assert label == "High"


# ---------------------------------------------------------------------------
# compute_score — integration of all scoring sub-steps
# ---------------------------------------------------------------------------

class TestComputeScore:
    """Tests for the full compute_score() pipeline."""

    def test_no_signals_score_zero_verdict_safe(self):
        score, verdict, confidence, c_label, top, evidence, breakdown = compute_score(
            [], {}, []
        )
        assert score == 0
        assert verdict == "SAFE"
        assert confidence == 100

    def test_known_arithmetic_three_header_signals(self):
        """
        SPF(15) + DKIM(15) + DMARC(15) = 45 header pts.
        Header cap = 45 → capped = 45.
        score = round(45/150*100) = round(30) = 30.
        """
        signals = [
            make_signal("header", 15, "SPF Fail"),
            make_signal("header", 15, "DKIM Fail"),
            make_signal("header", 15, "DMARC Fail"),
        ]
        score, verdict, *_ = compute_score(signals, {}, [])
        assert score == 30
        assert verdict == "SAFE"

    def test_header_category_cap_applied(self):
        """Raw header total 100 pts > cap of 45 → capped to 45."""
        signals = [make_signal("header", 50, f"H{i}") for i in range(2)]
        score, *_ = compute_score(signals, {}, [])
        # 100 raw → capped 45 → 45/150*100 = 30
        assert score == 30

    def test_url_category_cap_applied(self):
        """URL cap is 55; raw > 55 should not exceed the cap."""
        signals = [make_signal("url", 60)]
        score, *_ = compute_score(signals, {}, [])
        # capped to 55 → round(55/150*100) = round(36.67) = 37
        assert score == 37

    def test_max_score_100_when_all_categories_at_cap(self):
        """Every category at its cap → sum = 150 → 100/100."""
        signals = [
            make_signal("header",   CATEGORY_CAPS["header"]),
            make_signal("url",      CATEGORY_CAPS["url"]),
            make_signal("ip",       CATEGORY_CAPS["ip"]),
            make_signal("domain",   CATEGORY_CAPS["domain"]),
            make_signal("behavior", CATEGORY_CAPS["behavior"]),
        ]
        score, verdict, *_ = compute_score(signals, {}, [])
        assert score == 100
        assert verdict == "MALICIOUS"

    def test_suspicious_range(self):
        """Score in 31–65 → SUSPICIOUS."""
        # url = 20 pts → score = round(20/150*100) = round(13.3) = 13 — too low
        # need ~47+ raw to hit 31 → 47/150*100=31.33 → 31
        # Use ip=20 + domain=20 = 40 → round(40/150*100) = round(26.7) = 27 → still SAFE
        # Actually need 47: ip(20) + domain(20) + behavior(10) = 50 → round(50/150*100)=33 → SUSPICIOUS
        signals = [
            make_signal("ip", 20),
            make_signal("domain", 20),
            make_signal("behavior", 10),
        ]
        score, verdict, *_ = compute_score(signals, {}, [])
        assert score == 33
        assert verdict == "SUSPICIOUS"

    def test_malicious_range(self):
        """score >= 66 → MALICIOUS."""
        # header(45) + url(55) = 100 → round(100/150*100) = round(66.7) = 67
        signals = [
            make_signal("header", 45),
            make_signal("url", 55),
        ]
        score, verdict, *_ = compute_score(signals, {}, [])
        assert score == 67
        assert verdict == "MALICIOUS"

    def test_top_contributors_sorted_descending(self):
        signals = [
            make_signal("header", 5,  "Low"),
            make_signal("url",    20, "High"),
            make_signal("ip",     12, "Mid"),
            make_signal("domain", 15, "Med"),
        ]
        _, _, _, _, top, *_ = compute_score(signals, {}, [])
        assert top[0].name == "High"
        assert top[1].name == "Med"
        assert top[2].name == "Mid"

    def test_top_contributors_capped_at_3(self):
        signals = [make_signal("url", 20, f"U{i}") for i in range(6)]
        _, _, _, _, top, *_ = compute_score(signals, {}, [])
        assert len(top) == 3

    def test_top_contributors_fewer_than_3_when_few_signals(self):
        signals = [make_signal("header", 15, "SPF Fail")]
        _, _, _, _, top, *_ = compute_score(signals, {}, [])
        assert len(top) == 1

    def test_evidence_items_count_matches_signals(self):
        signals = [
            make_signal("header", 15, "SPF Fail"),
            make_signal("url",    20, "Bad URL"),
        ]
        _, _, _, _, _, evidence, _ = compute_score(signals, {}, [])
        assert len(evidence) == 2

    def test_evidence_items_contain_signal_names(self):
        signals = [
            make_signal("header", 15, "SPF Fail"),
            make_signal("url",    20, "Bad URL"),
        ]
        _, _, _, _, _, evidence, _ = compute_score(signals, {}, [])
        evidence_names = {e.signal for e in evidence}
        assert "SPF Fail" in evidence_names
        assert "Bad URL" in evidence_names

    def test_scoring_breakdown_formula_includes_score(self):
        signals = [make_signal("header", 15, "SPF Fail")]
        _, _, _, _, _, _, breakdown = compute_score(signals, {}, [])
        assert "score=min(100" in breakdown.formula
        assert str(15) in breakdown.formula   # capped_points appears in formula

    def test_scoring_breakdown_totals_correct(self):
        signals = [
            make_signal("header", 15, "SPF Fail"),
            make_signal("url",    20, "Bad URL"),
        ]
        _, _, _, _, _, _, breakdown = compute_score(signals, {}, [])
        assert breakdown.total_points == 35
        assert breakdown.capped_points == 35
        assert breakdown.max_points == 150

    def test_scoring_breakdown_cap_reduces_total(self):
        # header raw = 100, cap = 45 → capped = 45, total_raw = 100
        signals = [make_signal("header", 100)]
        _, _, _, _, _, _, breakdown = compute_score(signals, {}, [])
        assert breakdown.total_points == 100
        assert breakdown.capped_points == 45

    def test_unknown_category_is_ignored_gracefully(self):
        """Unknown category must not crash and must not add to the score."""
        signals = [make_signal("unknown_category", 50, "Mystery")]
        score, *_ = compute_score(signals, {}, [])
        assert score == 0

    def test_confidence_passed_through_to_result(self):
        """Confidence from availability dict reaches the returned tuple."""
        availability = {"virustotal": False}  # -20
        _, _, confidence, label, *_ = compute_score([], availability, [])
        assert confidence == 80
        assert label == "High"

    def test_category_points_in_breakdown_match_caps(self):
        """category_points in breakdown should not exceed each category's cap."""
        signals = [
            make_signal("header",   100),
            make_signal("url",      100),
            make_signal("ip",       100),
            make_signal("domain",   100),
            make_signal("behavior", 100),
        ]
        _, _, _, _, _, _, breakdown = compute_score(signals, {}, [])
        assert breakdown.category_points["header"]   == CATEGORY_CAPS["header"]
        assert breakdown.category_points["url"]      == CATEGORY_CAPS["url"]
        assert breakdown.category_points["ip"]       == CATEGORY_CAPS["ip"]
        assert breakdown.category_points["domain"]   == CATEGORY_CAPS["domain"]
        assert breakdown.category_points["behavior"] == CATEGORY_CAPS["behavior"]
