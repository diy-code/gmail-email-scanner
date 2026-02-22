"""
Unit tests for engine-count-aware tiered scoring functions.

Tests the helper functions that scale severity and points based on the number
of reporting engines/sources, rather than using flat values.

Covers:
  - _vt_tiered_severity (urls.py)           — VirusTotal URL engine counts
  - _vt_domain_tiered_severity (domain_age.py) — VirusTotal domain engine counts
  - _abuseipdb_tiered_points (ip_reputation.py) — AbuseIPDB report counts
"""

from __future__ import annotations

import pytest

from signal_engine.urls import _vt_tiered_severity
from signal_engine.domain_age import _vt_domain_tiered_severity
from signal_engine.ip_reputation import _abuseipdb_tiered_points


# ---------------------------------------------------------------------------
# VirusTotal URL tiered severity
# ---------------------------------------------------------------------------

class TestVtTieredSeverity:
    """Tests for _vt_tiered_severity (URL engine)."""

    def test_single_engine_is_medium_5pts(self):
        severity, points = _vt_tiered_severity(1)
        assert severity == "medium"
        assert points == 5

    def test_two_engines_is_medium_5pts(self):
        severity, points = _vt_tiered_severity(2)
        assert severity == "medium"
        assert points == 5

    def test_three_engines_is_high_12pts(self):
        severity, points = _vt_tiered_severity(3)
        assert severity == "high"
        assert points == 12

    def test_nine_engines_is_high_12pts(self):
        severity, points = _vt_tiered_severity(9)
        assert severity == "high"
        assert points == 12

    def test_ten_engines_is_critical_20pts(self):
        severity, points = _vt_tiered_severity(10)
        assert severity == "critical"
        assert points == 20

    def test_forty_five_engines_is_critical_20pts(self):
        severity, points = _vt_tiered_severity(45)
        assert severity == "critical"
        assert points == 20

    def test_boundary_2_to_3(self):
        _, pts_2 = _vt_tiered_severity(2)
        _, pts_3 = _vt_tiered_severity(3)
        assert pts_2 < pts_3

    def test_boundary_9_to_10(self):
        _, pts_9 = _vt_tiered_severity(9)
        _, pts_10 = _vt_tiered_severity(10)
        assert pts_9 < pts_10


# ---------------------------------------------------------------------------
# VirusTotal domain tiered severity
# ---------------------------------------------------------------------------

class TestVtDomainTieredSeverity:
    """Tests for _vt_domain_tiered_severity (domain engine)."""

    # ---- malicious ----

    def test_malicious_1_engine_medium_5pts(self):
        severity, points = _vt_domain_tiered_severity(1, "malicious")
        assert severity == "medium"
        assert points == 5

    def test_malicious_2_engines_medium_5pts(self):
        severity, points = _vt_domain_tiered_severity(2, "malicious")
        assert severity == "medium"
        assert points == 5

    def test_malicious_5_engines_high_12pts(self):
        severity, points = _vt_domain_tiered_severity(5, "malicious")
        assert severity == "high"
        assert points == 12

    def test_malicious_10_engines_critical_20pts(self):
        severity, points = _vt_domain_tiered_severity(10, "malicious")
        assert severity == "critical"
        assert points == 20

    def test_malicious_50_engines_critical_20pts(self):
        severity, points = _vt_domain_tiered_severity(50, "malicious")
        assert severity == "critical"
        assert points == 20

    # ---- suspicious ----

    def test_suspicious_1_engine_low_3pts(self):
        severity, points = _vt_domain_tiered_severity(1, "suspicious")
        assert severity == "low"
        assert points == 3

    def test_suspicious_2_engines_low_3pts(self):
        severity, points = _vt_domain_tiered_severity(2, "suspicious")
        assert severity == "low"
        assert points == 3

    def test_suspicious_5_engines_medium_6pts(self):
        severity, points = _vt_domain_tiered_severity(5, "suspicious")
        assert severity == "medium"
        assert points == 6

    def test_suspicious_10_engines_high_10pts(self):
        severity, points = _vt_domain_tiered_severity(10, "suspicious")
        assert severity == "high"
        assert points == 10

    def test_suspicious_30_engines_high_10pts(self):
        severity, points = _vt_domain_tiered_severity(30, "suspicious")
        assert severity == "high"
        assert points == 10

    # ---- monotonicity: more engines → higher points ----

    def test_malicious_monotonic(self):
        """Points never decrease as engine count increases."""
        prev = 0
        for count in [1, 2, 3, 9, 10, 50]:
            _, pts = _vt_domain_tiered_severity(count, "malicious")
            assert pts >= prev
            prev = pts

    def test_suspicious_monotonic(self):
        prev = 0
        for count in [1, 2, 3, 9, 10, 50]:
            _, pts = _vt_domain_tiered_severity(count, "suspicious")
            assert pts >= prev
            prev = pts


# ---------------------------------------------------------------------------
# AbuseIPDB tiered scoring
# ---------------------------------------------------------------------------

class TestAbuseipdbTieredPoints:
    """Tests for _abuseipdb_tiered_points (IP reputation engine)."""

    # ---- base tier (confidence > 25%) ----

    def test_base_1_report_low_4pts(self):
        pts, sev = _abuseipdb_tiered_points(1, "base")
        assert sev == "low"
        assert pts == 4

    def test_base_2_reports_low_4pts(self):
        pts, sev = _abuseipdb_tiered_points(2, "base")
        assert sev == "low"
        assert pts == 4

    def test_base_5_reports_medium_8pts(self):
        pts, sev = _abuseipdb_tiered_points(5, "base")
        assert sev == "medium"
        assert pts == 8

    def test_base_10_reports_high_12pts(self):
        pts, sev = _abuseipdb_tiered_points(10, "base")
        assert sev == "high"
        assert pts == 12

    def test_base_100_reports_high_12pts(self):
        pts, sev = _abuseipdb_tiered_points(100, "base")
        assert sev == "high"
        assert pts == 12

    # ---- bonus tier (confidence > 75%) ----

    def test_bonus_1_report_medium_2pts(self):
        pts, sev = _abuseipdb_tiered_points(1, "bonus")
        assert sev == "medium"
        assert pts == 2

    def test_bonus_2_reports_medium_2pts(self):
        pts, sev = _abuseipdb_tiered_points(2, "bonus")
        assert sev == "medium"
        assert pts == 2

    def test_bonus_5_reports_high_4pts(self):
        pts, sev = _abuseipdb_tiered_points(5, "bonus")
        assert sev == "high"
        assert pts == 4

    def test_bonus_10_reports_critical_8pts(self):
        pts, sev = _abuseipdb_tiered_points(10, "bonus")
        assert sev == "critical"
        assert pts == 8

    def test_bonus_100_reports_critical_8pts(self):
        pts, sev = _abuseipdb_tiered_points(100, "bonus")
        assert sev == "critical"
        assert pts == 8

    # ---- additive totals for combined base + bonus ----

    def test_total_max_with_many_reports(self):
        """With >= 10 reports and confidence > 75%, total = 12 + 8 = 20 (fills cap)."""
        base_pts, _ = _abuseipdb_tiered_points(50, "base")
        bonus_pts, _ = _abuseipdb_tiered_points(50, "bonus")
        assert base_pts + bonus_pts == 20

    def test_total_min_with_few_reports(self):
        """With 1 report and confidence > 75%, total = 4 + 2 = 6."""
        base_pts, _ = _abuseipdb_tiered_points(1, "base")
        bonus_pts, _ = _abuseipdb_tiered_points(1, "bonus")
        assert base_pts + bonus_pts == 6

    def test_total_mid_with_moderate_reports(self):
        """With 5 reports and confidence > 75%, total = 8 + 4 = 12."""
        base_pts, _ = _abuseipdb_tiered_points(5, "base")
        bonus_pts, _ = _abuseipdb_tiered_points(5, "bonus")
        assert base_pts + bonus_pts == 12

    # ---- zero reports edge case ----

    def test_base_0_reports_low_4pts(self):
        """Zero reports should be treated same as 1-2 (weakest tier)."""
        pts, sev = _abuseipdb_tiered_points(0, "base")
        assert sev == "low"
        assert pts == 4

    def test_bonus_0_reports_medium_2pts(self):
        pts, sev = _abuseipdb_tiered_points(0, "bonus")
        assert sev == "medium"
        assert pts == 2

    # ---- monotonicity ----

    def test_base_monotonic(self):
        prev = 0
        for reports in [0, 1, 2, 3, 9, 10, 100]:
            pts, _ = _abuseipdb_tiered_points(reports, "base")
            assert pts >= prev
            prev = pts

    def test_bonus_monotonic(self):
        prev = 0
        for reports in [0, 1, 2, 3, 9, 10, 100]:
            pts, _ = _abuseipdb_tiered_points(reports, "bonus")
            assert pts >= prev
            prev = pts
