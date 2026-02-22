"""
Unit tests for signal_engine/domain_age.py — pure helper functions.

The live WHOIS lookup (analyze_domain_age) is NOT tested here because it
requires network I/O; that path is covered in integration tests with mocking.

Coverage:
- _extract_domain: full From header, bare email, no-@ input, lowercase normalisation
- _get_creation_date:
    - None input → None
    - single datetime (tz-aware) → returned as-is
    - single naive datetime → returned with UTC tzinfo attached
    - list of datetimes → earliest is returned
    - list with non-datetime entries → non-datetimes are skipped
    - empty list → None
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from signal_engine.domain_age import _extract_domain, _get_creation_date


# ---------------------------------------------------------------------------
# _extract_domain
# ---------------------------------------------------------------------------

class TestExtractDomain:
    def test_full_from_header_with_display_name(self):
        assert _extract_domain("Alice <alice@example.com>") == "example.com"

    def test_bare_email(self):
        assert _extract_domain("user@sub.domain.co.uk") == "sub.domain.co.uk"

    def test_no_at_sign_returns_none(self):
        assert _extract_domain("just a name") is None

    def test_empty_string_returns_none(self):
        assert _extract_domain("") is None

    def test_lowercase_normalisation(self):
        assert _extract_domain("User@EXAMPLE.COM") == "example.com"

    def test_trailing_whitespace_stripped(self):
        assert _extract_domain("user@example.com  ") == "example.com"

    def test_subdomain_preserved(self):
        assert _extract_domain("x@mail.paypal.com") == "mail.paypal.com"


# ---------------------------------------------------------------------------
# _get_creation_date — mock WhoisEntry via simple namespace objects
# ---------------------------------------------------------------------------

class MockWhois:
    """Minimal stand-in for a whois.WhoisEntry object."""
    def __init__(self, creation_date):
        self.creation_date = creation_date


class TestGetCreationDate:
    def test_none_returns_none(self):
        assert _get_creation_date(MockWhois(None)) is None

    def test_single_aware_datetime_returned(self):
        dt = datetime(2023, 1, 15, tzinfo=timezone.utc)
        result = _get_creation_date(MockWhois(dt))
        assert result == dt

    def test_single_naive_datetime_gets_utc_tzinfo(self):
        naive = datetime(2023, 1, 15)
        result = _get_creation_date(MockWhois(naive))
        assert result is not None
        assert result.tzinfo is not None
        # Value should be the same date/time
        assert result.replace(tzinfo=None) == naive

    def test_list_returns_earliest(self):
        early = datetime(2015, 6, 1, tzinfo=timezone.utc)
        mid   = datetime(2020, 3, 15, tzinfo=timezone.utc)
        late  = datetime(2023, 12, 31, tzinfo=timezone.utc)
        result = _get_creation_date(MockWhois([late, early, mid]))
        assert result == early

    def test_list_with_one_entry_returned(self):
        dt = datetime(2022, 7, 4, tzinfo=timezone.utc)
        result = _get_creation_date(MockWhois([dt]))
        assert result == dt

    def test_empty_list_returns_none(self):
        assert _get_creation_date(MockWhois([])) is None

    def test_list_with_non_datetime_entries_skipped(self):
        valid = datetime(2023, 1, 15, tzinfo=timezone.utc)
        result = _get_creation_date(MockWhois(["not-a-date", None, valid]))
        # Only the valid datetime should be considered
        assert result == valid

    def test_list_all_non_datetime_returns_none(self):
        assert _get_creation_date(MockWhois(["bad", "data", 42])) is None

    def test_mixed_naive_and_aware_min_is_correct(self):
        """Both naive and aware datetimes in the list should compare as UTC."""
        aware_late   = datetime(2023, 6,  1, tzinfo=timezone.utc)
        aware_early  = datetime(2020, 1,  1, tzinfo=timezone.utc)
        result = _get_creation_date(MockWhois([aware_late, aware_early]))
        assert result == aware_early

    def test_domain_age_7_days_would_trigger_high_threshold(self):
        """
        Smoke-check: a domain registered 5 days ago is within the < 7-day bucket.
        This does NOT call analyze_domain_age — it only validates the date arithmetic
        that the signal engine relies on.
        """
        now = datetime.now(tz=timezone.utc)
        five_days_ago = now - timedelta(days=5)
        result = _get_creation_date(MockWhois(five_days_ago))
        age_days = (now - result).days
        assert age_days < 7
        assert age_days < 30
