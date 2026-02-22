"""
Unit tests for signal_engine/ip_reputation.py — _is_private, _extract_external_ip.

The live AbuseIPDB API call (analyze_ip_reputation) is NOT tested here;
that path is covered in the integration test with a mocked HTTP client.

Coverage:
- _is_private: RFC-1918 ranges, loopback, link-local, valid public IPs, bad input
- _extract_external_ip:
    - empty header list → None
    - all-private headers → None
    - first external IP is returned (outermost-first order, Assumption A6)
    - internal IPs are skipped to find the first external one
    - no bracket-enclosed IPs in header → None
    - multiple IPs per header line → returns first external
"""

from __future__ import annotations

import pytest

from signal_engine.ip_reputation import _is_private, _extract_external_ip


# ---------------------------------------------------------------------------
# _is_private
# ---------------------------------------------------------------------------

class TestIsPrivate:
    # --- Private ranges ---
    def test_loopback_127_is_private(self):
        assert _is_private("127.0.0.1") is True

    def test_rfc1918_10_network(self):
        assert _is_private("10.0.0.1") is True

    def test_rfc1918_10_network_upper_bound(self):
        assert _is_private("10.255.255.255") is True

    def test_rfc1918_172_16_network(self):
        assert _is_private("172.16.0.1") is True

    def test_rfc1918_172_31_network(self):
        assert _is_private("172.31.255.255") is True

    def test_rfc1918_192_168_network(self):
        assert _is_private("192.168.1.1") is True

    def test_link_local_169_254(self):
        assert _is_private("169.254.0.1") is True

    # --- Public IPs ---
    def test_google_dns_public(self):
        assert _is_private("8.8.8.8") is False

    def test_cloudflare_dns_public(self):
        assert _is_private("1.1.1.1") is False

    def test_arbitrary_public_ip(self):
        assert _is_private("203.0.113.5") is False

    def test_172_15_not_private(self):
        # 172.15.x.x is NOT in the private range (172.16–172.31 is)
        assert _is_private("172.15.255.255") is False

    def test_172_32_not_private(self):
        # 172.32.x.x is beyond the private range
        assert _is_private("172.32.0.1") is False

    # --- Invalid input ---
    def test_invalid_string_treated_as_private(self):
        assert _is_private("not-an-ip") is True

    def test_empty_string_treated_as_private(self):
        assert _is_private("") is True


# ---------------------------------------------------------------------------
# _extract_external_ip
# ---------------------------------------------------------------------------

class TestExtractExternalIP:
    def test_empty_headers_returns_none(self):
        assert _extract_external_ip([]) is None

    def test_only_private_ips_returns_none(self):
        headers = [
            "Received: from internal (internal [192.168.1.10]) by relay",
            "Received: from localhost (localhost [127.0.0.1])",
        ]
        assert _extract_external_ip(headers) is None

    def test_single_external_ip_returned(self):
        headers = [
            "Received: from mail.evil.com (mail.evil.com [1.2.3.4]) by mx.google.com"
        ]
        assert _extract_external_ip(headers) == "1.2.3.4"

    def test_first_external_ip_preferred_assumption_a6(self):
        """
        The Received chain is ordered outermost-first; the first external IP
        is the actual sender's server (Assumption A6 / PLAN.md Phase 2.5).
        """
        headers = [
            "Received: from mail.evil.com (mail.evil.com [5.6.7.8]) by mx.google.com",
            "Received: from relay.internal [10.0.0.1]",
        ]
        assert _extract_external_ip(headers) == "5.6.7.8"

    def test_skips_private_to_reach_external(self):
        headers = [
            "Received: from relay.corp [172.16.0.10]",
            "Received: from mail.attacker.com [203.0.113.55]",
        ]
        assert _extract_external_ip(headers) == "203.0.113.55"

    def test_no_bracket_enclosed_ip_returns_none(self):
        headers = ["Received: from mail.example.com by mx.google.com with ESMTP"]
        assert _extract_external_ip(headers) is None

    def test_malformed_header_does_not_crash(self):
        headers = ["not a valid received header at all!!!"]
        result = _extract_external_ip(headers)
        assert result is None  # no crash, graceful None

    def test_multiple_ips_in_one_header_picks_first_external(self):
        # The regex picks whichever bracketed IP comes first in the string
        # Private 192.168.1.1 appears first in brackets but is internal;
        # 8.8.8.8 is the external one.
        headers = [
            "Received: from relay (relay [192.168.1.1]) via [8.8.8.8]"
        ]
        assert _extract_external_ip(headers) == "8.8.8.8"

    def test_google_infrastructure_ips_are_external(self):
        # 74.125.x.x (Google mail servers) are external — should be returned
        headers = [
            "Received: from mail-sor-f41.google.com ([74.125.82.41])"
        ]
        assert _extract_external_ip(headers) == "74.125.82.41"
