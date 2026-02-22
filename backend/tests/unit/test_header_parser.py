"""
Unit tests for signal_engine/headers.py

Coverage:
- _extract_domain: display-name + angle-bracket, bare email, edge cases
- _parse_auth_result: SPF / DKIM / DMARC parsing, trailing punctuation, case
- analyze_headers:
    - SPF fail / softfail → signal (15 pts)
    - DKIM fail / none   → signal (15 pts)
    - DMARC fail         → signal (15 pts)
    - all pass           → zero signals
    - missing auth header → parse warning, zero signals
    - reply-to same domain → no signal
    - reply-to different domain → signal (8 pts)
    - PayPal spoofing from evil domain → signal (10 pts)
    - PayPal from paypal.com → no signal
    - legitimate email → no signals, no warnings
"""

from __future__ import annotations

import pytest

from signal_engine.headers import (
    _extract_domain,
    _parse_auth_result,
    analyze_headers,
)

# Convenience auth header strings used across many tests
AUTH_ALL_PASS = "spf=pass dkim=pass dmarc=pass"
AUTH_ALL_FAIL = "spf=fail dkim=fail dmarc=fail"


# ---------------------------------------------------------------------------
# _extract_domain
# ---------------------------------------------------------------------------

class TestExtractDomain:
    def test_display_name_with_angle_brackets(self):
        assert _extract_domain("John Doe <john@example.com>") == "example.com"

    def test_quoted_display_name_with_angle_brackets(self):
        assert _extract_domain('"John Doe" <john@example.com>') == "example.com"

    def test_bare_email(self):
        assert _extract_domain("john@example.com") == "example.com"

    def test_no_email_returns_none(self):
        assert _extract_domain("Just A Name") is None

    def test_empty_string_returns_none(self):
        assert _extract_domain("") is None

    def test_subdomain_preserved(self):
        assert _extract_domain("user@mail.example.com") == "mail.example.com"

    def test_lowercase_normalisation(self):
        assert _extract_domain("User@EXAMPLE.COM") == "example.com"

    def test_plus_addressing_handled(self):
        assert _extract_domain("user+tag@example.com") == "example.com"


# ---------------------------------------------------------------------------
# _parse_auth_result
# ---------------------------------------------------------------------------

class TestParseAuthResult:
    def test_spf_pass(self):
        hdr = "spf=pass smtp.mailfrom=example.com"
        assert _parse_auth_result(hdr, "spf") == "pass"

    def test_spf_fail(self):
        hdr = "spf=fail (domain of example.com)"
        assert _parse_auth_result(hdr, "spf") == "fail"

    def test_spf_softfail(self):
        hdr = "spf=softfail (transitioning)"
        assert _parse_auth_result(hdr, "spf") == "softfail"

    def test_dkim_pass(self):
        assert _parse_auth_result("dkim=pass header.i=@example.com", "dkim") == "pass"

    def test_dkim_fail(self):
        assert _parse_auth_result("dkim=fail (bad signature)", "dkim") == "fail"

    def test_dkim_none(self):
        assert _parse_auth_result("dkim=none", "dkim") == "none"

    def test_dmarc_pass(self):
        assert _parse_auth_result("dmarc=pass", "dmarc") == "pass"

    def test_dmarc_fail(self):
        assert _parse_auth_result("dmarc=fail", "dmarc") == "fail"

    def test_protocol_absent_returns_none(self):
        assert _parse_auth_result("spf=pass dkim=pass", "dmarc") is None

    def test_strips_trailing_semicolon(self):
        assert _parse_auth_result("spf=fail;", "spf") == "fail"

    def test_strips_trailing_comma(self):
        assert _parse_auth_result("dkim=fail,", "dkim") == "fail"

    def test_case_insensitive_header(self):
        assert _parse_auth_result("SPF=FAIL", "spf") == "fail"

    def test_full_realistic_header_string(self):
        hdr = (
            "Authentication-Results: mx.google.com;"
            " dkim=pass header.i=@example.com header.s=sig1 header.b=abcd1234;"
            " spf=pass smtp.mailfrom=example.com;"
            " dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=example.com"
        )
        assert _parse_auth_result(hdr, "dkim") == "pass"
        assert _parse_auth_result(hdr, "spf") == "pass"
        assert _parse_auth_result(hdr, "dmarc") == "pass"


# ---------------------------------------------------------------------------
# analyze_headers — full pipeline
# ---------------------------------------------------------------------------

class TestAnalyzeHeadersSPFDKIMDMARC:
    def test_all_pass_no_auth_signals(self):
        signals, warnings = analyze_headers(
            "alice@example.com", None, AUTH_ALL_PASS
        )
        names = {s.name for s in signals}
        assert "SPF Fail" not in names
        assert "DKIM Fail" not in names
        assert "DMARC Fail" not in names

    def test_spf_fail_fires_with_15pts(self):
        signals, _ = analyze_headers(
            "alice@example.com", None, "spf=fail dkim=pass dmarc=pass"
        )
        spf = [s for s in signals if s.name == "SPF Fail"]
        assert len(spf) == 1
        assert spf[0].points == 15
        assert spf[0].category == "header"

    def test_spf_softfail_fires_signal(self):
        signals, _ = analyze_headers(
            "bob@example.com", None, "spf=softfail dkim=pass dmarc=pass"
        )
        assert any(s.name == "SPF Fail" for s in signals)

    def test_dkim_fail_fires_with_15pts(self):
        signals, _ = analyze_headers(
            "alice@example.com", None, "spf=pass dkim=fail dmarc=pass"
        )
        dkim = [s for s in signals if s.name == "DKIM Fail"]
        assert len(dkim) == 1
        assert dkim[0].points == 15

    def test_dkim_none_fires_signal(self):
        signals, _ = analyze_headers(
            "bob@example.com", None, "spf=pass dkim=none dmarc=pass"
        )
        assert any(s.name == "DKIM Fail" for s in signals)

    def test_dmarc_fail_fires_with_15pts(self):
        signals, _ = analyze_headers(
            "alice@example.com", None, "spf=pass dkim=pass dmarc=fail"
        )
        dmarc = [s for s in signals if s.name == "DMARC Fail"]
        assert len(dmarc) == 1
        assert dmarc[0].points == 15

    def test_all_three_fail_total_45pts(self):
        signals, _ = analyze_headers("alice@example.com", None, AUTH_ALL_FAIL)
        auth_pts = sum(
            s.points for s in signals
            if s.name in ("SPF Fail", "DKIM Fail", "DMARC Fail")
        )
        assert auth_pts == 45

    def test_missing_auth_header_adds_warning_no_crash(self):
        signals, warnings = analyze_headers("alice@example.com", None, None)
        assert any("Authentication-Results" in w for w in warnings)

    def test_missing_auth_header_no_false_positive_signals(self):
        signals, _ = analyze_headers("alice@example.com", None, None)
        names = {s.name for s in signals}
        assert "SPF Fail" not in names
        assert "DKIM Fail" not in names
        assert "DMARC Fail" not in names


class TestAnalyzeHeadersReplyTo:
    def test_reply_to_same_domain_no_signal(self):
        signals, _ = analyze_headers(
            "Alice <alice@example.com>",
            "alice@example.com",
            AUTH_ALL_PASS,
        )
        assert not any(s.name == "Reply-To Domain Mismatch" for s in signals)

    def test_reply_to_different_domain_fires_8pts(self):
        signals, _ = analyze_headers(
            "Alice <alice@example.com>",
            "attacker@evil.com",
            AUTH_ALL_PASS,
        )
        mismatch = [s for s in signals if s.name == "Reply-To Domain Mismatch"]
        assert len(mismatch) == 1
        assert mismatch[0].points == 8
        assert mismatch[0].category == "header"

    def test_no_reply_to_no_mismatch_signal(self):
        signals, _ = analyze_headers("alice@example.com", None, AUTH_ALL_PASS)
        assert not any(s.name == "Reply-To Domain Mismatch" for s in signals)

    def test_reply_to_subdomain_same_base_considered_different(self):
        # mail.example.com != example.com — strict domain comparison
        signals, _ = analyze_headers(
            "Alice <alice@example.com>",
            "alice@mail.example.com",
            AUTH_ALL_PASS,
        )
        # These ARE different domain strings → mismatch fires
        mismatch = [s for s in signals if s.name == "Reply-To Domain Mismatch"]
        assert len(mismatch) == 1


class TestAnalyzeHeadersDisplayNameSpoofing:
    def test_paypal_display_name_from_evil_domain_fires(self):
        signals, _ = analyze_headers(
            "PayPal Support <security@evil-domain.net>",
            None,
            AUTH_ALL_PASS,
        )
        spoof = [s for s in signals if s.name == "Display Name Spoofing"]
        assert len(spoof) == 1
        assert spoof[0].points == 10
        assert spoof[0].category == "header"

    def test_paypal_display_name_from_paypal_com_no_signal(self):
        signals, _ = analyze_headers(
            "PayPal <noreply@paypal.com>",
            None,
            AUTH_ALL_PASS,
        )
        assert not any(s.name == "Display Name Spoofing" for s in signals)

    def test_microsoft_spoofing_from_random_domain(self):
        signals, _ = analyze_headers(
            "Microsoft Account Team <no-reply@microsoftt-login.com>",
            None,
            AUTH_ALL_PASS,
        )
        spoof = [s for s in signals if s.name == "Display Name Spoofing"]
        assert len(spoof) == 1

    def test_no_brand_in_display_name_no_signal(self):
        signals, _ = analyze_headers(
            "John Smith <john@random-startup.io>",
            None,
            AUTH_ALL_PASS,
        )
        assert not any(s.name == "Display Name Spoofing" for s in signals)

    def test_brand_match_fires_only_once(self):
        # A contrived display name with two brand keywords — should still fire once
        signals, _ = analyze_headers(
            "PayPal Amazon <noreply@evil.com>",
            None,
            AUTH_ALL_PASS,
        )
        spoof = [s for s in signals if s.name == "Display Name Spoofing"]
        assert len(spoof) == 1


class TestAnalyzeHeadersLegitimateEmail:
    def test_fully_legitimate_email_produces_no_signals(self):
        signals, warnings = analyze_headers(
            "John Smith <john@legitimate-corp.com>",
            "john@legitimate-corp.com",
            AUTH_ALL_PASS,
        )
        assert signals == []

    def test_fully_legitimate_no_auth_warnings(self):
        _, warnings = analyze_headers(
            "John Smith <john@legitimate-corp.com>",
            "john@legitimate-corp.com",
            AUTH_ALL_PASS,
        )
        # No warnings should come from auth results since all three are present
        auth_warnings = [w for w in warnings if "SPF" in w or "DKIM" in w or "DMARC" in w]
        assert not auth_warnings
