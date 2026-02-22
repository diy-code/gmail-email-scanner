"""
Shared pytest fixtures for the Gmail Email Scanner test suite.

Fixtures defined here are available to all test sub-packages (unit, integration, smoke).

Key fixtures
------------
make_signal     : factory function for building Signal objects in tests
clean_request   : minimal AnalyzeRequest that should score 0 (all headers pass, no URLs)
phishing_request: AnalyzeRequest crafted to trigger every signal category
"""

from __future__ import annotations

import pytest

from models import AnalyzeRequest, Signal


# ---------------------------------------------------------------------------
# Signal factory
# ---------------------------------------------------------------------------

@pytest.fixture
def make_signal():
    """
    Returns a factory callable: make_signal(category, points, name="Test Signal").

    Usage::
        def test_foo(make_signal):
            sig = make_signal("header", 15, "SPF Fail")
    """
    def _factory(category: str, points: int, name: str = "Test Signal") -> Signal:
        return Signal(
            name=name,
            category=category,
            severity="medium",
            description=f"Test signal in category {category}",
            value=None,
            points=points,
        )
    return _factory


# ---------------------------------------------------------------------------
# Canonical request payloads
# ---------------------------------------------------------------------------

@pytest.fixture
def clean_request() -> AnalyzeRequest:
    """
    A minimal, well-formed email that should produce score=0 / SAFE:
    - All auth headers pass
    - Matching reply-to and from
    - No brand impersonation
    - No suspicious body content
    - No URLs
    - No received headers (IP check skipped)
    """
    return AnalyzeRequest(
        subject="Team standup notes",
        sender="alice@legitimate-corp.com",
        reply_to="alice@legitimate-corp.com",
        authentication_results="spf=pass dkim=pass dmarc=pass",
        received_headers=[],
        body_plain="Hi everyone, find the standup notes below. See you tomorrow.",
        body_html="",
        urls=[],
        message_date="Mon, 22 Feb 2026 09:00:00 +0000",
    )


@pytest.fixture
def phishing_request() -> AnalyzeRequest:
    """
    A synthetic phishing email that should fire signals in every category:
    - SPF, DKIM, DMARC all fail (header)
    - Reply-To != From domain (header)
    - Display name spoofing — PayPal (header)
    - Urgency language (behavior)
    - External IP in Received header (ip — signals depend on live AbuseIPDB)
    - URL shortener (url)
    - Domain registered recently is mocked separately where needed
    """
    return AnalyzeRequest(
        subject="URGENT: Your PayPal account has been limited!",
        sender='PayPal Security <security@paypa1-secure.net>',
        reply_to="attacker@catch-all.ru",
        authentication_results="spf=fail dkim=fail dmarc=fail",
        received_headers=[
            "Received: from mail.paypa1-secure.net (mail.paypa1-secure.net [5.6.7.8])"
            " by mx.google.com with ESMTP"
        ],
        body_plain=(
            "Your account will be suspended within 24 hours. "
            "Click here to verify your identity immediately."
        ),
        body_html="",
        urls=["http://bit.ly/paypal-verify123"],
        message_date="Mon, 22 Feb 2026 03:00:00 +0000",
    )
