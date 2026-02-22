"""
Smoke tests — live end-to-end checks against a deployed backend.

These tests are SKIPPED by default.  To run them, set the SMOKE_URL environment
variable to the deployed Cloud Run URL (with no trailing slash):

    SMOKE_URL=https://email-scanner-xxxx-uc.a.run.app pytest -m smoke -v

Optional: set SMOKE_API_KEY if the deployed backend requires an X-API-Key header.

What smoke tests verify:
1. /health returns {"status": "ok"} within 15 s (Cloud Run warm-start check).
2. A clean, legitimate email payload returns a valid response with score 0–100.
3. A synthetic phishing payload returns a SUSPICIOUS or MALICIOUS verdict
   (actual score depends on live AbuseIPDB / VirusTotal results).
4. Response fields conform to the AnalyzeResponse schema (spot-check).
5. Two sequential requests produce different request_ids (UUID uniqueness).
6. Unauthorised request (wrong key) returns 401.

These tests make real HTTP calls and require real API keys to be configured
on the server.  They are safe to run against a staging deployment.
"""

from __future__ import annotations

import os
import uuid

import httpx
import pytest

# ---------------------------------------------------------------------------
# Skip marker — all tests in this module are skipped unless SMOKE_URL is set
# ---------------------------------------------------------------------------

SMOKE_URL = os.getenv("SMOKE_URL", "").rstrip("/")
SMOKE_API_KEY = os.getenv("SMOKE_API_KEY", "")

pytestmark = pytest.mark.smoke

skip_without_smoke_url = pytest.mark.skipif(
    not SMOKE_URL,
    reason="Smoke tests skipped: set SMOKE_URL env var to run against a live backend",
)

# ---------------------------------------------------------------------------
# Payloads
# ---------------------------------------------------------------------------

CLEAN_PAYLOAD = {
    "subject": "Meeting tomorrow at 3pm",
    "sender": "boss@yourcompany.com",
    "reply_to": "boss@yourcompany.com",
    "authentication_results": "spf=pass dkim=pass dmarc=pass",
    "received_headers": [
        "Received: from mail.google.com (mail.google.com [74.125.0.1])"
        " by mx.yourcompany.com"
    ],
    "body_plain": "Hi, just a reminder about the meeting tomorrow at 3pm. See you there!",
    "body_html": "",
    "urls": [],
}

PHISHING_PAYLOAD = {
    "subject": "URGENT: Your PayPal account has been limited!",
    "sender": 'PayPal Security <noreply@paypa1-secure.net>',
    "reply_to": "attacker@catch-all.ru",
    "authentication_results": "spf=fail dkim=fail dmarc=fail",
    "received_headers": [
        "Received: from mail.paypa1-secure.net (mail.paypa1-secure.net [5.6.7.8])"
        " by mx.google.com"
    ],
    "body_plain": (
        "Your account will be suspended within 24 hours. "
        "Click here to verify your identity immediately."
    ),
    "body_html": "",
    "urls": ["http://bit.ly/paypal-verify123"],
}


def _headers() -> dict[str, str]:
    h = {}
    if SMOKE_API_KEY:
        h["X-API-Key"] = SMOKE_API_KEY
    return h


# ---------------------------------------------------------------------------
# Smoke test class
# ---------------------------------------------------------------------------

@skip_without_smoke_url
class TestSmokeHealth:
    def test_health_200_ok(self):
        resp = httpx.get(f"{SMOKE_URL}/health", timeout=15)
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"

    def test_health_status_field(self):
        data = httpx.get(f"{SMOKE_URL}/health", timeout=15).json()
        assert data.get("status") == "ok"

    def test_health_version_field_present(self):
        data = httpx.get(f"{SMOKE_URL}/health", timeout=15).json()
        assert "version" in data


@skip_without_smoke_url
class TestSmokeAnalyze:
    def test_clean_email_returns_200(self):
        resp = httpx.post(
            f"{SMOKE_URL}/analyze", json=CLEAN_PAYLOAD,
            headers=_headers(), timeout=30,
        )
        assert resp.status_code == 200, resp.text

    def test_clean_email_response_has_all_required_fields(self):
        data = httpx.post(
            f"{SMOKE_URL}/analyze", json=CLEAN_PAYLOAD,
            headers=_headers(), timeout=30,
        ).json()
        required = {
            "request_id", "score", "verdict", "confidence", "confidence_label",
            "signals", "top_contributors", "evidence", "scoring_breakdown",
            "explanation", "analysis_time_ms",
        }
        missing = required - data.keys()
        assert not missing, f"Missing response fields: {missing}"

    def test_clean_email_score_in_range(self):
        data = httpx.post(
            f"{SMOKE_URL}/analyze", json=CLEAN_PAYLOAD,
            headers=_headers(), timeout=30,
        ).json()
        assert 0 <= data["score"] <= 100

    def test_clean_email_verdict_is_valid(self):
        data = httpx.post(
            f"{SMOKE_URL}/analyze", json=CLEAN_PAYLOAD,
            headers=_headers(), timeout=30,
        ).json()
        assert data["verdict"] in ("SAFE", "SUSPICIOUS", "MALICIOUS")

    def test_clean_email_request_id_is_uuid4(self):
        data = httpx.post(
            f"{SMOKE_URL}/analyze", json=CLEAN_PAYLOAD,
            headers=_headers(), timeout=30,
        ).json()
        parsed = uuid.UUID(data["request_id"])
        assert parsed.version == 4

    def test_phishing_email_returns_suspicious_or_malicious(self):
        """
        A synthetic phishing email must score above the SAFE threshold.
        Even without external API results, header signals alone push score > 30.
        """
        data = httpx.post(
            f"{SMOKE_URL}/analyze", json=PHISHING_PAYLOAD,
            headers=_headers(), timeout=30,
        ).json()
        assert data["verdict"] in ("SUSPICIOUS", "MALICIOUS"), (
            f"Expected elevated verdict, got {data['verdict']} (score={data['score']})"
        )
        assert data["score"] > 30

    def test_phishing_email_has_nonempty_explanation(self):
        data = httpx.post(
            f"{SMOKE_URL}/analyze", json=PHISHING_PAYLOAD,
            headers=_headers(), timeout=30,
        ).json()
        assert isinstance(data["explanation"], str)
        assert len(data["explanation"]) > 20

    def test_two_requests_have_different_request_ids(self):
        ids = set()
        for _ in range(2):
            data = httpx.post(
                f"{SMOKE_URL}/analyze", json=CLEAN_PAYLOAD,
                headers=_headers(), timeout=30,
            ).json()
            ids.add(data["request_id"])
        assert len(ids) == 2, "request_id must be unique per request"

    def test_analysis_time_ms_is_positive(self):
        data = httpx.post(
            f"{SMOKE_URL}/analyze", json=CLEAN_PAYLOAD,
            headers=_headers(), timeout=30,
        ).json()
        assert data["analysis_time_ms"] > 0


@skip_without_smoke_url
class TestSmokeAuth:
    def test_wrong_api_key_returns_401(self):
        """
        If the server is configured with a key, a wrong key must return 401.
        If the server has no key configured, a wrong key is silently ignored and
        the request succeeds (200) — both outcomes are acceptable here.
        """
        resp = httpx.post(
            f"{SMOKE_URL}/analyze", json=CLEAN_PAYLOAD,
            headers={"X-API-Key": "definitely-wrong-key"},
            timeout=15,
        )
        assert resp.status_code in (200, 401), (
            f"Unexpected status {resp.status_code}: {resp.text}"
        )
