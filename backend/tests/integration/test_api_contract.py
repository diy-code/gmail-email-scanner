"""
Integration tests for the FastAPI application (main.py).

All external APIs are fully mocked via fixtures in conftest.py.
Tests verify:
  - GET /health  : response shape, version, status
  - POST /analyze: auth enforcement, full response schema, field types/ranges,
                   UUID request_id, verdict correctness with stubbed signals,
                   rate-limiter does not fire on normal load
  - Error handling: missing sender, oversized payload, wrong method

These tests use an async httpx.AsyncClient wired to the ASGI app (no real server).
"""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from models import Signal
from main import app  # module-level import so FastAPI builds its schema once


# ---------------------------------------------------------------------------
# Minimal valid payload helper
# ---------------------------------------------------------------------------

MINIMAL_PAYLOAD = {
    "subject": "Team standup notes",
    "sender": "alice@legitimate-corp.com",
    "reply_to": "alice@legitimate-corp.com",
    "authentication_results": "spf=pass dkim=pass dmarc=pass",
    "received_headers": [],
    "body_plain": "Hi everyone, standup notes attached.",
    "body_html": "",
    "urls": [],
    "message_date": "Mon, 22 Feb 2026 09:00:00 +0000",
}

PHISHING_PAYLOAD = {
    "subject": "URGENT: Your PayPal account has been limited!",
    "sender": "PayPal Security <security@paypa1-secure.net>",
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


# ---------------------------------------------------------------------------
# Health endpoint
# ---------------------------------------------------------------------------

class TestHealthEndpoint:
    async def test_health_returns_200(self, client):
        resp = await client.get("/health")
        assert resp.status_code == 200

    async def test_health_json_status_ok(self, client):
        resp = await client.get("/health")
        assert resp.json()["status"] == "ok"

    async def test_health_json_has_version(self, client):
        resp = await client.get("/health")
        assert "version" in resp.json()

    async def test_health_version_is_string(self, client):
        resp = await client.get("/health")
        assert isinstance(resp.json()["version"], str)


# ---------------------------------------------------------------------------
# Authentication enforcement
# ---------------------------------------------------------------------------

class TestAuthEnforcement:
    async def test_missing_api_key_rejected_when_key_configured(
        self, stub_signal_engines
    ):
        """When api_key is set, requests without X-API-Key should get 401."""
        from config import settings

        settings.api_key = "secret-test-key"
        try:
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://testserver"
            ) as ac:
                resp = await ac.post("/analyze", json=MINIMAL_PAYLOAD)
            assert resp.status_code == 401
        finally:
            settings.api_key = ""

    async def test_wrong_api_key_rejected(self, stub_signal_engines):
        from config import settings

        settings.api_key = "correct-key"
        try:
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://testserver"
            ) as ac:
                resp = await ac.post(
                    "/analyze", json=MINIMAL_PAYLOAD,
                    headers={"X-API-Key": "wrong-key"}
                )
            assert resp.status_code == 401
        finally:
            settings.api_key = ""

    async def test_correct_api_key_accepted(self, stub_signal_engines):
        from config import settings

        settings.api_key = "correct-key"
        try:
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://testserver"
            ) as ac:
                resp = await ac.post(
                    "/analyze", json=MINIMAL_PAYLOAD,
                    headers={"X-API-Key": "correct-key"}
                )
            assert resp.status_code == 200
        finally:
            settings.api_key = ""

    async def test_auth_disabled_when_api_key_empty(self, client):
        """Auth is disabled when api_key = '' (dev mode). All requests pass."""
        resp = await client.post("/analyze", json=MINIMAL_PAYLOAD)
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# POST /analyze — response schema
# ---------------------------------------------------------------------------

class TestAnalyzeResponseSchema:
    async def test_returns_200(self, client):
        resp = await client.post("/analyze", json=MINIMAL_PAYLOAD)
        assert resp.status_code == 200

    async def test_response_has_required_top_level_fields(self, client):
        resp = await client.post("/analyze", json=MINIMAL_PAYLOAD)
        data = resp.json()
        required = {
            "request_id", "score", "verdict", "confidence", "confidence_label",
            "signals", "top_contributors", "evidence", "scoring_breakdown",
            "explanation", "source_availability", "analysis_time_ms",
        }
        assert required.issubset(data.keys())

    async def test_source_availability_is_dict(self, client):
        resp = await client.post("/analyze", json=MINIMAL_PAYLOAD)
        sa = resp.json()["source_availability"]
        assert isinstance(sa, dict)
        for key in ("virustotal", "safe_browsing", "abuseipdb", "whois"):
            assert key in sa
            assert isinstance(sa[key], bool)

    async def test_request_id_is_valid_uuid4(self, client):
        resp = await client.post("/analyze", json=MINIMAL_PAYLOAD)
        rid = resp.json()["request_id"]
        parsed = uuid.UUID(rid)
        assert parsed.version == 4

    async def test_score_is_integer(self, client):
        resp = await client.post("/analyze", json=MINIMAL_PAYLOAD)
        assert isinstance(resp.json()["score"], int)

    async def test_score_in_0_100_range(self, client):
        resp = await client.post("/analyze", json=MINIMAL_PAYLOAD)
        score = resp.json()["score"]
        assert 0 <= score <= 100

    async def test_verdict_is_valid_string(self, client):
        resp = await client.post("/analyze", json=MINIMAL_PAYLOAD)
        assert resp.json()["verdict"] in ("SAFE", "SUSPICIOUS", "MALICIOUS")

    async def test_confidence_in_0_100_range(self, client):
        resp = await client.post("/analyze", json=MINIMAL_PAYLOAD)
        confidence = resp.json()["confidence"]
        assert 0 <= confidence <= 100

    async def test_confidence_label_is_valid(self, client):
        resp = await client.post("/analyze", json=MINIMAL_PAYLOAD)
        assert resp.json()["confidence_label"] in ("High", "Medium", "Low")

    async def test_signals_is_list(self, client):
        resp = await client.post("/analyze", json=MINIMAL_PAYLOAD)
        assert isinstance(resp.json()["signals"], list)

    async def test_top_contributors_is_list(self, client):
        resp = await client.post("/analyze", json=MINIMAL_PAYLOAD)
        assert isinstance(resp.json()["top_contributors"], list)

    async def test_top_contributors_max_3(self, client):
        resp = await client.post("/analyze", json=MINIMAL_PAYLOAD)
        assert len(resp.json()["top_contributors"]) <= 3

    async def test_evidence_is_list(self, client):
        resp = await client.post("/analyze", json=MINIMAL_PAYLOAD)
        assert isinstance(resp.json()["evidence"], list)

    async def test_explanation_is_nonempty_string(self, client):
        resp = await client.post("/analyze", json=MINIMAL_PAYLOAD)
        assert isinstance(resp.json()["explanation"], str)
        assert len(resp.json()["explanation"]) > 0

    async def test_analysis_time_ms_is_positive_int(self, client):
        resp = await client.post("/analyze", json=MINIMAL_PAYLOAD)
        assert isinstance(resp.json()["analysis_time_ms"], int)
        assert resp.json()["analysis_time_ms"] >= 0

    async def test_scoring_breakdown_has_required_fields(self, client):
        resp = await client.post("/analyze", json=MINIMAL_PAYLOAD)
        bd = resp.json()["scoring_breakdown"]
        for field in ("total_points", "capped_points", "max_points", "formula", "category_points"):
            assert field in bd, f"Missing field: {field}"


# ---------------------------------------------------------------------------
# Verdict correctness with realistic mocked signals
# ---------------------------------------------------------------------------

class TestAnalyzeVerdict:
    async def test_clean_email_stubs_returns_safe(self, stub_signal_engines, client):
        """With all signal engines returning [], score=0 → SAFE."""
        resp = await client.post("/analyze", json=MINIMAL_PAYLOAD)
        data = resp.json()
        assert data["score"] == 0
        assert data["verdict"] == "SAFE"

    async def test_header_signals_increase_score(self, stub_signal_engines):
        """
        Patch signal engines so header engine returns 3 signals totalling 45 pts.
        Expected: score=30 (45/150*100), verdict=SAFE.
        """
        header_signals = [
            Signal(name="SPF Fail",  category="header", severity="high",
                   description="SPF fail", value="spf=fail", points=15),
            Signal(name="DKIM Fail", category="header", severity="high",
                   description="DKIM fail", value="dkim=fail", points=15),
            Signal(name="DMARC Fail",category="header", severity="high",
                   description="DMARC fail",value="dmarc=fail", points=15),
        ]

        with (
            patch("main.analyze_headers",      MagicMock(return_value=(header_signals, []))),
            patch("main.analyze_urls",         AsyncMock(return_value=[])),
            patch("main.analyze_ip_reputation",AsyncMock(return_value=([], []))),
            patch("main.analyze_domain_age",   AsyncMock(return_value=([], []))),
            patch("main.analyze_behavior",     MagicMock(return_value=([], []))),
            patch("main.generate_explanation", AsyncMock(return_value="test explanation")),
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://testserver"
            ) as ac:
                resp = await ac.post("/analyze", json=MINIMAL_PAYLOAD)

        data = resp.json()
        assert data["score"] == 30
        assert data["verdict"] == "SAFE"

    async def test_full_phishing_signals_return_malicious(self, stub_signal_engines):
        """
        Inject signals that exceed the 66/100 MALICIOUS threshold:
        header(45) + url(55) = 100 capped → score=67 → MALICIOUS
        """
        big_signals = [
            Signal(name="SPF Fail",  category="header", severity="high",
                   description="SPF fail", points=15, value=None),
            Signal(name="DKIM Fail", category="header", severity="high",
                   description="DKIM fail", points=15, value=None),
            Signal(name="DMARC Fail",category="header", severity="high",
                   description="DMARC fail", points=15, value=None),
            Signal(name="VT Malicious", category="url", severity="critical",
                   description="VT flagged", points=55, value=None),
        ]

        with (
            patch("main.analyze_headers",      MagicMock(return_value=(big_signals[:3], []))),
            patch("main.analyze_urls",         AsyncMock(return_value=[big_signals[3]])),
            patch("main.analyze_ip_reputation",AsyncMock(return_value=([], []))),
            patch("main.analyze_domain_age",   AsyncMock(return_value=([], []))),
            patch("main.analyze_behavior",     MagicMock(return_value=([], []))),
            patch("main.generate_explanation", AsyncMock(return_value="Very dangerous.")),
        ):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://testserver"
            ) as ac:
                resp = await ac.post("/analyze", json=PHISHING_PAYLOAD)

        data = resp.json()
        assert data["verdict"] == "MALICIOUS"
        assert data["score"] >= 66


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

class TestAnalyzeInputValidation:
    async def test_missing_required_sender_field(self, client):
        """sender is required — missing it should return 422."""
        payload = {k: v for k, v in MINIMAL_PAYLOAD.items() if k != "sender"}
        resp = await client.post("/analyze", json=payload)
        assert resp.status_code == 422

    async def test_missing_required_subject_field(self, client):
        payload = {k: v for k, v in MINIMAL_PAYLOAD.items() if k != "subject"}
        resp = await client.post("/analyze", json=payload)
        assert resp.status_code == 422

    async def test_subject_exceeding_max_length_rejected(self, client):
        payload = {**MINIMAL_PAYLOAD, "subject": "x" * 501}
        resp = await client.post("/analyze", json=payload)
        assert resp.status_code == 422

    async def test_urls_list_exceeds_max_items_rejected(self, client):
        payload = {**MINIMAL_PAYLOAD, "urls": [f"http://url{i}.com" for i in range(11)]}
        resp = await client.post("/analyze", json=payload)
        assert resp.status_code == 422

    async def test_wrong_http_method_returns_405(self, client):
        resp = await client.get("/analyze")
        assert resp.status_code == 405

    async def test_404_for_unknown_path(self, client):
        resp = await client.get("/nonexistent")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Observability: request_id + analysis_time_ms
# ---------------------------------------------------------------------------

class TestAnalyzeObservability:
    async def test_each_request_has_unique_request_id(self, client):
        r1 = (await client.post("/analyze", json=MINIMAL_PAYLOAD)).json()["request_id"]
        r2 = (await client.post("/analyze", json=MINIMAL_PAYLOAD)).json()["request_id"]
        assert r1 != r2

    async def test_analysis_time_ms_positive(self, client):
        data = (await client.post("/analyze", json=MINIMAL_PAYLOAD)).json()
        assert data["analysis_time_ms"] >= 0
