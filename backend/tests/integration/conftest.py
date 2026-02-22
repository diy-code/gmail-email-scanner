"""
Fixtures for integration tests.

All external I/O (VirusTotal, Safe Browsing, AbuseIPDB, WHOIS, OpenAI) is
stubbed out here so the FastAPI app can start and respond without network access.

Fixtures
--------
disable_auth    : sets settings.api_key = "" so the API key check is bypassed.
stub_signal_engines : patches all 5 signal-engine functions + AI explainer with
                      safe, deterministic no-op return values.
client          : async httpx.AsyncClient wired to the FastAPI app; depends on
                  stub_signal_engines (applied automatically via autouse).
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from config import settings

# Import the app at module level so FastAPI builds its route table and resolves
# all Pydantic annotations ONCE, cleanly, before any test patches are applied.
# Patches in fixtures replace names in main's namespace at call-time — the app
# itself does not need to be re-imported per test.
from main import app as _app  # noqa: E402


# ---------------------------------------------------------------------------
# Disable API-key auth for all integration tests
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def disable_auth():
    """Patch the api_key setting to empty so auth is always bypassed."""
    original = settings.api_key
    settings.api_key = ""
    yield
    settings.api_key = original


# ---------------------------------------------------------------------------
# Stub every signal engine + AI explainer
# ---------------------------------------------------------------------------

@pytest.fixture
def stub_signal_engines():
    """
    Replaces all external-API-dependent functions in main.py's namespace with
    lightweight stubs that return empty/safe results instantly.

    Patched targets (by name in the main module):
        main.analyze_headers     → sync MagicMock → ([], [])
        main.analyze_urls        → AsyncMock      → []
        main.analyze_ip_reputation → AsyncMock    → ([], [])
        main.analyze_domain_age  → AsyncMock      → ([], [])
        main.analyze_behavior    → sync MagicMock → ([], [])
        main.generate_explanation → AsyncMock     → "Mocked AI explanation."
    """
    with (
        patch("main.analyze_headers",      MagicMock(return_value=([], []))),
        patch("main.analyze_urls",         AsyncMock(return_value=[])),
        patch("main.analyze_ip_reputation",AsyncMock(return_value=([], []))),
        patch("main.analyze_domain_age",   AsyncMock(return_value=([], []))),
        patch("main.analyze_behavior",     MagicMock(return_value=([], []))),
        patch("main.generate_explanation", AsyncMock(return_value="Mocked AI explanation.")),
    ):
        yield


@pytest.fixture
async def client(stub_signal_engines):
    """
    Async httpx client connected directly to the FastAPI ASGI app.
    Depends on stub_signal_engines so all external I/O is already mocked.
    The app was imported at module level; patches in stub_signal_engines replace
    the function names in main's namespace, which routes look up at call-time.
    """
    async with AsyncClient(
        transport=ASGITransport(app=_app),
        base_url="http://testserver",
    ) as ac:
        yield ac
