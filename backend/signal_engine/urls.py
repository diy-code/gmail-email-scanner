# Phase 2 — URL scanning signal engine
# Checks URLs extracted from the email body against:
#   1. VirusTotal (cached GET lookup — Assumption A1)
#   2. Google Safe Browsing (batch threat match)
#   3. URL shortener regex detection
#   4. Typosquatting via Levenshtein distance (rapidfuzz — Decision D5)
#
# All external calls use the per-signal timeout budget from config.
# On 429 / timeout / missing API key → signal is skipped, confidence is reduced.
# Returns list[Signal].

from __future__ import annotations

import base64
import logging
import re
from typing import Optional
from urllib.parse import urlparse

import httpx
from rapidfuzz.distance import Levenshtein

from config import settings
from models import Signal

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

URL_SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "goo.gl", "buff.ly",
    "ift.tt", "is.gd", "rebrand.ly", "short.io", "shorte.st", "cli.gs",
    "x.co", "po.st", "tiny.cc", "lnkd.in", "fb.me",
}

BRAND_DOMAINS_FOR_TYPOSQUAT = [
    "paypal.com", "amazon.com", "microsoft.com", "google.com", "apple.com",
    "netflix.com", "linkedin.com", "facebook.com", "instagram.com", "twitter.com",
    "x.com", "wellsfargo.com", "chase.com", "bankofamerica.com", "dropbox.com",
    "docusign.com", "icloud.com", "outlook.com", "gmail.com", "yahoo.com",
    "ebay.com", "walmart.com", "target.com", "bestbuy.com", "steam.com",
]

VIRUSTOTAL_URL_BASE = "https://www.virustotal.com/api/v3/urls"
SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


# ---------------------------------------------------------------------------
# Tiered severity for engine-count-based scoring
# ---------------------------------------------------------------------------

def _vt_tiered_severity(malicious_count: int) -> tuple[str, int]:
    """
    Returns (severity, points) scaled by the number of VirusTotal engines
    that flagged the URL/domain as malicious.

    Rationale: 1-2 engines flagging is a weak signal (possible false positive),
    3-9 is moderate consensus, >= 10 is strong consensus.
    """
    if malicious_count >= 10:
        return "critical", 20
    elif malicious_count >= 3:
        return "high", 12
    else:
        return "medium", 5


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_domain(url: str) -> Optional[str]:
    """Returns the lowercase hostname from a URL, or None on parse error."""
    try:
        parsed = urlparse(url)
        host = parsed.hostname
        return host.lower() if host else None
    except Exception:
        return None


def _vt_url_id(url: str) -> str:
    """Encodes a URL to the base64url format VirusTotal uses as its URL identifier."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def _is_typosquat(domain: str) -> Optional[str]:
    """
    Returns the brand domain being typosquatted if the input domain is within
    Levenshtein distance ≤ 2 of any known brand domain, otherwise None.
    Compares only the registrable part (e.g. 'paypa1.com' vs 'paypal.com').
    """
    for brand in BRAND_DOMAINS_FOR_TYPOSQUAT:
        distance = Levenshtein.distance(domain, brand)
        if 0 < distance <= 2:
            return brand
    return None


def _deduplicate_domains(urls: list[str]) -> list[str]:
    """Returns unique domains from a list of URLs, capped at virustotal_max_domains."""
    seen: dict[str, str] = {}
    for url in urls:
        domain = _extract_domain(url)
        if domain and domain not in seen:
            seen[domain] = url
    capped = dict(list(seen.items())[: settings.virustotal_max_domains])
    return list(capped.values())


# ---------------------------------------------------------------------------
# VirusTotal
# ---------------------------------------------------------------------------

async def _check_virustotal(url: str, client: httpx.AsyncClient) -> Optional[Signal]:
    """
    Queries VirusTotal for a cached URL verdict.
    Uses GET /api/v3/urls/{id} (cached lookup — Assumption A1).

    Returns a Signal if the URL is flagged malicious, None otherwise.
    Returns None silently on 404 (no cached data), 429 (rate limited), or timeout.
    """
    if not settings.virustotal_api_key:
        logger.debug("VirusTotal API key not configured — skipping")
        return None

    url_id = _vt_url_id(url)
    headers = {"x-apikey": settings.virustotal_api_key}

    try:
        resp = await client.get(
            f"{VIRUSTOTAL_URL_BASE}/{url_id}",
            headers=headers,
            timeout=settings.signal_timeout_seconds,
        )
    except httpx.TimeoutException:
        logger.warning("VirusTotal timeout for url=%s", url)
        return None

    if resp.status_code == 429:
        logger.warning("VirusTotal rate limited (429)")
        return None
    if resp.status_code == 404:
        logger.debug("VirusTotal: no cached data for url=%s", url)
        return None
    if resp.status_code != 200:
        logger.warning("VirusTotal unexpected status=%d", resp.status_code)
        return None

    try:
        data = resp.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        malicious_count = stats.get("malicious", 0)
        total = sum(stats.values())

        if malicious_count > 0:
            severity, points = _vt_tiered_severity(malicious_count)
            return Signal(
                name="VirusTotal: URL Flagged Malicious",
                category="url",
                severity=severity,
                description=(
                    f"{malicious_count} out of {total} security engines flagged this URL as malicious."
                ),
                value=f"{malicious_count}/{total} engines",
                points=points,
            )
    except (KeyError, ValueError) as exc:
        logger.warning("VirusTotal response parse error: %s", exc)

    return None


# ---------------------------------------------------------------------------
# Google Safe Browsing
# ---------------------------------------------------------------------------

async def _check_safe_browsing(urls: list[str], client: httpx.AsyncClient) -> list[Signal]:
    """
    Batch-checks all URLs against Google Safe Browsing v4 threat matches.

    Returns a list of Signals (one per flagged URL).
    Returns empty list on missing API key, timeout, or API error.

    Note: Safe Browsing returns an empty JSON object {} — NOT a 404 — when
    no threats are found (Things to Watch Out For in IMPLEMENTATION_NOTES.md).
    """
    if not settings.safe_browsing_api_key:
        logger.debug("Safe Browsing API key not configured — skipping")
        return []

    payload = {
        "client": {"clientId": "email-security-scanner", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in urls],
        },
    }

    try:
        resp = await client.post(
            SAFE_BROWSING_URL,
            params={"key": settings.safe_browsing_api_key},
            json=payload,
            timeout=settings.signal_timeout_seconds,
        )
    except httpx.TimeoutException:
        logger.warning("Safe Browsing timeout")
        return []

    if resp.status_code != 200:
        logger.warning("Safe Browsing unexpected status=%d", resp.status_code)
        return []

    try:
        data = resp.json()
        matches = data.get("matches", [])  # empty dict {} when clean
    except ValueError:
        logger.warning("Safe Browsing response JSON parse error")
        return []

    signals: list[Signal] = []
    flagged_urls: set[str] = set()
    for match in matches:
        flagged_url = match.get("threat", {}).get("url", "")
        if flagged_url and flagged_url not in flagged_urls:
            flagged_urls.add(flagged_url)
            threat_type = match.get("threatType", "UNKNOWN")
            signals.append(Signal(
                name="Safe Browsing: URL Flagged",
                category="url",
                severity="critical",
                description=f"Google Safe Browsing flagged this URL as {threat_type.replace('_', ' ').lower()}.",
                value=f"{flagged_url} ({threat_type})",
                points=20,
            ))

    return signals


# ---------------------------------------------------------------------------
# URL shortener
# ---------------------------------------------------------------------------

def _check_url_shorteners(urls: list[str]) -> list[Signal]:
    """Detects URLs served through known shortener domains."""
    signals: list[Signal] = []
    for url in urls:
        domain = _extract_domain(url)
        if domain in URL_SHORTENER_DOMAINS:
            signals.append(Signal(
                name="URL Shortener Detected",
                category="url",
                severity="low",
                description=(
                    f"The URL uses the shortener service '{domain}', "
                    "which obscures the final destination."
                ),
                value=url,
                points=5,
            ))
            break  # one signal per email is enough for this category
    return signals


# ---------------------------------------------------------------------------
# Typosquatting
# ---------------------------------------------------------------------------

def _check_typosquatting(urls: list[str]) -> list[Signal]:
    """
    Detects domains that are within Levenshtein distance ≤ 2 of a known brand domain.
    Uses rapidfuzz for fast string distance computation (Decision D5).
    """
    signals: list[Signal] = []
    seen_domains: set[str] = set()

    for url in urls:
        domain = _extract_domain(url)
        if not domain or domain in seen_domains:
            continue
        seen_domains.add(domain)

        brand = _is_typosquat(domain)
        if brand:
            signals.append(Signal(
                name="Typosquatted Domain",
                category="url",
                severity="high",
                description=(
                    f"The domain '{domain}' closely resembles the brand domain '{brand}'. "
                    "This is a common phishing technique."
                ),
                value=f"{domain} ≈ {brand}",
                points=10,
            ))

    return signals


# ---------------------------------------------------------------------------
# Main analysis function
# ---------------------------------------------------------------------------

async def analyze_urls(
    urls: list[str],
    availability_flags: dict[str, bool],
) -> list[Signal]:
    """
    Runs all URL-based signal checks.

    Args:
        urls: Pre-extracted, de-duplicated URLs from the email body (max 10).
        availability_flags: Mutable dict; this function sets
            'virustotal' and 'safe_browsing' to False if those APIs were unavailable.

    Returns:
        list of Signal objects for every check that fired.
    """
    if not urls:
        return []

    # Enforce server-side URL cap
    urls = urls[: settings.max_urls_per_request]

    signals: list[Signal] = []

    # Synchronous checks (no I/O) — run immediately
    signals.extend(_check_url_shorteners(urls))
    signals.extend(_check_typosquatting(urls))

    # Async API calls
    domains_to_scan = _deduplicate_domains(urls)

    async with httpx.AsyncClient() as client:
        # VirusTotal: one request per domain (capped at virustotal_max_domains)
        vt_available = bool(settings.virustotal_api_key)
        vt_hit = False
        for url in domains_to_scan:
            signal = await _check_virustotal(url, client)
            if signal:
                signals.append(signal)
                vt_hit = True
        if not vt_available:
            availability_flags["virustotal"] = False

        # Safe Browsing: single batched request
        sb_signals = await _check_safe_browsing(urls, client)
        signals.extend(sb_signals)
        if not settings.safe_browsing_api_key:
            availability_flags["safe_browsing"] = False

    return signals
