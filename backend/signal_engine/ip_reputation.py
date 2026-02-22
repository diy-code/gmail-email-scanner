# Phase 2 — IP reputation signal engine
# Extracts the sender IP from the Received header chain and queries AbuseIPDB.
#
# Reliability rules (PLAN.md Phase 2.5 + Assumption A6):
# - Uses the FIRST external (non-private) IP in the Received chain,
#   not the last (which may be an internal Google relay).
# - Private/reserved ranges are silently skipped.
# - Missing or unparseable IP → no signal, parse warning logged.

from __future__ import annotations

import ipaddress
import logging
import re
from typing import Optional

import httpx

from config import settings
from models import Signal

logger = logging.getLogger(__name__)

ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"

# ---------------------------------------------------------------------------
# Private/reserved IP ranges to ignore (Assumption A6)
# ---------------------------------------------------------------------------
PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


def _is_private(ip_str: str) -> bool:
    """Returns True if the IP is in a private/reserved range."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in PRIVATE_NETWORKS)
    except ValueError:
        return True  # Treat unparseable IPs as private (safe default)


def _extract_external_ip(received_headers: list[str]) -> Optional[str]:
    """
    Scans the Received header chain (outermost to innermost) and returns
    the first IP address that is not in a private/reserved range.

    Received headers are ordered outermost-first in the request payload
    (earliest external hop = index 0, as sent by App Script raw header parser).

    Returns None if no valid external IP is found.
    """
    ip_pattern = re.compile(r"\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]")

    for header in received_headers:
        matches = ip_pattern.findall(header)
        for ip in matches:
            if not _is_private(ip):
                logger.debug("Extracted external sender IP: %s", ip)
                return ip

    logger.debug("No external IP found in %d Received headers", len(received_headers))
    return None


async def analyze_ip_reputation(
    received_headers: list[str],
    availability_flags: dict[str, bool],
) -> tuple[list[Signal], list[str]]:
    """
    Checks the sender IP reputation using AbuseIPDB.

    Scoring (additive — Assumption A4):
        confidence > 25%  → +12 pts
        confidence > 75%  → additional +8 pts (total 20)

    Args:
        received_headers: All Received headers from the email, outermost first.
        availability_flags: Mutable dict; sets 'abuseipdb' to False if unavailable.

    Returns:
        (signals, parse_warnings)
    """
    signals: list[Signal] = []
    parse_warnings: list[str] = []

    if not received_headers:
        parse_warnings.append("No Received headers provided — IP reputation check skipped")
        return signals, parse_warnings

    sender_ip = _extract_external_ip(received_headers)

    if not sender_ip:
        parse_warnings.append("Could not extract external IP from Received headers")
        return signals, parse_warnings

    if not settings.abuseipdb_api_key:
        logger.debug("AbuseIPDB API key not configured — skipping")
        availability_flags["abuseipdb"] = False
        return signals, parse_warnings

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                ABUSEIPDB_CHECK_URL,
                headers={
                    "Key": settings.abuseipdb_api_key,
                    "Accept": "application/json",
                },
                params={"ipAddress": sender_ip, "maxAgeInDays": "90"},
                timeout=settings.signal_timeout_seconds,
            )
    except httpx.TimeoutException:
        logger.warning("AbuseIPDB timeout for ip=%s", sender_ip)
        availability_flags["abuseipdb"] = False
        return signals, parse_warnings

    if resp.status_code == 429:
        logger.warning("AbuseIPDB rate limited (429)")
        availability_flags["abuseipdb"] = False
        return signals, parse_warnings

    if resp.status_code != 200:
        logger.warning("AbuseIPDB unexpected status=%d", resp.status_code)
        availability_flags["abuseipdb"] = False
        return signals, parse_warnings

    try:
        data = resp.json()
        confidence = int(data["data"]["abuseConfidenceScore"])
    except (KeyError, ValueError, TypeError) as exc:
        logger.warning("AbuseIPDB response parse error: %s", exc)
        parse_warnings.append(f"AbuseIPDB response parse error: {exc}")
        return signals, parse_warnings

    logger.info("AbuseIPDB result: ip=%s confidence=%d%%", sender_ip, confidence)

    if confidence > 25:
        signals.append(Signal(
            name="AbuseIPDB: Sender IP Reported for Abuse",
            category="ip",
            severity="high",
            description=(
                f"The sending IP address ({sender_ip}) has an AbuseIPDB confidence "
                f"score of {confidence}%, indicating it has been reported for malicious activity."
            ),
            value=f"{sender_ip} — confidence={confidence}%",
            points=12,
        ))

    if confidence > 75:
        # Additive bonus for high-confidence abusive IPs (Assumption A4)
        signals.append(Signal(
            name="AbuseIPDB: High-Confidence Abusive IP",
            category="ip",
            severity="critical",
            description=(
                f"The sending IP ({sender_ip}) has an extremely high AbuseIPDB confidence "
                f"score of {confidence}%, strongly indicating a known malicious sender."
            ),
            value=f"{sender_ip} — confidence={confidence}%",
            points=8,
        ))

    return signals, parse_warnings
