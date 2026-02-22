# Phase 2 — Domain age signal engine
# Looks up the sender domain's registration date via WHOIS and flags recently
# registered domains (high indicator of phishing infrastructure).
#
# Key implementation notes:
# - python-whois is synchronous; wrapped in run_in_executor (Assumption A2).
# - Per-request domain cache passed in to avoid duplicate lookups (Decision D3).
# - Signals are mutually exclusive: only the higher-scoring threshold fires (Assumption A3).
#   < 7 days  = 20 pts
#   < 30 days = 12 pts (only if domain is NOT < 7 days)

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional

import whois

from config import settings
from models import Signal

logger = logging.getLogger(__name__)


def _extract_domain(sender: str) -> Optional[str]:
    """
    Extracts the domain from a From header value.
    Handles 'Display Name <user@domain.com>' and bare 'user@domain.com'.
    """
    import re
    match = re.search(r"@([\w.-]+\.\w+)", sender)
    if match:
        return match.group(1).lower().strip()
    return None


def _get_creation_date(w: whois.WhoisEntry) -> Optional[datetime]:
    """
    Normalises the creation_date field from python-whois, which can be:
    - a single datetime object
    - a list of datetime objects (some registrars return multiple)
    - None

    Returns the earliest date as a timezone-aware datetime, or None.
    """
    raw = w.creation_date
    if raw is None:
        return None

    dates: list[datetime] = raw if isinstance(raw, list) else [raw]

    valid: list[datetime] = []
    for d in dates:
        if isinstance(d, datetime):
            if d.tzinfo is None:
                d = d.replace(tzinfo=timezone.utc)
            valid.append(d)

    return min(valid) if valid else None


def _whois_lookup(domain: str) -> Optional[datetime]:
    """Blocking WHOIS lookup — must be called via run_in_executor."""
    try:
        w = whois.whois(domain)
        return _get_creation_date(w)
    except Exception as exc:
        logger.warning("WHOIS lookup failed for domain=%s: %s", domain, exc)
        return None


async def analyze_domain_age(
    sender: str,
    domain_cache: dict[str, Optional[datetime]],
    availability_flags: dict[str, bool],
) -> tuple[list[Signal], list[str]]:
    """
    Checks the sender domain's registration age.

    Args:
        sender: Raw From header value.
        domain_cache: Per-request dict mapping domain → creation_date (Decision D3).
            Pre-populated by caller; populated by this function if domain is new.
        availability_flags: Mutable dict; sets 'whois' to False if lookup fails.

    Returns:
        (signals, parse_warnings)
    """
    signals: list[Signal] = []
    parse_warnings: list[str] = []

    domain = _extract_domain(sender)
    if not domain:
        parse_warnings.append(f"Could not extract sender domain for WHOIS lookup: {sender!r}")
        return signals, parse_warnings

    # ---- Cache lookup (Decision D3) ----
    if domain in domain_cache:
        creation_date = domain_cache[domain]
        logger.debug("Domain cache hit for %s", domain)
    else:
        # Wrap blocking call in executor (Assumption A2)
        loop = asyncio.get_event_loop()
        try:
            creation_date = await asyncio.wait_for(
                loop.run_in_executor(None, _whois_lookup, domain),
                timeout=settings.signal_timeout_seconds,
            )
        except asyncio.TimeoutError:
            logger.warning("WHOIS timeout for domain=%s", domain)
            availability_flags["whois"] = False
            parse_warnings.append(f"WHOIS timeout for {domain}")
            return signals, parse_warnings

        domain_cache[domain] = creation_date

    if creation_date is None:
        logger.debug("WHOIS returned no creation date for %s", domain)
        parse_warnings.append(f"WHOIS: creation date unavailable for {domain}")
        availability_flags["whois"] = False
        return signals, parse_warnings

    now = datetime.now(tz=timezone.utc)
    domain_age_days = (now - creation_date).days
    logger.info("Domain %s age: %d days (created %s)", domain, domain_age_days, creation_date.date())

    # Mutually exclusive thresholds — Assumption A3
    if domain_age_days < 7:
        signals.append(Signal(
            name="Very New Domain (< 7 days)",
            category="domain",
            severity="critical",
            description=(
                f"The sending domain '{domain}' was registered only {domain_age_days} "
                "day(s) ago. Domains registered this recently are a strong indicator "
                "of purpose-built phishing infrastructure."
            ),
            value=f"{domain}: {domain_age_days} days old (created {creation_date.date()})",
            points=20,
        ))
    elif domain_age_days < 30:
        signals.append(Signal(
            name="New Domain (< 30 days)",
            category="domain",
            severity="high",
            description=(
                f"The sending domain '{domain}' was registered {domain_age_days} "
                "days ago. Recently registered domains are commonly used in phishing campaigns."
            ),
            value=f"{domain}: {domain_age_days} days old (created {creation_date.date()})",
            points=12,
        ))

    return signals, parse_warnings
