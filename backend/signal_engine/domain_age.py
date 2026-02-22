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

import httpx
import whois

from config import settings
from models import Signal

logger = logging.getLogger(__name__)

VIRUSTOTAL_DOMAIN_URL = "https://www.virustotal.com/api/v3/domains"


# ---------------------------------------------------------------------------
# Tiered severity for engine-count-based scoring
# ---------------------------------------------------------------------------

def _vt_domain_tiered_severity(
    count: int,
    kind: str,
) -> tuple[str, int]:
    """
    Returns (severity, points) scaled by how many VirusTotal engines flagged
    the domain.

    For 'malicious':
        >= 10 engines -> critical / 20 pts
        3-9 engines   -> high     / 12 pts
        1-2 engines   -> medium   /  5 pts

    For 'suspicious':
        >= 10 engines -> high   / 10 pts
        3-9 engines   -> medium /  6 pts
        1-2 engines   -> low    /  3 pts
    """
    if kind == "malicious":
        if count >= 10:
            return "critical", 20
        elif count >= 3:
            return "high", 12
        else:
            return "medium", 5
    else:  # suspicious
        if count >= 10:
            return "high", 10
        elif count >= 3:
            return "medium", 6
        else:
            return "low", 3


async def _check_virustotal_domain(
    domain: str,
    availability_flags: dict[str, bool],
) -> Optional[Signal]:
    """
    Queries VirusTotal GET /api/v3/domains/{domain} for reputation data.
    Returns a Signal if the domain is flagged malicious or suspicious, None otherwise.
    Sets availability_flags['virustotal'] = False on hard failures.
    """
    if not settings.virustotal_api_key:
        logger.debug("VirusTotal API key not configured — domain reputation check skipped")
        return None

    headers = {"x-apikey": settings.virustotal_api_key}

    logger.info("[VT-domain] Querying VirusTotal domain reputation for domain=%s", domain)

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{VIRUSTOTAL_DOMAIN_URL}/{domain}",
                headers=headers,
                timeout=settings.signal_timeout_seconds,
            )
    except httpx.TimeoutException:
        logger.warning("[VT-domain] VirusTotal domain lookup timed out for domain=%s", domain)
        availability_flags["virustotal"] = False
        return None
    except Exception as exc:
        logger.warning("[VT-domain] VirusTotal domain lookup error for domain=%s: %s", domain, exc)
        availability_flags["virustotal"] = False
        return None

    if resp.status_code == 429:
        logger.warning("[VT-domain] VirusTotal rate limited (429) for domain=%s", domain)
        availability_flags["virustotal"] = False
        return None
    if resp.status_code == 404:
        logger.debug("[VT-domain] VirusTotal: no data found for domain=%s", domain)
        return None
    if resp.status_code != 200:
        logger.warning(
            "[VT-domain] VirusTotal unexpected status=%d for domain=%s",
            resp.status_code, domain,
        )
        availability_flags["virustotal"] = False
        return None

    try:
        data = resp.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        malicious_count = stats.get("malicious", 0)
        suspicious_count = stats.get("suspicious", 0)
        total = sum(stats.values())

        logger.info(
            "[VT-domain] Result: domain=%s malicious=%d suspicious=%d total_engines=%d",
            domain, malicious_count, suspicious_count, total,
        )

        if malicious_count > 0:
            severity, points = _vt_domain_tiered_severity(malicious_count, "malicious")
            return Signal(
                name="VirusTotal: Malicious Domain",
                category="domain",
                severity=severity,
                description=(
                    f"{malicious_count} out of {total} security engines flagged the sender "
                    f"domain \'{domain}\' as malicious."
                ),
                value=f"{domain}: {malicious_count}/{total} engines flagged malicious",
                points=points,
            )
        elif suspicious_count > 0:
            severity, points = _vt_domain_tiered_severity(suspicious_count, "suspicious")
            return Signal(
                name="VirusTotal: Suspicious Domain",
                category="domain",
                severity=severity,
                description=(
                    f"{suspicious_count} out of {total} security engines flagged the sender "
                    f"domain \'{domain}\' as suspicious."
                ),
                value=f"{domain}: {suspicious_count}/{total} engines flagged suspicious",
                points=points,
            )
    except (KeyError, ValueError) as exc:
        logger.warning("[VT-domain] Response parse error for domain=%s: %s", domain, exc)

    logger.info("[VT-domain] No reputation flags for domain=%s", domain)
    return None


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


def _check_auth_complete_failure(
    domain: str,
    authentication_results: Optional[str],
) -> Optional[Signal]:
    """
    Fires a domain-category signal when the sender domain fails ALL three
    authentication checks (SPF fail/softfail, DKIM fail/none, DMARC fail).

    This is a deterministic, API-free signal distinct from the per-header
    signals in the 'header' category: those measure individual protocol
    failures; this measures that the domain as a whole has no valid
    authentication posture — a strong indicator of a spoofed/malicious sender.

    Returns a Signal (20 pts) or None.
    """
    if not authentication_results:
        return None

    import re as _re

    def _result(protocol: str) -> Optional[str]:
        m = _re.search(rf"\b{protocol}=(\S+)", authentication_results, _re.IGNORECASE)
        if m:
            return _re.sub(r"[;,)]$", "", m.group(1)).lower()
        return None

    spf   = _result("spf")
    dkim  = _result("dkim")
    dmarc = _result("dmarc")

    spf_fail  = spf   in ("fail", "softfail")
    dkim_fail = dkim  in ("fail", "none")
    dmarc_fail = dmarc == "fail"

    if spf_fail and dkim_fail and dmarc_fail:
        logger.info(
            "[domain-auth] Complete auth failure for domain=%s spf=%s dkim=%s dmarc=%s",
            domain, spf, dkim, dmarc,
        )
        return Signal(
            name="Domain: Complete Authentication Failure",
            category="domain",
            severity="critical",
            description=(
                f"The sender domain '{domain}' fails all three email authentication "
                f"checks (SPF={spf}, DKIM={dkim}, DMARC={dmarc}). "
                "A domain with no valid authentication posture is a strong indicator "
                "of spoofing or deliberately malicious infrastructure."
            ),
            value=f"{domain}: spf={spf}, dkim={dkim}, dmarc={dmarc}",
            points=20,
        )

    return None


async def analyze_domain_age(
    sender: str,
    domain_cache: dict[str, Optional[datetime]],
    availability_flags: dict[str, bool],
    authentication_results: Optional[str] = None,
) -> tuple[list[Signal], list[str]]:
    """
    Checks the sender domain reputation and registration age.

    Signals fired (additive up to category cap of 20 pts):
      - VirusTotal domain reputation (20 pts malicious / 10 pts suspicious)
      - Complete auth failure — SPF+DKIM+DMARC all fail (20 pts, deterministic)
      - Very new domain < 7 days (20 pts)
      - New domain < 30 days (12 pts)

    Args:
        sender: Raw From header value.
        domain_cache: Per-request dict mapping domain → creation_date (Decision D3).
            Pre-populated by caller; populated by this function if domain is new.
        availability_flags: Mutable dict; sets 'whois' / 'virustotal' to False on failure.
        authentication_results: Raw Authentication-Results header string (optional).
            Used for the deterministic complete-auth-failure signal.

    Returns:
        (signals, parse_warnings)
    """
    signals: list[Signal] = []
    parse_warnings: list[str] = []

    domain = _extract_domain(sender)
    if not domain:
        parse_warnings.append(f"Could not extract sender domain for WHOIS lookup: {sender!r}")
        return signals, parse_warnings

    logger.info("Domain extracted from sender %r → %s", sender, domain)

    # ---- VirusTotal domain reputation check ----
    vt_signal = await _check_virustotal_domain(domain, availability_flags)
    if vt_signal:
        signals.append(vt_signal)

    # ---- Deterministic: complete auth failure check ----
    auth_signal = _check_auth_complete_failure(domain, authentication_results)
    if auth_signal:
        signals.append(auth_signal)

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
