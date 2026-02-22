# Phase 2 — Header analysis signal engine
# Detects SPF/DKIM/DMARC failures, Reply-To/From domain mismatch,
# and display-name spoofing from email headers.
#
# All signals: category="header", max category contribution capped externally at 45 pts.
# Returns list[Signal] — empty list if no signals fired.
#
# Reliability rules (PLAN.md Phase 2.5):
# - Missing or ambiguous header → treated as "unknown" (no points, no false triggers)
# - parse_warnings[] is included in log output (not in the response model)

from __future__ import annotations

import re
import logging
from typing import Optional

from models import Signal

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Brand list for display-name spoofing detection
# ---------------------------------------------------------------------------
KNOWN_BRANDS: dict[str, str] = {
    "paypal": "paypal.com",
    "amazon": "amazon.com",
    "microsoft": "microsoft.com",
    "google": "google.com",
    "apple": "apple.com",
    "netflix": "netflix.com",
    "linkedin": "linkedin.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "twitter": "twitter.com",
    "x": "x.com",
    "wellsfargo": "wellsfargo.com",
    "chase": "chase.com",
    "bankofamerica": "bankofamerica.com",
    "dropbox": "dropbox.com",
    "docusign": "docusign.com",
    "irs": "irs.gov",
    "fedex": "fedex.com",
    "ups": "ups.com",
    "dhl": "dhl.com",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_domain(email_field: str) -> Optional[str]:
    """
    Extracts the domain from a From/Reply-To header value.
    Handles 'Name <user@domain.com>' and bare 'user@domain.com' formats.
    Returns None if no valid email address is found.
    """
    match = re.search(r"[\w.+-]+@([\w.-]+\.\w+)", email_field)
    if match:
        return match.group(1).lower().strip()
    return None


def _parse_auth_result(auth_header: str, protocol: str) -> Optional[str]:
    """
    Parses an Authentication-Results header and returns the result value
    for the given protocol (spf | dkim | dmarc).

    Handles both:
        spf=pass
        spf=fail (reason string with spaces)
    Returns the raw result word (e.g. "pass", "fail", "softfail", "none") or None.
    """
    # Tolerant regex: looks for 'protocol=word' anywhere in the string
    pattern = rf"\b{re.escape(protocol)}=(\S+)"
    match = re.search(pattern, auth_header, re.IGNORECASE)
    if match:
        # Strip trailing punctuation (e.g. "fail;" → "fail")
        return re.sub(r"[;,)]$", "", match.group(1)).lower()
    return None


# ---------------------------------------------------------------------------
# Main analysis function
# ---------------------------------------------------------------------------

def analyze_headers(
    sender: str,
    reply_to: Optional[str],
    authentication_results: Optional[str],
) -> tuple[list[Signal], list[str]]:
    """
    Runs all header-based signal checks.

    Args:
        sender: Raw From header value.
        reply_to: Raw Reply-To header value (may be None).
        authentication_results: Raw Authentication-Results header string (may be None).

    Returns:
        (signals, parse_warnings)
        - signals: list of Signal objects for every check that fired
        - parse_warnings: list of strings describing any ambiguous/missing parse results
    """
    signals: list[Signal] = []
    parse_warnings: list[str] = []

    # -----------------------------------------------------------------------
    # 1. SPF / DKIM / DMARC
    # -----------------------------------------------------------------------
    if not authentication_results:
        parse_warnings.append("Authentication-Results header missing — SPF/DKIM/DMARC unknown")
        logger.debug("auth_results missing; skipping header auth signals")
    else:
        auth = authentication_results

        # SPF
        spf_result = _parse_auth_result(auth, "spf")
        if spf_result in ("fail", "softfail"):
            signals.append(Signal(
                name="SPF Fail",
                category="header",
                severity="high",
                description="The sender's domain is not authorised to send email from this IP address.",
                value=f"spf={spf_result}",
                points=15,
            ))
        elif spf_result is None:
            parse_warnings.append("SPF result not found in Authentication-Results")

        # DKIM
        dkim_result = _parse_auth_result(auth, "dkim")
        if dkim_result in ("fail", "none"):
            signals.append(Signal(
                name="DKIM Fail",
                category="header",
                severity="high",
                description="The email's cryptographic signature is invalid or absent.",
                value=f"dkim={dkim_result}",
                points=15,
            ))
        elif dkim_result is None:
            parse_warnings.append("DKIM result not found in Authentication-Results")

        # DMARC
        dmarc_result = _parse_auth_result(auth, "dmarc")
        if dmarc_result == "fail":
            signals.append(Signal(
                name="DMARC Fail",
                category="header",
                severity="high",
                description="The email failed DMARC policy enforcement.",
                value=f"dmarc={dmarc_result}",
                points=15,
            ))
        elif dmarc_result is None:
            parse_warnings.append("DMARC result not found in Authentication-Results")

    # -----------------------------------------------------------------------
    # 2. Reply-To ≠ From domain mismatch
    # -----------------------------------------------------------------------
    sender_domain = _extract_domain(sender)
    if not sender_domain:
        parse_warnings.append(f"Could not extract domain from sender: {sender!r}")

    if reply_to and sender_domain:
        reply_domain = _extract_domain(reply_to)
        if reply_domain and reply_domain != sender_domain:
            signals.append(Signal(
                name="Reply-To Domain Mismatch",
                category="header",
                severity="medium",
                description=(
                    f"The Reply-To domain ({reply_domain}) differs from the "
                    f"From domain ({sender_domain}). Replies will go to a different server."
                ),
                value=f"from={sender_domain}, reply-to={reply_domain}",
                points=8,
            ))
    elif reply_to and not sender_domain:
        parse_warnings.append("Reply-To mismatch check skipped — sender domain unresolvable")

    # -----------------------------------------------------------------------
    # 3. Display name spoofing
    # -----------------------------------------------------------------------
    if sender_domain:
        # Extract display name — everything before the '<'
        display_name_match = re.match(r'^"?([^"<]+)"?\s*<', sender.strip())
        display_name = display_name_match.group(1).strip().lower() if display_name_match else ""

        for brand_keyword, canonical_domain in KNOWN_BRANDS.items():
            if brand_keyword in display_name:
                # The display name references a known brand
                if not sender_domain.endswith(canonical_domain):
                    signals.append(Signal(
                        name="Display Name Spoofing",
                        category="header",
                        severity="high",
                        description=(
                            f"The display name references '{brand_keyword.title()}' but the "
                            f"sending domain is '{sender_domain}', not '{canonical_domain}'."
                        ),
                        value=f"display_name={display_name!r}, domain={sender_domain}",
                        points=10,
                    ))
                    break  # Only fire once even if multiple brands match

    if parse_warnings:
        logger.warning("Header parse warnings: %s", parse_warnings)

    return signals, parse_warnings
