# Phase 2 — Body content / behaviour signal engine (Decision D1)
# Detects urgency language, credential-request patterns, and brand impersonation cues
# in the email body using regex-based keyword matching.
#
# This module fills the `behavior: 10` category cap reserved in scoring.py
# (PLAN.md Phase 3) which had no corresponding signal module in the original plan.
# See IMPLEMENTATION_NOTES.md Assumption A5 for rationale.
#
# Data privacy: only the matched phrase(s) — not the full body — are passed to
# the AI explainer prompt (IMPLEMENTATION_NOTES.md Assumption A8).

from __future__ import annotations

import re
import logging
from models import Signal

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Keyword patterns
# ---------------------------------------------------------------------------

# Urgency/threat language — triggers if ANY pattern matches
URGENCY_PATTERNS: list[re.Pattern] = [
    re.compile(r"\baccount.{0,20}(suspend|terminat|clos|lock|disabl)", re.IGNORECASE),
    re.compile(r"\b(immediate|urgent|action required|act now|respond within)", re.IGNORECASE),
    re.compile(r"\b(24 hours?|48 hours?|within \d+ hours?)", re.IGNORECASE),
    re.compile(r"\b(expire[s]?|expiring soon|last.{0,10}chance)", re.IGNORECASE),
    re.compile(r"\b(verify.{0,20}(identity|account|information))", re.IGNORECASE),
    re.compile(r"\b(click here to (confirm|verify|restore|unlock))", re.IGNORECASE),
]

# Credential / PII solicitation
CREDENTIAL_PATTERNS: list[re.Pattern] = [
    re.compile(r"\b(enter.{0,20}(password|credit card|ssn|social security))", re.IGNORECASE),
    re.compile(r"\b(provide.{0,20}(banking|card number|pin|passcode))", re.IGNORECASE),
    re.compile(r"\b(confirm.{0,20}(your details|payment|billing))", re.IGNORECASE),
]


def _first_match(text: str, patterns: list[re.Pattern]) -> str | None:
    """Returns the first matched substring for any pattern in the list, or None."""
    for pattern in patterns:
        m = pattern.search(text)
        if m:
            return m.group(0)
    return None


def analyze_behavior(body_plain: str, body_html: str) -> tuple[list[Signal], list[str]]:
    """
    Detects urgency and credential-solicitation language in the email body.

    Uses plain-text body if available; falls back to HTML body stripped of tags.
    Returns at most one Signal (behavior category is capped at 10 pts total).

    Args:
        body_plain: Plain-text version of the email body.
        body_html: HTML version of the email body.

    Returns:
        (signals, urgency_excerpts)
        - signals: list of Signal objects (0 or 1)
        - urgency_excerpts: short matched strings passed to the AI prompt (Assumption A8)
    """
    signals: list[Signal] = []
    excerpts: list[str] = []

    # Prefer plain text; fall back to HTML with tags stripped
    text = body_plain
    if not text.strip() and body_html:
        text = re.sub(r"<[^>]+>", " ", body_html)

    if not text.strip():
        return signals, excerpts

    urgency_match = _first_match(text, URGENCY_PATTERNS)
    credential_match = _first_match(text, CREDENTIAL_PATTERNS)

    matched_excerpts: list[str] = []
    reasons: list[str] = []

    if urgency_match:
        matched_excerpts.append(f'"{urgency_match}"')
        reasons.append("urgency/threat language")

    if credential_match:
        matched_excerpts.append(f'"{credential_match}"')
        reasons.append("credential solicitation")

    if reasons:
        excerpts.extend(matched_excerpts)
        signals.append(Signal(
            name="Suspicious Body Content",
            category="behavior",
            severity="medium",
            description=(
                "The email body contains "
                + " and ".join(reasons)
                + ". Phrases: "
                + ", ".join(matched_excerpts)
                + "."
            ),
            value="; ".join(matched_excerpts),
            points=10,
        ))
        logger.info("Behavior signal fired: reasons=%s", reasons)

    return signals, excerpts
