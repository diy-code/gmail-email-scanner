# Phase 3 — Scoring engine
# Aggregates signals from all 5 categories into a 0–100 score, a verdict,
# and a confidence badge. Returns the full ScoringBreakdown for auditability.
#
# Scoring formula (PLAN.md Phase 3):
#   1. Sum points within each category
#   2. Cap each category at its maximum
#   3. score = min(100, round(capped_total / effective_max * 100))
#
# Verdict thresholds:
#   0–30   → SAFE        (#34a853)
#   31–65  → SUSPICIOUS  (#f9ab00)
#   66–100 → MALICIOUS   (#d93025)
#
# Confidence starts at 100 and is reduced for each unavailable data source.
# See PLAN.md Phase 3 "Confidence Badge" section.

from __future__ import annotations

import logging
from models import Signal, EvidenceItem, ScoringBreakdown

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Scoring constants
# ---------------------------------------------------------------------------

CATEGORY_CAPS: dict[str, int] = {
    "header":   45,
    "url":      55,
    "ip":       20,
    "domain":   20,
    "behavior": 10,
}

VERDICT_THRESHOLDS = [
    (0,  30,  "SAFE",       "green"),
    (31, 65,  "SUSPICIOUS", "orange"),
    (66, 100, "MALICIOUS",  "red"),
]

CONFIDENCE_PENALTIES: dict[str, int] = {
    "virustotal":    20,
    "safe_browsing": 15,
    "abuseipdb":     10,
    "whois":         10,
}

# Penalty applied when critical parsing ambiguities are detected
PARSE_AMBIGUITY_PENALTY = 10


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _compute_verdict(score: int) -> str:
    for low, high, verdict, _ in VERDICT_THRESHOLDS:
        if low <= score <= high:
            return verdict
    return "MALICIOUS"  # fallback for score > 100 (should not happen)


def _compute_confidence(
    availability: dict[str, bool],
    parse_warning_count: int,
) -> tuple[int, str]:
    """
    Computes confidence score and label.

    availability: dict of signal source → True (available) / False (unavailable).
        A missing key is treated as available (True).
    parse_warning_count: total number of parse warnings across all signal checks.
    """
    confidence = 100

    for source, penalty in CONFIDENCE_PENALTIES.items():
        if not availability.get(source, True):
            confidence -= penalty
            logger.debug("Confidence --%d: %s unavailable", penalty, source)

    if parse_warning_count >= 2:
        confidence -= PARSE_AMBIGUITY_PENALTY
        logger.debug("Confidence --%d: %d parse warnings", PARSE_AMBIGUITY_PENALTY, parse_warning_count)

    confidence = max(0, min(100, confidence))

    if confidence >= 80:
        label = "High"
    elif confidence >= 50:
        label = "Medium"
    else:
        label = "Low"

    return confidence, label


# ---------------------------------------------------------------------------
# Main scoring function
# ---------------------------------------------------------------------------

def compute_score(
    all_signals: list[Signal],
    availability: dict[str, bool],
    parse_warnings: list[str],
) -> tuple[int, str, int, str, list[Signal], list[EvidenceItem], ScoringBreakdown]:
    """
    Aggregates all fired signals into a score, verdict, and full breakdown.

    Args:
        all_signals: Flat list of all Signal objects from every signal engine.
        availability: Dict of signal source name → availability flag.
        parse_warnings: Combined parse warnings from all signal engines.

    Returns:
        (score, verdict, confidence, confidence_label,
         top_contributors, evidence_items, scoring_breakdown)
    """
    # ---- Step 1: Sum points per category ----
    category_raw: dict[str, int] = {cat: 0 for cat in CATEGORY_CAPS}
    for signal in all_signals:
        cat = signal.category
        if cat in category_raw:
            category_raw[cat] += signal.points
        else:
            logger.warning("Unknown signal category '%s' — ignored in scoring", cat)

    # ---- Step 2: Apply category caps ----
    category_capped: dict[str, int] = {
        cat: min(raw, CATEGORY_CAPS[cat])
        for cat, raw in category_raw.items()
    }

    capped_total = sum(category_capped.values())
    effective_max = sum(CATEGORY_CAPS.values())  # 150

    # ---- Step 3: Normalise to 0–100 ----
    score = min(100, round(capped_total / effective_max * 100)) if effective_max > 0 else 0

    verdict = _compute_verdict(score)
    confidence, confidence_label = _compute_confidence(availability, len(parse_warnings))

    # ---- Step 4: Top 3 contributors ----
    top_contributors = sorted(all_signals, key=lambda s: s.points, reverse=True)[:3]

    # ---- Step 5: Evidence log ----
    evidence_items: list[EvidenceItem] = [
        EvidenceItem(
            signal=sig.name,
            source=_source_for_category(sig.category),
            raw_value=sig.value or sig.description,
            points=sig.points,
        )
        for sig in all_signals
    ]

    # ---- Step 6: Scoring breakdown ----
    total_raw = sum(category_raw.values())
    breakdown = ScoringBreakdown(
        total_points=total_raw,
        capped_points=capped_total,
        max_points=effective_max,
        formula=f"score=min(100, round({capped_total}/{effective_max}*100))={score}",
        category_points=dict(category_capped),
    )

    logger.info(
        "Score computed: score=%d verdict=%s confidence=%d%% (%s) "
        "capped=%d/%d signals=%d",
        score, verdict, confidence, confidence_label,
        capped_total, effective_max, len(all_signals),
    )

    return score, verdict, confidence, confidence_label, top_contributors, evidence_items, breakdown


def _source_for_category(category: str) -> str:
    """Maps a signal category to its primary data source name for evidence logging."""
    return {
        "header":   "Email Headers",
        "url":      "VirusTotal / Safe Browsing",
        "ip":       "AbuseIPDB",
        "domain":   "VirusTotal / WHOIS",
        "behavior": "Body Content Analysis",
    }.get(category, category)
