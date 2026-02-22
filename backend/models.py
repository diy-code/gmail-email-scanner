# Phase 1 — Pydantic request/response models (API contract)
# Defines the language of the entire system. All other modules import from here.
# Written before any logic as per the spec-first approach in PLAN.md Phase 1.
#
# Key design decisions:
# - Field constraints (max_length, max_items) provide server-side input validation
#   against oversized or pathological payloads (Security review finding #2).
# - All Optional fields default to None — missing headers are treated as unknown,
#   not as pass (PLAN.md Phase 2.5 reliability rules).
# - ScoringBreakdown carries the full arithmetic trace so every verdict is auditable.

from __future__ import annotations

from typing import Optional
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Request
# ---------------------------------------------------------------------------

class AnalyzeRequest(BaseModel):
    """Payload sent by the Gmail add-on to POST /analyze."""

    subject: str = Field(max_length=500)
    sender: str = Field(
        max_length=500,
        description="Full From header value: 'Display Name <email@domain.com>'",
    )
    reply_to: Optional[str] = Field(default=None, max_length=500)
    authentication_results: Optional[str] = Field(
        default=None,
        max_length=2000,
        description="Raw 'Authentication-Results' header string",
    )
    received_headers: list[str] = Field(
        default_factory=list,
        max_length=20,           # cap number of Received headers
        description="All 'Received' headers ordered from outermost to innermost",
    )
    body_plain: str = Field(
        default="",
        max_length=50_000,
        description="Plain-text body (used for urgency keyword extraction)",
    )
    body_html: str = Field(
        default="",
        max_length=100_000,
        description="HTML body (URL extraction happens client-side before this call)",
    )
    urls: list[str] = Field(
        default_factory=list,
        max_length=10,           # matches client-side cap in Api.gs
        description="Pre-extracted URLs from the email body (de-duplicated by client)",
    )
    message_date: Optional[str] = Field(
        default=None,
        max_length=100,
        description="Raw Date header value",
    )


# ---------------------------------------------------------------------------
# Response building blocks
# ---------------------------------------------------------------------------

class Signal(BaseModel):
    """A single threat indicator that fired during analysis."""

    name: str                              # e.g. "SPF Fail"
    category: str                          # "header" | "url" | "ip" | "domain" | "behavior"
    severity: str                          # "low" | "medium" | "high" | "critical"
    description: str                       # human-readable explanation of this signal
    value: Optional[str] = None            # raw value that triggered it, e.g. "2 days old"
    points: int                            # weight this signal contributes to the score


class EvidenceItem(BaseModel):
    """Auditable reason entry — one per signal that fired."""

    signal: str                            # signal name, e.g. "DMARC Fail"
    source: str                            # where the data came from, e.g. "VirusTotal"
    raw_value: str                         # the exact data point, e.g. "malicious=14"
    points: int                            # points added by this evidence item


class ScoringBreakdown(BaseModel):
    """Full arithmetic trace of how the score was computed.
    
    Satisfies the explainability contract in PLAN.md Phase 3:
    every verdict can be reproduced from this data alone.
    """

    total_points: int                      # sum of all fired signal points (pre-cap)
    capped_points: int                     # after applying per-category caps
    max_points: int                        # effective denominator used in formula
    formula: str                           # e.g. "score=min(100, round(capped/max*100))"
    category_points: dict[str, int]        # "header" | "url" | "ip" | "domain" | "behavior" → points


# ---------------------------------------------------------------------------
# Response
# ---------------------------------------------------------------------------

class AnalyzeResponse(BaseModel):
    """Full analysis result returned to the Gmail add-on."""

    request_id: str                        # UUID4 for log correlation (PLAN.md Phase 6.1)

    # --- Verdict ---
    score: int                             # 0–100
    verdict: str                           # "SAFE" | "SUSPICIOUS" | "MALICIOUS"
    confidence: int                        # 0–100 confidence badge
    confidence_label: str                  # "High" | "Medium" | "Low"

    # --- Signal data ---
    signals: list[Signal]                  # all signals that fired
    top_contributors: list[Signal]         # top 3 by points (used by UI prominently)
    evidence: list[EvidenceItem]           # full auditable reason log

    # --- Score arithmetic ---
    scoring_breakdown: ScoringBreakdown    # exact trace of the calculation

    # --- AI narrative ---
    explanation: str                       # GPT-4o generated text (or template fallback)

    # --- Observability ---
    analysis_time_ms: int                  # wall-clock time for the full analysis


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

class HealthResponse(BaseModel):
    status: str = "ok"
    version: str
