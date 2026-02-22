# Phase 6 — FastAPI application entry point
# Exposes two endpoints:
#   POST /analyze  — full email analysis pipeline
#   GET  /health   — liveness probe for Cloud Run and UptimeRobot warm-up
#
# Request flow for /analyze:
#   1. Validate API key (X-API-Key header)
#   2. Generate request_id for log correlation (PLAN.md Phase 6.1)
#   3. Run all 5 signal categories in parallel (asyncio.gather)
#   4. Compute score, verdict, confidence (scoring.py)
#   5. Generate AI explanation (ai_explainer.py)
#   6. Return AnalyzeResponse
#
# Rate limiting: 30 req/min per IP via slowapi (Decision D4).
# Structured JSON logging at every stage for observability (PLAN.md Phase 6.1).
#
# Note: `from __future__ import annotations` is intentionally absent.
# Pydantic v2 resolves route-parameter ForwardRefs at registration time; with
# PEP-563 deferred evaluation the `body: AnalyzeRequest` annotation becomes a
# string and Pydantic cannot look it up — causing PydanticUndefinedAnnotation.
# Python 3.9+ supports dict[k,v] / list[x] natively, so the import is not needed.

import asyncio
import logging
import time
import uuid
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from config import settings
from models import AnalyzeRequest, AnalyzeResponse, HealthResponse
from scoring import compute_score
from ai_explainer import generate_explanation
from signal_engine.headers import analyze_headers
from signal_engine.urls import analyze_urls
from signal_engine.ip_reputation import analyze_ip_reputation
from signal_engine.domain_age import analyze_domain_age
from signal_engine.behavior import analyze_behavior


# ---------------------------------------------------------------------------
# Logging (JSON-structured for Cloud Run / Stackdriver)
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format='{"time":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}',
)
logger = logging.getLogger("main")


# ---------------------------------------------------------------------------
# FastAPI app + rate limiter (Decision D4)
# ---------------------------------------------------------------------------

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(
    title="Email Security Scanner",
    version=settings.app_version,
    docs_url="/docs",
    redoc_url=None,
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Allow browser requests from the React dev server and any local origin
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# API key validation dependency
# ---------------------------------------------------------------------------

def verify_api_key(x_api_key: Optional[str] = Header(default=None)) -> None:
    """
    Validates the X-API-Key header.
    Raises 401 if the key is missing or incorrect.

    Note: If API_KEY is not configured (empty string), auth is skipped —
    useful for local development only.
    """
    if not settings.api_key:
        return  # Auth disabled in dev/unconfigured mode
    if x_api_key != settings.api_key:
        logger.warning("Invalid API key attempt")
        raise HTTPException(status_code=401, detail="Unauthorized: invalid API key")


# ---------------------------------------------------------------------------
# Health endpoint
# ---------------------------------------------------------------------------

@app.get("/health", response_model=HealthResponse)
async def health():
    """Liveness probe. Called by UptimeRobot and before demo to warm Cloud Run."""
    return HealthResponse(status="ok", version=settings.app_version)


# ---------------------------------------------------------------------------
# Main analysis endpoint
# ---------------------------------------------------------------------------

@app.post("/analyze", response_model=AnalyzeResponse)
@limiter.limit("30/minute")
async def analyze(
    request: Request,
    body: AnalyzeRequest,
    x_api_key: Optional[str] = Header(default=None),
) -> AnalyzeResponse:
    """
    Full email analysis pipeline.

    Accepts an AnalyzeRequest, runs all signal engines in parallel,
    computes score and confidence, generates AI explanation, and returns
    a fully structured AnalyzeResponse.
    """
    # ---- Auth ----
    verify_api_key(x_api_key)

    # ---- Request tracing (PLAN.md Phase 6.1) ----
    request_id = str(uuid.uuid4())
    start_time = time.time()

    logger.info(
        "Analysis started request_id=%s sender=%s subject=%.60r urls=%d",
        request_id,
        body.sender,
        body.subject,
        len(body.urls),
    )

    # ---- Availability flags ----
    # Each signal engine sets a flag to False when its API is unavailable.
    # These are passed to the confidence calculator.
    availability: dict[str, bool] = {
        "virustotal":    True,
        "safe_browsing": True,
        "abuseipdb":     True,
        "whois":         True,
    }

    # ---- Per-request domain cache (Decision D3) ----
    domain_cache: dict[str, Optional[datetime]] = {}

    # ---- Run all signal engines in parallel (asyncio.gather) ----
    try:
        (
            (header_signals, header_warnings),
            url_signals,
            (ip_signals, ip_warnings),
            (domain_signals, domain_warnings),
        ) = await asyncio.gather(
            # Sync functions wrapped in coroutines via run_in_executor for gather compatibility
            asyncio.get_event_loop().run_in_executor(
                None,
                lambda: analyze_headers(
                    body.sender,
                    body.reply_to,
                    body.authentication_results,
                )
            ),
            analyze_urls(body.urls, availability),
            analyze_ip_reputation(body.received_headers, availability),
            analyze_domain_age(body.sender, domain_cache, availability, body.authentication_results),
        )
    except Exception as exc:
        logger.error("Signal engine failure request_id=%s: %s", request_id, exc, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Signal engine error: {exc}")

    # Behavior analysis is synchronous — run after gather to keep latency clean
    behavior_signals, urgency_excerpts = analyze_behavior(body.body_plain, body.body_html)

    # Flatten all signals
    all_signals = (
        header_signals
        + url_signals
        + ip_signals
        + domain_signals
        + behavior_signals
    )
    all_warnings = header_warnings + ip_warnings + domain_warnings

    logger.info(
        "Signals collected request_id=%s total=%d "
        "header=%d url=%d ip=%d domain=%d behavior=%d warnings=%d",
        request_id,
        len(all_signals),
        len(header_signals),
        len(url_signals),
        len(ip_signals),
        len(domain_signals),
        len(behavior_signals),
        len(all_warnings),
    )

    # ---- Scoring ----
    score, verdict, confidence, confidence_label, top_contributors, evidence, breakdown = (
        compute_score(all_signals, availability, all_warnings)
    )

    # ---- AI explanation ----
    explanation = await generate_explanation(
        score=score,
        verdict=verdict,
        top_signals=top_contributors,
        urgency_excerpts=urgency_excerpts,
    )

    analysis_time_ms = int((time.time() - start_time) * 1000)

    # ---- Structured observability log (PLAN.md Phase 6.1) ----
    logger.info(
        "Analysis complete request_id=%s score=%d verdict=%s confidence=%d%% "
        "analysis_time_ms=%d availability=%s",
        request_id,
        score,
        verdict,
        confidence,
        analysis_time_ms,
        availability,
    )

    return AnalyzeResponse(
        request_id=request_id,
        score=score,
        verdict=verdict,
        confidence=confidence,
        confidence_label=confidence_label,
        signals=all_signals,
        top_contributors=top_contributors,
        evidence=evidence,
        scoring_breakdown=breakdown,
        explanation=explanation,
        analysis_time_ms=analysis_time_ms,
    )


# ---------------------------------------------------------------------------
# 404 / global error handler
# ---------------------------------------------------------------------------

@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    return JSONResponse(status_code=404, content={"detail": "Not found"})
