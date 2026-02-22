# Phase 2 — Signal engine package init
# Exposes a single entry-point: run_all_signals(), which fires all 5 signal
# categories in parallel via asyncio.gather() and returns a flat list of Signal objects.

from __future__ import annotations

from .headers import analyze_headers
from .urls import analyze_urls
from .ip_reputation import analyze_ip_reputation
from .domain_age import analyze_domain_age
from .behavior import analyze_behavior

__all__ = [
    "analyze_headers",
    "analyze_urls",
    "analyze_ip_reputation",
    "analyze_domain_age",
    "analyze_behavior",
]
