# Phase 4 — AI explanation layer
# Calls OpenAI GPT-4o to generate a plain-English 2–3 sentence explanation
# of the email verdict, based on the scored signals.
#
# Privacy trade-off (PLAN.md Phase 4 "Privacy trade-off"):
#   - Only signal summaries and short matched body excerpts (urgency phrases)
#     are sent to OpenAI — not the full email body (Assumption A8).
#   - This is a conscious demo trade-off. Production path: user toggle,
#     PII stripping, or self-hosted LLM.
#
# Fallback: if the OpenAI call fails for any reason, a deterministic template
# string is generated from the top 3 signals so the add-on never shows a blank
# explanation card.

from __future__ import annotations

import logging
from typing import Optional

from openai import AsyncOpenAI, OpenAIError

from config import settings
from models import Signal

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = (
    "You are a cybersecurity analyst reviewing an email for a non-technical user. "
    "Given the following signals and verdict, explain in exactly 2–3 sentences "
    "why this email is or isn't dangerous. Be specific about which signals matter most. "
    "Use simple language. Address the user directly (use 'this email...'). "
    "Do not repeat the score or verdict word-for-word."
)


def _build_user_prompt(
    score: int,
    verdict: str,
    top_signals: list[Signal],
    urgency_excerpts: list[str],
) -> str:
    """
    Constructs the GPT-4o user prompt from signal summaries and short body excerpts.
    Full email body is never included (Assumption A8 / privacy trade-off).
    """
    signal_lines = "\n".join(
        f"- {sig.name}: {sig.description}"
        + (f" (matched: {sig.value})" if sig.value else "")
        for sig in top_signals
    )

    excerpt_section = ""
    if urgency_excerpts:
        excerpt_section = "\nBody excerpts that triggered behavior signals:\n" + "\n".join(
            f"  • {ex}" for ex in urgency_excerpts[:3]
        )

    return (
        f"Verdict: {verdict} (score: {score}/100)\n\n"
        f"Top signals detected:\n{signal_lines}"
        f"{excerpt_section}\n\n"
        f"Explain why this email {'is dangerous' if verdict != 'SAFE' else 'appears safe'}."
    )


def _template_fallback(
    score: int,
    verdict: str,
    top_signals: list[Signal],
) -> str:
    """
    Generates a deterministic explanation without calling the AI API.
    Used when OpenAI is unavailable or the API call fails.
    """
    if not top_signals:
        if verdict == "SAFE":
            return (
                "This email passed all security checks. "
                "The sender domain is established, headers are valid, "
                "and no suspicious URLs were detected."
            )
        return f"This email received a {verdict.lower()} verdict (score: {score}/100). No specific signals were identified, but caution is advised."

    top_names = [s.name for s in top_signals[:3]]

    if verdict == "SAFE":
        return (
            f"This email appears safe with a score of {score}/100. "
            "No significant threat signals were detected, and all available checks passed."
        )
    elif verdict == "SUSPICIOUS":
        return (
            f"This email shows suspicious characteristics (score: {score}/100). "
            f"The following concerns were identified: {', '.join(top_names)}. "
            "Exercise caution before clicking any links or providing information."
        )
    else:  # MALICIOUS
        return (
            f"This email is likely malicious (score: {score}/100). "
            f"Key indicators include: {', '.join(top_names)}. "
            "Do not click any links or attachments. Delete this email immediately."
        )


async def generate_explanation(
    score: int,
    verdict: str,
    top_signals: list[Signal],
    urgency_excerpts: Optional[list[str]] = None,
) -> str:
    """
    Generates a 2–3 sentence plain-English explanation of the email verdict.

    Tries GPT-4o first; falls back to the deterministic template on any error.

    Args:
        score: 0–100 risk score.
        verdict: "SAFE" | "SUSPICIOUS" | "MALICIOUS".
        top_signals: Top contributing Signal objects (up to 3).
        urgency_excerpts: Short matched phrases from body content (Assumption A8).

    Returns:
        A string explanation suitable for display in the Gmail add-on sidebar.
    """
    if urgency_excerpts is None:
        urgency_excerpts = []

    if not settings.openai_api_key:
        logger.debug("OpenAI API key not configured — using template fallback")
        return _template_fallback(score, verdict, top_signals)

    user_prompt = _build_user_prompt(score, verdict, top_signals, urgency_excerpts)

    try:
        client = AsyncOpenAI(api_key=settings.openai_api_key)
        response = await client.chat.completions.create(
            model="gpt-4o",
            temperature=0.3,
            max_tokens=200,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
        )
        explanation = response.choices[0].message.content.strip()
        logger.info("AI explanation generated (tokens used: %d)", response.usage.total_tokens)
        return explanation

    except OpenAIError as exc:
        logger.warning("OpenAI API error — using template fallback: %s", exc)
        return _template_fallback(score, verdict, top_signals)
    except Exception as exc:
        logger.error("Unexpected error in AI explainer — using template fallback: %s", exc)
        return _template_fallback(score, verdict, top_signals)
