# Gmail Malicious Email Scorer

Analyzes opened emails for phishing/malicious signals and returns a 0–100 threat score with an AI-generated explanation.

## Architecture

```
┌────────────────────┐
│  Gmail Add-on      │  Google Apps Script (CardService UI)
│  (addon/)          │  Extracts headers, URLs, body from opened email
└────────┬───────────┘
         │ POST /analyze  (X-API-Key auth, 30 req/min rate limit)
         ▼
┌────────────────────┐   asyncio.gather — 5 parallel signal engines
│  FastAPI Backend   │─────────────────────────────────────────────┐
│  (backend/)        │   ┌──────────┬──────────┬─────────┬───────┐│
│  Google Cloud Run  │   │ Headers  │ URLs     │ IP Rep  │ WHOIS ││
│                    │   │ (sync)   │ (async)  │ (async) │(async)││
│                    │   └──────────┴──────────┴─────────┴───────┘│
│                    │   then: Behavior (sync, regex)              │
│                    ├────────────────────────────────────────────-┤
│                    │   scoring.py  → 0-100 score + verdict      │
│                    │   ai_explainer.py → GPT-4o narrative        │
└────────┬───────────┘
         │ JSON: score, verdict, signals[], explanation
         ▼
┌────────────────────┐
│  Gmail Sidebar     │  Renders verdict badge, signal cards,
│  (CardService)     │  scoring breakdown, AI explanation
└────────────────────┘

Optional: React debug UI (frontend/) for testing without the add-on.
```

## APIs Used

| API | Purpose |
|-----|---------|
| VirusTotal v3 | URL reputation lookup (cached, max 3 unique domains/request) |
| Google Safe Browsing v4 | URL threat matching (malware, social engineering) |
| AbuseIPDB v2 | Sender IP abuse confidence score |
| python-whois | Domain registration age via WHOIS |
| OpenAI GPT-4o | 2–3 sentence plain-English explanation from signal summaries |

## Implemented Features

- **SPF / DKIM / DMARC validation** — parses `Authentication-Results` header, fires signals on fail/softfail/none
- **Display-name spoofing detection** — matches 20 known brands against sender domain
- **Reply-To ≠ From domain mismatch** — flags social engineering redirects
- **URL scanning** — VirusTotal engine-count tiering (1–2 / 3–9 / ≥10) + Safe Browsing threat match
- **URL shortener & typosquatting detection** — known shortener list + Levenshtein distance ≤ 2
- **Sender IP reputation** — first external hop extraction from Received headers → AbuseIPDB (additive thresholds: >25% / >75%)
- **Domain age scoring** — mutually exclusive thresholds: <7 days (20 pts) or <30 days (12 pts)
- **Behavioral analysis** — urgency keyword detection in body text (regex, 10 pt cap)
- **Weighted scoring engine** — per-category caps (header=45, url=40, ip=20, domain=20, behavior=10), normalized to 0–100
- **Confidence system** — starts at 100, penalized per unavailable signal source
- **AI explanation** — GPT-4o narrates signal summaries; deterministic template fallback on failure
- **Auto-scan mode** — toggle on add-on homepage to analyze emails on open
- **Scan history** — last 10 scans stored in UserProperties, shown on homepage
- **Sender blacklist** — user-managed domain blocklist → instant MALICIOUS verdict
- **Rate limiting** — 30 req/min per IP via slowapi
- **React debug UI** — standalone frontend for testing `/analyze` without Gmail

## Limitations

- **No attachment analysis** — intentionally skipped; sandboxing complexity out of scope for MVP
- **VirusTotal free tier** — 4 req/min, 500/day; may throttle under load
- **3s timeout budget** — all external API calls time out at 3s; fast but may miss slow responses
- **Simplified auth** — single shared API key (`X-API-Key`), not per-user identity
- **Cold starts** — Cloud Run free tier has ~5–10s cold start latency
- **Brand list is static** — 20 hardcoded brands for spoofing detection; no dynamic updates
- **Email body sent to OpenAI** — only signal summaries + short urgency excerpts, but no user consent flow
- **No management console** — intentionally deferred (trade-off: low demo ROI)
- ⚠️ **History/blacklist are per-user only** — stored in Apps Script UserProperties, no shared admin view
