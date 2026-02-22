# Scoring Logic — Email Security Scanner

> **File**: `backend/scoring.py` · **Last updated**: February 2026  
> This document explains the complete scoring pipeline: how raw email data becomes a 0–100 threat score, a verdict, a confidence rating, and a human-readable explanation.

---

## Table of Contents

1. [High-Level Pipeline](#1-high-level-pipeline)
2. [Signal Engines](#2-signal-engines)
   - 2.1 [Header Analysis](#21-header-analysis-headerspy)
   - 2.2 [URL Intelligence](#22-url-intelligence-urlspy)
   - 2.3 [IP Reputation](#23-ip-reputation-ip_reputationpy)
   - 2.4 [Domain Age & Reputation](#24-domain-age--reputation-domain_agepy)
   - 2.5 [Behavioral Analysis](#25-behavioral-analysis-behaviorpy)
3. [Signal Model](#3-signal-model)
4. [Scoring Formula](#4-scoring-formula)
   - 4.1 [Category Caps](#41-category-caps)
   - 4.2 [Normalization](#42-normalization)
   - 4.3 [Worked Example](#43-worked-example)
5. [Verdict Thresholds](#5-verdict-thresholds)
6. [Confidence System](#6-confidence-system)
7. [AI Explanation Layer](#7-ai-explanation-layer)
8. [Top Contributors & Evidence](#8-top-contributors--evidence)
9. [Design Decisions & Rationale](#9-design-decisions--rationale)
10. [Complete Signal Reference Table](#10-complete-signal-reference-table)

---

## 1. High-Level Pipeline

```
Email payload (from Gmail Add-on)
  │
  ▼
┌──────────────────────────────────────────────┐
│  POST /analyze                               │
│  ├─ Auth: X-API-Key header validation        │
│  ├─ Rate limit: 30 req/min per IP (slowapi)  │
│  └─ Request ID: UUID4 for log correlation    │
└──────────────────────────────────────────────┘
  │
  ▼
┌──────────────────────────────────────────────┐
│  asyncio.gather — 4 parallel tasks           │
│  ┌──────────┐ ┌──────────┐ ┌──────────────┐ │
│  │ Headers  │ │  URLs    │ │ IP Reputation│ │
│  │ (sync    │ │ (async)  │ │ (async)      │ │
│  │  in exec)│ │          │ │              │ │
│  └──────────┘ └──────────┘ └──────────────┘ │
│  ┌──────────────────┐                        │
│  │ Domain Age+Rep   │                        │
│  │ (async + sync    │                        │
│  │  WHOIS in exec)  │                        │
│  └──────────────────┘                        │
│  Then sequentially:                          │
│  ┌──────────┐                                │
│  │ Behavior │ (sync, runs after gather)      │
│  └──────────┘                                │
└──────────────────────────────────────────────┘
  │
  ▼  All signals + availability flags + parse warnings
┌──────────────────────────────────────────────┐
│  scoring.compute_score()                     │
│  1. Sum points per category                  │
│  2. Cap each category                        │
│  3. Normalize to 0–100                       │
│  4. Determine verdict                        │
│  5. Calculate confidence                     │
│  6. Select top 3 contributors                │
│  7. Build evidence log                       │
└──────────────────────────────────────────────┘
  │
  ▼
┌──────────────────────────────────────────────┐
│  ai_explainer.generate_explanation()         │
│  GPT-4o → 2–3 sentence narrative             │
│  Fallback: deterministic template            │
└──────────────────────────────────────────────┘
  │
  ▼
  AnalyzeResponse JSON returned to add-on
```

All external API calls have a **3-second timeout budget** (`config.signal_timeout_seconds`). On timeout or `429 Too Many Requests`, the engine returns no signal and marks the source as unavailable — it never raises an exception.

---

## 2. Signal Engines

Each engine analyzes one facet of the email and returns a list of `Signal` objects. Engines are independent and do not read each other's output.

### 2.1 Header Analysis (`headers.py`)

**Category**: `header` · **Cap**: 45 pts · **I/O**: None (pure parsing)

Parses the `Authentication-Results` header and the `From` / `Reply-To` fields.

| Signal | Severity | Points | Trigger Condition |
|--------|----------|--------|-------------------|
| **SPF Fail** | high | 15 | `spf=fail` or `spf=softfail` in Authentication-Results |
| **DKIM Fail** | high | 15 | `dkim=fail` or `dkim=none` in Authentication-Results |
| **DMARC Fail** | high | 15 | `dmarc=fail` in Authentication-Results |
| **Reply-To Domain Mismatch** | medium | 8 | Reply-To domain ≠ From domain |
| **Display Name Spoofing** | high | 10 | Display name contains a known brand (PayPal, Amazon, etc.) but sending domain ≠ brand's canonical domain |

**Key decisions:**

- **Missing `Authentication-Results` header**: Treated as "unknown" — no points awarded, no false triggers. A parse warning is logged and fed to the confidence calculator.
- **Brand list**: 20 hardcoded brands with canonical domains (e.g., `paypal` → `paypal.com`). Only fires once even if multiple brands match the display name.
- **Regex for auth parsing**: Uses `\b{protocol}=(\S+)` — tolerant of varying header formats and trailing punctuation.

### 2.2 URL Intelligence (`urls.py`)

**Category**: `url` · **Cap**: 40 pts · **I/O**: VirusTotal API, Google Safe Browsing API

Analyzes up to 10 pre-extracted URLs from the email body.

| Signal | Severity | Points | Trigger Condition |
|--------|----------|--------|-------------------|
| **VirusTotal: URL Flagged Malicious** | critical | 20 | ≥ 10 VT engines flag the URL as malicious |
| **VirusTotal: URL Flagged Malicious** | high | 12 | 3–9 VT engines flag the URL as malicious |
| **VirusTotal: URL Flagged Malicious** | medium | 5 | 1–2 VT engines flag the URL as malicious |
| **Safe Browsing: URL Flagged** | critical | 20 | Google Safe Browsing threat match (MALWARE, SOCIAL_ENGINEERING, UNWANTED_SOFTWARE, POTENTIALLY_HARMFUL) |
| **URL Shortener Detected** | low | 5 | Domain matches known shortener list (bit.ly, tinyurl.com, t.co, etc.) |
| **Typosquatted Domain** | high | 10 | URL domain is within Levenshtein distance ≤ 2 of a known brand domain |

**Key decisions:**

- **VirusTotal engine-count tiering**: The number of engines flagging a URL directly affects severity and points. 1–2 engines is treated as a weak signal (medium/5 pts) since it may be a false positive. 3–9 engines is moderate consensus (high/12 pts). Only ≥ 10 engines qualifies as critical (20 pts). This prevents a single engine’s false positive from dominating the score.
- **VirusTotal rate limiting**: Free tier = 4 req/min, 500/day. To stay within budget, URLs are de-duplicated by domain and capped at `virustotal_max_domains` (default: 3) unique domains per request.
- **VirusTotal uses cached lookups**: `GET /api/v3/urls/{id}` retrieves existing scan results — it does NOT submit for a new scan. This avoids burning quota on active scanning.
- **Safe Browsing batching**: All URLs are checked in a single POST request (batch API). An empty response `{}` — not a 404 — means "no threats found."
- **Typosquatting**: Uses `rapidfuzz` Levenshtein distance. `0 < distance ≤ 2` flags the domain. This catches common substitutions like `paypa1.com` → `paypal.com`.
- **URL shortener**: Only fires once per email (one signal, even if multiple shorteners are present).

### 2.3 IP Reputation (`ip_reputation.py`)

**Category**: `ip` · **Cap**: 20 pts · **I/O**: AbuseIPDB API

Extracts the sender IP from `Received` headers and queries AbuseIPDB.

| Signal | Severity | Points | Trigger Condition |
|--------|----------|--------|-------------------|
| **AbuseIPDB: Sender IP Reported for Abuse** | high | 12 | Confidence > 25% AND ≥ 10 reports |
| **AbuseIPDB: Sender IP Reported for Abuse** | medium | 8 | Confidence > 25% AND 3–9 reports |
| **AbuseIPDB: Sender IP Reported for Abuse** | low | 4 | Confidence > 25% AND 1–2 reports |
| **AbuseIPDB: High-Confidence Abusive IP** | critical | 8 | Confidence > 75% AND ≥ 10 reports *(additive)* |
| **AbuseIPDB: High-Confidence Abusive IP** | high | 4 | Confidence > 75% AND 3–9 reports *(additive)* |
| **AbuseIPDB: High-Confidence Abusive IP** | medium | 2 | Confidence > 75% AND 1–2 reports *(additive)* |

**Key decisions:**

- **Report-count tiering**: The number of distinct users who reported the IP scales the points. A single report (1–2 users) is treated as a weak signal to avoid false positives from one abusive reporter. 3–9 reports indicate moderate community consensus. ≥ 10 reports represent strong consensus and earn full points.
- **Additive thresholds** (not mutually exclusive): If `confidence > 75%`, **both** signals fire. Maximum total with ≥ 10 reports = 12 + 8 = 20 pts (fills the cap). With only 1–2 reports, total = 4 + 2 = 6 pts.
- **First external IP, not last**: The engine scans `Received` headers outermost-first and returns the first IP not in a private/reserved range (RFC 1918, link-local, loopback, ULA). The last hop is typically an internal Google relay — not the actual sender.
- **Private IP filtering**: Addresses in `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`, `::1/128`, `fc00::/7` are silently skipped.

### 2.4 Domain Age & Reputation (`domain_age.py`)

**Category**: `domain` · **Cap**: 20 pts · **I/O**: WHOIS (python-whois), VirusTotal Domain API

Checks how recently the sender's domain was registered and its VirusTotal reputation.

| Signal | Severity | Points | Trigger Condition |
|--------|----------|--------|-------------------|
| **VirusTotal: Malicious Domain** | critical | 20 | ≥ 10 VT engines flag domain as malicious |
| **VirusTotal: Malicious Domain** | high | 12 | 3–9 VT engines flag domain as malicious |
| **VirusTotal: Malicious Domain** | medium | 5 | 1–2 VT engines flag domain as malicious |
| **VirusTotal: Suspicious Domain** | high | 10 | ≥ 10 VT engines flag domain as suspicious (and 0 malicious) |
| **VirusTotal: Suspicious Domain** | medium | 6 | 3–9 VT engines flag domain as suspicious (and 0 malicious) |
| **VirusTotal: Suspicious Domain** | low | 3 | 1–2 VT engines flag domain as suspicious (and 0 malicious) |
| **Domain: Complete Authentication Failure** | critical | 20 | SPF ∈ {fail, softfail} AND DKIM ∈ {fail, none} AND DMARC = fail — all three fail simultaneously |
| **Very New Domain (< 7 days)** | critical | 20 | WHOIS creation date < 7 days ago |
| **New Domain (< 30 days)** | high | 12 | WHOIS creation date < 30 days ago (and ≥ 7 days) |

**Key decisions:**

- **Mutually exclusive age thresholds**: Only the higher-scoring threshold fires. A 3-day-old domain gets 20 pts, NOT 20 + 12 = 32. This prevents double-counting the same data point.
- **Per-request domain cache**: A dict passed through the call chain avoids duplicate WHOIS lookups if the same domain appears in multiple signals.
- **WHOIS is synchronous**: `python-whois` is blocking, so it's wrapped in `asyncio.run_in_executor()` with the same 3-second timeout.
- **`creation_date` normalization**: python-whois can return a single datetime, a list, or None. The engine extracts the minimum (earliest) date from whatever it gets.
- **Complete auth failure signal**: This is a domain-category signal distinct from the individual header-category SPF/DKIM/DMARC signals. It detects that the domain has *zero* valid authentication posture — a stronger indicator than any single protocol failure.

### 2.5 Behavioral Analysis (`behavior.py`)

**Category**: `behavior` · **Cap**: 10 pts · **I/O**: None (pure regex)

Scans the email body for social engineering patterns.

| Signal | Severity | Points | Trigger Condition |
|--------|----------|--------|-------------------|
| **Suspicious Body Content** | medium | 10 | ≥ 1 urgency/threat pattern OR credential solicitation pattern matches |

**Urgency patterns** (regex, case-insensitive):
- `account.{0,20}(suspend|terminat|clos|lock|disabl)`
- `(immediate|urgent|action required|act now|respond within)`
- `(24 hours?|48 hours?|within \d+ hours?)`
- `(expire[s]?|expiring soon|last.{0,10}chance)`
- `verify.{0,20}(identity|account|information)`
- `click here to (confirm|verify|restore|unlock)`

**Credential patterns** (regex, case-insensitive):
- `enter.{0,20}(password|credit card|ssn|social security)`
- `provide.{0,20}(banking|card number|pin|passcode)`
- `confirm.{0,20}(your details|payment|billing)`

**Key decisions:**

- **Single signal, max 10 pts**: Even if both urgency and credential patterns match, only one Signal fires (at 10 pts). The description lists all matched categories.
- **Prefers plain-text body**: Falls back to HTML with tags stripped via regex if plain text is empty.
- **Privacy**: Only the matched phrase substring (not the full body) is recorded in the signal value. These excerpts are passed to the AI explainer — never the complete body text.

---

## 3. Signal Model

Every signal fired by any engine is a `Signal` Pydantic model:

```python
class Signal(BaseModel):
    name: str              # e.g. "SPF Fail"
    category: str          # "header" | "url" | "ip" | "domain" | "behavior"
    severity: str          # "low" | "medium" | "high" | "critical"
    description: str       # Human-readable explanation
    value: Optional[str]   # Raw value that triggered it, e.g. "spf=fail"
    points: int            # Weight this signal contributes to the score
```

Severity is assigned per-signal based on the seriousness of the finding:

| Severity | Meaning | Typical Points |
|----------|---------|---------------|
| `critical` | Active threat indicator, strong phishing signal | 15–20 |
| `high` | Significant concern, common in phishing | 8–15 |
| `medium` | Warrants attention, may be benign | 5–10 |
| `low` | Minor anomaly, informational | 3–5 |

---

## 4. Scoring Formula

### 4.1 Category Caps

Each category has a maximum number of points it can contribute, preventing any single signal type from dominating the score:

| Category | Cap | Rationale |
|----------|-----|-----------|
| `header` | 45 | Authentication is the most reliable indicator. SPF+DKIM+DMARC failure covers 45 pts. |
| `url` | 55 | URLs are the primary attack vector. VT + Safe Browsing + typosquatting can reach 55. |
| `ip` | 20 | Single data source (AbuseIPDB). Two additive thresholds fill the cap exactly. |
| `domain` | 20 | Supports but doesn't dominate. New domain OR VT reputation fills it. |
| `behavior` | 10 | Regex-based — lower confidence than API-backed signals. Capped low to avoid false positives. |
| **Total** | **150** | Sum of all caps = effective maximum denominator. |

### 4.2 Normalization

```
Step 1:  category_raw[cat]    = sum of all signal points in that category
Step 2:  category_capped[cat] = min(category_raw[cat], CATEGORY_CAPS[cat])
Step 3:  capped_total         = sum of all category_capped values
Step 4:  effective_max        = sum of all CATEGORY_CAPS = 150
Step 5:  score                = min(100, round(capped_total / effective_max * 100))
```

Formula: **`score = min(100, round(capped_points / 150 × 100))`**

### 4.3 Worked Example

An email where:
- SPF fails (15 pts) and DKIM fails (15 pts) → header raw = 30, capped = 30
- VirusTotal flags a URL (20 pts) + shortener detected (5 pts) → url raw = 25, capped = 25
- AbuseIPDB 80% confidence → 12 + 8 = 20 pts → ip raw = 20, capped = 20
- Domain is 5 days old (20 pts) → domain raw = 20, capped = 20
- Urgency language detected (10 pts) → behavior raw = 10, capped = 10

```
capped_total = 30 + 25 + 20 + 20 + 10 = 105
score        = min(100, round(105 / 150 * 100))
             = min(100, round(70.0))
             = 70
verdict      → MALICIOUS (66–100 range)
```

---

## 5. Verdict Thresholds

The final score maps to a verdict using fixed ranges:

| Score Range | Verdict | Color | Meaning |
|-------------|---------|-------|---------|
| 0 – 30 | `SAFE` | Green | No meaningful risk detected |
| 31 – 65 | `SUSPICIOUS` | Orange | Anomalies present — proceed with caution |
| 66 – 100 | `MALICIOUS` | Red | Active threat indicators — do not engage |

The thresholds are intentionally simple and non-overlapping. The lower boundary for `MALICIOUS` (66) was chosen so that a single-category maxed out alone rarely pushes above it — multiple corroborating categories are typically needed for a malicious verdict.

---

## 6. Confidence System

Confidence starts at **100%** and is reduced when external data sources are unavailable:

| Unavailable Source | Penalty | When It Triggers |
|-------------------|---------|-----------------|
| VirusTotal | –20 | API key missing, timeout, 429 rate limited |
| Safe Browsing | –15 | API key missing, timeout, non-200 response |
| AbuseIPDB | –10 | API key missing, timeout, 429 rate limited |
| WHOIS | –10 | Timeout, lookup failure, no creation date returned |

**Additional penalty**: If `parse_warning_count ≥ 2` across all engines, an additional **–10** penalty is applied. Parse warnings are generated when headers are missing, unparseable, or ambiguous.

Confidence is clamped to `[0, 100]` and labeled:

| Confidence Range | Label |
|-----------------|-------|
| ≥ 80% | `High` |
| 50 – 79% | `Medium` |
| < 50% | `Low` |

**Why confidence matters**: A score of 5 with High confidence means "definitely safe." A score of 5 with Low confidence means "we couldn't check enough sources to be sure." The add-on displays both so users can gauge how much to trust the verdict.

---

## 7. AI Explanation Layer

After scoring, GPT-4o generates a 2–3 sentence plain-English explanation.

**Input to GPT-4o** (privacy-conscious):
- Score and verdict
- Top 3 signals (name + description + value)
- Matched urgency/credential phrases only (not the full email body)

**System prompt role**: "Cybersecurity analyst reviewing an email for a non-technical user."

**Parameters**: `temperature=0.3`, `max_tokens=200` — biased toward deterministic, concise output.

**Fallback**: If OpenAI is unavailable (no API key, timeout, error), a deterministic template generates the explanation from the top signals. The add-on never shows a blank explanation card.

| Condition | Template Pattern |
|-----------|-----------------|
| SAFE + no signals | "This email passed all security checks…" |
| SAFE + signals | "This email appears safe with a score of X/100…" |
| SUSPICIOUS | Lists top signal names + "Exercise caution…" |
| MALICIOUS | Lists top signal names + "Do not click any links…" |

---

## 8. Top Contributors & Evidence

### Top Contributors

The **3 highest-scoring signals** (sorted by `points` descending) are selected as `top_contributors`. These are displayed prominently in the add-on's THREAT INTEL section.

### Evidence Log

Every fired signal generates an `EvidenceItem`:

```python
class EvidenceItem(BaseModel):
    signal: str       # Signal name
    source: str       # Data source (e.g., "AbuseIPDB", "Email Headers")
    raw_value: str    # The exact data point that triggered it
    points: int       # Points contributed
```

Source mapping:
| Category | Source Label |
|----------|-------------|
| `header` | "Email Headers" |
| `url` | "VirusTotal / Safe Browsing" |
| `ip` | "AbuseIPDB" |
| `domain` | "VirusTotal / WHOIS" |
| `behavior` | "Body Content Analysis" |

---

## 9. Design Decisions & Rationale

### D1 — Behavior engine existence
The original plan had no behavior module. A 10-point capped category was added to catch social engineering language that doesn't appear in technical signals (headers, IPs, URLs).

### D2 — Environment validation at startup
`pydantic-settings` validates all env vars at import time. Missing keys surface immediately on deployment — not mid-request when a user scans their first email.

### D3 — Per-request domain cache
A dict is passed through the signal pipeline so WHOIS results are shared within a single analysis. This avoids redundant lookups if the same domain appears in multiple contexts.

### D4 — Rate limiting
`slowapi` enforces 30 req/min per IP on `/analyze`. Prevents abuse and protects downstream VirusTotal/AbuseIPDB quotas.

### D5 — Typosquatting via Levenshtein
`rapidfuzz` provides O(n²) string distance in C. Levenshtein distance ≤ 2 catches common substitutions (`paypa1.com`, `paypall.com`) without flooding false positives.

### D7 — No `from __future__ import annotations` in main.py
PEP 563 deferred evaluation breaks Pydantic v2's route-parameter resolution. Annotations like `body: AnalyzeRequest` become strings and Pydantic can't resolve them. All other files use PEP 563 safely.

### A3 — Mutually exclusive domain age thresholds
A domain that is 3 days old fires the `< 7 days` signal (20 pts) only — not both `< 7 days` AND `< 30 days`. This prevents double-counting identical data.

### A4 — Additive AbuseIPDB thresholds (report-count-aware)
Unlike domain age, IP reputation thresholds ARE additive. A confidence of 80% fires both the > 25% signal and > 75% bonus. However, the points now scale with `totalReports`: ≥ 10 reports earns full points (12 + 8 = 20), 3–9 reports earns moderate points (8 + 4 = 12), and 1–2 reports earns reduced points (4 + 2 = 6). Rationale: a single spurious reporter should not produce the same score as broad community consensus.

### A6 — First external IP, not last
Email `Received` headers are stacked top-down as the message traverses servers. The first non-private IP is the originating external server — the actual sender. The last hop is usually a Google internal relay and would be meaningless to query.

### A8 — Privacy: signal summaries only to OpenAI
The full email body is never sent to GPT-4o. Only signal metadata and short matched urgency phrases are included in the prompt. This limits exposure while still enabling useful narrative generation.

---

## 10. Complete Signal Reference Table

| # | Signal Name | Category | Severity | Points | Source | Trigger |
|---|------------|----------|----------|--------|--------|---------|
| 1 | SPF Fail | header | high | 15 | Auth-Results header | `spf=fail\|softfail` |
| 2 | DKIM Fail | header | high | 15 | Auth-Results header | `dkim=fail\|none` |
| 3 | DMARC Fail | header | high | 15 | Auth-Results header | `dmarc=fail` |
| 4 | Reply-To Domain Mismatch | header | medium | 8 | From + Reply-To headers | Different domains |
| 5 | Display Name Spoofing | header | high | 10 | From header | Brand name in display, wrong domain |
| 6 | VirusTotal: URL Flagged Malicious | url | critical/high/medium | 20/12/5 | VirusTotal API | ≥10 / 3–9 / 1–2 engines flag URL |
| 7 | Safe Browsing: URL Flagged | url | critical | 20 | Google Safe Browsing | Threat match found |
| 8 | URL Shortener Detected | url | low | 5 | Regex domain match | Known shortener domain |
| 9 | Typosquatted Domain | url | high | 10 | rapidfuzz Levenshtein | Distance ≤ 2 to brand domain |
| 10 | AbuseIPDB: Sender IP Reported | ip | high/medium/low | 12/8/4 | AbuseIPDB API | Confidence > 25%, scaled by totalReports (≥10 / 3–9 / 1–2) |
| 11 | AbuseIPDB: High-Confidence Abusive IP | ip | critical/high/medium | 8/4/2 | AbuseIPDB API | Confidence > 75% (additive), scaled by totalReports |
| 12 | VirusTotal: Malicious Domain | domain | critical/high/medium | 20/12/5 | VirusTotal Domain API | ≥10 / 3–9 / 1–2 engines flag malicious |
| 13 | VirusTotal: Suspicious Domain | domain | high/medium/low | 10/6/3 | VirusTotal Domain API | ≥10 / 3–9 / 1–2 engines flag suspicious |
| 14 | Domain: Complete Auth Failure | domain | critical | 20 | Auth-Results header | SPF+DKIM+DMARC all fail |
| 15 | Very New Domain (< 7 days) | domain | critical | 20 | WHOIS | Created < 7 days ago |
| 16 | New Domain (< 30 days) | domain | high | 12 | WHOIS | Created 7–29 days ago |
| 17 | Suspicious Body Content | behavior | medium | 10 | Body regex | Urgency or credential patterns |

**Maximum theoretical score**: If every signal in every category fires at maximum, `capped_total = 150` → `score = 100`.

**Minimum non-zero score**: A single URL shortener (5 pts) → `round(5/150 × 100) = 3`.
