# Implementation Plan — Gmail Malicious Email Scorer

---

## TL;DR

Build a Gmail Add-on (Apps Script via `clasp`) that sends email data to a FastAPI backend on **Google Cloud Run**. The backend runs parallel threat-intel checks (VirusTotal, Google Safe Browsing, AbuseIPDB, WHOIS) + header validation, generates a weighted score 0–100, then feeds the signals to **OpenAI GPT-4o** for a plain-English explanation. The Gmail sidebar renders the verdict, signal breakdown, and AI narrative.

**Key decisions:**
- Backend: Google Cloud Run (free tier, ~5–10s cold starts, fits Google ecosystem narrative)
- AI: OpenAI GPT-4o (~$0.01/analysis, best explanation quality)
- Dev workflow: `clasp` (local VS Code, git-friendly)
- Card UI only — Gmail add-ons do **not** support HTML sidebars

---

## Project Structure

```
Gmail_Add_One/
├── backend/
│   ├── main.py                  ← FastAPI app, /analyze + /health endpoints
│   ├── models.py                ← Pydantic request/response schemas
│   ├── scoring.py               ← Weighted signal aggregation + verdict
│   ├── ai_explainer.py          ← OpenAI GPT-4o call
│   ├── config.py                ← Env vars and API keys
│   ├── requirements.txt
│   ├── Dockerfile
│   └── signal_engine/
│       ├── headers.py           ← SPF / DKIM / DMARC parsing
│       ├── urls.py              ← VirusTotal + Google Safe Browsing
│       ├── ip_reputation.py     ← AbuseIPDB
│       └── domain_age.py        ← WHOIS domain registration check
├── addon/
│   ├── Code.gs                  ← Entry point, contextual trigger handler
│   ├── Cards.gs                 ← CardService UI builders
│   ├── Api.gs                   ← UrlFetchApp call to backend
│   ├── appsscript.json          ← Manifest: scopes, triggers, branding
│   └── .clasp.json              ← clasp project config
├── PLAN.md                      ← This file
├── PROJECT_OUTLINE.md
├── ASSIGNMENT.md
└── README.md
```

---

## Phase 0 — Project Setup

| # | Task | Notes |
|---|---|---|
| 0.1 | Install `clasp` globally | `npm install -g @google/clasp` then `clasp login` |
| 0.2 | Create Apps Script project | `cd addon && clasp create --type standalone --title "Email Security Scanner"` |
| 0.3 | Link a GCP project | script.google.com > Project Settings > GCP project (needed for OAuth consent screen + Safe Browsing API) |
| 0.4 | Set up Python venv in `backend/` | `python -m venv .venv` then install fastapi, uvicorn, httpx, python-whois, openai, pydantic, slowapi |
| 0.5 | Write `Dockerfile` | Python 3.12-slim, install requirements, run `uvicorn main:app --host 0.0.0.0 --port $PORT` |
| 0.6 | Install Google Cloud CLI | `gcloud init`, create a Cloud Run service |
| 0.7 | Get all API keys | VirusTotal, AbuseIPDB, Google Safe Browsing (from GCP), OpenAI |

---

## Phase 1 — Define the API Contract (spec-first, no code yet)

> Write the Pydantic models before any logic. This defines the system's language.

### `POST /analyze` — Request model

```python
class AnalyzeRequest(BaseModel):
    subject: str
    sender: str                         # "Display Name <email@domain.com>"
    reply_to: Optional[str]
    authentication_results: Optional[str]  # raw "Authentication-Results" header
    received_headers: list[str]            # all "Received" headers (ordered)
    body_plain: str
    body_html: str
    urls: list[str]                        # pre-extracted from body
    message_date: Optional[str]
```

### `POST /analyze` — Response model

```python
class Signal(BaseModel):
    name: str                              # e.g. "SPF Fail"
    category: str                          # "header" | "url" | "ip" | "domain"
    severity: str                          # "low" | "medium" | "high" | "critical"
    description: str                       # human-readable explanation of this signal
    value: Optional[str]                   # the raw value that triggered it (e.g. "2 days old")
    points: int                            # weight contributed to score

class AnalyzeResponse(BaseModel):
    score: int                             # 0–100
    verdict: str                           # "SAFE" | "SUSPICIOUS" | "MALICIOUS"
    signals: list[Signal]                  # all signals that fired
    top_contributors: list[Signal]         # top 3 by points
    explanation: str                       # GPT-4o narrative
    analysis_time_ms: int
```

### `GET /health`

```python
{"status": "ok", "version": "1.0.0"}
```

---

## Phase 2 — Signal Engine

> All 4 signal categories run **in parallel** via `asyncio.gather()`. Each returns `list[Signal]`.

### 2.1 — Header Analysis (`signal_engine/headers.py`)

| Signal | Points | How to detect |
|---|---|---|
| SPF: FAIL | 15 | Parse `Authentication-Results` header — look for `spf=fail` or `spf=softfail` |
| DKIM: FAIL | 15 | Parse `Authentication-Results` — look for `dkim=fail` or `dkim=none` |
| DMARC: FAIL | 15 | Parse `Authentication-Results` — look for `dmarc=fail` |
| Reply-To ≠ From domain | 8 | Extract domains from both fields, compare |
| Display name spoofing | 10 | Display name contains a known brand (PayPal, Amazon, etc.) but domain doesn't match |

**How to parse `Authentication-Results`:**
```
dkim=pass → PASS (0 points)
dkim=fail → FAIL (15 points)
spf=pass  → PASS
spf=fail  → FAIL (15 points)
dmarc=pass → PASS
dmarc=fail → FAIL (15 points)
```

### 2.2 — URL Scanning (`signal_engine/urls.py`)

| Signal | Points | API |
|---|---|---|
| URL flagged malicious | 20 | VirusTotal — `POST /api/v3/urls`, check `positives` count |
| URL flagged phishing | 20 | Google Safe Browsing — `POST /v4/threatMatches:find` (batch all URLs) |
| URL shortener detected | 5 | Regex match against list: bit.ly, tinyurl, t.co, ow.ly, goo.gl, etc. |
| Typosquatted domain | 10 | Levenshtein distance ≤ 2 vs. top 50 brand domains |

**VirusTotal rate limit mitigation:** Scan max 3 unique domains per email. Cache domain → verdict in a simple dict. Skip gracefully if rate-limited (429 response).

**Brand list for typosquatting:** paypal, amazon, microsoft, google, apple, netflix, linkedin, facebook, instagram, twitter, wellsfargo, chase, bankofamerica, dropbox, docusign, etc.

### 2.3 — IP Reputation (`signal_engine/ip_reputation.py`)

| Signal | Points | How |
|---|---|---|
| AbuseIPDB confidence > 25% | 12 | Extract sender IP from last `Received` header via regex, query AbuseIPDB |
| AbuseIPDB confidence > 75% | +8 bonus | Same call, higher threshold |

**IP extraction from `Received` header:**
```
Received: from mail.evil.com (mail.evil.com [1.2.3.4]) ...
                                                ↑ extract this IP
```
Regex: `\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]` on the last `Received` header.

### 2.4 — Domain Age (`signal_engine/domain_age.py`)

| Signal | Points | How |
|---|---|---|
| Sender domain age < 7 days | 20 | `python-whois` lookup on sender domain |
| Sender domain age < 30 days | 12 | same lookup |

Extract sender domain from the `From` header email address. Cache results — WHOIS is slow (~1–3s) and rarely needed more than once per domain per session.

---

## Phase 3 — Scoring Engine (`scoring.py`)

```
Total possible points: 150

final_score = min(100, round(sum(triggered_points) / 150 * 100))

Verdict thresholds:
  0  – 30  → SAFE        (green  #34a853)
  31 – 65  → SUSPICIOUS  (orange #f9ab00)
  66 – 100 → MALICIOUS   (red    #d93025)
```

**Top 3 contributors:** sort triggered signals by `points` descending, take first 3. These are what the UI surface prominently.

---

## Phase 4 — AI Explanation Layer (`ai_explainer.py`)

### System prompt
```
You are a cybersecurity analyst reviewing an email for a non-technical user.
Given the following signals and verdict, explain in exactly 2–3 sentences
why this email is or isn't dangerous. Be specific about which signals matter
most. Use simple language. Address the user directly (use "this email...").
Do not repeat the score or verdict word-for-word.
```

### User prompt (injected dynamically)
```
Verdict: MALICIOUS (score: 84/100)

Signals detected:
- SPF: FAIL (the sender domain is not authorized to send this email)
- Domain age: 2 days old (domain was registered very recently)
- VirusTotal: 14 out of 90 engines flagged the URL as malicious
- Body: Contains urgency language ("Your account will be suspended in 24 hours")

Explain why this email is dangerous.
```

### Model config
- Model: `gpt-4o`
- Temperature: `0.3` (deterministic, consistent)
- Max tokens: `200`
- Fallback: if OpenAI call fails → generate template string from top 3 signals (no crash)

---

## Phase 5 — Gmail Add-on (Apps Script via clasp)

### 5.1 — Manifest (`appsscript.json`)

```json
{
  "timeZone": "Asia/Jerusalem",
  "exceptionLogging": "STACKDRIVER",
  "runtimeVersion": "V8",
  "oauthScopes": [
    "https://www.googleapis.com/auth/gmail.addons.current.message.readonly",
    "https://www.googleapis.com/auth/gmail.addons.current.message.metadata",
    "https://www.googleapis.com/auth/script.external_request",
    "https://www.googleapis.com/auth/userinfo.email"
  ],
  "addOns": {
    "common": {
      "name": "Email Security Scanner",
      "logoUrl": "https://YOUR_HOSTED_ICON_URL",
      "layoutProperties": {
        "primaryColor": "#1a73e8",
        "secondaryColor": "#d93025"
      },
      "homepageTrigger": { "runFunction": "onHomepage" }
    },
    "gmail": {
      "contextualTriggers": [
        {
          "unconditional": {},
          "onTriggerFunction": "onGmailMessageOpen"
        }
      ]
    }
  }
}
```

### 5.2 — Entry point (`Code.gs`)

- `onGmailMessageOpen(e)` — contextual trigger fires when user opens any email
  1. Call `GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken)` — **required before any GmailApp call**
  2. Return an initial card with the email subject + "Analyze Email" button
- `analyzeEmail(e)` — action callback on button click
  1. Get message via `GmailApp.getMessageById(e.gmail.messageId)`
  2. Extract all data (see step 5.3)
  3. Call backend via `Api.gs`
  4. Build and return result card via `Cards.gs`
- `onHomepage()` — shown when no email is open (welcome/instructions card)

> **Critical:** Contextual trigger functions must return an **array** of cards, not a single card: `return [card]`

### 5.3 — Data extraction in Apps Script

> Use `message.getRawContent()` — not `message.getHeader()`. `getHeader()` only returns the **first** matching header, which misses multiple `Received` headers needed for IP extraction.

```javascript
var raw = message.getRawContent();

// Extract all "Received" headers
var receivedHeaders = [];
var receivedMatches = raw.match(/^Received:.*(?:\r?\n[ \t].*)*/gmi);
if (receivedMatches) receivedHeaders = receivedMatches;

// Extract Authentication-Results header
var authMatch = raw.match(/^Authentication-Results:.*(?:\r?\n[ \t].*)*/mi);
var authResults = authMatch ? authMatch[0] : "";

// Extract URLs from HTML body
var body = message.getBody();
var urlMatches = body.match(/https?:\/\/[^\s"'<>]+/g) || [];
var urls = [...new Set(urlMatches)].slice(0, 10); // deduplicate, cap at 10
```

### 5.4 — Backend call (`Api.gs`)

```javascript
function callAnalyzeEndpoint(payload) {
  var apiKey = PropertiesService.getScriptProperties().getProperty('BACKEND_API_KEY');
  var backendUrl = PropertiesService.getScriptProperties().getProperty('BACKEND_URL');

  var options = {
    method: 'post',
    contentType: 'application/json',
    payload: JSON.stringify(payload),
    headers: { 'X-API-Key': apiKey },
    muteHttpExceptions: true   // never let UrlFetchApp throw — handle errors manually
  };

  var response = UrlFetchApp.fetch(backendUrl + '/analyze', options);
  var code = response.getResponseCode();

  if (code !== 200) {
    return { error: 'Backend returned ' + code };
  }
  return JSON.parse(response.getContentText());
}
```

> API keys are **never hardcoded**. Store them once via a setup function that calls `PropertiesService.getScriptProperties().setProperty(...)`.

### 5.5 — Card UI (`Cards.gs`)

**Initial card** (shown on email open):
- Header: "Email Security Scanner" + shield icon
- Section: email subject + sender
- Fixed footer: "🔍 Analyze Email" button (triggers `analyzeEmail`)

**Result card** (shown after analysis):
```
┌─────────────────────────────────┐
│  🛡 Security Analysis            │
│  subject line...                │
├─────────────────────────────────┤
│  [MALICIOUS badge image]  84/100│
│  ████████████             score│
├─────────────────────────────────┤
│  ⚠ SPF Fail     · Domain unauth│
│  ⚠ Domain Age   · Registered 2d│
│  ⚠ VirusTotal   · 14/90 engines│
├─────────────────────────────────┤
│  AI Analysis                    │
│  "This email impersonates PayPal│
│   The sending domain was..."    │
├─────────────────────────────────┤
│  ▸ All signals (collapsible)    │
└─────────────────────────────────┘
```

**Color workaround:** CardService doesn't support arbitrary text colors. Host 3 verdict badge PNG images (green SAFE, orange SUSPICIOUS, red MALICIOUS) somewhere (e.g., GitHub raw or Cloud Run `/assets/`) and use `CardService.newImage().setImageUrl(verdictBadgeUrl)`.

**Error card** (if backend is down or times out):
- Shows a clean "Analysis unavailable" message
- Never crashes — `muteHttpExceptions: true` in the fetch call

---

## Phase 6 — Deploy to Google Cloud Run

```bash
# From backend/ directory:

# 1. Authenticate
gcloud auth login
gcloud config set project YOUR_PROJECT_ID

# 2. Deploy (Cloud Run builds from source via Buildpacks — no Docker needed)
gcloud run deploy email-scanner \
  --source . \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars VIRUSTOTAL_API_KEY=xxx,ABUSEIPDB_API_KEY=xxx,SAFE_BROWSING_API_KEY=xxx,OPENAI_API_KEY=xxx,API_KEY=xxx

# 3. Get the service URL
gcloud run services describe email-scanner --region us-central1 --format='value(status.url)'
```

Then in Apps Script, set the returned URL once:
```javascript
// Run once in the Apps Script editor:
function setup() {
  PropertiesService.getScriptProperties().setProperties({
    'BACKEND_URL': 'https://email-scanner-xxxxx-uc.a.run.app',
    'BACKEND_API_KEY': 'your-secret-key'
  });
}
```

---

## Phase 7 — Testing & Demo Prep

### Test emails to prepare (forward to your Gmail)

| Email | Expected Verdict | Key signals |
|---|---|---|
| PayPal phishing sample | MALICIOUS | SPF fail + VirusTotal URL hit + domain age 3 days + urgency language |
| Fake "account suspended" | SUSPICIOUS | New domain + URL shortener + urgency language |
| Legitimate email from known sender | SAFE | All headers pass + no flagged URLs |

Find real phishing samples at: **PhishTank** (phishtank.org), **OpenPhish** (openphish.com), or create synthetic ones.

### End-to-end checklist
- [ ] All 3 test emails show correct verdict
- [ ] AI explanation is specific and reads naturally
- [ ] Signal breakdown shows correct top 3 contributors
- [ ] Error card shows cleanly if backend is unreachable
- [ ] Total latency < 20 seconds (add-on execution limit is 30s)
- [ ] Re-analyze same email → consistent result

### Demo day protocol
1. Hit `/health` endpoint 60 seconds before interview starts (warm up Cloud Run)
2. Have UptimeRobot (free) pinging `/health` every 10 minutes as backup
3. Have the add-on already installed and authorized in Gmail (no "allow access" dialog during demo)
4. Pre-load the phishing email in Gmail so it's one click away
5. Have a fallback: if backend is down, show the cached result card screenshot and explain the flow

---

## Phase 8 — README & Final Polish

### README structure
1. **What it does** — one paragraph, non-technical
2. **Architecture diagram** (copy from `PROJECT_OUTLINE.md`)
3. **API contract** — request/response shape
4. **Implemented features** — checklist vs. the 8 capabilities in the assignment
5. **External APIs used** — VirusTotal, Safe Browsing, AbuseIPDB, OpenAI, WHOIS
6. **Design decisions** — why each major choice was made
7. **Limitations** — VirusTotal rate limit, no attachment analysis, no history
8. **Future work** — blacklist, history, management console, attachment sandbox

### Git commit order (tells the spec-first story)
```
commit 1: "Add assignment spec and project outline"
commit 2: "Define API contract (request/response models)"
commit 3: "Implement signal engine — headers, URL, IP, domain age"
commit 4: "Implement scoring engine and verdict thresholds"
commit 5: "Add AI explanation layer (GPT-4o)"
commit 6: "Scaffold FastAPI app and /analyze endpoint"
commit 7: "Write Dockerfile and Cloud Run config"
commit 8: "Build Gmail add-on — Code.gs, Cards.gs, Api.gs, manifest"
commit 9: "Deploy to Cloud Run, end-to-end testing"
commit 10: "Write README, final polish"
```

---

## External APIs Summary

| API | Free Tier | Rate Limit | Where to get key |
|---|---|---|---|
| VirusTotal | 500 lookups/day | 4 req/min | virustotal.com/gui/join-us |
| Google Safe Browsing | 10,000 req/day | Generous | console.cloud.google.com → Safe Browsing API |
| AbuseIPDB | 1,000 checks/day | 60/min | abuseipdb.com/register |
| OpenAI (GPT-4o) | Pay-per-use | Tier-based | platform.openai.com (~$0.01/analysis) |
| python-whois | No API key needed | DNS rate limits | pip install python-whois |

---

## Key Technical Gotchas (to know before you start)

| Gotcha | Impact | Fix |
|---|---|---|
| **Add-on execution limit: 30 seconds** | Entire flow (extract + backend call + render) must complete in 30s | Keep backend fast with `asyncio.gather()` for parallel signal checks |
| **Must call `setCurrentMessageAccessToken()`** | All `GmailApp` calls fail without it | Always call it first with `e.gmail.accessToken` |
| **`getHeader()` returns only first match** | Misses multiple `Received` headers | Use `message.getRawContent()` and parse all headers manually |
| **Must return `[card]`, not `card`** | Contextual trigger returns blank if not array | Always return an array |
| **CardService, not HtmlService** | Gmail add-ons only support Card-based UI | Use `CardService` exclusively — no HTML/CSS |
| **VirusTotal 4 req/min** | Multi-URL emails exhaust quota fast | Deduplicate domains, cap at 3, cache results |
| **Cloud Run cold start on free tier** | ~5–10s first request after inactivity | Warm up before demo, use UptimeRobot ping |
| **Never hardcode API keys in .gs files** | Keys are visible in the script editor | Use `PropertiesService.getScriptProperties()` |
| **Manifest changes require reinstall** | Scope/trigger changes don't take effect | Uninstall → Reinstall test deployment after `appsscript.json` changes |
