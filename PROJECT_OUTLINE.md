# Gmail Add-on: Malicious Email Scorer
### Upwind Student Program — Home Task

---

## The Meta-Goal: Standing Out

> Everyone uses AI today. The question is whether you use it like a tool, or like an engineer.

This project is not just a home task — it is a **live presentation during an interview**. The goal is to demonstrate three things simultaneously:

1. **Spec-driven development** — I didn't start coding. I started by deeply understanding the problem, defining scope, making explicit trade-off decisions, and writing a spec. The code is the last step, not the first.
2. **Architectural maturity** — the system is designed in layers with clear boundaries, not a pile of scripts. Every design decision has a reason.
3. **I am a builder** — not someone who prompted ChatGPT and got a repo. Every component is understood, every trade-off is owned, and the demo works end-to-end on a real email.

### How to signal this during the interview:
- Walk them through the spec *before* showing the code — explain what you chose to build and what you deliberately left out, and *why*
- Narrate the architecture diagram before clicking anything
- When they ask "why FastAPI?" or "why this scoring model?" — have a specific, principled answer ready
- The demo should feel like a product, not a school project

---

## Objective

Build a Gmail Add-on that analyzes an opened email and produces a **maliciousness score** with a clear, AI-generated explainable verdict.  
The tool should act as a **second opinion security analyst** — not just flagging emails, but explaining *why* they are dangerous in plain language.

---

## Interview Demo Strategy

### The narrative arc (present it in this order):
1. **The problem** — "Phishing emails trick humans because they look legitimate. Rule-based spam filters miss them. I wanted to build something smarter."
2. **The process** — "Before writing a single line of code, I read the spec, mapped the capabilities, made explicit scope decisions, and designed the architecture." *(show this doc)*
3. **The architecture** — walk through the diagram, explain each layer and why it exists
4. **The demo** — open a real phishing email, click Analyze, show the verdict
5. **The reflection** — "Here's what I'd build next, and here's what I intentionally left out for now"

### The wow moment:
Open a real-looking phishing email → click **"Analyze"** → sidebar shows:
- A `MALICIOUS` verdict in red with score 0–100
- Per-signal breakdown (which checks fired and why)
- LLM-generated plain-English paragraph: *"This email impersonates PayPal. The sending domain was registered 3 days ago, the link was flagged by 14 VirusTotal engines, and the body uses fear language to pressure the user into clicking."*

That last part is the wow — it reads like a human security analyst wrote it.

---

## Architecture

### Design Principles (be ready to articulate these)

| Principle | Decision | Why |
|---|---|---|
| **Separation of concerns** | Frontend (Apps Script) knows nothing about scoring logic | Lets you swap the backend independently |
| **AI as explainability layer, not oracle** | Rule-based signals run first; AI only narrates the result | Deterministic scoring + human-readable output; avoids AI hallucinating verdicts |
| **Defense in depth** | Multiple independent signal sources (headers + URLs + IP + body) | No single API failure kills the analysis |
| **Fail gracefully** | Each signal is optional; missing API key = signal skipped, not crash | Production mindset even in a demo |
| **Thin client** | The Gmail add-on only renders; all logic lives in the backend | Keeps API keys server-side, UI stays clean |

### System Diagram

```
Gmail Add-on (Google Apps Script)
        │
        │  POST /analyze  { subject, sender, headers, body, urls[] }
        ▼
FastAPI Backend (Python) — deployed on Render (free tier)
        │
        ├── 1. Pre-processing
        │     ├── Extract all URLs from body
        │     ├── Parse authentication headers (SPF / DKIM / DMARC)
        │     └── Extract sender IP from Received headers
        │
        ├── 2. Signal Engine (runs in parallel)
        │     ├── Header checks   → SPF/DKIM/DMARC fail, domain age, display name spoof
        │     ├── URL checks      → VirusTotal + Google Safe Browsing per URL
        │     └── IP reputation   → AbuseIPDB sender IP score
        │
        ├── 3. Scoring Engine
        │     ├── Weighted signal aggregation → score 0–100
        │     ├── Verdict: SAFE / SUSPICIOUS / MALICIOUS
        │     └── Top 3 contributing factors selected
        │
        └── 4. AI Explanation Layer (OpenAI GPT-4o)
              ├── Input: verdict + score + top signals
              └── Output: 2–3 sentence plain-English analyst narrative

Response → { score, verdict, signals[], explanation }
        │
        ▼
Gmail Sidebar renders: verdict badge, score bar, signal cards, AI explanation
```

### Why this architecture is the right call (interview talking points)

- **Why not put everything in Apps Script?** — Apps Script can't securely store API keys, has execution time limits, and mixing UI and business logic makes it untestable.
- **Why FastAPI and not Node/Express?** — Python has the best ecosystem for security tooling (python-whois, requests, etc.), and FastAPI gives async support out of the box for parallel API calls.
- **Why run signals in parallel?** — VirusTotal + AbuseIPDB + Safe Browsing are 3 separate HTTP calls; sequential would triple the latency. Parallel keeps the demo snappy.
- **Why is AI the last step, not the first?** — If you send raw email text to GPT and ask "is this malicious?", you get a hallucination-prone black box with no auditability. By running deterministic signals first and only using AI to *narrate* the results, you get the best of both worlds: reliable scoring + human-readable explanation.

---

## Scope

### In Scope (MVP + wow factor)

| Feature | Priority | Notes |
|---|---|---|
| Email content & metadata analysis | MVP | Headers, sender domain, body patterns |
| URL scanning | MVP | VirusTotal + Google Safe Browsing |
| Sender IP reputation | MVP | AbuseIPDB — quick win, big signal |
| Risk score (0–100) + Verdict | MVP | SAFE / SUSPICIOUS / MALICIOUS |
| AI-generated explanation | WOW | GPT-4o / Gemini narrates why the email is risky |
| Signal breakdown UI | WOW | Show top contributing factors in sidebar |

### Out of Scope (mention in README as future work)

| Feature | Reason skipped |
|---|---|
| Attachment analysis | High complexity, sandboxing risk |
| User-managed blacklist | Architected for it — not built |
| History of actions | Not enough time ROI for demo |
| Management console | Out of scope for MVP |

---

## Signal Engine — Detailed Spec

### 1. Header & Metadata Checks
| Signal | Weight | How to detect |
|---|---|---|
| SPF fail | High | Parse `Authentication-Results` header |
| DKIM fail | High | Parse `Authentication-Results` header |
| DMARC fail | High | Parse `Authentication-Results` header |
| Sender domain age < 30 days | High | WHOIS lookup (via `python-whois`) |
| Reply-To ≠ From domain | Medium | Compare header fields |
| Display name spoofing | Medium | Name says "PayPal" but domain is not paypal.com |

### 2. URL Scanning
| Signal | Weight | API |
|---|---|---|
| URL flagged as malicious | Critical | VirusTotal (4 req/min free) |
| URL flagged as phishing | Critical | Google Safe Browsing (generous free tier) |
| URL uses URL shortener | Medium | Pattern match (bit.ly, tinyurl, etc.) |
| Typosquatted domain | Medium | Levenshtein distance vs known brands |

### 3. Sender IP Reputation
| Signal | Weight | API |
|---|---|---|
| IP reported for abuse/spam | High | AbuseIPDB (1000 req/day free) |
| IP confidence of abuse > 50% | High | AbuseIPDB score field |

### 4. Body Content (AI-assisted)
| Signal | How |
|---|---|
| Urgency / fear language | LLM prompt |
| Requests for credentials / PII | LLM prompt |
| Impersonation of known brand | LLM prompt |
| Suspicious call-to-action | LLM prompt |

---

## Scoring Model

```
final_score = weighted_sum(signals) / max_possible_score * 100

Verdict:
  0–30   → SAFE       (green)
  31–65  → SUSPICIOUS (orange)
  66–100 → MALICIOUS  (red)
```

Each signal contributes a weighted point value. The top 3 contributing signals are surfaced in the UI.

---

## AI Explanation Prompt (sketch)

```
System: You are a cybersecurity analyst. Analyze the following email signals 
and explain in 2-3 sentences why this email is or isn't dangerous.
Be specific, clear, and avoid jargon.

User: 
Signals detected:
- SPF: FAIL
- Domain age: 2 days
- VirusTotal: 12/90 engines flagged the URL
- Body: Contains urgency language ("Your account will be suspended")

Verdict: MALICIOUS (score: 84)

Explain why.
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Add-on frontend | Google Apps Script (HTML sidebar) |
| Backend | Python + FastAPI |
| Deployment | Render.com (free tier) |
| Threat intel | VirusTotal, Google Safe Browsing, AbuseIPDB |
| AI | OpenAI GPT-4o (or Gemini as fallback) |
| Domain age | `python-whois` |
| URL extraction | `beautifulsoup4` / regex |

---

## Build Plan (this week)

### The process itself is part of the story — follow this order:

| Day | Task | Why this order |
|---|---|---|
| Day 1 | Write the spec (this doc), define API contract, draw architecture | Spec first — no code until the design is clear |
| Day 2 | Scaffold FastAPI backend, implement Signal Engine (headers + URLs + IP) | Core logic before UI |
| Day 3 | Integrate AI explanation layer (GPT-4o), finalize scoring model | Add intelligence on top of working foundation |
| Day 4 | Build Apps Script add-on + sidebar UI | Frontend last — it's just a renderer |
| Day 5 | End-to-end testing, polish UI, prepare demo emails, rehearse narrative | Demo is a product, not a prototype |

### Demo email samples to prepare:
1. A PayPal phishing email (mismatched domain + VirusTotal URL hit)
2. A fake "your account is suspended" email (urgency language + new domain)
3. A legitimate email from a known sender (to show the SAFE verdict works too)

---

## Deliverables

- [ ] Source code (backend + add-on)
- [ ] README (architecture, APIs used, features, limitations)
- [ ] Live demo in Gmail during interview
- [ ] 2–3 prepared phishing email samples for the demo

---

## External APIs — Keys Needed

| API | Where to get | Free tier |
|---|---|---|
| VirusTotal | virustotal.com/gui/join-us | 4 req/min |
| Google Safe Browsing | console.cloud.google.com | Very generous |
| AbuseIPDB | abuseipdb.com | 1000 req/day |
| OpenAI | platform.openai.com | Pay-per-use (~$0.01/analysis) |
