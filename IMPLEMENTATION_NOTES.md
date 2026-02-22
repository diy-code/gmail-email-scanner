# Implementation Notes
> Living log for the Gmail Malicious Email Scorer project.
> Updated at the end of every phase. Treat this as the audit trail for every non-obvious decision made during coding.

---

## Assumptions

> Every time a decision was made where the plan or requirements were ambiguous,
> it is documented here with: what was assumed, why, and what the alternative was.

| # | Assumption | Reason | Alternative considered |
|---|-----------|--------|----------------------|
| A1 | VirusTotal URL lookup uses `GET /api/v3/urls/{base64_id}` (cached result) rather than `POST /api/v3/urls` (fresh scan submission). | A POST submission returns an analysis ID that requires a follow-up GET to retrieve results — adding a retry loop and latency. Cached lookups are sufficient for demo purposes and respects the 4 req/min free tier. | Full submit-then-poll loop (adds ~2–5s and complexity) |
| A2 | `python-whois` calls are wrapped in `asyncio.get_event_loop().run_in_executor(None, ...)` before being gathered in `asyncio.gather()`. | `python-whois` is synchronous and blocking. Running it directly in an async context would block the event loop and eliminate all parallelism benefits. | Use a dedicated threadpool executor per call |
| A3 | Domain age signals are mutually exclusive: only the higher-scoring threshold fires (< 7 days = 20 pts, < 30 days = 12 pts). If a domain is < 7 days, only 20 pts are added — not 20 + 12 = 32. | Accumulating both would double-count the same WHOIS fact. One finding, one score. | Additive scoring for both thresholds (rejected: artificially inflates score) |
| A4 | AbuseIPDB bonus points are additive: > 25% confidence = 12 pts; if also > 75%, add +8 = 20 pts total. | The plan describes the +8 as a "bonus", implying stacking on top of the base threshold. | Separate mutually exclusive buckets (rejected: plan language says "+8 bonus") |
| A5 | A `behavior` signal module (`signal_engine/behavior.py`) is added despite not being in the plan's Phase 2 signal engine phases. It fills the `behavior: 10` category cap that was explicitly reserved in the scoring engine but left unpopulated. | Without it, the `behavior` cap is dead code and the scoring model would silently never trigger that category. Urgency-keyword detection is low-effort and high-demo-value. | Leave behavior cap unused and remove it from scoring (rejected: creates misleading scoring model) |
| A6 | IP extraction from `Received` headers uses the **first external (non-private) hop**, not the last header. | The last `Received` header may be an internal Gmail relay (127.0.0.1 or 10.x.x.x). The first external hop is the actual mail server that injected the message. | Always use the last Received header (rejected: plan's 2.5 reliability rules explicitly say "prefer earliest external hop") |
| A7 | The `clasp` project type is `standalone` (no Google Sheets/Docs container). The test deployment flow (installing in Gmail) requires creating a test deployment from the Apps Script editor and installing it via the G Suite Marketplace test flow. This is a manual step documented in Phase 5 setup notes. | `clasp create --type standalone --title "..."` creates the project; actual Gmail Add-on installation requires the Apps Script editor UI for test deployments. | Using `--type addon` flag (not a valid clasp type; handled via manifest) |
| A8 | The `body_html` field in the request is passed to the behavior signal engine for urgency keyword extraction. The raw excerpts matched (short phrases, not full paragraphs) are what gets passed into the AI prompt — not the full raw HTML. | Limits OpenAI data exposure to signal summaries and short matched phrases, consistent with the privacy trade-off decision in PLAN.md Phase 4. | Send full body text to OpenAI (rejected: privacy trade-off decision) |

---

## Errors & Issues Encountered

> Every time an error, blocker, or unexpected behavior was hit, it is logged here.

| # | Phase | Error/Issue | Root Cause | How it was resolved |
|---|-------|------------|------------|-------------------|
| E1 | Phase 0 | `python-jose` added to `requirements.txt` unnecessarily | Initial plan noted "UUID handled in stdlib" in a comment but still included the package | Removed python-jose from requirements.txt; `uuid` from stdlib is sufficient |
| E2 | Phase 2 | `analyze_headers` is synchronous but needs to run alongside async signal engines in `asyncio.gather` | `asyncio.gather` requires awaitables; sync functions are not awaitable | Wrapped with `asyncio.get_event_loop().run_in_executor(None, lambda: ...)` in main.py. Note: `analyze_headers` is regex-only (no I/O) so executor overhead is minimal but maintains clean gather pattern |
| E3 | Phase 2 | `analyze_behavior` is synchronous and cannot be placed inside `asyncio.gather` directly | Same reason as E2; but behavior analysis depends on body content which is always available synchronously | Called sequentially after `asyncio.gather()` completes — no latency impact since it's regex-only with no I/O |
| E4 | Phase 3 | `scoring.py` imports `AnalyzeResponse` from `models.py` but `compute_score` does not construct it | Initial import included `AnalyzeResponse` for type reference but it's built in `main.py`, not `scoring.py` | Removed `AnalyzeResponse` from scoring.py imports; it is typed inline in main.py |
| E5 | Phase 7 | `PydanticUndefinedAnnotation: name 'AnalyzeRequest' is not defined` when running integration tests against the FastAPI app | `from __future__ import annotations` (PEP 563) in `main.py` converts all annotations to strings (ForwardRefs) at import time. FastAPI/Pydantic v2 resolves route-parameter types at route-registration time using the module's globals. Pydantic's `TypeAdapter` cannot look up `AnalyzeRequest` from a raw `ForwardRef` in that context, so it falls back to treating the parameter as a Query field with `PydanticUndefined`. | Removed `from __future__ import annotations` from `main.py`. Python 3.9+ supports `dict[k, v]` and `list[x]` natively — the import provided no benefit and introduced a latent production-breaking bug. This is documented under Decision D7 below. |

---

## Decisions & Trade-offs

> Architectural or implementation decisions made during coding that are not in the plan.

| # | Decision | Reason | Impact |
|---|---------|--------|--------|
| D1 | Added `signal_engine/behavior.py` as a 5th signal module | The `behavior: 10` cap in scoring.py was reserved in PLAN.md Phase 3 but no signal module was planned for it. Without it, the cap is dead code. Regex-based urgency detection is < 30 lines and directly improves demo quality. | Fills capability gap #3 (body content analysis) from the assignment. Low implementation risk. |
| D2 | `config.py` uses `pydantic-settings` (`BaseSettings`) to read environment variables, not bare `os.getenv()` | Provides type validation, clear defaults, and instant feedback if a required key is missing at startup. Avoids silent `None` bugs when an env var is misconfigured. | Requires `pydantic-settings` in requirements.txt (separate package in Pydantic v2). |
| D3 | A per-request in-memory domain cache (`dict`) is passed through signal engine calls within a single `/analyze` request to prevent duplicate WHOIS lookups for the same domain. | WHOIS is slow (1–3s) and the same sender domain may appear in both the From header and extracted URLs. One lookup per domain per request. | Redis/external cache (overkill for demo; per-request dict is sufficient) |
| D4 | `slowapi` rate limiter is applied at the `/analyze` endpoint level: 30 requests/minute per IP. | Prevents runaway external API quota exhaustion if the backend is called in a loop. Mentioned in PLAN.md Phase 0 requirements as a dependency but never described further. | No rate limiting (rejected: could exhaust VirusTotal free tier in minutes) |
| D5 | Typosquatting check uses `rapidfuzz` (Levenshtein/Jaro-Winkler) rather than a manual Levenshtein implementation. | `rapidfuzz` is ~100x faster than a pure Python implementation and is widely used in security tooling. Avoids reinventing string distance logic. | Hand-rolled Levenshtein (slower, more test surface) |
| D6 | `request_id` is a UUID4 generated in `main.py` at request intake, injected into all log calls and returned in the response. | Satisfies the observability contract in PLAN.md Phase 6.1 with minimal boilerplate. | nanoid or sequential counter (UUID4 is universally unique with no coordination) |
| D7 | Removed `from __future__ import annotations` from `main.py` (found and fixed during Phase 7 testing). | PEP 563 deferred annotation evaluation makes all function parameter type hints into `ForwardRef` strings. Pydantic v2 cannot resolve `ForwardRef('AnalyzeRequest')` at route-registration time, causing a `PydanticUndefinedAnnotation` crash on startup — a latent production-breaking bug. Python 3.9+ provides `dict[k,v]` and `list[x]` natively so the import was unnecessary. All other files that use `from __future__ import annotations` are safe because their annotations are only read by Pydantic's own model introspection, which handles ForwardRefs correctly. | Keep import in source files that solely define Pydantic models (models.py, scoring.py, etc.) since Pydantic v2 calls `model_rebuild()` internally and resolves all ForwardRefs within the model's module namespace. |

---

## Things to Watch Out For

> Gotchas, known limitations, fragile areas, or things future phases must be careful about.

- **Apps Script 30-second execution limit** — the entire `analyzeEmail()` action (data extraction + backend call + card render) must complete in < 30s. The backend's `asyncio.gather()` parallelism is the key mitigation. If any single external API hangs, the per-signal 3s timeout budget must fire before the add-on times out.
- **`setCurrentMessageAccessToken()` must be called before any `GmailApp` method** — forgetting this causes a silent auth error with no clear error message. It's the first call in `onGmailMessageOpen()`.
- **CardService only supports 1 card returned from a homepage trigger, but contextual triggers must return an array** — `return [card]` not `return card` in all contextual trigger functions.
- **VirusTotal free tier: 4 req/min, 500/day** — the domain cap (max 3 per email) and in-memory deduplication are critical safeguards. Without them, a single email with 10+ links exhausts the minute quota.
- **WHOIS rate limiting** — `python-whois` makes live DNS queries. Some registrars throttle repeated lookups for the same TLD. The per-request domain cache mitigates this within a single analysis.
- **Google Safe Browsing returns an empty response body (not a 404) when no threats are found** — the URL engine must handle both `{}` and `{"matches": [...]}` response shapes.
- **`Authentication-Results` header format varies across MTAs** — the regex parser must tolerate both `spf=pass` and `spf=pass (reason string)` syntax. Test against Gmail, Outlook, and Yahoo samples.
- **Private IP filtering in `Received` header parsing** — Google's internal relay IPs (e.g., `209.85.x.x`) are legitimately Google infrastructure and should not be sent to AbuseIPDB. Only truly external sender IPs should be queried.
- **Cloud Run cold starts (~5–10s)** — always warm up the `/health` endpoint before the demo. Use UptimeRobot to ping every 10 minutes during the interview window.
- **Manifest scope changes require add-on reinstall** — after any change to `appsscript.json` OAuth scopes, the test deployment must be uninstalled and reinstalled. Do this during setup, not the day of the demo.
- **`rapidfuzz` must be in `requirements.txt`** — it is not in Python's stdlib and must be explicitly declared for Cloud Run Buildpacks.
- **OpenAI prompt includes urgency phrase excerpts from the email body** — this is a documented privacy trade-off (PLAN.md Phase 4). No full body text is sent; only the matched urgency phrase strings.

---

## Phase Status

| Phase | Status | Notes |
|-------|--------|-------|
| IMPLEMENTATION_NOTES.md | ✅ Complete | This file |
| Phase 0 — Project Setup | ✅ Complete | `backend/requirements.txt`, `Dockerfile`, `config.py`, `.env.example`, `addon/.clasp.json`, `addon/appsscript.json` scaffolded. Manual steps (clasp login, GCP project link, API key acquisition) documented in PLAN.md Phase 0. |
| Phase 1 — API Contract | ✅ Complete | `backend/models.py` — full `AnalyzeRequest` / `AnalyzeResponse` schema with field-level length constraints, `ScoringBreakdown`, `EvidenceItem`, `Signal`. |
| Phase 2 — Signal Engine | ✅ Complete | `headers.py` (SPF/DKIM/DMARC + spoofing), `urls.py` (VirusTotal + Safe Browsing + shortener + typosquatting), `ip_reputation.py` (AbuseIPDB), `domain_age.py` (WHOIS), `behavior.py` (urgency keywords — fills `behavior: 10` cap). |
| Phase 3 — Scoring Engine | ✅ Complete | `scoring.py` — category caps, confidence degradation, top-3 contributors, evidence log, full arithmetic trace in `ScoringBreakdown`. |
| Phase 4 — AI Explanation | ✅ Complete | `ai_explainer.py` — GPT-4o with deterministic template fallback. Privacy trade-off implemented: only signal summaries + urgency phrase excerpts sent to OpenAI (no full body). |
| Phase 5 — Gmail Add-on | ✅ Complete | `Code.gs` (contextual trigger + analyzeEmail), `Api.gs` (UrlFetchApp backend call), `Cards.gs` (initial, result, error, homepage cards), `appsscript.json` manifest. |
| Phase 6 — Backend App | ✅ Complete | `main.py` — FastAPI with slowapi rate limiting, asyncio.gather parallelism, structured JSON logging, request_id observability. Dockerfile updated. |
| Phase 7 — Testing | ✅ Complete | 183 tests total: 149 unit + 34 integration (all pass, 1.57 s). 13 smoke tests present but skipped until `SMOKE_URL` env var is set. Bug E5 (`from __future__ import annotations` in `main.py`) found and fixed during this phase. Test layout: `backend/tests/unit/`, `backend/tests/integration/`, `backend/tests/smoke/`. Dev deps in `backend/requirements-dev.txt`. Config in `backend/pytest.ini` (`asyncio_mode=auto`, `pythonpath=.`). |
| Phase 8 — README | 🔜 Pending | To be written after end-to-end smoke test with real API keys. |

---

## Open Items & Next Steps

1. **Acquire API keys** — VirusTotal, AbuseIPDB, Safe Browsing, OpenAI. Copy `.env.example` → `.env` and fill in values.
2. **Run `clasp login` and `clasp create`** — from `addon/` directory: `clasp create --type standalone --title "Email Security Scanner"`. This populates `.clasp.json` with the real `scriptId`.
3. **Create a test deployment** — from the Apps Script editor (script.google.com), create a test deployment and install the add-on in your Gmail account.
4. **Run `setup()` once** — in the Apps Script editor, run `setup()` to store `BACKEND_URL` and `BACKEND_API_KEY` in Script Properties.
5. **Deploy backend to Cloud Run** — follow Phase 6 commands in PLAN.md. Replace `YOUR_PROJECT_ID` with your real GCP project.
6. **Host badge images** — upload `assets/badge_safe.png`, `assets/badge_suspicious.png`, `assets/badge_malicious.png`, `assets/shield_icon.png` to the repository `/assets/` folder. Update `BADGE_BASE_URL` in `Cards.gs` if using a different URL.
7. **Write unit tests** — start with `test_scoring_math.py` and `test_header_parser.py` (highest regression risk).
8. **Demo prep** — forward 3 test emails (PayPal phishing, fake suspension, legitimate email) to your Gmail. Run through Phase 7 end-to-end checklist in PLAN.md.

