# Copilot Instructions — Gmail Malicious Email Scorer

## Architecture

Three-component system:
- **`backend/`** — FastAPI on Cloud Run. Single `POST /analyze` endpoint runs 5 parallel signal engines via `asyncio.gather`, feeds results to a scoring engine and GPT-4o explainer.
- **`addon/`** — Google Apps Script (deployed via `clasp`). Extracts email data and calls the backend. UI is pure `CardService` — no HTML sidebars.
- **`frontend/`** — React + TypeScript + Vite debug UI for manually testing the backend without the Gmail add-on.

Signal engine modules live in `backend/signal_engine/`: `headers.py`, `urls.py`, `ip_reputation.py`, `domain_age.py`, `behavior.py`. Each returns `tuple[list[Signal], list[EvidenceItem]]`. See `backend/models.py` for the canonical schema.

## Build and Test

```bash
# Backend — run from backend/
pip install -r requirements.txt -r requirements-dev.txt
pytest                        # unit + integration (183 tests, ~1.6s)
pytest tests/unit/            # unit only
pytest tests/integration/     # integration only (all externals mocked)
pytest -m smoke               # requires SMOKE_URL env var

# Frontend — run from frontend/
npm install
npm run dev      # Vite dev server
npm run build    # tsc + Vite bundle

# Apps Script — run from addon/
clasp push       # push .gs files to Apps Script project
clasp open       # open in browser editor
```

## Python Code Style

- `from __future__ import annotations` is used in all files **except `main.py`**. Omitting it there is intentional — PEP 563 breaks Pydantic v2 route-parameter resolution (see Decision D7 in `IMPLEMENTATION_NOTES.md`).
- Import order: stdlib → third-party → local (flat `backend/` is on `sys.path`).
- Use `Optional[str]` (not `X | None`) and `list[str]` / `dict[str, int]` native generics.
- Signal engine functions that call external APIs are `async def`. Pure CPU functions (`analyze_headers`, `analyze_behavior`) are synchronous `def` and are wrapped in `run_in_executor` inside `asyncio.gather` (see `main.py`).
- All external API calls carry a 3-second timeout budget. On `429` or timeout, return `Signal(status="unknown")` and continue — never raise.

## Scoring Rules (do not change without updating PLAN.md)

- Category caps: `header=45, url=40, ip=20, domain=20, behavior=10`.
- Domain age signals are **mutually exclusive**: only the highest threshold fires (< 7 days = 20 pts OR < 30 days = 12 pts, never both).
- AbuseIPDB thresholds are **additive**: > 25% = 12 pts, and if also > 75%, +8 bonus = 20 pts total.
- `final_score = min(100, round(capped_points / capped_max_points * 100))`.
- Confidence starts at 100 and is penalized per unavailable signal source. See `backend/scoring.py`.

## Test Patterns

- Unit tests: `class Test<Subject>` containing `def test_<case>`. Test private helpers directly (e.g. `_extract_domain`, `_parse_auth_result`). No I/O — no mocks needed.
- Integration tests: `autouse` fixture `disable_auth` zeroes the API key; `stub_signal_engines` patches all signal engine functions in `main`'s namespace using `unittest.mock.patch` (`AsyncMock` for async, `MagicMock` for sync). Client is `httpx.AsyncClient` with `ASGITransport`. See `backend/tests/integration/conftest.py`.
- `asyncio_mode = auto` in `pytest.ini` — never add `@pytest.mark.asyncio`.

## Apps Script Conventions

- Always call `GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken)` as the **first line** of every contextual trigger function.
- Contextual triggers must return `[card]` (array), not a bare card object.
- Use `message.getRawContent()` (not `message.getHeader()`) to capture all `Received` headers.
- API keys stored in `PropertiesService.getScriptProperties()` only — never hardcoded.
- All card builders are `build*Card()` functions in `Cards.gs`. Use `CardService.newCardSection().setCollapsible(true)` for expandable detail sections.
- GAS code uses ES5-style `var` / `function` declarations (no `import`/`export`).

## Integration Points & API Keys

| Service | Used by | Env var |
|---|---|---|
| VirusTotal | `signal_engine/urls.py` | `VIRUSTOTAL_API_KEY` |
| Google Safe Browsing | `signal_engine/urls.py` | `SAFE_BROWSING_API_KEY` |
| AbuseIPDB | `signal_engine/ip_reputation.py` | `ABUSEIPDB_API_KEY` |
| OpenAI GPT-4o | `ai_explainer.py` | `OPENAI_API_KEY` |
| Backend → Add-on | `Api.gs` | `BACKEND_API_KEY` (Script Property) + `X-API-Key` header |

Copy `.env.example` → `.env` in `backend/`. VirusTotal free tier: **4 req/min, 500/day** — max 3 unique domains are scanned per `/analyze` call, deduplicated with a per-request `dict` cache.

## Security Constraints

- The `/analyze` endpoint is protected by `X-API-Key` header validation (`config.settings.api_key`).
- Never send full email body to OpenAI — only signal summaries and matched urgency phrase excerpts (see `IMPLEMENTATION_NOTES.md` A8).
- IP extraction uses the **first external (non-private) hop** from `Received` headers, not the last (see A6). Private/reserved ranges are filtered before any AbuseIPDB query.
- Rate limiting: 30 req/min per IP via `slowapi` on `/analyze`.
