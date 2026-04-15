# Architecture

## Modules

| Module | Responsibility |
|---|---|
| `app/config.py` | `Settings` loaded from `.env` via pydantic-settings. Single source of truth for API keys, timeouts, rate limits, transport, log level. |
| `app/logging_config.py` | structlog processor chain: adds timestamps, redacts secrets, truncates indicators (unless `LOG_FULL_INDICATORS=true`), renders JSON to stdout. |
| `app/indicator.py` | `IndicatorType` enum + `classify(value)` + `normalize(value, itype)`. Raises `InvalidIndicatorError` on garbage input. |
| `app/schema.py` | pydantic v2 models for the normalized response: `Indicator`, `SourceReport`, `Verdict`, `ErrorEntry`, `Meta`, `LookupResponse`. |
| `app/scoring.py` | `aggregate(reports) -> Verdict`. Averages reputation across OK providers, derives classification from thresholds, derives confidence from coverage. |
| `app/rate_limit.py` | In-process async token bucket per provider. Fails fast instead of blocking — a provider over quota is reported as `status="rate_limited"`. |
| `app/providers/base.py` | `Provider` ABC, `SourceReport` contract, `ProviderError` hierarchy. The public `lookup()` method catches all exceptions and always returns a `SourceReport` so the orchestrator can rely on the invariant. |
| `app/providers/virustotal.py` | VT v3 API for IPs, domains, and file hashes (MD5/SHA1/SHA256). |
| `app/providers/greynoise.py` | GreyNoise Community API, IP-only. RIOT hits are explicitly pinned to benign. |
| `app/providers/abuseipdb.py` | AbuseIPDB v2 `/check` endpoint, IP-only. |
| `app/lookup.py` | `LookupService`: owns a shared `httpx.AsyncClient` and a `RateLimiter`, classifies, fans out with per-provider timeouts, aggregates, builds `LookupResponse`. |
| `app/server.py` | FastMCP app, registers the `lookup_ioc` tool, picks transport. |
| `app/__main__.py` | CLI entry. Parses `--transport`, `--host`, `--port` and dispatches to `server.run()`. |

## Data Flow

```
input string
    │
    ▼
classify()  ── InvalidIndicatorError ──► MCP tool error
    │
    ▼
normalize()
    │
    ▼
LookupService.lookup()
    │
    ├── select providers that support this indicator type
    ├── per provider:
    │       rate_limiter.try_acquire(provider)  ── exhausted ──► rate_limited report
    │       asyncio.wait_for(provider.lookup(), provider_timeout_s)
    │                                         ── timeout ──► timeout report
    │                                         ── http error ──► error report
    │                                         ── ok ──► SourceReport
    ├── mark unsupported providers with `status="unsupported"` synthetic reports
    ▼
aggregate(ok reports) ──► Verdict { classification, reputation_score, confidence, summary }
    │
    ▼
LookupResponse { indicator, verdict, sources, errors, meta }
```

## Scoring Rules

**Per-provider score normalization** — each adapter produces a float in `[0.0, 1.0]` where `0 = clean`, `1 = malicious`.

- **VirusTotal**: `(malicious + 0.5 * suspicious) / total_analyses`. Classification follows: `>= 0.5` → malicious, `> 0` → suspicious, `== 0` → benign.
- **GreyNoise**: string classification (`benign`/`unknown`/`suspicious`/`malicious`) mapped to `0.0 / 0.3 / 0.6 / 0.95`. RIOT-without-noise is pinned to benign regardless of classification string.
- **AbuseIPDB**: `abuseConfidenceScore / 100`. Classification: `>= 50` → malicious, `>= 20 or totalReports > 0` → suspicious, else benign.

**Aggregation** (`app/scoring.py`):

- Reputation score = mean of `reputation_score` across reports with `status == OK`. Unsupported reports are excluded from coverage math.
- Classification from thresholds: `<= 0.2` → benign, `<= 0.6` → suspicious, `> 0.6` → malicious. `0/N responded` → unknown.
- Confidence:
  - `high`: all queried providers responded OK.
  - `medium`: ≥ 2 of 3 OK and ratio ≥ 0.66.
  - `low`: anything less.

## Error Model

Providers never raise out of `Provider.lookup()`. Internal exceptions are mapped to `SourceStatus`:

| Condition | `SourceStatus` |
|---|---|
| Successful response | `ok` |
| Provider-declared not-found (404) | `not_found` |
| Indicator type not supported | `unsupported` |
| httpx/asyncio timeout | `timeout` |
| HTTP 429 | `rate_limited` |
| HTTP 401/403 | `error` |
| Any other HTTP or transport failure | `error` |

Every non-ok, non-unsupported status also produces an `ErrorEntry` in `LookupResponse.errors`.

## Timeouts and Budgets

- `REQUEST_TIMEOUT_S` (default 10s): total budget on the shared `httpx.AsyncClient`.
- `PROVIDER_TIMEOUT_S` (default 6s): per-provider timeout enforced by both httpx and a wrapping `asyncio.wait_for`. Always strictly less than the request budget so one slow provider can't starve the rest.

## Logging

- All logs are structured JSON on stdout, via structlog.
- API keys, `Authorization`, `x-apikey`, `key`, `token`, `secret`, and `password` fields are replaced with `***REDACTED***` by a processor on every event.
- Indicator values are truncated to `first4***last4` by default. Set `LOG_FULL_INDICATORS=true` in `.env` for local debugging only.
- One `lookup_start` and one `lookup_complete` event per request, plus per-provider warnings on timeout or local rate-limit exhaustion.
