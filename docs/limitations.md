# Limitations

This document is deliberately blunt about what `menagos-ioc-mcp` does not do. Read it before you use this tool to make real block/allow decisions.

## Not a ground-truth oracle

`lookup_ioc` reports what VirusTotal, GreyNoise, and AbuseIPDB say about an indicator at a single point in time. None of those sources is authoritative on its own, and the aggregated verdict is a weighted average — not a legal ruling. Treat it as one input among many.

## Indicator coverage

v0.1 supports:

- IPv4 and IPv6 addresses
- Domains (including punycode / IDN)
- File hashes: MD5, SHA1, SHA256

v0.1 does **not** support:

- URLs (VirusTotal requires a base64url-encoded URL ID — deferred to v0.2)
- CIDR ranges
- Email addresses
- Mutexes, registry keys, or other host-based artifacts

Invalid input returns a structured `{"error": "invalid_indicator", ...}` payload rather than a crash.

## Provider coverage

| Provider   | IP | Domain | Hash | URL |
|---|:-:|:-:|:-:|:-:|
| VirusTotal | ✅ | ✅ | ✅ | ❌ (v0.2) |
| GreyNoise (Community) | ✅ | ❌ | ❌ | ❌ |
| AbuseIPDB  | ✅ | ❌ | ❌ | ❌ |

For a domain lookup, only VirusTotal responds — the other two report `status="unsupported"`. For a hash lookup, only VirusTotal responds. The orchestrator excludes unsupported reports from the verdict math so the coverage ratio stays honest.

## Rate limits

Each provider has its own upstream quota. The server uses an in-process token bucket per provider (default 60 requests/minute, configurable via `PROVIDER_RATE_LIMIT_PER_MIN`). When the bucket is empty, the provider is skipped with `status="rate_limited"` instead of blocking — confidence on the overall verdict is downgraded accordingly.

If the upstream returns HTTP 429, the provider is marked `rate_limited` for that single call. There is no in-memory retry loop; the next agent call will try again.

Be aware of the free tiers:

- **VirusTotal** public API: ~4 requests/minute, 500/day. Key is required.
- **GreyNoise Community**: ~50 lookups/week (combined with Visualizer usage).
  A key is optional — the adapter will make unauthenticated requests if
  `GREYNOISE_API_KEY` is empty. Authenticated calls may get slightly higher
  quotas.
- **AbuseIPDB**: ~1000 checks/day on the free tier. Key is required.

## Caching

There is no cache in v0.1. Every call to `lookup_ioc` makes live HTTP requests to all applicable providers. A small TTL cache is planned for v0.2.

## Concurrency and state

- The server holds a single `httpx.AsyncClient` per process. It is safe for an MCP client to make concurrent `lookup_ioc` calls.
- The rate limiter is in-process only. Running multiple `menagos-ioc-mcp` processes against the same API keys will let them exceed the configured per-minute quota independently.

## Logging and privacy

- API keys, `Authorization` headers, and other secret-like fields are redacted from structured logs.
- Indicator values are truncated (`abcd***wxyz`) by default. Set `LOG_FULL_INDICATORS=true` in `.env` only for local debugging.
- The server does not persist lookups to disk. If you want an audit trail, pipe stdout to your log aggregator of choice.

## Security of the HTTP transport

The HTTP transport binds to `127.0.0.1:8765` by default. **Do not bind to `0.0.0.0` or expose the port directly to the public internet.** This repo ships no authentication middleware; if you need remote access, front it with a reverse proxy and an auth layer you trust (Tailscale, Cloudflare Tunnel, Nginx + bearer token, etc.).

## Known gaps / roadmap

- **v0.2**: URL lookups, in-process TTL cache, richer GreyNoise Enterprise signals, optional bearer-token auth for the HTTP transport.
- **v0.3**: provider registry so users can plug in additional intel sources without editing `lookup.py`.
