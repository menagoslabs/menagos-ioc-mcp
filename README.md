# Menagos IOC MCP

A local-first MCP server that exposes a single tool, `lookup_ioc`, which fans out to VirusTotal, GreyNoise, and AbuseIPDB in parallel and returns a normalized verdict with per-source attribution, a reputation score, and a confidence rating.

Built for agents: plug it into Claude Desktop, Claude Code, or any MCP client and ask about an IP, domain, or file hash.

## Quick Start

```bash
git clone https://github.com/menagoslabs/menagos-ioc-mcp.git
cd menagos-ioc-mcp
cp .env.example .env        # fill in VT_API_KEY, GREYNOISE_API_KEY, ABUSEIPDB_API_KEY
make install-dev
make demo                    # installs, starts the server, runs a sample lookup
```

## What It Does

- Accepts one indicator (IP v4/v6, domain, or file hash — MD5/SHA1/SHA256)
- Classifies the indicator type
- Queries every provider that supports that type in parallel
- Normalizes each provider's response into a shared `SourceReport` shape
- Aggregates a verdict: `benign | suspicious | malicious | unknown` + reputation score + confidence
- Degrades gracefully: if one provider fails, the verdict still comes back with downgraded confidence
- Redacts API keys and truncates indicators in structured JSON logs

URL lookups are not supported in v0.1. They're deferred to v0.2.

## Stack

- **Language**: Python 3.11+
- **MCP framework**: [FastMCP](https://github.com/jlowin/fastmcp)
- **HTTP transport**: Streamable HTTP (FastMCP default)
- **Models**: pydantic v2 + pydantic-settings
- **HTTP client**: httpx (async)
- **Logging**: structlog → JSON to stdout
- **Tests**: pytest + pytest-asyncio + respx
- **Packaging**: hatchling

## Project Structure

```
app/            Python package (config, indicator, schema, scoring, providers, lookup, server)
frontend/      Web UI (Vite + React + TypeScript + Tailwind)
tests/         pytest suite + JSON fixtures
scripts/       demo.sh and client_example.py
docs/          Architecture, integration guides, limitations
```

## Development

### Backend

```bash
# Install (editable, with dev extras)
make install-dev

# Run as MCP stdio server (what Claude Desktop / Claude Code will spawn)
make stdio

# Run as local HTTP server on 127.0.0.1:8765 (MCP + REST API, for the web UI and other agents)
make serve

# Run the test suite
make test

# Run tests with coverage
make test-cov
```

The HTTP server exposes both the MCP endpoint (for agents) and a small REST API:

- `GET /api/health` — liveness check
- `GET /api/lookup?indicator=8.8.8.8` — JSON `LookupResponse` (same as the MCP tool)

### Web UI

A Vite + React + TypeScript + Tailwind frontend for visualizing lookups. Requires Node 18+.

```bash
# Install JS deps (one time)
make ui-install

# Start backend in terminal A
make serve

# Start frontend dev server in terminal B (http://localhost:5173)
make ui-dev
```

The dev server proxies `/api/*` to the backend, so there's nothing to configure. For a production build:

```bash
make ui-build        # writes frontend/dist/
```

## Integrations

- **Claude Desktop**: see [docs/claude-desktop.md](docs/claude-desktop.md)
- **Claude Code**: see [docs/claude-code.md](docs/claude-code.md)
- **Use from another agent**: see [scripts/client_example.py](scripts/client_example.py)

Quick version for Claude Desktop — add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "menagos-ioc": {
      "command": "python",
      "args": ["-m", "app", "--transport", "stdio"],
      "cwd": "/absolute/path/to/menagos-ioc-mcp",
      "env": {
        "VT_API_KEY": "...",
        "GREYNOISE_API_KEY": "...",
        "ABUSEIPDB_API_KEY": "..."
      }
    }
  }
}
```

Quick version for Claude Code:

```bash
claude mcp add menagos-ioc -- python -m app --transport stdio
```

## Response Shape

```json
{
  "indicator": { "value": "8.8.8.8", "type": "ip", "normalized_value": "8.8.8.8" },
  "verdict": {
    "classification": "benign",
    "reputation_score": 0.017,
    "confidence": "high",
    "summary": "3/3 sources responded. 0 flagged as suspicious or malicious."
  },
  "sources": [
    { "provider": "virustotal", "status": "ok", "reputation_score": 0.0, "classification": "benign", ... },
    { "provider": "greynoise", "status": "ok", "reputation_score": 0.05, "classification": "benign", ... },
    { "provider": "abuseipdb", "status": "ok", "reputation_score": 0.0, "classification": "benign", ... }
  ],
  "errors": [],
  "meta": {
    "server_version": "0.1.0",
    "query_id": "...",
    "duration_ms": 520,
    "providers_queried": ["virustotal", "greynoise", "abuseipdb"],
    "providers_skipped": []
  }
}
```

Field definitions live in [app/schema.py](app/schema.py) and [docs/architecture.md](docs/architecture.md).

## Documentation

- [Architecture](docs/architecture.md) — modules, data flow, scoring rules
- [Claude Desktop integration](docs/claude-desktop.md)
- [Claude Code integration](docs/claude-code.md)
- [Limitations](docs/limitations.md) — rate limits, provider coverage, known gaps

## Remote Exposure (optional)

This repo is deliberately local-first. If you want `menagos-ioc-mcp` reachable from a remote agent, wrap the HTTP transport with your own reverse proxy and auth — Tailscale, Cloudflare Tunnel, Nginx + bearer token, or whatever your environment already trusts. No opinionated infra ships here.

## Important

API keys are secrets. Never commit `.env`. The server redacts keys and `Authorization` headers from structured logs, and truncates indicator values by default (toggle with `LOG_FULL_INDICATORS=true` for local debugging).

This tool reports what VirusTotal, GreyNoise, and AbuseIPDB say about an indicator at a single point in time. It is not a ground-truth threat oracle and should not be the only input to a block or allow decision. See [limitations](docs/limitations.md).

## License

MIT. Copyright (c) 2026 Menagos LLC.
