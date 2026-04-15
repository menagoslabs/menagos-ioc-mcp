# Claude Code integration

Two ways to wire this server into Claude Code: as a stdio subprocess (recommended), or as a local HTTP endpoint (useful when you want to share the same server with other clients).

## Option 1: stdio (recommended)

```bash
git clone https://github.com/menagoslabs/menagos-ioc-mcp.git
cd menagos-ioc-mcp
cp .env.example .env        # fill in VT_API_KEY, GREYNOISE_API_KEY, ABUSEIPDB_API_KEY
make install-dev

# Register with Claude Code
claude mcp add menagos-ioc -- python -m app --transport stdio
```

Verify:
```bash
claude mcp list
```

Then in a Claude Code session:

> Call the lookup_ioc tool on 8.8.8.8

## Option 2: local HTTP

If you want a long-running server (e.g. so `scripts/client_example.py` or another agent can hit it), start it in one terminal:

```bash
make serve   # binds 127.0.0.1:8765
```

Then register with Claude Code as an HTTP MCP server:

```bash
claude mcp add menagos-ioc --transport http http://127.0.0.1:8765/mcp
```

The HTTP transport uses Streamable HTTP, which is what recent FastMCP and the official `mcp` Python SDK speak natively.

## Use from another agent

`scripts/client_example.py` is a minimal MCP client that connects over HTTP and calls `lookup_ioc`:

```bash
make serve                             # in terminal A
python scripts/client_example.py 8.8.8.8   # in terminal B
```

It uses FastMCP's `Client` class and prints the structured response as JSON. Copy it into your own agent project and adapt.

## Environment variables

Every setting in `.env.example` can be overridden at the shell level when you launch the server. Useful for one-off experimentation:

```bash
LOG_LEVEL=DEBUG LOG_FULL_INDICATORS=true python -m app --transport stdio
```
