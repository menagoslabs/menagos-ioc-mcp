"""Example: call lookup_ioc from another agent over local HTTP.

Usage:
    python scripts/client_example.py 8.8.8.8

Assumes a menagos-ioc-mcp server is already running on http://127.0.0.1:8765.
Start one with: `make serve` or `python -m app --transport http`.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys

from fastmcp import Client


DEFAULT_URL = os.environ.get(
    "MENAGOS_IOC_URL",
    "http://127.0.0.1:8765/mcp",
)


async def main(indicator: str, url: str) -> int:
    print(f">> connecting to {url}")
    async with Client(url) as client:
        print(">> calling lookup_ioc")
        result = await client.call_tool("lookup_ioc", {"indicator": indicator})

        # FastMCP returns a CallToolResult; its `data` field is the structured dict.
        payload = getattr(result, "data", None) or getattr(result, "structured_content", None)
        if payload is None and getattr(result, "content", None):
            # Fallback: parse the first text block as JSON.
            text = result.content[0].text
            payload = json.loads(text)

        print(json.dumps(payload, indent=2, default=str))
    return 0


if __name__ == "__main__":
    indicator = sys.argv[1] if len(sys.argv) > 1 else "8.8.8.8"
    url = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_URL
    sys.exit(asyncio.run(main(indicator, url)))
