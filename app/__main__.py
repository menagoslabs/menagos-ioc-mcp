"""CLI entry point. Parses transport args and hands off to app.server."""

from __future__ import annotations

import argparse
import sys

from app import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="menagos-ioc-mcp",
        description="MCP server that fans out IOC lookups to VirusTotal, GreyNoise, and AbuseIPDB.",
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "http"],
        default=None,
        help="Transport to use. Defaults to TRANSPORT env var or 'stdio'.",
    )
    parser.add_argument(
        "--host",
        default=None,
        help="HTTP bind host (only with --transport http). Defaults to HTTP_HOST env var or 127.0.0.1.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="HTTP bind port (only with --transport http). Defaults to HTTP_PORT env var or 8765.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"menagos-ioc-mcp {__version__}",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # Imported lazily so --version / --help work without loading the full stack.
    from app.server import run

    run(transport=args.transport, host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
