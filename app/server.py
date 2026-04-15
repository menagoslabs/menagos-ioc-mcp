"""FastMCP server — registers the lookup_ioc tool and picks a transport.

Also exposes a small REST JSON API (`/api/lookup`, `/api/health`) alongside
the MCP endpoint so a web frontend can drive the same LookupService. Both
surfaces call into the same code path — MCP and the REST API are two views
of one service.
"""

from __future__ import annotations

from typing import Any

from fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse

from app import __version__
from app.config import get_settings
from app.indicator import InvalidIndicatorError
from app.logging_config import configure_logging, get_logger
from app.lookup import LookupService

log = get_logger("app.server")

mcp: FastMCP = FastMCP(
    name="menagos-ioc-mcp",
    instructions=(
        "Multi-source indicator-of-compromise lookups. Call `lookup_ioc` with an "
        "IP, domain, or file hash (MD5/SHA1/SHA256) and receive a normalized "
        "verdict with per-source attribution, reputation score, and confidence."
    ),
)

_service: LookupService | None = None


def _get_service() -> LookupService:
    global _service
    if _service is None:
        _service = LookupService()
    return _service


_CORS_HEADERS = {
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET, POST, OPTIONS",
    "access-control-allow-headers": "content-type",
}


def _cors(body: Any, status: int = 200) -> JSONResponse:
    return JSONResponse(body, status_code=status, headers=_CORS_HEADERS)


@mcp.custom_route("/api/health", methods=["GET", "OPTIONS"])
async def health(_request: Request) -> JSONResponse:
    return _cors({"status": "ok", "version": __version__})


@mcp.custom_route("/api/lookup", methods=["GET", "OPTIONS"])
async def api_lookup(request: Request) -> JSONResponse:
    """REST wrapper around LookupService. Used by the web UI.

    Query params:
        indicator: the IP, domain, or hash to look up (required).
    """
    if request.method == "OPTIONS":
        return _cors({})

    indicator = (request.query_params.get("indicator") or "").strip()
    if not indicator:
        return _cors(
            {"error": "missing_indicator", "message": "query param 'indicator' is required"},
            status=400,
        )

    service = _get_service()
    try:
        response = await service.lookup(indicator)
        return _cors(response.model_dump(mode="json"))
    except InvalidIndicatorError as e:
        return _cors(
            {"error": "invalid_indicator", "message": str(e)},
            status=400,
        )
    except Exception as e:  # pragma: no cover — last-resort safety net
        log.exception("api_lookup_unexpected_error")
        return _cors(
            {"error": "internal", "message": f"{e.__class__.__name__}: {e}"},
            status=500,
        )


@mcp.tool
async def lookup_ioc(indicator: str) -> dict[str, Any]:
    """Look up an indicator of compromise across VirusTotal, GreyNoise, and AbuseIPDB.

    Args:
        indicator: An IP address (v4 or v6), a domain name, or a file hash
            (MD5, SHA1, or SHA256). URL lookups are not supported in v0.1.

    Returns:
        A dict with keys:
          - indicator: { value, type, normalized_value }
          - verdict: { classification, reputation_score, confidence, summary }
          - sources: list of per-provider SourceReports
          - errors: structured list of per-provider failures
          - meta: { server_version, query_id, duration_ms, providers_queried, providers_skipped }

        If the input is not a valid IOC, returns { "error": "invalid_indicator", "message": "..." }
        instead of raising.
    """
    service = _get_service()
    try:
        response = await service.lookup(indicator)
        return response.model_dump(mode="json")
    except InvalidIndicatorError as e:
        return {"error": "invalid_indicator", "message": str(e)}


def run(
    transport: str | None = None,
    host: str | None = None,
    port: int | None = None,
) -> None:
    """Configure logging, pick a transport, and run the FastMCP server."""
    settings = get_settings()
    configure_logging(
        level=settings.log_level,
        log_full_indicators=settings.log_full_indicators,
    )

    chosen_transport = (transport or settings.transport).lower()
    chosen_host = host or settings.http_host
    chosen_port = port or settings.http_port

    log.info(
        "server_starting",
        version=__version__,
        transport=chosen_transport,
        host=chosen_host if chosen_transport == "http" else None,
        port=chosen_port if chosen_transport == "http" else None,
    )

    if chosen_transport == "stdio":
        mcp.run(transport="stdio")
    elif chosen_transport == "http":
        # FastMCP's HTTP transport uses Streamable HTTP by default.
        mcp.run(transport="http", host=chosen_host, port=chosen_port)
    else:
        raise ValueError(f"unknown transport: {chosen_transport!r}")
