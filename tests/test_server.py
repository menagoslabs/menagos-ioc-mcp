"""Smoke tests for the FastMCP server: tool registration and a direct call."""

import httpx
import respx

from app.schema import Classification, SourceStatus
from tests.conftest import load_fixture


async def test_tool_is_registered():
    # Import lazily so configure_logging isn't called at import time in other tests.
    from app.server import mcp

    tools = await mcp.get_tools()
    names = {t.name if hasattr(t, "name") else t for t in tools}
    assert "lookup_ioc" in names


@respx.mock
async def test_tool_returns_normalized_response(monkeypatch, settings):
    # Patch the global service in app.server to use our test settings.
    from app import server
    from app.lookup import LookupService

    respx.get("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8").mock(
        return_value=httpx.Response(200, json=load_fixture("virustotal_ip.json"))
    )
    respx.get("https://api.greynoise.io/v3/community/8.8.8.8").mock(
        return_value=httpx.Response(200, json=load_fixture("greynoise_ip.json"))
    )
    respx.get("https://api.abuseipdb.com/api/v2/check").mock(
        return_value=httpx.Response(200, json=load_fixture("abuseipdb_ip.json"))
    )

    test_service = LookupService(settings=settings)
    monkeypatch.setattr(server, "_service", test_service)

    try:
        result = await server.lookup_ioc.fn("8.8.8.8")
    finally:
        await test_service.close()
        monkeypatch.setattr(server, "_service", None)

    assert result["indicator"]["value"] == "8.8.8.8"
    assert result["verdict"]["classification"] == Classification.BENIGN.value
    assert len(result["sources"]) == 3


async def test_tool_handles_invalid_indicator(monkeypatch, settings):
    from app import server
    from app.lookup import LookupService

    test_service = LookupService(settings=settings)
    monkeypatch.setattr(server, "_service", test_service)

    try:
        result = await server.lookup_ioc.fn("not-an-ioc")
    finally:
        await test_service.close()
        monkeypatch.setattr(server, "_service", None)

    assert result["error"] == "invalid_indicator"
    assert "could not classify" in result["message"]
