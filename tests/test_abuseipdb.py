import httpx
import pytest
import respx

from app.indicator import IndicatorType
from app.providers.abuseipdb import AbuseIPDBProvider
from app.schema import Classification, SourceStatus
from tests.conftest import load_fixture


@respx.mock
async def test_abuseipdb_benign(settings):
    respx.get("https://api.abuseipdb.com/api/v2/check").mock(
        return_value=httpx.Response(200, json=load_fixture("abuseipdb_ip.json"))
    )
    async with httpx.AsyncClient() as http:
        p = AbuseIPDBProvider(http, settings)
        report = await p.lookup("8.8.8.8", IndicatorType.IP)
    assert report.status == SourceStatus.OK
    assert report.classification == Classification.BENIGN
    assert report.reputation_score == 0.0
    assert report.raw_signals["isp"] == "Google LLC"


@respx.mock
async def test_abuseipdb_malicious(settings):
    respx.get("https://api.abuseipdb.com/api/v2/check").mock(
        return_value=httpx.Response(200, json=load_fixture("abuseipdb_ip_malicious.json"))
    )
    async with httpx.AsyncClient() as http:
        p = AbuseIPDBProvider(http, settings)
        report = await p.lookup("1.2.3.4", IndicatorType.IP)
    assert report.status == SourceStatus.OK
    assert report.classification == Classification.MALICIOUS
    assert report.reputation_score > 0.9


@respx.mock
async def test_abuseipdb_rate_limited(settings):
    respx.get("https://api.abuseipdb.com/api/v2/check").mock(
        return_value=httpx.Response(429, json={"errors": [{"detail": "Too many"}]})
    )
    async with httpx.AsyncClient() as http:
        p = AbuseIPDBProvider(http, settings)
        report = await p.lookup("8.8.8.8", IndicatorType.IP)
    assert report.status == SourceStatus.RATE_LIMITED


@respx.mock
async def test_abuseipdb_auth_error(settings):
    respx.get("https://api.abuseipdb.com/api/v2/check").mock(
        return_value=httpx.Response(401, json={"errors": [{"detail": "bad key"}]})
    )
    async with httpx.AsyncClient() as http:
        p = AbuseIPDBProvider(http, settings)
        report = await p.lookup("8.8.8.8", IndicatorType.IP)
    assert report.status == SourceStatus.ERROR


async def test_abuseipdb_rejects_hash(settings):
    async with httpx.AsyncClient() as http:
        p = AbuseIPDBProvider(http, settings)
        report = await p.lookup("d41d8cd98f00b204e9800998ecf8427e", IndicatorType.HASH_MD5)
    assert report.status == SourceStatus.UNSUPPORTED
