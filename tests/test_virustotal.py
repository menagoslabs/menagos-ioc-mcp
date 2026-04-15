import httpx
import pytest
import respx

from app.indicator import IndicatorType
from app.providers.virustotal import VirusTotalProvider
from app.schema import Classification, SourceStatus
from tests.conftest import load_fixture


@respx.mock
async def test_virustotal_benign_ip(settings):
    respx.get("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8").mock(
        return_value=httpx.Response(200, json=load_fixture("virustotal_ip.json"))
    )
    async with httpx.AsyncClient() as http:
        p = VirusTotalProvider(http, settings)
        report = await p.lookup("8.8.8.8", IndicatorType.IP)
    assert report.status == SourceStatus.OK
    assert report.classification == Classification.BENIGN
    assert report.reputation_score == 0.0
    assert "harmless" in report.raw_signals
    assert report.reference_url and "8.8.8.8" in report.reference_url


@respx.mock
async def test_virustotal_malicious_ip(settings):
    respx.get("https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4").mock(
        return_value=httpx.Response(200, json=load_fixture("virustotal_ip_malicious.json"))
    )
    async with httpx.AsyncClient() as http:
        p = VirusTotalProvider(http, settings)
        report = await p.lookup("1.2.3.4", IndicatorType.IP)
    assert report.status == SourceStatus.OK
    assert report.classification in (Classification.SUSPICIOUS, Classification.MALICIOUS)
    assert report.reputation_score > 0.0


@respx.mock
async def test_virustotal_hash(settings):
    sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    respx.get(f"https://www.virustotal.com/api/v3/files/{sha256}").mock(
        return_value=httpx.Response(200, json=load_fixture("virustotal_hash.json"))
    )
    async with httpx.AsyncClient() as http:
        p = VirusTotalProvider(http, settings)
        report = await p.lookup(sha256, IndicatorType.HASH_SHA256)
    assert report.status == SourceStatus.OK
    assert report.classification == Classification.MALICIOUS
    assert report.reputation_score > 0.5


@respx.mock
async def test_virustotal_not_found(settings):
    respx.get("https://www.virustotal.com/api/v3/ip_addresses/9.9.9.9").mock(
        return_value=httpx.Response(404, json={"error": {"code": "NotFoundError"}})
    )
    async with httpx.AsyncClient() as http:
        p = VirusTotalProvider(http, settings)
        report = await p.lookup("9.9.9.9", IndicatorType.IP)
    assert report.status == SourceStatus.NOT_FOUND


@respx.mock
async def test_virustotal_rate_limited(settings):
    respx.get("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8").mock(
        return_value=httpx.Response(429, json={"error": {"code": "QuotaExceededError"}})
    )
    async with httpx.AsyncClient() as http:
        p = VirusTotalProvider(http, settings)
        report = await p.lookup("8.8.8.8", IndicatorType.IP)
    assert report.status == SourceStatus.RATE_LIMITED


@respx.mock
async def test_virustotal_auth_error(settings):
    respx.get("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8").mock(
        return_value=httpx.Response(401, json={"error": {"code": "AuthenticationRequiredError"}})
    )
    async with httpx.AsyncClient() as http:
        p = VirusTotalProvider(http, settings)
        report = await p.lookup("8.8.8.8", IndicatorType.IP)
    assert report.status == SourceStatus.ERROR


async def test_virustotal_unsupported_type(settings):
    async with httpx.AsyncClient() as http:
        p = VirusTotalProvider(http, settings)
        # URL is not in v0.1 supported_types
        report = await p.lookup("https://example.com", IndicatorType.URL)
    assert report.status == SourceStatus.UNSUPPORTED
