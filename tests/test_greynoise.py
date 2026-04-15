import httpx
import pytest
import respx

from app.indicator import IndicatorType
from app.providers.greynoise import GreyNoiseProvider
from app.schema import Classification, SourceStatus
from tests.conftest import load_fixture


@respx.mock
async def test_greynoise_benign_riot(settings):
    respx.get("https://api.greynoise.io/v3/community/8.8.8.8").mock(
        return_value=httpx.Response(200, json=load_fixture("greynoise_ip.json"))
    )
    async with httpx.AsyncClient() as http:
        p = GreyNoiseProvider(http, settings)
        report = await p.lookup("8.8.8.8", IndicatorType.IP)
    assert report.status == SourceStatus.OK
    assert report.classification == Classification.BENIGN
    assert report.reputation_score <= 0.1
    assert report.raw_signals["riot"] is True


@respx.mock
async def test_greynoise_malicious(settings):
    respx.get("https://api.greynoise.io/v3/community/185.220.101.5").mock(
        return_value=httpx.Response(200, json=load_fixture("greynoise_ip_malicious.json"))
    )
    async with httpx.AsyncClient() as http:
        p = GreyNoiseProvider(http, settings)
        report = await p.lookup("185.220.101.5", IndicatorType.IP)
    assert report.status == SourceStatus.OK
    assert report.classification == Classification.MALICIOUS
    assert report.reputation_score > 0.8


@respx.mock
async def test_greynoise_not_found(settings):
    respx.get("https://api.greynoise.io/v3/community/9.9.9.9").mock(
        return_value=httpx.Response(404, json={"ip": "9.9.9.9", "message": "IP not observed"})
    )
    async with httpx.AsyncClient() as http:
        p = GreyNoiseProvider(http, settings)
        report = await p.lookup("9.9.9.9", IndicatorType.IP)
    assert report.status == SourceStatus.NOT_FOUND


async def test_greynoise_rejects_domain(settings):
    async with httpx.AsyncClient() as http:
        p = GreyNoiseProvider(http, settings)
        report = await p.lookup("example.com", IndicatorType.DOMAIN)
    assert report.status == SourceStatus.UNSUPPORTED
