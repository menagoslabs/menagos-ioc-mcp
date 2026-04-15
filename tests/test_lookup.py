import httpx
import pytest
import respx

from app.indicator import InvalidIndicatorError
from app.lookup import LookupService
from app.schema import Classification, Confidence, SourceStatus
from tests.conftest import load_fixture


@respx.mock
async def test_lookup_all_providers_succeed_benign(settings):
    respx.get("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8").mock(
        return_value=httpx.Response(200, json=load_fixture("virustotal_ip.json"))
    )
    respx.get("https://api.greynoise.io/v3/community/8.8.8.8").mock(
        return_value=httpx.Response(200, json=load_fixture("greynoise_ip.json"))
    )
    respx.get("https://api.abuseipdb.com/api/v2/check").mock(
        return_value=httpx.Response(200, json=load_fixture("abuseipdb_ip.json"))
    )

    svc = LookupService(settings=settings)
    try:
        resp = await svc.lookup("8.8.8.8")
    finally:
        await svc.close()

    assert resp.indicator.value == "8.8.8.8"
    assert resp.verdict.classification == Classification.BENIGN
    assert resp.verdict.confidence == Confidence.HIGH
    assert len(resp.sources) == 3
    assert all(s.status == SourceStatus.OK for s in resp.sources)
    assert resp.errors == []


@respx.mock
async def test_lookup_one_provider_times_out(settings):
    respx.get("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8").mock(
        return_value=httpx.Response(200, json=load_fixture("virustotal_ip.json"))
    )
    respx.get("https://api.greynoise.io/v3/community/8.8.8.8").mock(
        side_effect=httpx.ReadTimeout("timeout")
    )
    respx.get("https://api.abuseipdb.com/api/v2/check").mock(
        return_value=httpx.Response(200, json=load_fixture("abuseipdb_ip.json"))
    )

    svc = LookupService(settings=settings)
    try:
        resp = await svc.lookup("8.8.8.8")
    finally:
        await svc.close()

    ok = [s for s in resp.sources if s.status == SourceStatus.OK]
    bad = [s for s in resp.sources if s.status != SourceStatus.OK]
    assert len(ok) == 2
    assert len(bad) == 1
    assert bad[0].provider == "greynoise"
    assert bad[0].status == SourceStatus.TIMEOUT
    # Still a verdict, but confidence is downgraded.
    assert resp.verdict.classification == Classification.BENIGN
    assert resp.verdict.confidence in (Confidence.MEDIUM, Confidence.HIGH)
    assert any(e.provider == "greynoise" for e in resp.errors)


@respx.mock
async def test_lookup_all_providers_fail(settings):
    respx.get("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8").mock(
        return_value=httpx.Response(500)
    )
    respx.get("https://api.greynoise.io/v3/community/8.8.8.8").mock(
        return_value=httpx.Response(500)
    )
    respx.get("https://api.abuseipdb.com/api/v2/check").mock(
        return_value=httpx.Response(500)
    )

    svc = LookupService(settings=settings)
    try:
        resp = await svc.lookup("8.8.8.8")
    finally:
        await svc.close()

    assert resp.verdict.classification == Classification.UNKNOWN
    assert resp.verdict.confidence == Confidence.LOW
    assert len(resp.errors) == 3


@respx.mock
async def test_lookup_hash_only_virustotal_queried(settings):
    sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    respx.get(f"https://www.virustotal.com/api/v3/files/{sha256}").mock(
        return_value=httpx.Response(200, json=load_fixture("virustotal_hash.json"))
    )

    svc = LookupService(settings=settings)
    try:
        resp = await svc.lookup(sha256)
    finally:
        await svc.close()

    assert resp.meta.providers_queried == ["virustotal"]
    assert set(resp.meta.providers_skipped) == {"greynoise", "abuseipdb"}

    statuses = {s.provider: s.status for s in resp.sources}
    assert statuses["virustotal"] == SourceStatus.OK
    assert statuses["greynoise"] == SourceStatus.UNSUPPORTED
    assert statuses["abuseipdb"] == SourceStatus.UNSUPPORTED

    assert resp.verdict.classification == Classification.MALICIOUS


async def test_lookup_invalid_indicator(settings):
    svc = LookupService(settings=settings)
    try:
        with pytest.raises(InvalidIndicatorError):
            await svc.lookup("not-an-ioc")
    finally:
        await svc.close()
