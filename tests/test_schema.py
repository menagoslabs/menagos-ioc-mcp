from datetime import datetime, timezone

from app.schema import (
    Classification,
    Confidence,
    ErrorEntry,
    Indicator,
    LookupResponse,
    Meta,
    SourceReport,
    SourceStatus,
    Verdict,
)
from app.indicator import IndicatorType


def _now():
    return datetime.now(timezone.utc)


def test_source_report_clamps_score_high():
    r = SourceReport(
        provider="x",
        status=SourceStatus.OK,
        reputation_score=5.0,
        classification=Classification.MALICIOUS,
        fetched_at=_now(),
    )
    assert r.reputation_score == 1.0


def test_source_report_clamps_score_low():
    r = SourceReport(
        provider="x",
        status=SourceStatus.OK,
        reputation_score=-0.5,
        classification=Classification.BENIGN,
        fetched_at=_now(),
    )
    assert r.reputation_score == 0.0


def test_source_report_allows_none_score():
    r = SourceReport(
        provider="x",
        status=SourceStatus.ERROR,
        reputation_score=None,
        fetched_at=_now(),
    )
    assert r.reputation_score is None


def test_lookup_response_round_trip():
    resp = LookupResponse(
        indicator=Indicator(value="8.8.8.8", type=IndicatorType.IP, normalized_value="8.8.8.8"),
        verdict=Verdict(
            classification=Classification.BENIGN,
            reputation_score=0.05,
            confidence=Confidence.HIGH,
            summary="3/3 sources responded.",
        ),
        sources=[],
        errors=[
            ErrorEntry(provider="greynoise", error_type="timeout", message="timed out")
        ],
        meta=Meta(
            server_version="0.1.0",
            query_id="abc123",
            duration_ms=512,
            providers_queried=["virustotal", "greynoise", "abuseipdb"],
            providers_skipped=[],
        ),
    )
    dumped = resp.model_dump(mode="json")
    assert dumped["verdict"]["classification"] == "benign"
    assert dumped["verdict"]["confidence"] == "high"
    assert dumped["errors"][0]["provider"] == "greynoise"
    # Round trip back through the model.
    reloaded = LookupResponse.model_validate(dumped)
    assert reloaded.verdict.confidence == Confidence.HIGH
