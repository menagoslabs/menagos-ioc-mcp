from datetime import datetime, timezone

from app.schema import Classification, Confidence, SourceReport, SourceStatus
from app.scoring import aggregate


def _ok(provider: str, score: float, cls: Classification) -> SourceReport:
    return SourceReport(
        provider=provider,
        status=SourceStatus.OK,
        reputation_score=score,
        classification=cls,
        fetched_at=datetime.now(timezone.utc),
    )


def _bad(provider: str, status: SourceStatus) -> SourceReport:
    return SourceReport(
        provider=provider,
        status=status,
        reputation_score=None,
        classification=None,
        fetched_at=datetime.now(timezone.utc),
    )


def test_all_clean_yields_benign_high():
    reports = [
        _ok("virustotal", 0.0, Classification.BENIGN),
        _ok("greynoise", 0.05, Classification.BENIGN),
        _ok("abuseipdb", 0.0, Classification.BENIGN),
    ]
    v = aggregate(reports)
    assert v.classification == Classification.BENIGN
    assert v.confidence == Confidence.HIGH
    assert v.reputation_score <= 0.2


def test_all_malicious_yields_malicious_high():
    reports = [
        _ok("virustotal", 0.9, Classification.MALICIOUS),
        _ok("greynoise", 0.95, Classification.MALICIOUS),
        _ok("abuseipdb", 0.92, Classification.MALICIOUS),
    ]
    v = aggregate(reports)
    assert v.classification == Classification.MALICIOUS
    assert v.confidence == Confidence.HIGH


def test_mixed_signals_yield_suspicious_medium():
    reports = [
        _ok("virustotal", 0.4, Classification.SUSPICIOUS),
        _ok("greynoise", 0.5, Classification.SUSPICIOUS),
        _bad("abuseipdb", SourceStatus.ERROR),
    ]
    v = aggregate(reports)
    assert v.classification == Classification.SUSPICIOUS
    assert v.confidence == Confidence.MEDIUM


def test_all_failed_yields_unknown_low():
    reports = [
        _bad("virustotal", SourceStatus.ERROR),
        _bad("greynoise", SourceStatus.TIMEOUT),
        _bad("abuseipdb", SourceStatus.RATE_LIMITED),
    ]
    v = aggregate(reports)
    assert v.classification == Classification.UNKNOWN
    assert v.confidence == Confidence.LOW
    assert v.reputation_score == 0.0


def test_one_source_yields_low_confidence():
    reports = [
        _ok("virustotal", 0.0, Classification.BENIGN),
        _bad("greynoise", SourceStatus.TIMEOUT),
        _bad("abuseipdb", SourceStatus.ERROR),
    ]
    v = aggregate(reports)
    assert v.classification == Classification.BENIGN
    assert v.confidence == Confidence.LOW  # only 1 of 3 responded
