"""Aggregate per-provider SourceReports into an overall Verdict."""

from __future__ import annotations

from app.schema import Classification, Confidence, SourceReport, SourceStatus, Verdict

# Thresholds on the 0..1 aggregated score.
_BENIGN_MAX = 0.2
_SUSPICIOUS_MAX = 0.6


def _classify_score(score: float) -> Classification:
    if score <= _BENIGN_MAX:
        return Classification.BENIGN
    if score <= _SUSPICIOUS_MAX:
        return Classification.SUSPICIOUS
    return Classification.MALICIOUS


def _confidence(ok_count: int, total_queried: int) -> Confidence:
    """Confidence depends on how many providers successfully responded."""
    if total_queried == 0 or ok_count == 0:
        return Confidence.LOW
    ratio = ok_count / total_queried
    if ok_count >= 3 and ratio == 1.0:
        return Confidence.HIGH
    if ok_count >= 2 and ratio >= 0.66:
        return Confidence.MEDIUM
    return Confidence.LOW


def aggregate(reports: list[SourceReport]) -> Verdict:
    """Build a Verdict from a list of SourceReports."""
    total_queried = len(reports)
    ok_reports = [r for r in reports if r.status == SourceStatus.OK and r.reputation_score is not None]
    ok_count = len(ok_reports)
    flagged = sum(
        1
        for r in ok_reports
        if r.classification in (Classification.SUSPICIOUS, Classification.MALICIOUS)
    )

    if ok_count == 0:
        return Verdict(
            classification=Classification.UNKNOWN,
            reputation_score=0.0,
            confidence=Confidence.LOW,
            summary=f"0/{total_queried} sources responded. Verdict unknown.",
        )

    avg_score = sum(r.reputation_score or 0.0 for r in ok_reports) / ok_count
    classification = _classify_score(avg_score)
    confidence = _confidence(ok_count, total_queried)

    summary = (
        f"{ok_count}/{total_queried} sources responded. "
        f"{flagged} flagged as suspicious or malicious."
    )

    return Verdict(
        classification=classification,
        reputation_score=round(avg_score, 3),
        confidence=confidence,
        summary=summary,
    )
