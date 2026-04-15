"""Orchestrator: classify the indicator, fan out to providers, aggregate."""

from __future__ import annotations

import asyncio
import time
import uuid
from datetime import datetime, timezone

import httpx

from app import __version__
from app.config import Settings, get_settings
from app.indicator import (
    IndicatorType,
    InvalidIndicatorError,
    classify,
    normalize,
)
from app.logging_config import get_logger
from app.providers.abuseipdb import AbuseIPDBProvider
from app.providers.base import Provider
from app.providers.greynoise import GreyNoiseProvider
from app.providers.virustotal import VirusTotalProvider
from app.rate_limit import RateLimiter
from app.schema import (
    ErrorEntry,
    Indicator,
    LookupResponse,
    Meta,
    SourceReport,
    SourceStatus,
)
from app.scoring import aggregate

log = get_logger("app.lookup")


def _build_providers(http: httpx.AsyncClient, settings: Settings) -> list[Provider]:
    return [
        VirusTotalProvider(http, settings),
        GreyNoiseProvider(http, settings),
        AbuseIPDBProvider(http, settings),
    ]


async def _run_one(
    provider: Provider,
    value: str,
    itype: IndicatorType,
    settings: Settings,
    limiter: RateLimiter,
) -> SourceReport:
    """Run one provider call with rate limiting and per-provider timeout."""
    start = time.perf_counter()

    if not await limiter.try_acquire(provider.name):
        log.warning(
            "provider_rate_limited_locally",
            provider=provider.name,
            indicator=value,
        )
        return SourceReport(
            provider=provider.name,
            status=SourceStatus.RATE_LIMITED,
            reputation_score=None,
            classification=None,
            raw_signals={},
            reference_url=None,
            latency_ms=int((time.perf_counter() - start) * 1000),
            fetched_at=datetime.now(timezone.utc),
            error_message="local rate limit bucket empty",
        )

    try:
        return await asyncio.wait_for(
            provider.lookup(value, itype),
            timeout=settings.provider_timeout_s,
        )
    except asyncio.TimeoutError:
        log.warning(
            "provider_timeout",
            provider=provider.name,
            indicator=value,
            timeout_s=settings.provider_timeout_s,
        )
        return SourceReport(
            provider=provider.name,
            status=SourceStatus.TIMEOUT,
            reputation_score=None,
            classification=None,
            raw_signals={},
            reference_url=None,
            latency_ms=int((time.perf_counter() - start) * 1000),
            fetched_at=datetime.now(timezone.utc),
            error_message=f"timed out after {settings.provider_timeout_s}s",
        )


class LookupService:
    """Holds a shared httpx client + rate limiter across lookup_ioc calls."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self._http: httpx.AsyncClient | None = None
        self._limiter = RateLimiter(rate_per_minute=self.settings.provider_rate_limit_per_min)

    async def _ensure_client(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient(
                timeout=httpx.Timeout(self.settings.request_timeout_s),
                headers={"user-agent": f"menagos-ioc-mcp/{__version__}"},
            )
        return self._http

    async def close(self) -> None:
        if self._http is not None:
            await self._http.aclose()
            self._http = None

    async def lookup(self, value: str) -> LookupResponse:
        """Main entry point. Classifies, fans out, aggregates. Never raises for
        valid indicators — only raises InvalidIndicatorError for garbage input.
        """
        query_id = uuid.uuid4().hex[:12]
        overall_start = time.perf_counter()

        itype = classify(value)  # may raise InvalidIndicatorError
        normalized = normalize(value, itype)

        log.info(
            "lookup_start",
            query_id=query_id,
            indicator=normalized,
            indicator_type=itype.value,
        )

        http = await self._ensure_client()
        providers = _build_providers(http, self.settings)

        applicable = [p for p in providers if itype in p.supported_types]
        skipped = [p.name for p in providers if itype not in p.supported_types]

        tasks = [
            _run_one(p, normalized, itype, self.settings, self._limiter) for p in applicable
        ]

        if tasks:
            reports: list[SourceReport] = await asyncio.gather(*tasks, return_exceptions=False)
        else:
            reports = []

        # For providers we skipped at classification time (unsupported type),
        # add a synthetic "unsupported" entry so the response surface is consistent.
        for name in skipped:
            reports.append(
                SourceReport(
                    provider=name,
                    status=SourceStatus.UNSUPPORTED,
                    reputation_score=None,
                    classification=None,
                    raw_signals={},
                    reference_url=None,
                    latency_ms=0,
                    fetched_at=datetime.now(timezone.utc),
                    error_message=f"{name} does not support {itype.value}",
                )
            )

        # Exclude unsupported reports from verdict aggregation so coverage ratios make sense.
        aggregated_inputs = [r for r in reports if r.status != SourceStatus.UNSUPPORTED]
        verdict = aggregate(aggregated_inputs)

        errors = [
            ErrorEntry(
                provider=r.provider,
                error_type=r.status.value,
                message=r.error_message or "",
            )
            for r in reports
            if r.status not in (SourceStatus.OK, SourceStatus.UNSUPPORTED)
        ]

        duration_ms = int((time.perf_counter() - overall_start) * 1000)

        response = LookupResponse(
            indicator=Indicator(value=value, type=itype, normalized_value=normalized),
            verdict=verdict,
            sources=reports,
            errors=errors,
            meta=Meta(
                server_version=__version__,
                query_id=query_id,
                duration_ms=duration_ms,
                providers_queried=[p.name for p in applicable],
                providers_skipped=skipped,
            ),
        )

        log.info(
            "lookup_complete",
            query_id=query_id,
            indicator=normalized,
            classification=verdict.classification.value,
            confidence=verdict.confidence.value,
            duration_ms=duration_ms,
            ok_count=sum(1 for r in reports if r.status == SourceStatus.OK),
            error_count=len(errors),
        )

        return response


async def lookup_ioc(value: str) -> dict:
    """Module-level helper used by the MCP tool. Returns a plain dict."""
    service = _service_singleton()
    try:
        response = await service.lookup(value)
        return response.model_dump(mode="json")
    except InvalidIndicatorError as e:
        # Surface a structured error dict so the MCP layer can convert it to a tool error.
        return {
            "error": "invalid_indicator",
            "message": str(e),
        }


_service: LookupService | None = None


def _service_singleton() -> LookupService:
    global _service
    if _service is None:
        _service = LookupService()
    return _service


async def shutdown() -> None:
    """Close the shared httpx client (used at server shutdown)."""
    global _service
    if _service is not None:
        await _service.close()
        _service = None
