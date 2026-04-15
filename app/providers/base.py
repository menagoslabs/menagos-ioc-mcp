"""Provider ABC, error hierarchy, and shared helpers."""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import ClassVar

import httpx

from app.config import Settings
from app.indicator import IndicatorType
from app.schema import Classification, SourceReport, SourceStatus


class ProviderError(Exception):
    """Base class for provider errors. Subclasses map to a SourceStatus."""

    status: ClassVar[SourceStatus] = SourceStatus.ERROR


class ProviderTimeoutError(ProviderError):
    status = SourceStatus.TIMEOUT


class ProviderRateLimitedError(ProviderError):
    status = SourceStatus.RATE_LIMITED


class ProviderAuthError(ProviderError):
    status = SourceStatus.ERROR


class ProviderNotFoundError(ProviderError):
    status = SourceStatus.NOT_FOUND


class ProviderUnsupportedTypeError(ProviderError):
    status = SourceStatus.UNSUPPORTED


class Provider(ABC):
    """Abstract base for a threat-intel provider adapter."""

    name: ClassVar[str]
    supported_types: ClassVar[set[IndicatorType]]

    def __init__(self, http: httpx.AsyncClient, settings: Settings) -> None:
        self.http = http
        self.settings = settings

    @abstractmethod
    async def _fetch(self, value: str, itype: IndicatorType) -> SourceReport:
        """Perform the HTTP call and return a successful SourceReport.

        Subclasses should raise one of the ProviderError subclasses on failure;
        the public lookup() method below converts those into SourceReports.
        """

    async def lookup(self, value: str, itype: IndicatorType) -> SourceReport:
        """Public entry point. Never raises — always returns a SourceReport.

        The orchestrator depends on this invariant.
        """
        start = time.perf_counter()

        if itype not in self.supported_types:
            return self._failure_report(
                status=SourceStatus.UNSUPPORTED,
                start=start,
                error_message=f"{self.name} does not support indicator type {itype.value}",
            )

        try:
            report = await self._fetch(value, itype)
            # Ensure latency is set even if subclass forgot.
            if report.latency_ms == 0:
                report.latency_ms = int((time.perf_counter() - start) * 1000)
            return report
        except ProviderError as e:
            return self._failure_report(
                status=e.status,
                start=start,
                error_message=str(e) or e.__class__.__name__,
            )
        except httpx.TimeoutException as e:
            return self._failure_report(
                status=SourceStatus.TIMEOUT,
                start=start,
                error_message=f"timeout: {e}",
            )
        except httpx.HTTPStatusError as e:
            status_code = e.response.status_code
            if status_code == 429:
                st = SourceStatus.RATE_LIMITED
            elif status_code in (401, 403):
                st = SourceStatus.ERROR
            elif status_code == 404:
                st = SourceStatus.NOT_FOUND
            else:
                st = SourceStatus.ERROR
            return self._failure_report(
                status=st,
                start=start,
                error_message=f"http {status_code}",
            )
        except httpx.HTTPError as e:
            return self._failure_report(
                status=SourceStatus.ERROR,
                start=start,
                error_message=f"http error: {e.__class__.__name__}",
            )
        except Exception as e:  # pragma: no cover — last-resort safety net
            return self._failure_report(
                status=SourceStatus.ERROR,
                start=start,
                error_message=f"unexpected: {e.__class__.__name__}",
            )

    def _failure_report(
        self,
        status: SourceStatus,
        start: float,
        error_message: str,
    ) -> SourceReport:
        return SourceReport(
            provider=self.name,
            status=status,
            reputation_score=None,
            classification=None,
            raw_signals={},
            reference_url=None,
            latency_ms=int((time.perf_counter() - start) * 1000),
            fetched_at=datetime.now(timezone.utc),
            error_message=error_message,
        )

    def _ok_report(
        self,
        start: float,
        reputation_score: float,
        classification: Classification,
        raw_signals: dict,
        reference_url: str | None = None,
    ) -> SourceReport:
        return SourceReport(
            provider=self.name,
            status=SourceStatus.OK,
            reputation_score=reputation_score,
            classification=classification,
            raw_signals=raw_signals,
            reference_url=reference_url,
            latency_ms=int((time.perf_counter() - start) * 1000),
            fetched_at=datetime.now(timezone.utc),
            error_message=None,
        )

    def _not_found_report(self, start: float) -> SourceReport:
        return SourceReport(
            provider=self.name,
            status=SourceStatus.NOT_FOUND,
            reputation_score=None,
            classification=None,
            raw_signals={},
            reference_url=None,
            latency_ms=int((time.perf_counter() - start) * 1000),
            fetched_at=datetime.now(timezone.utc),
            error_message=None,
        )
