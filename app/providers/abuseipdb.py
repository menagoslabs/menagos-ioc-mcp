"""AbuseIPDB adapter. IP-only."""

from __future__ import annotations

import time
from typing import ClassVar

from app.indicator import IndicatorType
from app.providers.base import (
    Provider,
    ProviderAuthError,
    ProviderRateLimitedError,
)
from app.schema import Classification, SourceReport

_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"


class AbuseIPDBProvider(Provider):
    name: ClassVar[str] = "abuseipdb"
    supported_types: ClassVar[set[IndicatorType]] = {IndicatorType.IP}

    async def _fetch(self, value: str, itype: IndicatorType) -> SourceReport:
        start = time.perf_counter()
        api_key = self.settings.abuseipdb_api_key.get_secret_value()
        if not api_key:
            raise ProviderAuthError("ABUSEIPDB_API_KEY not configured")

        headers = {"Key": api_key, "Accept": "application/json"}
        params = {"ipAddress": value, "maxAgeInDays": 90}

        resp = await self.http.get(
            _CHECK_URL,
            headers=headers,
            params=params,
            timeout=self.settings.provider_timeout_s,
        )
        if resp.status_code == 429:
            raise ProviderRateLimitedError("AbuseIPDB rate limit exceeded")
        if resp.status_code in (401, 403):
            raise ProviderAuthError(f"AbuseIPDB auth error: {resp.status_code}")
        resp.raise_for_status()

        data = resp.json().get("data", {}) or {}
        abuse_score = int(data.get("abuseConfidenceScore", 0) or 0)
        total_reports = int(data.get("totalReports", 0) or 0)

        score = abuse_score / 100.0
        # Classification tracks abuse *confidence*, not raw report count.
        # Well-known infrastructure like 8.8.8.8 always has some stray reports
        # that weren't verified as abuse, we don't want to call that suspicious.
        if abuse_score >= 50:
            classification = Classification.MALICIOUS
        elif abuse_score >= 20:
            classification = Classification.SUSPICIOUS
        else:
            classification = Classification.BENIGN

        raw = {
            "abuseConfidenceScore": abuse_score,
            "totalReports": total_reports,
            "countryCode": data.get("countryCode"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "usageType": data.get("usageType"),
            "lastReportedAt": data.get("lastReportedAt"),
        }

        return self._ok_report(
            start=start,
            reputation_score=score,
            classification=classification,
            raw_signals=raw,
            reference_url=f"https://www.abuseipdb.com/check/{value}",
        )
