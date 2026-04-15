"""VirusTotal v3 API adapter. Supports IP, domain, and file hashes in v0.1."""

from __future__ import annotations

import time
from typing import ClassVar

from app.indicator import IndicatorType
from app.providers.base import (
    Provider,
    ProviderAuthError,
    ProviderNotFoundError,
    ProviderRateLimitedError,
)
from app.schema import Classification, SourceReport

_BASE = "https://www.virustotal.com/api/v3"


class VirusTotalProvider(Provider):
    name: ClassVar[str] = "virustotal"
    supported_types: ClassVar[set[IndicatorType]] = {
        IndicatorType.IP,
        IndicatorType.DOMAIN,
        IndicatorType.HASH_MD5,
        IndicatorType.HASH_SHA1,
        IndicatorType.HASH_SHA256,
    }

    def _endpoint(self, value: str, itype: IndicatorType) -> str:
        if itype == IndicatorType.IP:
            return f"{_BASE}/ip_addresses/{value}"
        if itype == IndicatorType.DOMAIN:
            return f"{_BASE}/domains/{value}"
        if itype in (
            IndicatorType.HASH_MD5,
            IndicatorType.HASH_SHA1,
            IndicatorType.HASH_SHA256,
        ):
            return f"{_BASE}/files/{value}"
        raise AssertionError(f"unreachable: {itype}")

    def _reference_url(self, value: str, itype: IndicatorType) -> str:
        if itype == IndicatorType.IP:
            return f"https://www.virustotal.com/gui/ip-address/{value}"
        if itype == IndicatorType.DOMAIN:
            return f"https://www.virustotal.com/gui/domain/{value}"
        return f"https://www.virustotal.com/gui/file/{value}"

    async def _fetch(self, value: str, itype: IndicatorType) -> SourceReport:
        start = time.perf_counter()
        api_key = self.settings.vt_api_key.get_secret_value()
        if not api_key:
            raise ProviderAuthError("VT_API_KEY not configured")

        headers = {"x-apikey": api_key, "accept": "application/json"}
        url = self._endpoint(value, itype)

        resp = await self.http.get(
            url, headers=headers, timeout=self.settings.provider_timeout_s
        )
        if resp.status_code == 404:
            raise ProviderNotFoundError(f"not found in VirusTotal: {value}")
        if resp.status_code == 429:
            raise ProviderRateLimitedError("VirusTotal rate limit exceeded")
        if resp.status_code in (401, 403):
            raise ProviderAuthError(f"VirusTotal auth error: {resp.status_code}")
        resp.raise_for_status()

        payload = resp.json()
        attrs = payload.get("data", {}).get("attributes", {}) or {}
        stats = attrs.get("last_analysis_stats", {}) or {}
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        harmless = int(stats.get("harmless", 0) or 0)
        undetected = int(stats.get("undetected", 0) or 0)
        total = malicious + suspicious + harmless + undetected

        if total == 0:
            score = 0.0
        else:
            # Weight suspicious at half the weight of malicious.
            score = (malicious + 0.5 * suspicious) / total

        if score >= 0.5:
            cls = Classification.MALICIOUS
        elif malicious > 0 or suspicious > 0:
            cls = Classification.SUSPICIOUS
        elif total > 0:
            cls = Classification.BENIGN
        else:
            cls = Classification.UNKNOWN

        raw = {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "reputation": attrs.get("reputation"),
        }

        return self._ok_report(
            start=start,
            reputation_score=score,
            classification=cls,
            raw_signals=raw,
            reference_url=self._reference_url(value, itype),
        )
