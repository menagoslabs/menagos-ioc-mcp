"""GreyNoise Community API adapter. IP-only."""

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

_BASE = "https://api.greynoise.io/v3/community"

# GreyNoise Community returns a classification string. Map to our enum and score.
_CLASSIFICATION_MAP: dict[str, tuple[Classification, float]] = {
    "benign": (Classification.BENIGN, 0.0),
    "unknown": (Classification.UNKNOWN, 0.3),
    "suspicious": (Classification.SUSPICIOUS, 0.6),
    "malicious": (Classification.MALICIOUS, 0.95),
}


class GreyNoiseProvider(Provider):
    name: ClassVar[str] = "greynoise"
    supported_types: ClassVar[set[IndicatorType]] = {IndicatorType.IP}

    async def _fetch(self, value: str, itype: IndicatorType) -> SourceReport:
        start = time.perf_counter()
        api_key = self.settings.greynoise_api_key.get_secret_value()
        if not api_key:
            raise ProviderAuthError("GREYNOISE_API_KEY not configured")

        headers = {"key": api_key, "accept": "application/json"}
        url = f"{_BASE}/{value}"

        resp = await self.http.get(
            url, headers=headers, timeout=self.settings.provider_timeout_s
        )
        if resp.status_code == 404:
            # GreyNoise returns 404 for IPs they have no data on.
            raise ProviderNotFoundError(f"no GreyNoise data for {value}")
        if resp.status_code == 429:
            raise ProviderRateLimitedError("GreyNoise rate limit exceeded")
        if resp.status_code in (401, 403):
            raise ProviderAuthError(f"GreyNoise auth error: {resp.status_code}")
        resp.raise_for_status()

        payload = resp.json()

        # Community response shape:
        # { "ip", "noise", "riot", "classification", "name", "link", "last_seen", "message" }
        cls_string = str(payload.get("classification", "unknown")).lower()
        classification, score = _CLASSIFICATION_MAP.get(
            cls_string, (Classification.UNKNOWN, 0.3)
        )

        # RIOT-only hits (benign infrastructure) should never be flagged.
        if payload.get("riot") and not payload.get("noise"):
            classification = Classification.BENIGN
            score = min(score, 0.05)

        raw = {
            "noise": bool(payload.get("noise", False)),
            "riot": bool(payload.get("riot", False)),
            "classification": cls_string,
            "name": payload.get("name"),
            "last_seen": payload.get("last_seen"),
        }

        return self._ok_report(
            start=start,
            reputation_score=score,
            classification=classification,
            raw_signals=raw,
            reference_url=payload.get("link") or f"https://viz.greynoise.io/ip/{value}",
        )
