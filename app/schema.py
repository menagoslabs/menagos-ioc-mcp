"""Pydantic models for the normalized lookup_ioc response."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator

from app.indicator import IndicatorType


class Classification(str, Enum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class SourceStatus(str, Enum):
    OK = "ok"
    NOT_FOUND = "not_found"
    UNSUPPORTED = "unsupported"
    ERROR = "error"
    TIMEOUT = "timeout"
    RATE_LIMITED = "rate_limited"


class Indicator(BaseModel):
    value: str
    type: IndicatorType
    normalized_value: str


class SourceReport(BaseModel):
    provider: str
    status: SourceStatus
    reputation_score: float | None = None
    classification: Classification | None = None
    raw_signals: dict[str, Any] = Field(default_factory=dict)
    reference_url: str | None = None
    latency_ms: int = 0
    fetched_at: datetime
    error_message: str | None = None

    @field_validator("reputation_score")
    @classmethod
    def _clamp_score(cls, v: float | None) -> float | None:
        if v is None:
            return None
        if v < 0.0:
            return 0.0
        if v > 1.0:
            return 1.0
        return v


class Verdict(BaseModel):
    classification: Classification
    reputation_score: float = Field(ge=0.0, le=1.0)
    confidence: Confidence
    summary: str


class ErrorEntry(BaseModel):
    provider: str
    error_type: str
    message: str


class Meta(BaseModel):
    server_version: str
    query_id: str
    duration_ms: int
    providers_queried: list[str]
    providers_skipped: list[str] = Field(default_factory=list)


class LookupResponse(BaseModel):
    indicator: Indicator
    verdict: Verdict
    sources: list[SourceReport]
    errors: list[ErrorEntry] = Field(default_factory=list)
    meta: Meta
