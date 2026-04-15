"""Structured JSON logging to stdout with secret and indicator redaction."""

from __future__ import annotations

import logging
import sys
from typing import Any

import structlog

_SENSITIVE_KEYS = {
    "api_key",
    "apikey",
    "vt_api_key",
    "greynoise_api_key",
    "abuseipdb_api_key",
    "authorization",
    "x-apikey",
    "key",
    "token",
    "secret",
    "password",
}


def _redact_secrets(
    logger: logging.Logger, method_name: str, event_dict: dict[str, Any]
) -> dict[str, Any]:
    """structlog processor: replace any sensitive value with '***REDACTED***'."""
    for key in list(event_dict.keys()):
        if key.lower() in _SENSITIVE_KEYS:
            event_dict[key] = "***REDACTED***"
    return event_dict


def _truncate_indicator(value: str) -> str:
    """Hash-like truncation: keep first 4 and last 4 characters."""
    if len(value) <= 12:
        return value[:2] + "***" + value[-2:] if len(value) > 4 else "***"
    return f"{value[:4]}***{value[-4:]}"


def make_indicator_processor(log_full: bool):
    """Build a structlog processor that optionally truncates 'indicator' fields."""

    def processor(
        logger: logging.Logger, method_name: str, event_dict: dict[str, Any]
    ) -> dict[str, Any]:
        if log_full:
            return event_dict
        for key in ("indicator", "indicator_value", "value"):
            if key in event_dict and isinstance(event_dict[key], str):
                event_dict[key] = _truncate_indicator(event_dict[key])
        return event_dict

    return processor


def configure_logging(level: str = "INFO", log_full_indicators: bool = False) -> None:
    """Configure structlog + stdlib logging to emit JSON to stdout."""
    log_level = getattr(logging, level.upper(), logging.INFO)

    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=log_level,
    )

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            _redact_secrets,
            make_indicator_processor(log_full_indicators),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Return a structlog logger. Pass the module name for provenance."""
    return structlog.get_logger(name) if name else structlog.get_logger()
