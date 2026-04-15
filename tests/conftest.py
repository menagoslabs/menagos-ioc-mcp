"""Shared pytest fixtures."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from app.config import Settings, reset_settings_cache
from pydantic import SecretStr

FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> dict:
    with (FIXTURES / name).open() as f:
        return json.load(f)


@pytest.fixture
def settings() -> Settings:
    reset_settings_cache()
    return Settings(
        VT_API_KEY=SecretStr("test-vt"),
        GREYNOISE_API_KEY=SecretStr("test-gn"),
        ABUSEIPDB_API_KEY=SecretStr("test-abuse"),
        REQUEST_TIMEOUT_S=5.0,
        PROVIDER_TIMEOUT_S=3.0,
        PROVIDER_RATE_LIMIT_PER_MIN=600,
        LOG_LEVEL="WARNING",
    )


@pytest.fixture
async def http_client() -> httpx.AsyncClient:
    async with httpx.AsyncClient() as client:
        yield client
