"""Indicator classification: decide whether a string is an IP, domain, URL, or hash."""

from __future__ import annotations

import ipaddress
import re
from enum import Enum


class IndicatorType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"


class InvalidIndicatorError(ValueError):
    """Raised when an input string cannot be classified as any supported indicator type."""


_MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
_SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")

# RFC 1035-ish: labels of 1-63 chars, letters/digits/hyphens, not starting or ending with hyphen.
# Allows underscores (common in practice). Total length up to 253.
_DOMAIN_LABEL = r"[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?"
# TLD must start with a letter but may contain alphanumerics/hyphens (IDN/punycode).
_TLD = r"[a-zA-Z][a-zA-Z0-9-]{1,62}"
_DOMAIN_RE = re.compile(rf"^(?:{_DOMAIN_LABEL}\.)+{_TLD}$")


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_url(value: str) -> bool:
    """We only classify a string as URL if it starts with http:// or https://."""
    return value.startswith(("http://", "https://"))


def _is_domain(value: str) -> bool:
    if len(value) > 253:
        return False
    if not _DOMAIN_RE.match(value):
        return False
    # Reject things that parse as an IP (e.g., "1.2.3.4" matches domain regex
    # with a numeric TLD, but our TLD rule is [a-zA-Z]{2,}, so IPs already won't match).
    return not _is_ip(value)


def classify(value: str) -> IndicatorType:
    """Classify an input string into an IndicatorType, or raise InvalidIndicatorError."""
    if not isinstance(value, str):
        raise InvalidIndicatorError(f"indicator must be a string, got {type(value).__name__}")

    v = value.strip()
    if not v:
        raise InvalidIndicatorError("indicator is empty")

    # Hashes first, cheapest check, unambiguous.
    if _MD5_RE.match(v):
        return IndicatorType.HASH_MD5
    if _SHA1_RE.match(v):
        return IndicatorType.HASH_SHA1
    if _SHA256_RE.match(v):
        return IndicatorType.HASH_SHA256

    # IPs (v4 or v6).
    if _is_ip(v):
        return IndicatorType.IP

    # URLs.
    if _is_url(v):
        return IndicatorType.URL

    # Domains.
    if _is_domain(v):
        return IndicatorType.DOMAIN

    raise InvalidIndicatorError(f"could not classify indicator: {v!r}")


def normalize(value: str, itype: IndicatorType) -> str:
    """Return a canonical form of the indicator (lowercased domain/hash, etc.)."""
    v = value.strip()
    if itype in (
        IndicatorType.DOMAIN,
        IndicatorType.HASH_MD5,
        IndicatorType.HASH_SHA1,
        IndicatorType.HASH_SHA256,
    ):
        return v.lower()
    if itype == IndicatorType.IP:
        try:
            return str(ipaddress.ip_address(v))
        except ValueError:
            return v
    return v
