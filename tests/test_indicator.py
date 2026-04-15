import pytest

from app.indicator import (
    IndicatorType,
    InvalidIndicatorError,
    classify,
    normalize,
)


@pytest.mark.parametrize(
    "value,expected",
    [
        ("8.8.8.8", IndicatorType.IP),
        ("1.1.1.1", IndicatorType.IP),
        ("2001:4860:4860::8888", IndicatorType.IP),
        ("::1", IndicatorType.IP),
        ("example.com", IndicatorType.DOMAIN),
        ("sub.example.co.uk", IndicatorType.DOMAIN),
        ("xn--e1afmkfd.xn--p1ai", IndicatorType.DOMAIN),  # punycode
        ("https://example.com/path?q=1", IndicatorType.URL),
        ("http://127.0.0.1:8080", IndicatorType.URL),
        ("d41d8cd98f00b204e9800998ecf8427e", IndicatorType.HASH_MD5),
        ("da39a3ee5e6b4b0d3255bfef95601890afd80709", IndicatorType.HASH_SHA1),
        (
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            IndicatorType.HASH_SHA256,
        ),
        # uppercase hashes should still classify
        ("D41D8CD98F00B204E9800998ECF8427E", IndicatorType.HASH_MD5),
    ],
)
def test_classify_valid(value: str, expected: IndicatorType) -> None:
    assert classify(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "",
        "   ",
        "not an indicator",
        "..",
        ".example",
        "example.",
        "999.999.999.999",  # invalid IP octets
        "abc",  # no TLD
        "1234567890abcdef",  # 16 hex — not a valid hash length
    ],
)
def test_classify_invalid(value: str) -> None:
    with pytest.raises(InvalidIndicatorError):
        classify(value)


def test_classify_rejects_non_string() -> None:
    with pytest.raises(InvalidIndicatorError):
        classify(123)  # type: ignore[arg-type]


def test_normalize_lowercases_domain() -> None:
    assert normalize("Example.COM", IndicatorType.DOMAIN) == "example.com"


def test_normalize_lowercases_hash() -> None:
    h = "D41D8CD98F00B204E9800998ECF8427E"
    assert normalize(h, IndicatorType.HASH_MD5) == h.lower()


def test_normalize_canonicalizes_ipv6() -> None:
    assert normalize("2001:4860:4860:0000:0000:0000:0000:8888", IndicatorType.IP) == "2001:4860:4860::8888"


def test_normalize_passes_through_url() -> None:
    u = "https://Example.com/Path"
    assert normalize(u, IndicatorType.URL) == u
