"""Tests for recording the final URL after redirects: when a probe's
redirect chain lands on a different host or path, the landing URL is
recorded on the validator instead of only the original subdomain.

dnspython, click and rich are not installed where the suite runs, so
these tests stub ``dns`` (same approach as test_titles.py).
``requests`` is patched on the reloaded ``subx.validator`` module with
a fake serving scripted responses whose ``.url`` is the landing URL.
"""

import sys
import types

import pytest


def _install_dns_stub(resolve_map):
    dns = types.ModuleType("dns")
    resolver_mod = types.ModuleType("dns.resolver")
    exception_mod = types.ModuleType("dns.exception")

    class NXDOMAIN(Exception):
        pass

    class NoAnswer(Exception):
        pass

    class Timeout(Exception):
        pass

    class DNSException(Exception):
        pass

    class FakeRdata:
        def __init__(self, ip):
            self._ip = ip

        def __str__(self):
            return self._ip

    class FakeResolver:
        def __init__(self, configure=True):
            self.configure = configure
            self.nameservers = []
            self.timeout = None
            self.lifetime = None

        def resolve(self, name, rdtype):
            key = str(name).rstrip(".").lower()
            if str(rdtype).upper() == "CNAME":
                raise NoAnswer(key)
            if key in resolve_map:
                return [FakeRdata(ip) for ip in resolve_map[key]]
            raise NXDOMAIN(key)

    resolver_mod.Resolver = FakeResolver
    resolver_mod.NXDOMAIN = NXDOMAIN
    resolver_mod.NoAnswer = NoAnswer
    resolver_mod.Timeout = Timeout
    exception_mod.DNSException = DNSException
    dns.resolver = resolver_mod
    dns.exception = exception_mod

    for mod_name, mod in (
        ("dns", dns),
        ("dns.resolver", resolver_mod),
        ("dns.exception", exception_mod),
    ):
        sys.modules[mod_name] = mod


@pytest.fixture()
def validator_module():
    def make(resolve_map):
        _install_dns_stub(resolve_map)
        import importlib

        import subx.validator

        importlib.reload(subx.validator)
        return subx.validator

    yield make
    for mod_name in ("dns", "dns.resolver", "dns.exception"):
        sys.modules.pop(mod_name, None)


class _FakeRequests:
    """Stand-in for ``requests`` serving scripted responses.

    ``pages`` maps a probed URL to ``(status_code, body)`` or
    ``(status_code, body, landing_url)``; the landing URL is what
    ``response.url`` reports after redirects. An unlisted URL raises
    ``ConnectionError``. A 2-tuple response carries no ``.url``
    attribute at all, like a minimal test double.
    """

    class RequestException(Exception):
        pass

    class ConnectionError(RequestException):
        pass

    class Timeout(RequestException):
        pass

    def __init__(self, pages=None):
        self.calls = []
        self.pages = pages or {}

    def get(self, url, **kwargs):
        self.calls.append(url)
        if url not in self.pages:
            raise self.ConnectionError(f"refused: {url}")
        page = self.pages[url]
        if len(page) == 3:
            status_code, body, landing = page
            return types.SimpleNamespace(
                status_code=status_code, content=body, url=landing
            )
        status_code, body = page
        return types.SimpleNamespace(status_code=status_code, content=body)


def _patch_requests(monkeypatch, module, fake):
    monkeypatch.setattr(module, "requests", fake)


def test_validate_records_final_url_when_redirect_lands_elsewhere(
    validator_module, monkeypatch
):
    module = validator_module({"a.example.com": ["1.2.3.4"]})
    fake = _FakeRequests({
        "https://a.example.com": (
            301, b"", "https://other.example.com/landing"),
    })
    _patch_requests(monkeypatch, module, fake)
    validator = module.Validator()
    assert validator.validate("a.example.com") == (["1.2.3.4"], 301, None)
    assert validator.final_urls == {
        "a.example.com": "https://other.example.com/landing",
    }


def test_validate_skips_final_url_when_landing_matches_probe(
    validator_module, monkeypatch
):
    module = validator_module({"a.example.com": ["1.2.3.4"]})
    fake = _FakeRequests({
        "https://a.example.com": (200, b"", "https://a.example.com"),
    })
    _patch_requests(monkeypatch, module, fake)
    validator = module.Validator()
    assert validator.validate("a.example.com") == (["1.2.3.4"], 200, None)
    assert validator.final_urls == {}


def test_validate_skips_final_url_when_no_http(
    validator_module, monkeypatch
):
    module = validator_module({"a.example.com": ["1.2.3.4"]})
    fake = _FakeRequests({})
    _patch_requests(monkeypatch, module, fake)
    validator = module.Validator()
    assert validator.validate("a.example.com") == (
        ["1.2.3.4"], "No HTTP", None)
    assert validator.final_urls == {}


def test_validate_records_http_fallback_final_url(
    validator_module, monkeypatch
):
    module = validator_module({"a.example.com": ["1.2.3.4"]})
    fake = _FakeRequests({
        "http://a.example.com": (
            200, b"", "http://a.example.com/welcome"),
    })
    _patch_requests(monkeypatch, module, fake)
    validator = module.Validator()
    assert validator.validate("a.example.com") == (["1.2.3.4"], 200, None)
    assert validator.final_urls == {
        "a.example.com": "http://a.example.com/welcome",
    }


def test_validate_tolerates_response_without_url_attribute(
    validator_module, monkeypatch
):
    module = validator_module({"a.example.com": ["1.2.3.4"]})
    fake = _FakeRequests({
        "https://a.example.com": (200, b""),
    })
    _patch_requests(monkeypatch, module, fake)
    validator = module.Validator()
    assert validator.validate("a.example.com") == (["1.2.3.4"], 200, None)
    assert validator.final_urls == {}
