"""Tests for the configurable HTTP probe timeout on ``Validator``.

dnspython may not be installed where the suite runs, so these tests stub
the ``dns``/``dns.resolver``/``dns.exception`` modules instead of mocking
a real resolver. ``requests`` is patched on the reloaded
``subx.validator`` module (after the factory's reload, which rebinds
module globals) to observe the timeout passed to ``requests.get``.
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
        def __init__(self):
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
def validator_factory():
    def make(resolve_map, **kwargs):
        _install_dns_stub(resolve_map)
        import importlib

        import subx.validator

        importlib.reload(subx.validator)
        return subx.validator.Validator(**kwargs)

    yield make
    for mod_name in ("dns", "dns.resolver", "dns.exception"):
        sys.modules.pop(mod_name, None)


class _FakeRequests:
    """Stand-in for the ``requests`` module; records ``get`` calls."""

    class RequestException(Exception):
        pass

    def __init__(self, https_behavior="ok"):
        self.calls = []
        self.https_behavior = https_behavior

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if url.startswith("https://") and self.https_behavior != "ok":
            raise self.RequestException("https failed")
        response = types.SimpleNamespace(status_code=200)
        return response


def _patched_requests(validator_factory, monkeypatch, fake):
    # The factory reloads subx.validator with the dns stub installed;
    # patch the reloaded module object (already in sys.modules) after
    # that reload, which rebinds module globals.
    module = sys.modules["subx.validator"]
    monkeypatch.setattr(module, "requests", fake)
    return module


def test_http_timeout_default(validator_factory):
    v = validator_factory({"www.example.com": ["192.0.2.10"]})
    assert v.http_timeout == v.DEFAULT_HTTP_TIMEOUT == 3.0


def test_http_timeout_custom(validator_factory):
    v = validator_factory({"www.example.com": ["192.0.2.10"]}, http_timeout=9.5)
    assert v.http_timeout == 9.5


def test_http_timeout_rejects_non_positive(validator_factory):
    import pytest as _pytest

    with _pytest.raises(ValueError):
        validator_factory({"www.example.com": ["192.0.2.10"]}, http_timeout=0)
    with _pytest.raises(ValueError):
        validator_factory({"www.example.com": ["192.0.2.10"]}, http_timeout=-1)


def test_probe_uses_configured_timeout(validator_factory, monkeypatch):
    v = validator_factory({"www.example.com": ["192.0.2.10"]}, http_timeout=7.5)
    fake = _FakeRequests()
    _patched_requests(validator_factory, monkeypatch, fake)
    ips, status, alias = v.validate("www.example.com", check_http=True)
    assert status == 200
    assert fake.calls, "expected at least one HTTP probe"
    for url, kwargs in fake.calls:
        assert kwargs["timeout"] == 7.5


def test_both_probes_share_the_timeout(validator_factory, monkeypatch):
    # HTTPS fails, HTTP succeeds: both attempts must carry the timeout.
    fake = _FakeRequests(https_behavior="fail")
    v = validator_factory({"www.example.com": ["192.0.2.10"]}, http_timeout=2.5)
    _patched_requests(validator_factory, monkeypatch, fake)
    ips, status, alias = v.validate("www.example.com", check_http=True)
    assert status == 200
    assert [url.split("://")[0] for url, _ in fake.calls] == ["https", "http"]
    for url, kwargs in fake.calls:
        assert kwargs["timeout"] == 2.5
