"""Tests for retrying the HTTP/HTTPS probe on transient failures.

dnspython may not be installed where the suite runs, so these tests stub
the ``dns``/``dns.resolver``/``dns.exception`` modules, following the
pattern in test_http_timeout.py. ``requests`` is patched on the reloaded
``subx.validator`` module with a fake that can fail a configurable number
of times with a connection error or a timeout before succeeding.
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
    """Stand-in for ``requests`` with scripted transient failures.

    ``failures`` maps a URL scheme ("https"/"http") to a list of
    exception classes raised in order before a 200 response is
    returned. Unlisted schemes succeed immediately.
    """

    class RequestException(Exception):
        pass

    class ConnectionError(RequestException):
        pass

    class Timeout(RequestException):
        pass

    # A non-transient failure: must never be retried.
    class TooManyRedirects(RequestException):
        pass

    def __init__(self, failures=None):
        self.calls = []
        self.failures = {k: list(v) for k, v in (failures or {}).items()}

    def get(self, url, **kwargs):
        self.calls.append(url)
        scheme = url.split("://")[0]
        queued = self.failures.get(scheme, [])
        if queued:
            raise queued.pop(0)("scripted failure")
        return types.SimpleNamespace(status_code=200)


def _patched_requests(monkeypatch, fake):
    module = sys.modules["subx.validator"]
    monkeypatch.setattr(module, "requests", fake)
    return module


def test_http_retries_default(validator_factory):
    v = validator_factory({"www.example.com": ["192.0.2.10"]})
    assert v.http_retries == v.DEFAULT_HTTP_RETRIES == 1


def test_http_retries_rejects_negative(validator_factory):
    with pytest.raises(ValueError):
        validator_factory({"www.example.com": ["192.0.2.10"]}, http_retries=-1)


def test_probe_retried_once_on_connection_error(validator_factory, monkeypatch):
    fake = _FakeRequests({"https": [_FakeRequests.ConnectionError]})
    v = validator_factory({"www.example.com": ["192.0.2.10"]})
    _patched_requests(monkeypatch, fake)
    ips, status, alias = v.validate("www.example.com", check_http=True)
    assert status == 200
    assert fake.calls == ["https://www.example.com", "https://www.example.com"]
    assert v.http_probe_retries == 1


def test_probe_retried_once_on_timeout(validator_factory, monkeypatch):
    fake = _FakeRequests({"https": [_FakeRequests.Timeout]})
    v = validator_factory({"www.example.com": ["192.0.2.10"]})
    _patched_requests(monkeypatch, fake)
    ips, status, alias = v.validate("www.example.com", check_http=True)
    assert status == 200
    assert len(fake.calls) == 2
    assert v.http_probe_retries == 1


def test_probe_falls_through_after_retry_exhausted(validator_factory, monkeypatch):
    # HTTPS fails twice (initial + retry), HTTP then succeeds.
    fake = _FakeRequests(
        {"https": [_FakeRequests.ConnectionError, _FakeRequests.Timeout]}
    )
    v = validator_factory({"www.example.com": ["192.0.2.10"]})
    _patched_requests(monkeypatch, fake)
    ips, status, alias = v.validate("www.example.com", check_http=True)
    assert status == 200
    assert fake.calls == [
        "https://www.example.com",
        "https://www.example.com",
        "http://www.example.com",
    ]
    assert v.http_probe_retries == 1


def test_non_transient_failure_not_retried(validator_factory, monkeypatch):
    fake = _FakeRequests({"https": [_FakeRequests.TooManyRedirects]})
    v = validator_factory({"www.example.com": ["192.0.2.10"]})
    _patched_requests(monkeypatch, fake)
    ips, status, alias = v.validate("www.example.com", check_http=True)
    assert status == 200
    assert fake.calls == ["https://www.example.com", "http://www.example.com"]
    assert v.http_probe_retries == 0


def test_http_retries_zero_disables_retry(validator_factory, monkeypatch):
    fake = _FakeRequests({"https": [_FakeRequests.ConnectionError]})
    v = validator_factory({"www.example.com": ["192.0.2.10"]}, http_retries=0)
    _patched_requests(monkeypatch, fake)
    ips, status, alias = v.validate("www.example.com", check_http=True)
    assert status == 200
    assert fake.calls == ["https://www.example.com", "http://www.example.com"]
    assert v.http_probe_retries == 0
