"""Tests for the DNS retry-on-timeout policy in ``Validator``.

dnspython may not be installed where the suite runs, so these tests stub
the ``dns``/``dns.resolver``/``dns.exception`` modules. The flaky
resolver raises ``Timeout`` a configurable number of times for a name
before answering, so the retry path is exercised without real DNS.
"""

import sys
import types

import pytest


def _install_dns_stub(resolve_map, cname_map=None, flaky_timeouts=None):
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
            self.calls = []

        def resolve(self, name, rdtype):
            key = str(name).rstrip(".").lower()
            rtype = str(rdtype).upper()
            self.calls.append((key, rtype))
            # ``flaky_timeouts`` is keyed by (name, rdtype) so timeouts can
            # be injected on exactly the query under test.
            timeouts_left = (flaky_timeouts or {}).get((key, rtype), 0)
            if timeouts_left > 0:
                flaky_timeouts[(key, rtype)] = timeouts_left - 1
                raise Timeout(key)
            if rtype == "CNAME":
                targets = (cname_map or {}).get(key)
                if targets:
                    return [FakeCnameTarget(t) for t in targets]
                raise NoAnswer(key)
            if key in resolve_map:
                return [FakeRdata(ip) for ip in resolve_map[key]]
            raise NXDOMAIN(key)

    class FakeCnameTarget:
        def __init__(self, target):
            self.target = target

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
    def make(resolve_map, cname_map=None, flaky_timeouts=None, **kwargs):
        _install_dns_stub(resolve_map, cname_map, flaky_timeouts)
        import importlib

        import subx.validator

        importlib.reload(subx.validator)
        return subx.validator.Validator(**kwargs)

    yield make
    for mod_name in ("dns", "dns.resolver", "dns.exception"):
        sys.modules.pop(mod_name, None)


def test_timeout_once_then_succeeds(validator_factory):
    # A single timeout is retried (default dns_retries=1) and the
    # candidate survives instead of being dropped as a miss.
    v = validator_factory(
        {"www.example.com": ["192.0.2.10"]},
        flaky_timeouts={("www.example.com", "A"): 1},
    )
    assert v.validate("www.example.com", check_http=False) is not None
    # The injected timeout hits the A-record query: it is retried once
    # (dns_retries=1) and succeeds, so the candidate survives instead of
    # being dropped as a miss.
    a_calls = [c for c in v.resolver.calls if c[1] == "A"]
    assert len(a_calls) == 2


def test_timeout_exhausted_returns_none(validator_factory):
    # Three timeouts with dns_retries=1 means the retry is also lost;
    # validate() treats the candidate as a miss.
    v = validator_factory(
        {"www.example.com": ["192.0.2.10"]},
        flaky_timeouts={("www.example.com", "A"): 3},
        dns_retries=1,
    )
    assert v.validate("www.example.com", check_http=False) is None


def test_nxdomain_is_not_retried(validator_factory):
    # Definitive answers fail fast: one query only, no retry loop.
    v = validator_factory({}, dns_retries=2)
    assert v.validate("nope.example.com", check_http=False) is None
    a_calls = [c for c in v.resolver.calls if c[1] == "A"]
    assert len(a_calls) == 1


def test_dns_retries_zero_disables_retry(validator_factory):
    v = validator_factory(
        {"www.example.com": ["192.0.2.10"]},
        flaky_timeouts={("www.example.com", "A"): 2},
        dns_retries=0,
    )
    assert v.validate("www.example.com", check_http=False) is None
    a_calls = [c for c in v.resolver.calls if c[1] == "A"]
    assert len(a_calls) == 1


def test_invalid_dns_retries_rejected(validator_factory):
    v = validator_factory({})
    with pytest.raises(ValueError):
        v.__init__(dns_retries=-1)
    with pytest.raises(ValueError):
        v.__init__(dns_retries="1")
