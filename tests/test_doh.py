"""Tests for the ``--doh`` DNS-over-HTTPS resolver option.

dnspython is not installed where the suite runs, so these tests stub
the ``dns``/``dns.resolver``/``dns.exception`` modules (same approach
as test_resolver.py) plus fake ``dns.query``/``dns.message`` modules
for the DoH transport. The fake ``https`` records every call, so the
tests prove queries go to the DoH endpoint instead of the UDP
resolver -- the fake resolver raises if it is ever touched.
"""

import sys
import types

import pytest


def _install_dns_stub(doh_map, timeout_failures=0):
    dns = types.ModuleType("dns")
    resolver_mod = types.ModuleType("dns.resolver")
    exception_mod = types.ModuleType("dns.exception")
    query_mod = types.ModuleType("dns.query")
    message_mod = types.ModuleType("dns.message")

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

    class FakeCnameTarget:
        def __init__(self, target):
            self.target = target

    class FakeResolver:
        def __init__(self, configure=True):
            self.configure = configure
            self.nameservers = []
            self.timeout = None
            self.lifetime = None

        def resolve(self, name, rdtype):
            raise AssertionError(
                "UDP resolver must not be used when --doh is set")

    class FakeMessage:
        def __init__(self, answer):
            # answer is a list of RRsets; each RRset is a list of rdata.
            self.answer = answer

    def make_query(name, rdtype):
        return ("query", str(name).rstrip(".").lower(), str(rdtype).upper())

    def https(url, query, timeout=None):
        https.calls.append((url, query, timeout))
        if https.timeout_failures_remaining:
            https.timeout_failures_remaining -= 1
            raise Timeout("slow DoH endpoint")
        _, name, rdtype = query
        rdata = doh_map.get((name, rdtype))
        if rdata is None:
            return FakeMessage([])
        return FakeMessage([rdata])

    https.calls = []
    https.timeout_failures_remaining = timeout_failures

    resolver_mod.Resolver = FakeResolver
    resolver_mod.NXDOMAIN = NXDOMAIN
    resolver_mod.NoAnswer = NoAnswer
    resolver_mod.Timeout = Timeout
    # Real dnspython defines dns.exception.Timeout too (resolver.Timeout
    # subclasses it); the DoH path catches it, so the stub must too.
    exception_mod.DNSException = DNSException
    exception_mod.Timeout = Timeout
    query_mod.https = https
    message_mod.make_query = make_query
    dns.resolver = resolver_mod
    dns.exception = exception_mod
    dns.query = query_mod
    dns.message = message_mod

    for mod_name, mod in (
        ("dns", dns),
        ("dns.resolver", resolver_mod),
        ("dns.exception", exception_mod),
        ("dns.query", query_mod),
        ("dns.message", message_mod),
    ):
        sys.modules[mod_name] = mod
    return https


@pytest.fixture()
def validator_factory():
    def make(doh_map=None, timeout_failures=0, **kwargs):
        https = _install_dns_stub(doh_map or {}, timeout_failures)
        import importlib

        import subx.validator

        importlib.reload(subx.validator)
        return subx.validator.Validator(**kwargs), https

    yield make
    for mod_name in ("dns", "dns.resolver", "dns.exception",
                     "dns.query", "dns.message"):
        sys.modules.pop(mod_name, None)


DOH_URL = "https://dns.cloudflare.com/dns-query"


def _doh_map(entries):
    """Build a DoH answer map from {(name, rdtype): [ip, ...]}."""

    class _Rdata:
        def __init__(self, ip):
            self._ip = ip

        def __str__(self):
            return self._ip

    return {
        (name.lower(), rdtype): [_Rdata(ip) for ip in ips]
        for (name, rdtype), ips in entries.items()
    }


def test_doh_resolves_via_https(validator_factory):
    validator, https = validator_factory(
        _doh_map({("a.example.com", "A"): ["1.2.3.4"]}),
        doh_url=DOH_URL,
    )
    assert validator.doh_url == DOH_URL
    assert validator.validate("a.example.com", check_http=False) == (
        ["1.2.3.4"],
        "N/A",
        None,
    )
    assert https.calls
    url, query, timeout = https.calls[0]
    assert url == DOH_URL
    assert query[1] == "a.example.com"
    assert timeout == validator.dns_timeout


def test_doh_follows_cname_chain(validator_factory):
    class _Rdata:
        def __init__(self, ip):
            self._ip = ip

        def __str__(self):
            return self._ip

    class _Cname:
        def __init__(self, target):
            self.target = target

    doh_map = {
        ("a.example.com", "CNAME"): [_Cname("final.example.com")],
        ("final.example.com", "A"): [_Rdata("5.6.7.8")],
    }
    validator, _ = validator_factory(doh_map, doh_url=DOH_URL)
    assert validator.validate("a.example.com", check_http=False) == (
        ["5.6.7.8"],
        "N/A",
        "final.example.com",
    )


def test_doh_empty_answer_is_a_miss(validator_factory):
    validator, _ = validator_factory({}, doh_url=DOH_URL)
    assert validator.validate("missing.example.com", check_http=False) is None


def test_doh_timeout_is_retried_then_a_miss(validator_factory):
    # The fake https raises the stub's dns.exception.Timeout; the
    # validator must retry it (dns_retries=1) and then give up like
    # a UDP timeout, never caching it as a miss.
    validator, https = validator_factory(
        _doh_map({("a.example.com", "A"): ["1.2.3.4"]}),
        timeout_failures=2,
        doh_url=DOH_URL,
        dns_retries=1,
    )
    assert validator.validate("a.example.com", check_http=False) is None
    assert len(https.calls) == 2


@pytest.mark.parametrize("bad", [
    "http://dns.cloudflare.com/dns-query",
    "dns.cloudflare.com/dns-query",
    "https://",
    "",
    "ftp://dns.cloudflare.com/dns-query",
    "not a url",
])
def test_garbage_doh_url_rejected(validator_factory, bad):
    with pytest.raises(ValueError):
        validator_factory(doh_url=bad)


def test_resolver_and_doh_conflict(validator_factory):
    with pytest.raises(ValueError):
        validator_factory(resolver_ip="1.1.1.1", doh_url=DOH_URL)


def test_default_path_still_uses_udp_resolver():
    # Without --doh, the plain resolver is used: install a stub whose
    # resolver actually answers, and prove no dns.query module is
    # needed at all.
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
            self.timeout = None
            self.lifetime = None

        def resolve(self, name, rdtype):
            if str(rdtype).upper() == "CNAME":
                raise NoAnswer(name)
            if str(name).rstrip(".").lower() == "a.example.com":
                return [FakeRdata("1.2.3.4")]
            raise NXDOMAIN(name)

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
    try:
        import importlib

        import subx.validator

        importlib.reload(subx.validator)
        validator = subx.validator.Validator()
        assert validator.doh_url is None
        assert validator.validate("a.example.com", check_http=False) == (
            ["1.2.3.4"],
            "N/A",
            None,
        )
    finally:
        for mod_name in ("dns", "dns.resolver", "dns.exception"):
            sys.modules.pop(mod_name, None)
