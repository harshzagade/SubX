"""Tests for the per-FQDN DNS resolution cache in ``Validator``.

The brute-force phase validates every wordlist candidate and the
validation phase then re-validates all hits, so without a cache every
brute-force hit is resolved twice (CNAME chain + A records). These
tests stub dnspython (it may not be installed where the suite runs)
with a *counting* resolver and assert that the second validation of a
name performs zero DNS queries.

The stub mirrors ``resolve_cnames`` semantics: a name with no entry in
``cname_map`` raises ``NoAnswer`` on a CNAME query (like a real
resolver), names in ``cname_map`` return dnspython-style rdata with a
``.target`` attribute, and names in ``resolve_map`` return A-record
rdata.
"""

import sys
import threading
import types

import pytest


def _install_dns_stub(resolve_map, cname_map=None, calls=None, fail_with=None):
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

    class FakeCnameRdata:
        def __init__(self, target):
            self.target = target

    class FakeResolver:
        def __init__(self):
            self.timeout = None
            self.lifetime = None

        def resolve(self, name, rdtype):
            if calls is not None:
                calls.append((str(name).rstrip(".").lower(), str(rdtype).upper()))
            if fail_with is not None:
                exc_class = {"Timeout": Timeout, "NXDOMAIN": NXDOMAIN}[fail_with]
                raise exc_class(str(name))
            key = str(name).rstrip(".").lower()
            if str(rdtype).upper() == "CNAME":
                targets = (cname_map or {}).get(key)
                if targets:
                    return [FakeCnameRdata(t) for t in targets]
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
    def make(resolve_map, cname_map=None, **kwargs):
        calls = []
        _install_dns_stub(resolve_map, cname_map, calls,
                          fail_with=kwargs.pop("fail_with", None))
        import importlib

        import subx.validator

        importlib.reload(subx.validator)
        validator = subx.validator.Validator(**kwargs)
        return validator, calls

    yield make
    # Remove the stubs so other test modules are unaffected.
    for mod_name in ("dns", "dns.resolver", "dns.exception"):
        sys.modules.pop(mod_name, None)


_REAL_IP = "198.51.100.23"


def test_second_validate_is_served_from_cache(validator_factory):
    v, calls = validator_factory({"a.example.com": [_REAL_IP]})
    first = v.validate("a.example.com", check_http=False)
    assert first is not None
    ips, status, alias = first
    assert ips == [_REAL_IP]
    assert alias is None
    first_call_count = len(calls)
    assert first_call_count == 3  # CNAME probe (NoAnswer) + A + AAAA lookups

    second = v.validate("a.example.com", check_http=False)
    assert second is not None
    assert second[0] == [_REAL_IP]
    assert len(calls) == first_call_count  # zero new DNS queries
    assert v.dns_cache_hits == 1


def test_cname_chain_and_alias_are_cached(validator_factory):
    v, calls = validator_factory(
        {"cdn.example.net": [_REAL_IP]},
        cname_map={"a.example.com": ["cdn.example.net"]},
    )
    first = v.validate("a.example.com", check_http=False)
    assert first[2] == "cdn.example.net"
    first_call_count = len(calls)

    second = v.validate("a.example.com", check_http=False)
    assert second[2] == "cdn.example.net"
    assert len(calls) == first_call_count
    assert v.dns_cache_hits == 1


def test_dead_name_is_cached_not_requeried(validator_factory):
    v, calls = validator_factory({"a.example.com": [_REAL_IP]})
    assert v.validate("ghost.example.com", check_http=False) is None
    first_call_count = len(calls)
    assert first_call_count == 3  # CNAME probe (NoAnswer) + A (NXDOMAIN) + AAAA (NXDOMAIN)

    assert v.validate("ghost.example.com", check_http=False) is None
    assert len(calls) == first_call_count
    assert v.dns_cache_hits == 1


def test_timeout_is_never_cached(validator_factory):
    v, calls = validator_factory({}, dns_retries=0, fail_with="Timeout")
    assert v.validate("a.example.com", check_http=False) is None
    assert v.validate("a.example.com", check_http=False) is None
    # Transient failures must be retried fresh, never served from cache.
    assert len(calls) == 2
    assert v.dns_cache_hits == 0


def test_wildcard_filter_applies_to_cache_hits(validator_factory):
    v, calls = validator_factory({"a.example.com": [_REAL_IP]})
    assert v.validate("a.example.com", check_http=False) is not None
    assert v.dns_cache_hits == 0

    # The CLI sets wildcard_ips after the wildcard probe, which runs
    # before brute-force/validation populate the cache -- but a
    # library caller may set it at any point, and the cached IPs must
    # still be filtered.
    v.wildcard_ips = {_REAL_IP}
    assert v.validate("a.example.com", check_http=False) is None
    assert v.dns_cache_hits == 1
    assert v.wildcard_filtered == 1


def test_cache_is_thread_safe(validator_factory):
    v, calls = validator_factory({"a.example.com": [_REAL_IP]})
    threads = [
        threading.Thread(
            target=lambda: [
                v.validate("a.example.com", check_http=False) for _ in range(25)
            ]
        )
        for _ in range(8)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    # The DNS work happens once (CNAME probe + A + AAAA lookups); every
    # other validation is a cache hit.
    assert len(calls) == 3
    assert v.dns_cache_hits == 200 - 1


def test_different_names_resolve_independently(validator_factory):
    v, calls = validator_factory(
        {"a.example.com": [_REAL_IP], "b.example.com": ["203.0.113.7"]}
    )
    assert v.validate("a.example.com", check_http=False)[0] == [_REAL_IP]
    assert v.validate("b.example.com", check_http=False)[0] == ["203.0.113.7"]
    assert v.validate("a.example.com", check_http=False)[0] == [_REAL_IP]
    # a: 3 queries + cache hit; b: 3 queries. No cross-contamination.
    assert len(calls) == 6
    assert v.dns_cache_hits == 1
