"""Tests for AAAA (IPv6) resolution alongside A records.

The stub resolver is rdtype-aware: A and AAAA answers live in separate
maps, a missing type raises ``NoAnswer`` (like a real resolver), and
CNAME entries are followed before either record type is queried.
"""

import sys
import types

import pytest


def _install_dns_stub(a_map, aaaa_map=None, cname_map=None, calls=None):
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
                calls.append((str(name).rstrip(".").lower(),
                              str(rdtype).upper()))
            key = str(name).rstrip(".").lower()
            rtype = str(rdtype).upper()
            if rtype == "CNAME":
                targets = (cname_map or {}).get(key)
                if targets:
                    return [FakeCnameRdata(t) for t in targets]
                raise NoAnswer(key)
            table = a_map if rtype == "A" else (aaaa_map or {})
            if key in table:
                return [FakeRdata(ip) for ip in table[key]]
            raise NoAnswer(key)

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
    def make(a_map, aaaa_map=None, cname_map=None, **kwargs):
        calls = []
        _install_dns_stub(a_map, aaaa_map, cname_map, calls)
        import importlib

        import subx.validator

        importlib.reload(subx.validator)
        return subx.validator.Validator(**kwargs), calls

    yield make
    for mod_name in ("dns", "dns.resolver", "dns.exception"):
        sys.modules.pop(mod_name, None)


def test_dual_stack_reports_a_then_aaaa(validator_factory):
    v, _ = validator_factory(
        {"www.example.com": ["192.0.2.10"]},
        {"www.example.com": ["2001:db8::1"]},
    )
    ips, status, alias = v.validate("www.example.com", check_http=False)
    assert ips == ["192.0.2.10", "2001:db8::1"]
    assert status == "N/A"
    assert alias is None


def test_ipv6_only_host_is_not_a_miss(validator_factory):
    v, _ = validator_factory(
        {},
        {"v6.example.com": ["2001:db8::2"]},
    )
    result = v.validate("v6.example.com", check_http=False)
    assert result is not None
    assert result[0] == ["2001:db8::2"]


def test_ipv4_only_host_unchanged(validator_factory):
    v, _ = validator_factory({"www.example.com": ["192.0.2.10"]})
    ips, _, _ = v.validate("www.example.com", check_http=False)
    assert ips == ["192.0.2.10"]


def test_aaaa_followed_through_cname(validator_factory):
    v, _ = validator_factory(
        {"cdn.provider.net": ["203.0.113.5"]},
        {"cdn.provider.net": ["2001:db8::3"]},
        cname_map={"cdn.example.com": ["cdn.provider.net"]},
    )
    ips, _, alias = v.validate("cdn.example.com", check_http=False)
    assert ips == ["203.0.113.5", "2001:db8::3"]
    assert alias == "cdn.provider.net"


def test_wildcard_filter_applies_to_ipv6_set(validator_factory):
    # All-v6-wildcard host: filtered, like an all-v4-wildcard host.
    v, _ = validator_factory(
        {},
        {"v6.example.com": ["2001:db8::9"]},
        wildcard_ips={"2001:db8::9"},
    )
    assert v.validate("v6.example.com", check_http=False) is None
    assert v.wildcard_filtered == 1

    # Mixed host (unique v4 + wildcard v6): kept, per the filter rule.
    v2, _ = validator_factory(
        {"mix.example.com": ["192.0.2.20"]},
        {"mix.example.com": ["2001:db8::9"]},
        wildcard_ips={"2001:db8::9"},
    )
    result = v2.validate("mix.example.com", check_http=False)
    assert result is not None
    assert result[0] == ["192.0.2.20", "2001:db8::9"]
    assert v2.wildcard_filtered == 0


def test_aaaa_result_is_cached_like_a(validator_factory):
    v, calls = validator_factory(
        {"a.example.com": ["198.51.100.23"]},
        {"a.example.com": ["2001:db8::4"]},
    )
    first = v.validate("a.example.com", check_http=False)
    assert first[0] == ["198.51.100.23", "2001:db8::4"]
    # CNAME probe + A lookup + AAAA lookup on the first validation.
    assert len(calls) == 3
    assert v.validate("a.example.com", check_http=False)[0] == first[0]
    assert len(calls) == 3  # second validation served from the cache
    assert v.dns_cache_hits == 1


def test_duplicate_ips_across_types_deduplicated(validator_factory):
    # Defensive: a resolver returning the same address for both types
    # (as the older non-rdtype-aware stubs do) must not double-report it.
    v, _ = validator_factory(
        {"www.example.com": ["192.0.2.10"]},
        {"www.example.com": ["192.0.2.10"]},
    )
    ips, _, _ = v.validate("www.example.com", check_http=False)
    assert ips == ["192.0.2.10"]
