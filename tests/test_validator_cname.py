"""Tests for CNAME following in ``Validator.validate``.

dnspython may not be installed where the suite runs, so these tests stub
the ``dns``/``dns.resolver``/``dns.exception`` modules instead of mocking
a real resolver. The stub is rdtype-aware: a name with no CNAME entry
raises ``NoAnswer`` (like a real resolver), names in ``cname_map``
return dnspython-style rdata objects exposing ``.target``, and names in
``resolve_map`` return A-record rdata.
"""

import sys
import types

import pytest


def _install_dns_stub(resolve_map, cname_map=None):
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
        _install_dns_stub(resolve_map, cname_map)
        import importlib

        import subx.validator

        importlib.reload(subx.validator)
        return subx.validator.Validator(**kwargs)

    yield make
    for mod_name in ("dns", "dns.resolver", "dns.exception"):
        sys.modules.pop(mod_name, None)


def test_cname_followed_and_alias_reported(validator_factory):
    v = validator_factory(
        {"cdn.provider.net": ["203.0.113.5"]},
        cname_map={"cdn.example.com": ["cdn.provider.net"]},
    )
    ips, status, alias = v.validate("cdn.example.com", check_http=False)
    assert ips == ["203.0.113.5"]
    assert status == "N/A"
    assert alias == "cdn.provider.net"


def test_cname_only_name_is_not_dropped_as_miss(validator_factory):
    # cdn.example.com has NO direct A record: without CNAME following
    # the A lookup would raise NXDOMAIN and validate() would return None.
    v = validator_factory(
        {"cdn.provider.net": ["198.51.100.23"]},
        cname_map={"cdn.example.com": ["cdn.provider.net"]},
    )
    assert v.validate("cdn.example.com", check_http=False) is not None


def test_no_cname_means_alias_is_none(validator_factory):
    v = validator_factory({"www.example.com": ["192.0.2.10"]})
    ips, status, alias = v.validate("www.example.com", check_http=False)
    assert ips == ["192.0.2.10"]
    assert alias is None


def test_cname_chain_reports_first_alias(validator_factory):
    v = validator_factory(
        {"c.example.com": ["192.0.2.44"]},
        cname_map={
            "a.example.com": ["b.example.com"],
            "b.example.com": ["c.example.com"],
        },
    )
    final, alias = v.resolve_cnames("a.example.com")
    assert final == "c.example.com"
    assert alias == "b.example.com"
    ips, status, alias = v.validate("a.example.com", check_http=False)
    assert ips == ["192.0.2.44"]
    assert alias == "b.example.com"


def test_cname_loop_is_cut(validator_factory):
    v = validator_factory(
        {"b.example.com": ["192.0.2.55"]},
        cname_map={
            "a.example.com": ["b.example.com"],
            "b.example.com": ["a.example.com"],
        },
    )
    # Must terminate instead of looping forever.
    ips, status, alias = v.validate("a.example.com", check_http=False)
    assert ips == ["192.0.2.55"]
    assert alias == "b.example.com"


def test_long_chain_stops_at_max_depth(validator_factory):
    hops = ["a", "b", "c", "d", "e", "f", "g"]
    cname_map = {
        f"{hops[i]}.example.com": [f"{hops[i + 1]}.example.com"]
        for i in range(len(hops) - 1)
    }
    v = validator_factory(
        {"f.example.com": ["192.0.2.66"]},
        cname_map=cname_map,
    )
    final, alias = v.resolve_cnames("a.example.com")
    # MAX_CNAME_DEPTH hops are followed; the chain stops at f.
    assert final == "f.example.com"
    assert alias == "b.example.com"
    ips, _, _ = v.validate("a.example.com", check_http=False)
    assert ips == ["192.0.2.66"]


def test_cname_target_nxdomain_returns_none(validator_factory):
    v = validator_factory(
        {},
        cname_map={"gone.example.com": ["dead.provider.net"]},
    )
    assert v.validate("gone.example.com", check_http=False) is None


def test_wildcard_filter_applies_to_final_target_ips(validator_factory):
    wildcard_ip = "203.0.113.10"
    v = validator_factory(
        {"cdn.provider.net": [wildcard_ip]},
        cname_map={"cdn.example.com": ["cdn.provider.net"]},
        wildcard_ips={wildcard_ip},
    )
    assert v.validate("cdn.example.com", check_http=False) is None
    assert v.wildcard_filtered == 1


def test_http_probe_uses_original_subdomain_not_alias(validator_factory, monkeypatch):
    v = validator_factory(
        {"cdn.provider.net": ["203.0.113.5"]},
        cname_map={"cdn.example.com": ["cdn.provider.net"]},
    )
    # Grab the stub-bound module object the factory reloaded -- it is
    # already in sys.modules, so do not re-import it here (and patch it
    # only after the factory's reload, which rebinds module globals).
    validator_module = sys.modules["subx.validator"]

    probed_urls = []

    class FakeResponse:
        status_code = 200

    class FakeRequests:
        class RequestException(Exception):
            pass

        @staticmethod
        def get(url, **kwargs):
            probed_urls.append(url)
            return FakeResponse()

    monkeypatch.setattr(validator_module, "requests", FakeRequests)

    ips, status, alias = v.validate("cdn.example.com", check_http=True)
    assert status == 200
    assert alias == "cdn.provider.net"
    # The Host header / TLS SNI must stay on the original name.
    assert probed_urls
    assert all("cdn.example.com" in url for url in probed_urls)
    assert not any("cdn.provider.net" in url for url in probed_urls)
