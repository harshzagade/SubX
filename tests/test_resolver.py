"""Tests for the ``--resolver`` custom DNS resolver option.

dnspython may not be installed where the suite runs, so these tests stub
the ``dns``/``dns.resolver``/``dns.exception`` modules (same approach as
``test_dns_retry.py``). The stub resolver records whether it was built
with ``configure=False`` and which nameservers it was given, so the
custom-resolver wiring is exercised without real DNS.
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

    class FakeCnameTarget:
        def __init__(self, target):
            self.target = target

    class FakeResolver:
        instances = []

        def __init__(self, configure=True):
            self.configure = configure
            self.nameservers = []
            self.timeout = None
            self.lifetime = None
            FakeResolver.instances.append(self)

        def resolve(self, name, rdtype):
            key = str(name).rstrip(".").lower()
            rtype = str(rdtype).upper()
            if rtype == "CNAME":
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
    return FakeResolver


@pytest.fixture(autouse=True)
def _clean_dns_stub():
    for name in ("dns", "dns.resolver", "dns.exception"):
        sys.modules.pop(name, None)
    for name in list(sys.modules):
        if name == "subx.validator" or name.startswith("subx.validator."):
            sys.modules.pop(name)
    yield
    for name in ("dns", "dns.resolver", "dns.exception"):
        sys.modules.pop(name, None)
    for name in list(sys.modules):
        if name == "subx.validator" or name.startswith("subx.validator."):
            sys.modules.pop(name)


def _validator(**kwargs):
    _install_dns_stub({"a.example.com": ["1.2.3.4"]})
    from subx.validator import Validator

    return Validator(**kwargs)


def test_custom_resolver_uses_configure_false_and_nameserver():
    validator = _validator(resolver_ip="1.1.1.1")
    assert validator.resolver_ip == "1.1.1.1"
    assert validator.resolver.configure is False
    assert validator.resolver.nameservers == ["1.1.1.1"]
    assert validator.resolver.timeout == validator.dns_timeout
    assert validator.resolver.lifetime == validator.dns_timeout


def test_custom_ipv6_resolver_accepted():
    validator = _validator(resolver_ip="2606:4700:4700::1111")
    assert validator.resolver_ip == "2606:4700:4700::1111"
    assert validator.resolver.nameservers == ["2606:4700:4700::1111"]


def test_default_resolver_unchanged():
    validator = _validator()
    assert validator.resolver_ip is None
    assert validator.resolver.configure is True
    assert validator.resolver.nameservers == []


@pytest.mark.parametrize("bad", ["not-an-ip", "999.1.1.1", "", "1.1.1.1/32", "example.com"])
def test_garbage_resolver_rejected(bad):
    with pytest.raises(ValueError):
        _validator(resolver_ip=bad)


def test_validate_uses_custom_resolver():
    validator = _validator(resolver_ip="8.8.8.8")
    assert validator.validate("a.example.com", check_http=False) == (
        ["1.2.3.4"],
        "N/A",
        None,
    )
