"""Tests for the wildcard false-positive counter on ``Validator``.

dnspython may not be installed where the suite runs, so these tests stub
the ``dns``/``dns.resolver``/``dns.exception`` modules instead of mocking
a real resolver. The stub drives ``Validator`` with a fixed
name -> [IPs] map, which is enough to exercise the wildcard filtering
logic, the counter, and its thread safety.
"""

import sys
import threading
import types

import pytest

_WILDCARD_IP = "203.0.113.10"
_REAL_IP = "198.51.100.23"


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
    def make(resolve_map, wildcard_ips=None, **kwargs):
        # Install the stub before importing subx.validator: the module
        # does `import dns.resolver` at import time and keeps the module
        # object in its globals, so reload it whenever the stub changes
        # to rebind to the current resolve_map.
        _install_dns_stub(resolve_map)
        import importlib

        import subx.validator

        importlib.reload(subx.validator)
        return subx.validator.Validator(wildcard_ips=wildcard_ips, **kwargs)

    yield make
    # Remove the stubs so other test modules are unaffected.
    for mod_name in ("dns", "dns.resolver", "dns.exception"):
        sys.modules.pop(mod_name, None)


def test_wildcard_match_dropped_and_counted(validator_factory):
    v = validator_factory(
        {"x.example.com": [_WILDCARD_IP]},
        wildcard_ips={_WILDCARD_IP},
    )
    assert v.validate("x.example.com", check_http=False) is None
    assert v.wildcard_filtered == 1


def test_mixed_ips_are_kept(validator_factory):
    v = validator_factory(
        {"mix.example.com": [_WILDCARD_IP, _REAL_IP]},
        wildcard_ips={_WILDCARD_IP},
    )
    result = v.validate("mix.example.com", check_http=False)
    assert result is not None
    ips, status = result
    assert _REAL_IP in ips
    assert v.wildcard_filtered == 0


def test_no_wildcard_set_means_nothing_filtered(validator_factory):
    v = validator_factory({"x.example.com": [_WILDCARD_IP]})
    assert v.validate("x.example.com", check_http=False) is not None
    assert v.wildcard_filtered == 0


def test_counter_is_thread_safe(validator_factory):
    v = validator_factory(
        {"x.example.com": [_WILDCARD_IP]},
        wildcard_ips={_WILDCARD_IP},
    )
    threads = [
        threading.Thread(
            target=lambda: [
                v.validate("x.example.com", check_http=False) for _ in range(25)
            ]
        )
        for _ in range(8)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert v.wildcard_filtered == 200
