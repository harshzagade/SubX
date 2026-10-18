"""Tests for two-probe wildcard detection in ``Validator``.

A single random-subdomain probe can hit an anycast fluke -- one stray
resolving name -- which would poison ``wildcard_ips`` and filter out
real candidates for the whole scan. ``detect_wildcard`` therefore probes
``WILDCARD_PROBES`` independent random names and only declares a
wildcard when at least two probes resolve AND agree on at least one IP.

dnspython may not be installed where the suite runs, so the ``dns``
modules are stubbed. The stub resolver answers each A query by popping
the next programmed response for the queried domain, so tests can
simulate agreeing probes, disagreeing probes, and a lone resolving
probe (the anycast fluke).
"""

import importlib
import sys
import types

import pytest


class _NXDOMAIN(Exception):
    pass


class _NoAnswer(Exception):
    pass


class _Timeout(Exception):
    pass


class _DNSException(Exception):
    pass


class _FakeRdata:
    def __init__(self, ip):
        self._ip = ip

    def __str__(self):
        return self._ip


def _install_dns_stub(probe_responses):
    """Stub ``dns``/``dns.resolver``/``dns.exception``.

    ``probe_responses`` maps a domain (lowercased, no trailing dot) to
    a list of per-probe responses; each response is either a list of
    IP strings (the probe resolves) or an exception *class* to raise
    (the probe does not resolve). Every A query pops the next response
    for its domain; exhausted domains raise ``_NXDOMAIN``.
    """
    dns = types.ModuleType("dns")
    resolver_mod = types.ModuleType("dns.resolver")
    exception_mod = types.ModuleType("dns.exception")

    queues = {d: list(rs) for d, rs in probe_responses.items()}

    class FakeResolver:
        def __init__(self):
            self.timeout = None
            self.lifetime = None

        def resolve(self, name, rdtype):
            key = str(name).rstrip(".").lower()
            if str(rdtype).upper() == "CNAME":
                raise _NoAnswer(key)
            labels = key.split(".")
            domain = ".".join(labels[1:])  # strip the random probe label
            queue = queues.get(domain, [])
            if not queue:
                raise _NXDOMAIN(key)
            response = queue.pop(0)
            if isinstance(response, type) and issubclass(response, Exception):
                raise response(key)
            return [_FakeRdata(ip) for ip in response]

    resolver_mod.Resolver = FakeResolver
    resolver_mod.NXDOMAIN = _NXDOMAIN
    resolver_mod.NoAnswer = _NoAnswer
    resolver_mod.Timeout = _Timeout
    exception_mod.DNSException = _DNSException
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
    def make(probe_responses, **kwargs):
        _install_dns_stub(probe_responses)
        import subx.validator

        importlib.reload(subx.validator)
        return subx.validator.Validator(**kwargs)

    yield make
    for mod_name in ("dns", "dns.resolver", "dns.exception"):
        sys.modules.pop(mod_name, None)


_FLUKE_IP = "203.0.113.99"


def test_two_agreeing_probes_declare_wildcard(validator_factory):
    v = validator_factory({"example.com": [["1.2.3.4"], ["1.2.3.4"]]})
    assert v.detect_wildcard("example.com") == {"1.2.3.4"}


def test_disagreeing_probes_are_not_a_wildcard(validator_factory):
    v = validator_factory({"example.com": [["1.2.3.4"], ["5.6.7.8"]]})
    assert v.detect_wildcard("example.com") == set()


def test_lone_resolving_probe_ignored_as_anycast_fluke(validator_factory):
    v = validator_factory({"example.com": [[_FLUKE_IP], _NXDOMAIN]})
    assert v.detect_wildcard("example.com") == set()


def test_timeout_fluke_does_not_poison(validator_factory):
    v = validator_factory({"example.com": [_Timeout, ["1.2.3.4"]]})
    assert v.detect_wildcard("example.com") == set()


def test_no_resolving_probes(validator_factory):
    v = validator_factory({"example.com": [_NXDOMAIN, _NXDOMAIN]})
    assert v.detect_wildcard("example.com") == set()


def test_partial_overlap_returns_common_ips(validator_factory):
    v = validator_factory(
        {"example.com": [["1.2.3.4", "9.9.9.9"], ["1.2.3.4"]]}
    )
    assert v.detect_wildcard("example.com") == {"1.2.3.4"}


def test_probe_queues_are_consumed_in_order(validator_factory):
    # Each probe consumes exactly one programmed response regardless of
    # the random label generated; once the queue is exhausted, no
    # wildcard can be declared.
    v = validator_factory({"example.com": [["1.2.3.4"], ["1.2.3.4"]]})
    assert v.detect_wildcard("example.com") == {"1.2.3.4"}
    assert v.detect_wildcard("example.com") == set()
