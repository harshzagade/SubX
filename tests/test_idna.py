"""Tests for IDN/punycode support (``to_ascii_domain``).

``to_ascii_domain`` is stdlib-only, so most tests need no stubs. The
last two verify that ``Validator`` actually queries the punycode form,
using the same ``dns``-stub pattern as the other validator tests.
"""

import sys
import types

import pytest


def _to_ascii(name):
    """Lazily import: ``subx.validator`` needs the ``dns`` stub at import
    time, so it cannot be imported at module scope in this env."""
    import subx.validator

    return subx.validator.to_ascii_domain(name)


def test_ascii_passthrough():
    assert _to_ascii("example.com") == "example.com"


def test_unicode_to_punycode():
    assert _to_ascii("münchen.de") == "xn--mnchen-3ya.de"


def test_snowman_to_punycode():
    assert _to_ascii("☃.net") == "xn--n3h.net"


def test_uppercase_lowercased():
    assert _to_ascii("Example.COM") == "example.com"
    assert _to_ascii("MÜNCHEN.de") == "xn--mnchen-3ya.de"


def test_trailing_dot_stripped():
    assert _to_ascii("example.com.") == "example.com"
    assert _to_ascii("münchen.de.") == "xn--mnchen-3ya.de"


def test_whitespace_stripped():
    assert _to_ascii("  example.com  ") == "example.com"


def test_idempotent_on_punycode():
    assert _to_ascii("xn--mnchen-3ya.de") == "xn--mnchen-3ya.de"


def test_empty_rejected():
    with pytest.raises(ValueError):
        _to_ascii("")
    with pytest.raises(ValueError):
        _to_ascii("   ")


def test_empty_label_rejected():
    with pytest.raises(ValueError):
        _to_ascii("a..example.com")
    with pytest.raises(ValueError):
        _to_ascii(".example.com")


def test_invalid_chars_rejected():
    with pytest.raises(ValueError):
        _to_ascii("exa mple.com")
    with pytest.raises(ValueError):
        _to_ascii("ex_ample.com")


def test_overlong_label_rejected():
    with pytest.raises(ValueError):
        _to_ascii("a" * 64 + ".com")


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
            self.calls = []

        def resolve(self, name, rdtype):
            key = str(name).rstrip(".").lower()
            self.calls.append((key, str(rdtype).upper()))
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


def test_validate_queries_punycode_form(validator_factory):
    v = validator_factory({"xn--mnchen-3ya.de": ["192.0.2.10"]})
    result = v.validate("münchen.de", check_http=False)
    assert result is not None
    ips, status, alias = result
    assert ips == ["192.0.2.10"]
    a_calls = [c for c in v.resolver.calls if c[1] == "A"]
    assert ("xn--mnchen-3ya.de", "A") in a_calls
    assert not any("münchen" in name for name, _ in v.resolver.calls)


def test_detect_wildcard_queries_punycode_form(validator_factory):
    v = validator_factory({})
    v.detect_wildcard("münchen.de")
    probed = [name for name, _ in v.resolver.calls]
    assert probed, "expected a wildcard probe query"
    assert all(name.endswith(".xn--mnchen-3ya.de") for name in probed)
