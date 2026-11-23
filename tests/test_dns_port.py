"""Tests for the ``--dns-port`` flag: query the resolver on a
non-standard DNS port (dnspython ``Resolver.port``) for resolvers
that listen off port 53 (e.g. a local stub on 5353).

dnspython is not installed where the suite runs, so these tests stub
the ``dns``/``dns.resolver``/``dns.exception`` modules (same approach
as test_dns_tcp.py). The fake resolver records its ``port`` attribute,
so the tests prove the configured port is applied -- and that the
default stays 53. The CLI test at the bottom drives the real
``subx.cli.main`` with the same minimal click/rich/dns stubs as
test_dns_tcp.py.
"""

import json
import logging
import sys
import types

import pytest


def _install_dns_stub(resolve_map, doh_map=None):
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

    class FakeResolver:
        calls = []

        def __init__(self, configure=True):
            self.configure = configure
            self.nameservers = []
            self.timeout = None
            self.lifetime = None
            self.port = 53

        def resolve(self, name, rdtype, **kwargs):
            FakeResolver.calls.append(
                (str(name).rstrip(".").lower(),
                 str(rdtype).upper(), dict(kwargs)))
            key = (str(name).rstrip(".").lower(), str(rdtype).upper())
            if key in resolve_map:
                return [FakeRdata(ip) for ip in resolve_map[key]]
            if str(rdtype).upper() == "CNAME":
                raise NoAnswer(name)
            raise NXDOMAIN(name)

    class FakeMessage:
        def __init__(self, answer):
            self.answer = answer

    def make_query(name, rdtype):
        return ("query", str(name).rstrip(".").lower(), str(rdtype).upper())

    def https(url, query, timeout=None):
        https.calls.append((url, query, timeout))
        _, name, rdtype = query
        rdata = (doh_map or {}).get((name, rdtype))
        if rdata is None:
            return FakeMessage([])
        return FakeMessage([rdata])

    https.calls = []

    resolver_mod.Resolver = FakeResolver
    resolver_mod.NXDOMAIN = NXDOMAIN
    resolver_mod.NoAnswer = NoAnswer
    resolver_mod.Timeout = Timeout
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
    def make(resolve_map, doh_map=None, **kwargs):
        https = _install_dns_stub(resolve_map, doh_map)
        import importlib

        import subx.validator

        importlib.reload(subx.validator)
        # Fresh call log per validator: the FakeResolver class holds
        # calls on the class, so clear it after the stub is installed.
        subx.validator.dns.resolver.Resolver.calls.clear()
        return subx.validator.Validator(**kwargs), https

    yield make
    for mod_name in ("dns", "dns.resolver", "dns.exception",
                     "dns.query", "dns.message"):
        sys.modules.pop(mod_name, None)


def test_dns_port_defaults_to_53(validator_factory):
    validator, _ = validator_factory(
        {("a.example.com", "A"): ["1.2.3.4"]})
    assert validator.dns_port == 53
    assert validator.resolver.port == 53
    assert validator.validate("a.example.com", check_http=False) == (
        ["1.2.3.4"],
        "N/A",
        None,
    )


def test_dns_port_custom_applied_to_resolver(validator_factory):
    validator, _ = validator_factory(
        {("a.example.com", "A"): ["1.2.3.4"]}, dns_port=5353)
    assert validator.dns_port == 5353
    assert validator.resolver.port == 5353
    assert validator.validate("a.example.com", check_http=False) == (
        ["1.2.3.4"],
        "N/A",
        None,
    )


def test_dns_port_custom_with_custom_resolver_ip(validator_factory):
    # The port applies to the custom resolver too, not just the
    # system one: a stub resolver on 1.1.1.1:5353 is the exact case
    # this flag exists for.
    validator, _ = validator_factory(
        {("a.example.com", "A"): ["1.2.3.4"]},
        resolver_ip="1.1.1.1", dns_port=5353)
    assert validator.resolver.nameservers == ["1.1.1.1"]
    assert validator.resolver.port == 5353


@pytest.mark.parametrize("bad", [0, -1, 65536, 100000, "5353", 53.0, True])
def test_dns_port_invalid_values_fail_fast(validator_factory, bad):
    with pytest.raises(ValueError, match="dns_port"):
        validator_factory({}, dns_port=bad)


def test_dns_port_edges_accepted(validator_factory):
    for port in (1, 65535):
        validator, _ = validator_factory({}, dns_port=port)
        assert validator.resolver.port == port


# ---------------------------------------------------------------------------
# CLI wiring: --dns-port reaches Validator.
# ---------------------------------------------------------------------------

def _install_stubs():
    click = types.ModuleType("click")

    def _identity_decorator(*dargs, **dkwargs):
        def wrap(fn):
            return fn

        return wrap

    class _DummyType:
        def __init__(self, *args, **kwargs):
            pass

    click.Command = object
    click.command = _identity_decorator
    click.version_option = _identity_decorator
    click.argument = _identity_decorator
    click.option = _identity_decorator
    click.Path = _DummyType
    click.FloatRange = _DummyType
    click.IntRange = _DummyType

    rich = types.ModuleType("rich")

    class _StatusCtx:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    class Console:
        def __init__(self, *args, **kwargs):
            self.printed = []

        def print(self, *args, **kwargs):
            self.printed.append(" ".join(str(a) for a in args))

        def status(self, text):
            return _StatusCtx()

    rich_console = types.ModuleType("rich.console")
    rich_console.Console = Console

    class Table:
        def __init__(self, *args, **kwargs):
            self.rows = []

        def add_column(self, *args, **kwargs):
            pass

        def add_row(self, *args):
            self.rows.append(args)

    rich_table = types.ModuleType("rich.table")
    rich_table.Table = Table

    class _Progress:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def add_task(self, desc, total=None):
            return 0

        def update(self, task, advance=0):
            pass

    class _Column:
        def __init__(self, *args, **kwargs):
            pass

    rich_progress = types.ModuleType("rich.progress")
    rich_progress.Progress = _Progress
    for name in ("SpinnerColumn", "TextColumn", "BarColumn",
                 "TimeElapsedColumn", "MofNCompleteColumn"):
        setattr(rich_progress, name, _Column)

    class RichHandler(logging.Handler):
        def __init__(self, *args, **kwargs):
            super().__init__()

        def emit(self, record):
            pass

    rich_logging = types.ModuleType("rich.logging")
    rich_logging.RichHandler = RichHandler

    rich_panel = types.ModuleType("rich.panel")
    rich_panel.Panel = _Column

    dns = types.ModuleType("dns")
    resolver_mod = types.ModuleType("dns.resolver")
    exception_mod = types.ModuleType("dns.exception")

    class _DNSException(Exception):
        pass

    resolver_mod.Resolver = object
    resolver_mod.NXDOMAIN = _DNSException
    resolver_mod.NoAnswer = _DNSException
    resolver_mod.Timeout = _DNSException
    exception_mod.DNSException = _DNSException
    dns.resolver = resolver_mod
    dns.exception = exception_mod

    for mod_name, mod in (
        ("click", click),
        ("rich", rich),
        ("rich.console", rich_console),
        ("rich.table", rich_table),
        ("rich.progress", rich_progress),
        ("rich.logging", rich_logging),
        ("rich.panel", rich_panel),
        ("dns", dns),
        ("dns.resolver", resolver_mod),
        ("dns.exception", exception_mod),
    ):
        sys.modules[mod_name] = mod


_install_stubs()

import subx.cli  # noqa: E402  (import after stub installation)


class TestDnsPortCli:
    def _run_main(self, monkeypatch, tmp_path, dns_port=53):
        captured = {}

        class FakeValidator:
            def __init__(self, *args, **kwargs):
                captured.update(kwargs)
                self.wildcard_ips = set()
                self.wildcard_filtered = 0
                self.dns_cache_hits = 0

            def detect_wildcard(self, domain):
                return set()

            def validate(self, sub, check_http=True):
                return (["93.184.216.34"], 200, None)

        class FakeEnumerator:
            def __init__(self, domain, source_timeout=None,
                         only_sources=None):
                self.domain = domain
                self.log = None

            def passive_enumerate(self):
                return {"www.example.com"}

        monkeypatch.setattr(subx.cli, "Validator", FakeValidator)
        monkeypatch.setattr(subx.cli, "Enumerator", FakeEnumerator)

        out_file = tmp_path / "out.json"
        subx.cli.main(
            domain="example.com",
            wordlist=None,
            threads=1,
            timeout=5.0,
            http_timeout=3.0,
            dns_retries=1,
            http_retries=1,
            source_timeout=15.0,
            resolver=None,
            output=str(out_file),
            no_passive=False,
            no_brute=True,
            exclude_sub=(),
            no_http=False,
            only_live=False,
            verbose=False,
            quiet=True,
            only_source=(),
            dns_port=dns_port,
        )
        return captured, out_file

    def test_dns_port_reaches_validator(self, monkeypatch, tmp_path):
        captured, out_file = self._run_main(
            monkeypatch, tmp_path, dns_port=5353)
        assert captured["dns_port"] == 5353
        data = json.loads(out_file.read_text())
        assert [r["subdomain"] for r in data["results"]] == ["www.example.com"]

    def test_dns_port_defaults_to_53(self, monkeypatch, tmp_path):
        captured, _out_file = self._run_main(monkeypatch, tmp_path)
        assert captured["dns_port"] == 53
