"""Tests for the ``--no-follow-redirects`` flag: the probe reports the
first response's status instead of following the redirect chain, so
pipelines see the raw 301/302 rather than the landing page's 200.

dnspython may not be installed where the suite runs, so these tests stub
the ``dns``/``dns.resolver``/``dns.exception`` modules, following the
pattern in test_http_retry.py. ``requests`` is patched on the reloaded
``subx.validator`` module with a fake whose response depends on the
``allow_redirects`` kwarg it receives. The CLI test at the bottom drives
the real ``subx.cli.main`` with the same minimal click/rich/dns stubs
as test_skip_passive.py.
"""

import json
import logging
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

    class FakeResolver:
        def __init__(self):
            self.timeout = None
            self.lifetime = None

        def resolve(self, name, rdtype):
            key = str(name).rstrip(".").lower()
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


class _FakeRequests:
    """Stand-in for ``requests`` with redirect-aware responses.

    With ``allow_redirects=True`` the probe "lands" on a different URL
    with a 200 and a titled page; with ``allow_redirects=False`` it
    sees the raw 301 at the probed URL with an empty body. Every call
    records its ``allow_redirects`` value so tests can prove the flag
    actually reached ``requests.get``.
    """

    class RequestException(Exception):
        pass

    class ConnectionError(RequestException):
        pass

    class Timeout(RequestException):
        pass

    def __init__(self):
        self.calls = []

    def get(self, url, **kwargs):
        follow = kwargs.get("allow_redirects")
        self.calls.append((url, follow))
        if follow:
            return types.SimpleNamespace(
                status_code=200,
                url=url + "/landing",
                content=b"<html><head><title>Landing Page</title></head></html>",
            )
        return types.SimpleNamespace(
            status_code=301, url=url, content=b"")


def _patched_requests(monkeypatch, fake):
    module = sys.modules["subx.validator"]
    monkeypatch.setattr(module, "requests", fake)
    return module


def test_follow_redirects_default(validator_factory, monkeypatch):
    v = validator_factory({"www.example.com": ["192.0.2.10"]})
    assert v.follow_redirects is True
    fake = _FakeRequests()
    _patched_requests(monkeypatch, fake)
    ips, status, alias = v.validate("www.example.com", check_http=True)
    assert status == 200
    assert fake.calls == [("https://www.example.com", True)]
    # The probe landed elsewhere, so the final URL is recorded.
    assert v.final_urls == {
        "www.example.com": "https://www.example.com/landing"}


def test_no_follow_redirects_reports_first_status(
        validator_factory, monkeypatch):
    v = validator_factory({"www.example.com": ["192.0.2.10"]},
                          follow_redirects=False)
    assert v.follow_redirects is False
    fake = _FakeRequests()
    _patched_requests(monkeypatch, fake)
    ips, status, alias = v.validate("www.example.com", check_http=True)
    assert status == 301
    assert fake.calls == [("https://www.example.com", False)]
    # The response URL is the probed URL, so no final URL is recorded.
    assert v.final_urls == {}


def test_fetch_title_follows_flag(validator_factory, monkeypatch):
    # Following redirects: the landing page's title is recorded.
    v = validator_factory({"www.example.com": ["192.0.2.10"]})
    fake = _FakeRequests()
    _patched_requests(monkeypatch, fake)
    assert v.fetch_title("www.example.com") == "Landing Page"

    # Not following: the bare 301 body has no title (the 301 is still
    # in the 200-399 range, so the title fetch stops at HTTPS).
    v = validator_factory({"www.example.com": ["192.0.2.10"]},
                          follow_redirects=False)
    fake = _FakeRequests()
    _patched_requests(monkeypatch, fake)
    assert v.fetch_title("www.example.com") == ""
    assert fake.calls == [("https://www.example.com", False)]


# ---------------------------------------------------------------------------
# CLI wiring: --no-follow-redirects reaches Validator.
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


class TestNoFollowRedirectsCli:
    def _run_main(self, monkeypatch, tmp_path, no_follow_redirects=False):
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
            no_follow_redirects=no_follow_redirects,
        )
        return captured, out_file

    def test_no_follow_redirects_reaches_validator(
            self, monkeypatch, tmp_path):
        captured, out_file = self._run_main(
            monkeypatch, tmp_path, no_follow_redirects=True)
        assert captured["follow_redirects"] is False
        data = json.loads(out_file.read_text())
        assert [r["subdomain"] for r in data["results"]] == ["www.example.com"]

    def test_redirects_followed_by_default(self, monkeypatch, tmp_path):
        captured, _out_file = self._run_main(monkeypatch, tmp_path)
        assert captured["follow_redirects"] is True
