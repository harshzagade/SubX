"""Tests for the ``--head-only`` flag: HTTP probes use HEAD instead of
GET (lighter, no body downloaded) when only the status code matters.

dnspython may not be installed where the suite runs, so these tests stub
the ``dns``/``dns.resolver``/``dns.exception`` modules, following the
pattern in test_no_follow_redirects.py. ``requests`` is patched on the
reloaded ``subx.validator`` module with a fake whose ``head`` returns a
200 with an empty body (a HEAD response carries no body) and whose
``get`` returns a 200 with a titled page, so tests can prove which
method the probe actually used. The CLI test at the bottom drives the
real ``subx.cli.main`` with the same minimal click/rich/dns stubs as
test_skip_passive.py.
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
    """Stand-in for ``requests`` with method-aware responses.

    ``head`` answers 200 with an empty body (a HEAD response carries
    no body) and a redirect history; ``get`` answers 200 with a titled
    page. Every call records its method and URL so tests can prove
    which method the probe actually used.
    """

    class RequestException(Exception):
        pass

    class ConnectionError(RequestException):
        pass

    class Timeout(RequestException):
        pass

    def __init__(self):
        self.calls = []

    def head(self, url, **kwargs):
        self.calls.append(("HEAD", url, kwargs.get("allow_redirects")))
        return types.SimpleNamespace(
            status_code=200,
            url=url,
            content=b"",
            history=[],
        )

    def get(self, url, **kwargs):
        self.calls.append(("GET", url, kwargs.get("allow_redirects")))
        return types.SimpleNamespace(
            status_code=200,
            url=url,
            content=b"<html><head><title>Live Page</title></head></html>",
            history=[],
        )


def _patched_requests(monkeypatch, fake):
    module = sys.modules["subx.validator"]
    monkeypatch.setattr(module, "requests", fake)
    return module


def test_get_used_by_default(validator_factory, monkeypatch):
    v = validator_factory({"www.example.com": ["192.0.2.10"]})
    assert v.head_only is False
    fake = _FakeRequests()
    _patched_requests(monkeypatch, fake)
    ips, status, alias = v.validate("www.example.com", check_http=True)
    assert status == 200
    assert fake.calls == [("GET", "https://www.example.com", True)]
    # The final URL is unchanged, so nothing is recorded; the hop
    # count is recorded for every probe that gets a response.
    assert v.final_urls == {}
    assert v.redirect_counts == {"www.example.com": 0}


def test_head_only_uses_head(validator_factory, monkeypatch):
    v = validator_factory({"www.example.com": ["192.0.2.10"]},
                          head_only=True)
    assert v.head_only is True
    fake = _FakeRequests()
    _patched_requests(monkeypatch, fake)
    ips, status, alias = v.validate("www.example.com", check_http=True)
    assert status == 200
    assert fake.calls == [("HEAD", "https://www.example.com", True)]
    assert v.redirect_counts == {"www.example.com": 0}


def test_fetch_title_empty_with_head_only(validator_factory, monkeypatch):
    # A HEAD response has no body, so there is no <title> to read --
    # the title fetch stops at HTTPS with an empty body and returns "".
    v = validator_factory({"www.example.com": ["192.0.2.10"]},
                          head_only=True)
    fake = _FakeRequests()
    _patched_requests(monkeypatch, fake)
    assert v.fetch_title("www.example.com") == ""
    assert fake.calls == [("HEAD", "https://www.example.com", True)]

    # Same host with GET: the titled page is returned as before.
    v = validator_factory({"www.example.com": ["192.0.2.10"]})
    fake = _FakeRequests()
    _patched_requests(monkeypatch, fake)
    assert v.fetch_title("www.example.com") == "Live Page"
    assert fake.calls == [("GET", "https://www.example.com", True)]


def test_head_only_combines_with_no_follow_redirects(
        validator_factory, monkeypatch):
    # HEAD + no-follow: the method and the redirect policy are
    # independent -- both reach the request.
    v = validator_factory({"www.example.com": ["192.0.2.10"]},
                          head_only=True, follow_redirects=False)
    fake = _FakeRequests()
    _patched_requests(monkeypatch, fake)
    ips, status, alias = v.validate("www.example.com", check_http=True)
    assert status == 200
    assert fake.calls == [("HEAD", "https://www.example.com", False)]


# ---------------------------------------------------------------------------
# CLI wiring: --head-only reaches Validator, and --head-only + --titles
# fails fast.
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


class TestHeadOnlyCli:
    def _run_main(self, monkeypatch, tmp_path, head_only=False,
                  fetch_titles=False):
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
            no_follow_redirects=False,
            fetch_titles=fetch_titles,
            head_only=head_only,
        )
        return captured, out_file

    def test_head_only_reaches_validator(self, monkeypatch, tmp_path):
        captured, out_file = self._run_main(
            monkeypatch, tmp_path, head_only=True)
        assert captured["head_only"] is True
        data = json.loads(out_file.read_text())
        assert [r["subdomain"] for r in data["results"]] == ["www.example.com"]

    def test_get_used_by_default(self, monkeypatch, tmp_path):
        captured, _out_file = self._run_main(monkeypatch, tmp_path)
        assert captured["head_only"] is False

    def test_head_only_with_titles_fails_fast(self, monkeypatch, tmp_path):
        with pytest.raises(SystemExit) as excinfo:
            self._run_main(monkeypatch, tmp_path, head_only=True,
                           fetch_titles=True)
        assert excinfo.value.code == 2
