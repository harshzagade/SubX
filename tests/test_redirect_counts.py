"""Tests for the redirect hop count: when a probe follows a redirect
chain, ``response.history``'s length is recorded on the validator and
surfaces as a ``redirects`` field in the JSON output, so long chains
and redirect loops are visible to pipelines.

dnspython, click and rich are not installed where the suite runs, so
these tests stub ``dns`` (same approach as test_final_url.py).
``requests`` is patched on the reloaded ``subx.validator`` module with
a fake serving scripted responses whose ``.history`` is the redirect
chain the probe followed. The render test drives ``render_results``
with the same minimal click/rich/dns stubs as test_final_url_cli.py.
"""

import json
import logging
import sys
import time
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
        def __init__(self, configure=True):
            self.configure = configure
            self.nameservers = []
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
def validator_module():
    def make(resolve_map):
        _install_dns_stub(resolve_map)
        import importlib

        import subx.validator

        importlib.reload(subx.validator)
        return subx.validator

    yield make
    for mod_name in ("dns", "dns.resolver", "dns.exception"):
        sys.modules.pop(mod_name, None)


class _FakeRequests:
    """Stand-in for ``requests`` serving scripted responses.

    ``pages`` maps a probed URL to ``(status_code, body, hops)`` where
    ``hops`` is the number of redirects the probe followed (the length
    of ``response.history``). A ``hops`` of ``None`` means the response
    carries no ``.history`` attribute at all, like a minimal test
    double. An unlisted URL raises ``ConnectionError``.
    """

    class RequestException(Exception):
        pass

    class ConnectionError(RequestException):
        pass

    class Timeout(RequestException):
        pass

    def __init__(self, pages=None):
        self.calls = []
        self.pages = pages or {}

    def get(self, url, **kwargs):
        self.calls.append(url)
        if url not in self.pages:
            raise self.ConnectionError(f"refused: {url}")
        status_code, body, hops = self.pages[url]
        response = types.SimpleNamespace(
            status_code=status_code, content=body,
            url=url + "/landing" if hops else url)
        if hops is not None:
            response.history = [
                types.SimpleNamespace(status_code=301) for _ in range(hops)
            ]
        return response


def _patch_requests(monkeypatch, module, fake):
    monkeypatch.setattr(module, "requests", fake)


def test_validate_records_two_hop_chain(validator_module, monkeypatch):
    module = validator_module({"a.example.com": ["1.2.3.4"]})
    fake = _FakeRequests({
        "https://a.example.com": (200, b"", 2),
    })
    _patch_requests(monkeypatch, module, fake)
    validator = module.Validator()
    assert validator.validate("a.example.com") == (["1.2.3.4"], 200, None)
    assert validator.redirect_counts == {"a.example.com": 2}


def test_validate_records_zero_for_direct_response(
        validator_module, monkeypatch):
    module = validator_module({"a.example.com": ["1.2.3.4"]})
    fake = _FakeRequests({
        "https://a.example.com": (200, b"", 0),
    })
    _patch_requests(monkeypatch, module, fake)
    validator = module.Validator()
    assert validator.validate("a.example.com") == (["1.2.3.4"], 200, None)
    assert validator.redirect_counts == {"a.example.com": 0}


def test_validate_tolerates_response_without_history(
        validator_module, monkeypatch):
    module = validator_module({"a.example.com": ["1.2.3.4"]})
    fake = _FakeRequests({
        "https://a.example.com": (200, b"", None),
    })
    _patch_requests(monkeypatch, module, fake)
    validator = module.Validator()
    assert validator.validate("a.example.com") == (["1.2.3.4"], 200, None)
    assert validator.redirect_counts == {"a.example.com": 0}


def test_validate_records_no_count_when_no_http(
        validator_module, monkeypatch):
    module = validator_module({"a.example.com": ["1.2.3.4"]})
    fake = _FakeRequests({})
    _patch_requests(monkeypatch, module, fake)
    validator = module.Validator()
    assert validator.validate("a.example.com") == (
        ["1.2.3.4"], "No HTTP", None)
    assert validator.redirect_counts == {}


def test_validate_records_zero_when_redirects_not_followed(
        validator_module, monkeypatch):
    module = validator_module({"a.example.com": ["1.2.3.4"]})
    fake = _FakeRequests({
        "https://a.example.com": (301, b"", 0),
    })
    _patch_requests(monkeypatch, module, fake)
    validator = module.Validator(follow_redirects=False)
    assert validator.validate("a.example.com") == (["1.2.3.4"], 301, None)
    assert validator.redirect_counts == {"a.example.com": 0}


def test_resume_carries_redirect_counts(tmp_path):
    from subx.results import load_resumed_results

    path = tmp_path / "prev.json"
    path.write_text(json.dumps({
        "results": [
            {"subdomain": "www.example.com", "status": 200,
             "source": "Passive", "ips": "93.184.216.34", "cname": None,
             "redirects": 2},
            {"subdomain": "mail.example.com", "status": 200,
             "source": "Brute", "ips": "93.184.216.34", "cname": None,
             "redirects": 0},
            {"subdomain": "bad.example.com", "status": 200,
             "source": "Brute", "ips": "93.184.216.34", "cname": None,
             "redirects": "three"},
        ],
    }))
    rows, _, _, redirect_counts = load_resumed_results(str(path))
    assert len(rows) == 3
    assert redirect_counts == {
        "www.example.com": 2,
        "mail.example.com": 0,
    }


# ---------------------------------------------------------------------------
# Render: the ``redirects`` field in JSON output.
# ---------------------------------------------------------------------------

def _install_render_stubs():
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


_install_render_stubs()

import subx.cli  # noqa: E402  (import after stub installation)


class _FakeConsole:
    def __init__(self):
        self.printed = []

    def print(self, *args, **kwargs):
        self.printed.append(" ".join(str(a) for a in args))


class _FakeLog:
    def info(self, *args, **kwargs):
        pass

    def warning(self, *args, **kwargs):
        pass

    def error(self, *args, **kwargs):
        pass


class _FakeValidator:
    wildcard_filtered = 0
    dns_cache_hits = 0
    http_probe_retries = 0
    final_urls = {}
    redirect_counts = {}


def test_redirect_counts_in_json_output(tmp_path):
    from subx.cli import render_results

    results = [
        ("www.example.com", "200", "Passive", "93.184.216.34", ""),
        ("mail.example.com", "200", "Brute", "93.184.216.34", ""),
        ("dns.example.com", "No HTTP", "Brute", "93.184.216.34", ""),
    ]
    found = {r[0]: r[2] for r in results}
    redirect_counts = {"www.example.com": 2, "mail.example.com": 0}

    out_file = tmp_path / "out.json"
    render_results(
        _FakeConsole(), _FakeLog(), results, found, _FakeValidator(),
        str(out_file), False, False, time.time(),
        redirect_counts=redirect_counts,
    )
    data = json.loads(out_file.read_text())
    by_sub = {row["subdomain"]: row for row in data["results"]}
    assert by_sub["www.example.com"]["redirects"] == 2
    assert by_sub["mail.example.com"]["redirects"] == 0
    assert by_sub["dns.example.com"]["redirects"] is None
