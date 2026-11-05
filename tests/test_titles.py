"""Tests for the ``--titles`` flag: record each live host's HTML
``<title>`` in a new results column.

dnspython, click and rich are not installed where the suite runs, so
these tests stub ``dns`` (same approach as test_http_retry.py) and
``click``/``rich`` (same approach as test_json_stats.py). ``requests``
is patched on the reloaded ``subx.validator`` module with a fake
serving scripted page bodies.
"""

import json
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
    """Stand-in for ``requests`` serving scripted page bodies.

    ``pages`` maps a full URL to ``(status_code, body_bytes)``; an
    unlisted URL raises ``ConnectionError`` so the HTTPS-then-HTTP
    fallback is exercised.
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
        status_code, body = self.pages[url]
        return types.SimpleNamespace(status_code=status_code, content=body)


def _patch_requests(monkeypatch, module, fake):
    monkeypatch.setattr(module, "requests", fake)


# --- extract_title ---


def test_extract_title_basic(validator_module):
    module = validator_module({})
    assert module.extract_title("<html><head><title>Example Site</title></head></html>") == "Example Site"


def test_extract_title_missing_is_blank(validator_module):
    module = validator_module({})
    assert module.extract_title("<html><head></head><body>no title</body></html>") == ""


def test_extract_title_unescapes_entities_and_collapses_whitespace(validator_module):
    module = validator_module({})
    title = module.extract_title("<title>  Fish &amp; Chips\n\tOfficial  </title>")
    assert title == "Fish & Chips Official"


def test_extract_title_is_case_insensitive_and_tolerates_attributes(validator_module):
    module = validator_module({})
    title = module.extract_title('<TITLE data-x="1">Mixed Case</TITLE>')
    assert title == "Mixed Case"


def test_extract_title_truncates_to_title_max_length(validator_module):
    module = validator_module({})
    long_title = "x" * 200
    title = module.extract_title(f"<title>{long_title}</title>")
    assert title == "x" * module.TITLE_MAX_LENGTH


# --- fetch_title ---


def test_fetch_title_prefers_https(validator_module, monkeypatch):
    module = validator_module({"a.example.com": ["1.2.3.4"]})
    fake = _FakeRequests({
        "https://a.example.com": (200, b"<title>Secure Title</title>"),
        "http://a.example.com": (200, b"<title>Plain Title</title>"),
    })
    _patch_requests(monkeypatch, module, fake)
    validator = module.Validator()
    assert validator.fetch_title("a.example.com") == "Secure Title"
    assert fake.calls == ["https://a.example.com"]


def test_fetch_title_falls_back_to_http(validator_module, monkeypatch):
    module = validator_module({"a.example.com": ["1.2.3.4"]})
    fake = _FakeRequests({
        "http://a.example.com": (200, b"<html><head><title>HTTP Only</title></head></html>"),
    })
    _patch_requests(monkeypatch, module, fake)
    validator = module.Validator()
    assert validator.fetch_title("a.example.com") == "HTTP Only"
    # HTTPS is retried once on the transient failure (the probe's
    # default http_retries=1) before the HTTP fallback is tried.
    assert fake.calls == ["https://a.example.com", "https://a.example.com",
                          "http://a.example.com"]


def test_fetch_title_blank_when_no_title_or_no_http(validator_module, monkeypatch):
    module = validator_module({"a.example.com": ["1.2.3.4"]})
    fake = _FakeRequests({
        # 200 but no <title> element at all.
        "https://a.example.com": (200, b"<html><body>untitled</body></html>"),
        # The second host answers nothing on either protocol.
    })
    _patch_requests(monkeypatch, module, fake)
    validator = module.Validator()
    assert validator.fetch_title("a.example.com") == ""
    assert validator.fetch_title("b.example.com") == ""


def test_fetch_title_ignores_error_status(validator_module, monkeypatch):
    module = validator_module({"a.example.com": ["1.2.3.4"]})
    fake = _FakeRequests({
        "https://a.example.com": (404, b"<title>Not Found Page</title>"),
        "http://a.example.com": (500, b"<title>Server Error</title>"),
    })
    _patch_requests(monkeypatch, module, fake)
    validator = module.Validator()
    assert validator.fetch_title("a.example.com") == ""


# --- render_results with titles ---


def _install_cli_stubs():
    if "click" not in sys.modules:
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
        sys.modules["click"] = click

    if "rich" not in sys.modules:
        rich = types.ModuleType("rich")

        class Console:
            def __init__(self, *args, **kwargs):
                self.printed = []

            def print(self, *args, **kwargs):
                self.printed.append(" ".join(str(a) for a in args))

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

        class _Column:
            def __init__(self, *args, **kwargs):
                pass

        rich_progress = types.ModuleType("rich.progress")
        rich_progress.Progress = _Column
        for name in ("SpinnerColumn", "TextColumn", "BarColumn",
                     "TimeElapsedColumn", "MofNCompleteColumn"):
            setattr(rich_progress, name, _Column)

        import logging

        class RichHandler(logging.Handler):
            def emit(self, record):
                pass

        rich_logging = types.ModuleType("rich.logging")
        rich_logging.RichHandler = RichHandler

        rich_panel = types.ModuleType("rich.panel")
        rich_panel.Panel = _Column

        for mod_name, mod in (
            ("rich", rich),
            ("rich.console", rich_console),
            ("rich.table", rich_table),
            ("rich.progress", rich_progress),
            ("rich.logging", rich_logging),
            ("rich.panel", rich_panel),
        ):
            sys.modules[mod_name] = mod


_install_cli_stubs()


class _FakeConsole:
    def __init__(self):
        self.printed = []

    def print(self, *args, **kwargs):
        self.printed.append(" ".join(str(a) for a in args))


class _FakeTable:
    """Table double that records columns and rows like the rich stub."""

    def __init__(self, *args, **kwargs):
        self.columns = []
        self.rows = []

    def add_column(self, *args, **kwargs):
        self.columns.append(args[0] if args else "")

    def add_row(self, *args):
        self.rows.append(args)


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


def _results_with_titles(tmp_path, fmt, titles):
    from subx.cli import render_results

    out_file = tmp_path / f"out.{fmt}"
    results = [
        ("www.example.com", "200", "Brute", "192.0.2.6", ""),
        ("mail.example.com", "No HTTP", "Passive", "192.0.2.7", ""),
    ]
    found = {"www.example.com": "Brute", "mail.example.com": "Passive"}
    render_results(
        _FakeConsole(), _FakeLog(), results, found, _FakeValidator(),
        str(out_file), False, False, time.time(), titles=titles,
    )
    return out_file


def test_json_output_carries_titles(tmp_path):
    out_file = _results_with_titles(
        tmp_path, "json", {"www.example.com": "Example Site"})
    data = json.loads(out_file.read_text())
    by_sub = {r["subdomain"]: r for r in data["results"]}
    assert by_sub["www.example.com"]["title"] == "Example Site"
    # A DNS-only row has no title: null, not a stale value.
    assert by_sub["mail.example.com"]["title"] is None


def test_csv_output_carries_title_column(tmp_path):
    out_file = _results_with_titles(
        tmp_path, "csv", {"www.example.com": "Example Site"})
    lines = out_file.read_text().splitlines()
    assert lines[0] == "Subdomain,Status,Source,IP Addresses,CNAME,Takeover,Title"
    www_line = next(line for line in lines if line.startswith("www.example.com,"))
    assert "Example Site" in www_line


def test_txt_output_appends_title(tmp_path):
    out_file = _results_with_titles(
        tmp_path, "txt", {"www.example.com": "Example Site"})
    lines = out_file.read_text().splitlines()
    www_line = next(line for line in lines if line.startswith("www.example.com"))
    assert www_line.endswith(" | Example Site")
    mail_line = next(line for line in lines if line.startswith("mail.example.com"))
    assert " | " not in mail_line


def test_titles_guard_rejects_no_http(monkeypatch):
    import subx.cli

    with pytest.raises(SystemExit) as exc:
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
            output=None,
            no_passive=True,
            no_brute=True,
            exclude_sub=(),
            no_http=True,
            only_live=False,
            verbose=False,
            quiet=True,
            exclude_status=None,
            exclude_ip=None,
            no_wildcard_check=False,
            fetch_titles=True,
        )
    assert exc.value.code == 2
