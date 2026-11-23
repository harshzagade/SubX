"""Tests for the per-status breakdown in the scan summary.

``count_statuses()`` in ``subx/results.py`` counts result rows per
HTTP status (numeric codes first, ascending, then the DNS-only
labels), and ``render_results()`` prints it as a ``Statuses:`` line
alongside the existing ``Sources:`` line and carries it in the JSON
``stats`` block as ``status_breakdown``.

click, rich, dnspython and requests are not installed where the suite
runs, so this module installs minimal stubs for them before importing
``subx.cli`` (same approach as test_interrupt_summary.py). The
render-level tests drive the real ``main()`` with a fake ``Validator``
that returns a different status per subdomain.
"""

import json
import logging
import sys
import types

import pytest

from subx.results import count_statuses


# ---------------------------------------------------------------------------
# Unit tests: count_statuses()
# ---------------------------------------------------------------------------

def _row(sub, status):
    return (sub, status, "Brute", "93.184.216.34", None)


def test_count_statuses_mixed_codes_and_dns_only():
    rows = [
        _row("a.example.com", "200"),
        _row("b.example.com", "301"),
        _row("c.example.com", "200"),
        _row("d.example.com", "404"),
        _row("e.example.com", "No HTTP"),
        _row("f.example.com", "N/A"),
        _row("g.example.com", "301"),
    ]
    # Numeric codes first, ascending; DNS-only labels after,
    # alphabetically -- "N/A" before "No HTTP".
    assert list(count_statuses(rows).items()) == [
        ("200", 2),
        ("301", 2),
        ("404", 1),
        ("N/A", 1),
        ("No HTTP", 1),
    ]


def test_count_statuses_empty():
    assert count_statuses([]) == {}


def test_count_statuses_single_status():
    assert count_statuses([_row("a.example.com", "200")]) == {"200": 1}


def test_count_statuses_numeric_order_not_lexical():
    # 404 < 500 numerically; lexical order would put "500" first.
    rows = [_row("a.example.com", "500"), _row("b.example.com", "404")]
    assert list(count_statuses(rows)) == ["404", "500"]


# ---------------------------------------------------------------------------
# Stubs (installed into sys.modules before importing subx.cli)
# ---------------------------------------------------------------------------

def _install_stubs():
    # --- click ---
    click = types.ModuleType("click")

    class Command:
        pass

    def _identity_decorator(*dargs, **dkwargs):
        def wrap(fn):
            return fn

        return wrap

    class _DummyType:
        def __init__(self, *args, **kwargs):
            pass

    click.Command = Command
    click.command = _identity_decorator
    click.version_option = _identity_decorator
    click.argument = _identity_decorator
    click.option = _identity_decorator
    click.Path = _DummyType
    click.FloatRange = _DummyType
    click.IntRange = _DummyType

    # --- rich ---
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

    # --- dns (import-time only; the fake Validator never touches it) ---
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


# ---------------------------------------------------------------------------
# Render-level tests: the Statuses line and the JSON stats block.
# ---------------------------------------------------------------------------

# One status per subdomain, so the summary makeup is exact.
_STATUSES = {
    "www.example.com": 200,
    "mail.example.com": 301,
    "ftp.example.com": "No HTTP",
}


class _FakeValidator:
    def __init__(self, *args, **kwargs):
        self.wildcard_ips = set()
        self.wildcard_filtered = 0
        self.dns_cache_hits = 0

    def detect_wildcard(self, domain):
        return set()

    def validate(self, sub, check_http=True):
        return (["93.184.216.34"], _STATUSES[sub], None)


def _run_main(monkeypatch, tmp_path, only_live=False):
    monkeypatch.setattr(subx.cli, "Validator", _FakeValidator)
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("www\nmail\nftp\n")
    out_file = tmp_path / "out.json"
    console = subx.cli.console
    console.printed.clear()
    subx.cli.main(
        domain="example.com",
        wordlist=str(wordlist),
        threads=1,
        timeout=5.0,
        http_timeout=3.0,
        dns_retries=1,
        http_retries=1,
        source_timeout=15.0,
        resolver=None,
        output=str(out_file),
        no_passive=True,
        no_brute=False,
        exclude_sub=(),
        no_http=False,
        only_live=only_live,
        verbose=False,
        quiet=False,
    )
    return out_file, console


def test_statuses_line_printed_and_json_stats_match(monkeypatch, tmp_path):
    out_file, console = _run_main(monkeypatch, tmp_path)
    text = "\n".join(console.printed)
    assert "Statuses: 200: 1, 301: 1, No HTTP: 1" in text
    # The Sources line is still there alongside it.
    assert "Sources: Brute: 3" in text

    data = json.loads(out_file.read_text())
    assert data["stats"]["status_breakdown"] == {
        "200": 1, "301": 1, "No HTTP": 1,
    }


def test_status_breakdown_follows_display_filters(monkeypatch, tmp_path):
    # --only-live hides the DNS-only row, so the breakdown must drop
    # it too -- the summary describes the rendered table, not the
    # pre-filter validation set.
    out_file, console = _run_main(monkeypatch, tmp_path, only_live=True)
    text = "\n".join(console.printed)
    assert "Statuses: 200: 1, 301: 1" in text
    assert "No HTTP" not in text.split("Statuses:")[1].split("\n")[0]

    data = json.loads(out_file.read_text())
    assert data["stats"]["status_breakdown"] == {"200": 1, "301": 1}
    assert len(data["results"]) == 2
