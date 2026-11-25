"""Tests for the ``--max-results N`` row cap.

``cap_results()`` in ``subx/results.py`` keeps the first N rows of an
already deduped/sorted list and reports how many were hidden, and
``render_results()`` applies it last -- after the other display
filters -- so the rendered table, quiet output, and saved files all
show the same first N rows. The JSON ``stats`` block carries
``max_results`` and ``hidden_by_max_results``, while ``validated``
still counts everything validation produced (before the cap).

click, rich, dnspython and requests are not installed where the suite
runs, so this module installs minimal stubs for them before importing
``subx.cli`` (same approach as test_status_breakdown.py). The
render-level tests drive the real ``main()`` with a fake ``Validator``.
"""

import json
import logging
import sys
import time
import types

from subx.results import cap_results


# ---------------------------------------------------------------------------
# Unit tests: cap_results()
# ---------------------------------------------------------------------------

def _row(sub):
    return (sub, "200", "Brute", "93.184.216.34", None)


def test_cap_none_keeps_everything():
    rows = [_row("a.example.com"), _row("b.example.com")]
    kept, hidden = cap_results(rows, None)
    assert kept == rows
    assert hidden == 0


def test_cap_larger_than_rows_keeps_everything():
    rows = [_row("a.example.com"), _row("b.example.com")]
    kept, hidden = cap_results(rows, 10)
    assert kept == rows
    assert hidden == 0


def test_cap_equal_to_rows_hides_nothing():
    rows = [_row("a.example.com"), _row("b.example.com")]
    kept, hidden = cap_results(rows, 2)
    assert kept == rows
    assert hidden == 0


def test_cap_keeps_first_n_in_order():
    rows = [_row("a.example.com"), _row("b.example.com"),
            _row("c.example.com"), _row("d.example.com")]
    kept, hidden = cap_results(rows, 2)
    assert kept == rows[:2]
    assert hidden == 2


def test_cap_one_keeps_only_first_row():
    rows = [_row("a.example.com"), _row("b.example.com")]
    kept, hidden = cap_results(rows, 1)
    assert kept == rows[:1]
    assert hidden == 1


def test_cap_empty_input():
    assert cap_results([], 5) == ([], 0)


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
from subx.cli import render_results  # noqa: E402


# ---------------------------------------------------------------------------
# Render-level tests: render_results() with a collecting fake log
# ---------------------------------------------------------------------------

class _FakeConsole:
    def __init__(self):
        self.printed = []

    def print(self, *args, **kwargs):
        self.printed.append(" ".join(str(a) for a in args))


class _CollectingLog:
    def __init__(self):
        self.infos = []

    def info(self, *args, **kwargs):
        self.infos.append(" ".join(str(a) for a in args))

    def warning(self, *args, **kwargs):
        pass

    def error(self, *args, **kwargs):
        pass


class _FakeValidator:
    wildcard_filtered = 0
    dns_cache_hits = 0
    http_probe_retries = 0


def _three_rows():
    return [
        ("a.example.com", "200", "Brute", "192.0.2.1", ""),
        ("b.example.com", "200", "Brute", "192.0.2.2", ""),
        ("c.example.com", "200", "Brute", "192.0.2.3", ""),
    ]


def test_render_cap_keeps_first_n_and_records_hidden(tmp_path):
    out_file = tmp_path / "out.json"
    console = _FakeConsole()
    log = _CollectingLog()
    found = {r[0]: "Brute" for r in _three_rows()}
    render_results(console, log, _three_rows(), found, _FakeValidator(),
                   str(out_file), False, False, time.time(),
                   max_results=2)
    data = json.loads(out_file.read_text())
    assert [r["subdomain"] for r in data["results"]] == [
        "a.example.com", "b.example.com"]
    assert data["stats"]["validated"] == 3
    assert data["stats"]["max_results"] == 2
    assert data["stats"]["hidden_by_max_results"] == 1
    assert any("--max-results: hid 1 row(s); showing 2." in m
               for m in log.infos)


def test_render_no_cap_shows_everything(tmp_path):
    out_file = tmp_path / "out.json"
    console = _FakeConsole()
    log = _CollectingLog()
    found = {r[0]: "Brute" for r in _three_rows()}
    render_results(console, log, _three_rows(), found, _FakeValidator(),
                   str(out_file), False, False, time.time())
    data = json.loads(out_file.read_text())
    assert len(data["results"]) == 3
    assert data["stats"]["max_results"] is None
    assert data["stats"]["hidden_by_max_results"] == 0
    assert not any("--max-results" in m for m in log.infos)


def test_render_cap_larger_than_rows_hides_nothing(tmp_path):
    out_file = tmp_path / "out.json"
    console = _FakeConsole()
    log = _CollectingLog()
    found = {r[0]: "Brute" for r in _three_rows()}
    render_results(console, log, _three_rows(), found, _FakeValidator(),
                   str(out_file), False, False, time.time(),
                   max_results=10)
    data = json.loads(out_file.read_text())
    assert len(data["results"]) == 3
    assert data["stats"]["hidden_by_max_results"] == 0
    assert not any("--max-results" in m for m in log.infos)


# ---------------------------------------------------------------------------
# End-to-end tests: the --max-results flag threads through main()
# ---------------------------------------------------------------------------

class _MainFakeValidator:
    def __init__(self, *args, **kwargs):
        self.wildcard_ips = set()
        self.wildcard_filtered = 0
        self.dns_cache_hits = 0

    def detect_wildcard(self, domain):
        return set()

    def validate(self, sub, check_http=True):
        return (["93.184.216.34"], "200", None)


def _run_main(monkeypatch, tmp_path, max_results=None):
    monkeypatch.setattr(subx.cli, "Validator", _MainFakeValidator)
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
        only_live=False,
        verbose=False,
        quiet=True,
        max_results=max_results,
    )
    return out_file


def test_main_max_results_caps_json_output(monkeypatch, tmp_path):
    out_file = _run_main(monkeypatch, tmp_path, max_results=2)
    data = json.loads(out_file.read_text())
    # Rows are sorted by subdomain, so the cap keeps ftp + mail.
    assert [r["subdomain"] for r in data["results"]] == [
        "ftp.example.com", "mail.example.com"]
    assert data["stats"]["validated"] == 3
    assert data["stats"]["max_results"] == 2
    assert data["stats"]["hidden_by_max_results"] == 1


def test_main_without_max_results_shows_all(monkeypatch, tmp_path):
    out_file = _run_main(monkeypatch, tmp_path)
    data = json.loads(out_file.read_text())
    assert len(data["results"]) == 3
    assert data["stats"]["hidden_by_max_results"] == 0
