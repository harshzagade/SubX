"""End-to-end and render tests for the final-URL-after-redirects
recording: the landing URL surfaces in the JSON output, the txt
output, and the CSV output, and rows without a redirect carry null /
blank instead.

Drives the real ``subx.cli.main`` and ``render_results`` with the
same minimal click/rich/dns stubs as test_skip_passive.py (click and
dnspython are not installed where the suite runs).
"""

import csv
import json
import logging
import sys
import time
import types

import pytest


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


def test_final_url_in_json_output(monkeypatch, tmp_path):
    class FakeValidator:
        def __init__(self, *args, **kwargs):
            self.wildcard_ips = set()
            self.wildcard_filtered = 0
            self.dns_cache_hits = 0
            self.final_urls = {}

        def detect_wildcard(self, domain):
            return set()

        def validate(self, sub, check_http=True):
            if sub == "www.example.com":
                self.final_urls[sub] = "https://www.example.com/landing"
                return (["93.184.216.34"], 301, None)
            return (["93.184.216.34"], 200, None)

    class FakeEnumerator:
        def __init__(self, domain, source_timeout=None, only_sources=None):
            self.domain = domain
            self.log = None

        def passive_enumerate(self):
            return {"www.example.com"}

    monkeypatch.setattr(subx.cli, "Validator", FakeValidator)
    monkeypatch.setattr(subx.cli, "Enumerator", FakeEnumerator)

    wordlist = tmp_path / "words.txt"
    wordlist.write_text("mail\n")
    out_file = tmp_path / "out.json"

    assert subx.cli.main(
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
        no_passive=False,
        no_brute=False,
        exclude_sub=(),
        no_http=False,
        only_live=False,
        verbose=False,
        quiet=True,
    ) is None

    data = json.loads(out_file.read_text())
    by_sub = {row["subdomain"]: row for row in data["results"]}
    assert by_sub["www.example.com"]["final_url"] == (
        "https://www.example.com/landing")
    assert by_sub["mail.example.com"]["final_url"] is None


def test_final_url_in_txt_and_csv_output(tmp_path):
    from subx.cli import render_results

    results = [
        ("www.example.com", "301", "Passive", "93.184.216.34", ""),
        ("mail.example.com", "200", "Brute", "93.184.216.34", ""),
    ]
    found = {"www.example.com": "Passive", "mail.example.com": "Brute"}
    final_urls = {"www.example.com": "https://www.example.com/landing"}

    txt_file = tmp_path / "out.txt"
    render_results(
        _FakeConsole(), _FakeLog(), results, found, _FakeValidator(),
        str(txt_file), False, False, time.time(),
        final_urls=final_urls,
    )
    lines = txt_file.read_text().splitlines()
    # Rows are sorted by subdomain, so mail comes first.
    assert lines[0] == "mail.example.com (200) - 93.184.216.34"
    assert lines[1] == (
        "www.example.com (301) - 93.184.216.34"
        " => https://www.example.com/landing")

    csv_file = tmp_path / "out.csv"
    render_results(
        _FakeConsole(), _FakeLog(), results, found, _FakeValidator(),
        str(csv_file), False, False, time.time(),
        final_urls=final_urls,
    )
    with open(csv_file, newline="") as f:
        rows = list(csv.reader(f))
    assert rows[0][-1] == "Final URL"
    assert rows[1][-1] == ""
    assert rows[2][-1] == "https://www.example.com/landing"
