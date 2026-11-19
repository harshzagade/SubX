"""Tests for ``--include-status`` result filtering.

``parse_include_statuses()`` / ``filter_included_statuses()`` live in
stdlib-only ``subx/results.py`` and are tested directly. The CLI
wiring (the flag threads through ``render_results`` in both the normal
and interrupt paths, a bad value fails fast with exit 2, and combining
it with ``--exclude-status`` fails fast with exit 2) is tested by
driving the real ``main()`` / ``render_results()`` with a fake
``Validator`` -- click, rich and dnspython are not installed where the
suite runs, so this module installs minimal stubs for them before
importing ``subx.cli`` (same approach as the exclude-cname tests).
"""

import json
import logging
import sys
import time
import types

import pytest

from subx.results import (
    dedupe_results,
    filter_included_statuses,
    parse_include_statuses,
    sort_results,
)


def test_parse_single_and_multiple_codes():
    assert parse_include_statuses("200") == frozenset({"200"})
    assert parse_include_statuses("200,301") == frozenset({"200", "301"})
    assert parse_include_statuses(" 200 , 301 ") == frozenset({"200", "301"})


def test_parse_rejects_junk():
    for bad in ("", "abc", "200,abc", "99", "1000", "200.5", "20x"):
        with pytest.raises(ValueError):
            parse_include_statuses(bad)


def test_filter_keeps_only_matching_statuses():
    rows = [
        ("a.example.com", "200", "Brute", "198.51.100.1", ""),
        ("b.example.com", "403", "Passive", "198.51.100.2", ""),
        ("c.example.com", "404", "Brute", "198.51.100.3", ""),
        ("d.example.com", "301", "Both", "198.51.100.4", ""),
    ]
    kept = filter_included_statuses(rows, frozenset({"200", "301"}))
    assert [r[0] for r in kept] == ["a.example.com", "d.example.com"]


def test_filter_drops_dns_only_rows():
    # DNS-only rows carry no numeric code, so an allowlist can never
    # keep them -- unlike --exclude-status, which never drops them.
    rows = [
        ("a.example.com", "No HTTP", "Passive", "198.51.100.1", ""),
        ("b.example.com", "N/A", "Brute", "198.51.100.2", ""),
        ("c.example.com", "200", "Brute", "198.51.100.3", ""),
    ]
    kept = filter_included_statuses(rows, frozenset({"200"}))
    assert [r[0] for r in kept] == ["c.example.com"]


def test_filter_after_dedupe_matches_merged_status():
    # A DNS-only passive row and a 200 brute-force row for the same
    # host merge into one 200 row -- the merge keeps the most
    # informative status, so --include-status must run after dedupe
    # for the merged row to be kept.
    rows = dedupe_results(
        [
            ("A.example.com", "No HTTP", "Passive", "198.51.100.1", ""),
            ("a.example.com", "200", "Brute", "198.51.100.1", ""),
        ]
    )
    assert len(rows) == 1
    kept = filter_included_statuses(rows, frozenset({"200"}))
    assert [r[0] for r in kept] == ["a.example.com"]
    assert filter_included_statuses(rows, frozenset({"404"})) == []


def test_filter_preserves_order_and_shape():
    rows = sort_results(
        [
            ("b.example.com", "200", "Brute", "198.51.100.2", ""),
            ("a.example.com", "200", "Passive", "198.51.100.1", ""),
        ]
    )
    kept = filter_included_statuses(rows, frozenset({"200"}))
    assert [r[0] for r in kept] == ["a.example.com", "b.example.com"]
    assert all(len(r) == 5 for r in kept)


def _install_stubs():
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


class _CountingValidator:
    """Fake Validator that never touches DNS."""

    instances = []

    def __init__(self, *args, **kwargs):
        self.wildcard_ips = set(kwargs.get("wildcard_ips") or ())
        self.wildcard_filtered = 0
        self.dns_cache_hits = 0
        self.wildcard_probes = 0
        _CountingValidator.instances.append(self)

    def detect_wildcard(self, domain):
        self.wildcard_probes += 1
        return set()

    def validate(self, sub, check_http=True):
        raise AssertionError("no candidates: validate must not run")


def test_render_applies_include_status_to_output_file(tmp_path):
    from subx.cli import render_results

    out_file = tmp_path / "out.json"
    results = [
        ("www.example.com", "200", "Brute", "192.0.2.6", ""),
        ("mail.example.com", "403", "Passive", "192.0.2.7", ""),
        ("dns.example.com", "No HTTP", "Passive", "192.0.2.8", ""),
    ]
    found = {
        "www.example.com": "Brute",
        "mail.example.com": "Passive",
        "dns.example.com": "Passive",
    }
    render_results(
        _FakeConsole(), _FakeLog(), results, found, _FakeValidator(),
        str(out_file), False, True, time.time(),
        include_status=frozenset({"200"}),
    )
    data = json.loads(out_file.read_text())
    assert [r["subdomain"] for r in data["results"]] == ["www.example.com"]
    # The stats block still reports what validation produced, not
    # what survived the display filter.
    assert data["stats"]["validated"] == 3


def _base_main_kwargs(**overrides):
    kwargs = dict(
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
        no_http=False,
        only_live=False,
        verbose=False,
        quiet=True,
        exclude_status=None,
        exclude_ip=None,
        no_wildcard_check=False,
        wildcard_ips=None,
        exclude_cname=(),
        include_status=None,
    )
    kwargs.update(overrides)
    return kwargs


def test_bad_include_status_value_exits_2(monkeypatch):
    monkeypatch.setattr(subx.cli, "Validator", _CountingValidator)
    with pytest.raises(SystemExit) as exc:
        subx.cli.main(**_base_main_kwargs(include_status="abc"))
    assert exc.value.code == 2


def test_include_status_with_exclude_status_exits_2(monkeypatch):
    monkeypatch.setattr(subx.cli, "Validator", _CountingValidator)
    with pytest.raises(SystemExit) as exc:
        subx.cli.main(
            **_base_main_kwargs(
                include_status="200", exclude_status="404"))
    assert exc.value.code == 2
