"""Tests for the JSON output ``stats`` block.

Drives the real ``render_results`` with a collecting fake console,
using the same minimal click/rich/dns stubs as test_takeover.py
(click and dnspython are not installed where the suite runs).
"""

import json
import sys
import time
import types


def _install_stubs():
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

    if "dns" not in sys.modules:
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
            ("dns", dns),
            ("dns.resolver", resolver_mod),
            ("dns.exception", exception_mod),
        ):
            sys.modules[mod_name] = mod


_install_stubs()


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
    wildcard_filtered = 3
    dns_cache_hits = 5
    http_probe_retries = 0


def test_json_stats_block(tmp_path):
    from subx.cli import render_results

    out_file = tmp_path / "out.json"
    results = [
        ("www.example.com", "200", "Brute", "192.0.2.6", ""),
        ("mail.example.com", "No HTTP", "Passive", "192.0.2.7", ""),
    ]
    # Two candidates collected, both validated; the stats block must
    # report the scan counters, not just the row list.
    found = {"www.example.com": "Brute", "mail.example.com": "Passive"}
    render_results(
        _FakeConsole(), _FakeLog(), results, found, _FakeValidator(),
        str(out_file), False, False, time.time(),
    )
    data = json.loads(out_file.read_text())
    assert [r["subdomain"] for r in data["results"]] == [
        "mail.example.com",
        "www.example.com",
    ]
    stats = data["stats"]
    assert stats["candidates_collected"] == 2
    assert stats["validated"] == 2
    assert stats["wildcard_filtered"] == 3
    assert stats["dns_cache_hits"] == 5
    assert isinstance(stats["duration_seconds"], float)


def test_json_stats_validated_counts_pre_filter_rows(tmp_path):
    from subx.cli import render_results

    out_file = tmp_path / "out.json"
    results = [
        ("www.example.com", "200", "Brute", "192.0.2.6", ""),
        ("mail.example.com", "No HTTP", "Passive", "192.0.2.7", ""),
    ]
    found = {"www.example.com": "Brute", "mail.example.com": "Passive"}
    # --only-live hides the DNS-only row from results, but validated
    # still counts everything validation produced.
    render_results(
        _FakeConsole(), _FakeLog(), results, found, _FakeValidator(),
        str(out_file), True, False, time.time(),
    )
    data = json.loads(out_file.read_text())
    assert [r["subdomain"] for r in data["results"]] == ["www.example.com"]
    assert data["stats"]["validated"] == 2
    assert data["stats"]["candidates_collected"] == 2
