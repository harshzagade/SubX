"""Tests for subdomain-takeover hints (subx/takeover.py) and their
wiring into render_results' saved files.

The hint function is pure stdlib pattern matching, so no DNS stubs
are needed. The render test drives the real render_results with a
collecting fake console -- no rich rendering happens, the table
object is just passed to console.print.
"""

import json
import sys
import time
import types

import pytest

from subx.takeover import takeover_hint


# click, rich and dnspython are not installed where the suite runs, so
# the render tests install minimal stubs before importing subx.cli
# (same approach as test_interrupt_summary.py).
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


def test_exact_suffix_matches():
    assert takeover_hint("user.github.io") == "GitHub Pages"
    assert takeover_hint("app.herokuapp.com") == "Heroku"


def test_service_suffix_itself_matches():
    assert takeover_hint("github.io") == "GitHub Pages"


def test_case_and_trailing_dot_insensitive():
    assert takeover_hint("User.GitHub.IO.") == "GitHub Pages"


def test_spoofed_suffix_does_not_match():
    # "fakegithub.io" merely ends with "github.io" -- it is not a
    # subdomain of github.io, so it must not match.
    assert takeover_hint("fakegithub.io") is None
    # Nor does a longer name that merely contains the suffix.
    assert takeover_hint("github.io.evil.com") is None


def test_empty_and_unknown_aliases():
    assert takeover_hint("") is None
    assert takeover_hint(None) is None
    assert takeover_hint("cdn.example.net") is None


def test_specific_suffix_beats_generic():
    # "s3.amazonaws.com" must report AWS S3, not the generic AWS
    # fallback that "amazonaws.com" would give.
    assert takeover_hint("bucket.s3.amazonaws.com") == "AWS S3"
    assert takeover_hint("other.amazonaws.com") == "AWS"


def test_azure_and_common_services():
    assert takeover_hint("app.azurewebsites.net") == "Azure App Service"
    assert takeover_hint("site.netlify.app") == "Netlify"
    assert takeover_hint("shop.shopify.com") == "Shopify"
    assert takeover_hint("blog.wordpress.com") == "WordPress.com"


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


def test_render_json_carries_takeover_hint(tmp_path):
    from subx.cli import render_results

    out_file = tmp_path / "out.json"
    results = [
        ("old.example.com", "No HTTP", "Passive", "192.0.2.5", "old.github.io"),
        ("www.example.com", "200", "Brute", "192.0.2.6", ""),
    ]
    render_results(
        _FakeConsole(), _FakeLog(), results, {}, _FakeValidator(),
        str(out_file), False, False, time.time(),
    )
    data = json.loads(out_file.read_text())
    assert data[0]["takeover"] == "GitHub Pages"
    assert data[1]["takeover"] is None


def test_render_txt_appends_takeover_note(tmp_path):
    from subx.cli import render_results

    out_file = tmp_path / "out.txt"
    results = [
        ("old.example.com", "No HTTP", "Passive", "192.0.2.5", "old.github.io"),
    ]
    render_results(
        _FakeConsole(), _FakeLog(), results, {}, _FakeValidator(),
        str(out_file), False, False, time.time(),
    )
    assert "[possible takeover: GitHub Pages]" in out_file.read_text()


def test_render_summary_names_takeover_count():
    from subx.cli import render_results

    console = _FakeConsole()
    results = [
        ("old.example.com", "No HTTP", "Passive", "192.0.2.5", "old.github.io"),
    ]
    render_results(
        console, _FakeLog(), results, {}, _FakeValidator(),
        None, False, False, time.time(),
    )
    assert any("1 possible subdomain takeover" in line for line in console.printed)
