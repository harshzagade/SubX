"""Tests for the ``--exclude-cname`` result filter.

``excluded_cname()`` / ``parse_exclude_patterns()`` live in stdlib-only
``subx/filters.py`` and ``filter_excluded_cname_results()`` in stdlib-only
``subx/results.py``; both are tested directly. The CLI fail-fast (a bad
glob exits 2 before any network work) is tested by driving the real
``main()`` with a fake ``Validator`` -- click, rich and dnspython are not
installed where the suite runs, so this module installs minimal stubs
for them before importing ``subx.cli`` (same approach as the
wildcard-ips tests).
"""

import logging
import sys
import types

import pytest

from subx.filters import excluded_cname, parse_exclude_patterns
from subx.results import filter_excluded_cname_results


def test_parse_rejects_empty_with_cname_label():
    with pytest.raises(ValueError, match="exclude-cname"):
        parse_exclude_patterns([""], name="exclude-cname")
    with pytest.raises(ValueError, match="exclude-cname"):
        parse_exclude_patterns(["   "], name="exclude-cname")


def test_excluded_cname_glob_match():
    compiled = parse_exclude_patterns(["*.cloudfront.net"])
    assert excluded_cname("d111111abcdef8.cloudfront.net", compiled) is True
    assert excluded_cname("example.herokuapp.com", compiled) is False


def test_excluded_cname_case_insensitive_and_full_match():
    compiled = parse_exclude_patterns(["*.CLOUDFRONT.NET"])
    assert excluded_cname("d111.cloudfront.net", compiled) is True
    # A bare suffix is not a full-name match: the glob must cover the
    # whole alias, so "*.cloudfront.net" never hides "cloudfront.net".
    assert excluded_cname("cloudfront.net", compiled) is False


def test_excluded_cname_never_drops_alias_less_rows():
    compiled = parse_exclude_patterns(["*"])
    assert excluded_cname(None, compiled) is False
    assert excluded_cname("", compiled) is False
    assert excluded_cname("anything.example.com", []) is False


def test_filter_drops_matching_alias_rows_only():
    rows = [
        ("a.example.com", "200", "Brute", "203.0.113.5",
         "d111.cloudfront.net"),
        ("b.example.com", "200", "Brute", "198.51.100.2",
         "example.herokuapp.com"),
        # No alias at all: never dropped, whatever the patterns say.
        ("c.example.com", "200", "Brute", "192.0.2.9", ""),
        ("d.example.com", "200", "Brute", "192.0.2.10", None),
    ]
    kept = filter_excluded_cname_results(
        rows, parse_exclude_patterns(["*.cloudfront.net"]))
    assert [r[0] for r in kept] == [
        "b.example.com", "c.example.com", "d.example.com"]


def test_filter_multiple_patterns():
    rows = [
        ("a.example.com", "200", "Brute", "203.0.113.5",
         "d111.cloudfront.net"),
        ("b.example.com", "200", "Brute", "198.51.100.2",
         "example.herokuapp.com"),
        ("c.example.com", "200", "Brute", "192.0.2.9",
         "other.example.com"),
    ]
    kept = filter_excluded_cname_results(
        rows, parse_exclude_patterns(
            ["*.cloudfront.net", "*.herokuapp.com"]))
    assert [r[0] for r in kept] == ["c.example.com"]


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


class _CountingValidator:
    """Fake Validator that records wildcard probes; never touches DNS."""

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


def test_bad_exclude_cname_pattern_exits_2(monkeypatch):
    monkeypatch.setattr(subx.cli, "Validator", _CountingValidator)
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
            no_http=False,
            only_live=False,
            verbose=False,
            quiet=True,
            exclude_status=None,
            exclude_ip=None,
            no_wildcard_check=False,
            wildcard_ips=None,
            exclude_cname=("",),
        )
    assert exc.value.code == 2
