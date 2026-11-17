"""Tests for the ``--wildcard-ips`` flag in ``subx.cli``.

``parse_wildcard_ips()`` lives in stdlib-only ``subx/results.py`` and is
tested directly. The CLI wiring (supplied IPs skip the two detection
probes, land on the validator, and conflict with ``--no-wildcard-check``)
is tested by driving the real ``main()`` with a fake ``Validator`` --
click, rich and dnspython are not installed where the suite runs, so
this module installs minimal stubs for them before importing
``subx.cli`` (same approach as the no-wildcard-check tests).
"""

import logging
import sys
import types

import pytest

from subx.results import parse_wildcard_ips


def test_parse_valid_v4_and_v6():
    ips = parse_wildcard_ips("203.0.113.7, 198.51.100.42")
    assert ips == frozenset({"203.0.113.7", "198.51.100.42"})


def test_parse_normalizes_ipv6():
    # ipaddress canonical form, so the two spellings of one address
    # compare equal against the resolver's normalized answers.
    ips = parse_wildcard_ips("2001:0db8::1")
    assert ips == frozenset({"2001:db8::1"})


def test_parse_rejects_junk():
    for bad in ("", "abc", "203.0.113.999", "203.0.113.0/24",
                "203.0.113.7,abc", "example.com"):
        with pytest.raises(ValueError):
            parse_wildcard_ips(bad)


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


def _run_main(monkeypatch, wildcard_ips=None, no_wildcard_check=False):
    monkeypatch.setattr(subx.cli, "Validator", _CountingValidator)
    _CountingValidator.instances.clear()
    # --no-passive + --no-brute: no candidates, so main returns after
    # the wildcard step without ever reaching validation or rendering.
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
        no_wildcard_check=no_wildcard_check,
        wildcard_ips=wildcard_ips,
    )
    assert len(_CountingValidator.instances) == 1
    return _CountingValidator.instances[0]


def test_supplied_ips_skip_detection_probes(monkeypatch):
    validator = _run_main(monkeypatch, wildcard_ips="203.0.113.7,198.51.100.42")
    assert validator.wildcard_probes == 0
    assert validator.wildcard_ips == {"203.0.113.7", "198.51.100.42"}


def test_default_path_still_probes(monkeypatch):
    validator = _run_main(monkeypatch)
    assert validator.wildcard_probes == 1


def test_conflict_with_no_wildcard_check_exits_2(monkeypatch):
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
            no_wildcard_check=True,
            wildcard_ips="203.0.113.7",
        )
    assert exc.value.code == 2


def test_junk_wildcard_ips_exit_2(monkeypatch):
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
            wildcard_ips="not-an-ip",
        )
    assert exc.value.code == 2
