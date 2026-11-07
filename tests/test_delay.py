"""Tests for the ``--delay`` per-worker probe pause.

click, rich and dnspython are not installed where the suite runs, so
this module installs minimal stubs for them before importing
``subx.validator`` / ``subx.cli`` (same approach as the
no-wildcard-check tests). Validator-level tests patch ``_cached_dns``
and ``requests.get`` so no real DNS or HTTP traffic is involved, and
patch ``time.sleep`` so the suite stays fast; the CLI test drives the
real ``main()`` with a recording fake ``Validator`` to prove the flag
reaches the validator.
"""

import logging
import sys
import types
from unittest.mock import patch

import pytest
import requests


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

    class _NXDOMAIN(_DNSException):
        pass

    class _NoAnswer(_DNSException):
        pass

    class _Timeout(_DNSException):
        pass

    class FakeResolver:
        def __init__(self, configure=True):
            self.configure = configure
            self.nameservers = []
            self.timeout = None
            self.lifetime = None

        def resolve(self, name, rdtype):
            raise _NoAnswer(f"no {rdtype} for {name}")

    resolver_mod.Resolver = FakeResolver
    resolver_mod.NXDOMAIN = _NXDOMAIN
    resolver_mod.NoAnswer = _NoAnswer
    resolver_mod.Timeout = _Timeout
    resolver_mod.DNSException = _DNSException
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
from subx.validator import Validator  # noqa: E402


class _FakeResponse:
    def __init__(self, status_code=200):
        self.status_code = status_code


def _validating_validator(delay, monkeypatch):
    """A Validator whose DNS layer is stubbed to resolve, so only the
    delay behaviour is under test."""
    validator = Validator(delay=delay)
    monkeypatch.setattr(
        validator, "_cached_dns",
        lambda sub: (["93.184.216.34"], None))
    monkeypatch.setattr(
        requests, "get",
        lambda *args, **kwargs: _FakeResponse(200))
    return validator


def test_default_delay_is_zero():
    assert Validator().delay == 0.0


def test_negative_delay_rejected():
    with pytest.raises(ValueError):
        Validator(delay=-0.5)


def test_delay_sleeps_before_each_probe(monkeypatch):
    validator = _validating_validator(0.5, monkeypatch)
    with patch("time.sleep") as mock_sleep:
        result = validator.validate("www.example.com")
    mock_sleep.assert_called_once_with(0.5)
    assert result == (["93.184.216.34"], 200, None)


def test_no_sleep_when_delay_is_zero(monkeypatch):
    validator = _validating_validator(0.0, monkeypatch)
    with patch("time.sleep") as mock_sleep:
        validator.validate("www.example.com")
    mock_sleep.assert_not_called()


def test_delay_applies_even_on_dns_miss(monkeypatch):
    # The pause happens before the lookup, so a miss still costs the
    # delay -- the probe rate stays steady instead of bunching up on
    # the live names.
    # Raise the exact NXDOMAIN class the validator module itself
    # imported (other test files install their own dns stubs and may
    # remove them from sys.modules, so `import dns.resolver` here is
    # not reliable in a full-suite run).
    import subx.validator as validator_mod

    validator = Validator(delay=0.25)

    def _miss(sub):
        raise validator_mod.dns.resolver.NXDOMAIN(sub)

    monkeypatch.setattr(validator, "_cached_dns", _miss)
    with patch("time.sleep") as mock_sleep:
        result = validator.validate("dead.example.com")
    mock_sleep.assert_called_once_with(0.25)
    assert result is None


class _RecordingValidator:
    """Fake Validator that records its constructor kwargs; never
    touches DNS."""

    instances = []

    def __init__(self, *args, **kwargs):
        self.kwargs = kwargs
        self.wildcard_ips = set()
        self.wildcard_filtered = 0
        self.dns_cache_hits = 0
        _RecordingValidator.instances.append(self)

    def detect_wildcard(self, domain):
        return set()

    def validate(self, sub, check_http=True):
        raise AssertionError("no candidates: validate must not run")


def _run_main(monkeypatch, **overrides):
    monkeypatch.setattr(subx.cli, "Validator", _RecordingValidator)
    _RecordingValidator.instances.clear()
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
        no_wildcard_check=True,
    )
    kwargs.update(overrides)
    # --no-passive + --no-brute + --no-wildcard-check: no candidates,
    # so main returns after the wildcard step without ever reaching
    # validation or rendering.
    subx.cli.main(**kwargs)
    assert len(_RecordingValidator.instances) == 1
    return _RecordingValidator.instances[0]


def test_cli_delay_reaches_validator(monkeypatch):
    validator = _run_main(monkeypatch, delay=0.7)
    assert validator.kwargs["delay"] == 0.7


def test_cli_delay_defaults_to_zero(monkeypatch):
    validator = _run_main(monkeypatch)
    assert validator.kwargs["delay"] == 0.0


if __name__ == "__main__":
    import unittest

    unittest.main()
