"""Tests for the ``--only-source`` per-source enable flag.

``Enumerator(only_sources=[...])`` restricts the passive phase to the
named sources, for debugging or when one source is rate-limiting.
Names are normalized (canonical key, display name, or the ``crt`` /
``otx`` shorthands, case-insensitively) and unknown names fail fast
with ``ValueError``. The CLI test at the bottom drives the real
``subx.cli.main`` with the same minimal click/rich/dns stubs as
test_skip_passive.py (click and dnspython are not installed where the
suite runs).
"""

import json
import logging
import sys
import types
from unittest.mock import MagicMock, patch

import pytest
import requests

from subx.enumerator import Enumerator


def _quiet_enumerator(**kwargs):
    enumerator = Enumerator("example.com", **kwargs)
    # Silence logging; the tests assert on return values and counters.
    enumerator.log = logging.getLogger("subx.test")
    enumerator.log.addHandler(logging.NullHandler())
    return enumerator


_SOURCE_SETS = {
    "_crtsh": {"a.example.com"},
    "_hackertarget": {"b.example.com"},
    "_alienvault": {"c.example.com"},
    "_urlscan": {"d.example.com"},
}


def _patch_all_sources():
    """Patch all four source methods to return distinct fixed sets.

    Returns the ``patch.multiple`` context manager; its ``__enter__``
    value maps method names to the MagicMock replacements, so tests
    can assert which sources were (not) called.
    """
    return patch.multiple(
        Enumerator,
        **{name: MagicMock(return_value=set(s))
           for name, s in _SOURCE_SETS.items()},
    )


class TestNormalizeSourceName:
    def test_canonical_keys(self):
        for key in ("crtsh", "hackertarget", "alienvault", "urlscan"):
            assert Enumerator.normalize_source_name(key) == key

    def test_display_names(self):
        assert Enumerator.normalize_source_name("crt.sh") == "crtsh"
        assert Enumerator.normalize_source_name("HackerTarget") == "hackertarget"
        assert Enumerator.normalize_source_name("AlienVault") == "alienvault"
        assert Enumerator.normalize_source_name("urlscan.io") == "urlscan"

    def test_aliases_and_case(self):
        assert Enumerator.normalize_source_name("CRT") == "crtsh"
        assert Enumerator.normalize_source_name("OTX") == "alienvault"
        assert Enumerator.normalize_source_name("URLSCAN") == "urlscan"

    def test_unknown_name_raises_naming_valid_sources(self):
        with pytest.raises(ValueError) as excinfo:
            Enumerator.normalize_source_name("certspotter")
        assert "certspotter" in str(excinfo.value)
        for key in ("crtsh", "hackertarget", "alienvault", "urlscan"):
            assert key in str(excinfo.value)


class TestOnlySource:
    def test_default_runs_all_sources(self):
        enumerator = _quiet_enumerator()
        with _patch_all_sources():
            result = enumerator.passive_enumerate()
        assert result == {"a.example.com", "b.example.com",
                          "c.example.com", "d.example.com"}
        assert enumerator.source_failures == {}

    def test_only_one_source_runs_just_it(self):
        enumerator = _quiet_enumerator(only_sources=["crtsh"])
        with _patch_all_sources() as mocked:
            result = enumerator.passive_enumerate()
        assert result == {"a.example.com"}
        # The other three source methods were never called.
        for name, mock in mocked.items():
            if name == "_crtsh":
                mock.assert_called_once()
            else:
                mock.assert_not_called()

    def test_only_source_accepts_display_names(self):
        enumerator = _quiet_enumerator(
            only_sources=["crt.sh", "urlscan.io"])
        with _patch_all_sources():
            result = enumerator.passive_enumerate()
        assert result == {"a.example.com", "d.example.com"}

    def test_only_source_case_insensitive(self):
        enumerator = _quiet_enumerator(only_sources=["CRTSH", "Otx"])
        with _patch_all_sources():
            result = enumerator.passive_enumerate()
        assert result == {"a.example.com", "c.example.com"}

    def test_unknown_source_fails_fast_at_construction(self):
        with pytest.raises(ValueError):
            _quiet_enumerator(only_sources=["certspotter"])

    def test_source_failures_only_for_enabled_sources(self):
        # crt.sh fails transiently; urlscan.io succeeds. With the
        # filter on, the failing source is never queried, so it is
        # neither retried nor recorded as a failure.
        enumerator = _quiet_enumerator(only_sources=["urlscan"])
        with patch.object(Enumerator, "_crtsh",
                          side_effect=requests.ConnectionError("boom")), \
             patch.object(Enumerator, "_urlscan",
                          return_value={"d.example.com"}):
            result = enumerator.passive_enumerate()
        assert result == {"d.example.com"}
        assert enumerator.source_failures == {}

        # Without the filter the same failure is recorded.
        enumerator = _quiet_enumerator()
        with patch.object(Enumerator, "_crtsh",
                          side_effect=requests.ConnectionError("boom")), \
             patch.object(Enumerator, "_hackertarget", return_value=set()), \
             patch.object(Enumerator, "_alienvault", return_value=set()), \
             patch.object(Enumerator, "_urlscan",
                          return_value={"d.example.com"}):
            result = enumerator.passive_enumerate()
        assert result == {"d.example.com"}
        assert "crt.sh" in enumerator.source_failures


# ---------------------------------------------------------------------------
# CLI wiring: --only-source reaches Enumerator, bad names exit 2.
# ---------------------------------------------------------------------------

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


class TestOnlySourceCli:
    def _run_main(self, monkeypatch, tmp_path, only_source=(), **overrides):
        captured = {}

        class FakeValidator:
            def __init__(self, *args, **kwargs):
                self.wildcard_ips = set()
                self.wildcard_filtered = 0
                self.dns_cache_hits = 0

            def detect_wildcard(self, domain):
                return set()

            def validate(self, sub, check_http=True):
                return (["93.184.216.34"], 200, None)

        class FakeEnumerator:
            # main() validates --only-source names and renders display
            # names through these class attributes; delegate to the
            # real Enumerator so the CLI path exercises the real
            # normalization instead of a second fake copy.
            normalize_source_name = Enumerator.normalize_source_name
            SOURCES = Enumerator.SOURCES

            def __init__(self, domain, source_timeout=None,
                         only_sources=None):
                captured["only_sources"] = only_sources
                self.domain = domain
                self.log = None

            def passive_enumerate(self):
                return {"www.example.com"}

        monkeypatch.setattr(subx.cli, "Validator", FakeValidator)
        monkeypatch.setattr(subx.cli, "Enumerator", FakeEnumerator)

        out_file = tmp_path / "out.json"
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
            output=str(out_file),
            no_passive=False,
            no_brute=True,
            exclude_sub=(),
            no_http=False,
            only_live=False,
            verbose=False,
            quiet=True,
            only_source=only_source,
        )
        kwargs.update(overrides)
        subx.cli.main(**kwargs)
        return captured, out_file

    def test_only_source_reaches_enumerator(self, monkeypatch, tmp_path):
        captured, out_file = self._run_main(
            monkeypatch, tmp_path, only_source=("crtsh", "urlscan"))
        assert captured["only_sources"] == ["crtsh", "urlscan"]
        data = json.loads(out_file.read_text())
        assert [r["subdomain"] for r in data["results"]] == ["www.example.com"]

    def test_only_source_defaults_to_none(self, monkeypatch, tmp_path):
        captured, _out_file = self._run_main(monkeypatch, tmp_path)
        assert captured["only_sources"] is None

    def test_invalid_only_source_exits_2(self, monkeypatch, tmp_path):
        with pytest.raises(SystemExit) as excinfo:
            self._run_main(monkeypatch, tmp_path,
                           only_source=("certspotter",))
        assert excinfo.value.code == 2
