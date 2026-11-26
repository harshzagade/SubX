"""Tests for per-phase timing in the scan summary.

``format_phase_timings()`` in ``subx/results.py`` renders the
``Phases:`` line, and ``main()`` in ``subx/cli.py`` times the three
phases -- passive enumeration, brute-force, validation -- so a slow
scan shows where the time went. Skipped phases (``--no-passive`` /
``--no-brute``) are absent from the line and from the JSON ``stats``
block's ``phase_timings`` map; a phase interrupted by Ctrl-C still
records the time spent before the interrupt.

click, rich, dnspython and requests are not installed where the suite
runs, so this module installs minimal stubs for them before importing
``subx.cli`` (same approach as test_status_breakdown.py). The
render-level tests drive the real ``main()`` with a fake
``Enumerator`` and a fake ``Validator``.
"""

import json
import logging
import re
import sys
import types

import pytest

from subx.results import format_phase_timings


# ---------------------------------------------------------------------------
# Unit tests: format_phase_timings()
# ---------------------------------------------------------------------------

def test_format_phase_timings_all_three_in_canonical_order():
    # Input order is deliberately scrambled; the line always reads
    # passive -> brute-force -> validation.
    assert format_phase_timings({
        "validation": 7.89,
        "brute-force": 4.56,
        "passive": 1.23,
    }) == "passive 1.23s, brute-force 4.56s, validation 7.89s"


def test_format_phase_timings_partial_skips_missing_phases():
    # A --no-passive scan never records "passive", so it stays out.
    assert format_phase_timings({
        "brute-force": 0.5,
        "validation": 2.0,
    }) == "brute-force 0.50s, validation 2.00s"


def test_format_phase_timings_empty_and_none():
    assert format_phase_timings({}) == ""
    assert format_phase_timings(None) == ""


def test_format_phase_timings_unknown_phase_appended():
    # A future phase is never silently dropped from the line.
    assert format_phase_timings({
        "validation": 1.0,
        "wildcard": 0.25,
    }) == "validation 1.00s, wildcard 0.25s"


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
# Render-level tests: the Phases line and the JSON stats block.
# ---------------------------------------------------------------------------

_STATUSES = {
    "api.example.com": 200,
    "dev.example.com": 301,
    "www.example.com": 200,
    "mail.example.com": 200,
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


class _FakeEnumerator:
    def __init__(self, *args, **kwargs):
        self.source_failures = {}

    def passive_enumerate(self):
        return ["api.example.com", "dev.example.com"]


def _run_main(monkeypatch, tmp_path, no_passive=False, no_brute=False,
              validator_cls=_FakeValidator):
    monkeypatch.setattr(subx.cli, "Validator", validator_cls)
    monkeypatch.setattr(subx.cli, "Enumerator", _FakeEnumerator)
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
        no_passive=no_passive,
        no_brute=no_brute,
        exclude_sub=(),
        no_http=False,
        only_live=False,
        verbose=False,
        quiet=False,
    )
    return out_file, console


def _phases_line(text):
    match = re.search(r"Phases: (.+)", text)
    assert match, "no Phases: line in the summary"
    return match.group(1)


def test_all_three_phases_timed(monkeypatch, tmp_path):
    out_file, console = _run_main(monkeypatch, tmp_path)
    text = "\n".join(console.printed)
    line = _phases_line(text)
    assert line.startswith("passive "), line
    assert "brute-force " in line
    assert "validation " in line
    # Canonical order: passive, then brute-force, then validation.
    assert line.index("passive") < line.index("brute-force") < line.index("validation")
    # Each timing is a non-negative number of seconds.
    for value in re.findall(r"(\d+\.\d+)s", line):
        assert float(value) >= 0

    data = json.loads(out_file.read_text())
    timings = data["stats"]["phase_timings"]
    assert set(timings) == {"passive", "brute-force", "validation"}
    assert all(isinstance(v, float) and v >= 0 for v in timings.values())


def test_skipped_passive_phase_absent(monkeypatch, tmp_path):
    out_file, console = _run_main(monkeypatch, tmp_path, no_passive=True)
    text = "\n".join(console.printed)
    line = _phases_line(text)
    assert "passive" not in line
    assert "brute-force " in line and "validation " in line

    data = json.loads(out_file.read_text())
    assert set(data["stats"]["phase_timings"]) == {"brute-force", "validation"}


def test_skipped_brute_phase_absent(monkeypatch, tmp_path):
    out_file, console = _run_main(monkeypatch, tmp_path, no_brute=True)
    text = "\n".join(console.printed)
    line = _phases_line(text)
    assert "brute-force" not in line
    assert "passive " in line and "validation " in line

    data = json.loads(out_file.read_text())
    assert set(data["stats"]["phase_timings"]) == {"passive", "validation"}


def test_interrupt_closes_open_phase(monkeypatch, tmp_path):
    # The validator raises KeyboardInterrupt on its second
    # validation-phase call (the first candidate validated, the
    # second interrupted), with brute-force off so the count is
    # unambiguous: the validation phase still records the time spent
    # before the interrupt, and the completed passive phase keeps
    # its timing.
    calls = {"n": 0}

    class _InterruptingValidator(_FakeValidator):
        def validate(self, sub, check_http=True):
            calls["n"] += 1
            if calls["n"] == 2:
                raise KeyboardInterrupt
            return super().validate(sub, check_http)

    with pytest.raises(SystemExit) as excinfo:
        _run_main(monkeypatch, tmp_path, no_brute=True,
                  validator_cls=_InterruptingValidator)
    assert excinfo.value.code == 130

    # The interrupt path re-ran render_results into a fresh console
    # capture; read the timings back from the JSON file it wrote.
    out_file = tmp_path / "out.json"
    data = json.loads(out_file.read_text())
    timings = data["stats"]["phase_timings"]
    assert set(timings) == {"passive", "validation"}
    assert all(isinstance(v, float) and v >= 0 for v in timings.values())
    # One row was validated before the interrupt; it is kept.
    assert len(data["results"]) == 1
