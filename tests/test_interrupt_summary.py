"""Tests for the graceful KeyboardInterrupt summary in ``subx.cli``.

click, rich, dnspython and requests are not installed where the suite
runs, so this module installs minimal stubs for them before importing
``subx.cli`` (same approach as the validator tests' dns stubs). It then
drives the real ``main()`` with a fake ``Validator`` that raises
``KeyboardInterrupt`` mid-scan and asserts the partial results are
rendered, the output file is still written, and the process exits 130.
"""

import json
import logging
import sys
import types

import pytest


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

    # NOTE: requests and urllib3 are intentionally NOT stubbed here -- both
    # are installed in this environment, and other test modules (e.g.
    # test_enumerator.py) patch the real requests module. Overwriting
    # sys.modules["requests"] at collection time would silently unpatch
    # their mocks.

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
# Fake Validator: validates every word until `fail_on_call`-th call, then
# raises KeyboardInterrupt from inside the worker thread (surfaced by
# future.result(), exactly like a real Ctrl-C during the scan).
# ---------------------------------------------------------------------------

def _make_fake_validator(fail_on_call=None):
    class FakeValidator:
        def __init__(self, *args, **kwargs):
            self.wildcard_ips = set()
            self.wildcard_filtered = 0
            self.dns_cache_hits = 0
            self.calls = 0

        def detect_wildcard(self, domain):
            return set()

        def validate(self, sub, check_http=True):
            self.calls += 1
            if fail_on_call is not None and self.calls >= fail_on_call:
                raise KeyboardInterrupt()
            return (["93.184.216.34"], 200, None)

    return FakeValidator


def _run_main(monkeypatch, tmp_path, words, fail_on_call):
    monkeypatch.setattr(subx.cli, "Validator", _make_fake_validator(fail_on_call))
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("\n".join(words) + "\n")
    out_file = tmp_path / "out.json"
    console = subx.cli.console
    console.printed.clear()
    return out_file, console


def _main_kwargs(wordlist, out_file):
    # main(domain, wordlist, threads, timeout, http_timeout, dns_retries,
    #      http_retries, source_timeout, resolver, output, no_passive,
    #      no_brute, exclude_sub, no_http, only_live, verbose, quiet)
    return dict(
        domain="example.com",
        wordlist=str(wordlist),
        threads=1,  # single worker: futures complete in submission order
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
    )


def test_interrupt_mid_scan_renders_partial_results_and_exits_130(
    monkeypatch, tmp_path
):
    out_file, console = _run_main(
        monkeypatch, tmp_path, ["www", "mail", "ftp"], fail_on_call=2
    )
    with pytest.raises(SystemExit) as exc:
        subx.cli.main(**_main_kwargs(tmp_path / "words.txt", out_file))
    assert exc.value.code == 130

    text = "\n".join(console.printed)
    assert "interrupted" in text.lower()
    assert "partial results" in text.lower()
    assert "1 of 1 candidate(s) validated" in text
    assert "www.example.com" in text  # the validated row is still shown

    # The output file is still written with the partial results.
    data = json.loads(out_file.read_text())
    assert len(data) == 1
    assert data[0]["subdomain"] == "www.example.com"


def test_interrupt_during_validation_reports_collected_candidates(
    monkeypatch, tmp_path
):
    # fail_on_call=4: the 3 brute-force words validate cleanly (calls 1-3),
    # then the first validation-phase re-check raises KeyboardInterrupt.
    out_file, console = _run_main(
        monkeypatch, tmp_path, ["www", "mail", "ftp"], fail_on_call=4
    )
    with pytest.raises(SystemExit) as exc:
        subx.cli.main(**_main_kwargs(tmp_path / "words.txt", out_file))
    assert exc.value.code == 130

    text = "\n".join(console.printed)
    assert "interrupted" in text.lower()
    assert "3 candidate(s) collected" in text
    assert "none validated yet" in text.lower()
    assert not out_file.exists()  # nothing validated, nothing to save


def test_normal_path_has_no_interrupt_banner(monkeypatch, tmp_path):
    out_file, console = _run_main(
        monkeypatch, tmp_path, ["www", "mail"], fail_on_call=None
    )
    # No SystemExit on the clean path.
    assert subx.cli.main(**_main_kwargs(tmp_path / "words.txt", out_file)) is None

    text = "\n".join(console.printed)
    assert "interrupt" not in text.lower()

    data = json.loads(out_file.read_text())
    assert sorted(r["subdomain"] for r in data) == [
        "mail.example.com",
        "www.example.com",
    ]
