"""End-to-end test for skipping brute-force words found passively.

Drives the real ``subx.cli.main`` (quiet, single worker) with a fake
``Enumerator`` returning two passive hits and a fake ``Validator``
recording every probe. A wordlist word that is already a passive hit
must not be probed in the brute-force phase, yet must still appear in
the final results -- validated once in the validation phase, tagged
``Both`` (the wordlist contained it too).
"""

import json
import logging
import sys
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


def test_passive_word_skipped_in_brute_force_but_kept_as_both(
    monkeypatch, tmp_path
):
    calls = []

    class FakeValidator:
        def __init__(self, *args, **kwargs):
            self.wildcard_ips = set()
            self.wildcard_filtered = 0
            self.dns_cache_hits = 0

        def detect_wildcard(self, domain):
            return set()

        def validate(self, sub, check_http=True):
            calls.append(sub)
            return (["93.184.216.34"], 200, None)

    class FakeEnumerator:
        def __init__(self, domain):
            self.domain = domain
            self.log = None

        def passive_enumerate(self):
            return {"www.example.com", "api.example.com"}

    monkeypatch.setattr(subx.cli, "Validator", FakeValidator)
    monkeypatch.setattr(subx.cli, "Enumerator", FakeEnumerator)

    wordlist = tmp_path / "words.txt"
    wordlist.write_text("www\nmail\nftp\n")
    out_file = tmp_path / "out.json"

    assert subx.cli.main(
        domain="example.com",
        wordlist=str(wordlist),
        threads=1,
        timeout=5.0,
        http_timeout=3.0,
        dns_retries=1,
        output=str(out_file),
        no_passive=False,
        no_brute=False,
        exclude_sub=(),
        no_http=False,
        only_live=False,
        verbose=False,
        quiet=True,
    ) is None

    # Brute-force phase (single worker, submission order) probes only
    # the words not already known passively; www is never probed there.
    assert calls[:2] == ["mail.example.com", "ftp.example.com"]
    # Validation phase then validates every collected candidate once.
    assert len(calls) == 6
    assert sorted(calls[2:]) == [
        "api.example.com",
        "ftp.example.com",
        "mail.example.com",
        "www.example.com",
    ]

    data = json.loads(out_file.read_text())
    by_sub = {row["subdomain"]: row["source"] for row in data}
    assert by_sub == {
        "api.example.com": "Passive",
        "ftp.example.com": "Brute",
        "mail.example.com": "Brute",
        "www.example.com": "Both",
    }
