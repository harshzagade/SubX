"""Tests for the ``--resume FILE`` flag: continue a scan from a
previous ``-o`` JSON output instead of re-validating every host.

Unit tests cover ``load_resumed_results`` (normalization, dedupe,
title extraction, fail-fast on garbage); end-to-end tests drive the
real ``subx.cli.main`` (quiet, single worker) with a fake
``Enumerator``/``Validator`` and check that resumed hosts are never
re-probed yet still appear in the output.
"""

import json
import logging
import sys
import types

import pytest

from subx.results import load_resumed_results


# --- load_resumed_results ---


def _write_resume(tmp_path, data):
    path = tmp_path / "prev.json"
    if isinstance(data, str):
        path.write_text(data)
    else:
        path.write_text(json.dumps(data))
    return str(path)


def test_load_resumed_results_valid(tmp_path):
    path = _write_resume(tmp_path, {
        "results": [
            {"subdomain": "WWW.Example.COM.", "status": 200,
             "source": "Passive", "ips": "93.184.216.34",
             "cname": None, "takeover": None, "title": "WWW Home",
             "final_url": "https://www.example.com/home"},
            {"subdomain": "api.example.com", "status": "No HTTP",
             "source": "Brute", "ips": ["192.0.2.1", "192.0.2.2"],
             "cname": "api.cdn.example.net", "title": None},
        ],
        "stats": {"duration_seconds": 1.0},
    })
    rows, titles, final_urls, redirect_counts = load_resumed_results(path)
    assert rows == [
        ("www.example.com", "200", "Passive", "93.184.216.34", ""),
        ("api.example.com", "No HTTP", "Brute", "192.0.2.1, 192.0.2.2",
         "api.cdn.example.net"),
    ]
    assert titles == {"www.example.com": "WWW Home"}
    assert final_urls == {"www.example.com": "https://www.example.com/home"}
    assert redirect_counts == {}


def test_load_resumed_results_dedupes_spelling_variants(tmp_path):
    path = _write_resume(tmp_path, {
        "results": [
            {"subdomain": "www.example.com", "status": "200",
             "source": "Passive", "ips": "93.184.216.34", "cname": None},
            {"subdomain": "WWW.EXAMPLE.COM", "status": "404",
             "source": "Brute", "ips": "93.184.216.34", "cname": None},
        ],
    })
    rows, _, _, _ = load_resumed_results(path)
    assert rows == [
        ("www.example.com", "200", "Passive", "93.184.216.34", ""),
    ]


def test_load_resumed_results_missing_file_raises_oserror(tmp_path):
    with pytest.raises(OSError):
        load_resumed_results(str(tmp_path / "nope.json"))


def test_load_resumed_results_bad_json_raises_valueerror(tmp_path):
    path = _write_resume(tmp_path, "{not json")
    with pytest.raises(ValueError):
        load_resumed_results(path)


def test_load_resumed_results_wrong_shape_raises_valueerror(tmp_path):
    for bad in ([], {"results": "nope"}, {"stats": {}}, {"results": [42]},
                {"results": [{"status": "200", "source": "Passive",
                              "ips": "1.2.3.4"}]},
                {"results": [{"subdomain": "a.example.com",
                              "source": "Passive", "ips": "1.2.3.4"}]},
                {"results": [{"subdomain": "a.example.com", "status": "200",
                              "ips": "1.2.3.4"}]},
                {"results": [{"subdomain": "a.example.com", "status": "200",
                              "source": "Passive"}]}):
        path = _write_resume(tmp_path, bad)
        with pytest.raises(ValueError):
            load_resumed_results(path)


# --- end-to-end: resume skips re-validation, keeps prior rows ---


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


def _run_main(monkeypatch, tmp_path, resume_path):
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
        def __init__(self, domain, source_timeout=None, only_sources=None):
            self.domain = domain
            self.log = None

        def passive_enumerate(self):
            return {"www.example.com", "api.example.com"}

    monkeypatch.setattr(subx.cli, "Validator", FakeValidator)
    monkeypatch.setattr(subx.cli, "Enumerator", FakeEnumerator)

    wordlist = tmp_path / "words.txt"
    wordlist.write_text("www\nmail\nftp\n")
    out_file = tmp_path / "out.json"

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
        no_passive=False,
        no_brute=False,
        exclude_sub=(),
        no_http=False,
        only_live=False,
        verbose=False,
        quiet=True,
        resume=resume_path,
    )
    return calls, out_file


def test_resume_skips_revalidation_but_keeps_prior_row(
    monkeypatch, tmp_path
):
    resume_path = _write_resume(tmp_path, {
        "results": [
            {"subdomain": "www.example.com", "status": "200",
             "source": "Passive", "ips": "93.184.216.34",
             "cname": None, "takeover": None, "title": "WWW Home",
             "final_url": "https://www.example.com/home"},
            # Not a candidate in this scan: ignored, not resurrected.
            {"subdomain": "stale.example.com", "status": "200",
             "source": "Brute", "ips": "192.0.2.99",
             "cname": None, "takeover": None, "title": None},
        ],
        "stats": {"validated": 2},
    })
    calls, out_file = _run_main(monkeypatch, tmp_path, resume_path)

    # Brute-force phase probes only the words not already recorded;
    # www is never probed there, and the validation phase never
    # re-validates it either.
    assert calls[:2] == ["mail.example.com", "ftp.example.com"]
    assert len(calls) == 5
    assert sorted(calls[2:]) == [
        "api.example.com",
        "ftp.example.com",
        "mail.example.com",
    ]
    assert "www.example.com" not in calls

    data = json.loads(out_file.read_text())
    by_sub = {row["subdomain"]: row for row in data["results"]}
    assert sorted(by_sub) == [
        "api.example.com",
        "ftp.example.com",
        "mail.example.com",
        "www.example.com",
    ]
    # The resumed row keeps its prior status, source, IPs and title.
    www = by_sub["www.example.com"]
    assert www["status"] == "200"
    assert www["source"] == "Passive"
    assert www["ips"] == "93.184.216.34"
    assert www["title"] == "WWW Home"
    assert www["final_url"] == "https://www.example.com/home"
    assert data["stats"]["resumed"] == 1
    assert data["stats"]["validated"] == 4
    assert data["stats"]["candidates_collected"] == 4


def test_resume_bad_file_fails_fast(monkeypatch, tmp_path):
    resume_path = _write_resume(tmp_path, "{not json")
    with pytest.raises(SystemExit) as exc:
        _run_main(monkeypatch, tmp_path, resume_path)
    assert exc.value.code == 2


def test_resume_missing_file_fails_fast(monkeypatch, tmp_path):
    with pytest.raises(SystemExit) as exc:
        _run_main(monkeypatch, tmp_path, str(tmp_path / "nope.json"))
    assert exc.value.code == 2
