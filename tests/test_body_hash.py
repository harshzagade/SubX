"""Tests for the response-body hash: every probe that gets a 2xx/3xx
response records a short SHA-256 prefix of the response body
(``body_hash``) in the JSON output, so identical pages across
subdomains (default pages, parking pages) can be grouped without
re-fetching.

dnspython may not be installed where the suite runs, so these tests stub
the ``dns``/``dns.resolver``/``dns.exception`` modules, following the
pattern in test_no_follow_redirects.py. ``requests`` is patched on the
reloaded ``subx.validator`` module with a fake serving per-host bodies.
The CLI test at the bottom drives the real ``subx.cli.main`` with the
same minimal click/rich/dns stubs as test_skip_passive.py.
"""

import hashlib
import json
import logging
import sys
import types

import pytest


def _install_dns_stub(resolve_map):
    dns = types.ModuleType("dns")
    resolver_mod = types.ModuleType("dns.resolver")
    exception_mod = types.ModuleType("dns.exception")

    class NXDOMAIN(Exception):
        pass

    class NoAnswer(Exception):
        pass

    class Timeout(Exception):
        pass

    class DNSException(Exception):
        pass

    class FakeRdata:
        def __init__(self, ip):
            self._ip = ip

        def __str__(self):
            return self._ip

    class FakeResolver:
        def __init__(self):
            self.timeout = None
            self.lifetime = None

        def resolve(self, name, rdtype):
            key = str(name).rstrip(".").lower()
            if str(rdtype).upper() == "CNAME":
                raise NoAnswer(key)
            if key in resolve_map:
                return [FakeRdata(ip) for ip in resolve_map[key]]
            raise NXDOMAIN(key)

    resolver_mod.Resolver = FakeResolver
    resolver_mod.NXDOMAIN = NXDOMAIN
    resolver_mod.NoAnswer = NoAnswer
    resolver_mod.Timeout = Timeout
    exception_mod.DNSException = DNSException
    dns.resolver = resolver_mod
    dns.exception = exception_mod

    for mod_name, mod in (
        ("dns", dns),
        ("dns.resolver", resolver_mod),
        ("dns.exception", exception_mod),
    ):
        sys.modules[mod_name] = mod


@pytest.fixture()
def validator_factory():
    def make(resolve_map, **kwargs):
        _install_dns_stub(resolve_map)
        import importlib

        import subx.validator

        importlib.reload(subx.validator)
        return subx.validator.Validator(**kwargs)

    yield make
    for mod_name in ("dns", "dns.resolver", "dns.exception"):
        sys.modules.pop(mod_name, None)


def _hash(body):
    return hashlib.sha256(body).hexdigest()[:12]


class _FakeRequests:
    """Stand-in for ``requests`` serving a fixed body per host.

    ``bodies`` maps a hostname to its response body (``None`` means
    the host refuses the connection). A 200 with the mapped body is
    returned for known hosts; anything else raises the fake
    ``ConnectionError`` so the probe falls through to HTTP.
    """

    class RequestException(Exception):
        pass

    class ConnectionError(RequestException):
        pass

    class Timeout(RequestException):
        pass

    def __init__(self, bodies):
        self.bodies = bodies

    def _response(self, url):
        host = url.split("://", 1)[1].split("/", 1)[0]
        body = self.bodies.get(host)
        if body is None:
            raise self.ConnectionError(f"refused: {host}")
        return types.SimpleNamespace(
            status_code=200, url=url, content=body, history=[])

    def get(self, url, **kwargs):
        return self._response(url)

    def head(self, url, **kwargs):
        # A HEAD response carries no body, whatever the host serves.
        host = url.split("://", 1)[1].split("/", 1)[0]
        if self.bodies.get(host) is None:
            raise self.ConnectionError(f"refused: {host}")
        return types.SimpleNamespace(
            status_code=200, url=url, content=b"", history=[])


def _patched_requests(monkeypatch, fake):
    module = sys.modules["subx.validator"]
    monkeypatch.setattr(module, "requests", fake)
    return module


def test_body_hash_recorded(validator_factory, monkeypatch):
    body = b"<html><body>Default page</body></html>"
    v = validator_factory({"www.example.com": ["192.0.2.10"]})
    _patched_requests(monkeypatch, _FakeRequests(
        {"www.example.com": body}))
    ips, status, alias = v.validate("www.example.com", check_http=True)
    assert status == 200
    assert v.body_hashes == {"www.example.com": _hash(body)}


def test_identical_bodies_share_hash(validator_factory, monkeypatch):
    # Two subdomains serving the same page (e.g. a parking page)
    # group under one hash without re-fetching.
    body = b"parked domain"
    v = validator_factory({
        "a.example.com": ["192.0.2.10"],
        "b.example.com": ["192.0.2.11"],
    })
    _patched_requests(monkeypatch, _FakeRequests(
        {"a.example.com": body, "b.example.com": body}))
    v.validate("a.example.com", check_http=True)
    v.validate("b.example.com", check_http=True)
    assert v.body_hashes == {
        "a.example.com": _hash(body),
        "b.example.com": _hash(body),
    }


def test_different_bodies_differ(validator_factory, monkeypatch):
    v = validator_factory({
        "a.example.com": ["192.0.2.10"],
        "b.example.com": ["192.0.2.11"],
    })
    _patched_requests(monkeypatch, _FakeRequests(
        {"a.example.com": b"page one",
         "b.example.com": b"page two, slightly different"}))
    v.validate("a.example.com", check_http=True)
    v.validate("b.example.com", check_http=True)
    assert (v.body_hashes["a.example.com"]
            != v.body_hashes["b.example.com"])
    assert len(v.body_hashes["a.example.com"]) == 12


def test_no_hash_when_no_http(validator_factory, monkeypatch):
    # DNS resolves but no web service: no response, no body, no hash.
    v = validator_factory({"dead.example.com": ["192.0.2.10"]})
    _patched_requests(monkeypatch, _FakeRequests({}))
    ips, status, alias = v.validate("dead.example.com", check_http=True)
    assert status == "No HTTP"
    assert v.body_hashes == {}


def test_no_hash_for_head_only(validator_factory, monkeypatch):
    # A HEAD probe carries no body: hashing it would fingerprint the
    # empty string and falsely group every HEAD row together.
    v = validator_factory({"www.example.com": ["192.0.2.10"]},
                          head_only=True)
    _patched_requests(monkeypatch, _FakeRequests(
        {"www.example.com": b"<html><body>Real page</body></html>"}))
    ips, status, alias = v.validate("www.example.com", check_http=True)
    assert status == 200
    assert v.body_hashes == {}


def test_resume_carries_body_hash(tmp_path):
    from subx.results import load_resumed_results

    path = tmp_path / "prev.json"
    path.write_text(json.dumps({
        "results": [
            {"subdomain": "www.example.com", "status": 200,
             "source": "Passive", "ips": "93.184.216.34", "cname": None,
             "body_hash": "a1b2c3d4e5f6"},
            {"subdomain": "api.example.com", "status": "No HTTP",
             "source": "Brute", "ips": "192.0.2.1", "cname": None,
             "body_hash": None},
            {"subdomain": "junk.example.com", "status": 200,
             "source": "Brute", "ips": "192.0.2.2", "cname": None,
             "body_hash": 12345},
        ],
    }))
    rows, _, _, _, body_hashes = load_resumed_results(str(path))
    assert len(rows) == 3
    # Only the well-formed string hash survives; null and non-string
    # values are ignored like the other optional fields.
    assert body_hashes == {"www.example.com": "a1b2c3d4e5f6"}


# ---------------------------------------------------------------------------
# CLI wiring: body_hash reaches the JSON output, and --resume carries a
# prior hash through.
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


class TestBodyHashCli:
    def _run_main(self, monkeypatch, tmp_path, resume=None):
        class FakeValidator:
            def __init__(self, *args, **kwargs):
                self.wildcard_ips = set()
                self.wildcard_filtered = 0
                self.dns_cache_hits = 0
                self.final_urls = {}
                self.redirect_counts = {}
                self.body_hashes = {}

            def detect_wildcard(self, domain):
                return set()

            def validate(self, sub, check_http=True):
                # Like the real validator, the hash is recorded only
                # for hosts actually probed -- a resumed host is never
                # probed, so it never gains a fresh hash here.
                self.body_hashes[sub] = "deadbeefcafe"
                return (["93.184.216.34"], 200, None)

        class FakeEnumerator:
            def __init__(self, domain, source_timeout=None,
                         only_sources=None):
                self.domain = domain
                self.log = None

            def passive_enumerate(self):
                return {"www.example.com"}

        monkeypatch.setattr(subx.cli, "Validator", FakeValidator)
        monkeypatch.setattr(subx.cli, "Enumerator", FakeEnumerator)

        out_file = tmp_path / "out.json"
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
            output=str(out_file),
            no_passive=False,
            no_brute=True,
            exclude_sub=(),
            no_http=False,
            only_live=False,
            verbose=False,
            quiet=True,
            only_source=(),
            no_follow_redirects=False,
            resume=resume,
        )
        return json.loads(out_file.read_text())

    def test_body_hash_in_json_output(self, monkeypatch, tmp_path):
        data = self._run_main(monkeypatch, tmp_path)
        assert data["results"] == [{
            "subdomain": "www.example.com",
            "status": "200",
            "source": "Passive",
            "ips": "93.184.216.34",
            "cname": None,
            "takeover": None,
            "title": None,
            "final_url": None,
            "redirects": None,
            "body_hash": "deadbeefcafe",
        }]

    def test_resume_carries_prior_body_hash(self, monkeypatch, tmp_path):
        # The resumed host was validated in an earlier scan; its
        # prior hash rides through untouched (no fresh probe ran).
        prev = tmp_path / "prev.json"
        prev.write_text(json.dumps({
            "results": [{
                "subdomain": "www.example.com",
                "status": 200,
                "source": "Passive",
                "ips": "93.184.216.34",
                "cname": None,
                "body_hash": "0123456789ab",
            }],
        }))
        data = self._run_main(monkeypatch, tmp_path, resume=str(prev))
        assert len(data["results"]) == 1
        assert data["results"][0]["body_hash"] == "0123456789ab"
