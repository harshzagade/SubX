"""Tests for the urlscan.io passive source in ``subx.enumerator``.

The source queries urlscan.io's public search API (no API key) and
collects each result's ``page.domain``. Tests drive the source method
directly with a faked ``requests.get`` plus one end-to-end check
through ``passive_enumerate()``.
"""

import logging
import unittest
from unittest.mock import patch

import requests

from subx.enumerator import Enumerator


def _quiet_enumerator(**kwargs):
    enumerator = Enumerator("example.com", **kwargs)
    # Silence logging; the tests assert on return values and counters.
    enumerator.log = logging.getLogger("subx.test")
    enumerator.log.addHandler(logging.NullHandler())
    return enumerator


class _FakeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}

    def json(self):
        return self._payload


_URLSCAN_PAYLOAD = {
    "results": [
        {"page": {"domain": "a.example.com",
                  "url": "https://a.example.com/"}},
        {"page": {"domain": "B.example.com",
                  "url": "https://b.example.com/"}},
        {"page": {"domain": "other.com",
                  "url": "https://other.com/"}},
        {"page": {"domain": "example.com",
                  "url": "https://example.com/"}},
    ],
    "total": 4,
}


class TestUrlscan(unittest.TestCase):
    def test_collects_page_domains(self):
        enumerator = _quiet_enumerator()
        with patch("requests.get",
                   return_value=_FakeResponse(200, _URLSCAN_PAYLOAD)) as mock_get:
            result = enumerator._urlscan()

        self.assertEqual(result,
                         {"a.example.com", "b.example.com", "example.com"})
        # Only the urlscan.io search endpoint was queried, with the
        # target domain in the query and the configured timeout.
        url = mock_get.call_args[0][0]
        self.assertIn("urlscan.io/api/v1/search/", url)
        self.assertIn("domain%3Aexample.com", url)
        self.assertEqual(mock_get.call_args[1]["timeout"], 15.0)

    def test_non_200_returns_empty(self):
        enumerator = _quiet_enumerator()
        with patch("requests.get", return_value=_FakeResponse(429, {})):
            self.assertEqual(enumerator._urlscan(), set())

    def test_empty_results_returns_empty(self):
        enumerator = _quiet_enumerator()
        with patch("requests.get",
                   return_value=_FakeResponse(200, {"results": []})):
            self.assertEqual(enumerator._urlscan(), set())

    def test_missing_keys_returns_empty(self):
        # A payload without "results", or results without a page
        # domain, is a source quirk -- not a crash.
        enumerator = _quiet_enumerator()
        with patch("requests.get", return_value=_FakeResponse(200, {})):
            self.assertEqual(enumerator._urlscan(), set())
        with patch("requests.get", return_value=_FakeResponse(
                200, {"results": [{"page": {}}, {}]})):
            self.assertEqual(enumerator._urlscan(), set())

    def test_transient_http_errors_propagate(self):
        # The retry loop in passive_enumerate can only work if the
        # source method re-raises transient HTTP failures instead of
        # swallowing them into an empty result.
        enumerator = _quiet_enumerator()
        with patch("requests.get",
                   side_effect=requests.ConnectionError("boom")):
            with self.assertRaises(requests.ConnectionError):
                enumerator._urlscan()

    def test_passive_enumerate_includes_urlscan(self):
        enumerator = _quiet_enumerator()
        with patch.object(enumerator, "_crtsh", return_value=set()), \
                patch.object(enumerator, "_hackertarget",
                             return_value=set()), \
                patch.object(enumerator, "_alienvault",
                             return_value=set()), \
                patch.object(enumerator, "_urlscan",
                             return_value={"scan.example.com"}):
            result = enumerator.passive_enumerate()

        self.assertEqual(result, {"scan.example.com"})
        self.assertEqual(enumerator.source_failures, {})

    def test_persistent_urlscan_failure_recorded(self):
        enumerator = _quiet_enumerator()
        with patch.object(enumerator, "_crtsh", return_value=set()), \
                patch.object(enumerator, "_hackertarget",
                             return_value=set()), \
                patch.object(enumerator, "_alienvault",
                             return_value=set()), \
                patch.object(enumerator, "_urlscan",
                             side_effect=requests.Timeout("slow")):
            result = enumerator.passive_enumerate()

        self.assertEqual(result, set())
        self.assertIn("urlscan.io", enumerator.source_failures)


if __name__ == "__main__":
    unittest.main()
