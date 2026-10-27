"""Tests for retrying passive sources once on transient HTTP failure.

A source that fails with a connection error or timeout used to be
silently dropped on the first failure; ``passive_enumerate()`` now
retries it once, and a source that still fails is recorded in
``Enumerator.source_failures`` so the CLI summary can name it.
"""

import unittest
from unittest.mock import patch

import requests

from subx.enumerator import Enumerator


def _quiet_enumerator(**kwargs):
    enumerator = Enumerator("example.com", **kwargs)
    # Silence logging; the tests assert on return values and counters.
    import logging

    enumerator.log = logging.getLogger("subx.test")
    enumerator.log.addHandler(logging.NullHandler())
    return enumerator


class TestPassiveRetry(unittest.TestCase):
    def test_transient_failure_retried_once_then_succeeds(self):
        enumerator = _quiet_enumerator()
        calls = {"n": 0}

        def flaky_crtsh():
            calls["n"] += 1
            if calls["n"] == 1:
                raise requests.ConnectionError("boom")
            return {"a.example.com"}

        with patch.object(enumerator, "_crtsh", side_effect=flaky_crtsh), \
                patch.object(enumerator, "_hackertarget", return_value=set()), \
                patch.object(enumerator, "_alienvault", return_value=set()):
            result = enumerator.passive_enumerate()

        self.assertEqual(calls["n"], 2)
        self.assertIn("a.example.com", result)
        self.assertEqual(enumerator.source_failures, {})

    def test_persistent_transient_failure_recorded_after_retry(self):
        enumerator = _quiet_enumerator()
        with patch.object(
            enumerator, "_crtsh",
            side_effect=requests.Timeout("slow")) as mock_crtsh, \
                patch.object(enumerator, "_hackertarget",
                             return_value={"b.example.com"}), \
                patch.object(enumerator, "_alienvault", return_value=set()):
            result = enumerator.passive_enumerate()

        self.assertIn("b.example.com", result)
        self.assertIn("crt.sh", enumerator.source_failures)
        # Initial attempt + exactly one retry, not an unbounded loop.
        self.assertEqual(mock_crtsh.call_count, 2)

    def test_non_transient_error_not_retried(self):
        enumerator = _quiet_enumerator()
        with patch.object(enumerator, "_crtsh",
                          side_effect=ValueError("bad payload")) as mock_crtsh, \
                patch.object(enumerator, "_hackertarget", return_value=set()), \
                patch.object(enumerator, "_alienvault", return_value=set()):
            enumerator.passive_enumerate()

        self.assertEqual(mock_crtsh.call_count, 1)
        self.assertIn("crt.sh", enumerator.source_failures)

    def test_zero_retries_means_single_attempt(self):
        enumerator = _quiet_enumerator(source_retries=0)
        with patch.object(
            enumerator, "_crtsh",
            side_effect=requests.ConnectionError("boom")) as mock_crtsh, \
                patch.object(enumerator, "_hackertarget", return_value=set()), \
                patch.object(enumerator, "_alienvault", return_value=set()):
            enumerator.passive_enumerate()

        self.assertEqual(mock_crtsh.call_count, 1)
        self.assertIn("crt.sh", enumerator.source_failures)

    def test_transient_http_errors_propagate_from_sources(self):
        # The retry loop in passive_enumerate can only work if the
        # individual source methods re-raise transient HTTP failures
        # instead of swallowing them into an empty result.
        enumerator = _quiet_enumerator()
        with patch("requests.get", side_effect=requests.ConnectionError("boom")):
            with self.assertRaises(requests.ConnectionError):
                enumerator._crtsh()
            with self.assertRaises(requests.ConnectionError):
                enumerator._hackertarget()
            with self.assertRaises(requests.ConnectionError):
                enumerator._alienvault()

    def test_default_retries_is_one(self):
        self.assertEqual(Enumerator("example.com").source_retries, 1)

    def test_negative_retries_rejected(self):
        with self.assertRaises(ValueError):
            Enumerator("example.com", source_retries=-1)


if __name__ == "__main__":
    unittest.main()
