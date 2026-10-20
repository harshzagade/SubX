"""Tests for ``--only-live`` result filtering.

``subx/results.py`` is stdlib-only, so these tests exercise
``filter_live_results()`` (the helper the CLI applies after
dedupe/sort) directly, without needing click.
"""

from subx.results import (
    dedupe_results,
    filter_live_results,
    is_live_status,
    sort_results,
)


def test_live_statuses_are_numeric_codes():
    assert is_live_status("200")
    assert is_live_status("301")
    assert is_live_status(404)  # non-string statuses are coerced


def test_dns_only_statuses_are_not_live():
    assert not is_live_status("No HTTP")
    assert not is_live_status("N/A")
    assert not is_live_status("")


def test_filter_keeps_only_live_rows():
    rows = [
        ("a.example.com", "200", "Brute", "198.51.100.1", ""),
        ("b.example.com", "No HTTP", "Passive", "198.51.100.2", ""),
        ("c.example.com", "N/A", "Brute", "198.51.100.3", ""),
        ("d.example.com", "301", "Both", "198.51.100.4", "cdn.example.net"),
    ]
    live = filter_live_results(rows)
    assert [r[0] for r in live] == ["a.example.com", "d.example.com"]


def test_filter_preserves_row_order_and_shape():
    rows = sort_results(
        [
            ("b.example.com", "200", "Brute", "198.51.100.2", ""),
            ("a.example.com", "200", "Passive", "198.51.100.1", ""),
        ]
    )
    live = filter_live_results(rows)
    assert [r[0] for r in live] == ["a.example.com", "b.example.com"]
    assert all(len(r) == 5 for r in live)


def test_filter_after_dedupe_merges_live_status():
    # A DNS-only passive row and a live brute-force row for the same
    # host merge into one live row -- the merge keeps the most
    # informative status, so --only-live must run after dedupe.
    rows = dedupe_results(
        [
            ("A.example.com", "No HTTP", "Passive", "198.51.100.1", ""),
            ("a.example.com", "200", "Brute", "198.51.100.1", ""),
        ]
    )
    assert len(rows) == 1
    assert filter_live_results(rows) == rows


def test_empty_input_stays_empty():
    assert filter_live_results([]) == []
