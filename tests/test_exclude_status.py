"""Tests for ``--exclude-status`` result filtering.

``subx/results.py`` is stdlib-only, so these tests exercise
``parse_exclude_statuses()`` and ``filter_excluded_statuses()`` (the
helpers the CLI applies after dedupe/sort) directly, without needing
click.
"""

import pytest

from subx.results import (
    dedupe_results,
    filter_excluded_statuses,
    parse_exclude_statuses,
    sort_results,
)


def test_parse_single_and_multiple_codes():
    assert parse_exclude_statuses("403") == frozenset({"403"})
    assert parse_exclude_statuses("403,404") == frozenset({"403", "404"})
    assert parse_exclude_statuses(" 403 , 404 ") == frozenset({"403", "404"})


def test_parse_rejects_junk():
    for bad in ("", "abc", "403,abc", "99", "1000", "403.5", "20x"):
        with pytest.raises(ValueError):
            parse_exclude_statuses(bad)


def test_filter_drops_matching_statuses_only():
    rows = [
        ("a.example.com", "200", "Brute", "198.51.100.1", ""),
        ("b.example.com", "403", "Passive", "198.51.100.2", ""),
        ("c.example.com", "404", "Brute", "198.51.100.3", ""),
        ("d.example.com", "301", "Both", "198.51.100.4", ""),
    ]
    kept = filter_excluded_statuses(rows, frozenset({"403", "404"}))
    assert [r[0] for r in kept] == ["a.example.com", "d.example.com"]


def test_filter_never_drops_dns_only_rows():
    rows = [
        ("a.example.com", "No HTTP", "Passive", "198.51.100.1", ""),
        ("b.example.com", "N/A", "Brute", "198.51.100.2", ""),
        ("c.example.com", "403", "Brute", "198.51.100.3", ""),
    ]
    kept = filter_excluded_statuses(rows, frozenset({"403", "404"}))
    assert [r[0] for r in kept] == ["a.example.com", "b.example.com"]


def test_filter_after_dedupe_matches_merged_status():
    # A DNS-only passive row and a 403 brute-force row for the same
    # host merge into one 403 row -- the merge keeps the most
    # informative status, so --exclude-status must run after dedupe
    # for the merged row to be dropped.
    rows = dedupe_results(
        [
            ("A.example.com", "No HTTP", "Passive", "198.51.100.1", ""),
            ("a.example.com", "403", "Brute", "198.51.100.1", ""),
        ]
    )
    assert len(rows) == 1
    kept = filter_excluded_statuses(rows, frozenset({"403"}))
    assert kept == []


def test_filter_preserves_order_and_shape():
    rows = sort_results(
        [
            ("b.example.com", "200", "Brute", "198.51.100.2", ""),
            ("a.example.com", "200", "Passive", "198.51.100.1", ""),
        ]
    )
    kept = filter_excluded_statuses(rows, frozenset({"404"}))
    assert [r[0] for r in kept] == ["a.example.com", "b.example.com"]
    assert all(len(r) == 5 for r in kept)
