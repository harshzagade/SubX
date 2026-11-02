"""Tests for ``--exclude-ip`` result filtering.

``subx/results.py`` is stdlib-only, so these tests exercise
``parse_exclude_ip_networks()`` and ``filter_excluded_ip_results()``
(the helpers the CLI applies after dedupe/sort) directly, without
needing click.
"""

import pytest

from subx.results import (
    filter_excluded_ip_results,
    parse_exclude_ip_networks,
)


def test_parse_cidr_and_bare_ip():
    networks = parse_exclude_ip_networks("203.0.113.0/24, 198.51.100.7")
    assert [str(n) for n in networks] == ["203.0.113.0/24", "198.51.100.7/32"]


def test_parse_ipv6():
    networks = parse_exclude_ip_networks("2001:db8::/32")
    assert str(networks[0]) == "2001:db8::/32"


def test_parse_rejects_junk_and_host_bits():
    for bad in ("", "abc", "203.0.113.0/33", "203.0.113.7/24",
                "203.0.113.0/24,abc", "203.0.113.999"):
        with pytest.raises(ValueError):
            parse_exclude_ip_networks(bad)


def test_filter_drops_any_matching_ip():
    rows = [
        ("a.example.com", "200", "Brute", "203.0.113.5", ""),
        ("b.example.com", "200", "Brute", "198.51.100.2", ""),
        # One CDN IP plus one origin IP: the row is still hidden,
        # because the pipeline sees the row's whole IP set.
        ("c.example.com", "200", "Brute", "192.0.2.9, 203.0.113.200", ""),
    ]
    kept = filter_excluded_ip_results(
        rows, parse_exclude_ip_networks("203.0.113.0/24"))
    assert [r[0] for r in kept] == ["b.example.com"]


def test_filter_ignores_unparseable_tokens_and_version_mismatch():
    rows = [
        ("a.example.com", "200", "Brute", "not-an-ip", ""),
        ("b.example.com", "200", "Brute", "2001:db8::1", ""),
    ]
    # IPv4-only filter must not drop the IPv6 row or crash on it.
    kept = filter_excluded_ip_results(
        rows, parse_exclude_ip_networks("203.0.113.0/24"))
    assert [r[0] for r in kept] == ["a.example.com", "b.example.com"]
    # And the IPv6 filter drops only the IPv6 row.
    kept = filter_excluded_ip_results(
        rows, parse_exclude_ip_networks("2001:db8::/32"))
    assert [r[0] for r in kept] == ["a.example.com"]
