"""Unit tests for ``subx.filters`` -- the ``--exclude-sub`` glob matcher."""

import pytest

from subx.filters import excluded_subdomain, parse_exclude_patterns


def test_empty_pattern_fails_fast():
    with pytest.raises(ValueError):
        parse_exclude_patterns([""])
    with pytest.raises(ValueError):
        parse_exclude_patterns(["   "])


def test_no_patterns_never_excludes():
    assert excluded_subdomain("api.example.com", []) is False


def test_wildcard_matches_noise_subtree():
    compiled = parse_exclude_patterns(["*.blog.*"])
    assert excluded_subdomain("news.blog.example.com", compiled) is True
    assert excluded_subdomain("a.b.blog.example.com", compiled) is True
    assert excluded_subdomain("api.example.com", compiled) is False


def test_pattern_matches_full_candidate_name():
    # Globs are matched against the whole candidate, so a pattern
    # without wildcards is an exact match only.
    compiled = parse_exclude_patterns(["*.blog"])
    assert excluded_subdomain("news.blog.example.com", compiled) is False
    assert excluded_subdomain("news.blog", compiled) is True


def test_matching_is_case_insensitive():
    compiled = parse_exclude_patterns(["*.BLOG.*"])
    assert excluded_subdomain("news.blog.example.com", compiled) is True
    compiled = parse_exclude_patterns(["STAGING-*"])
    assert excluded_subdomain("staging-1.example.com", compiled) is True


def test_prefix_glob():
    compiled = parse_exclude_patterns(["staging-*"])
    assert excluded_subdomain("staging-1.example.com", compiled) is True
    assert excluded_subdomain("prod.example.com", compiled) is False


def test_exact_name_match():
    compiled = parse_exclude_patterns(["api.example.com"])
    assert excluded_subdomain("api.example.com", compiled) is True
    assert excluded_subdomain("api2.example.com", compiled) is False


def test_any_pattern_matching_excludes():
    compiled = parse_exclude_patterns(["*.blog.*", "staging-*"])
    assert excluded_subdomain("news.blog.example.com", compiled) is True
    assert excluded_subdomain("staging-9.example.com", compiled) is True
    assert excluded_subdomain("api.example.com", compiled) is False


def test_whitespace_is_stripped():
    compiled = parse_exclude_patterns(["  *.blog.*  "])
    assert excluded_subdomain("news.blog.example.com", compiled) is True
