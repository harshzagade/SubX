"""Tests for wordlist loading and case-variant dedup (stdlib-only)."""

import os

import pytest

from subx.wordlist import load_wordlist, load_words_from_lines, dedupe_case_variants, skip_passive_hits


def test_dedupe_case_variants_drops_duplicates(tmp_path):
    words, dropped = dedupe_case_variants(
        ["admin", "Admin", "ADMIN", "mail", "Mail", "ftp"]
    )
    assert words == ["admin", "mail", "ftp"]
    assert dropped == 3


def test_dedupe_case_variants_keeps_first_seen_order():
    words, dropped = dedupe_case_variants(["B", "a", "b", "A", "c"])
    assert words == ["b", "a", "c"]
    assert dropped == 2


def test_dedupe_case_variants_empty_and_unique():
    assert dedupe_case_variants([]) == ([], 0)
    assert dedupe_case_variants(["a", "b"]) == (["a", "b"], 0)


def test_load_wordlist_strips_blanks_and_lowercases(tmp_path):
    path = tmp_path / "words.txt"
    path.write_text("  Admin  \n\nMAIL\n\t\nftp\n")
    assert load_wordlist(str(path)) == ["admin", "mail", "ftp"]


def test_load_words_from_lines_matches_file_normalization():
    # Same normalization as load_wordlist: strip, lowercase, drop blanks.
    assert load_words_from_lines(["  Admin  ", "", "MAIL", "\t", "ftp\n"]) == [
        "admin", "mail", "ftp",
    ]
    assert load_words_from_lines([]) == []


def test_load_wordlist_missing_file_raises():
    with pytest.raises(OSError):
        load_wordlist("/nonexistent/wordlist.txt")


def test_skip_passive_hits_skips_exact_matches():
    kept, skipped = skip_passive_hits(
        ["www", "mail", "ftp"],
        {"www.example.com", "api.example.com"},
        "example.com",
    )
    assert kept == ["mail", "ftp"]
    assert skipped == ["www"]


def test_skip_passive_hits_case_and_trailing_dot_tolerant():
    kept, skipped = skip_passive_hits(
        ["www", "mail"],
        {"WWW.EXAMPLE.COM.", "Mail.Example.Com"},
        "example.com",
    )
    assert kept == []
    assert skipped == ["www", "mail"]


def test_skip_passive_hits_keeps_deeper_names_and_bare_domain():
    # a.www.example.com is a different host from www.example.com,
    # and the bare target domain matches no word.
    kept, skipped = skip_passive_hits(
        ["www", "api"],
        {"a.www.example.com", "example.com", "api.other.com"},
        "example.com",
    )
    assert kept == ["www", "api"]
    assert skipped == []


def test_skip_passive_hits_empty_inputs():
    assert skip_passive_hits([], {"www.example.com"}, "example.com") == ([], [])
    assert skip_passive_hits(["www"], set(), "example.com") == (["www"], [])
    assert skip_passive_hits(["www"], None, "example.com") == (["www"], [])


def test_load_then_dedupe_end_to_end(tmp_path):
    path = tmp_path / "words.txt"
    path.write_text("Admin\nadmin\nAPI\napi\n")
    words, dropped = dedupe_case_variants(load_wordlist(str(path)))
    assert words == ["admin", "api"]
    assert dropped == 2
