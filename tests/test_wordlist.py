"""Tests for wordlist loading and case-variant dedup (stdlib-only)."""

import os

import pytest

from subx.wordlist import load_wordlist, dedupe_case_variants


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


def test_load_wordlist_missing_file_raises():
    with pytest.raises(OSError):
        load_wordlist("/nonexistent/wordlist.txt")


def test_load_then_dedupe_end_to_end(tmp_path):
    path = tmp_path / "words.txt"
    path.write_text("Admin\nadmin\nAPI\napi\n")
    words, dropped = dedupe_case_variants(load_wordlist(str(path)))
    assert words == ["admin", "api"]
    assert dropped == 2
