"""Wordlist loading and normalization for SubX's brute-force phase.

Deliberately stdlib-only so this module stays importable (and
unit-testable) in environments where the CLI dependencies (click,
rich) are not installed.
"""


def load_wordlist(path):
    """Read brute-force candidate words from ``path``.

    Lines are stripped of surrounding whitespace, lowercased, and
    blank lines are dropped, preserving file order. Raises the usual
    ``OSError`` when the file cannot be read.
    """
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return [line.strip().lower() for line in f if line.strip()]


def dedupe_case_variants(words):
    """Drop case-variant duplicates from a wordlist, keeping first-seen order.

    Wordlists assembled from multiple sources often contain the same
    label in different cases (``Admin`` vs ``admin``); DNS is
    case-insensitive, so probing both wastes queries. Comparison folds
    case and the surviving spelling is the lowercased word.

    Returns ``(unique_words, dropped_count)``.
    """
    seen = set()
    unique = []
    for word in words:
        key = word.lower()
        if key in seen:
            continue
        seen.add(key)
        unique.append(key)
    return unique, len(words) - len(unique)
