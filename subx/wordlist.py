"""Wordlist loading and normalization for SubX's brute-force phase.

Deliberately stdlib-only so this module stays importable (and
unit-testable) in environments where the CLI dependencies (click,
rich) are not installed.
"""


def load_words_from_lines(lines):
    """Normalize an iterable of wordlist lines into candidate words.

    Lines are stripped of surrounding whitespace, lowercased, and
    blank lines are dropped, preserving order. This is the shared
    normalization for both file wordlists and stdin (``-w -``), so a
    piped list behaves exactly like the same words in a file.
    """
    return [line.strip().lower() for line in lines if line.strip()]


def load_wordlist(path):
    """Read brute-force candidate words from ``path``.

    Lines are stripped of surrounding whitespace, lowercased, and
    blank lines are dropped, preserving file order. Raises the usual
    ``OSError`` when the file cannot be read.
    """
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return load_words_from_lines(f)


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


def skip_passive_hits(words, passive_subdomains, domain):
    """Drop brute-force words already discovered by passive sources.

    A word ``w`` is skipped when ``w.<domain>`` already appears among
    the passive hits, because the validation phase will validate that
    candidate exactly once anyway -- probing it again in the
    brute-force phase spends a DNS lookup plus an HTTP probe for a
    candidate that is already known. Comparison is case-insensitive
    (like DNS itself) and tolerates a trailing dot on either side, so
    ``WWW.example.com.`` still matches word ``www``.

    Only exact single-label matches are skipped: a passive hit such
    as ``a.www.example.com`` does not skip word ``www`` (that would
    be ``www.example.com``, a different host), and the bare target
    domain itself never matches a word.

    Returns ``(kept_words, skipped_words)``, both in input order.
    The caller's passive set is untouched; it should upgrade each
    skipped candidate's source to ``"Both"`` so the result table
    still records that the wordlist contained it.
    """
    domain_key = domain.strip().rstrip(".").lower()
    passive_keys = {
        str(name).strip().rstrip(".").lower()
        for name in passive_subdomains or []
    }
    kept = []
    skipped = []
    for word in words:
        candidate = f"{word.strip().lower()}.{domain_key}"
        if candidate in passive_keys:
            skipped.append(word)
        else:
            kept.append(word)
    return kept, skipped
