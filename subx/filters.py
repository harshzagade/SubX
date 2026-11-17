"""Candidate-exclusion helpers for SubX.

Deliberately stdlib-only so this module stays importable (and
unit-testable) in environments where the CLI dependencies (click,
rich) are not installed.
"""

import fnmatch
import re


def parse_exclude_patterns(patterns, name="exclude-sub"):
    """Compile ``--exclude-sub`` (or ``--exclude-cname``) glob patterns
    into case-insensitive matchers.

    Each pattern is matched against the FULL candidate subdomain (e.g.
    ``news.blog.example.com``), so wildcards go around the part you want
    to skip: ``*.blog.*`` skips everything under any ``blog`` subdomain.
    Matching is case-insensitive, like DNS names themselves.

    Raises ``ValueError`` on empty or whitespace-only patterns so bad
    input fails fast instead of silently matching nothing. ``name`` is
    the flag the patterns came from, used in the error message.
    """
    compiled = []
    for pattern in patterns or []:
        text = pattern.strip()
        if not text:
            raise ValueError(f"{name} pattern must not be empty")
        compiled.append(re.compile(fnmatch.translate(text), re.IGNORECASE))
    return compiled


def excluded_subdomain(name, compiled):
    """Return True when ``name`` matches any compiled exclude pattern.

    ``name`` is lowercased before matching; an empty pattern list never
    excludes anything.
    """
    candidate = name.lower()
    return any(rx.match(candidate) is not None for rx in compiled)


def excluded_cname(alias, compiled):
    """Return True when a result's CNAME ``alias`` matches any compiled
    exclude pattern.

    The alias is matched in full (e.g. ``*.cloudfront.net`` hides every
    row aliased under CloudFront), case-insensitively like DNS names.
    Rows with no alias (``None`` or ``""``) are never excluded -- there
    is nothing to match -- and an empty pattern list excludes nothing.
    """
    if not alias:
        return False
    candidate = alias.lower()
    return any(rx.match(candidate) is not None for rx in compiled)
