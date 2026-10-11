"""Result post-processing for SubX: dedupe and deterministic sorting.

Rows produced by the validation phase are (subdomain, status, source, ips)
tuples, collected from threads in arbitrary order. The same DNS host can
appear more than once with different spellings -- letter case (passive
sources lowercase, the target domain may not) or a trailing dot -- because
DNS is case-insensitive and the collection dict keys on exact strings.
This module collapses those spelling variants into a single row per host
and sorts rows deterministically, so the results table, quiet output, and
the saved files (-o/--output) all show one clean, ordered list.
"""


def normalize_subdomain(sub):
    """Return the canonical spelling of a subdomain.

    DNS names are case-insensitive and a trailing dot just denotes the
    root, so both are folded away before comparing subdomains.
    """
    return sub.strip().rstrip(".").lower()


def merge_sources(a, b):
    """Combine the source labels of two rows naming the same host."""
    if a == b:
        return a
    parts = set()
    for label in (a, b):
        if label == "Both":
            parts.update(("Passive", "Brute"))
        else:
            parts.add(label)
    if parts == {"Passive", "Brute"}:
        return "Both"
    return "+".join(sorted(parts))


def _status_rank(status):
    """Rank a status string for merging: real HTTP status wins,
    then DNS-only, then unchecked."""
    s = str(status)
    if s.isdigit():
        return (0, int(s))
    if s == "No HTTP":
        return (1, 0)
    return (2, 0)


def _prefer_status(a, b):
    """Pick the more informative of two statuses deterministically."""
    return a if _status_rank(a) <= _status_rank(b) else b


def _ip_sort_key(ip):
    """Sort IPv4 numerically, anything else after, alphabetically."""
    try:
        return (0, tuple(int(part) for part in ip.split(".")))
    except ValueError:
        return (1, ip)


def _merge_ips(a, b):
    """Union the observed IP addresses of two merged rows, sorted."""
    ips = set()
    for chunk in (a, b):
        if chunk:
            ips.update(ip.strip() for ip in str(chunk).split(",") if ip.strip())
    return ", ".join(sorted(ips, key=_ip_sort_key))


def dedupe_results(results):
    """Collapse rows that name the same DNS host into a single row.

    The merged row uses the canonical (normalized) subdomain, the most
    informative status, the combined source label, and the union of
    observed IP addresses.
    """
    merged = {}
    for sub, status, source, ips in results:
        key = normalize_subdomain(sub)
        existing = merged.get(key)
        if existing is None:
            merged[key] = [key, status, source, ips]
            continue
        existing[1] = _prefer_status(existing[1], status)
        existing[2] = merge_sources(existing[2], source)
        existing[3] = _merge_ips(existing[3], ips)
    return [tuple(row) for row in merged.values()]


def sort_results(results):
    """Sort rows deterministically: subdomain first, then best status."""
    return sorted(results, key=lambda r: (r[0].lower(), _status_rank(r[1])))
