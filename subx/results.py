"""Result post-processing for SubX: dedupe and deterministic sorting.

Rows produced by the validation phase are (subdomain, status, source,
ips, cname) tuples, collected from threads in arbitrary order. The same
DNS host can appear more than once with different spellings -- letter
case (passive sources lowercase, the target domain may not) or a
trailing dot -- because DNS is case-insensitive and the collection dict
keys on exact strings. This module collapses those spelling variants
into a single row per host and sorts rows deterministically, so the
results table, quiet output, and the saved files (-o/--output) all show
one clean, ordered list.
"""

import ipaddress


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
    informative status, the combined source label, the union of
    observed IP addresses, and the first non-empty CNAME alias seen.
    """
    merged = {}
    for sub, status, source, ips, cname in results:
        key = normalize_subdomain(sub)
        existing = merged.get(key)
        if existing is None:
            merged[key] = [key, status, source, ips, cname]
            continue
        existing[1] = _prefer_status(existing[1], status)
        existing[2] = merge_sources(existing[2], source)
        existing[3] = _merge_ips(existing[3], ips)
        existing[4] = existing[4] or cname
    return [tuple(row) for row in merged.values()]


def sort_results(results):
    """Sort rows deterministically: subdomain first, then best status."""
    return sorted(results, key=lambda r: (r[0].lower(), _status_rank(r[1])))


def is_live_status(status):
    """True when a status string is a real HTTP response code.

    A validation row is "live" when the probe recorded an HTTP status
    (e.g. ``"200"``); ``"No HTTP"`` and ``"N/A"`` rows are DNS-only and
    not live.
    """
    return str(status).isdigit()


def filter_live_results(results):
    """Keep only rows with a working HTTP service.

    Used by ``--only-live``: drops the DNS-only rows (``"No HTTP"`` /
    ``"N/A"``) so recon pipelines get only subdomains that answered an
    HTTP(S) probe. Run after ``dedupe_results``/``sort_results`` so the
    merged rows stay consistent.
    """
    return [row for row in results if is_live_status(row[1])]


def parse_exclude_statuses(value):
    """Parse a comma-separated ``--exclude-status`` value into codes.

    Each token must be a three-digit HTTP status code (100-999);
    anything else raises ``ValueError`` so the CLI can fail fast
    instead of silently filtering nothing. Returns a frozenset of
    code strings, matching how statuses are stored on result rows.
    """
    codes = set()
    for token in str(value).split(","):
        token = token.strip()
        if not token.isdigit() or not 100 <= int(token) <= 999:
            raise ValueError(
                f"invalid status code {token!r} in --exclude-status "
                "(expected comma-separated codes like '403,404')"
            )
        codes.add(token)
    if not codes:
        raise ValueError("--exclude-status needs at least one status code")
    return frozenset(codes)


def filter_excluded_statuses(results, codes):
    """Drop rows whose HTTP status is in ``codes``.

    Used by ``--exclude-status``: hides e.g. 403/404 noise from
    recon pipelines. Run after ``dedupe_results``/``sort_results``
    so a merged row's best status is what gets matched, and
    DNS-only rows (``"No HTTP"``/``"N/A"``) are never dropped --
    they carry no numeric code to match.
    """
    return [row for row in results if str(row[1]) not in codes]


def parse_exclude_ip_networks(value):
    """Parse a comma-separated ``--exclude-ip`` value into networks.

    Each token is a CIDR range (``203.0.113.0/24``) or a bare IP
    (``203.0.113.7``, treated as a single-host network). CIDRs with
    host bits set (``203.0.113.7/24``) are rejected so a typo does not
    silently widen the filter; anything unparseable raises
    ``ValueError`` so the CLI can fail fast instead of filtering
    nothing. Returns a tuple of ``ipaddress`` network objects.
    """
    networks = []
    for token in str(value).split(","):
        token = token.strip()
        if not token:
            raise ValueError(
                "--exclude-ip needs at least one IP or CIDR "
                "(expected comma-separated values like "
                "'203.0.113.0/24,198.51.100.7')"
            )
        try:
            if "/" in token:
                networks.append(ipaddress.ip_network(token, strict=True))
            else:
                networks.append(ipaddress.ip_network(ipaddress.ip_address(token)))
        except ValueError:
            raise ValueError(
                f"invalid IP or CIDR {token!r} in --exclude-ip "
                "(expected values like '203.0.113.0/24' or '203.0.113.7')"
            ) from None
    if not networks:
        raise ValueError("--exclude-ip needs at least one IP or CIDR")
    return tuple(networks)


def _row_ip_in_networks(ips, networks):
    """True when any resolved IP in a row's IP column is filtered.

    The IP column is a comma-separated string (A records first, then
    AAAA). Unparseable tokens are ignored rather than dropping the
    row, and IPv4 addresses are never matched against IPv6 networks
    (or vice versa).
    """
    for chunk in str(ips).split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            addr = ipaddress.ip_address(chunk)
        except ValueError:
            continue
        for net in networks:
            if addr.version == net.version and addr in net:
                return True
    return False


def filter_excluded_ip_results(results, networks):
    """Drop rows with a resolved IP inside any of ``networks``.

    Used by ``--exclude-ip``: hides e.g. CDN ranges that blanket a
    target. A row is dropped when ANY of its IPs matches, so a host
    with one CDN IP and one origin IP is still hidden -- the row's IP
    set is what the pipeline sees. Run after
    ``dedupe_results``/``sort_results`` so merged rows are matched on
    their full IP union.
    """
    return [row for row in results if not _row_ip_in_networks(row[3], networks)]
