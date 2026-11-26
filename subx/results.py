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
import json

from .filters import excluded_cname


def load_resumed_results(path):
    """Read a previous SubX ``-o`` JSON output file for ``--resume``.

    Returns ``(rows, titles, final_urls, redirect_counts,
    body_hashes)``: ``rows`` are the prior result rows as (subdomain,
    status, source, ips, cname) tuples, ``titles`` maps normalized
    subdomains to their recorded HTML ``<title>`` (only rows that had
    one), ``final_urls`` maps normalized subdomains to the URL the
    probe landed on after following redirects (only rows that had
    one), ``redirect_counts`` maps normalized subdomains to the
    redirect hop count recorded for the probe (only rows that had
    one), and ``body_hashes`` maps normalized subdomains to the short
    SHA-256 prefix of the probe response body (only rows that had
    one). Subdomains are normalized (lowercased, trailing dot
    stripped) and duplicate spellings collapse to the first row seen,
    matching how ``dedupe_results`` treats them.

    Raises ``OSError`` when the file cannot be read and ``ValueError``
    when it is not a SubX JSON output (bad JSON, wrong top-level
    shape, or a result entry missing a required field), so the CLI
    can fail fast instead of silently resuming from garbage.
    """
    with open(path, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"{path} is not valid JSON: {e}") from None
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        raise ValueError(
            f"{path} is not a SubX JSON output (expected an object "
            'with a "results" list)'
        )
    rows = []
    titles = {}
    final_urls = {}
    redirect_counts = {}
    body_hashes = {}
    seen = set()
    for entry in data["results"]:
        if not isinstance(entry, dict):
            raise ValueError(
                f"{path} has a result entry that is not an object: {entry!r}"
            )
        sub = entry.get("subdomain")
        if not isinstance(sub, str) or not sub.strip():
            raise ValueError(
                f"{path} has a result entry without a subdomain: {entry!r}"
            )
        status = entry.get("status")
        if not isinstance(status, (str, int)):
            raise ValueError(
                f"{path} has a result entry without a status: {entry!r}"
            )
        source = entry.get("source")
        if not isinstance(source, str) or not source:
            raise ValueError(
                f"{path} has a result entry without a source: {entry!r}"
            )
        ips = entry.get("ips")
        if isinstance(ips, list):
            if not all(isinstance(ip, str) for ip in ips):
                raise ValueError(
                    f"{path} has a result entry with non-string IPs: {entry!r}"
                )
            ips = ", ".join(ips)
        elif not isinstance(ips, str):
            raise ValueError(
                f"{path} has a result entry without IPs: {entry!r}"
            )
        cname = entry.get("cname")
        if cname is not None and not isinstance(cname, str):
            raise ValueError(
                f"{path} has a result entry with a non-string CNAME: {entry!r}"
            )
        key = normalize_subdomain(sub)
        if key in seen:
            continue
        seen.add(key)
        rows.append((key, str(status), source, ips, cname or ""))
        title = entry.get("title")
        if isinstance(title, str) and title:
            titles[key] = title
        final_url = entry.get("final_url")
        if isinstance(final_url, str) and final_url:
            final_urls[key] = final_url
        redirects = entry.get("redirects")
        # A JSON true/false is a bool, which is an int subclass, so
        # exclude bools explicitly; negative counts are not valid
        # hop counts and are ignored like any other junk field.
        if (isinstance(redirects, int) and not isinstance(redirects, bool)
                and redirects >= 0):
            redirect_counts[key] = redirects
        body_hash = entry.get("body_hash")
        if isinstance(body_hash, str) and body_hash:
            body_hashes[key] = body_hash
    return rows, titles, final_urls, redirect_counts, body_hashes


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


def cap_results(results, max_results):
    """Keep at most ``max_results`` rows, in the order given.

    Used by ``--max-results``: rows arrive already deduped and
    sorted, so the cap keeps the first N rows and reports how many
    were hidden, so huge scans stay readable. ``None`` means no cap:
    every row is kept and nothing is hidden.
    """
    if max_results is None:
        return list(results), 0
    kept = list(results)[:max_results]
    return kept, len(results) - len(kept)


def count_statuses(results):
    """Count rows per HTTP status, for the scan summary.

    Numeric codes sort first in ascending order (200, 301, 404),
    then the DNS-only labels (``"N/A"``, ``"No HTTP"``)
    alphabetically, so the summary reads as the scan's 200/301/404
    makeup at a glance. Counts are taken from the rows passed in --
    the caller runs this after the display filters, so the breakdown
    matches the rendered table.
    """
    counts = {}
    for row in results:
        status = str(row[1])
        counts[status] = counts.get(status, 0) + 1

    def _order(status):
        if status.isdigit():
            return (0, int(status))
        return (1, status)

    return {s: counts[s] for s in sorted(counts, key=_order)}


# The scan's phases, in the order they run. ``format_phase_timings``
# and the JSON ``stats`` block both use this order so the summary
# always reads passive -> brute-force -> validation.
PHASE_ORDER = ("passive", "brute-force", "validation")


def format_phase_timings(phase_timings):
    """Format per-phase timings for the scan summary.

    ``phase_timings`` maps phase name to elapsed seconds (float);
    phases that were skipped (``--no-passive`` / ``--no-brute``) are
    simply absent, so they never appear in the line. Returns
    ``"passive 1.23s, brute-force 4.56s, validation 7.89s"`` in
    canonical phase order, or ``""`` when nothing ran (e.g. a scan
    that found no candidates and returned before validation).
    """
    if not phase_timings:
        return ""
    parts = []
    for name in PHASE_ORDER:
        if name in phase_timings:
            parts.append(f"{name} {phase_timings[name]:.2f}s")
    # Unknown keys (a future phase) still show up, after the known
    # ones, so new phases are never silently dropped from the line.
    for name in sorted(phase_timings):
        if name not in PHASE_ORDER:
            parts.append(f"{name} {phase_timings[name]:.2f}s")
    return ", ".join(parts)


def _parse_status_codes(value, flag):
    """Shared comma-separated status-code grammar for the status filters.

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
                f"invalid status code {token!r} in {flag} "
                "(expected comma-separated codes like '403,404')"
            )
        codes.add(token)
    if not codes:
        raise ValueError(f"{flag} needs at least one status code")
    return frozenset(codes)


def parse_exclude_statuses(value):
    """Parse a comma-separated ``--exclude-status`` value into codes."""
    return _parse_status_codes(value, "--exclude-status")


def parse_include_statuses(value):
    """Parse a comma-separated ``--include-status`` value into codes."""
    return _parse_status_codes(value, "--include-status")


def filter_included_statuses(results, codes):
    """Keep only rows whose HTTP status is in ``codes``.

    Used by ``--include-status``: the inverse of
    ``--exclude-status``, for pipelines that only care about e.g.
    200s. Run after ``dedupe_results``/``sort_results`` so a merged
    row's best status is what gets matched, and DNS-only rows
    (``"No HTTP"``/``"N/A"``) are dropped -- they carry no numeric
    code to keep.
    """
    return [row for row in results if str(row[1]) in codes]


def filter_excluded_cname_results(results, compiled):
    """Drop rows whose CNAME alias matches any compiled glob pattern.

    Used by ``--exclude-cname``: hides e.g. known CDN/alias noise the
    way ``--exclude-sub`` hides brute-force noise. Run after
    ``dedupe_results``/``sort_results`` so merged rows are matched on
    their final alias, and rows with no alias are never dropped --
    there is nothing to match.
    """
    return [row for row in results
            if not excluded_cname(row[4], compiled)]


def parse_wildcard_ips(value):
    """Parse a comma-separated ``--wildcard-ips`` value into IP strings.

    Each token must be a valid IPv4 or IPv6 address; anything else
    raises ``ValueError`` so the CLI can fail fast instead of
    silently filtering nothing. Returns a frozenset of normalized
    address strings (``ipaddress`` canonical form, so e.g.
    ``2001:0db8::1`` and ``2001:db8::1`` compare equal), matching how
    resolved IPs are stored on the validator's ``wildcard_ips`` set.
    """
    ips = set()
    for token in str(value).split(","):
        token = token.strip()
        if not token:
            raise ValueError(
                "--wildcard-ips needs at least one IP address "
                "(expected comma-separated values like "
                "'203.0.113.7,198.51.100.42')"
            )
        try:
            ips.add(str(ipaddress.ip_address(token)))
        except ValueError:
            raise ValueError(
                f"invalid IP address {token!r} in --wildcard-ips "
                "(expected comma-separated values like "
                "'203.0.113.7,198.51.100.42')"
            ) from None
    if not ips:
        raise ValueError("--wildcard-ips needs at least one IP address")
    return frozenset(ips)


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
