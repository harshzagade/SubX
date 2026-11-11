import dns.resolver
import html
import ipaddress
import requests
import random
import re
import string
import threading
import time
import urllib.parse

#: ASCII hostname check applied after punycode conversion, so garbage
#: input (spaces, empty labels) fails fast instead of hitting DNS.
_ASCII_HOSTNAME_RE = re.compile(
    r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$"
)

#: Sentinel stored in ``Validator._dns_cache`` for names that
#: definitively did not resolve. A dedicated object (not ``None``)
#: distinguishes "looked up, found nothing" from "never looked up".
_DNS_MISS = object()

#: Maximum length of a recorded page title. Titles are a recon label,
#: not a document dump, so anything longer is cut rather than widening
#: the results table.
TITLE_MAX_LENGTH = 80

#: Bytes of a probe response body scanned for a ``<title>``. Titles
#: live in ``<head>``, so 64 KiB is plenty and bounds the work on huge
#: pages instead of decoding the whole body.
_TITLE_SCAN_BYTES = 65536

#: Matches a page's ``<title>`` element. ``<title>`` content is raw
#: text by spec, but the strip step below tolerates stray markup.
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def extract_title(html_text):
    """Extract a page's ``<title>`` text, or ``""`` when there is none.

    HTML entities are unescaped (``&amp;`` becomes ``&``), runs of
    whitespace collapse to single spaces, and the result is cut to
    :data:`TITLE_MAX_LENGTH` characters so one long title cannot
    stretch the results table.
    """
    match = _TITLE_RE.search(html_text)
    if not match:
        return ""
    title = re.sub(r"<[^>]+>", "", match.group(1))
    title = html.unescape(title)
    title = " ".join(title.split())
    return title[:TITLE_MAX_LENGTH]


def to_ascii_domain(name):
    """Convert a domain name to its ASCII (punycode) form.

    Uses only the stdlib ``idna`` codec, so internationalized targets
    resolve instead of erroring out -- no extra dependency needed.
    Lowercases the name, strips a trailing dot, and validates the
    result as an ASCII hostname. Raises ``ValueError`` on empty input,
    unencodable labels, or anything that is not a valid hostname.

    Conversion is idempotent: already-ASCII names pass through
    unchanged (aside from lowercasing).
    """
    name = name.strip().rstrip(".").lower()
    if not name:
        raise ValueError("domain name is empty")
    try:
        labels = [label.encode("idna").decode("ascii") for label in name.split(".")]
    except UnicodeError as e:
        raise ValueError(f"cannot encode {name!r} as punycode: {e}")
    ascii_name = ".".join(labels)
    if not _ASCII_HOSTNAME_RE.match(ascii_name):
        raise ValueError(f"{ascii_name!r} is not a valid domain name")
    return ascii_name

class Validator:
    #: Timeout (seconds) applied to every DNS query when the caller
    #: does not pass an explicit value.
    DEFAULT_DNS_TIMEOUT = 5.0
    #: Timeout (seconds) for each HTTP/HTTPS probe request when the
    #: caller does not pass an explicit value.
    DEFAULT_HTTP_TIMEOUT = 3.0
    #: Maximum CNAME hops followed before resolving A records. Chains
    #: longer than this stop at the last reachable name; loops are cut
    #: at the first repeated name.
    MAX_CNAME_DEPTH = 5

    #: Number of extra attempts after a ``dns.resolver.Timeout`` before a
    #: DNS query is treated as a miss. Only timeouts are retried: NXDOMAIN,
    #: NoAnswer and other definitive answers fail fast on the first try.
    DEFAULT_DNS_RETRIES = 1

    #: Number of extra attempts after a transient HTTP probe failure
    #: (connection error or probe timeout) before a protocol is given
    #: up as "No HTTP". A single dropped packet or reset connection
    #: should not mark a live host dead, so the probe is retried once;
    #: non-transient failures (HTTP error responses, redirect loops,
    #: TLS errors) are never retried and fall through to the next
    #: protocol immediately.
    DEFAULT_HTTP_RETRIES = 1

    #: Number of independent random subdomains probed by
    #: :meth:`detect_wildcard`. A single probe can hit an anycast fluke
    #: -- one random name resolving to an unrelated anycast IP -- which
    #: would poison ``wildcard_ips`` and filter out real candidates for
    #: the whole scan. Two probes must resolve AND agree before the
    #: domain is treated as wildcarded.
    WILDCARD_PROBES = 2

    #: Pause (seconds) between probes when the caller does not pass an
    #: explicit value. Zero means no pacing -- probes run back to back.
    DEFAULT_DELAY = 0.0

    def __init__(self, wildcard_ips=None, dns_timeout=None, http_timeout=None,
                 dns_retries=None, resolver_ip=None, http_retries=None,
                 doh_url=None, delay=None, follow_redirects=True):
        self.wildcard_ips = wildcard_ips or set()
        if dns_timeout is None:
            dns_timeout = self.DEFAULT_DNS_TIMEOUT
        if dns_timeout <= 0:
            raise ValueError("dns_timeout must be positive")
        self.dns_timeout = dns_timeout
        if http_timeout is None:
            http_timeout = self.DEFAULT_HTTP_TIMEOUT
        if http_timeout <= 0:
            raise ValueError("http_timeout must be positive")
        self.http_timeout = http_timeout
        if dns_retries is None:
            dns_retries = self.DEFAULT_DNS_RETRIES
        if not isinstance(dns_retries, int) or dns_retries < 0:
            raise ValueError("dns_retries must be a non-negative integer")
        if http_retries is None:
            http_retries = self.DEFAULT_HTTP_RETRIES
        if not isinstance(http_retries, int) or http_retries < 0:
            raise ValueError("http_retries must be a non-negative integer")
        self.http_retries = http_retries
        # How many HTTP probes were retried after a transient failure.
        # Reported in the scan summary so a flaky network leaves a
        # visible trace instead of silently costing an extra request.
        self.http_probe_retries = 0
        self.dns_retries = dns_retries
        # Final URL per subdomain after the probe followed redirects,
        # keyed by subdomain. Only recorded when the landing URL
        # differs from the probed one, so same-URL responses add no
        # noise; read by the CLI to show a Final URL column. A plain
        # dict (not a return-value change) keeps validate()'s
        # (ips, status, alias) tuple stable for existing callers.
        self.final_urls = {}
        # Custom resolver: a single IP (v4 or v6) validated up front,
        # so garbage input fails fast instead of breaking mid-scan.
        # ``None`` keeps the system resolver, exactly as before.
        self.resolver_ip = None
        if resolver_ip is not None:
            try:
                self.resolver_ip = str(ipaddress.ip_address(str(resolver_ip).strip()))
            except ValueError:
                raise ValueError(
                    f"resolver_ip must be a valid IP address, got {resolver_ip!r}"
                ) from None
        # DNS-over-HTTPS endpoint: an ``https://`` URL with a host,
        # validated up front so garbage fails fast instead of breaking
        # mid-scan. ``None`` keeps plain UDP DNS, exactly as before.
        # A DoH endpoint and a custom resolver IP are two different
        # transports for the same queries, so they cannot be combined.
        self.doh_url = None
        if doh_url is not None:
            parsed = urllib.parse.urlparse(str(doh_url).strip())
            if parsed.scheme != "https" or not parsed.netloc:
                raise ValueError(
                    f"doh_url must be an https:// URL with a host, "
                    f"got {doh_url!r}"
                )
            self.doh_url = str(doh_url).strip()
        if self.resolver_ip is not None and self.doh_url is not None:
            raise ValueError(
                "--resolver and --doh cannot be combined: pick one "
                "DNS transport"
            )
        # Per-worker pause between probes, for stealthy scans against
        # rate-limited targets (mirrors DurbX's --delay). Applied at
        # the start of validate(), so each worker thread spaces its
        # own candidate probes by at least this long; with N threads
        # the aggregate rate is roughly N/delay probes per second.
        # Zero (the default) means no pacing.
        if delay is None:
            delay = self.DEFAULT_DELAY
        if delay < 0:
            raise ValueError("delay must be non-negative")
        self.delay = delay
        # Whether HTTP probes follow redirects (the default). When
        # False, the probe reports the first response's status (e.g.
        # a 301) instead of the landing page's 200, and no final URL
        # is recorded -- the response URL is the probed URL, so the
        # ``final_urls`` guard in ``validate`` never fires.
        self.follow_redirects = bool(follow_redirects)
        # How many candidates were dropped as wildcard false positives.
        # Incremented from worker threads, so updates are serialized.
        self.wildcard_filtered = 0
        self._filter_lock = threading.Lock()
        # Per-FQDN cache of DNS resolution results, keyed by the
        # normalized (punycode, lowercased) name. The brute-force phase
        # validates every wordlist candidate, and the validation phase
        # then re-validates all hits -- without this cache every
        # brute-force hit is resolved twice (CNAME chain + A records).
        # Values are (ips, alias) tuples on success; _DNS_MISS marks a
        # name that definitively did not resolve. Timeouts are never
        # cached: they are transient, so the next phase retries them
        # fresh instead of inheriting a stale miss.
        self._dns_cache = {}
        self._cache_lock = threading.Lock()
        # How many validations were served from the cache instead of
        # hitting DNS. Updated under _cache_lock; reported in the scan
        # summary.
        self.dns_cache_hits = 0
        # A dedicated resolver so the timeout is configurable per scan
        # instead of relying on dnspython's global default resolver.
        # With a custom resolver IP, dnspython must not read the system
        # resolv.conf (configure=False) or the system nameservers would
        # still be consulted alongside the chosen one.
        if self.resolver_ip is not None:
            self.resolver = dns.resolver.Resolver(configure=False)
            self.resolver.nameservers = [self.resolver_ip]
        else:
            self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = dns_timeout
        self.resolver.lifetime = dns_timeout

    def _resolve_doh(self, name, rdtype):
        """Resolve ``name``/``rdtype`` over DNS-over-HTTPS.

        Builds a DNS query message and sends it to ``self.doh_url``
        with ``dns.query.https`` (dnspython's DoH transport), so scans
        work on networks where UDP port 53 is filtered. The answer
        RRsets are flattened to the same rdata list
        ``resolver.resolve`` returns, so CNAME following and A/AAAA
        handling work unchanged.

        A DoH timeout surfaces as ``dns.exception.Timeout``; it is
        converted to ``dns.resolver.Timeout`` so the retry loop in
        :meth:`_resolve`, the no-cache rule in :meth:`_cached_dns`,
        and the miss handling in :meth:`validate` all treat a slow
        DoH endpoint exactly like a slow UDP resolver. An empty answer
        raises ``NoAnswer``, matching the resolver's behaviour for a
        name with no records of the requested type.
        """
        import dns.message
        import dns.query

        query = dns.message.make_query(name, rdtype)
        try:
            response = dns.query.https(self.doh_url, query,
                                       timeout=self.dns_timeout)
        except dns.exception.Timeout as e:
            raise dns.resolver.Timeout(str(e)) from e
        answers = [rdata for rrset in response.answer for rdata in rrset]
        if not answers:
            raise dns.resolver.NoAnswer()
        return answers

    def _resolve(self, name, rdtype):
        """Resolve ``name``/``rdtype`` with retry on timeout.

        A single dropped packet or slow authoritative server should not
        kill a candidate during brute-force, so ``dns.resolver.Timeout``
        is retried up to ``dns_retries`` times. Definitive answers
        (NXDOMAIN, NoAnswer, other DNSErrors) are never retried and
        propagate immediately.

        With a DoH endpoint configured, queries go over HTTPS instead
        of UDP; the transport is chosen here so every caller (wildcard
        probes, CNAME chains, A/AAAA lookups) uses it automatically.
        """
        last_error = None
        for _ in range(self.dns_retries + 1):
            try:
                if self.doh_url is not None:
                    return self._resolve_doh(name, rdtype)
                return self.resolver.resolve(name, rdtype)
            except dns.resolver.Timeout as e:
                last_error = e
        raise last_error

    @staticmethod
    def _random_label(length=15):
        """Generate one random lowercase/digit subdomain label."""
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

    def _probe_random_name(self, domain):
        """Resolve a single random subdomain of ``domain``.

        Returns the set of A-record IPs, or an empty set when the name
        does not resolve -- NXDOMAIN, NoAnswer, timeouts, and other DNS
        errors all just mean "no wildcard answer for this name".
        """
        full_domain = f"{self._random_label()}.{domain}"
        try:
            answers = self._resolve(full_domain, 'A')
            return {str(ip) for ip in answers}
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.Timeout, dns.exception.DNSException):
            return set()

    def detect_wildcard(self, domain):
        """Detect if the domain has a wildcard DNS record.

        Probes :attr:`WILDCARD_PROBES` independent random subdomains and
        declares a wildcard only when at least two probes resolve AND
        their answers agree on at least one IP. A lone resolving probe
        (an anycast fluke) is ignored, so a single stray answer can no
        longer poison ``wildcard_ips`` and filter out genuine subdomains
        for the rest of the scan.

        Returns the agreed-upon wildcard IP set -- empty when the domain
        is not wildcarded or the probes disagree.
        """
        domain = to_ascii_domain(domain)
        hits = []
        for _ in range(self.WILDCARD_PROBES):
            ips = self._probe_random_name(domain)
            if ips:
                hits.append(ips)
        if len(hits) < 2:
            return set()
        return set.intersection(*hits)

    @staticmethod
    def _cname_target(answers):
        """Extract the target hostname from a CNAME answer."""
        rdata = next(iter(answers))
        target = getattr(rdata, "target", None)
        if target is not None:
            return str(target).rstrip(".")
        # Fallback for rdata-like objects without a .target attribute.
        return str(rdata).rstrip(".")

    def resolve_cnames(self, name):
        """Follow the CNAME chain starting at ``name``.

        Returns ``(final_name, alias)`` where ``alias`` is the first
        CNAME target seen (``None`` when ``name`` carries no CNAME
        record) and ``final_name`` is the last name in the chain whose
        A records should be resolved. Loops are cut at the first
        repeated name; chains longer than :attr:`MAX_CNAME_DEPTH`
        stop at that depth.

        Raises the usual dnspython exceptions when a name in the
        chain does not exist or cannot be resolved.
        """
        seen = {name.rstrip(".").lower()}
        alias = None
        current = name
        for _ in range(self.MAX_CNAME_DEPTH):
            try:
                answers = self._resolve(current, "CNAME")
            except dns.resolver.NoAnswer:
                break  # No CNAME here; A records live on `current`.
            target = self._cname_target(answers)
            if alias is None:
                alias = target
            key = target.rstrip(".").lower()
            if key in seen:
                break  # CNAME loop; resolve what we have.
            seen.add(key)
            current = target
        return current, alias

    def _cached_dns(self, subdomain):
        """Resolve ``subdomain``'s CNAME chain and A/AAAA records, using the cache.

        The first validation of a name performs the DNS work -- CNAME
        chain following plus A-record and AAAA-record lookups -- and
        stores the outcome keyed by the normalized name. Later
        validations of the same name skip DNS entirely and reuse the
        stored result, which is what saves the validation phase from
        re-resolving every brute-force hit from scratch.

        A name with only AAAA records (no A) is a hit, not a miss:
        each record type's definitive failure (NXDOMAIN, NoAnswer) is
        tolerated on its own, and the name is a miss only when both
        types fail. The reported IP list is the A addresses followed
        by the AAAA addresses, deduplicated in order, so the IP column
        shows the full dual-stack picture and the wildcard filter
        (which drops a candidate only when *all* its IPs are wildcard
        IPs) applies to the v6 set as well.

        Definitive misses (NXDOMAIN, NoAnswer, other DNSErrors) are
        cached too, since a dead name stays dead for the length of a
        scan. ``Timeout`` is deliberately NOT cached: it is transient,
        so a later phase retries the lookup fresh instead of reusing a
        stale miss.

        Returns ``(ips, alias)``. Raises the usual dnspython exceptions
        on resolution failure, exactly as an uncached lookup would.
        """
        with self._cache_lock:
            cached = self._dns_cache.get(subdomain)
        if cached is not None:
            with self._cache_lock:
                self.dns_cache_hits += 1
            if cached is _DNS_MISS:
                raise dns.resolver.NXDOMAIN(subdomain)
            return cached
        # Resolve without holding the lock so concurrent validations of
        # different names are not serialized. Every writer stores the
        # same deterministic data, so last-write-wins is safe.
        try:
            final_name, alias = self.resolve_cnames(subdomain)
            ips = []
            failures = []
            for rdtype in ("A", "AAAA"):
                try:
                    answers = self._resolve(final_name, rdtype)
                except dns.resolver.Timeout:
                    raise  # Transient: never cached, retried fresh.
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                        dns.exception.DNSException) as e:
                    failures.append(e)
                    continue
                ips.extend(str(ip) for ip in answers)
            if not ips:
                # Both record types failed definitively; surface the
                # last failure so the caller caches it as a miss.
                raise failures[-1]
            result = (list(dict.fromkeys(ips)), alias)
        except dns.resolver.Timeout:
            raise  # Transient: never cached, retried fresh next time.
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.exception.DNSException):
            with self._cache_lock:
                self._dns_cache[subdomain] = _DNS_MISS
            raise
        with self._cache_lock:
            self._dns_cache[subdomain] = result
        return result

    def _probe_http(self, url):
        """GET ``url``, retrying transient failures once.

        Redirects are followed unless the validator was built with
        ``follow_redirects=False`` (``--no-follow-redirects``), in
        which case the first response is returned as-is.

        Only connection errors and timeouts are retried -- a refused
        connection or a stalled response is often a flaky network, not
        a dead host. Every other ``requests`` failure (TLS errors,
        redirect loops, invalid URLs) propagates immediately so the
        caller can fall through to the next protocol.

        The transient exception classes are resolved from the
        ``requests`` module at call time rather than import time, so
        test doubles that define their own ``ConnectionError`` /
        ``Timeout`` subclasses are honored.

        Returns the response. Raises the last transient error when
        all attempts are exhausted.
        """
        transient = tuple(
            exc for exc in (
                getattr(requests, "ConnectionError", None),
                getattr(requests, "Timeout", None),
            )
            if isinstance(exc, type)
        )
        for attempt in range(self.http_retries + 1):
            try:
                return requests.get(url, timeout=self.http_timeout,
                                    allow_redirects=self.follow_redirects,
                                    verify=False)
            except requests.RequestException as e:
                if not transient or not isinstance(e, transient):
                    raise
                if attempt == self.http_retries:
                    raise
                self.http_probe_retries += 1

    def fetch_title(self, subdomain):
        """Fetch ``subdomain``'s HTML ``<title>`` (``""`` when unavailable).

        One extra GET per call -- the caller decides when a title is
        worth it (live hosts only). Tries HTTPS first, then HTTP,
        reusing the probe's transient-retry behaviour; any failure (no
        HTTP service, a non-2xx/3xx status, a missing ``<title>``)
        leaves the title blank instead of failing the scan. Only the
        first 64 KiB of the body is scanned, since ``<title>`` lives
        in ``<head>``.
        """
        subdomain = to_ascii_domain(subdomain)
        for protocol in ("https", "http"):
            try:
                response = self._probe_http(f"{protocol}://{subdomain}")
            except requests.RequestException:
                continue
            if 200 <= response.status_code < 400:
                body = getattr(response, "content", b"") or b""
                text = body[:_TITLE_SCAN_BYTES].decode("utf-8", errors="ignore")
                return extract_title(text)
        return ""

    def validate(self, subdomain, check_http=True):
        """Check if a subdomain resolves and optionally has a working web service.

        CNAME aliases are followed to their final target: a name that
        is only a CNAME (e.g. pointing at a CDN) is no longer dropped
        as a miss. Returns ``(ips, status, alias)`` -- the final
        A-record and AAAA-record IPs (A first, deduplicated), the HTTP
        status (or ``"No HTTP"``/``"N/A"``), and the first CNAME target
        seen (``None`` when the name has no CNAME record). Returns
        ``None`` when the name does not resolve.

        Internationalized names are converted to punycode first, so
        unicode targets resolve instead of erroring out.

        DNS resolution results (CNAME chain + A records) are cached per
        FQDN: validating the same name twice -- as the brute-force and
        validation phases do -- performs the DNS lookups only once. The
        HTTP probe is not cached and always runs fresh; each protocol's
        probe is retried once on transient connection errors or
        timeouts before the host is marked "No HTTP".

        When ``delay`` is set, this call pauses first, so each worker
        thread spaces its candidate probes by at least ``delay``
        seconds -- the pacing that keeps a scan under a target's rate
        limit. The pause happens even when the name turns out to be a
        miss, so the rate stays steady instead of bunching up on the
        live names.

        The HTTP probe always targets the original ``subdomain`` (so
        the Host header and TLS SNI stay correct), not the CNAME
        target. By default the probe follows redirects and reports the
        landing page's status; with ``follow_redirects=False`` it
        reports the first response's status instead (a 301 stays a
        301), so pipelines see the raw redirect rather than the
        landing page's 200.
        """
        subdomain = to_ascii_domain(subdomain)
        if self.delay:
            time.sleep(self.delay)
        try:
            # CNAME chain + A/AAAA records come from the per-FQDN cache, so
            # the validation phase reuses the brute-force phase's DNS
            # work instead of repeating it. The wildcard filter below
            # still runs on every call against the cached IPs, so a
            # mid-scan update of wildcard_ips is always honored.
            ips, alias = self._cached_dns(subdomain)

            # If all resolved IPs are in the wildcard set, it's likely a false positive
            if self.wildcard_ips and all(ip in self.wildcard_ips for ip in ips):
                with self._filter_lock:
                    self.wildcard_filtered += 1
                return None

            if not check_http:
                return ips, "N/A", alias

            # Now, check for a working HTTP/HTTPS response. Each
            # protocol's probe is retried once on transient failures
            # (connection error / timeout) inside _probe_http, so a
            # flaky network does not mark a live host "No HTTP".
            for protocol in ["https", "http"]:
                try:
                    url = f"{protocol}://{subdomain}"
                    # Use a short timeout to keep it fast
                    response = self._probe_http(url)

                    # Consider it "working" if it returns a success or redirect code
                    if 200 <= response.status_code < 400:
                        # The probe follows redirects, so the status may
                        # belong to a different host or path than the
                        # subdomain probed. Record the landing URL when
                        # it differs, so the results show where the
                        # redirect chain actually ended instead of only
                        # the original name. getattr: test doubles may
                        # not carry .url.
                        final_url = getattr(response, "url", "") or ""
                        if final_url and final_url != url:
                            self.final_urls[subdomain] = final_url
                        return ips, response.status_code, alias
                except requests.RequestException:
                    continue

            # If HTTP check failed but DNS resolved, return DNS info if check_http was optional
            # But the logic here is: if check_http is True, we want results with HTTP response.
            # Let's adjust: if HTTP fails, we still return the IP but with "Down" status?
            # Or just return None if we strictly want active web services.
            # Given the tool's goal, let's return "DNS Only" if HTTP fails but DNS works.
            return ips, "No HTTP", alias

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, dns.exception.DNSException):
            return None
