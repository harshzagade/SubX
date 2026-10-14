import dns.resolver
import requests
import random
import string
import threading

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

    def __init__(self, wildcard_ips=None, dns_timeout=None, http_timeout=None):
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
        # How many candidates were dropped as wildcard false positives.
        # Incremented from worker threads, so updates are serialized.
        self.wildcard_filtered = 0
        self._filter_lock = threading.Lock()
        # A dedicated resolver so the timeout is configurable per scan
        # instead of relying on dnspython's global default resolver.
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = dns_timeout
        self.resolver.lifetime = dns_timeout

    def detect_wildcard(self, domain):
        """Detect if the domain has a wildcard DNS record."""
        random_sub = ''.join(random.choices(string.ascii_lowercase + string.digits, k=15))
        try:
            full_domain = f"{random_sub}.{domain}"
            answers = self.resolver.resolve(full_domain, 'A')
            ips = {str(ip) for ip in answers}
            return ips
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, dns.exception.DNSException):
            return set()

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
                answers = self.resolver.resolve(current, "CNAME")
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

    def validate(self, subdomain, check_http=True):
        """Check if a subdomain resolves and optionally has a working web service.

        CNAME aliases are followed to their final target: a name that
        is only a CNAME (e.g. pointing at a CDN) is no longer dropped
        as a miss. Returns ``(ips, status, alias)`` -- the final
        A-record IPs, the HTTP status (or ``"No HTTP"``/``"N/A"``), and
        the first CNAME target seen (``None`` when the name has no
        CNAME record). Returns ``None`` when the name does not resolve.

        The HTTP probe always targets the original ``subdomain`` (so
        the Host header and TLS SNI stay correct), not the CNAME
        target.
        """
        try:
            # Follow any CNAME chain first, then resolve A records on
            # the final name.
            final_name, alias = self.resolve_cnames(subdomain)
            answers = self.resolver.resolve(final_name, 'A')
            ips = [str(ip) for ip in answers]

            # If all resolved IPs are in the wildcard set, it's likely a false positive
            if self.wildcard_ips and all(ip in self.wildcard_ips for ip in ips):
                with self._filter_lock:
                    self.wildcard_filtered += 1
                return None

            if not check_http:
                return ips, "N/A", alias

            # Now, check for a working HTTP/HTTPS response
            for protocol in ["https", "http"]:
                try:
                    url = f"{protocol}://{subdomain}"
                    # Use a short timeout to keep it fast
                    response = requests.get(url, timeout=self.http_timeout, allow_redirects=True, verify=False)

                    # Consider it "working" if it returns a success or redirect code
                    if 200 <= response.status_code < 400:
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
