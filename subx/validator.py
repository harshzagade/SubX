import dns.resolver
import requests
import random
import string

class Validator:
    #: Timeout (seconds) applied to every DNS query when the caller
    #: does not pass an explicit value.
    DEFAULT_DNS_TIMEOUT = 5.0

    def __init__(self, wildcard_ips=None, dns_timeout=None):
        self.wildcard_ips = wildcard_ips or set()
        if dns_timeout is None:
            dns_timeout = self.DEFAULT_DNS_TIMEOUT
        if dns_timeout <= 0:
            raise ValueError("dns_timeout must be positive")
        self.dns_timeout = dns_timeout
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

    def validate(self, subdomain, check_http=True):
        """Check if a subdomain resolves and optionally has a working web service."""
        try:
            # First, check DNS resolution
            answers = self.resolver.resolve(subdomain, 'A')
            ips = [str(ip) for ip in answers]
            
            # If all resolved IPs are in the wildcard set, it's likely a false positive
            if self.wildcard_ips and all(ip in self.wildcard_ips for ip in ips):
                return None

            if not check_http:
                return ips, "N/A"

            # Now, check for a working HTTP/HTTPS response
            for protocol in ["https", "http"]:
                try:
                    url = f"{protocol}://{subdomain}"
                    # Use a short timeout to keep it fast
                    response = requests.get(url, timeout=3, allow_redirects=True, verify=False)
                    
                    # Consider it "working" if it returns a success or redirect code
                    if 200 <= response.status_code < 400:
                        return ips, response.status_code
                except requests.RequestException:
                    continue
            
            # If HTTP check failed but DNS resolved, return DNS info if check_http was optional
            # But the logic here is: if check_http is True, we want results with HTTP response.
            # Let's adjust: if HTTP fails, we still return the IP but with "Down" status?
            # Or just return None if we strictly want active web services.
            # Given the tool's goal, let's return "DNS Only" if HTTP fails but DNS works.
            return ips, "No HTTP"
            
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, dns.exception.DNSException):
            return None
