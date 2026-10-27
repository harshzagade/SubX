import requests
import re
import logging

class Enumerator:
    DEFAULT_SOURCE_TIMEOUT = 15.0
    #: Retries after a transient passive-source HTTP failure
    #: (connection error / timeout) before the source is dropped.
    DEFAULT_SOURCE_RETRIES = 1

    def __init__(self, domain, source_timeout=None, source_retries=None):
        self.domain = domain
        if source_timeout is None:
            source_timeout = self.DEFAULT_SOURCE_TIMEOUT
        if source_timeout <= 0:
            raise ValueError("source_timeout must be positive")
        self.source_timeout = source_timeout
        if source_retries is None:
            source_retries = self.DEFAULT_SOURCE_RETRIES
        if not isinstance(source_retries, int) or source_retries < 0:
            raise ValueError("source_retries must be a non-negative integer")
        self.source_retries = source_retries
        self.log = logging.getLogger("subx.enumerator")
        # Sources that ultimately failed, name -> error text. The CLI
        # reports this count in the scan summary so a silently dropped
        # source is visible instead of disappearing into a debug log.
        self.source_failures = {}

    def passive_enumerate(self):
        """Passive enumeration using multiple sources"""
        subdomains = set()

        sources = [
            ("crt.sh", self._crtsh),
            ("HackerTarget", self._hackertarget),
            ("AlienVault", self._alienvault)
        ]

        for name, func in sources:
            self.log.debug(f"Querying [bold cyan]{name}[/bold cyan]...")
            found = None
            last_error = None
            for attempt in range(self.source_retries + 1):
                try:
                    found = func()
                    break
                except requests.RequestException as e:
                    # Transient HTTP failure: one retry, then drop.
                    last_error = e
                    if attempt < self.source_retries:
                        self.log.debug(
                            f"Retrying [bold cyan]{name}[/bold cyan] "
                            f"after transient failure: {e}")
                except Exception as e:
                    # Anything else (bad payload, parse error) is not
                    # transient, so retrying would just repeat it.
                    last_error = e
                    break
            if found is None:
                self.source_failures[name] = str(last_error)
                self.log.error(f"Error querying {name}: {last_error}")
            else:
                self.log.debug(f"Found [green]{len(found)}[/green] candidates from {name}.")
                subdomains.update(found)

        return subdomains

    def _alienvault(self):
        subdomains = set()
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
        try:
            response = requests.get(url, timeout=self.source_timeout)
            if response.status_code == 200:
                data = response.json()
                for entry in data.get('passive_dns', []):
                    sub = entry.get('hostname', '').lower()
                    if sub.endswith(self.domain):
                        subdomains.add(sub)
        except requests.RequestException:
            raise
        except Exception:
            pass
        return subdomains

    def _crtsh(self):
        subdomains = set()
        url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
        # Regex to ensure the subdomain is a valid format (no spaces, valid characters)
        domain_regex = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$")
        try:
            response = requests.get(url, timeout=self.source_timeout)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name_value = entry['name_value']
                    for sub in name_value.split('\n'):
                        sub = sub.strip().lower()
                        if sub.endswith(self.domain) and '*' not in sub:
                            # Final check: is it a valid domain format?
                            if domain_regex.match(sub):
                                subdomains.add(sub)
        except requests.RequestException:
            raise
        except Exception:
            pass
        return subdomains

    def _hackertarget(self):
        subdomains = set()
        url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
        try:
            response = requests.get(url, timeout=self.source_timeout)
            if response.status_code == 200:
                for line in response.text.split('\n'):
                    if ',' in line:
                        sub = line.split(',')[0]
                        if sub.endswith(self.domain):
                            subdomains.add(sub.strip().lower())
        except requests.RequestException:
            raise
        except Exception:
            pass
        return subdomains
