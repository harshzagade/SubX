import requests
import re
import logging

class Enumerator:
    DEFAULT_SOURCE_TIMEOUT = 15.0

    def __init__(self, domain, source_timeout=None):
        self.domain = domain
        if source_timeout is None:
            source_timeout = self.DEFAULT_SOURCE_TIMEOUT
        if source_timeout <= 0:
            raise ValueError("source_timeout must be positive")
        self.source_timeout = source_timeout
        self.log = logging.getLogger("subx.enumerator")

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
            try:
                found = func()
                self.log.debug(f"Found [green]{len(found)}[/green] candidates from {name}.")
                subdomains.update(found)
            except Exception as e:
                self.log.error(f"Error querying {name}: {e}")
                
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
        except Exception:
            pass
        return subdomains
