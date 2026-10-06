# SubX

<p align="center">
  <img src="https://img.shields.io/badge/Version-0.1.0-blue.svg?style=flat-square">
  <img src="https://img.shields.io/badge/Python-3.10%2B-yellow.svg?style=flat-square">
  <img src="https://img.shields.io/badge/License-MIT-green.svg?style=flat-square">
</p>

**SubX** is a subdomain discovery tool for security professionals and bug bounty hunters. It finds subdomains of a target domain two ways: by querying passive OSINT sources (certificate transparency logs, DNS record aggregators, threat intel), and by actively brute-forcing DNS with a wordlist. Every candidate is then validated — DNS resolution, automatic wildcard filtering, and an HTTP/HTTPS service check — and the results are shown in a rich terminal table or exported to JSON, CSV, or plain text.

---

## ✨ Key Features

- **🔍 Hybrid Discovery**
  - **Passive enumeration:** queries crt.sh, HackerTarget, and AlienVault OTX APIs in parallel
  - **Active brute-forcing:** DNS resolution against a bundled wordlist of 84 common subdomains (or your own)
  - **Wildcard detection:** automatically detects wildcard DNS and filters out false positives
- **⚡ Performance**
  - Multi-threaded validation with configurable thread count (default 10)
  - Short-timeout HTTP/HTTPS checks (HTTPS first, then HTTP)
  - Skip HTTP validation entirely (`--no-http`) for faster pure-DNS scans
- **📊 Flexible Output**
  - Rich terminal table with progress bars and colored status codes
  - Export to JSON, CSV, or plain text for pipelines and further analysis
  - Quiet mode (`-q`) prints only subdomains — perfect for piping into httpx, nuclei, etc.
- **🛡️ Accuracy**
  - Random-subdomain probe detects wildcard DNS before the scan starts
  - Status per subdomain: HTTP status code, `No HTTP` (resolves, no web service), or `N/A` (HTTP checks skipped)
  - IP address resolution and grouping per subdomain

---

## 📦 Installation

Requires Python 3.10+ and internet access (passive sources are web APIs, and scans need DNS).

### Using pipx (recommended)
```bash
git clone https://github.com/harshzagade/SubX.git
cd SubX
pipx install .
```

### Using pip
```bash
git clone https://github.com/harshzagade/SubX.git
cd SubX
pip install .
```

### From source (development)
```bash
git clone https://github.com/harshzagade/SubX.git
cd SubX
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -e .
```

Dependencies: `requests`, `dnspython`, `rich`, `click` (see `requirements.txt`).

---

## 🚀 Quick Start

```bash
# Full scan: passive sources + wordlist brute-force + HTTP validation
subx example.com

# Faster scan: skip the HTTP service checks
subx example.com -t 50 --no-http

# Passive enumeration only (quietest — no DNS brute-forcing)
subx example.com --no-brute

# Save results to a file
subx example.com -o results.json

# Quiet mode: only subdomains, ready to pipe into other tools
subx example.com -q | httpx -silent
```

---

## 📖 Usage Examples

### Custom wordlist
```bash
subx example.com -w /path/to/wordlist.txt
```

### Active brute-force only
```bash
subx example.com --no-passive -w custom.txt
```

### Passive enumeration only
```bash
subx example.com --no-brute
```

### Skip HTTP validation (faster, DNS-only results)
```bash
subx example.com --no-http -t 100
```

### Multiple output formats
```bash
subx example.com -o results.json   # JSON
subx example.com -o results.csv    # CSV
subx example.com -o results.txt    # plain text
```

### Verbose logging
```bash
subx example.com -v
```

---

## 🖼️ Screenshots

Real terminal output, captured from SubX v0.1.0 (`subx --help` — the only command that runs without scanning anything):

```
   _____       __   _  __   SubX v0.1.0
  / ___/__  __/ /_ | |/ /   Advanced Subdomain Discovery
  \__ \/ / / / __ \|   /    by Harsh Zagade
 ___/ / /_/ / /_/ /   |  
/____/\__,_/_.___/_/|_|  


USAGE
  $ subx [options] <domain>

SCAN SETTINGS
  -w, --wordlist          Path to custom wordlist for brute-forcing 
  -t, --threads           Number of concurrent threads (default: 10)

ENUMERATION CONTROL
  --no-passive            Disable passive source discovery  
  --no-brute              Disable wordlist brute-forcing    
  --no-http               Skip HTTP/HTTPS service validation

OUTPUT & LOGGING
  -o, --output            Save results to file (json, csv, txt)
  -v, --verbose           Enable detailed query logging        
  -q, --quiet             Output only discovered subdomains    
  --version               Show version information             
  -h, --help              Show this help message               

EXAMPLES
  $ subx example.com
  $ subx example.com -t 50 --no-http -o results.txt
  $ subx example.com -q > subdomains.txt
```

A real scan prints a rich results table with columns **Subdomain**, **Status**, **Source** (Passive / Brute / Both), and **IP Addresses**, followed by a summary line (`Finished in Xs. Found N active subdomains.`).

---

## 🎯 How It Works

### 1. Wildcard Detection
Before anything else, SubX resolves a random 15-character subdomain of the target. If it resolves, the domain uses wildcard DNS — those IPs are recorded, and any later result resolving only to wildcard IPs is dropped as a false positive. If no wildcard is found, a note is printed and scanning continues normally.

### 2. Passive Enumeration
Three OSINT sources are queried in parallel (each with a 15-second timeout; a failed source is skipped, not fatal):
- **crt.sh** — Certificate Transparency logs; subdomain names are validated against a strict domain regex and wildcard entries (`*.example.com`) are excluded
- **HackerTarget** — DNS record aggregation API
- **AlienVault OTX** — passive DNS records

All unique subdomains found are combined.

### 3. Active Brute-Forcing
Each word from the wordlist is prefixed to the domain (`api.example.com`), resolved via DNS, and checked against the wildcard IP set. Subdomains found this way that were also found passively are tagged as source **Both**; otherwise **Passive** or **Brute**.

### 4. Validation
Each candidate is resolved to its A records and then probed: HTTPS first, then HTTP, with a 3-second timeout. A 2xx/3xx response records the status code; a subdomain that resolves but has no web service shows `No HTTP`; with `--no-http` the status shows `N/A` and DNS-only results are returned.

---

## 🔧 CLI Options

```
usage: subx [options] <domain>

positional arguments:
  domain                Target domain (e.g., example.com)

scan settings:
  -w, --wordlist PATH   Path to custom wordlist for brute-forcing
  -t, --threads NUM     Number of concurrent threads (default: 10)

enumeration control:
  --no-passive         Disable passive source discovery
  --no-brute           Disable wordlist brute-forcing
  --no-http            Skip HTTP/HTTPS service validation

output & logging:
  -o, --output FILE    Save results to file (.json, .csv, .txt)
  -v, --verbose        Enable detailed query logging
  -q, --quiet          Output only discovered subdomains
  --version            Show version information
  -h, --help           Show this help message
```

---

## 🎨 Output Formats

### JSON
```json
[
  {
    "subdomain": "api.example.com",
    "status": "200",
    "source": "Brute",
    "ips": "104.20.23.154, 172.66.147.243"
  }
]
```

### CSV
```csv
Subdomain,Status,Source,IP Addresses
api.example.com,200,Brute,"104.20.23.154, 172.66.147.243"
www.example.com,301,Both,"172.66.147.243"
```

### Plain Text
```
api.example.com (200) - 104.20.23.154, 172.66.147.243
www.example.com (301) - 172.66.147.243
```

---

## 🔄 Integration Examples

### Chain with HTTPx
```bash
subx example.com -q | httpx -silent -status-code
```

### Chain with Nuclei
```bash
subx example.com -q | nuclei -t vulnerabilities/
```

### Export for further analysis
```bash
subx example.com -o subs.json
jq -r '.[].subdomain' subs.json | httprobe
```

---

## 🏗️ Architecture

```
subx/
├── cli.py           # Command-line interface and argument parsing
├── enumerator.py    # Passive OSINT and DNS brute-forcing logic
├── validator.py     # DNS resolution, wildcard detection, HTTP/HTTPS validation
├── utils.py         # Terminal UI, logging, and formatting
└── data/
    └── default_wordlist.txt  # Built-in subdomain wordlist (84 entries)
```

Tests live in `tests/` (run with `pytest`). See [TESTING_NOTES.md](./TESTING_NOTES.md) for verification details.

**Note:** SubX needs internet connectivity and a real domain to scan — localhost testing is not supported, and there is no built-in demo mode.

---

## 🛡️ Default Wordlist

SubX ships with a curated wordlist of 84 common subdomains, including:
- `www`, `mail`, `api`, `dev`, `staging`
- `admin`, `portal`, `vpn`, `blog`, `shop`

Located at: `subx/data/default_wordlist.txt`. Override it with `-w /path/to/wordlist.txt`.

---

## ⚡ Performance Tips

### Maximum speed (DNS only)
```bash
subx example.com -t 100 --no-http --no-passive
```

### Balanced scan
```bash
subx example.com -t 50
```

### Quiet passive-only enumeration
```bash
subx example.com --no-brute -q
```

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author

**Harsh Zagade**
- GitHub: [@harshzagade](https://github.com/harshzagade)
- LinkedIn: [harsh-zagade](https://linkedin.com/in/harsh-zagade)

---

## 🙏 Acknowledgments

- Certificate Transparency Project
- HackerTarget API
- AlienVault OTX Community
- Bug bounty hunters worldwide

---

## ⚖️ Disclaimer

This tool is intended for authorized security research and bug bounty programs only. Always obtain proper authorization before scanning domains you do not own.

---

**Built with ❤️ for the bug bounty community**
