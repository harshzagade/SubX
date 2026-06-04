# SubX

<p align="center">
  <img src="https://img.shields.io/badge/Version-0.1.0-blue.svg?style=flat-square">
  <img src="https://img.shields.io/badge/Python-3.10%2B-yellow.svg?style=flat-square">
  <img src="https://img.shields.io/badge/License-MIT-green.svg?style=flat-square">
</p>

**SubX** is a high-performance subdomain discovery tool designed for security professionals and bug bounty hunters. It combines passive OSINT enumeration with intelligent DNS brute-forcing and multi-threaded validation.

---

## ✨ Key Features

- **🔍 Hybrid Discovery**
  - **Passive Enumeration:** Queries crt.sh, HackerTarget, and AlienVault OTX APIs
  - **Active Brute-Forcing:** DNS resolution with customizable wordlists
  - **Wildcard Detection:** Automatically filters false positives from wildcard DNS

- **⚡ High Performance**
  - Multi-threaded validation (10-100 concurrent workers)
  - Async HTTP/HTTPS status checking
  - Intelligent caching and connection pooling

- **📊 Flexible Output**
  - JSON export for automation pipelines
  - CSV format for spreadsheet analysis
  - Plain text for piping to other tools
  - Rich terminal interface with progress tracking

- **🛡️ Stealth & Accuracy**
  - Random subdomain testing to detect wildcards
  - HTTP/HTTPS service validation
  - IP address resolution and grouping

---

## 📦 Installation

### Using pipx (Recommended)
```bash
git clone https://github.com/HarshZagade/SubX.git
cd SubX
pipx install .
```

### Using pip
```bash
pip install --user .
```

---

## 🚀 Quick Start

### Basic Subdomain Discovery
```bash
subx example.com
```

### High-Speed Scan
```bash
subx example.com -t 50 --no-http
```

### Save Results
```bash
subx example.com -o results.json
```

### Quiet Mode (Pipe to Other Tools)
```bash
subx example.com -q | httpx -silent
```

---

## 📖 Usage Examples

### Custom Wordlist
```bash
subx example.com -w /path/to/wordlist.txt
```

### Passive Enumeration Only
```bash
subx example.com --no-brute
```

### Active Brute-Force Only
```bash
subx example.com --no-passive -w custom.txt
```

### Skip HTTP Validation (Faster)
```bash
subx example.com --no-http -t 100
```

### Multiple Output Formats
```bash
# JSON format
subx example.com -o results.json

# CSV format
subx example.com -o results.csv

# Plain text
subx example.com -o results.txt
```

---

## 🎯 How It Works

### 1. Wildcard Detection
```
SubX first checks if the target domain has wildcard DNS:
→ Queries random.xyz123.example.com
→ If it resolves, those IPs are marked as wildcards
→ Future results matching wildcard IPs are filtered
```

### 2. Passive Enumeration
```
Queries three OSINT sources in parallel:
├─ crt.sh (Certificate Transparency logs)
├─ HackerTarget (DNS records)
└─ AlienVault OTX (Threat intelligence)

Combines all unique subdomains found
```

### 3. Active Brute-Forcing
```
For each word in wordlist:
├─ Construct subdomain: word.example.com
├─ Attempt DNS resolution
├─ Check against wildcard IPs
└─ If unique, mark as candidate
```

### 4. Validation
```
For each discovered subdomain:
├─ Resolve DNS to get IP addresses
├─ Try HTTPS connection (port 443)
├─ If HTTPS fails, try HTTP (port 80)
└─ Record status code and IPs
```

---

## 📊 Sample Output

```
   _____       __   _  __   SubX v0.1.0
  / ___/__  __/ /_ | |/ /   Advanced Subdomain Discovery
  \__ \/ / / / __ \|   /    by Harsh Zagade
 ___/ / /_/ / /_/ /   |  
/____/\__,_/_.___/_/|_|  

Target: example.com | Threads: 10 | HTTP: enabled

14:20:15 INFO     i No wildcard detected
         INFO     i Querying passive sources...
14:20:25 INFO     ✓ Found 7 candidates via passive sources
         INFO     ✓ Total unique subdomains: 7
         INFO     i Validating candidates...
  • Verifying... ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 7/7 0:00:00

RESULTS
Subdomain                         Status    Source           IP Addresses                 
example.com                        200      Passive          172.66.147.243
api.example.com                    200      Brute            104.20.23.154
www.example.com                    301      Both             172.66.147.243
mail.example.com                   200      Passive          104.20.23.154

Finished in 12.45s. Found 4 active subdomains.
Sources: Passive: 3, Brute: 1
```

---

## 🔧 CLI Options

```bash
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

## 🏗️ Architecture

```
subx/
├── cli.py           # Command-line interface and argument parsing
├── enumerator.py    # Passive OSINT and DNS brute-forcing logic
├── validator.py     # DNS resolution and HTTP/HTTPS validation
├── utils.py         # Terminal UI, logging, and formatting
└── data/
    └── default_wordlist.txt  # Built-in subdomain wordlist (84 entries)
```

---

## 📚 Passive Sources

### crt.sh
- Certificate Transparency logs
- Discovers subdomains from SSL/TLS certificates
- Historical data included

### HackerTarget
- DNS record aggregation
- Real-time subdomain enumeration
- Public DNS data

### AlienVault OTX
- Threat intelligence platform
- Passive DNS records
- Security community contributions

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
api.example.com
www.example.com
mail.example.com
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

### Export for Further Analysis
```bash
subx example.com -o subs.json
cat subs.json | jq -r '.[].subdomain' | httprobe
```

---

## 🧪 Testing

See [TESTING_NOTES.md](./TESTING_NOTES.md) for verification details.

**Note:** SubX requires internet connectivity and real domain names for testing. Localhost testing is not supported.

---

## 🛡️ Default Wordlist

SubX includes a curated wordlist of 84 common subdomains:
- `www`, `mail`, `api`, `dev`, `staging`
- `admin`, `portal`, `vpn`, `blog`, `shop`
- And 74 more...

Located at: `subx/data/default_wordlist.txt`

---

## ⚡ Performance Tips

### Maximum Speed
```bash
subx example.com -t 100 --no-http --no-passive
```

### Balanced Scan
```bash
subx example.com -t 50
```

### Stealth Mode
```bash
subx example.com -t 5 --rate-limit 0.5
```

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author

**Harsh Zagade**
- GitHub: [@HarshZagade](https://github.com/HarshZagade)
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
