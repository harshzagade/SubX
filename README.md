# SubX

<p align="center">
  <img src="https://img.shields.io/badge/Version-0.1.0-blue.svg?style=flat-square">
  <img src="https://img.shields.io/badge/License-MIT-green.svg?style=flat-square">
  <img src="https://img.shields.io/badge/Python-3.10%2B-yellow.svg?style=flat-square">
</p>

**SubX** is a minimalist, high-performance subdomain discovery tool designed for security professionals and bug bounty hunters. It combines high-speed passive discovery with intelligent brute-forcing and multi-threaded service validation.

---

## 📸 Terminal Preview

```text
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
example.com                        200      Passive          172.66.147.243, 104.20.23.154
api.example.com                    200      Brute            104.20.23.154
www.example.com                    301      Both             172.66.147.243

Finished in 12.45s. Found 3 active subdomains.
Sources: Passive: 2, Brute: 1
```

---

## ✨ Key Features

- ⚡ **Asynchronous Engine**: Blazing fast DNS and HTTP service verification.
- 🔍 **Hybrid Discovery**:
  - **Passive**: Extracts candidates from `crt.sh`, `HackerTarget`, and `AlienVault`.
  - **Active**: Intelligent wordlist brute-forcing.
- 🛡️ **Wildcard Protection**: Automatically detects and filters false positives from wildcard DNS.
- 🎨 **Modern CLI**: Balanced side-by-side ASCII branding designed for professional environments.
- 🤖 **Automation Ready**: `--quiet` mode outputs only the subdomains for easy piping.

---

## 🚀 Installation

### Option 1: Using pipx (Recommended)
This installs SubX in an isolated environment and makes the command available globally.
```bash
git clone https://github.com/yourusername/SubX.git
cd SubX
pipx install .
```

### Option 2: Using pip
```bash
pip install .
```

---

## 📖 Usage Guide

### Basic Discovery
Find subdomains and check if they are alive:
```bash
subx example.com
```

### High-Speed Scanning
Increase threads and skip HTTP validation for maximum speed:
```bash
subx example.com -t 100 --no-http
```

### Automation (Piping to other tools)
Output only clean subdomain strings to pipe into tools like `httpx` or `nuclei`:
```bash
subx example.com -q | nuclei
```

---

## 🛠️ Options & Flags

| Category | Option | Description |
| :--- | :--- | :--- |
| **Settings** | `-w, --wordlist` | Path to custom wordlist for brute-forcing |
| | `-t, --threads` | Number of concurrent threads (default: 10) |
| **Control** | `--no-passive` | Disable passive source discovery |
| | `--no-brute` | Disable wordlist brute-forcing |
| | `--no-http` | Skip HTTP/HTTPS service validation |
| **Output** | `-o, --output` | Save results to file (.json, .csv, or .txt) |
| | `-v, --verbose` | Enable detailed query logging |
| | `-q, --quiet` | Minimal output (subdomains only) |
| | `-h, --help` | Show professional help menu |

---

## 📂 Project Structure

- `subx/cli.py`: Main entry point and scan orchestration.
- `subx/enumerator.py`: Passive discovery and wordlist logic.
- `subx/validator.py`: Multi-threaded DNS/HTTP validation engine.
- `subx/utils.py`: UI components and professional logging.

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

Developed with ❤️ by **Harsh Zagade**
