# Changelog

All notable changes to SubX are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Fixed
- Corrected README claims that did not match the code: removed a
  non-existent `--rate-limit` flag from examples, removed claims of
  async HTTP checks and connection pooling (validation is
  multi-threaded, not async), and corrected the thread-count
  description (configurable, default 10 — no hardcoded 10–100 range).
- Fixed the clone URL in the README to the correct
  `github.com/harshzagade/SubX`.

### Changed
- README rewritten for accuracy: "what it does" summary, honest
  feature list, verified installation steps, usage examples from real
  CLI flags only, and a Screenshots section containing only a real
  captured `subx --help` terminal output.
- README now documents wildcard-domain behavior (random-subdomain
  probe, wildcard IP filtering) and the meaning of result statuses
  (`No HTTP`, `N/A`).
- Replaced the fabricated sample-scan output with an honest
  description of the results table format.

### Added
- `--timeout` flag (seconds, default 5.0) to control the DNS resolution
  timeout used in all phases (wildcard probe, brute-force, validation).
  `Validator` now uses a dedicated `dns.resolver.Resolver` with the
  configured `timeout`/`lifetime` instead of dnspython's global
  defaults; non-positive values are rejected.
- This CHANGELOG file.

## [0.1.0] — 2026-06-05

### Added
- Initial professional release of SubX, a hybrid subdomain discovery
  tool combining passive OSINT enumeration with DNS brute-forcing.
- Passive enumeration from three sources in parallel: crt.sh
  (Certificate Transparency), HackerTarget, and AlienVault OTX.
- Active DNS brute-forcing with a bundled 84-entry wordlist and
  support for custom wordlists (`-w/--wordlist`).
- Wildcard DNS detection via a random-subdomain probe, with
  automatic filtering of wildcard false positives.
- DNS + HTTP/HTTPS validation of candidates (HTTPS first, then HTTP,
  3-second timeouts); per-subdomain status, source
  (Passive / Brute / Both), and resolved IP addresses.
- Multi-threaded validation with configurable thread count
  (`-t/--threads`, default 10).
- Custom output formats: JSON, CSV, and plain text (`-o/--output`).
- Rich terminal UI (logo, progress bars, colored results table),
  verbose logging (`-v`), and quiet pipe-friendly mode (`-q`).
- Error handling for passive enumeration sources (a failed source is
  skipped rather than aborting the scan).
- `TESTING_NOTES.md` documenting manual testing and code
  verification; unit test suite in `tests/`.
