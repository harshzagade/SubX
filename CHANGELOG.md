# Changelog

All notable changes to SubX are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added
- Retry-on-timeout policy for DNS queries: a single `dns.resolver.Timeout`
  no longer kills a brute-force candidate -- every DNS lookup (CNAME
  probe, A records, wildcard probe) is retried up to `--dns-retries`
  times (default 1, `Validator(dns_retries=...)`; 0 disables, only
  non-negative integers accepted). Definitive answers (NXDOMAIN,
  NoAnswer) still fail fast on the first attempt and are never retried.
  5 new stub-based unit tests (timeout-then-success, exhausted retries,
  NXDOMAIN not retried, zero disables, invalid values rejected).
- `--http-timeout SEC` CLI flag: the 3-second HTTP/HTTPS probe timeout
  in the validation phase is now configurable (`Validator(http_timeout=...)`,
  default 3.0, values below 0.1 rejected like `--timeout`). Useful for
  slow targets (raise it) or fast noisy scans (lower it). README CLI
  options and How-It-Works updated; 5 new stub-based unit tests
  (default, custom, validation, timeout actually passed to
  `requests.get` on both the HTTPS and HTTP attempts).
- CNAME following in the DNS validation phase: candidates that are only
  a CNAME record (e.g. pointing at a CDN) are followed up to 5 hops --
  loops are cut at the first repeated name -- and the final target's A
  records are resolved, instead of the alias being dropped as a miss.
  `validate()` now returns `(ips, status, alias)`; the first CNAME
  target is reported in a new `CNAME` column in the results table and
  in JSON (`cname`), CSV, and text output, and flows through the
  dedupe/sort step (first non-empty alias wins on merge). The HTTP probe
  still targets the original subdomain so Host/TLS SNI stay correct,
  and the wildcard filter applies to the final target IPs. 9 new
  stub-based unit tests (chain, loop, depth cap, NXDOMAIN target,
  wildcard interplay, probe-target check).
- Wildcard-filter visibility: `Validator` now counts candidates dropped
  as wildcard false positives (`wildcard_filtered`, thread-safe) and the
  end-of-scan summary reports the count, so filtered scans are visible
  instead of silently short. 4 new stub-based unit tests covering the
  filter rule, mixed-IP keep, and counter thread safety.
- Dedupe + deterministic sort of results before display and file output
  (new `subx/results.py`): rows naming the same DNS host in different
  spellings (letter case, trailing dot) are collapsed into one row per
  host — merged rows keep the most informative status, the combined
  source label, and the union of observed IPs — and rows are sorted by
  subdomain so the table, `-q` output, and saved files (`-o`) all show
  the same clean, ordered list. 17 new unit tests.
- "In simple words" plain-language intro line at the top of the README.
- Detailed wildcard-domain behavior documentation in the README: the
  exact filtering rule (a candidate is dropped only when *all* resolved
  IPs are in the wildcard set; mixed wildcard+unique IPs are kept), the
  detection probe and its caveats, and guidance for full-wildcard
  targets (`--no-brute` for quiet passive-only scans).
- Real terminal screenshot of `subx --help` (`assets/screenshots/help.png`),
  replacing the old text-block capture.

### Fixed
- Corrected the Python version requirement in the README (badge and
  installation note said 3.10+, but the code uses no 3.7+ features and
  `pyproject.toml` declares `>=3.6`). Both now say Python 3.6+.
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
