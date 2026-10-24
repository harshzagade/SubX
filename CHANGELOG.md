# Changelog

All notable changes to SubX are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added
- AAAA (IPv6) resolution alongside A records: `Validator` now queries
  both record types on the CNAME-resolved final name and reports A
  addresses followed by AAAA addresses (deduplicated, in order), so
  IPv6-only hosts are no longer dropped as misses and dual-stack hosts
  show their full address set. A record type's definitive failure is
  tolerated on its own; only both types failing is a miss, and the
  wildcard filter applies to the combined set (all-IPs-wildcard drops,
  mixed unique/wildcard keeps). The combined result is cached per FQDN
  like before. 7 new rdtype-aware tests in `tests/test_aaaa.py`;
  `test_dns_cache.py` query counts updated (CNAME + A + AAAA = 3 per
  first validation); README validation section updated.
- Skip brute-force words already discovered by passive sources: a
  word whose candidate (`www.example.com`) is already a passive hit
  is no longer probed in the brute-force phase -- the validation phase
  validates every candidate exactly once anyway, so re-probing spent a
  DNS lookup plus an HTTP probe per word on large wordlists. Skipped
  candidates are upgraded to source `Both` (the wordlist contained them
  too) and the skipped count is logged. New stdlib-only
  `skip_passive_hits()` in `subx/wordlist.py` (exact single-label,
  case-insensitive, trailing-dot tolerant; deeper names like
  `a.www.example.com` do not skip `www`); 4 unit tests + 1 stub-based
  end-to-end test driving the real `main()`; README brute-force section
  updated.
- Graceful summary on KeyboardInterrupt: pressing Ctrl-C mid-scan no
  longer drops everything -- the results renderer was extracted into a
  shared `render_results()` used by both the normal and interrupt paths,
  so an interrupted scan prints a partial-results banner (validated vs
  collected candidate counts), renders the table for what was validated,
  and still writes the `-o` output file. Brute-force hits are now
  accumulated as validated rows during the phase (the validation phase
  re-checks everything fresh and supersedes them), and the process exits
  130 instead of 1. 3 stub-based end-to-end tests drive the real `main()`
  with a fake Validator (interrupt mid-brute-force, mid-validation, and
  the clean path); README documents the Ctrl-C behavior.
- Wordlist case-variant dedup before brute-forcing: wordlists merged
  from several sources often contain the same label in different cases
  (`Admin` vs `admin`); DNS is case-insensitive, so probing both wasted
  queries. New stdlib-only `subx/wordlist.py` (`load_wordlist()` +
  `dedupe_case_variants()`) collapses variants to one candidate in
  first-seen order, and the dropped count is logged. 6 new tests; README
  brute-force section updated.
- `--only-live` CLI flag: show only subdomains with a working HTTP
  service -- rows with `No HTTP`/`N/A` status are hidden from the
  table, quiet (`-q`) output, and saved `-o` files, which is what
  recon pipelines want when feeding into httpx/nuclei. The filter
  runs after dedupe/sort (so merged rows keep their best status), the
  hidden count is logged, and combining it with `--no-http` fails
  fast with exit 2. New `is_live_status()`/`filter_live_results()`
  helpers in `subx/results.py` with 6 tests (no click needed);
  custom `--help` screen and README CLI options/Features updated.
- Per-FQDN DNS resolution cache in `Validator`: the brute-force phase
  validates every wordlist candidate and the validation phase then
  re-validates all hits, so every brute-force hit used to be resolved
  twice (CNAME chain + A records). Resolved IPs and the CNAME alias are
  now cached per normalized name via the new `_cached_dns()` helper, so
  the validation phase reuses the brute-force phase's DNS work; dead
  names are cached too, while DNS timeouts are deliberately never
  cached (transient -- retried fresh next time). The wildcard filter
  still runs on every call against the cached IPs, so mid-scan updates
  of `wildcard_ips` are honored. Lookups and counter updates are
  thread-safe for the worker pools; `Validator.dns_cache_hits` tracks
  cache servings and the scan summary reports them. 7 stub-based unit
  tests (cache reuse, dead-name caching, timeout exclusion,
  wildcard-filter interplay, thread safety); README How-It-Works
  updated.
- Two-probe wildcard detection: `detect_wildcard()` now probes two
  independent random subdomains (`Validator.WILDCARD_PROBES`) and
  declares a wildcard only when at least two probes resolve AND agree
  on at least one IP (the agreed intersection becomes `wildcard_ips`).
  A lone resolving probe -- an anycast fluke -- is ignored, so one
  stray answer can no longer poison the filter and drop genuine
  subdomains for the whole scan. New `_probe_random_name()` helper and
  7 stub-based unit tests (agreement, disagreement, fluke, timeout,
  overlap). README "How It Works" + wildcard-behavior section updated.
- `--exclude-sub PATTERN` CLI flag (repeatable): skip brute-force
  candidates matching a glob before any DNS query is made -- e.g.
  `--exclude-sub '*.blog.*'` drops everything under noisy `blog`
  subtrees. Patterns match the full candidate subdomain,
  case-insensitively; empty patterns fail fast with exit 2; the count
  skipped is logged. Applies to brute-force only, not passive
  candidates. New stdlib-only `subx/filters.py`
  (`parse_exclude_patterns()`/`excluded_subdomain()`) with 9 unit
  tests; README How-It-Works updated.
- IDN/punycode support: unicode targets like `münchen.de` are converted
  to `xn--mnchen-3ya.de` before any DNS query, using only the stdlib
  `idna` codec (no new dependency). New `to_ascii_domain()` in
  `validator.py` lowercases, strips the trailing dot, and validates the
  ASCII form as a hostname (fail-fast `ValueError` on invalid input);
  the CLI converts the target up front and notes the conversion, and
  `Validator.validate()`/`detect_wildcard()` convert defensively for
  direct library callers. 13 new tests (conversion rules, punycode
  actually queried via the DNS stub).
- Retry-on-timeout policy for DNS queries: a single `dns.resolver.Timeout`  no longer kills a brute-force candidate -- every DNS lookup (CNAME
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
