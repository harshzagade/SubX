import click
import os
import json
import csv
import time
import logging
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
try:
    from importlib import resources as pkg_resources
except ImportError:
    import importlib_resources as pkg_resources
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn, MofNCompleteColumn
from .enumerator import Enumerator
from .validator import Validator, to_ascii_domain
from .filters import parse_exclude_patterns, excluded_subdomain
from .wordlist import load_wordlist, load_words_from_lines, dedupe_case_variants, skip_passive_hits
from .results import (dedupe_results, sort_results, filter_live_results,
                      is_live_status, normalize_subdomain,
                      load_resumed_results,
                      parse_exclude_statuses, filter_excluded_statuses,
                      parse_exclude_ip_networks, filter_excluded_ip_results)
from .takeover import takeover_hint
from .utils import setup_logging, LOGO, console, RichHelpCommand
import urllib3

# Suppress insecure request warnings if verify=False is used in Validator
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_default_wordlist():
    """Get the path to the internal default wordlist."""
    try:
        # For Python 3.9+
        with pkg_resources.as_file(pkg_resources.files('subx.data').joinpath('default_wordlist.txt')) as f:
            return str(f)
    except Exception:
        base_dir = os.path.dirname(__file__)
        return os.path.join(base_dir, 'data', 'default_wordlist.txt')

def render_results(console, log, results, found_subdomains, validator,
                   output, only_live, quiet, start_time, interrupted=False,
                   exclude_status=None, exclude_ip=None, titles=None,
                   resumed_count=0):
    """Display the results table/summary and save the output file.

    Shared by the normal end-of-scan path and the KeyboardInterrupt
    path: with ``interrupted=True`` a partial-results banner is printed
    (naming how many candidates were validated before the interrupt)
    and the output file is still written, so an interrupted scan no
    longer drops everything it found.

    ``titles`` maps subdomains to their recorded HTML ``<title>``
    (``--titles``); rows without one get an empty title. The Title
    column only appears in the table when at least one title was
    recorded, so scans without ``--titles`` keep the old table.
    ``resumed_count`` is how many rows came from a ``--resume`` file
    instead of this run's validation; it is reported in the JSON
    ``stats`` block so pipelines can tell fresh rows from resumed
    ones.
    """
    duration = time.time() - start_time
    if results:
        if interrupted:
            console.print(
                f"\n[bold yellow][!] Scan interrupted by user -- partial results "
                f"below ({len(results)} of {len(found_subdomains)} "
                f"candidate(s) validated).[/bold yellow]")
        # Collapse spelling variants of the same DNS host (letter case,
        # trailing dot) into one row, then sort deterministically, so the
        # table, quiet output, and saved files (-o) all show the same
        # clean, ordered list.
        results = sort_results(dedupe_results(results))
        # Validated count is captured before the display filters
        # (--only-live, --exclude-status) so the JSON stats block
        # reports what validation actually produced, not what survived
        # filtering for display.
        validated_count = len(results)

        if only_live:
            live_total = len(results)
            results = filter_live_results(results)
            hidden = live_total - len(results)
            if hidden:
                log.info(f"[dim]--only-live: hid {hidden} DNS-only row(s); showing {len(results)} live.[/dim]")

        if exclude_status:
            status_total = len(results)
            results = filter_excluded_statuses(results, exclude_status)
            hidden = status_total - len(results)
            if hidden:
                log.info(f"[dim]--exclude-status: hid {hidden} row(s) with excluded status code(s); "
                         f"showing {len(results)}.[/dim]")

        if exclude_ip:
            ip_total = len(results)
            results = filter_excluded_ip_results(results, exclude_ip)
            hidden = ip_total - len(results)
            if hidden:
                log.info(f"[dim]--exclude-ip: hid {hidden} row(s) with an IP in an excluded range; "
                         f"showing {len(results)}.[/dim]")

        # Takeover hints are derived from the CNAME alias each row
        # already carries -- no extra requests, just a pattern match
        # against known dangling-service suffixes. Computed once here
        # so the table, summary, and saved files all agree.
        hints = [takeover_hint(r[4]) for r in results]
        # Titles were fetched during validation (one extra GET per live
        # row); rows without one simply show blank, exactly like the
        # Takeover column's opt-in behaviour.
        titles = titles or {}
        show_titles = any(titles.get(r[0]) for r in results)

        if quiet:
            for sub, status, source, ips, alias in results:
                console.print(sub)
        else:
            table = Table(
                box=None,
                header_style="bold blue",
                border_style="dim",
                expand=False,
                pad_edge=False,
                show_header=True
            )
            table.add_column("Subdomain", style="white", no_wrap=True, min_width=30)
            table.add_column("Status", justify="center", min_width=10)
            table.add_column("Source", style="dim white", min_width=15)
            table.add_column("IP Addresses", style="dim green")
            table.add_column("CNAME", style="dim cyan")
            # The Takeover column only appears when at least one row
            # carries a hint, so clean scans keep the old narrow table.
            if any(hints):
                table.add_column("Takeover", style="bold yellow")
            # Same opt-in rule for the Title column: only when at least
            # one live host actually yielded a title.
            if show_titles:
                table.add_column("Title", style="dim white")

            for (sub, status, source, ips, alias), hint in zip(results, hints):
                # Colorize status
                status_styled = status
                if status == "200":
                    status_styled = f"[bold green]{status}[/bold green]"
                elif status.startswith("3"):
                    status_styled = f"[bold yellow]{status}[/bold yellow]"
                elif status == "No HTTP":
                    status_styled = "[dim]DNS[/dim]"
                elif status == "N/A":
                    status_styled = "[dim]N/A[/dim]"
                else:
                    status_styled = f"[bold red]{status}[/bold red]"

                row = [sub, status_styled, source, ips, alias or ""]
                if any(hints):
                    row.append(f"possible: {hint}" if hint else "")
                if show_titles:
                    row.append(titles.get(sub, ""))
                table.add_row(*row)

            console.print("\n[bold white]RESULTS[/bold white]")
            console.print(table)

            source_counts = {}
            for _, _, source, _, _ in results:
                source_counts[source] = source_counts.get(source, 0) + 1
            summary_items = [f"{s}: {c}" for s, c in source_counts.items()]

            console.print(f"\n[dim]Finished in {duration:.2f}s. Found {len(results)} active subdomains.[/dim]")
            console.print(f"[dim]Sources: {', '.join(summary_items)}[/dim]")
            if validator.wildcard_filtered:
                console.print(f"[dim]Filtered {validator.wildcard_filtered} wildcard false positive(s).[/dim]")
            if validator.dns_cache_hits:
                console.print(f"[dim]Reused {validator.dns_cache_hits} cached DNS result(s) across phases.[/dim]")
            if getattr(validator, "http_probe_retries", 0):
                console.print(f"[dim]Retried {validator.http_probe_retries} transient HTTP probe failure(s).[/dim]")
            takeover_count = sum(1 for h in hints if h)
            if takeover_count:
                console.print(f"[dim]Flagged {takeover_count} possible subdomain takeover(s) -- "
                              f"CNAME pattern match only, verify the hosted resource is gone before acting.[/dim]")
            title_count = sum(1 for r in results if titles.get(r[0]))
            if title_count:
                console.print(f"[dim]Recorded {title_count} page title(s).[/dim]")

        # 5. Output to file
        if output:
            try:
                if output.endswith('.json'):
                    data = {
                        "results": [
                            {"subdomain": r[0], "status": r[1], "source": r[2],
                             "ips": r[3], "cname": r[4] or None,
                             "takeover": hint,
                             "title": titles.get(r[0]) or None}
                            for r, hint in zip(results, hints)
                        ],
                        "stats": {
                            "duration_seconds": round(duration, 2),
                            # Resumed hosts were removed from
                            # found_subdomains before validation, so
                            # they are added back here: the count is
                            # candidates this scan collected, not just
                            # the ones it re-validated.
                            "candidates_collected": len(found_subdomains) + resumed_count,
                            "validated": validated_count,
                            "resumed": resumed_count,
                            "wildcard_filtered": getattr(validator, "wildcard_filtered", 0),
                            "dns_cache_hits": getattr(validator, "dns_cache_hits", 0),
                        },
                    }
                    with open(output, 'w') as f:
                        json.dump(data, f, indent=4)
                elif output.endswith('.csv'):
                    with open(output, 'w', newline='') as f:
                        writer = csv.writer(f)
                        writer.writerow(["Subdomain", "Status", "Source", "IP Addresses", "CNAME", "Takeover", "Title"])
                        writer.writerows([(*r, hint or "", titles.get(r[0], "")) for r, hint in zip(results, hints)])
                else:
                    with open(output, 'w') as f:
                        for r, hint in zip(results, hints):
                            line = f"{r[0]} ({r[1]}) - {r[3]}"
                            if r[4]:
                                line += f" -> {r[4]}"
                            if hint:
                                line += f" [possible takeover: {hint}]"
                            if titles.get(r[0]):
                                line += f" | {titles[r[0]]}"
                            f.write(line + "\n")
                log.info(f"Results saved to [bold underline]{output}[/bold underline]")
            except Exception as e:
                log.error(f"Error saving output: {e}")
    elif interrupted:
        console.print("\n[bold yellow][!] Scan interrupted by user.[/bold yellow]")
        if found_subdomains:
            console.print(f"[dim]{len(found_subdomains)} candidate(s) collected, "
                          f"none validated yet.[/dim]")
    else:
        log.warning("No active subdomains found after validation.")


@click.command(cls=RichHelpCommand, context_settings=dict(help_option_names=['-h', '--help']))
@click.version_option(version='0.1.0', prog_name='SubX')
@click.argument('domain')
@click.option('--wordlist', '-w', type=click.Path(), help='Path to custom wordlist, or "-" to read candidates from stdin.')
@click.option('--threads', '-t', default=10, help='Number of threads to use.')
@click.option('--timeout', type=click.FloatRange(min=0.1), default=5.0, show_default=True,
              help='DNS resolution timeout in seconds (applies to DNS lookups in all phases).')
@click.option('--http-timeout', type=click.FloatRange(min=0.1), default=3.0, show_default=True,
              help='Timeout in seconds for each HTTP/HTTPS probe request during validation.')
@click.option('--dns-retries', type=click.IntRange(min=0), default=1, show_default=True,
              help='Retry attempts per DNS query after a timeout before a candidate is dropped.')
@click.option('--http-retries', type=click.IntRange(min=0), default=1, show_default=True,
              help='Retry attempts per HTTP/HTTPS probe after a transient connection error or timeout.')
@click.option('--delay', type=click.FloatRange(min=0), default=0.0, show_default=True,
              help='Pause in seconds between probes per worker thread, for stealthy scans against rate-limited targets (mirrors DurbX --delay).')
@click.option('--source-timeout', type=click.FloatRange(min=0.1), default=15.0, show_default=True,
              help='Timeout in seconds for each passive-source HTTP request.')
@click.option('--resolver', default=None,
              help='IP address of a custom DNS resolver (e.g. 1.1.1.1) instead of the system resolver.')
@click.option('--doh', default=None,
              help='DNS-over-HTTPS endpoint URL (e.g. https://dns.cloudflare.com/dns-query) instead of UDP DNS; cannot be combined with --resolver.')
@click.option('--resume', default=None, type=click.Path(),
              help='Resume from a previous -o JSON output: skip re-validating hosts already recorded there.')
@click.option('--output', '-o', help='Path to output file (json, csv, or txt).')
@click.option('--no-passive', is_flag=True, help='Skip passive enumeration.')
@click.option('--no-brute', is_flag=True, help='Skip brute-force enumeration.')
@click.option('--exclude-sub', multiple=True,
              help='Glob pattern to skip brute-force candidates (e.g. "*.blog.*"); repeatable.')
@click.option('--no-http', is_flag=True, help='Skip HTTP/HTTPS status check.')
@click.option('--only-live', is_flag=True,
              help='Show only subdomains with a working HTTP service (hide DNS-only rows).')
@click.option('--exclude-status', default=None,
              help='Comma-separated HTTP status codes to hide from results (e.g. "403,404"); applied after dedupe.')
@click.option('--exclude-ip', default=None,
              help='Comma-separated IPs/CIDR ranges to hide from results (e.g. "203.0.113.0/24"); applied after dedupe.')
@click.option('--no-wildcard-check', is_flag=True,
              help='Skip wildcard detection entirely (for targets already known to be non-wildcard).')
@click.option('--titles', 'fetch_titles', is_flag=True,
              help='Record the HTML <title> of each live host in a new results column (one extra GET per live row).')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging.')
@click.option('--quiet', '-q', is_flag=True, help='Suppress all output except results.')
def main(domain, wordlist, threads, timeout, http_timeout, dns_retries, http_retries, source_timeout, resolver, output, no_passive, no_brute, exclude_sub, no_http, only_live, verbose, quiet, exclude_status=None, exclude_ip=None, no_wildcard_check=False, fetch_titles=False, doh=None, delay=0.0, resume=None):
    """SubX - Advanced Subdomain Finder."""
    log = setup_logging(verbose, quiet)

    if only_live and no_http:
        console.print("[bold red]--only-live requires the HTTP check; remove --no-http.[/bold red]")
        sys.exit(2)

    if fetch_titles and no_http:
        console.print("[bold red]--titles requires the HTTP check; remove --no-http.[/bold red]")
        sys.exit(2)

    if exclude_status:
        try:
            exclude_status = parse_exclude_statuses(exclude_status)
        except ValueError as e:
            console.print(f"[bold red]Invalid --exclude-status:[/bold red] {e}")
            sys.exit(2)

    if exclude_ip:
        try:
            exclude_ip = parse_exclude_ip_networks(exclude_ip)
        except ValueError as e:
            console.print(f"[bold red]Invalid --exclude-ip:[/bold red] {e}")
            sys.exit(2)

    # Normalize the target up front: internationalized names become
    # punycode (stdlib only, no extra dependency) so every downstream
    # DNS query, passive-source URL, and result row uses the ASCII form.
    original_domain = domain
    try:
        domain = to_ascii_domain(domain)
    except ValueError as e:
        console.print(f"[bold red]Invalid target domain:[/bold red] {e}")
        sys.exit(2)
    if domain != original_domain.lower():
        log.info(f"[bold blue]i[/bold blue] IDN target converted to punycode: [white]{domain}[/white]")

    # --resume loads up front so a bad file fails fast, before any
    # network work; the skip itself is applied after the candidate
    # set is collected (brute-force words first, then the validation
    # phase), and the prior rows are merged back into the results.
    resumed_rows = []
    resumed_titles = {}
    resumed_subs = set()
    if resume:
        try:
            resumed_rows, resumed_titles = load_resumed_results(resume)
        except (OSError, ValueError) as e:
            console.print(f"[bold red]Invalid --resume file:[/bold red] {e}")
            sys.exit(2)
        resumed_subs = {normalize_subdomain(r[0]) for r in resumed_rows}

    if not quiet:
        console.print(LOGO)
        console.print()
        console.print(f"[dim]Target:[/dim] [bold white]{domain}[/bold white] [dim]|[/dim] [dim]Threads:[/dim] [white]{threads}[/white] [dim]|[/dim] [dim]HTTP:[/dim] [white]{'enabled' if not no_http else 'disabled'}[/white]\n")
    
    start_time = time.time()
    
    enumerator = Enumerator(domain, source_timeout=source_timeout)
    # Inject logger into enumerator for verbose feedback
    enumerator.log = log
    
    try:
        validator = Validator(dns_timeout=timeout, http_timeout=http_timeout,
                              dns_retries=dns_retries, resolver_ip=resolver,
                              http_retries=http_retries, doh_url=doh,
                              delay=delay)
    except ValueError as e:
        console.print(f"[bold red]Invalid option:[/bold red] {e}")
        sys.exit(2)
    found_subdomains = {}  # subdomain -> source
    # Validated rows, kept outside the try so a KeyboardInterrupt
    # still renders and saves what was found before the interrupt.
    results = []
    # Titles recorded for live hosts (--titles), keyed by subdomain.
    # Kept outside the try alongside `results` so an interrupt still
    # renders and saves the titles collected before it.
    titles = {}
    # Rows carried over from a --resume file. Kept outside the try so
    # the interrupt path can merge them too (an interrupt before the
    # resume-apply step leaves this empty, which is a safe no-op).
    resumed_applied = []

    try:
        # 0. Wildcard Detection
        if no_wildcard_check:
            # Targets already known to be non-wildcard skip both probe
            # queries; validator.wildcard_ips stays empty, so the
            # validation-phase filter lets everything through.
            wildcard_ips = set()
            log.info("[bold blue]i[/bold blue] Wildcard check skipped (--no-wildcard-check)")
        else:
            if not quiet:
                with console.status("[dim]Checking wildcard...[/dim]"):
                    wildcard_ips = validator.detect_wildcard(domain)
            else:
                wildcard_ips = validator.detect_wildcard(domain)

            if wildcard_ips:
                log.warning(f"[bold yellow]![/bold yellow] Wildcard detected: [dim]{', '.join(wildcard_ips)}[/dim]")
                validator.wildcard_ips = wildcard_ips
            else:
                log.info("[bold blue]i[/bold blue] No wildcard detected")

        # 1. Passive Enumeration
        if not no_passive:
            log.info(f"[bold blue]i[/bold blue] Querying passive sources...")
            passive_subs = enumerator.passive_enumerate()
            for sub in passive_subs:
                found_subdomains[sub] = "Passive"
            log.info(f"[bold green]✓[/bold green] Found [white]{len(passive_subs)}[/white] candidates via passive sources")
            failures = getattr(enumerator, "source_failures", {})
            if failures:
                names = ", ".join(sorted(failures))
                log.info(f"[dim]Passive source failures: {len(failures)} ({names}) -- retried once, still failing.[/dim]")

        # 2. Brute Force Enumeration
        if not no_brute:
            path = wordlist if wordlist else get_default_wordlist()
            try:
                if wordlist == "-":
                    # Piped candidates (e.g. `assetfinder ... | subx
                    # example.com -w -`): read from stdin instead of a
                    # file. Normalization matches load_wordlist, so a
                    # piped list behaves like the same words in a file.
                    words = load_words_from_lines(sys.stdin)
                else:
                    words = load_wordlist(path)
            except Exception as e:
                log.error(f"[bold red]✗[/bold red] Error reading wordlist: {e}")
                words = []

            # DNS is case-insensitive, so case-variant duplicates in the
            # wordlist (e.g. "Admin" and "admin") would waste queries.
            words, dupes = dedupe_case_variants(words)
            if dupes:
                log.info(f"[dim]Skipped {dupes} case-variant duplicate(s) in wordlist[/dim]")

            if resumed_subs:
                # Words already validated in the earlier scan need no
                # brute-force probe either: their rows come back from
                # the resume file in the validation phase.
                before = len(words)
                words = [w for w in words
                         if normalize_subdomain(f"{w}.{domain}") not in resumed_subs]
                skipped = before - len(words)
                if skipped:
                    log.info(f"[dim]Skipped {skipped} brute-force candidate(s) already recorded in --resume file[/dim]")

            if exclude_sub:
                try:
                    exclude_patterns = parse_exclude_patterns(exclude_sub)
                except ValueError as e:
                    log.error(f"[bold red]✗[/bold red] Invalid --exclude-sub pattern: {e}")
                    sys.exit(2)
                before = len(words)
                words = [w for w in words
                         if not excluded_subdomain(f"{w}.{domain}", exclude_patterns)]
                skipped = before - len(words)
                if skipped:
                    log.info(f"[dim]Skipped {skipped} brute-force candidate(s) matching --exclude-sub[/dim]")

            if found_subdomains:
                # Words already found passively need no brute-force
                # probe: the validation phase validates each candidate
                # exactly once anyway. Skipping them here saves a DNS
                # lookup plus an HTTP probe per word on large
                # wordlists. Their source is upgraded to "Both" (not
                # left as "Passive") so the results still record that
                # the wordlist contained them -- only the redundant
                # probe is skipped, not the information.
                words, passive_skipped = skip_passive_hits(
                    words, found_subdomains, domain)
                if passive_skipped:
                    passive_index = {
                        sub.strip().rstrip(".").lower(): sub
                        for sub in found_subdomains
                    }
                    for word in passive_skipped:
                        key = passive_index.get(f"{word.strip().lower()}.{domain}")
                        if key is not None:
                            found_subdomains[key] = "Both"
                    log.info(f"[dim]Skipped {len(passive_skipped)} brute-force candidate(s) already found via passive sources[/dim]")

            if words:
                log.info(f"[bold blue]i[/bold blue] Brute-forcing with [white]{len(words)}[/white] words...")
                
                def check_sub(word):
                    sub = f"{word}.{domain}"
                    return sub, validator.validate(sub, check_http=not no_http)

                if not quiet:
                    with Progress(
                        TextColumn("  [dim]•[/dim] [progress.description]{task.description}"),
                        BarColumn(bar_width=40, pulse_style="blue"),
                        MofNCompleteColumn(),
                        TimeElapsedColumn(),
                        console=console,
                    ) as progress:
                        task = progress.add_task("[dim]Running brute-force...[/dim]", total=len(words))
                        with ThreadPoolExecutor(max_workers=threads) as executor:
                            futures = {executor.submit(check_sub, word): word for word in words}
                            for future in as_completed(futures):
                                sub, result = future.result()
                                if result:
                                    if sub in found_subdomains:
                                        found_subdomains[sub] = "Both"
                                    else:
                                        found_subdomains[sub] = "Brute"
                                    ips, status, alias = result
                                    results.append((sub, str(status),
                                                    found_subdomains[sub],
                                                    ", ".join(ips),
                                                    alias or ""))
                                progress.update(task, advance=1)
                else:
                    with ThreadPoolExecutor(max_workers=threads) as executor:
                        futures = {executor.submit(check_sub, word): word for word in words}
                        for future in as_completed(futures):
                            sub, result = future.result()
                            if result:
                                if sub in found_subdomains:
                                    found_subdomains[sub] = "Both"
                                else:
                                    found_subdomains[sub] = "Brute"
                                ips, status, alias = result
                                results.append((sub, str(status),
                                                found_subdomains[sub],
                                                ", ".join(ips),
                                                alias or ""))
        
        log.info(f"[bold green]✓[/bold green] Total unique subdomains: [bold white]{len(found_subdomains)}[/bold white]")

        # --resume: hosts already validated in the earlier scan are not
        # re-probed. They leave the candidate set here and their prior
        # rows are merged back into the results after the validation
        # phase, so the output still lists every host. Prior titles
        # are seeded too, so the Title column keeps working for them.
        # Resume entries that are not candidates in this scan (a
        # different wordlist, a passive source that no longer lists
        # them) are ignored -- only this scan's candidates resume.
        if resumed_subs:
            candidates = {normalize_subdomain(s) for s in found_subdomains}
            resumed_applied = [r for r in resumed_rows
                               if normalize_subdomain(r[0]) in candidates]
            for sub in [s for s in found_subdomains
                        if normalize_subdomain(s) in resumed_subs]:
                del found_subdomains[sub]
            for row in resumed_applied:
                title = resumed_titles.get(normalize_subdomain(row[0]))
                if title:
                    titles[normalize_subdomain(row[0])] = title
            if resumed_applied:
                log.info(f"[bold blue]i[/bold blue] Resumed {len(resumed_applied)} previously validated subdomain(s) from [white]{resume}[/white]; skipping re-validation")

        if not found_subdomains and not resumed_applied:
            log.warning("[bold yellow]![/bold yellow] No candidates found")
            return

        # 3. Validation
        log.info(f"[bold blue]i[/bold blue] Validating candidates...")
        results = []
        
        def validate_task(sub_source):
            sub, source = sub_source
            val = validator.validate(sub, check_http=not no_http)
            if val:
                ips, status, alias = val
                # Titles are fetched only for live hosts: one extra
                # GET per live row, and a blank title on any failure
                # (fetch_title never raises for HTTP/DNS trouble).
                if fetch_titles and is_live_status(status):
                    titles[sub] = validator.fetch_title(sub)
                return (sub, str(status), source, ", ".join(ips), alias or "")
            return None

        if not quiet:
            with Progress(
                TextColumn("  [dim]•[/dim] [progress.description]{task.description}"),
                BarColumn(bar_width=40, pulse_style="green"),
                MofNCompleteColumn(),
                TimeElapsedColumn(),
                console=console,
            ) as progress:
                task = progress.add_task("[dim]Verifying...[/dim]", total=len(found_subdomains))
                with ThreadPoolExecutor(max_workers=threads) as executor:
                    futures = [executor.submit(validate_task, item) for item in found_subdomains.items()]
                    for future in as_completed(futures):
                        res = future.result()
                        if res:
                            results.append(res)
                        progress.update(task, advance=1)
        else:
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = [executor.submit(validate_task, item) for item in found_subdomains.items()]
                for future in as_completed(futures):
                    res = future.result()
                    if res:
                        results.append(res)

        # 4. Results Display
        # Resumed rows join the fresh results here: render_results
        # dedupes/sorts the combined list, so the output lists every
        # host (old and new) exactly once.
        results.extend(resumed_applied)
        render_results(console, log, results, found_subdomains, validator,
                       output, only_live, quiet, start_time,
                       exclude_status=exclude_status, exclude_ip=exclude_ip,
                       titles=titles, resumed_count=len(resumed_applied))

    except KeyboardInterrupt:
        # Same merge as the normal path: the output keeps the resumed
        # rows alongside whatever this run validated before the
        # interrupt.
        results.extend(resumed_applied)
        render_results(console, log, results, found_subdomains, validator,
                       output, only_live, quiet, start_time, interrupted=True,
                       exclude_status=exclude_status, exclude_ip=exclude_ip,
                       titles=titles, resumed_count=len(resumed_applied))
        sys.exit(130)


if __name__ == '__main__':
    main()
