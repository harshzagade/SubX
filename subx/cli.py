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
from .results import dedupe_results, sort_results
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

@click.command(cls=RichHelpCommand, context_settings=dict(help_option_names=['-h', '--help']))
@click.version_option(version='0.1.0', prog_name='SubX')
@click.argument('domain')
@click.option('--wordlist', '-w', type=click.Path(exists=True), help='Path to custom wordlist.')
@click.option('--threads', '-t', default=10, help='Number of threads to use.')
@click.option('--timeout', type=click.FloatRange(min=0.1), default=5.0, show_default=True,
              help='DNS resolution timeout in seconds (applies to DNS lookups in all phases).')
@click.option('--http-timeout', type=click.FloatRange(min=0.1), default=3.0, show_default=True,
              help='Timeout in seconds for each HTTP/HTTPS probe request during validation.')
@click.option('--dns-retries', type=click.IntRange(min=0), default=1, show_default=True,
              help='Retry attempts per DNS query after a timeout before a candidate is dropped.')
@click.option('--output', '-o', help='Path to output file (json, csv, or txt).')
@click.option('--no-passive', is_flag=True, help='Skip passive enumeration.')
@click.option('--no-brute', is_flag=True, help='Skip brute-force enumeration.')
@click.option('--exclude-sub', multiple=True,
              help='Glob pattern to skip brute-force candidates (e.g. "*.blog.*"); repeatable.')
@click.option('--no-http', is_flag=True, help='Skip HTTP/HTTPS status check.')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging.')
@click.option('--quiet', '-q', is_flag=True, help='Suppress all output except results.')
def main(domain, wordlist, threads, timeout, http_timeout, dns_retries, output, no_passive, no_brute, exclude_sub, no_http, verbose, quiet):
    """SubX - Advanced Subdomain Finder."""
    log = setup_logging(verbose, quiet)

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

    if not quiet:
        console.print(LOGO)
        console.print()
        console.print(f"[dim]Target:[/dim] [bold white]{domain}[/bold white] [dim]|[/dim] [dim]Threads:[/dim] [white]{threads}[/white] [dim]|[/dim] [dim]HTTP:[/dim] [white]{'enabled' if not no_http else 'disabled'}[/white]\n")
    
    start_time = time.time()
    
    enumerator = Enumerator(domain)
    # Inject logger into enumerator for verbose feedback
    enumerator.log = log
    
    validator = Validator(dns_timeout=timeout, http_timeout=http_timeout,
                        dns_retries=dns_retries)
    found_subdomains = {}  # subdomain -> source

    try:
        # 0. Wildcard Detection
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

        # 2. Brute Force Enumeration
        if not no_brute:
            path = wordlist if wordlist else get_default_wordlist()
            try:
                with open(path, 'r') as f:
                    words = [line.strip().lower() for line in f if line.strip()]
            except Exception as e:
                log.error(f"[bold red]✗[/bold red] Error reading wordlist: {e}")
                words = []

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
        
        log.info(f"[bold green]✓[/bold green] Total unique subdomains: [bold white]{len(found_subdomains)}[/bold white]")

        if not found_subdomains:
            log.warning("[bold yellow]![/bold yellow] No candidates found")
            return

        # 3. Validation
        results = []
        log.info(f"[bold blue]i[/bold blue] Validating candidates...")
        
        def validate_task(sub_source):
            sub, source = sub_source
            val = validator.validate(sub, check_http=not no_http)
            if val:
                ips, status, alias = val
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
        duration = time.time() - start_time
        if results:
            # Collapse spelling variants of the same DNS host (letter case,
            # trailing dot) into one row, then sort deterministically, so the
            # table, quiet output, and saved files (-o) all show the same
            # clean, ordered list.
            results = sort_results(dedupe_results(results))
            
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

                for sub, status, source, ips, alias in results:
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
                    
                    table.add_row(sub, status_styled, source, ips, alias or "")
                
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

            # 5. Output to file
            if output:
                try:
                    if output.endswith('.json'):
                        data = [{"subdomain": r[0], "status": r[1], "source": r[2], "ips": r[3], "cname": r[4] or None} for r in results]
                        with open(output, 'w') as f:
                            json.dump(data, f, indent=4)
                    elif output.endswith('.csv'):
                        with open(output, 'w', newline='') as f:
                            writer = csv.writer(f)
                            writer.writerow(["Subdomain", "Status", "Source", "IP Addresses", "CNAME"])
                            writer.writerows(results)
                    else:
                        with open(output, 'w') as f:
                            for r in results:
                                line = f"{r[0]} ({r[1]}) - {r[3]}"
                                if r[4]:
                                    line += f" -> {r[4]}"
                                f.write(line + "\n")
                    log.info(f"Results saved to [bold underline]{output}[/bold underline]")
                except Exception as e:
                    log.error(f"Error saving output: {e}")
        else:
            log.warning("No active subdomains found after validation.")
            
    except KeyboardInterrupt:
        console.print("\n[bold red][!] Scan interrupted by user. Exiting...[/bold red]")
        sys.exit(1)

if __name__ == '__main__':
    main()
