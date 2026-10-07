import logging
import click
from rich.logging import RichHandler
from rich.console import Console

from rich.panel import Panel
from rich.table import Table

console = Console()

LOGO = r"""
[bold cyan]   _____       __   _  __[/bold cyan]   [bold white]SubX[/bold white] [dim]v0.1.0[/dim]
[bold cyan]  / ___/__  __/ /_ | |/ /[/bold cyan]   [dim]Advanced Subdomain Discovery[/dim]
[bold cyan]  \__ \/ / / / __ \|   / [/bold cyan]   [bold white]by Harsh Zagade[/bold white]
[bold cyan] ___/ / /_/ / /_/ /   |  [/bold cyan]
[bold cyan]/____/\__,_/_.___/_/|_|  [/bold cyan]
"""

class RichHelpCommand(click.Command):
    def format_help(self, ctx, formatter):
        console.print(f"\n{LOGO}")
        console.print(f"\n[bold white]USAGE[/bold white]")
        console.print(r"  $ subx [dim]\[options][/dim] <domain>")
        
        # Define groups
        groups = {
            "SCAN SETTINGS": [
                ("-w, --wordlist", "Path to custom wordlist for brute-forcing"),
                ("-t, --threads", "Number of concurrent threads [dim](default: 10)[/dim]"),
                ("--timeout", "DNS resolution timeout in seconds [dim](default: 5.0)[/dim]"),
            ],
            "ENUMERATION CONTROL": [
                ("--no-passive", "Disable passive source discovery"),
                ("--no-brute", "Disable wordlist brute-forcing"),
                ("--no-http", "Skip HTTP/HTTPS service validation"),
            ],
            "OUTPUT & LOGGING": [
                ("-o, --output", "Save results to file [dim](json, csv, txt)[/dim]"),
                ("-v, --verbose", "Enable detailed query logging"),
                ("-q, --quiet", "Output only discovered subdomains"),
                ("--version", "Show version information"),
                ("-h, --help", "Show this help message"),
            ]
        }

        for group, options in groups.items():
            table = Table(box=None, expand=False, show_header=False, pad_edge=False)
            table.add_column("Option", style="blue", width=24)
            table.add_column("Description", style="white")
            
            for opt, desc in options:
                table.add_row(f"  {opt}", desc)
                
            console.print(f"\n[bold white]{group}[/bold white]")
            console.print(table)
            
        console.print(f"\n[bold white]EXAMPLES[/bold white]")
        console.print("  [dim]$[/dim] subx example.com")
        console.print("  [dim]$[/dim] subx example.com -t 50 --no-http -o results.txt")
        console.print("  [dim]$[/dim] subx example.com -q > subdomains.txt\n")

def setup_logging(verbose, quiet):
    log = logging.getLogger("subx")
    if quiet:
        log.setLevel(logging.ERROR)
        log.addHandler(logging.NullHandler())
        log.propagate = False
        return log
    
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="%H:%M:%S",
        handlers=[RichHandler(
            rich_tracebacks=True, 
            console=console, 
            show_path=False,
            markup=True,
            highlighter=None
        )]
    )
    # Suppress noisy library logs
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
    
    return log
