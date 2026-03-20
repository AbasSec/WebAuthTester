"""
WebAuthTester Pro - CLI Interface.
"""

import asyncio
import aiohttp
import argparse
import os
import sys
import yaml
import logging
from typing import Dict, Any, Tuple
from textwrap import dedent
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from webauthtester.core.engine import DiscoveryEngine, BruteEngine
from webauthtester.core.utils import (
    show_banner, print_error, print_status, print_success, 
    display_results, display_findings, console
)

# Configure proper logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('webauthtester.log')
    ]
)
logger = logging.getLogger(__name__)

VERSION = "2.6"

def load_config(config_path: str = "config.yaml") -> Dict[str, Any]:
    """Loads operational configuration from a YAML file."""
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f) or {}
        except yaml.YAMLError as e:
            print_error(f"Failed to parse config.yaml: {e}")
    return {}

def show_welcome():
    """Displays a beautiful, beginner-friendly Welcome Dashboard."""
    show_banner()
    
    # About Section
    about_text = Text.from_markup(dedent("""
        [bold cyan]WebAuthTester Pro[/bold cyan] is your automated assistant for website security.
        It scans for login forms and tests if they are properly protected against 
        common password-guessing attacks.
        
        [bold white]Core Goals:[/bold white]
        • [green]Discovery:[/green] Automatically find hidden login pages and APIs.
        • [green]Analysis:[/green] Use advanced math to detect successful logins.
        • [green]Security:[/green] Ensure your site isn't leaking user data.
    """))
    console.print(Panel(about_text, title="[bold yellow]Welcome Dashboard[/bold yellow]", border_style="blue", padding=(1, 2)))

    # Quick Start Guide
    quick_start = dedent("""
        [bold green]Ready to start your first audit?[/bold green]
        Run this command to test a website:
        [bold white]python3 main.py -t https://mysite.com[/bold white]
        
        [bold yellow]Looking for technical options?[/bold yellow]
        View the full manual:
        [bold white]python3 main.py --help[/bold white]
    """)
    console.print(Panel(quick_start, title="[bold green]🚀 Quick Start[/bold green]", border_style="green"))
    console.print("\n[italic white]Tip: Always ensure you have permission before testing any website![/italic white]\n")

def show_manual():
    """Displays a clean, organized technical manual."""
    show_banner()
    
    # Manual Header
    console.print("\n[bold magenta]COMMAND LINE MANUAL[/bold magenta]")
    console.print("[bold white]Usage:[/bold white] [cyan]python3 main.py -t <url> [options][/cyan]\n")

    # Options Table
    opts_table = Table(header_style="bold cyan", box=None, expand=True)
    opts_table.add_column("Flag", style="bold yellow", no_wrap=True, width=20)
    opts_table.add_column("Technical Purpose", style="white")

    opts_table.add_row("-t, --target", "The target URL to begin crawling and auditing.")
    opts_table.add_row("-u, --userlist", "Path to a custom list of usernames.")
    opts_table.add_row("-p, --passlist", "Path to a custom list of passwords.")
    opts_table.add_row("-c, --concurrency", "Max parallel requests (default: 10).")
    opts_table.add_row("-o, --output", "Save findings to a JSON report file.")
    opts_table.add_row("--stealth", "Enable randomized jitter to bypass WAFs.")
    opts_table.add_row("--stuffing", "Perform 1:1 credential stuffing pairs.")
    opts_table.add_row("--version", "Print version and exit.")
    opts_table.add_row("-h, --help", "Display this technical manual.")
    
    console.print(opts_table)

    # Advanced Examples
    example_text = dedent("""
        [bold cyan]Standard Brute Force:[/bold cyan]
        python3 main.py -t https://example.com
        
        [bold cyan]Stealthy Audit with Custom Lists:[/bold cyan]
        python3 main.py -t https://example.com -u users.txt -p pass.txt --stealth
        
        [bold cyan]Credential Stuffing (Linear):[/bold cyan]
        python3 main.py -t https://example.com --stuffing
    """)
    console.print(Panel(example_text, title="[bold magenta]Practical Examples[/bold magenta]", border_style="magenta"))
    console.print("")

def parse_arguments() -> Tuple[argparse.ArgumentParser, argparse.Namespace]:
    """Parses command-line arguments."""
    parser = argparse.ArgumentParser(add_help=False)
    
    parser.add_argument("-h", "--help", "-help", action="store_true")
    parser.add_argument("-t", "--target", type=str)
    parser.add_argument("-u", "--userlist", type=str)
    parser.add_argument("-p", "--passlist", type=str)
    parser.add_argument("-c", "--concurrency", type=int)
    parser.add_argument("-x", "--proxy", type=str)
    parser.add_argument("-o", "--output", type=str)
    parser.add_argument("--config", type=str, default="config.yaml")
    parser.add_argument("--full-scan", action="store_true")
    parser.add_argument("--stealth", action="store_true")
    parser.add_argument("--stuffing", action="store_true")
    parser.add_argument("--version", action="store_true")
    
    return parser, parser.parse_args()

async def run_audit() -> None:
    """Main orchestration function for the security audit."""
    parser, args = parse_arguments()

    if args.version:
        console.print(f"[bold cyan]WebAuthTester Pro v{VERSION}[/bold cyan]")
        return

    # Triggered when no arguments are provided
    if len(sys.argv) == 1:
        show_welcome()
        return

    # Triggered when --help is used
    if args.help:
        show_manual()
        return

    config = load_config(args.config)
    
    target_raw = args.target or config.get('target')
    target = str(target_raw) if target_raw else None
    
    userlist = args.userlist or config.get('wordlists', {}).get('usernames', 'wordlists/usernames.txt')
    passlist = args.passlist or config.get('wordlists', {}).get('passwords', 'wordlists/passwords.txt')
    concurrency = args.concurrency or config.get('concurrency', 10)
    proxy = args.proxy or config.get('proxy')
    stealth = args.stealth or config.get('stealth', False)
    stuffing = args.stuffing or config.get('stuffing', False)
    output_file = args.output or config.get('output')

    show_banner()
    
    if not target:
        show_manual()
        print_error("\nNo target specified. Please use the -t flag to provide a URL.")
        return

    logger.info(f"Audit Started - WebAuthTester Pro v{VERSION} targeting {target}")
    
    if not os.path.exists(userlist) or not os.path.exists(passlist):
        print_error(f"Wordlists missing. Checked paths: {userlist}, {passlist}")
        return

    print_status(f"Initializing Enterprise Audit for: [bold white]{target}[/bold white]")

    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        
        discovery = DiscoveryEngine(session, target, proxy=proxy)
        with console.status("[bold green]Crawling target and parsing DOM for entry points..."):
            endpoints = await discovery.run()

        print_success(f"Discovered and mapped {len(endpoints)} authentication gateway(s).")

        brute = BruteEngine(session, concurrency, proxy, stealth=stealth)
        
        for ep in endpoints:
            print_status(f"Targeting Endpoint: [bold cyan]{ep.url}[/bold cyan] (Type: {ep.auth_type})")
            
            await brute.capture_baseline(ep)
            if ep.url not in brute.baselines and not ep.is_oauth:
                continue

            try:
                with open(userlist, 'r', encoding='utf-8') as fu:
                    users = [line.strip() for line in fu if line.strip()]
                with open(passlist, 'r', encoding='utf-8') as fp:
                    passwords = [line.strip() for line in fp if line.strip()]
            except IOError as e:
                print_error(f"Error reading wordlists: {e}")
                return

            if stuffing:
                pairs = list(zip(users, passwords))
                print_status(f"Stuffing Mode: [bold yellow]ON[/bold yellow]. Pairs: {len(pairs)}")
            else:
                pairs = [(u, p) for u in users for p in passwords]
                print_status(f"Brute Mode: [bold cyan]ON[/bold cyan]. Combinations: {len(pairs)}")

            total_attempts = len(pairs)
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=console
            ) as progress:
                task_p = progress.add_task("[cyan]Auditing credentials...", total=total_attempts)
                
                async def track_task(u, p):
                    if brute.rate_limited:
                        return
                    await brute.test(ep, u, p)
                    progress.update(task_p, advance=1)

                tasks = [track_task(u, p) for u, p in pairs]
                await asyncio.gather(*tasks)
            
            if brute.rate_limited:
                print_error("Security Response Triggered: Rate Limit detected. Aborted endpoint audit.")

        display_findings(brute.findings)
        display_results(brute.results)
        
        if output_file and (brute.results or brute.findings):
            try:
                import json
                with open(output_file, 'w', encoding='utf-8') as f:
                    res = [{"url": r[0], "username": r[1], "password": r[2]} for r in brute.results]
                    finds = [f.__dict__ for f in brute.findings]
                    for fin in finds:
                        if 'timestamp' in fin: fin['timestamp'] = fin['timestamp'].isoformat()
                    out = {"credentials": res, "vulnerabilities": finds}
                    json.dump(out, f, indent=4)
                print_success(f"Full report exported to: [bold white]{output_file}[/bold white]")
            except Exception as e:
                print_error(f"Failed to save output: {e}")

def main():
    """Main entry point for the CLI."""
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        asyncio.run(run_audit())
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        print(f"Fatal Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
